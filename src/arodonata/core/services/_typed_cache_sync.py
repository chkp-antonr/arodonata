"""Shared generic incremental/full sync and WriteSession overlay helpers for objects and services."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Collection, Sequence
from datetime import datetime
from typing import Any, Literal, Protocol

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.errors import ServerIdentityError
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.common import to_naive_utc
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.ports import ApiPort
from arodonata.core.services.sync_coordinator import DomainProbeResult


class _ScopedEntity(Protocol):
    uid: str
    name: str
    type: str
    mgmt_name: str
    domain_name: str

    def model_copy(self, *, update: dict[str, Any]) -> Any: ...


def unwrap_change_item(item: Any) -> Any:
    """Unwrap R82+ `show-changes` modified-object wrapper (`{'new-object': {...}}` or `{'old-object': {...}}`)."""
    if isinstance(item, dict) and not item.get("uid"):
        for key in ("new-object", "old-object"):
            inner = item.get(key)
            if isinstance(inner, dict):
                return inner
    return item


def extract_changes_from_show_changes(
    data: dict[str, Any],
    *,
    tracked_types: set[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract `(added_or_modified_uid_and_type, deleted_uids)` for `tracked_types` from `show-changes` response."""
    upserts: dict[str, str] = {}
    deleted: set[str] = set()

    change_containers: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        for task in data["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("task-details"), list):
                for detail in task["task-details"]:
                    if isinstance(detail, dict):
                        if isinstance(detail.get("changes"), list):
                            for ch in detail["changes"]:
                                if isinstance(ch, dict):
                                    change_containers.append(ch)
                        else:
                            change_containers.append(detail)
    if isinstance(data.get("changes"), list):
        for ch in data["changes"]:
            if isinstance(ch, dict):
                change_containers.append(ch)
    if isinstance(data.get("operations"), dict):
        change_containers.append(data)

    for container in change_containers:
        ops = container.get("operations")
        if not isinstance(ops, dict):
            ops = container

        for key in ("added-objects", "modified-objects", "added_objects", "modified_objects"):
            items = ops.get(key)
            if isinstance(items, list):
                for raw_item in items:
                    item = unwrap_change_item(raw_item)
                    if not isinstance(item, dict):
                        continue
                    uid = str(item.get("uid") or "")
                    obj_type = str(item.get("type") or "")
                    if not uid or (obj_type and obj_type not in tracked_types):
                        continue
                    upserts[uid] = obj_type
                    deleted.discard(uid)

        for key in ("deleted-objects", "deleted_objects"):
            items = ops.get(key)
            if isinstance(items, list):
                for raw_item in items:
                    item = unwrap_change_item(raw_item)
                    if isinstance(item, str) and item:
                        deleted.add(item)
                        upserts.pop(item, None)
                    elif isinstance(item, dict):
                        uid = str(item.get("uid") or "")
                        obj_type = str(item.get("type") or "")
                        if not uid or (obj_type and obj_type not in tracked_types):
                            continue
                        deleted.add(uid)
                        upserts.pop(uid, None)

    return list(upserts.items()), list(deleted)


def can_try_incremental(probe: DomainProbeResult) -> bool:
    """Return `True` if every stale `item_type` in `probe` has a baseline `DomainSyncState`."""
    if not probe.stale_types:
        return False
    for t in probe.stale_types:
        st = probe.existing_states.get(t)
        if st is None or st.status != "ok":
            return False
        if st.last_session_uid is None and st.last_published_at is None:
            return False
    return True


async def try_incremental_sync[TEntity: _ScopedEntity](
    *,
    scope: Literal["objects", "services"],
    probe: DomainProbeResult,
    emit: Callable[[SyncProgressEvent], Awaitable[None]],
    api: ApiPort,
    settings: ArodonataSettings,
    now_fn: Callable[[], datetime],
    model_from_cp_dict: Callable[[str, str, dict[str, Any]], TEntity],
    get_cached_by_type: Callable[[str, str, list[str]], Awaitable[Sequence[TEntity]]],
    apply_diff_fn: Callable[[str, str, Sequence[str], Sequence[TEntity], Sequence[DomainSyncState]], Awaitable[Any]],
) -> int | None:
    """Attempt incremental refresh via `show-changes`; return `None` to fall back to full reload."""
    mgmt_name = probe.mgmt_name
    dom_name = probe.domain.name
    stale_set = set(probe.stale_types)

    baseline_states = [probe.existing_states[t] for t in probe.stale_types if t in probe.existing_states]
    if not baseline_states:
        return None

    earliest_state = min(
        baseline_states,
        key=lambda s: (s.last_published_at is None, s.last_published_at or datetime.max),
    )

    payload: dict[str, Any] = {"details-level": "standard"}
    if earliest_state.last_session_uid is not None:
        payload["from-session"] = earliest_state.last_session_uid
    elif earliest_state.last_published_at is not None:
        payload["from-date"] = to_naive_utc(earliest_state.last_published_at).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        res = await api.api_call(
            mgmt_name,
            "show-changes",
            payload,
            domain=dom_name,
            wait_for_task=True,
        )
        if not res.success:
            return None

        upserts_meta, deleted_uids = extract_changes_from_show_changes(
            res.data,
            tracked_types=stale_set,
        )
        total_changes = len(upserts_meta) + len(deleted_uids)
        if total_changes > settings.max_incremental_changes:
            await emit(
                DomainSyncProgressEvent(
                    scope=scope,
                    mgmt_name=mgmt_name,
                    domain=dom_name,
                    item_type=",".join(probe.stale_types),
                    processed=0,
                    total=total_changes,
                    message=(
                        f"Incremental diff count ({total_changes}) exceeds "
                        f"max_incremental_changes ({settings.max_incremental_changes}); "
                        "falling back to full type-scoped reload."
                    ),
                )
            )
            return None

        fetched_entities: list[TEntity] = []
        for uid, _hint_type in upserts_meta:
            obj_res = await api.api_call(
                mgmt_name,
                "show-object",
                {"uid": uid, "details-level": "full"},
                domain=dom_name,
            )
            if not obj_res.success:
                return None
            raw_obj = obj_res.data.get("object") if isinstance(obj_res.data.get("object"), dict) else obj_res.data
            if not isinstance(raw_obj, dict) or not raw_obj.get("uid"):
                return None
            entity = model_from_cp_dict(mgmt_name, dom_name, raw_obj)
            if entity.type in stale_set:
                fetched_entities.append(entity)

        existing_by_type: dict[str, Sequence[TEntity]] = {}
        for item_type in probe.stale_types:
            existing_by_type[item_type] = await get_cached_by_type(mgmt_name, dom_name, [item_type])

        deleted_uid_set = set(deleted_uids)
        fetched_by_type: dict[str, dict[str, TEntity]] = {t: {} for t in probe.stale_types}
        for entity in fetched_entities:
            if entity.type in fetched_by_type:
                fetched_by_type[entity.type][entity.uid] = entity

        synced_at = probe.probe_started_at or now_fn()
        sync_states: list[DomainSyncState] = []
        for item_type in probe.stale_types:
            uid_set = {e.uid for e in existing_by_type.get(item_type, ()) if e.uid not in deleted_uid_set}
            uid_set.update(fetched_by_type.get(item_type, {}).keys())
            sync_states.append(
                DomainSyncState(
                    mgmt_name=mgmt_name,
                    domain_name=dom_name,
                    scope=scope,
                    item_type=item_type,
                    last_published_at=probe.remote_published_at,
                    last_session_uid=probe.remote_session_uid,
                    synced_at=synced_at,
                    status="ok",
                    object_count=len(uid_set),
                    last_error=None,
                )
            )

        await apply_diff_fn(mgmt_name, dom_name, deleted_uids, fetched_entities, sync_states)

        label = "service diff" if scope == "services" else "diff"
        await emit(
            DomainSyncProgressEvent(
                scope=scope,
                mgmt_name=mgmt_name,
                domain=dom_name,
                item_type=",".join(probe.stale_types),
                processed=total_changes,
                total=total_changes,
                message=(
                    f"Applied incremental {label} on {mgmt_name}:{dom_name} "
                    f"({len(fetched_entities)} upserted, {len(deleted_uids)} deleted)."
                ),
            )
        )
        return len(fetched_entities) + len(deleted_uids)
    except ServerIdentityError:
        raise
    except Exception:
        return None


async def full_reload_types[TEntity: _ScopedEntity](
    *,
    scope: Literal["objects", "services"],
    probe: DomainProbeResult,
    emit: Callable[[SyncProgressEvent], Awaitable[None]],
    api: ApiPort,
    now_fn: Callable[[], datetime],
    resolve_command_fn: Callable[[str], tuple[str, dict[str, Any]]],
    model_from_cp_dict: Callable[[str, str, dict[str, Any]], TEntity],
    replace_domain_fn: Callable[[str, str, list[TEntity], Sequence[str], Sequence[DomainSyncState]], Awaitable[Any]],
) -> int:
    """Fetch all entities for `probe.stale_types` and atomically replace them in cache."""
    mgmt_name = probe.mgmt_name
    dom_name = probe.domain.name
    collected_by_type: dict[str, list[TEntity]] = {}
    all_collected: list[TEntity] = []
    noun = "service(s)" if scope == "services" else "object(s)"

    for item_type in probe.stale_types:
        cmd, extra_payload = resolve_command_fn(item_type)
        q_res = await api.api_query(
            mgmt_name,
            cmd,
            domain=dom_name,
            details_level="full",
            payload=extra_payload or None,
        )
        if not q_res.success:
            raise RuntimeError(
                f"Failed to query {item_type!r} ({cmd}) on {mgmt_name}:{dom_name}: "
                f"{q_res.error_message or q_res.code or 'query failed'}"
            )

        typed_entities: list[TEntity] = []
        for raw in q_res.objects:
            if not isinstance(raw, dict) or not raw.get("uid"):
                continue
            raw_copy = dict(raw)
            if not raw_copy.get("type"):
                raw_copy["type"] = item_type
            entity = model_from_cp_dict(mgmt_name, dom_name, raw_copy)
            if entity.type != item_type:
                entity = entity.model_copy(update={"type": item_type})
            typed_entities.append(entity)
        del q_res

        collected_by_type[item_type] = typed_entities
        all_collected.extend(typed_entities)

        await emit(
            DomainSyncProgressEvent(
                scope=scope,
                mgmt_name=mgmt_name,
                domain=dom_name,
                item_type=item_type,
                processed=len(typed_entities),
                total=len(typed_entities),
                message=f"Fetched {len(typed_entities)} {item_type} {noun} from {mgmt_name}:{dom_name}.",
            )
        )

    synced_at = probe.probe_started_at or now_fn()
    sync_states = [
        DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope=scope,
            item_type=item_type,
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=synced_at,
            status="ok",
            object_count=len(collected_by_type.get(item_type, [])),
            last_error=None,
        )
        for item_type in probe.stale_types
    ]
    await replace_domain_fn(mgmt_name, dom_name, all_collected, probe.stale_types, sync_states)
    return len(all_collected)


def apply_typed_context_overlay[TEntity: _ScopedEntity](
    cached_items: Sequence[TEntity],
    *,
    overlay_apply_fn: Callable[[Any, list[TEntity], Sequence[str] | None], list[TEntity]],
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    allowed_domains: Collection[str] | None = None,
    include_global: bool = True,
    types: Sequence[str] | None = None,
    names: Sequence[str] | None = None,
    uids: Sequence[str] | None = None,
) -> list[TEntity]:
    """Merge active `WriteSession` overlay from `contextvars` onto `cached_items`."""
    ws = get_write_session()
    if ws is None:
        return list(cached_items)
    if mgmt_name is not None and ws.mgmt_name != mgmt_name:
        return list(cached_items)
    if allowed_domains is not None:
        if ws.domain_name not in allowed_domains:
            return list(cached_items)
    elif domain_name is not None:
        if ws.domain_name != domain_name:
            return list(cached_items)
    elif not include_global and ws.domain_name == "Global":
        return list(cached_items)

    in_scope: list[TEntity] = []
    out_of_scope: list[TEntity] = []
    for item in cached_items:
        if item.mgmt_name == ws.mgmt_name and item.domain_name == ws.domain_name:
            in_scope.append(item)
        else:
            out_of_scope.append(item)

    merged_scope = overlay_apply_fn(ws.overlay, in_scope, types)
    if names is not None:
        name_set = set(names)
        merged_scope = [item for item in merged_scope if item.name in name_set]
    if uids is not None:
        uid_set = set(uids)
        merged_scope = [item for item in merged_scope if item.uid in uid_set]

    return out_of_scope + merged_scope
