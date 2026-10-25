"""Network object cache synchronization service (`ObjectService`).

Provides:
- Paired `await refresh_objects(...)` and `stream_refresh_objects(...)` methods.
- Canonical `CacheMode` support (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`).
- Default tracked object types `DEFAULT_OBJECT_TYPES = ("host", "network", "address-range", "group", "dns-domain")`.
- Type-scoped atomic replacement in `arodonata_objects` (`CachePort.replace_domain_objects`).
- `"smart-fast"` incremental sync via `show-changes`: deletes removed UIDs directly, re-fetches
  added/modified tracked objects in full (`show-object` with `details-level="full"`), and falls back
  automatically to an atomic type-scoped reload when changes exceed `max_incremental_changes`
  (default 500) or any error occurs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.errors import ServerIdentityError
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.common import (
    DEFAULT_OBJECT_TYPES,
    CacheMode,
    to_naive_utc,
    utc_now,
)
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced

OBJECT_TYPE_TO_SHOW_COMMAND: dict[str, str] = {
    "host": "show-hosts",
    "network": "show-networks",
    "address-range": "show-address-ranges",
    "multicast-address-range": "show-multicast-address-ranges",
    "group": "show-groups",
    "group-with-exclusion": "show-groups-with-exclusion",
    "dns-domain": "show-dns-domains",
    "wildcard": "show-wildcards",
    "security-zone": "show-security-zones",
    "dynamic-object": "show-dynamic-objects",
    "time": "show-times",
    "time-group": "show-time-groups",
    "access-role": "show-access-roles",
    "tag": "show-tags",
    "gsn-handover-group": "show-gsn-handover-groups",
    "network-feed": "show-network-feeds",
}


def resolve_object_query_command(item_type: str) -> tuple[str, dict[str, Any]]:
    """Map an object `item_type` to `(command, extra_payload)` for `api_query`."""
    clean = item_type.strip().lower()
    if clean in OBJECT_TYPE_TO_SHOW_COMMAND:
        return OBJECT_TYPE_TO_SHOW_COMMAND[clean], {}
    return "show-objects", {"type": clean}


def _unwrap_change_item(item: Any) -> Any:
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
    """Extract `(added_or_modified_uid_and_type, deleted_uids)` for `tracked_types` from `show-changes` response.

    Returns:
        `(upserts, deleted_uids)` where `upserts` is a list of `(uid, obj_type)` pairs and
        `deleted_uids` is a list of deleted object UIDs.
    """
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
                    item = _unwrap_change_item(raw_item)
                    if not isinstance(item, dict):
                        continue
                    uid = str(item.get("uid") or "")
                    obj_type = str(item.get("type") or "")
                    if not uid:
                        continue
                    if obj_type and obj_type not in tracked_types:
                        continue
                    upserts[uid] = obj_type
                    deleted.discard(uid)

        for key in ("deleted-objects", "deleted_objects"):
            items = ops.get(key)
            if isinstance(items, list):
                for raw_item in items:
                    item = _unwrap_change_item(raw_item)
                    if isinstance(item, str) and item:
                        deleted.add(item)
                        upserts.pop(item, None)
                    elif isinstance(item, dict):
                        uid = str(item.get("uid") or "")
                        obj_type = str(item.get("type") or "")
                        if not uid:
                            continue
                        if obj_type and obj_type not in tracked_types:
                            continue
                        deleted.add(uid)
                        upserts.pop(uid, None)

    return list(upserts.items()), list(deleted)


class ObjectService:
    """Synchronizes and queries cached network objects (`arodonata_objects`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        coordinator: DomainSyncCoordinator,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    def _normalize_types(self, types: Sequence[str] | None) -> list[str]:
        if types is None:
            return list(DEFAULT_OBJECT_TYPES)
        seen: list[str] = []
        for t in types:
            clean = str(t).strip().lower()
            if clean and clean not in seen:
                seen.append(clean)
        return seen or list(DEFAULT_OBJECT_TYPES)

    async def stream_refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing network objects across domains."""
        target_types = self._normalize_types(types)

        async def _sync_domain_objects(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            if mode == "smart-fast" and self._can_try_incremental(probe):
                inc_count = await self._try_incremental_sync(probe, emit)
                if inc_count is not None:
                    return inc_count

            return await self._full_reload_types(probe, emit)

        async for event in self._coordinator.stream_ensure(
            scope="objects",
            item_types=target_types,
            handler=_sync_domain_objects,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    @traced
    async def refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh network objects across domains and return `RefreshOutcome`."""
        target_types = self._normalize_types(types)
        span_attrs(mgmt_name=mgmt_name, mode=mode, types=target_types, include_global=include_global)

        async def _sync_domain_objects(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            if mode == "smart-fast" and self._can_try_incremental(probe):
                inc_count = await self._try_incremental_sync(probe, emit)
                if inc_count is not None:
                    return inc_count

            return await self._full_reload_types(probe, emit)

        return await self._coordinator.ensure(
            scope="objects",
            item_types=target_types,
            handler=_sync_domain_objects,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    def _can_try_incremental(self, probe: DomainProbeResult) -> bool:
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

    async def _try_incremental_sync(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int | None:
        """Attempt incremental refresh via `show-changes`; return `None` to fall back to full reload."""
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name
        stale_set = set(probe.stale_types)

        # Pick earliest baseline across stale types
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
            res = await self._api.api_call(
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
            if total_changes > self._settings.max_incremental_changes:
                await emit(
                    DomainSyncProgressEvent(
                        scope="objects",
                        mgmt_name=mgmt_name,
                        domain=dom_name,
                        item_type=",".join(probe.stale_types),
                        processed=0,
                        total=total_changes,
                        message=(
                            f"Incremental diff count ({total_changes}) exceeds "
                            f"max_incremental_changes ({self._settings.max_incremental_changes}); "
                            "falling back to full type-scoped reload."
                        ),
                    )
                )
                return None

            if deleted_uids:
                await self._cache.delete_objects_by_uids(mgmt_name, dom_name, deleted_uids)

            fetched_objects: list[CPObject] = []
            for uid, _hint_type in upserts_meta:
                obj_res = await self._api.api_call(
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
                cp_obj = CPObject.from_cp_dict(mgmt_name, dom_name, raw_obj)
                if cp_obj.type in stale_set:
                    fetched_objects.append(cp_obj)

            now = self._now()
            existing_by_type: dict[str, list[CPObject]] = {}
            for item_type in probe.stale_types:
                existing_by_type[item_type] = await self._cache.get_objects(mgmt_name, dom_name, types=[item_type])

            fetched_by_type: dict[str, dict[str, CPObject]] = {t: {} for t in probe.stale_types}
            for obj in fetched_objects:
                if obj.type in fetched_by_type:
                    fetched_by_type[obj.type][obj.uid] = obj

            sync_states: list[DomainSyncState] = []
            for item_type in probe.stale_types:
                uid_set = {o.uid for o in existing_by_type.get(item_type, [])}
                uid_set.update(fetched_by_type.get(item_type, {}).keys())
                sync_states.append(
                    DomainSyncState(
                        mgmt_name=mgmt_name,
                        domain_name=dom_name,
                        scope="objects",
                        item_type=item_type,
                        last_published_at=probe.remote_published_at,
                        last_session_uid=probe.remote_session_uid,
                        synced_at=now,
                        status="ok",
                        object_count=len(uid_set),
                        last_error=None,
                    )
                )

            if fetched_objects:
                await self._cache.upsert_objects(fetched_objects, sync_states=sync_states)
            else:
                for st in sync_states:
                    await self._cache.upsert_sync_state(st)

            await emit(
                DomainSyncProgressEvent(
                    scope="objects",
                    mgmt_name=mgmt_name,
                    domain=dom_name,
                    item_type=",".join(probe.stale_types),
                    processed=total_changes,
                    total=total_changes,
                    message=(
                        f"Applied incremental diff on {mgmt_name}:{dom_name} "
                        f"({len(fetched_objects)} upserted, {len(deleted_uids)} deleted)."
                    ),
                )
            )
            return len(fetched_objects) + len(deleted_uids)
        except ServerIdentityError:
            raise
        except Exception:
            # Automatic fallback to full reload on any incremental diff error
            return None

    async def _full_reload_types(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        """Fetch all objects for `probe.stale_types` and atomically replace them in `arodonata_objects`."""
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name
        collected_by_type: dict[str, list[CPObject]] = {}
        all_collected: list[CPObject] = []

        for item_type in probe.stale_types:
            cmd, extra_payload = resolve_object_query_command(item_type)
            q_res = await self._api.api_query(
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

            typed_objs: list[CPObject] = []
            for raw in q_res.objects:
                if not isinstance(raw, dict) or not raw.get("uid"):
                    continue
                raw_copy = dict(raw)
                if not raw_copy.get("type"):
                    raw_copy["type"] = item_type
                cp_obj = CPObject.from_cp_dict(mgmt_name, dom_name, raw_copy)
                # Normalize type to requested item_type so replace_domain_objects matches
                if cp_obj.type != item_type:
                    cp_obj = cp_obj.model_copy(update={"type": item_type})
                typed_objs.append(cp_obj)

            collected_by_type[item_type] = typed_objs
            all_collected.extend(typed_objs)

            await emit(
                DomainSyncProgressEvent(
                    scope="objects",
                    mgmt_name=mgmt_name,
                    domain=dom_name,
                    item_type=item_type,
                    processed=len(typed_objs),
                    total=len(typed_objs),
                    message=f"Fetched {len(typed_objs)} {item_type} object(s) from {mgmt_name}:{dom_name}.",
                )
            )

        now = self._now()
        sync_states = [
            DomainSyncState(
                mgmt_name=mgmt_name,
                domain_name=dom_name,
                scope="objects",
                item_type=item_type,
                last_published_at=probe.remote_published_at,
                last_session_uid=probe.remote_session_uid,
                synced_at=now,
                status="ok",
                object_count=len(collected_by_type.get(item_type, [])),
                last_error=None,
            )
            for item_type in probe.stale_types
        ]
        await self._cache.replace_domain_objects(
            mgmt_name,
            dom_name,
            all_collected,
            types=probe.stale_types,
            sync_states=sync_states,
        )

        return len(all_collected)

    @traced
    async def get_objects(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Ensure requested object types are fresh (unless `cache_mode="cache"`), then return objects with active `WriteSession` overlay applied."""
        target_types = self._normalize_types(types) if types is not None else list(DEFAULT_OBJECT_TYPES)
        if cache_mode != "cache":
            await self.refresh_objects(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                types=target_types,
                include_global=include_global or (domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        cached = await self._cache.get_objects(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
            names=names,
            uids=uids,
        )
        if not include_global and domain is None:
            cached = [o for o in cached if o.domain_name != "Global"]

        return self.apply_context_overlay(
            cached,
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
            names=names,
            uids=uids,
        )

    @traced
    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain: str,
        uid: str,
        *,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | None:
        """Fetch a single `CPObject` by `(mgmt_name, domain, uid)`, checking active `WriteSession` overlay first."""
        ws = get_write_session(mgmt_name=mgmt_name, domain_name=domain)
        if ws is not None:
            touched, overlaid = ws.overlay.lookup_object_by_uid(uid)
            if touched:
                return overlaid

        if cache_mode != "cache":
            await self.refresh_objects(
                mgmt_name=mgmt_name,
                domains=[domain],
                include_global=(domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        obj = await self._cache.get_object_by_uid(mgmt_name, domain, uid)
        if obj is not None and ws is not None:
            merged = ws.overlay.apply_to_objects([obj])
            return merged[0] if merged else None
        return obj

    @staticmethod
    def apply_context_overlay(
        cached_objects: Sequence[CPObject],
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPObject]:
        """Merge active `WriteSession` overlay from `contextvars` onto `cached_objects`."""
        ws = get_write_session()
        if ws is None:
            return list(cached_objects)
        if mgmt_name is not None and ws.mgmt_name != mgmt_name:
            return list(cached_objects)
        if domain_name is not None and ws.domain_name != domain_name:
            return list(cached_objects)

        # Partition objects belonging to the WriteSession's (mgmt_name, domain_name) vs other domains
        in_scope: list[CPObject] = []
        out_of_scope: list[CPObject] = []
        for obj in cached_objects:
            if obj.mgmt_name == ws.mgmt_name and obj.domain_name == ws.domain_name:
                in_scope.append(obj)
            else:
                out_of_scope.append(obj)

        merged_scope = ws.overlay.apply_to_objects(in_scope, types=types)
        if names is not None:
            name_set = set(names)
            merged_scope = [o for o in merged_scope if o.name in name_set]
        if uids is not None:
            uid_set = set(uids)
            merged_scope = [o for o in merged_scope if o.uid in uid_set]

        return out_of_scope + merged_scope


__all__ = [
    "OBJECT_TYPE_TO_SHOW_COMMAND",
    "ObjectService",
    "extract_changes_from_show_changes",
    "resolve_object_query_command",
]
