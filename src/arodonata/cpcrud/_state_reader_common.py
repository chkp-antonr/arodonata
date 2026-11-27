"""Shared constants, overlay helpers, and base state reader (`arodonata.cpcrud._state_reader_common`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Protocol

from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.models.common import SyncScope, to_naive_utc
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, ObjectCachePort, ServiceCachePort, SyncStatePort
from arodonata.core.primitives import mask_to_prefix_len
from arodonata.cpcrud._state_reader_constants import (
    OBJECT_ITEM_TYPES as OBJECT_ITEM_TYPES,
)
from arodonata.cpcrud._state_reader_constants import (
    SERVICE_ITEM_TYPES as SERVICE_ITEM_TYPES,
)
from arodonata.cpcrud._state_reader_constants import (
    TYPE_TO_SHOW_PLURAL_CMD as TYPE_TO_SHOW_PLURAL_CMD,
)
from arodonata.cpcrud._state_reader_constants import (
    TYPE_TO_SHOW_SINGLE_CMD as TYPE_TO_SHOW_SINGLE_CMD,
)
from arodonata.cpcrud._state_reader_constants import (
    StateLookupError as StateLookupError,
)
from arodonata.cpcrud._state_reader_constants import (
    is_not_found_error as is_not_found_error,
)
from arodonata.cpcrud._state_reader_constants import (
    normalize_app_site_url_key as normalize_app_site_url_key,
)
from arodonata.cpcrud.models import DomainStamp
from arodonata.rulebase.pager import PagedRulebaseResult


def normalize_mask_length(
    mask_length: int | float | str | None,
    subnet_mask: str | None = None,
    *,
    strict: bool = False,
) -> int | None:
    """Normalize a mask length or dotted-quad subnet mask into an integer prefix length (0..32).

    When `strict=True`, explicitly supplied invalid `mask_length` or `subnet_mask` values raise
    `ValidationError` instead of silently returning `None`.
    """
    if mask_length is not None:
        parsed = mask_to_prefix_len(mask_length)
        if parsed is not None:
            return parsed
        if strict:
            raise ValidationError(
                f"Invalid IPv4 mask_length4 value {mask_length!r}: expected prefix length 0..32 or contiguous netmask."
            )
    if subnet_mask is not None and str(subnet_mask).strip():
        parsed_sub = mask_to_prefix_len(subnet_mask, allow_prefix_int=False)
        if parsed_sub is not None:
            return parsed_sub
        if strict:
            raise ValidationError(
                f"Invalid IPv4 subnet_mask value {subnet_mask!r}: expected contiguous dotted-quad netmask."
            )
    return None


def _sync_state_matches_stamp(
    sync_state: DomainSyncState | None,
    stamp: DomainStamp | None,
) -> bool:
    """Return `True` iff `sync_state` is `"ok"` and matches `stamp`'s session UID and publish timestamp."""
    if sync_state is None or sync_state.status != "ok":
        return False
    if stamp is None or not stamp.readable:
        return False

    # Both last_published_at and last_session_uid must match when present on the stamp
    if stamp.last_session_uid is not None:
        if sync_state.last_session_uid != stamp.last_session_uid:
            return False
    elif sync_state.last_session_uid is not None:
        return False

    if stamp.last_published_at is not None:
        if to_naive_utc(sync_state.last_published_at) != to_naive_utc(stamp.last_published_at):
            return False
    elif sync_state.last_published_at is not None:
        return False

    # Require at least one non-None identifier on the stamp to trust the cache
    return stamp.last_session_uid is not None or stamp.last_published_at is not None


def _is_command_not_recognized(code: str | None, error_message: str | None) -> bool:
    """Return `True` when an adapter reports Check Point `generic_err_command_not_recognized`."""
    haystack = f"{code or ''} {error_message or ''}".lower()
    return "command_not_recognized" in haystack


def _apply_fetched_entity_overlay[T: (CPObject, CPService)](
    entity_type: str,
    fetched: T | None,
    del_set: set[str],
    virt_map: dict[str, T],
) -> T | None:
    """Reconcile a fetched cache/API entity against intra-plan virtual updates and deletions."""
    if fetched is None:
        return None
    if fetched.uid and f"uid:{fetched.uid}" in del_set:
        return None
    if fetched.uid:
        uid_override = virt_map.get(f"uid:{fetched.uid}")
        if uid_override is not None:
            return uid_override
    if f"name:{entity_type}:{fetched.name}" in del_set:
        return None
    name_override = virt_map.get(f"name:{entity_type}:{fetched.name}")
    if name_override is not None:
        return name_override
    return fetched


class _StateReaderCachePort(ObjectCachePort, ServiceCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `HybridStateReader`."""


class _HybridStateReaderBase:
    """Shared domain-stamp, slice-freshness, virtual-overlay, and `show-objects` plumbing."""

    def __init__(
        self,
        *,
        api: ApiPort,
        cache: _StateReaderCachePort,
        domain_stamps: dict[str, DomainStamp] | None = None,
    ) -> None:
        self._api = api
        self._cache = cache
        self._stamps: dict[str, DomainStamp] = dict(domain_stamps or {})

        # Memoized cache-eligibility decisions per (mgmt_name, domain_name, scope, item_type)
        self._slice_fresh_memo: dict[tuple[str, str, str, str], bool] = {}

        # Memoized live listings per (mgmt_name, domain_name, item_type) to avoid redundant full queries in one plan
        self._live_objects_memo: dict[tuple[str, str, str], list[CPObject]] = {}
        self._live_services_memo: dict[tuple[str, str, str], list[CPService]] = {}

        # Memoized targeted `show-objects` queries per (mgmt_name, domain_name, obj_type, filter_text, ip_only)
        self._filtered_objects_memo: dict[tuple[str, str, str, str, bool], list[dict[str, Any]]] = {}

        # Memoized rulebases per (mgmt_name, domain_name, rulebase_type, layer_or_pkg)
        self._rulebase_memo: dict[tuple[str, str, str, str], PagedRulebaseResult] = {}

        # Intra-plan virtual state overlay keyed by (mgmt_name, domain_name)
        self._virtual_objects: dict[tuple[str, str], dict[str, CPObject]] = {}
        self._deleted_objects: dict[tuple[str, str], set[str]] = {}
        self._virtual_services: dict[tuple[str, str], dict[str, CPService]] = {}
        self._deleted_services: dict[tuple[str, str], set[str]] = {}
        # Intra-plan virtual rulebase overlay keyed by (mgmt_name, domain_name, rulebase_type, layer_or_pkg)
        self._virtual_rules: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._deleted_rules: dict[tuple[str, str, str, str], set[str]] = {}

    def set_domain_stamp(self, stamp: DomainStamp) -> None:
        """Record or update a `DomainStamp` for `(stamp.mgmt_name, stamp.domain_name)`."""
        self._stamps[stamp.key] = stamp

    def get_domain_stamp(self, mgmt_name: str, domain_name: str = "") -> DomainStamp | None:
        """Return the recorded `DomainStamp` for `(mgmt_name, domain_name)`."""
        return self._stamps.get(f"{mgmt_name}:{domain_name}")

    async def is_slice_cache_fresh(
        self,
        mgmt_name: str,
        domain_name: str,
        scope: SyncScope,
        item_type: str,
    ) -> bool:
        """Check whether `(mgmt_name, domain_name, scope, item_type)` in `domain_sync_state` matches `DomainStamp`."""
        memo_key = (mgmt_name, domain_name, scope, item_type)
        if memo_key in self._slice_fresh_memo:
            return self._slice_fresh_memo[memo_key]

        stamp = self.get_domain_stamp(mgmt_name, domain_name)
        if stamp is None or not stamp.readable:
            self._slice_fresh_memo[memo_key] = False
            return False

        try:
            sync_state = await self._cache.get_sync_state(mgmt_name, domain_name, scope, item_type)
        except Exception as exc:
            raise StateLookupError(
                f"Failed to read domain_sync_state for {mgmt_name}:{domain_name} ({scope}/{item_type}): {exc}"
            ) from exc

        fresh = _sync_state_matches_stamp(sync_state, stamp)
        self._slice_fresh_memo[memo_key] = fresh
        return fresh

    # ------------------------------------------------------------------
    # Intra-plan Virtual Overlay Recording
    # ------------------------------------------------------------------

    def record_virtual_object(self, obj: CPObject, *, previous_name: str | None = None) -> None:
        """Record an object planned for creation or update within the current `plan()` run."""
        dom_key = (obj.mgmt_name, obj.domain_name)
        bucket = self._virtual_objects.setdefault(dom_key, {})
        deleted = self._deleted_objects.setdefault(dom_key, set())
        if previous_name and previous_name != obj.name:
            deleted.add(f"name:{obj.type}:{previous_name}")
            bucket.pop(f"name:{obj.type}:{previous_name}", None)
        bucket[f"name:{obj.type}:{obj.name}"] = obj
        if obj.uid:
            bucket[f"uid:{obj.uid}"] = obj
            deleted.discard(f"uid:{obj.uid}")
        deleted.discard(f"name:{obj.type}:{obj.name}")

    def record_virtual_object_delete(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        obj_type: str,
        name: str | None = None,
        uid: str | None = None,
    ) -> None:
        """Record an object planned for deletion within the current `plan()` run."""
        dom_key = (mgmt_name, domain_name)
        bucket = self._virtual_objects.setdefault(dom_key, {})
        deleted = self._deleted_objects.setdefault(dom_key, set())
        if name:
            deleted.add(f"name:{obj_type}:{name}")
            bucket.pop(f"name:{obj_type}:{name}", None)
        if uid:
            deleted.add(f"uid:{uid}")
            bucket.pop(f"uid:{uid}", None)

    def record_virtual_service(self, svc: CPService, *, previous_name: str | None = None) -> None:
        """Record a service planned for creation or update within the current `plan()` run."""
        dom_key = (svc.mgmt_name, svc.domain_name)
        bucket = self._virtual_services.setdefault(dom_key, {})
        deleted = self._deleted_services.setdefault(dom_key, set())
        if previous_name and previous_name != svc.name:
            deleted.add(f"name:{svc.type}:{previous_name}")
            bucket.pop(f"name:{svc.type}:{previous_name}", None)
        bucket[f"name:{svc.type}:{svc.name}"] = svc
        if svc.uid:
            bucket[f"uid:{svc.uid}"] = svc
            deleted.discard(f"uid:{svc.uid}")
        deleted.discard(f"name:{svc.type}:{svc.name}")

    def record_virtual_service_delete(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        svc_type: str,
        name: str | None = None,
        uid: str | None = None,
    ) -> None:
        """Record a service planned for deletion within the current `plan()` run."""
        dom_key = (mgmt_name, domain_name)
        bucket = self._virtual_services.setdefault(dom_key, {})
        deleted = self._deleted_services.setdefault(dom_key, set())
        if name:
            deleted.add(f"name:{svc_type}:{name}")
            bucket.pop(f"name:{svc_type}:{name}", None)
        if uid:
            deleted.add(f"uid:{uid}")
            bucket.pop(f"uid:{uid}", None)

    def record_virtual_rule(
        self,
        mgmt_name: str,
        domain_name: str,
        rulebase_type: str,
        target_key: str,
        rule: Any,
        *,
        previous_name: str | None = None,
    ) -> None:
        """Record a rule planned for creation or update within the current `plan()` run."""
        rb_key = (mgmt_name, domain_name, rulebase_type, target_key)
        bucket = self._virtual_rules.setdefault(rb_key, {})
        deleted = self._deleted_rules.setdefault(rb_key, set())
        if previous_name and previous_name != rule.name:
            deleted.add(f"name:{previous_name}")
            bucket.pop(f"name:{previous_name}", None)
        if rule.name:
            bucket[f"name:{rule.name}"] = rule
            deleted.discard(f"name:{rule.name}")
        if rule.uid:
            bucket[f"uid:{rule.uid}"] = rule
            deleted.discard(f"uid:{rule.uid}")

    def record_virtual_rule_delete(
        self,
        mgmt_name: str,
        domain_name: str,
        rulebase_type: str,
        target_key: str,
        *,
        uid: str | None = None,
        name: str | None = None,
    ) -> None:
        """Record a rule planned for deletion within the current `plan()` run."""
        rb_key = (mgmt_name, domain_name, rulebase_type, target_key)
        bucket = self._virtual_rules.setdefault(rb_key, {})
        deleted = self._deleted_rules.setdefault(rb_key, set())
        if name:
            deleted.add(f"name:{name}")
            bucket.pop(f"name:{name}", None)
        if uid:
            deleted.add(f"uid:{uid}")
            bucket.pop(f"uid:{uid}", None)

    def is_entity_virtually_deleted(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        uid: str | None = None,
        name: str | None = None,
        entity_type: str | None = None,
    ) -> bool:
        """Return `True` if `(uid, name)` was already marked deleted in this run's virtual overlay."""
        dom_key = (mgmt_name, domain_name)
        del_sets = (
            self._deleted_objects.get(dom_key, set()),
            self._deleted_services.get(dom_key, set()),
        )
        for del_set in del_sets:
            if uid and f"uid:{uid}" in del_set:
                return True
            if name:
                if entity_type and f"name:{entity_type}:{name}" in del_set:
                    return True
                suffix = f":{name}"
                if any(entry.startswith("name:") and entry.endswith(suffix) for entry in del_set):
                    return True
        return False

    @staticmethod
    def _merge_entity_overlay[T: (CPObject, CPService)](
        entity_type: str,
        base_list: list[T],
        del_set: set[str],
        virt_map: dict[str, T],
    ) -> list[T]:
        """Merge intra-plan virtual creations, updates, and deletions onto `base_list`."""
        result: list[T] = []
        seen_names: set[str] = set()
        for item in base_list:
            if (item.uid and f"uid:{item.uid}" in del_set) or f"name:{entity_type}:{item.name}" in del_set:
                continue
            override = (virt_map.get(f"uid:{item.uid}") if item.uid else None) or virt_map.get(
                f"name:{entity_type}:{item.name}"
            )
            if override is not None:
                if override.name not in seen_names:
                    result.append(override)
                    seen_names.add(override.name)
            elif item.name not in seen_names:
                result.append(item)
                seen_names.add(item.name)

        for key, virt_item in virt_map.items():
            if key.startswith(f"name:{entity_type}:") and virt_item.name not in seen_names:
                result.append(virt_item)
                seen_names.add(virt_item.name)

        return result

    def _merge_object_overlay(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        base_list: list[CPObject],
    ) -> list[CPObject]:
        """Merge intra-plan virtual creations, updates, and deletions onto `base_list`."""
        dom_key = (mgmt_name, domain_name)
        return self._merge_entity_overlay(
            obj_type,
            base_list,
            self._deleted_objects.get(dom_key, set()),
            self._virtual_objects.get(dom_key, {}),
        )

    def _merge_service_overlay(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        base_list: list[CPService],
    ) -> list[CPService]:
        """Merge intra-plan virtual service creations, updates, and deletions onto `base_list`."""
        dom_key = (mgmt_name, domain_name)
        return self._merge_entity_overlay(
            svc_type,
            base_list,
            self._deleted_services.get(dom_key, set()),
            self._virtual_services.get(dom_key, {}),
        )

    async def _query_filtered_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        obj_type: str,
        filter_text: str,
        ip_only: bool = False,
    ) -> list[dict[str, Any]] | None:
        """Query `show-objects` for cold-cache value lookups; returns `None` on `command_not_recognized`."""
        memo_key = (mgmt_name, domain_name, obj_type, filter_text, ip_only)
        if memo_key in self._filtered_objects_memo:
            return list(self._filtered_objects_memo[memo_key])

        query_payload: dict[str, Any] = {"type": obj_type, "filter": filter_text}
        if ip_only:
            query_payload["ip-only"] = True

        try:
            q_res = await self._api.api_query(
                mgmt_name,
                "show-objects",
                domain=domain_name or None,
                details_level="standard",
                payload=query_payload,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(f"Live API query (show-objects) failed in {mgmt_name}:{domain_name}: {exc}") from exc

        if not q_res.success:
            if _is_command_not_recognized(q_res.code, q_res.error_message):
                return None
            reason = q_res.error_message or q_res.code or "show-objects query failed"
            raise StateLookupError(f"Live API query (show-objects) failed in {mgmt_name}:{domain_name}: {reason}")

        if q_res.code == "paging_inconsistent":
            reason = q_res.error_message or q_res.code
            raise StateLookupError(f"Live API query (show-objects) failed in {mgmt_name}:{domain_name}: {reason}")

        raw_items = [raw for raw in q_res.objects if isinstance(raw, dict)]
        self._filtered_objects_memo[memo_key] = list(raw_items)
        return raw_items

    async def _live_single_lookup(
        self,
        mgmt_name: str,
        domain_name: str,
        entity_type: str,
        payload: dict[str, Any],
        label: str,
    ) -> dict[str, Any] | None:
        """Invoke `show-<type>` with single-key `payload`; returns `None` on not-found."""
        cmd = TYPE_TO_SHOW_SINGLE_CMD[entity_type]
        try:
            res = await self._api.api_call(mgmt_name, cmd, payload, domain=domain_name or None)
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(
                f"Live API lookup ({cmd}) failed for {label} in {mgmt_name}:{domain_name}: {exc}"
            ) from exc
        if not res.success:
            if is_not_found_error(res.status_code, res.error_code, res.error_message):
                return None
            raise StateLookupError(
                f"Live API lookup ({cmd}) failed for {label} in {mgmt_name}:{domain_name}: "
                f"{res.error_message or res.error_code or f'HTTP {res.status_code}'}"
            )
        return res.data if isinstance(res.data, dict) and res.data else None

    async def _get_entity_by_name[T: (CPObject, CPService)](
        self,
        mgmt_name: str,
        domain_name: str,
        entity_type: str,
        name: str,
        *,
        valid_types: frozenset[str],
        invalid_type_label: str,
        scope: SyncScope,
        deleted_store: dict[tuple[str, str], set[str]],
        virtual_store: dict[tuple[str, str], dict[str, T]],
        cache_fetch_by_names: Callable[[list[str]], Awaitable[Sequence[T]]],
        parser: Callable[[dict[str, Any]], T],
        allow_dot_domain_fallback: bool = False,
    ) -> T | None:
        """Shared cache-first + live API + overlay name lookup for objects and services."""
        if entity_type not in valid_types:
            raise ValidationError(f"Unsupported CPCRUD {invalid_type_label} type: {entity_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = deleted_store.get(dom_key, set())
        virt_map = virtual_store.get(dom_key, {})
        if f"name:{entity_type}:{name}" in del_set:
            return None
        virt = virt_map.get(f"name:{entity_type}:{name}")
        if virt is not None:
            return virt

        dot_fallback = allow_dot_domain_fallback and entity_type == "dns-domain" and not name.startswith(".")
        if await self.is_slice_cache_fresh(mgmt_name, domain_name, scope, entity_type):
            lookup_names = [name, f".{name}"] if dot_fallback else [name]
            try:
                items = await cache_fetch_by_names(lookup_names)
            except Exception as exc:
                raise StateLookupError(
                    f"Cache lookup failed for {entity_type} {name!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            for target_name in lookup_names:
                if target_name != name:
                    if f"name:dns-domain:{target_name}" in del_set:
                        return None
                    if (dot_virt := virt_map.get(f"name:dns-domain:{target_name}")) is not None:
                        return dot_virt
                for item in items:
                    if (
                        item.name == target_name
                        and (resolved := _apply_fetched_entity_overlay(entity_type, item, del_set, virt_map))
                        is not None
                    ):
                        return resolved
            return None

        raw = await self._live_single_lookup(mgmt_name, domain_name, entity_type, {"name": name}, f"{name!r}")
        if raw is None and dot_fallback:
            dot_name = f".{name}"
            if f"name:dns-domain:{dot_name}" in del_set:
                return None
            dot_virt = virt_map.get(f"name:dns-domain:{dot_name}")
            if dot_virt is not None:
                return dot_virt
            raw = await self._live_single_lookup(mgmt_name, domain_name, entity_type, {"name": dot_name}, f".{name!r}")
        return _apply_fetched_entity_overlay(entity_type, parser(raw), del_set, virt_map) if raw is not None else None

    async def _get_entity_by_uid[T: (CPObject, CPService)](
        self,
        mgmt_name: str,
        domain_name: str,
        entity_type: str,
        uid: str,
        *,
        valid_types: frozenset[str],
        invalid_type_label: str,
        scope: SyncScope,
        deleted_store: dict[tuple[str, str], set[str]],
        virtual_store: dict[tuple[str, str], dict[str, T]],
        cache_fetch_by_uid: Callable[[], Awaitable[T | None]],
        parser: Callable[[dict[str, Any]], T],
    ) -> T | None:
        """Shared cache-first + live API + overlay UID lookup for objects and services."""
        if entity_type not in valid_types:
            raise ValidationError(f"Unsupported CPCRUD {invalid_type_label} type: {entity_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = deleted_store.get(dom_key, set())
        virt_map = virtual_store.get(dom_key, {})
        if f"uid:{uid}" in del_set:
            return None
        virt = virt_map.get(f"uid:{uid}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, scope, entity_type):
            try:
                item = await cache_fetch_by_uid()
            except Exception as exc:
                raise StateLookupError(
                    f"Cache UID lookup failed for {entity_type} {uid!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            if item is not None and item.type == entity_type:
                return _apply_fetched_entity_overlay(entity_type, item, del_set, virt_map)
            return None

        raw = await self._live_single_lookup(mgmt_name, domain_name, entity_type, {"uid": uid}, f"{uid!r}")
        return _apply_fetched_entity_overlay(entity_type, parser(raw), del_set, virt_map) if raw is not None else None

    async def _candidates_for_entity_value_lookup[T: (CPObject, CPService)](
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        entity_type: str,
        filter_text: str,
        ip_only: bool,
        valid_types: frozenset[str],
        invalid_type_label: str,
        scope: SyncScope,
        live_memo: dict[tuple[str, str, str], list[T]],
        deleted_store: dict[tuple[str, str], set[str]],
        virtual_store: dict[tuple[str, str], dict[str, T]],
        list_all: Callable[[], Awaitable[list[T]]],
        parser: Callable[[dict[str, Any]], T],
    ) -> list[T]:
        """Shared candidate lookup from fresh cache, live memo, or targeted `show-objects`."""
        if entity_type not in valid_types:
            raise ValidationError(f"Unsupported CPCRUD {invalid_type_label} type: {entity_type!r}")
        if (
            await self.is_slice_cache_fresh(mgmt_name, domain_name, scope, entity_type)
            or (mgmt_name, domain_name, entity_type) in live_memo
        ):
            return await list_all()

        raw_items = await self._query_filtered_objects(
            mgmt_name,
            domain_name,
            obj_type=entity_type,
            filter_text=filter_text,
            ip_only=ip_only,
        )
        if raw_items is None:
            return await list_all()

        base_list = [parser(raw) for raw in raw_items]
        dom_key = (mgmt_name, domain_name)
        return self._merge_entity_overlay(
            entity_type,
            base_list,
            deleted_store.get(dom_key, set()),
            virtual_store.get(dom_key, {}),
        )

    async def _list_entities_of_type[T: (CPObject, CPService)](
        self,
        mgmt_name: str,
        domain_name: str,
        entity_type: str,
        *,
        valid_types: frozenset[str],
        invalid_type_label: str,
        scope: SyncScope,
        live_memo: dict[tuple[str, str, str], list[T]],
        deleted_store: dict[tuple[str, str], set[str]],
        virtual_store: dict[tuple[str, str], dict[str, T]],
        cache_list: Callable[[], Awaitable[list[T]]],
        parser: Callable[[dict[str, Any]], T],
    ) -> list[T]:
        """Shared full type listing from fresh cache or memoized live `api_query` with overlay."""
        if entity_type not in valid_types:
            raise ValidationError(f"Unsupported CPCRUD {invalid_type_label} type: {entity_type!r}")

        base_list: list[T]
        if await self.is_slice_cache_fresh(mgmt_name, domain_name, scope, entity_type):
            try:
                base_list = await cache_list()
            except Exception as exc:
                raise StateLookupError(
                    f"Cache listing failed for {entity_type} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
        else:
            memo_key = (mgmt_name, domain_name, entity_type)
            if memo_key in live_memo:
                base_list = list(live_memo[memo_key])
            else:
                plural_cmd = TYPE_TO_SHOW_PLURAL_CMD[entity_type]
                try:
                    q_res = await self._api.api_query(
                        mgmt_name,
                        plural_cmd,
                        domain=domain_name or None,
                        details_level="standard",
                    )
                except ServerIdentityError:
                    raise
                except Exception as exc:
                    raise StateLookupError(
                        f"Live API query ({plural_cmd}) failed in {mgmt_name}:{domain_name}: {exc}"
                    ) from exc

                if not q_res.success or q_res.code == "paging_inconsistent":
                    reason = q_res.error_message or q_res.code or f"{plural_cmd} query failed"
                    raise StateLookupError(
                        f"Live API query ({plural_cmd}) failed in {mgmt_name}:{domain_name}: {reason}"
                    )

                base_list = [parser(raw) for raw in q_res.objects if isinstance(raw, dict)]
                live_memo[memo_key] = list(base_list)

        dom_key = (mgmt_name, domain_name)
        return self._merge_entity_overlay(
            entity_type,
            base_list,
            deleted_store.get(dom_key, set()),
            virtual_store.get(dom_key, {}),
        )
