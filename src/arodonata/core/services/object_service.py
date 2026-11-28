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

from collections.abc import AsyncIterator, Awaitable, Callable, Collection, Sequence
from datetime import datetime
from typing import Any, Protocol

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.common import (
    DEFAULT_OBJECT_TYPES,
    CacheMode,
    normalize_object_type,
    partition_entity_types,
    to_naive_utc,
    utc_now,
)
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.ports import ApiPort, ObjectCachePort, SyncStatePort
from arodonata.core.services._typed_cache_sync import (
    apply_typed_context_overlay,
    can_try_incremental,
    extract_changes_from_show_changes,
    full_reload_types,
    try_incremental_sync,
)
from arodonata.core.services._typed_cache_sync import (
    unwrap_change_item as _unwrap_change_item,
)
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced


class _ObjectServiceCachePort(ObjectCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `ObjectService`."""


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
    "application-site": "show-application-sites",
}


def resolve_object_query_command(item_type: str) -> tuple[str, dict[str, Any]]:
    """Map an object `item_type` to `(command, extra_payload)` for `api_query`."""
    clean = normalize_object_type(item_type)
    if clean in OBJECT_TYPE_TO_SHOW_COMMAND:
        return OBJECT_TYPE_TO_SHOW_COMMAND[clean], {}
    return "show-objects", {"type": clean}


# Re-export extract_changes_from_show_changes and _unwrap_change_item for compatibility.
_COMPAT_CHANGE_HELPERS = (_unwrap_change_item, extract_changes_from_show_changes)


class ObjectService:
    """Synchronizes and queries cached network objects (`arodonata_objects`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: _ObjectServiceCachePort,
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
        return partition_entity_types(types).object_types

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
        if not target_types:
            return

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
        if not target_types:
            return RefreshOutcome(scope="objects")

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
        return can_try_incremental(probe)

    async def _try_incremental_sync(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int | None:
        """Attempt incremental refresh via `show-changes`; return `None` to fall back to full reload."""
        return await try_incremental_sync(
            scope="objects",
            probe=probe,
            emit=emit,
            api=self._api,
            settings=self._settings,
            now_fn=self._now,
            model_from_cp_dict=CPObject.from_cp_dict,
            get_cached_by_type=lambda m, d, types: self._cache.get_objects(m, d, types=types),
            apply_diff_fn=lambda m, d, del_uids, objs, states: self._cache.apply_object_diff(
                m, d, deleted_uids=del_uids, objects=objs, sync_states=states
            ),
        )

    async def _full_reload_types(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        """Fetch all objects for `probe.stale_types` and atomically replace them in `arodonata_objects`."""
        return await full_reload_types(
            scope="objects",
            probe=probe,
            emit=emit,
            api=self._api,
            now_fn=self._now,
            resolve_command_fn=resolve_object_query_command,
            model_from_cp_dict=CPObject.from_cp_dict,
            replace_domain_fn=lambda m, d, items, types, states: self._cache.replace_domain_objects(
                m, d, items, types=types, sync_states=states
            ),
        )

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
        norm_types = self._normalize_types(types) if types is not None else None
        if norm_types is not None and not norm_types:
            return []
        target_types = list(norm_types) if norm_types is not None else list(DEFAULT_OBJECT_TYPES)
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
            types=norm_types,
            names=names,
            uids=uids,
        )
        if not include_global and domain is None:
            cached = [o for o in cached if o.domain_name != "Global"]

        return self.apply_context_overlay(
            cached,
            mgmt_name=mgmt_name,
            domain_name=domain,
            include_global=include_global,
            types=norm_types,
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
            return ws.overlay.apply_to_single_object(obj)
        return obj

    @staticmethod
    def apply_context_overlay(
        cached_objects: Sequence[CPObject],
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        allowed_domains: Collection[str] | None = None,
        include_global: bool = True,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPObject]:
        """Merge active `WriteSession` overlay from `contextvars` onto `cached_objects`."""
        return apply_typed_context_overlay(
            cached_objects,
            overlay_apply_fn=lambda ov, items, t: ov.apply_to_objects(items, types=t),
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            allowed_domains=allowed_domains,
            include_global=include_global,
            types=types,
            names=names,
            uids=uids,
        )


__all__ = [
    "OBJECT_TYPE_TO_SHOW_COMMAND",
    "ObjectService",
    "extract_changes_from_show_changes",
    "resolve_object_query_command",
]
