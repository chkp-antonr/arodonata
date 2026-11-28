"""Dedicated service object cache synchronization service (`ServiceCacheService`).

Provides:
- Paired `await refresh_services(...)` and `stream_refresh_services(...)` methods for `arodonata_services`.
- Default tracked service types `DEFAULT_SERVICE_TYPES = ("service-tcp", "service-udp", "service-icmp", "service-group")`.
- On-demand syncing of additional types via `types=[...]` (e.g. `types=["service-other"]`) using
  type-scoped replacement (`CachePort.replace_domain_services`) without wiping other cached service types.
- `"smart-fast"` incremental sync via `show-changes` with automatic fallback to type-scoped reload.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Collection, Sequence
from datetime import datetime
from typing import Any, Protocol

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.common import (
    DEFAULT_SERVICE_TYPES,
    CacheMode,
    normalize_service_type,
    partition_entity_types,
    to_naive_utc,
    utc_now,
)
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, ServiceCachePort, SyncStatePort
from arodonata.core.services._typed_cache_sync import (
    apply_typed_context_overlay,
    can_try_incremental,
    full_reload_types,
    try_incremental_sync,
)
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced


class _ServiceCachePort(ServiceCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `ServiceCacheService`."""


SERVICE_TYPE_TO_SHOW_COMMAND: dict[str, str] = {
    "service-tcp": "show-services-tcp",
    "service-udp": "show-services-udp",
    "service-icmp": "show-services-icmp",
    "service-icmp6": "show-services-icmp6",
    "service-group": "show-service-groups",
    "service-other": "show-services-other",
    "service-dce-rpc": "show-services-dce-rpc",
    "service-rpc": "show-services-rpc",
    "service-sctp": "show-services-sctp",
    "service-gtp": "show-services-gtp",
    "service-citrix-tcp": "show-services-citrix-tcp",
    "service-compound-tcp": "show-services-compound-tcp",
}


def resolve_service_query_command(item_type: str) -> tuple[str, dict[str, Any]]:
    """Map a service `item_type` to `(command, extra_payload)` for `api_query`."""
    clean = normalize_service_type(item_type)
    if clean in SERVICE_TYPE_TO_SHOW_COMMAND:
        return SERVICE_TYPE_TO_SHOW_COMMAND[clean], {}
    if clean.startswith("service-"):
        suffix = clean.removeprefix("service-")
        return f"show-services-{suffix}", {}
    return "show-objects", {"type": clean}


class ServiceCacheService:
    """Synchronizes and queries cached service objects (`arodonata_services`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: _ServiceCachePort,
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
            return list(DEFAULT_SERVICE_TYPES)
        return partition_entity_types(types, group_as_service=True).service_types

    async def stream_refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing service objects across domains."""
        target_types = self._normalize_types(types)
        if not target_types:
            return

        async def _sync_domain_services(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            if mode == "smart-fast" and self._can_try_incremental(probe):
                inc_count = await self._try_incremental_sync(probe, emit)
                if inc_count is not None:
                    return inc_count

            return await self._full_reload_types(probe, emit)

        async for event in self._coordinator.stream_ensure(
            scope="services",
            item_types=target_types,
            handler=_sync_domain_services,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    @traced
    async def refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh service objects across domains and return `RefreshOutcome`."""
        target_types = self._normalize_types(types)
        span_attrs(mgmt_name=mgmt_name, mode=mode, types=target_types, include_global=include_global)
        if not target_types:
            return RefreshOutcome(scope="services")

        async def _sync_domain_services(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            if mode == "smart-fast" and self._can_try_incremental(probe):
                inc_count = await self._try_incremental_sync(probe, emit)
                if inc_count is not None:
                    return inc_count

            return await self._full_reload_types(probe, emit)

        return await self._coordinator.ensure(
            scope="services",
            item_types=target_types,
            handler=_sync_domain_services,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    def _can_try_incremental(self, probe: DomainProbeResult) -> bool:
        return can_try_incremental(probe)

    async def _try_incremental_sync(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int | None:
        return await try_incremental_sync(
            scope="services",
            probe=probe,
            emit=emit,
            api=self._api,
            settings=self._settings,
            now_fn=self._now,
            model_from_cp_dict=CPService.from_cp_dict,
            get_cached_by_type=lambda m, d, types: self._cache.get_services(m, d, types=types),
            apply_diff_fn=lambda m, d, del_uids, svcs, states: self._cache.apply_service_diff(
                m, d, deleted_uids=del_uids, services=svcs, sync_states=states
            ),
        )

    async def _full_reload_types(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        """Fetch all service objects for `probe.stale_types` and atomically replace them in `arodonata_services`."""
        return await full_reload_types(
            scope="services",
            probe=probe,
            emit=emit,
            api=self._api,
            now_fn=self._now,
            resolve_command_fn=resolve_service_query_command,
            model_from_cp_dict=CPService.from_cp_dict,
            replace_domain_fn=lambda m, d, items, types, states: self._cache.replace_domain_services(
                m, d, items, types=types, sync_states=states
            ),
        )

    @traced
    async def get_services(
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
    ) -> list[CPService]:
        """Ensure requested service types are fresh (unless `cache_mode="cache"`), then return services with active `WriteSession` overlay applied."""
        norm_types = self._normalize_types(types) if types is not None else None
        if norm_types is not None and not norm_types:
            return []
        target_types = list(norm_types) if norm_types is not None else list(DEFAULT_SERVICE_TYPES)
        if cache_mode != "cache":
            await self.refresh_services(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                types=target_types,
                include_global=include_global or (domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        cached = await self._cache.get_services(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=norm_types,
            names=names,
            uids=uids,
        )
        if not include_global and domain is None:
            cached = [s for s in cached if s.domain_name != "Global"]

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
    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain: str,
        uid: str,
        *,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPService | None:
        """Fetch a single `CPService` by `(mgmt_name, domain, uid)`, checking active `WriteSession` overlay first."""
        ws = get_write_session(mgmt_name=mgmt_name, domain_name=domain)
        if ws is not None:
            touched, overlaid = ws.overlay.lookup_service_by_uid(uid)
            if touched:
                return overlaid

        if cache_mode != "cache":
            await self.refresh_services(
                mgmt_name=mgmt_name,
                domains=[domain],
                include_global=(domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        svc = await self._cache.get_service_by_uid(mgmt_name, domain, uid)
        if svc is not None and ws is not None:
            return ws.overlay.apply_to_single_service(svc)
        return svc

    @staticmethod
    def apply_context_overlay(
        cached_services: Sequence[CPService],
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        allowed_domains: Collection[str] | None = None,
        include_global: bool = True,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPService]:
        """Merge active `WriteSession` overlay from `contextvars` onto `cached_services`."""
        return apply_typed_context_overlay(
            cached_services,
            overlay_apply_fn=lambda ov, items, t: ov.apply_to_services(items, types=t),
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            allowed_domains=allowed_domains,
            include_global=include_global,
            types=types,
            names=names,
            uids=uids,
        )


__all__ = [
    "SERVICE_TYPE_TO_SHOW_COMMAND",
    "ServiceCacheService",
    "resolve_service_query_command",
]
