"""Dedicated service object cache synchronization service (`ServiceCacheService`).

Provides:
- Paired `await refresh_services(...)` and `stream_refresh_services(...)` methods for `arodonata_services`.
- Default tracked service types `DEFAULT_SERVICE_TYPES = ("service-tcp", "service-udp", "service-icmp", "service-group")`.
- On-demand syncing of additional types via `types=[...]` (e.g. `types=["service-other"]`) using
  type-scoped replacement (`CachePort.replace_domain_services`) without wiping other cached service types.
- `"smart-fast"` incremental sync via `show-changes` with automatic fallback to type-scoped reload.
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
    DEFAULT_SERVICE_TYPES,
    CacheMode,
    to_naive_utc,
    utc_now,
)
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.object_service import extract_changes_from_show_changes
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced

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
    clean = item_type.strip().lower()
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
            return list(DEFAULT_SERVICE_TYPES)
        seen: list[str] = []
        for t in types:
            clean = str(t).strip().lower()
            if clean and clean not in seen:
                seen.append(clean)
        return seen or list(DEFAULT_SERVICE_TYPES)

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
                return None

            if deleted_uids:
                await self._cache.delete_services_by_uids(mgmt_name, dom_name, deleted_uids)

            fetched_services: list[CPService] = []
            for uid, _hint_type in upserts_meta:
                svc_res = await self._api.api_call(
                    mgmt_name,
                    "show-object",
                    {"uid": uid, "details-level": "full"},
                    domain=dom_name,
                )
                if not svc_res.success:
                    return None
                raw_svc = svc_res.data.get("object") if isinstance(svc_res.data.get("object"), dict) else svc_res.data
                if not isinstance(raw_svc, dict) or not raw_svc.get("uid"):
                    return None
                cp_svc = CPService.from_cp_dict(mgmt_name, dom_name, raw_svc)
                if cp_svc.type in stale_set:
                    fetched_services.append(cp_svc)

            now = self._now()
            existing_by_type: dict[str, list[CPService]] = {}
            for item_type in probe.stale_types:
                existing_by_type[item_type] = await self._cache.get_services(mgmt_name, dom_name, types=[item_type])

            fetched_by_type: dict[str, dict[str, CPService]] = {t: {} for t in probe.stale_types}
            for svc in fetched_services:
                if svc.type in fetched_by_type:
                    fetched_by_type[svc.type][svc.uid] = svc

            sync_states: list[DomainSyncState] = []
            for item_type in probe.stale_types:
                uid_set = {s.uid for s in existing_by_type.get(item_type, [])}
                uid_set.update(fetched_by_type.get(item_type, {}).keys())
                sync_states.append(
                    DomainSyncState(
                        mgmt_name=mgmt_name,
                        domain_name=dom_name,
                        scope="services",
                        item_type=item_type,
                        last_published_at=probe.remote_published_at,
                        last_session_uid=probe.remote_session_uid,
                        synced_at=now,
                        status="ok",
                        object_count=len(uid_set),
                        last_error=None,
                    )
                )

            if fetched_services:
                await self._cache.upsert_services(fetched_services, sync_states=sync_states)
            else:
                for st in sync_states:
                    await self._cache.upsert_sync_state(st)

            await emit(
                DomainSyncProgressEvent(
                    scope="services",
                    mgmt_name=mgmt_name,
                    domain=dom_name,
                    item_type=",".join(probe.stale_types),
                    processed=total_changes,
                    total=total_changes,
                    message=(
                        f"Applied incremental service diff on {mgmt_name}:{dom_name} "
                        f"({len(fetched_services)} upserted, {len(deleted_uids)} deleted)."
                    ),
                )
            )
            return len(fetched_services) + len(deleted_uids)
        except ServerIdentityError:
            raise
        except Exception:
            return None

    async def _full_reload_types(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        """Fetch all service objects for `probe.stale_types` and atomically replace them in `arodonata_services`."""
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name
        collected_by_type: dict[str, list[CPService]] = {}
        all_collected: list[CPService] = []

        for item_type in probe.stale_types:
            cmd, extra_payload = resolve_service_query_command(item_type)
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

            typed_svcs: list[CPService] = []
            for raw in q_res.objects:
                if not isinstance(raw, dict) or not raw.get("uid"):
                    continue
                raw_copy = dict(raw)
                if not raw_copy.get("type"):
                    raw_copy["type"] = item_type
                cp_svc = CPService.from_cp_dict(mgmt_name, dom_name, raw_copy)
                if cp_svc.type != item_type:
                    cp_svc = cp_svc.model_copy(update={"type": item_type})
                typed_svcs.append(cp_svc)

            collected_by_type[item_type] = typed_svcs
            all_collected.extend(typed_svcs)

            await emit(
                DomainSyncProgressEvent(
                    scope="services",
                    mgmt_name=mgmt_name,
                    domain=dom_name,
                    item_type=item_type,
                    processed=len(typed_svcs),
                    total=len(typed_svcs),
                    message=f"Fetched {len(typed_svcs)} {item_type} service(s) from {mgmt_name}:{dom_name}.",
                )
            )

        now = self._now()
        sync_states = [
            DomainSyncState(
                mgmt_name=mgmt_name,
                domain_name=dom_name,
                scope="services",
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
        await self._cache.replace_domain_services(
            mgmt_name,
            dom_name,
            all_collected,
            types=probe.stale_types,
            sync_states=sync_states,
        )

        return len(all_collected)

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
        target_types = self._normalize_types(types) if types is not None else list(DEFAULT_SERVICE_TYPES)
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
            types=types,
            names=names,
            uids=uids,
        )
        if not include_global and domain is None:
            cached = [s for s in cached if s.domain_name != "Global"]

        return self.apply_context_overlay(
            cached,
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
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
            merged = ws.overlay.apply_to_services([svc])
            return merged[0] if merged else None
        return svc

    @staticmethod
    def apply_context_overlay(
        cached_services: Sequence[CPService],
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPService]:
        """Merge active `WriteSession` overlay from `contextvars` onto `cached_services`."""
        ws = get_write_session()
        if ws is None:
            return list(cached_services)
        if mgmt_name is not None and ws.mgmt_name != mgmt_name:
            return list(cached_services)
        if domain_name is not None and ws.domain_name != domain_name:
            return list(cached_services)

        in_scope: list[CPService] = []
        out_of_scope: list[CPService] = []
        for svc in cached_services:
            if svc.mgmt_name == ws.mgmt_name and svc.domain_name == ws.domain_name:
                in_scope.append(svc)
            else:
                out_of_scope.append(svc)

        merged_scope = ws.overlay.apply_to_services(in_scope, types=types)
        if names is not None:
            name_set = set(names)
            merged_scope = [s for s in merged_scope if s.name in name_set]
        if uids is not None:
            uid_set = set(uids)
            merged_scope = [s for s in merged_scope if s.uid in uid_set]

        return out_of_scope + merged_scope


__all__ = [
    "SERVICE_TYPE_TO_SHOW_COMMAND",
    "ServiceCacheService",
    "resolve_service_query_command",
]
