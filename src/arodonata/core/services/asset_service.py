"""Asset and gateway cache synchronization service (`AssetRefreshService`).

Provides:
- Paired `await refresh_assets(...)` and `stream_refresh_assets(...)` methods.
- Concurrent per-MDS-member domain asset collection via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`).
- Re-exported `ClusterRelationshipManager` and `VSXRelationshipManager` relationship enrichers.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

import arlogi

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import LockAcquisitionError
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, expand_asset_types, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.ports import ApiPort, AssetCachePort
from arodonata.core.services._asset_linking import (
    CLUSTER_MEMBER_TYPES,
    CLUSTER_PARENT_TYPES,
    VSX_CHILD_TYPES,
    VSX_GENERIC_OBJECT_CLASSES,
    VSX_PARENT_TYPES,
    ClusterRelationshipManager,
    VSXRelationshipManager,
    _extract_interfaces_from_generic,
    _extract_vsx_parent_ref,
    _is_slot_object,
    _is_vsx_slot0_object,
    _link_parent_and_child_assets,
    _merge_vs_slot_data,
    _unwrap_object_list,
)
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced

logger = arlogi.get_logger(__name__)

_VSX_RECONCILE_LOCK_WAIT_TIMEOUT_S = 15.0

_REEXPORTED_LINKING_HELPERS = (
    CLUSTER_MEMBER_TYPES,
    CLUSTER_PARENT_TYPES,
    VSX_CHILD_TYPES,
    VSX_GENERIC_OBJECT_CLASSES,
    VSX_PARENT_TYPES,
    _extract_interfaces_from_generic,
    _extract_vsx_parent_ref,
    _is_slot_object,
    _is_vsx_slot0_object,
    _link_parent_and_child_assets,
    _merge_vs_slot_data,
    _unwrap_object_list,
)


def _open_reconcile_lock(provider: Any, key: str) -> Any:
    """Acquire a distributed reconcile lock waiting briefly when available."""
    try:
        return provider.lock(key, wait_timeout=_VSX_RECONCILE_LOCK_WAIT_TIMEOUT_S)
    except TypeError:
        return provider.lock(key)


def _normalize_classification_filter(values: Sequence[str] | str | None) -> set[str] | None:
    """Normalize optional `roles` / `platforms` filter inputs into a lowercase underscore set."""
    if values is None:
        return None
    items = [values] if isinstance(values, str) else list(values)
    return {str(v).strip().lower().replace("-", "_") for v in items if str(v or "").strip()}


class AssetRefreshService:
    """Synchronizes and queries cached gateway, cluster, VSX, and management server assets (`assets`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: AssetCachePort,
        coordinator: DomainSyncCoordinator,
        cluster_manager: ClusterRelationshipManager | None = None,
        vsx_manager: VSXRelationshipManager | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._cluster_manager = cluster_manager or ClusterRelationshipManager()
        self._vsx_manager = vsx_manager or VSXRelationshipManager(api)
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    @property
    def cluster_manager(self) -> ClusterRelationshipManager:
        """Return the `ClusterRelationshipManager`."""
        return self._cluster_manager

    @property
    def vsx_manager(self) -> VSXRelationshipManager:
        """Return the `VSXRelationshipManager`."""
        return self._vsx_manager

    async def _reconcile_cross_domain_vsx_for_mgmt(self, mgmt_name: str) -> None:
        lock_provider = getattr(self._coordinator, "_lock_port", None)
        lock_key = f"vsx-reconcile:{mgmt_name}"
        if lock_provider is not None and hasattr(lock_provider, "lock"):
            lock_ctx: Any = _open_reconcile_lock(lock_provider, lock_key)
        elif hasattr(self._cache, "lock"):
            lock_ctx = _open_reconcile_lock(self._cache, lock_key)
        else:
            lock_ctx = contextlib.nullcontext()
        try:
            async with lock_ctx:
                all_assets = await self._cache.get_assets(mgmt_name=mgmt_name)
                if not all_assets:
                    return
                orig_by_id = {a.id: a for a in all_assets}
                modified = self._vsx_manager.reconcile_cross_domain(all_assets)
                if modified:
                    updater = getattr(self._cache, "update_assets_vsx_links", None)
                    if callable(updater):
                        patches: list[tuple[str, datetime, dict[str, Any]]] = []
                        for upd in modified:
                            orig = orig_by_id.get(upd.id)
                            if orig is None:
                                continue
                            changed_cols: dict[str, Any] = {}
                            for field_name in (
                                "parent_uid",
                                "parent_name",
                                "parent_id",
                                "parent_asset_id",
                                "virtual_system_uids",
                                "virtual_system_asset_ids",
                                "interfaces",
                                "raw_data",
                            ):
                                new_val = getattr(upd, field_name)
                                if new_val != getattr(orig, field_name):
                                    changed_cols[field_name] = (
                                        list(new_val)
                                        if isinstance(new_val, list)
                                        else (dict(new_val) if isinstance(new_val, dict) else new_val)
                                    )
                            if changed_cols:
                                patches.append((upd.id, orig.updated_at, changed_cols))
                        if patches:
                            await updater(patches)
                    else:
                        await self._cache.upsert_assets(modified)
        except LockAcquisitionError as exc:
            logger.warning(
                f"Skipped cross-domain VSX reconciliation for '{mgmt_name}' because lock '{lock_key}' was busy: {exc}",
                mgmt_name=mgmt_name,
            )

    async def _reconcile_cross_domain_vsx(self, mgmt_name: str | None) -> None:
        """Reconcile cross-domain VSX parent/child relationships across cached domains."""
        if mgmt_name is not None:
            await self._reconcile_cross_domain_vsx_for_mgmt(mgmt_name)
            return
        all_assets = await self._cache.get_assets(mgmt_name=None)
        for m_name in sorted({a.mgmt_name for a in all_assets}):
            await self._reconcile_cross_domain_vsx_for_mgmt(m_name)

    async def stream_refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing gateway/cluster/VSX assets across domains."""
        wrote_any = False
        reconcile_attempted = False

        async def _handler(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            nonlocal wrote_any
            count = await self._sync_domain_assets(probe, emit)
            wrote_any = True
            return count

        try:
            async for event in self._coordinator.stream_ensure(
                scope="assets",
                item_types=["*"],
                handler=_handler,
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            ):
                if event.event_type == "sync_completed":
                    reconcile_attempted = True
                    if mode != "cache" and wrote_any:
                        await self._reconcile_cross_domain_vsx(mgmt_name)
                yield event
        finally:
            if mode != "cache" and wrote_any and not reconcile_attempted:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self._reconcile_cross_domain_vsx(mgmt_name))

    @traced
    async def refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh gateway/cluster/VSX assets across domains and return `RefreshOutcome`."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        wrote_any = False
        reconcile_attempted = False

        async def _handler(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            nonlocal wrote_any
            count = await self._sync_domain_assets(probe, emit)
            wrote_any = True
            return count

        try:
            outcome = await self._coordinator.ensure(
                scope="assets",
                item_types=["*"],
                handler=_handler,
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            )
            reconcile_attempted = True
            if mode != "cache" and wrote_any:
                await self._reconcile_cross_domain_vsx(mgmt_name)
            return outcome
        finally:
            if mode != "cache" and wrote_any and not reconcile_attempted:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self._reconcile_cross_domain_vsx(mgmt_name))

    async def _sync_domain_assets(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name

        q_res = await self._api.api_query(
            mgmt_name,
            "show-gateways-and-servers",
            domain=dom_name,
            details_level="full",
        )
        if not q_res.success:
            raise RuntimeError(
                f"Failed to query gateways and servers on {mgmt_name}:{dom_name}: "
                f"{q_res.error_message or q_res.code or 'query failed'}"
            )

        raw_assets: list[Asset] = []
        for raw in q_res.objects:
            if isinstance(raw, dict) and raw.get("uid"):
                raw_assets.append(Asset.from_cp_dict(mgmt_name, dom_name, raw))

        await emit(
            DomainSyncProgressEvent(
                scope="assets",
                mgmt_name=mgmt_name,
                domain=dom_name,
                item_type="gateways-and-servers",
                processed=len(raw_assets),
                total=len(raw_assets),
                message=f"Fetched {len(raw_assets)} raw asset(s) from {mgmt_name}:{dom_name}; resolving relationships.",
            )
        )

        cluster_enriched = self._cluster_manager.enrich(raw_assets)
        fully_enriched = await self._vsx_manager.enrich(mgmt_name, dom_name, cluster_enriched)

        synced_at = probe.probe_started_at or self._now()
        sync_state = DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope="assets",
            item_type="*",
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=synced_at,
            status="ok",
            object_count=len(fully_enriched),
            last_error=None,
        )
        await self._cache.replace_domain_assets(
            mgmt_name,
            dom_name,
            fully_enriched,
            sync_states=[sync_state],
        )
        return len(fully_enriched)

    @traced
    async def get_assets(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        roles: Sequence[str] | None = None,
        platforms: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[Asset]:
        """Ensure assets are fresh (unless `cache_mode="cache"`), then return cached `Asset` models."""
        expanded_types = expand_asset_types(types) if types is not None else None
        if expanded_types is not None and not expanded_types:
            return []
        role_set = _normalize_classification_filter(roles)
        platform_set = _normalize_classification_filter(platforms)
        if (role_set is not None and not role_set) or (platform_set is not None and not platform_set):
            return []

        if cache_mode != "cache":
            await self.refresh_assets(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                include_global=include_global or (domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        assets = await self._cache.get_assets(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=expanded_types,
        )
        if expanded_types is not None:
            lowered_set = {t.lower() for t in expanded_types}
            assets = [a for a in assets if a.type.lower() in lowered_set]
        if not include_global and domain is None:
            assets = [a for a in assets if a.domain_name != "Global"]
        if role_set is not None:
            assets = [a for a in assets if a.asset_role.lower() in role_set]
        if platform_set is not None:
            assets = [a for a in assets if a.platform_family.lower() in platform_set]
        return assets


__all__ = [
    "CLUSTER_MEMBER_TYPES",
    "CLUSTER_PARENT_TYPES",
    "VSX_CHILD_TYPES",
    "VSX_GENERIC_OBJECT_CLASSES",
    "VSX_PARENT_TYPES",
    "AssetRefreshService",
    "ClusterRelationshipManager",
    "VSXRelationshipManager",
]
