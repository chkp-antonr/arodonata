"""Gateway interface topology extraction, caching, and affected gateway candidate matching (`TopologyService`)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.scripts import (
    CpridScriptMode,
    EnsureRepositoryScriptResult,
    RepositoryScriptStatus,
)
from arodonata.core.models.topology import (
    AffectedGatewayCandidate,
    ExportedTopologyPrefix,
    GatewayInterfaceSummary,
    GatewayTopologyEntry,
    RouteCollectionOutcome,
    TopologyAnnotation,
    TopologyDiagnostic,
    TopologyDiagnosticSeverity,
    TopologyReconciliationReport,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import (
    ApiPort,
    GatewayCliCallable,
    GatewayCliPort,
    RulebaseRefreshPort,
)
from arodonata.core.primitives import parse_cidr_or_range_bounds
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.script_service import ScriptRepositoryService
from arodonata.core.services.sync_coordinator import DomainSyncCoordinator, resolve_engine_registry
from arodonata.core.services.topology import (
    diagnostics as _diagnostics,
)
from arodonata.core.services.topology import (
    extractor as _extractor,
)
from arodonata.core.services.topology import (
    objects as _objects,
)
from arodonata.core.services.topology import (
    policy_matcher as _policy_matcher,
)
from arodonata.core.services.topology import (
    policy_rules as _policy_rules,
)
from arodonata.core.services.topology import (
    reconciler as _reconciler,
)
from arodonata.core.services.topology import (
    refresh as _refresh,
)
from arodonata.core.services.topology import (
    route_collection as _route_collection,
)
from arodonata.core.services.topology import (
    scoring as _scoring,
)
from arodonata.core.services.topology._shared import (
    _PROCESS_TOPOLOGY_REGISTRIES,
    RepositoryScriptArgsCallable,
    _matches_gateway_filter,
    _normalize_gateway_filter_tokens,
    _ProcessTopologyRegistry,
    _TopologyServiceCachePort,
)
from arodonata.core.services.topology.route_scripts import build_route_collection_repository_script
from arodonata.core.telemetry import traced


class TopologyService:
    """Extracts, caches, reconciles, and matches gateway interface topology and live routes across domains."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: _TopologyServiceCachePort,
        coordinator: DomainSyncCoordinator,
        asset_service: AssetRefreshService,
        object_service: ObjectService,
        rulebase_refresh: RulebaseRefreshPort | None = None,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        script_service: ScriptRepositoryService | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        """Initialize `TopologyService`; pass `rulebase_refresh` (`RulebaseRefreshPort`) to enable lazy `show-packages` catalog warming."""
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._asset_service = asset_service
        self._object_service = object_service
        self._rulebase_refresh: RulebaseRefreshPort | None = rulebase_refresh
        self._gateway_cli = gateway_cli
        self._script_service = script_service or ScriptRepositoryService(api=api, settings=settings)
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())
        self._fallback_registry = _ProcessTopologyRegistry()

    def _get_topology_registry(self) -> _ProcessTopologyRegistry:
        return resolve_engine_registry(
            self._cache,
            _PROCESS_TOPOLOGY_REGISTRIES,
            self._fallback_registry,
            _ProcessTopologyRegistry,
        )

    def _get_refresh_flights(self) -> dict[tuple[Any, ...], asyncio.Future[RefreshOutcome]]:
        return self._get_topology_registry().state().refresh_flights

    def _get_route_collect_flights(self) -> dict[tuple[Any, ...], asyncio.Future[RouteCollectionOutcome]]:
        return self._get_topology_registry().state().route_collect_flights

    def _get_route_collect_semaphore(self, mgmt_key: str, limit: int) -> asyncio.Semaphore:
        eff_limit = max(1, int(limit))
        sem_key = (mgmt_key, eff_limit)
        store = self._get_topology_registry().state().route_collect_sems
        sem = store.get(sem_key)
        if sem is None:
            sem = asyncio.Semaphore(eff_limit)
            store[sem_key] = sem
        return sem

    def _get_route_node_lock(self, mgmt_key: str, node_key: str) -> asyncio.Lock:
        lock_key = (mgmt_key, node_key)
        store = self._get_topology_registry().state().route_node_locks
        lock = store.get(lock_key)
        if lock is None:
            lock = asyncio.Lock()
            store[lock_key] = lock
        return lock

    async def _load_domain_package_snapshot(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        allow_refresh: bool = False,
        cache_ttl: float | None = None,
    ) -> DomainRulebaseSnapshot:
        """Load lightweight rulebase package metadata without reading rule tables, refreshing `show-packages` if cold."""
        return await _policy_rules._load_domain_package_snapshot(
            self._cache,
            self._rulebase_refresh,
            mgmt_name,
            domain_name,
            allow_refresh=allow_refresh,
            cache_ttl=cache_ttl,
        )

    async def _load_domain_scoped_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        global_cache: dict[str, list[CPObject]] | None = None,
        global_lock: asyncio.Lock | None = None,
    ) -> list[CPObject]:
        """Load cached objects for `(mgmt_name, domain_name)` plus `Global` with write-session overlay."""
        return await _objects._load_domain_scoped_objects(
            self._cache,
            mgmt_name,
            domain_name,
            global_cache=global_cache,
            global_lock=global_lock,
        )

    @property
    def gateway_cli(self) -> GatewayCliPort | GatewayCliCallable | None:
        """Configured `GatewayCliPort` or async callable for executing CLI commands on gateways."""
        return self._gateway_cli

    @property
    def script_service(self) -> ScriptRepositoryService:
        """Associated `ScriptRepositoryService` used for repository-mode route collection."""
        return self._script_service

    def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None:
        """Set or replace the runtime `GatewayCliPort` or async callable."""
        self._gateway_cli = gateway_cli

    @traced
    async def check_route_collection_script(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        script_name: str | None = None,
    ) -> RepositoryScriptStatus:
        """Check read-only whether the canonical route-collection repository script exists and matches."""
        eff_name = (script_name or self._settings.cprid_repository_script_name).strip()
        return await self._script_service.check_repository_script(
            mgmt_name,
            eff_name,
            domain=domain,
            expected_body=build_route_collection_repository_script(),
        )

    @traced
    async def ensure_route_collection_script(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        script_name: str | None = None,
        comments: str | None = None,
    ) -> EnsureRepositoryScriptResult:
        """Idempotently provision or update the canonical route-collection script in `domain`."""
        eff_name = (script_name or self._settings.cprid_repository_script_name).strip()
        eff_comments = comments if comments is not None else "Arodonata live route collection script (managed)"
        return await self._script_service.ensure_repository_script(
            mgmt_name,
            eff_name,
            build_route_collection_repository_script(),
            domain=domain,
            comments=eff_comments,
        )

    async def stream_refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing gateway topology across domains (or targeted `gateways`)."""
        async for event in _refresh.stream_refresh_topology(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._coordinator,
            asset_service=self._asset_service,
            rulebase_refresh=self._rulebase_refresh,
            now_fn=self._now,
            collect_routes_fn=self.collect_gateway_routes,
            mgmt_name=mgmt_name,
            domains=domains,
            gateways=gateways,
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        ):
            yield event

    @traced
    async def refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> RefreshOutcome:
        """Refresh gateway topology across domains (or targeted `gateways`) and return `RefreshOutcome`."""
        return await _refresh.refresh_topology(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._coordinator,
            asset_service=self._asset_service,
            rulebase_refresh=self._rulebase_refresh,
            now_fn=self._now,
            collect_routes_fn=self.collect_gateway_routes,
            refresh_flights=self._get_refresh_flights(),
            mgmt_name=mgmt_name,
            domains=domains,
            gateways=gateways,
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    async def _extract_domain_topology_entries(
        self,
        *,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
        objects: Sequence[CPObject],
        target_gateway_uids: set[str] | None = None,
        allow_live_detail: bool = True,
        force_object_refresh: bool = False,
        trusted_object_domains: set[str] | None = None,
        already_detailed_uids: set[str] | None = None,
        global_cache: dict[str, list[CPObject]] | None = None,
        global_lock: asyncio.Lock | None = None,
        emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
    ) -> tuple[list[GatewayTopologyEntry], list[Asset]]:
        """Extract `GatewayTopologyEntry` rows for all policy-enforcing gateways in `(mgmt_name, domain_name)`."""
        return await _extractor._extract_domain_topology_entries(
            api=self._api,
            cache=self._cache,
            rulebase_refresh=self._rulebase_refresh,
            now_fn=self._now,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            assets=assets,
            objects=objects,
            target_gateway_uids=target_gateway_uids,
            allow_live_detail=allow_live_detail,
            force_object_refresh=force_object_refresh,
            trusted_object_domains=trusted_object_domains,
            already_detailed_uids=already_detailed_uids,
            global_cache=global_cache,
            global_lock=global_lock,
            emit=emit,
        )

    @traced
    async def get_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        topology_zone: TopologyZone | None = None,
        source_types: Sequence[TopologySourceType | str] | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[GatewayTopologyEntry]:
        """Ensure topology is synchronized (unless `cache_mode="cache"`) and return cached `GatewayTopologyEntry` rows."""
        return await _diagnostics.get_gateway_topology(
            self._cache,
            self._rulebase_refresh,
            refresh_topology_fn=self.refresh_topology,
            mgmt_name=mgmt_name,
            domain=domain,
            gateway=gateway,
            topology_zone=topology_zone,
            source_types=source_types,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @staticmethod
    def summarize_gateway_interfaces(
        entries: Sequence[GatewayTopologyEntry],
    ) -> list[GatewayInterfaceSummary]:
        """Aggregate flat `GatewayTopologyEntry` rows into per-interface `GatewayInterfaceSummary` models."""
        return _diagnostics.summarize_gateway_interfaces(entries)

    @traced
    async def get_topology_diagnostics(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateways: Sequence[str] | str | None = None,
        gateway: str | None = None,
        min_severity: TopologyDiagnosticSeverity = "info",
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[TopologyDiagnostic]:
        """Inspect gateway and interface definitions and return `TopologyDiagnostic` items."""
        return await _diagnostics.get_topology_diagnostics(
            self._cache,
            refresh_topology_fn=self.refresh_topology,
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            min_severity=min_severity,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def collect_gateway_routes(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        include_global: bool = True,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        timeout: float = 30.0,
        concurrency: int | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> RouteCollectionOutcome:
        """Collect live IPv4 routing tables (`ip -4 route show` and `clish -c "show route"`) from gateways via SSH DI or `cprid` `run-script`."""
        return await _route_collection.collect_gateway_routes(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            asset_service=self._asset_service,
            rulebase_refresh=self._rulebase_refresh,
            script_service=self._script_service,
            default_gateway_cli=self._gateway_cli,
            now_fn=self._now,
            route_collect_flights=self._get_route_collect_flights(),
            get_node_lock=self._get_route_node_lock,
            get_semaphore=self._get_route_collect_semaphore,
            mgmt_name=mgmt_name,
            domain=domain,
            domains=domains,
            gateways=gateways,
            include_global=include_global,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
            concurrency=concurrency,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    @traced
    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Return persistent `TopologyAnnotation` records from `arodonata_topology_annotations`."""
        return await _diagnostics.get_topology_annotations(
            self._cache,
            mgmt_name=mgmt_name,
            domain=domain,
            gateway=gateway,
            interface_name=interface_name,
        )

    @traced
    async def upsert_topology_annotations(
        self,
        annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any],
    ) -> list[TopologyAnnotation]:
        """Insert or update persistent `TopologyAnnotation` records and return the normalized models."""
        return await _diagnostics.upsert_topology_annotations(self._cache, annotations)

    @traced
    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str] | str | None = None,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateway_uid: str | None = None,
    ) -> int:
        """Delete persistent `TopologyAnnotation` records by ID or filter."""
        return await _diagnostics.delete_topology_annotations(
            self._cache,
            annotation_ids,
            mgmt_name=mgmt_name,
            domain=domain,
            gateway_uid=gateway_uid,
        )

    @traced
    async def reconcile_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        collect_live_routes: bool = False,
        check_policy: bool = False,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> TopologyReconciliationReport:
        """Compare SmartConsole static topology against live gateway routing tables (and optionally gateway-targeted policy rules) and return `TopologyReconciliationReport`."""
        return await _reconciler.reconcile_gateway_topology(
            cache=self._cache,
            rulebase_refresh=self._rulebase_refresh,
            weights=self._settings.topology_confidence_weights,
            refresh_topology_fn=self.refresh_topology,
            collect_routes_fn=self.collect_gateway_routes,
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            collect_routes=collect_routes,
            collect_live_routes=collect_live_routes,
            check_policy=check_policy,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    @traced
    async def export_topology_prefixes(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateways: Sequence[str] | str | None = None,
        gateway: str | None = None,
        include_external: bool = False,
        include_ignored: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[ExportedTopologyPrefix]:
        """Export deduplicated gateway/interface prefixes with confidence scores and IPAM annotations."""
        return await _scoring.export_topology_prefixes(
            self._cache,
            self._settings.topology_confidence_weights,
            refresh_topology_fn=self.refresh_topology,
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            include_external=include_external,
            include_ignored=include_ignored,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    async def _resolve_gateway_policy_metadata(
        self,
        mgmt_name: str,
        domain_name: str,
        asset: Asset | None,
        gateway_uid: str,
        gateway_name: str,
        all_assets: Sequence[Asset] | None = None,
        *,
        snapshot: DomainRulebaseSnapshot | None = None,
    ) -> tuple[str | None, list[str], list[str]]:
        return await _policy_rules._resolve_gateway_policy_metadata(
            self._cache,
            self._rulebase_refresh,
            mgmt_name,
            domain_name,
            asset,
            gateway_uid,
            gateway_name,
            all_assets=all_assets,
            snapshot=snapshot,
        )

    @traced
    async def find_affected_gateways(
        self,
        sources: Sequence[str] | str,
        destinations: Sequence[str] | str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        source_types: Sequence[TopologySourceType | str] | None = None,
        include_annotations: bool = True,
        min_confidence: float = 0.0,
        include_standby: bool = True,
        include_policy_inferred: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[AffectedGatewayCandidate]:
        """Locate all policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces (`src_interface != dst_interface`), or via explicit installed policy rules when `include_policy_inferred=True`."""
        return await _policy_matcher.find_affected_gateways(
            api=self._api,
            cache=self._cache,
            rulebase_refresh=self._rulebase_refresh,
            weights=self._settings.topology_confidence_weights,
            now_fn=self._now,
            refresh_topology_fn=self.refresh_topology,
            sources=sources,
            destinations=destinations,
            mgmt_name=mgmt_name,
            domain=domain,
            source_types=source_types,
            include_annotations=include_annotations,
            min_confidence=min_confidence,
            include_standby=include_standby,
            include_policy_inferred=include_policy_inferred,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    # Pure helper compatibility aliases preserved on `TopologyService`
    _normalize_gateway_filter_tokens = staticmethod(_normalize_gateway_filter_tokens)
    _matches_gateway_filter = staticmethod(_matches_gateway_filter)
    _does_sync_state_match_head = staticmethod(_extractor._does_sync_state_match_head)
    _unpack_topology_raw_object = staticmethod(_objects._unpack_topology_raw_object)
    _index_objects_into = staticmethod(_objects._index_objects_into)
    _index_objects = staticmethod(_objects._index_objects)
    _expand_cp_object = staticmethod(_objects._expand_cp_object)
    _expand_specific_reference = staticmethod(_objects._expand_specific_reference)
    _parse_cidr_or_range_bounds = staticmethod(parse_cidr_or_range_bounds)
    _index_annotations_for_gateway = staticmethod(_scoring._index_annotations_for_gateway)
    _is_cidr_covered_by_entries = staticmethod(_scoring._is_cidr_covered_by_entries)
    _build_effective_gateway_entries = staticmethod(_scoring._build_effective_gateway_entries)
    _score_interface_group = staticmethod(_scoring._score_interface_group)
    _resolve_endpoint_intervals = staticmethod(_scoring._resolve_endpoint_intervals)
    _is_range_covered_by_intervals = staticmethod(_scoring._is_range_covered_by_intervals)
    _locate_intervals_on_gateway = staticmethod(_scoring._locate_intervals_on_gateway)
    _is_explicit_rule_terms = staticmethod(_policy_rules._is_explicit_rule_terms)
    _normalize_install_on_tokens = staticmethod(_policy_rules._normalize_install_on_tokens)
    _expand_domain_policy_rules = staticmethod(_policy_rules._expand_domain_policy_rules)
    _filter_rules_for_gateway = staticmethod(_policy_rules._filter_rules_for_gateway)
    _match_endpoints_against_policy_rules = staticmethod(_policy_rules._match_endpoints_against_policy_rules)
    _is_one_arm_or_incomplete_topology_gateway = staticmethod(_policy_rules._is_one_arm_or_incomplete_topology_gateway)
