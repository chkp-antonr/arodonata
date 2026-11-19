"""Gateway topology, route collection, reconciliation, and annotation facades for `ArodonataClient`."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

from arodonata.client._base import ClientBase
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.common import CacheMode
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.scripts import (
    CpridScriptMode,
    EnsureRepositoryScriptResult,
    RepositoryScriptStatus,
)
from arodonata.core.models.topology import (
    AffectedGatewayCandidate,
    ExportedTopologyPrefix,
    GatewayTopologyEntry,
    RouteCollectionOutcome,
    TopologyAnnotation,
    TopologyDiagnostic,
    TopologyDiagnosticSeverity,
    TopologyReconciliationReport,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import GatewayCliCallable, GatewayCliPort
from arodonata.core.services import RepositoryScriptArgsCallable
from arodonata.core.telemetry import traced


class ClientTopologyMixin(ClientBase):
    """Provides gateway topology, route collection, diagnostics, reconciliation, and annotation methods."""

    def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None:
        """Register or replace the optional SSH/CLI callback or `GatewayCliPort` adapter."""
        self._topology_service.set_gateway_cli(gateway_cli)

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
        """Synchronize gateway interface topology across target domains (or specific `gateways`) and return `RefreshOutcome`."""
        await self._ensure_initialized()
        return await self._topology_service.refresh_topology(
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
        """Stream `SyncProgressEvent` items while synchronizing gateway interface topology."""
        await self._ensure_initialized()
        async for ev in self._topology_service.stream_refresh_topology(
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
            yield ev

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
        """Return cached `GatewayTopologyEntry` rows for policy-enforcing gateways."""
        await self._ensure_initialized()
        return await self._topology_service.get_gateway_topology(
            mgmt_name=mgmt_name,
            domain=domain,
            gateway=gateway,
            topology_zone=topology_zone,
            source_types=source_types,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def find_affected_gateways(
        self,
        sources: Sequence[str] | str,
        destinations: Sequence[str] | str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        min_confidence: float = 0.0,
        include_standby: bool = True,
        include_policy_inferred: bool = True,
        source_types: Sequence[TopologySourceType | str] | None = None,
        include_annotations: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[AffectedGatewayCandidate]:
        """Locate policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces or via explicit installed policy rules."""
        await self._ensure_initialized()
        return await self._topology_service.find_affected_gateways(
            sources,
            destinations,
            mgmt_name=mgmt_name,
            domain=domain,
            min_confidence=min_confidence,
            include_standby=include_standby,
            include_policy_inferred=include_policy_inferred,
            source_types=source_types,
            include_annotations=include_annotations,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def collect_gateway_routes(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        gateways: Sequence[str] | str | None = None,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        timeout: float = 45.0,
        concurrency: int | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> RouteCollectionOutcome:
        """Collect live OS/Clish routing tables from gateways via SSH (`GatewayCliPort`) or `cprid` `run-script` fallback."""
        await self._ensure_initialized()
        return await self._topology_service.collect_gateway_routes(
            mgmt_name=mgmt_name,
            domain=domain,
            domains=domains,
            include_global=include_global,
            gateways=gateways,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
            concurrency=concurrency,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    @traced
    async def check_route_collection_script(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        script_name: str | None = None,
    ) -> RepositoryScriptStatus:
        """Check read-only whether the canonical route-collection repository script exists and matches in `domain`."""
        await self._ensure_initialized()
        return await self._topology_service.check_route_collection_script(
            mgmt_name,
            domain,
            script_name=script_name,
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
        await self._ensure_initialized()
        return await self._topology_service.ensure_route_collection_script(
            mgmt_name,
            domain,
            script_name=script_name,
            comments=comments,
        )

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
        """Return static topology health diagnostics (`TopologyDiagnostic`) across policy-enforcing gateways."""
        await self._ensure_initialized()
        return await self._topology_service.get_topology_diagnostics(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            min_severity=min_severity,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def reconcile_gateway_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
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
        """Reconcile SmartConsole static topology against cached/collected live routes, gateway-targeted policy rules, and administrator annotations."""
        await self._ensure_initialized()
        return await self._topology_service.reconcile_gateway_topology(
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
    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Return persistent administrator `TopologyAnnotation` records."""
        await self._ensure_initialized()
        return await self._topology_service.get_topology_annotations(
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
        """Persist one or more administrator `TopologyAnnotation` overrides and IPAM metadata records."""
        await self._ensure_initialized()
        return await self._topology_service.upsert_topology_annotations(annotations)

    @traced
    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str] | str | None = None,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateway_uid: str | None = None,
    ) -> int:
        """Delete persistent administrator `TopologyAnnotation` rows matching the supplied filters."""
        await self._ensure_initialized()
        return await self._topology_service.delete_topology_annotations(
            annotation_ids=annotation_ids,
            mgmt_name=mgmt_name,
            domain=domain,
            gateway_uid=gateway_uid,
        )

    @traced
    async def export_topology_prefixes(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateways: Sequence[str] | str | None = None,
        gateway: str | None = None,
        include_external: bool = False,
        include_ignored: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[ExportedTopologyPrefix]:
        """Export consolidated `ExportedTopologyPrefix` records for IPAM comparison."""
        await self._ensure_initialized()
        return await self._topology_service.export_topology_prefixes(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            include_external=include_external,
            include_ignored=include_ignored,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
