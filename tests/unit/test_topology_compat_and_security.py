"""Backward-compatibility re-export identity, shared logger monkeypatching, and SID-redaction tests for Wave 2."""

from __future__ import annotations

from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import REDACTED_PLACEHOLDER, RepositoryScriptError, SessionError, SessionStateError
from arodonata.core.events import DomainSyncFailedEvent, SyncCompletedEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.topology import GatewayCliTarget
from arodonata.core.services import (
    AssetRefreshService,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    TopologyService,
)
from arodonata.core.services import route_collector as route_mod
from arodonata.core.services import topology as topology_pkg
from arodonata.core.services import topology_service as topo_mod
from arodonata.core.services.topology import (
    _shared,
    extractor,
    normalizer,
    policy_matcher,
    policy_rules,
    refresh,
    route_collection,
    route_executor,
    route_parsers,
    route_scripts,
    service,
)


class _SecurityTestApi:
    """Minimal `ApiPort` double simulating SID-leaking exceptions for redaction verification."""

    def __init__(self) -> None:
        self.fail_with: Exception | None = None
        self.raise_session_state_first: bool = False
        self.ded_sid = "RawDedSidValue9999"

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        if command == "run-script":
            if sid is None and self.raise_session_state_first:
                raise SessionStateError("Session is read-only")
            if self.fail_with is not None:
                raise self.fail_with
            return ApiCallResult(success=False, command=command, error_message="unexpected")
        if command == "show-simple-gateway":
            if self.fail_with is not None:
                raise self.fail_with
        return ApiCallResult(success=True, command=command, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        limit: int = 500,
    ) -> ApiQueryResult:
        return ApiQueryResult(success=True, command=command, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
        read_only: bool = False,
        session_name: str | None = None,
    ) -> tuple[str, str]:
        return self.ded_sid, "10.0.0.1"

    async def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> bool:
        return True

    async def get_readonly_session(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
    ) -> tuple[str, str]:
        return "ReadOnlySid0001", "10.0.0.1"

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.spec("SCN-CLIENT-018-1", "SCN-CLIENT-018-2", "SCN-CLIENT-018-3", "SCN-TOPO-003-2")
@pytest.mark.asyncio
async def test_topology_and_route_collector_reexport_identity_and_shared_logger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify exact object identity across shims/submodules and monkeypatch propagation via shared logger."""
    # Topology service shim identity
    assert topo_mod.TopologyService is TopologyService is topology_pkg.TopologyService is service.TopologyService
    assert (
        topo_mod.is_policy_enforcing_gateway
        is topology_pkg.is_policy_enforcing_gateway
        is _shared.is_policy_enforcing_gateway
    )
    assert topo_mod.POLICY_GATEWAY_TYPES is topology_pkg.POLICY_GATEWAY_TYPES is _shared.POLICY_GATEWAY_TYPES
    assert topo_mod.EXCLUDED_GATEWAY_TYPES is topology_pkg.EXCLUDED_GATEWAY_TYPES is _shared.EXCLUDED_GATEWAY_TYPES
    assert topo_mod.TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY is _shared.TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY
    assert topo_mod._TopologyServiceCachePort is _shared._TopologyServiceCachePort
    assert topo_mod._NormalizedInterface is _shared._NormalizedInterface
    assert topo_mod._ResolvedEndpointInterval is _shared._ResolvedEndpointInterval
    assert topo_mod._InterfaceMatch is _shared._InterfaceMatch
    assert topo_mod._ExpandedPolicyRule is _shared._ExpandedPolicyRule
    assert topo_mod._LoopTopologyState is _shared._LoopTopologyState
    assert topo_mod._ProcessTopologyRegistry is _shared._ProcessTopologyRegistry
    assert topo_mod._PROCESS_TOPOLOGY_REGISTRIES is _shared._PROCESS_TOPOLOGY_REGISTRIES
    assert topo_mod._run_single_flight is _shared._run_single_flight
    assert topo_mod._normalize_interface is normalizer._normalize_interface
    assert topo_mod._normalize_gateway_interfaces is normalizer._normalize_gateway_interfaces
    assert topo_mod._parse_route_destination is normalizer._parse_route_destination
    assert topo_mod._parse_route_nexthop_and_interface is normalizer._parse_route_nexthop_and_interface
    assert topo_mod._extract_anti_spoofing_mode is normalizer._extract_anti_spoofing_mode
    assert topo_mod._extract_vpn_domain_refs is normalizer._extract_vpn_domain_refs
    assert topo_mod._extract_raw_routes is normalizer._extract_raw_routes
    assert topo_mod._extract_timestamp_posix is normalizer._extract_timestamp_posix
    assert topo_mod._extract_policy_candidates_from_raw is normalizer._extract_policy_candidates_from_raw

    # Policy matcher compatibility aliases
    assert policy_matcher._load_domain_package_snapshot is policy_rules._load_domain_package_snapshot
    assert policy_matcher._resolve_gateway_policy_metadata is policy_rules._resolve_gateway_policy_metadata

    # Route collector shim identity
    assert (
        route_mod.AutoScriptModeResolver is topology_pkg.AutoScriptModeResolver is route_scripts.AutoScriptModeResolver
    )
    assert route_mod.ParsedCliRoute is topology_pkg.ParsedCliRoute is route_scripts.ParsedCliRoute
    assert (
        route_mod.build_route_collection_script
        is topology_pkg.build_route_collection_script
        is route_scripts.build_route_collection_script
    )
    assert (
        route_mod.build_route_collection_repository_script
        is topology_pkg.build_route_collection_repository_script
        is route_scripts.build_route_collection_repository_script
    )
    assert (
        route_mod.format_route_collection_repository_args
        is topology_pkg.format_route_collection_repository_args
        is route_scripts.format_route_collection_repository_args
    )
    assert (
        route_mod.resolve_gateway_cli_targets
        is topology_pkg.resolve_gateway_cli_targets
        is route_scripts.resolve_gateway_cli_targets
    )
    assert (
        route_mod.decode_cprid_task_output
        is topology_pkg.decode_cprid_task_output
        is route_parsers.decode_cprid_task_output
    )
    assert route_mod.parse_ip_route_show is topology_pkg.parse_ip_route_show is route_parsers.parse_ip_route_show
    assert (
        route_mod.parse_clish_show_route is topology_pkg.parse_clish_show_route is route_parsers.parse_clish_show_route
    )
    assert (
        route_mod.parse_combined_cli_routes
        is topology_pkg.parse_combined_cli_routes
        is route_parsers.parse_combined_cli_routes
    )
    assert (
        route_mod.parse_combined_cli_routes_with_status
        is topology_pkg.parse_combined_cli_routes_with_status
        is route_parsers.parse_combined_cli_routes_with_status
    )
    assert (
        route_mod.routes_to_topology_entries
        is topology_pkg.routes_to_topology_entries
        is route_parsers.routes_to_topology_entries
    )
    assert route_mod.execute_gateway_cli is topology_pkg.execute_gateway_cli is route_executor.execute_gateway_cli
    assert topology_pkg.collect_gateway_routes is route_collection.collect_gateway_routes

    # Shared logger identity across all logging submodules
    assert topo_mod.logger is _shared.logger is extractor.logger is policy_rules.logger is refresh.logger
    assert route_mod.logger is _shared.route_logger

    # Monkeypatching `topo_mod.logger.warning` intercepts warnings from both policy_rules and extractor
    warning_messages: list[str] = []
    orig_warning = topo_mod.logger.warning

    def _spy_warning(msg: str, *args: Any, **kwargs: Any) -> None:
        warning_messages.append(msg)
        orig_warning(msg, *args, **kwargs)

    monkeypatch.setattr(topo_mod.logger, "warning", _spy_warning)

    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        api = _SecurityTestApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)  # type: ignore[arg-type]
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,  # type: ignore[arg-type]
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_service,
        )
        asset_service = AssetRefreshService(settings=settings, api=api, cache=cache, coordinator=coordinator)  # type: ignore[arg-type]
        object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)  # type: ignore[arg-type]
        topo_svc = TopologyService(
            settings=settings,
            api=api,  # type: ignore[arg-type]
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            object_service=object_service,
            rulebase_refresh=None,
        )

        # Trigger policy_rules warning (`rulebase_refresh is None` during cold snapshot)
        await topo_svc._load_domain_package_snapshot("mds1", "Corp", allow_refresh=True)
        assert any("without rulebase_refresh" in msg for msg in warning_messages)

        # Trigger extractor warning (gateway interface with undefined behind_mode)
        warning_messages.clear()
        undef_gw = Asset(
            uid="gw-undef-1",
            name="gw-undef",
            type="simple-gateway",
            mgmt_name="mds1",
            domain_name="Corp",
            interfaces=[
                {
                    "interface-name": "eth9",
                    "ipv4-address": "10.10.9.1",
                    "ipv4-mask-length": 24,
                    "topology": {"leads-to-internet": False, "ip-address-behind-this-interface": "not defined"},
                }
            ],
        )
        await topo_svc._extract_domain_topology_entries(
            mgmt_name="mds1",
            domain_name="Corp",
            assets=[undef_gw],
            objects=[],
            allow_live_detail=False,
        )
        assert any("dynamic routing or undefined topology" in msg and "eth9" in msg for msg in warning_messages)
    finally:
        await db.close()


@pytest.mark.spec("SCN-TOPO-007-2", "SCN-TOPO-009-1", "SCN-CLIENT-015-1")
@pytest.mark.asyncio
async def test_sid_redaction_in_route_collection_and_targeted_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify exception SID tokens are redacted in CLI results, route statuses, sync states, progress events, and warnings."""
    target = GatewayCliTarget(
        mgmt_name="mds1",
        domain_name="Corp",
        gateway_id="mds1:Corp:gw-sec-1",
        gateway_asset_id="mds1:Corp:gw-sec",
        gateway_uid="gw-sec-1",
        gateway_name="gw-sec",
        gateway_type="simple-gateway",
        node_uid="gw-sec-1",
        node_name="gw-sec",
        node_ipv4="10.1.1.1",
    )

    async def _failing_ssh(_tgt: GatewayCliTarget, _script: str) -> str:
        raise RuntimeError("SSH transport failed with X-chkp-sid: SuperSecretSid123456")

    api = _SecurityTestApi()

    # 1. SSH exception without cprid fallback
    ssh_only_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_failing_ssh,
        fallback_to_cprid=False,
    )
    assert not ssh_only_res.success
    assert "SuperSecretSid123456" not in (ssh_only_res.error_message or "")
    assert "SuperSecretSid123456" not in ssh_only_res.stderr
    assert REDACTED_PLACEHOLDER in (ssh_only_res.error_message or "")

    # 2. SSH fallback to inline cprid failing with SessionError + raw dedicated SID
    api.raise_session_state_first = True
    api.fail_with = SessionError('API failed {"sid": "SecondSecretSid789012"} token=RawDedSidValue9999')
    inline_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_failing_ssh,
        fallback_to_cprid=True,
        cprid_script_mode="inline",
    )
    assert not inline_res.success
    for leaked in ("SuperSecretSid123456", "SecondSecretSid789012", "RawDedSidValue9999"):
        assert leaked not in (inline_res.error_message or "")
        assert leaked not in inline_res.stderr
    assert REDACTED_PLACEHOLDER in (inline_res.error_message or "")

    # 3. Repository mode raising RepositoryScriptError and generic Exception with X-chkp-sid
    api.raise_session_state_first = False
    for repo_exc in (
        RepositoryScriptError("Repo failure X-chkp-sid: RepoSecretSid654321"),
        RuntimeError("Unexpected repo error X-chkp-sid: GenericRepoSid555666"),
    ):

        class _FailingScriptService:
            def __init__(self, exc_to_raise: Exception) -> None:
                self._exc = exc_to_raise

            async def run_repository_script(self, *_args: Any, **_kwargs: Any) -> Any:
                raise self._exc

        repo_res = await route_executor.execute_gateway_cli(
            target,
            "ip -4 route show",
            api=api,  # type: ignore[arg-type]
            cprid_script_mode="repository",
            script_service=_FailingScriptService(repo_exc),  # type: ignore[arg-type]
        )
        assert not repo_res.success
        assert "RepoSecretSid654321" not in (repo_res.error_message or "")
        assert "GenericRepoSid555666" not in (repo_res.error_message or "")
        assert "RepoSecretSid654321" not in repo_res.stderr
        assert "GenericRepoSid555666" not in repo_res.stderr
        assert REDACTED_PLACEHOLDER in (repo_res.error_message or "")

    # 4. End-to-end collect_gateway_routes + targeted refresh SID redaction across events, logs, and sync state
    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
        await cache.upsert_domains(
            [DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
        )
        cluster_gw = Asset(
            uid="cl-sec-1",
            name="cl-sec",
            type="simple-cluster",
            mgmt_name="mds1",
            domain_name="Corp",
            member_uids=["cl-sec-m1", "cl-sec-m2"],
            interfaces=[
                {
                    "interface-name": "eth1",
                    "ipv4-address": "10.20.1.1",
                    "ipv4-mask-length": 24,
                    "topology": {
                        "leads-to-internet": False,
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                }
            ],
        )
        m1 = Asset(
            uid="cl-sec-m1",
            name="cl-sec-m1",
            type="cluster-member",
            mgmt_name="mds1",
            domain_name="Corp",
            parent_uid="cl-sec-1",
        )
        m2 = Asset(
            uid="cl-sec-m2",
            name="cl-sec-m2",
            type="cluster-member",
            mgmt_name="mds1",
            domain_name="Corp",
            parent_uid="cl-sec-1",
        )
        await cache.upsert_assets([cluster_gw, m1, m2])

        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)  # type: ignore[arg-type]
        domain_service.tracker.mark_refreshed("mds1")
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,  # type: ignore[arg-type]
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_service,
        )
        asset_service = AssetRefreshService(settings=settings, api=api, cache=cache, coordinator=coordinator)  # type: ignore[arg-type]
        object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)  # type: ignore[arg-type]
        topo_svc = TopologyService(
            settings=settings,
            api=api,  # type: ignore[arg-type]
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            object_service=object_service,
        )

        # 4a. Both members fail in collect_gateway_routes (error + sync_state.last_error redacted)
        api.raise_session_state_first = True
        api.fail_with = RuntimeError("Raw crash X-chkp-sid: CollectFailSid313131 and RawDedSidValue9999")
        failed_routes = await topo_svc.collect_gateway_routes(
            mgmt_name="mds1",
            domain="Corp",
            gateways=["cl-sec"],
            cprid_script_mode="inline",
        )
        assert failed_routes.failed_gateways == 1
        st = failed_routes.gateways[0]
        assert "CollectFailSid313131" not in (st.error or "")
        assert "RawDedSidValue9999" not in (st.error or "")
        assert REDACTED_PLACEHOLDER in (st.error or "")

        sync_st = await cache.get_sync_state("mds1", "Corp", "topology", "routes")
        assert sync_st is not None and sync_st.status == "failed"
        assert "CollectFailSid313131" not in (sync_st.last_error or "")
        assert "RawDedSidValue9999" not in (sync_st.last_error or "")
        assert REDACTED_PLACEHOLDER in (sync_st.last_error or "")

        # 4b. Partial cluster member failure emits redacted `warnings` when another member succeeds
        async def _partial_ssh(tgt: GatewayCliTarget, _script: str) -> str:
            if tgt.node_name == "cl-sec-m2":
                raise RuntimeError("Member2 SSH failed X-chkp-sid: PartialWarnSid818181")
            return "===ARODONATA_IP_ROUTE_START===\n10.20.1.0/24 dev eth1 proto kernel scope link\n===ARODONATA_IP_ROUTE_END===\n"

        partial_routes = await topo_svc.collect_gateway_routes(
            mgmt_name="mds1",
            domain="Corp",
            gateways=["cl-sec"],
            gateway_cli=_partial_ssh,
            fallback_to_cprid=False,
        )
        assert partial_routes.succeeded_gateways == 1
        assert partial_routes.gateways[0].warnings
        joined_warns = "\n".join(partial_routes.gateways[0].warnings)
        assert "PartialWarnSid818181" not in joined_warns
        assert REDACTED_PLACEHOLDER in joined_warns

        # 4c. Targeted gateway refresh failure redacts SIDs in warning logs, DomainSyncFailedEvent, SyncCompletedEvent, and RefreshOutcome
        logged_warnings: list[str] = []
        orig_warn = topo_mod.logger.warning

        def _capture_warn(msg: str, *args: Any, **kwargs: Any) -> None:
            logged_warnings.append(msg)
            orig_warn(msg, *args, **kwargs)

        monkeypatch.setattr(topo_mod.logger, "warning", _capture_warn)

        async def _explode_replace(*_args: Any, **_kwargs: Any) -> int:
            raise RuntimeError("Targeted store exploded with X-chkp-sid: TargetRefreshSid424242")

        monkeypatch.setattr(cache, "replace_domain_topology", _explode_replace)

        events: list[Any] = []
        async for ev in topo_svc.stream_refresh_topology(
            mgmt_name="mds1",
            domains=["Corp"],
            gateways=["cl-sec"],
            mode="smart",
        ):
            events.append(ev)

        failed_events = [e for e in events if isinstance(e, DomainSyncFailedEvent)]
        completed_events = [e for e in events if isinstance(e, SyncCompletedEvent)]
        assert len(failed_events) == 1
        assert "TargetRefreshSid424242" not in failed_events[0].error
        assert "TargetRefreshSid424242" not in failed_events[0].message
        assert REDACTED_PLACEHOLDER in failed_events[0].error

        assert len(completed_events) == 1
        failed_map = completed_events[0].details["failed_domains"]
        assert "mds1:Corp" in failed_map
        assert "TargetRefreshSid424242" not in failed_map["mds1:Corp"]
        assert REDACTED_PLACEHOLDER in failed_map["mds1:Corp"]

        assert any(REDACTED_PLACEHOLDER in m and "TargetRefreshSid424242" not in m for m in logged_warnings)

        outcome = await topo_svc.refresh_topology(
            mgmt_name="mds1",
            domains=["Corp"],
            gateways=["cl-sec"],
            mode="smart",
        )
        assert "mds1:Corp" in outcome.failed_domains
        assert "TargetRefreshSid424242" not in outcome.failed_domains["mds1:Corp"]
        assert REDACTED_PLACEHOLDER in outcome.failed_domains["mds1:Corp"]
    finally:
        await db.close()
