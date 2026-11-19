"""Backward-compatibility re-export identity, shared logger monkeypatching, and SID-redaction tests for Wave 2."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    CertificateMismatchError,
    RepositoryScriptError,
    SessionError,
    SessionStateError,
)
from arodonata.core.events import DomainSyncFailedEvent, SyncCompletedEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState, RefreshOutcome
from arodonata.core.models.scripts import RepositoryScriptExecutionOutcome, ScriptTargetExecutionResult
from arodonata.core.models.topology import GatewayCliResult, GatewayCliTarget, GatewayRouteCollectionStatus
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
from arodonata.core.services.script_service import ScriptRepositoryService
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
    """Minimal `ApiPort` double simulating SID-leaking exceptions and TLS identity failures."""

    def __init__(self) -> None:
        self.fail_with: Exception | None = None
        self.api_result_override: ApiCallResult | None = None
        self.raise_session_state_first: bool = False
        self.ded_sid = "RawDedSidValue9999"
        self.logged_out_sids: list[str] = []
        self.commands_called: list[tuple[str, str | None]] = []

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
        self.commands_called.append((command, domain))
        if command == "run-script":
            if sid is None and self.raise_session_state_first:
                raise SessionStateError("Session is read-only")
            if self.fail_with is not None:
                raise self.fail_with
            if self.api_result_override is not None:
                return self.api_result_override
            return ApiCallResult(success=False, command=command, error_message="unexpected")
        if command in ("show-simple-gateway", "show-simple-cluster"):
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
        self.commands_called.append((command, domain))
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
        self.logged_out_sids.append(sid)
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


@pytest.mark.spec("SCN-TOPO-020-1", "SCN-TOPO-003-2")
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

    # Restored route_collector helpers on topology_service shim
    assert topo_mod.CLISH_SKIPPED_LARGE_TABLE_MARKER is route_scripts.CLISH_SKIPPED_LARGE_TABLE_MARKER
    assert (
        topo_mod.DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME
        is route_scripts.DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME
    )
    assert topo_mod.AutoScriptModeResolver is route_scripts.AutoScriptModeResolver
    assert topo_mod.ParsedCliRoute is route_scripts.ParsedCliRoute
    assert topo_mod.RepositoryScriptArgsCallable is _shared.RepositoryScriptArgsCallable
    assert topo_mod.build_route_collection_repository_script is route_scripts.build_route_collection_repository_script
    assert topo_mod.build_route_collection_script is route_scripts.build_route_collection_script
    assert topo_mod.execute_gateway_cli is route_executor.execute_gateway_cli
    assert topo_mod.parse_combined_cli_routes_with_status is route_parsers.parse_combined_cli_routes_with_status
    assert topo_mod.resolve_gateway_cli_targets is route_scripts.resolve_gateway_cli_targets
    assert topo_mod.routes_to_topology_entries is route_parsers.routes_to_topology_entries

    # Internal collect_gateway_routes orchestration must not be publicly re-exported by topology package
    assert "collect_gateway_routes" not in topology_pkg.__all__
    assert not hasattr(topology_pkg, "collect_gateway_routes")

    # Policy matcher compatibility aliases
    assert policy_matcher._load_domain_package_snapshot is policy_rules._load_domain_package_snapshot
    assert policy_matcher._resolve_gateway_policy_metadata is policy_rules._resolve_gateway_policy_metadata

    # Route collector shim identity
    assert (
        route_mod.DEFAULT_REPOSITORY_MAX_ROUTES
        == topology_pkg.DEFAULT_REPOSITORY_MAX_ROUTES
        == route_scripts.DEFAULT_REPOSITORY_MAX_ROUTES
        == 50000
    )
    assert (
        route_mod.VSX_BUNDLE_START_MARKER
        is topology_pkg.VSX_BUNDLE_START_MARKER
        is route_scripts.VSX_BUNDLE_START_MARKER
    )
    assert route_mod.VSX_BUNDLE_END_MARKER is topology_pkg.VSX_BUNDLE_END_MARKER is route_scripts.VSX_BUNDLE_END_MARKER
    assert route_mod.VS_START_PREFIX is topology_pkg.VS_START_PREFIX is route_scripts.VS_START_PREFIX
    assert route_mod.VS_END_MARKER is topology_pkg.VS_END_MARKER is route_scripts.VS_END_MARKER
    assert route_mod.VS_ERROR_PREFIX is topology_pkg.VS_ERROR_PREFIX is route_scripts.VS_ERROR_PREFIX
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
    assert route_mod.VsxBundleSlice is topology_pkg.VsxBundleSlice is route_parsers.VsxBundleSlice
    assert (
        route_mod.parse_vsx_bundle_output
        is topology_pkg.parse_vsx_bundle_output
        is route_parsers.parse_vsx_bundle_output
    )
    assert (
        route_mod.extract_vs_slice_from_bundle
        is topology_pkg.extract_vs_slice_from_bundle
        is route_parsers.extract_vs_slice_from_bundle
    )
    assert route_mod.execute_gateway_cli is topology_pkg.execute_gateway_cli is route_executor.execute_gateway_cli
    assert callable(route_collection.collect_gateway_routes)

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


@pytest.mark.spec("SCN-TOPO-020-2")
@pytest.mark.asyncio
async def test_sid_redaction_in_route_collection_and_targeted_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify SID redaction at model boundaries, ScriptRepositoryService, SSH paths, route collection, and targeted refresh."""
    # 0. Model boundary regex sanitization
    cli_model = GatewayCliResult(
        success=False,
        stderr="err X-chkp-sid: ModelStderrSid1234",
        error_message='{"sid": "ModelJsonSid5678"} Authorization: Bearer BearerTok9999',
    )
    assert "ModelStderrSid1234" not in cli_model.stderr
    assert "ModelJsonSid5678" not in (cli_model.error_message or "")
    assert "BearerTok9999" not in (cli_model.error_message or "")
    assert REDACTED_PLACEHOLDER in cli_model.stderr
    assert REDACTED_PLACEHOLDER in (cli_model.error_message or "")

    status_model = GatewayRouteCollectionStatus(
        mgmt_name="mds1",
        domain_name="Corp",
        gateway_uid="gw-1",
        gateway_name="gw-1",
        gateway_type="simple-gateway",
        success=False,
        warnings=["warn X-chkp-sid: WarnSid11223344"],
        error="fail X-chkp-sid: StatusSid22334455",
    )
    assert "WarnSid11223344" not in status_model.warnings[0]
    assert "StatusSid22334455" not in (status_model.error or "")

    sync_model = DomainSyncState(
        mgmt_name="mds1",
        domain_name="Corp",
        scope="topology",
        item_type="routes",
        last_error="sync X-chkp-sid: SyncStateSid334455",
    )
    assert "SyncStateSid334455" not in (sync_model.last_error or "")

    refresh_model = RefreshOutcome(
        scope="topology",
        failed_domains={"mds1:Corp": "refresh X-chkp-sid: RefreshOutcomeSid4455"},
    )
    assert "RefreshOutcomeSid4455" not in refresh_model.failed_domains["mds1:Corp"]

    ev_model = DomainSyncFailedEvent(
        scope="topology",
        mgmt_name="mds1",
        domain="Corp",
        error="ev X-chkp-sid: EventErrSid556677",
        message="msg X-chkp-sid: EventMsgSid667788",
    )
    assert "EventErrSid556677" not in (ev_model.error or "")
    assert "EventMsgSid667788" not in ev_model.message

    tgt_script_model = ScriptTargetExecutionResult(target="gw-1", success=False, stderr="X-chkp-sid: TgtStderrSid11")
    out_script_model = RepositoryScriptExecutionOutcome(
        mgmt_name="mds1",
        domain_name="Corp",
        script_ref="arodonata-collect-routes-v1",
        success=False,
        stderr="X-chkp-sid: RepoOutStderr22",
        error_message="X-chkp-sid: RepoOutErr33",
    )
    assert "TgtStderrSid11" not in tgt_script_model.stderr
    assert "RepoOutStderr22" not in out_script_model.stderr
    assert "RepoOutErr33" not in (out_script_model.error_message or "")

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

    # 1b. SSH callback returning GatewayCliResult (mutated/unredacted or _vs_error=) or str with _vs_error=
    mutated_res = GatewayCliResult.model_construct(
        success=False,
        stdout="",
        stderr="SSH err X-chkp-sid: UnredactedFailSid11",
        exit_code=1,
        executor="ssh",
        error_message="SSH msg X-chkp-sid: UnredactedErrSid22",
    )

    async def _ssh_mutated(_tgt: GatewayCliTarget, _script: str) -> GatewayCliResult:
        return mutated_res

    ssh_res_obj = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_ssh_mutated,
        fallback_to_cprid=False,
    )
    assert "UnredactedFailSid11" not in ssh_res_obj.stderr
    assert "UnredactedErrSid22" not in (ssh_res_obj.error_message or "")

    async def _ssh_vs_error_obj(_tgt: GatewayCliTarget, _script: str) -> GatewayCliResult:
        return GatewayCliResult(success=True, stdout="_vs_error=failed X-chkp-sid: VsObjLeakSid3344", executor="ssh")

    ssh_vs_obj_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_ssh_vs_error_obj,
        fallback_to_cprid=False,
    )
    assert not ssh_vs_obj_res.success
    assert "VsObjLeakSid3344" not in (ssh_vs_obj_res.error_message or "")
    assert REDACTED_PLACEHOLDER in (ssh_vs_obj_res.error_message or "")

    async def _ssh_vs_error_str(_tgt: GatewayCliTarget, _script: str) -> str:
        return "_vs_error=bad X-chkp-sid: VsStrLeakSid5566"

    ssh_vs_str_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_ssh_vs_error_str,
        fallback_to_cprid=False,
    )
    assert not ssh_vs_str_res.success
    assert "VsStrLeakSid5566" not in ssh_vs_str_res.stderr
    assert "VsStrLeakSid5566" not in (ssh_vs_str_res.error_message or "")

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

    # 3b. Repository mode without cprid_session_getter scrubs internal dedicated SID in errors and outcomes
    repo_api = _SecurityTestApi()
    repo_svc = ScriptRepositoryService(api=repo_api)  # type: ignore[arg-type]
    repo_api.api_result_override = ApiCallResult(
        success=False,
        command="run-script",
        error_code="generic_err_no_permissions",
        error_message=f"Permission denied for {repo_api.ded_sid}",
    )
    direct_perm_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=repo_api,  # type: ignore[arg-type]
        cprid_session_getter=None,
        cprid_script_mode="repository",
        script_service=repo_svc,
    )
    assert not direct_perm_res.success
    assert repo_api.ded_sid not in (direct_perm_res.error_message or "")
    assert repo_api.ded_sid not in direct_perm_res.stderr
    assert REDACTED_PLACEHOLDER in (direct_perm_res.error_message or "")

    repo_api.api_result_override = None
    repo_api.fail_with = RuntimeError(f"Transport fault on bare token {repo_api.ded_sid}")
    direct_exc_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=repo_api,  # type: ignore[arg-type]
        cprid_session_getter=None,
        cprid_script_mode="repository",
        script_service=repo_svc,
    )
    assert not direct_exc_res.success
    assert repo_api.ded_sid not in (direct_exc_res.error_message or "")
    assert repo_api.ded_sid not in direct_exc_res.stderr
    assert REDACTED_PLACEHOLDER in (direct_exc_res.error_message or "")

    repo_api.fail_with = None
    repo_api.api_result_override = ApiCallResult(
        success=False,
        command="run-script",
        error_message=f"Task failed with {repo_api.ded_sid}",
        data={
            "tasks": [
                {
                    "task-id": "t-1",
                    "status": "failed",
                    "task-details": [
                        {
                            "gatewayName": "gw-sec",
                            "statusCode": "failed",
                            "responseError": f"Detail err {repo_api.ded_sid}",
                        }
                    ],
                }
            ]
        },
    )
    direct_task_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=repo_api,  # type: ignore[arg-type]
        cprid_session_getter=None,
        cprid_script_mode="repository",
        script_service=repo_svc,
    )
    assert not direct_task_res.success
    assert repo_api.ded_sid not in (direct_task_res.error_message or "")
    assert repo_api.ded_sid not in direct_task_res.stderr
    assert REDACTED_PLACEHOLDER in direct_task_res.stderr

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


@pytest.mark.spec("SCN-TOPO-020-3")
@pytest.mark.asyncio
async def test_server_identity_error_fail_fast_and_ssh_none_fallback_parity() -> None:
    """Verify ServerIdentityError fail-fast propagation across route collection & targeted refresh, plus None SSH fallback parity."""
    target = GatewayCliTarget(
        mgmt_name="mds1",
        domain_name="CorpA",
        gateway_id="mds1:CorpA:gw-id-1",
        gateway_asset_id="mds1:CorpA:gw-id",
        gateway_uid="gw-id-1",
        gateway_name="gw-id",
        gateway_type="simple-gateway",
        node_uid="gw-id-1",
        node_name="gw-id",
        node_ipv4="10.1.1.1",
    )

    api = _SecurityTestApi()

    # 1. SSH returning None preserves legacy cprid fallback error string (no spurious 'SSH failed (...)')
    async def _returns_none(_tgt: GatewayCliTarget, _script: str) -> Any:
        return None

    api.fail_with = RuntimeError("inline boom")
    none_fallback_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_returns_none,
        fallback_to_cprid=True,
        cprid_script_mode="inline",
    )
    assert not none_fallback_res.success
    assert (none_fallback_res.error_message or "").startswith("run-script failed: inline boom")
    assert "SSH failed (" not in (none_fallback_res.error_message or "")

    none_no_fallback_res = await route_executor.execute_gateway_cli(
        target,
        "ip -4 route show",
        api=api,  # type: ignore[arg-type]
        gateway_cli=_returns_none,
        fallback_to_cprid=False,
    )
    assert not none_no_fallback_res.success
    assert none_no_fallback_res.error_message == "SSH execution failed"

    # 2. execute_gateway_cli propagates CertificateMismatchError across SSH, inline cprid, and repository cprid
    async def _ssh_cert_err(_tgt: GatewayCliTarget, _script: str) -> str:
        raise CertificateMismatchError("pinned fingerprint mismatch on SSH/API")

    with pytest.raises(CertificateMismatchError):
        await route_executor.execute_gateway_cli(
            target,
            "ip -4 route show",
            api=api,  # type: ignore[arg-type]
            gateway_cli=_ssh_cert_err,
            fallback_to_cprid=True,
        )

    api.fail_with = CertificateMismatchError("inline run-script cert mismatch")
    with pytest.raises(CertificateMismatchError):
        await route_executor.execute_gateway_cli(
            target,
            "ip -4 route show",
            api=api,  # type: ignore[arg-type]
            cprid_script_mode="inline",
        )

    class _CertFailScriptService:
        async def run_repository_script(self, *_args: Any, **_kwargs: Any) -> Any:
            raise CertificateMismatchError("repo run-script cert mismatch")

    with pytest.raises(CertificateMismatchError):
        await route_executor.execute_gateway_cli(
            target,
            "ip -4 route show",
            api=api,  # type: ignore[arg-type]
            cprid_script_mode="repository",
            script_service=_CertFailScriptService(),  # type: ignore[arg-type]
        )

    # 3. AutoScriptModeResolver propagates CertificateMismatchError to waiting targets
    resolver = route_scripts.AutoScriptModeResolver()
    with pytest.raises(CertificateMismatchError):
        await asyncio.gather(
            route_executor.execute_gateway_cli(
                target,
                "ip -4 route show",
                api=api,  # type: ignore[arg-type]
                cprid_script_mode="auto",
                script_service=_CertFailScriptService(),  # type: ignore[arg-type]
                auto_mode_resolver=resolver,
            ),
            route_executor.execute_gateway_cli(
                target,
                "ip -4 route show",
                api=api,  # type: ignore[arg-type]
                cprid_script_mode="auto",
                script_service=_CertFailScriptService(),  # type: ignore[arg-type]
                auto_mode_resolver=resolver,
            ),
        )

    # 4. Multi-gateway collect_gateway_routes cancels siblings on CertificateMismatchError & skips failed sync_state
    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        settings = ArodonataSettings(
            mgmt_name="mds1",
            mgmt_ip="10.0.0.1",
            api_key="secret",
            cache_ttl=0,
            route_collect_concurrency=4,
        )
        await cache.upsert_domains(
            [
                DomainInfo(mgmt_name="mds1", uid="d-a", name="CorpA", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
                DomainInfo(mgmt_name="mds1", uid="d-b", name="CorpB", active_ip="10.2.0.1", active_mds_ip="10.0.0.1"),
            ]
        )
        gw_a = Asset(uid="gw-a-1", name="gw-a", type="simple-gateway", mgmt_name="mds1", domain_name="CorpA")
        gw_b = Asset(uid="gw-b-1", name="gw-b", type="simple-gateway", mgmt_name="mds1", domain_name="CorpA")
        gw_c = Asset(uid="gw-c-1", name="gw-c", type="simple-gateway", mgmt_name="mds1", domain_name="CorpB")
        await cache.upsert_assets([gw_a, gw_b, gw_c])

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

        gw_b_started = asyncio.Event()
        gw_b_cancelled = False

        async def _cancel_sibling_ssh(tgt: GatewayCliTarget, _script: str) -> str:
            nonlocal gw_b_cancelled
            if tgt.gateway_name == "gw-b":
                gw_b_started.set()
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    gw_b_cancelled = True
                    raise
            await asyncio.wait_for(gw_b_started.wait(), timeout=2.0)
            raise CertificateMismatchError("sibling cancellation cert mismatch")

        with pytest.raises(CertificateMismatchError):
            await topo_svc.collect_gateway_routes(
                mgmt_name="mds1",
                domain="CorpA",
                gateways=["gw-a", "gw-b"],
                gateway_cli=_cancel_sibling_ssh,
                fallback_to_cprid=False,
                concurrency=2,
            )
        assert gw_b_cancelled is True
        assert await cache.get_sync_state("mds1", "CorpA", "topology", "routes") is None

        # 4b. Dedicated cprid session opened before CertificateMismatchError is cleanly logged out
        api.logged_out_sids.clear()
        api.raise_session_state_first = True
        api.fail_with = CertificateMismatchError("cprid run-script cert mismatch")
        with pytest.raises(CertificateMismatchError):
            await topo_svc.collect_gateway_routes(
                mgmt_name="mds1",
                domain="CorpA",
                gateways=["gw-a"],
                cprid_script_mode="inline",
            )
        assert api.ded_sid in api.logged_out_sids

        # 5. Multi-domain targeted refresh aborts on CorpA CertificateMismatchError before touching CorpB
        api.commands_called.clear()
        api.raise_session_state_first = False
        api.fail_with = CertificateMismatchError("show-simple-gateway cert mismatch")
        emitted_before_error: list[Any] = []
        with pytest.raises(CertificateMismatchError):
            async for ev in topo_svc.stream_refresh_topology(
                mgmt_name="mds1",
                domains=["CorpA", "CorpB"],
                gateways=["gw-a", "gw-c"],
                mode="smart",
            ):
                emitted_before_error.append(ev)

        assert not any(isinstance(e, (DomainSyncFailedEvent, SyncCompletedEvent)) for e in emitted_before_error)
        assert not any(dom == "CorpB" for _cmd, dom in api.commands_called)

        with pytest.raises(CertificateMismatchError):
            await topo_svc.refresh_topology(
                mgmt_name="mds1",
                domains=["CorpA", "CorpB"],
                gateways=["gw-a", "gw-c"],
                mode="smart",
            )
    finally:
        await db.close()
