"""Multi-gateway live IPv4 route collection orchestration and sync-state persistence."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable, Collection, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.models.assets import Asset
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.scripts import CpridScriptMode
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    GatewayCliResult,
    GatewayCliTarget,
    GatewayRouteCollectionStatus,
    RouteCollectionOutcome,
)
from arodonata.core.ports import ApiPort, GatewayCliCallable, GatewayCliPort, RulebaseRefreshPort
from arodonata.core.primitives import normalize_str_sequence
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.script_service import ScriptRepositoryService
from arodonata.core.services.topology._shared import (
    RepositoryScriptArgsCallable,
    _matches_gateway_filter,
    _normalize_gateway_filter_tokens,
    _run_single_flight,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology.normalizer import _normalize_gateway_interfaces
from arodonata.core.services.topology.policy_rules import (
    _load_domain_package_snapshot,
    _resolve_gateway_policy_metadata,
)
from arodonata.core.services.topology.route_executor import execute_gateway_cli
from arodonata.core.services.topology.route_parsers import (
    extract_vs_slice_from_bundle,
    parse_combined_cli_routes_with_status,
    routes_to_topology_entries,
)
from arodonata.core.services.topology.route_scripts import (
    CLISH_SKIPPED_LARGE_TABLE_MARKER,
    DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME,
    AutoScriptModeResolver,
    ParsedCliRoute,
    build_route_collection_script,
    resolve_gateway_cli_targets,
)
from arodonata.core.telemetry import span_attrs


async def _execute_coalesced_target(
    target: GatewayCliTarget,
    *,
    api: ApiPort,
    eff_cli: GatewayCliPort | GatewayCliCallable | None,
    fallback_to_cprid: bool,
    timeout: float,
    eff_concurrency: int,
    eff_script_mode: CpridScriptMode,
    eff_script_name: str,
    repository_script_args_fn: RepositoryScriptArgsCallable | None,
    max_routes: int,
    script_service: ScriptRepositoryService,
    cprid_session_getter: Callable[[str, str], Any],
    auto_mode_resolver: AutoScriptModeResolver,
    repo_node_flights: dict[tuple[str, str, str], asyncio.Future[GatewayCliResult]],
    repo_node_locks: dict[tuple[str, str, str], asyncio.Lock],
    get_node_lock: Callable[[str, str], Any],
    get_semaphore: Callable[[str, int], Any],
) -> tuple[GatewayCliTarget, GatewayCliResult]:
    """Execute or coalesce a single target's CLI route collection across concurrent VSX targets."""
    preclaimed = False
    if eff_script_mode == "auto" and eff_cli is None:
        preclaimed = await auto_mode_resolver.acquire_probe_turn(target.mgmt_name, target.domain_name)

    probe_exc: BaseException | None = None
    node_key = str(target.node_uid or target.node_ipv4 or target.node_name or target.gateway_uid)
    coalesce_key = (target.mgmt_name, target.domain_name, node_key)

    should_coalesce = (
        eff_cli is None
        and repository_script_args_fn is None
        and (
            eff_script_mode == "repository"
            or (
                eff_script_mode == "auto"
                and (
                    preclaimed or auto_mode_resolver.get_resolved(target.mgmt_name, target.domain_name) == "repository"
                )
            )
        )
    )

    flight_fut: asyncio.Future[GatewayCliResult] | None = None
    is_leader = False
    if should_coalesce:
        async with repo_node_locks[coalesce_key]:
            existing_fut = repo_node_flights.get(coalesce_key)
            if existing_fut is None or (preclaimed and existing_fut.done() and existing_fut.exception() is not None):
                flight_fut = asyncio.get_running_loop().create_future()
                repo_node_flights[coalesce_key] = flight_fut
                is_leader = True
            else:
                flight_fut = existing_fut
                is_leader = False

        if not is_leader:
            try:
                bundle_res = await asyncio.shield(flight_fut)
            except ServerIdentityError:
                raise
            except asyncio.CancelledError:
                cur_task = asyncio.current_task()
                if cur_task is not None and cur_task.cancelling() > 0:
                    raise
                bundle_res = GatewayCliResult(
                    success=False,
                    error_code="leader_cancelled",
                    error_message="Coalescing leader flight was cancelled",
                    executor="cprid",
                )
            except Exception as exc:
                bundle_res = GatewayCliResult(
                    success=False,
                    error_code="coalesce_leader_failed",
                    error_message=f"Coalescing leader flight failed: {exc}",
                    executor="cprid",
                )

            raw_bundle = bundle_res.bundle_stdout or bundle_res.stdout
            res = extract_vs_slice_from_bundle(
                raw_bundle,
                vsid=target.vsid,
                vs_name=target.vs_name,
                executor=bundle_res.executor,
                base_result=bundle_res,
            )
            return target, res

    try:
        node_lock = get_node_lock(target.mgmt_name, node_key)
        mgmt_sem = get_semaphore(target.mgmt_name, eff_concurrency)
        # Acquire per-node lock BEFORE management concurrency slot so multiple VSX Virtual Systems
        # hosted on the same physical VSX chassis serialize cleanly without starving other gateways.
        async with node_lock, mgmt_sem:
            script = build_route_collection_script(
                vsid=target.vsid,
                vs_name=target.vs_name,
                max_routes=max_routes,
            )
            res = await execute_gateway_cli(
                target,
                script,
                api=api,
                gateway_cli=eff_cli,
                fallback_to_cprid=fallback_to_cprid,
                timeout=timeout,
                cprid_session_getter=cprid_session_getter,
                cprid_script_mode=eff_script_mode,
                repository_script_name=eff_script_name,
                repository_script_args_fn=repository_script_args_fn,
                max_routes=max_routes,
                script_service=script_service,
                auto_mode_resolver=auto_mode_resolver,
                preclaimed_auto_probe=preclaimed,
            )
            if should_coalesce and is_leader and flight_fut is not None and not flight_fut.done():
                bundle_for_followers = (
                    res.model_copy(update={"success": True, "error_code": None, "error_message": None, "exit_code": 0})
                    if (res.bundle_stdout and res.error_code in ("vs_context_error", "vs_not_found_in_bundle"))
                    else res
                )
                flight_fut.set_result(bundle_for_followers)
            return target, res
    except BaseException as exc:
        probe_exc = exc
        if should_coalesce and is_leader and flight_fut is not None and not flight_fut.done():
            if isinstance(exc, asyncio.CancelledError):
                flight_fut.set_exception(RuntimeError("Coalescing leader flight was cancelled"))
            else:
                flight_fut.set_exception(exc)
        raise
    finally:
        if preclaimed:
            auto_mode_resolver.abort_probe_if_unresolved(
                target.mgmt_name,
                target.domain_name,
                exc=probe_exc,
            )


async def _persist_gateway_routes(
    gw_asset: Asset,
    parsed_by_node: dict[str, list[ParsedCliRoute]],
    *,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    dom_assets: list[Asset],
    dom_pkg_snapshot: DomainRulebaseSnapshot,
    now: datetime,
    executors_used: list[str],
    truncation_warnings: list[str],
    node_errors: list[str],
) -> tuple[GatewayRouteCollectionStatus, int]:
    """Normalize routes for one gateway, persist them in cache, and build its status summary."""
    if_meta: dict[str, tuple[str | None, int | None, bool, str, bool]] = {
        norm.interface_name: (
            norm.ipv4_address,
            norm.mask_length,
            norm.leads_to_dmz,
            norm.anti_spoofing_mode,
            norm.is_external,
        )
        for norm in _normalize_gateway_interfaces(gw_asset)
    }

    inst_pol, pkg_names, _ = await _resolve_gateway_policy_metadata(
        cache,
        rulebase_refresh,
        gw_asset.mgmt_name,
        gw_asset.domain_name,
        gw_asset,
        gw_asset.uid,
        gw_asset.name,
        all_assets=dom_assets,
        snapshot=dom_pkg_snapshot,
    )

    route_entries, drift_detected, drift_map = routes_to_topology_entries(
        gateway_asset=gw_asset,
        parsed_routes_by_node=parsed_by_node,
        interface_meta=if_meta,
        installed_access_policy=inst_pol,
        policy_packages=pkg_names,
        now=now,
    )
    parsed_by_node.clear()
    entry_count = len(route_entries)

    await cache.replace_domain_topology(
        gw_asset.mgmt_name,
        gw_asset.domain_name,
        route_entries,
        gateway_uids=[gw_asset.uid],
        source_types=list(LIVE_ROUTE_SOURCES),
        sync_states=None,
    )
    route_entries.clear()

    gw_warnings: list[str] = []
    if drift_detected:
        for (d_if, d_cidr), present_nodes in sorted(drift_map.items()):
            gw_warnings.append(
                f"Cluster member route drift on {gw_asset.name} :: {d_if} ({d_cidr}): "
                f"present only on {', '.join(present_nodes)}"
            )
    if truncation_warnings:
        gw_warnings.extend(truncation_warnings)
    if node_errors:
        gw_warnings.extend(node_errors)

    return (
        GatewayRouteCollectionStatus(
            mgmt_name=gw_asset.mgmt_name,
            domain_name=gw_asset.domain_name,
            gateway_id=gw_asset.id,
            gateway_asset_id=gw_asset.asset_id,
            gateway_uid=gw_asset.uid,
            gateway_name=gw_asset.name,
            gateway_type=gw_asset.type,
            success=True,
            executor=",".join(executors_used) if executors_used else "ssh",
            routes_collected=entry_count,
            member_drift_detected=drift_detected,
            warnings=gw_warnings,
            error=None,
        ),
        entry_count,
    )


async def _finalize_domain_route_sync_states(
    results: list[tuple[GatewayRouteCollectionStatus, int]],
    *,
    cache: _TopologyServiceCachePort,
    gw_tokens: Collection[str],
    total_gateways: int,
    now: datetime,
) -> RouteCollectionOutcome:
    """Persist domain-level `routes` sync states after TaskGroup completion and return the outcome."""
    statuses = [st for st, _ in results]
    succeeded_count = sum(1 for st in statuses if st.success)
    failed_count = len(statuses) - succeeded_count
    total_routes_count = sum(cnt for _, cnt in results)

    # If any gateway in a domain failed route collection, downgrade the domain-level `routes` sync state
    # so subsequent `smart` refreshes retry route collection for that domain.
    failed_by_dom: dict[tuple[str, str], list[str]] = defaultdict(list)
    routes_count_by_dom: dict[tuple[str, str], int] = defaultdict(int)
    for st, cnt in results:
        routes_count_by_dom[(st.mgmt_name, st.domain_name)] += cnt
        if not st.success:
            failed_by_dom[(st.mgmt_name, st.domain_name)].append(f"{st.gateway_name}: {st.error or 'failed'}")

    if not gw_tokens:
        for (m_name, d_name), total_cnt in routes_count_by_dom.items():
            errs = failed_by_dom.get((m_name, d_name), [])
            prev_state = await cache.get_sync_state(m_name, d_name, "topology", "routes") if errs else None
            await cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name=m_name,
                    domain_name=d_name,
                    scope="topology",
                    item_type="routes",
                    last_published_at=prev_state.last_published_at if (errs and prev_state) else None,
                    last_session_uid=prev_state.last_session_uid if (errs and prev_state) else None,
                    synced_at=(prev_state.synced_at if prev_state else None) if errs else now,
                    status="failed" if errs else "ok",
                    object_count=total_cnt,
                    last_error="; ".join(errs) if errs else None,
                )
            )

    return RouteCollectionOutcome(
        total_gateways=total_gateways,
        succeeded_gateways=succeeded_count,
        failed_gateways=failed_count,
        total_routes=total_routes_count,
        gateways=statuses,
    )


async def collect_gateway_routes(
    *,
    settings: ArodonataSettings,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    script_service: ScriptRepositoryService,
    default_gateway_cli: GatewayCliPort | GatewayCliCallable | None,
    now_fn: Callable[[], datetime],
    route_collect_flights: dict[tuple[Any, ...], asyncio.Future[RouteCollectionOutcome]],
    get_node_lock: Callable[[str, str], asyncio.Lock],
    get_semaphore: Callable[[str, int], asyncio.Semaphore],
    mgmt_name: str | None = None,
    domain: str | None = None,
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
    eff_concurrency = (
        max(1, int(concurrency)) if concurrency is not None else max(1, int(settings.route_collect_concurrency))
    )
    eff_script_mode: CpridScriptMode = (
        cprid_script_mode if cprid_script_mode is not None else settings.cprid_script_mode
    )
    eff_script_name = (
        repository_script_name or settings.cprid_repository_script_name
    ).strip() or DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME
    span_attrs(
        mgmt_name=mgmt_name,
        domain=domain,
        fallback_to_cprid=fallback_to_cprid,
        concurrency=eff_concurrency,
        cprid_script_mode=eff_script_mode,
    )

    domain_set: set[str] | None = None
    if domains is not None:
        domain_set = set(normalize_str_sequence(domains))
    elif domain is not None and domain.strip():
        domain_set = {domain.strip()}

    gw_tokens = set(_normalize_gateway_filter_tokens(gateways))
    eff_cli = gateway_cli if gateway_cli is not None else default_gateway_cli
    can_coalesce = get_write_session() is None
    flight_key = (
        mgmt_name or "",
        tuple(sorted(domain_set)) if domain_set is not None else None,
        tuple(sorted(gw_tokens)),
        bool(include_global),
        bool(fallback_to_cprid),
        id(eff_cli) if eff_cli is not None else None,
        eff_script_mode,
        eff_script_name,
        id(repository_script_args_fn) if repository_script_args_fn is not None else None,
    )

    return await _run_single_flight(
        route_collect_flights,
        flight_key,
        can_coalesce=can_coalesce,
        is_reusable=lambda out: out.failed_gateways == 0,
        clone_result=lambda out: out.model_copy(deep=True),
        work=lambda: _collect_gateway_routes_impl(
            settings=settings,
            api=api,
            cache=cache,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            script_service=script_service,
            default_gateway_cli=default_gateway_cli,
            now_fn=now_fn,
            get_node_lock=get_node_lock,
            get_semaphore=get_semaphore,
            mgmt_name=mgmt_name,
            domain_set=domain_set,
            gw_tokens=gw_tokens,
            include_global=include_global,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
            eff_concurrency=eff_concurrency,
            eff_script_mode=eff_script_mode,
            eff_script_name=eff_script_name,
            repository_script_args_fn=repository_script_args_fn,
        ),
    )


async def _collect_gateway_routes_impl(
    *,
    settings: ArodonataSettings,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    script_service: ScriptRepositoryService,
    default_gateway_cli: GatewayCliPort | GatewayCliCallable | None,
    now_fn: Callable[[], datetime],
    get_node_lock: Callable[[str, str], asyncio.Lock],
    get_semaphore: Callable[[str, int], asyncio.Semaphore],
    mgmt_name: str | None,
    domain_set: set[str] | None,
    gw_tokens: set[str],
    include_global: bool,
    gateway_cli: GatewayCliPort | GatewayCliCallable | None,
    fallback_to_cprid: bool,
    timeout: float,
    eff_concurrency: int,
    eff_script_mode: CpridScriptMode,
    eff_script_name: str,
    repository_script_args_fn: RepositoryScriptArgsCallable | None,
) -> RouteCollectionOutcome:
    """Execute per-gateway live route collection and update cached `routes` sync states."""
    eff_cli = gateway_cli if gateway_cli is not None else default_gateway_cli
    max_routes = int(settings.max_routes_per_gateway)

    # Load all assets across the management server so VSX parents in other domains and cluster members are visible.
    # Hydrate any uncached requested domains (or uncached servers) before filtering gateways.
    all_mgmt_assets = await cache.get_assets(mgmt_name=mgmt_name)
    if domain_set is not None:
        cached_doms_by_mgmt: dict[str, set[str]] = defaultdict(set)
        for asset in all_mgmt_assets:
            cached_doms_by_mgmt[asset.mgmt_name].add(asset.domain_name)
        target_mgmts = [mgmt_name] if mgmt_name is not None else list(settings.servers.keys())
        missing_domains = sorted(
            {d for m_name in target_mgmts for d in domain_set if d not in cached_doms_by_mgmt.get(m_name, set())}
        )
        if missing_domains:
            await asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=missing_domains,
                include_global=include_global or ("Global" in missing_domains),
                mode="smart",
            )
            all_mgmt_assets = await cache.get_assets(mgmt_name=mgmt_name)
    elif not all_mgmt_assets or (
        mgmt_name is None and set(settings.servers.keys()) - {a.mgmt_name for a in all_mgmt_assets}
    ):
        await asset_service.refresh_assets(
            mgmt_name=mgmt_name,
            domains=None,
            include_global=include_global,
            mode="smart",
        )
        all_mgmt_assets = await cache.get_assets(mgmt_name=mgmt_name)

    target_gateways = [
        a
        for a in all_mgmt_assets
        if is_policy_enforcing_gateway(a)
        and (domain_set is None or a.domain_name in domain_set)
        and (include_global or domain_set is not None or a.domain_name != "Global")
        and _matches_gateway_filter(a, gw_tokens)
    ]

    now = now_fn()
    sorted_gateways = sorted(target_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name))

    dom_assets_by_key: dict[tuple[str, str], list[Asset]] = defaultdict(list)
    for a in all_mgmt_assets:
        dom_assets_by_key[(a.mgmt_name, a.domain_name)].append(a)

    pkg_snapshots_by_dom: dict[tuple[str, str], DomainRulebaseSnapshot] = {}
    pkg_snapshot_locks: dict[tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)

    async def _get_pkg_snapshot(m_name: str, d_name: str) -> DomainRulebaseSnapshot:
        key = (m_name, d_name)
        if key in pkg_snapshots_by_dom:
            return pkg_snapshots_by_dom[key]
        async with pkg_snapshot_locks[key]:
            if key not in pkg_snapshots_by_dom:
                pkg_snapshots_by_dom[key] = await _load_domain_package_snapshot(
                    cache,
                    rulebase_refresh,
                    m_name,
                    d_name,
                )
            return pkg_snapshots_by_dom[key]

    cprid_sessions: dict[tuple[str, str], tuple[str, str]] = {}
    cprid_session_locks: dict[tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)

    async def _get_cprid_session(m_name: str, d_name: str) -> tuple[str, str]:
        key = (m_name, d_name)
        async with cprid_session_locks[key]:
            if key not in cprid_sessions:
                cprid_sessions[key] = await api.create_dedicated_session(
                    m_name,
                    domain=d_name,
                    session_name="arodonata-route-collect",
                )
            return cprid_sessions[key]

    auto_mode_resolver = AutoScriptModeResolver()
    repo_node_flights: dict[tuple[str, str, str], asyncio.Future[GatewayCliResult]] = {}
    repo_node_locks: dict[tuple[str, str, str], asyncio.Lock] = defaultdict(asyncio.Lock)

    async def _run_target(target: GatewayCliTarget) -> tuple[GatewayCliTarget, GatewayCliResult]:
        return await _execute_coalesced_target(
            target,
            api=api,
            eff_cli=eff_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
            eff_concurrency=eff_concurrency,
            eff_script_mode=eff_script_mode,
            eff_script_name=eff_script_name,
            repository_script_args_fn=repository_script_args_fn,
            max_routes=max_routes,
            script_service=script_service,
            cprid_session_getter=_get_cprid_session,
            auto_mode_resolver=auto_mode_resolver,
            repo_node_flights=repo_node_flights,
            repo_node_locks=repo_node_locks,
            get_node_lock=get_node_lock,
            get_semaphore=get_semaphore,
        )

    async def _collect_for_gateway(gw_asset: Asset) -> tuple[GatewayRouteCollectionStatus, int]:
        cli_targets = resolve_gateway_cli_targets(gw_asset, all_mgmt_assets)
        try:
            async with asyncio.TaskGroup() as tg:
                target_tasks = [tg.create_task(_run_target(t)) for t in cli_targets]
            target_results = [t.result() for t in target_tasks]
        except* ServerIdentityError as eg:
            raise eg.exceptions[0] from None
        except* Exception as eg:
            raise eg.exceptions[0] from None
        known_sid_set = {sid for sid, _ in cprid_sessions.values() if sid}
        active_gw_ws = get_write_session(mgmt_name=gw_asset.mgmt_name, domain_name=gw_asset.domain_name)
        if active_gw_ws is not None and active_gw_ws.sid:
            known_sid_set.add(active_gw_ws.sid)
        known_sids = list(known_sid_set) or None

        parsed_by_node: dict[str, list[ParsedCliRoute]] = {}
        node_errors: list[str] = []
        node_error_codes: list[str] = []
        truncation_warnings: list[str] = []
        executors_used: list[str] = []

        for target, cli_res in target_results:
            if cli_res.executor and cli_res.executor not in executors_used:
                executors_used.append(cli_res.executor)
            if not cli_res.success:
                if cli_res.error_code:
                    node_error_codes.append(cli_res.error_code)
                raw_node_err = f"{target.node_name}: {cli_res.error_message or cli_res.stderr or 'CLI command failed'}"
                node_errors.append(redact_sid(raw_node_err, known_sids=known_sids) if known_sids else raw_node_err)
                continue
            raw_stdout = cli_res.stdout
            parsed_routes, was_truncated = parse_combined_cli_routes_with_status(
                raw_stdout,
                max_routes=max_routes,
            )
            if was_truncated:
                truncation_warnings.append(
                    f"Route table on {target.node_name} reached max_routes_per_gateway={max_routes} limit and was truncated"
                )
            if CLISH_SKIPPED_LARGE_TABLE_MARKER in raw_stdout:
                truncation_warnings.append(
                    f"Large routing table on {target.node_name}: skipped clish 'show route' enrichment and used kernel routes"
                )
            parsed_by_node[target.node_name] = parsed_routes
        target_results.clear()

        if not parsed_by_node:
            err_summary = "; ".join(node_errors) if node_errors else "No routes returned"
            return (
                GatewayRouteCollectionStatus(
                    mgmt_name=gw_asset.mgmt_name,
                    domain_name=gw_asset.domain_name,
                    gateway_id=gw_asset.id,
                    gateway_asset_id=gw_asset.asset_id,
                    gateway_uid=gw_asset.uid,
                    gateway_name=gw_asset.name,
                    gateway_type=gw_asset.type,
                    success=False,
                    executor=",".join(executors_used) if executors_used else "cprid",
                    routes_collected=0,
                    error_code=node_error_codes[0] if node_error_codes else None,
                    error=err_summary,
                ),
                0,
            )

        dom_assets = dom_assets_by_key.get((gw_asset.mgmt_name, gw_asset.domain_name), [])
        dom_pkg_snapshot = await _get_pkg_snapshot(gw_asset.mgmt_name, gw_asset.domain_name)
        return await _persist_gateway_routes(
            gw_asset,
            parsed_by_node,
            cache=cache,
            rulebase_refresh=rulebase_refresh,
            dom_assets=dom_assets,
            dom_pkg_snapshot=dom_pkg_snapshot,
            now=now,
            executors_used=executors_used,
            truncation_warnings=truncation_warnings,
            node_errors=node_errors,
        )

    try:
        try:
            async with asyncio.TaskGroup() as tg:
                gw_tasks = [tg.create_task(_collect_for_gateway(gw)) for gw in sorted_gateways]
            results = [t.result() for t in gw_tasks]
        except* ServerIdentityError as eg:
            raise eg.exceptions[0] from None
        except* Exception as eg:
            raise eg.exceptions[0] from None
    finally:
        pending_cancel: asyncio.CancelledError | None = None
        for (m_name, _d_name), (ded_sid, ded_ip) in list(cprid_sessions.items()):
            try:
                await asyncio.shield(api.logout_sid(m_name, ded_sid, server_ip=ded_ip))
            except asyncio.CancelledError as exc:
                if pending_cancel is None:
                    pending_cancel = exc
            except Exception:
                pass
        if pending_cancel is not None:
            raise pending_cancel

    return await _finalize_domain_route_sync_states(
        results,
        cache=cache,
        gw_tokens=gw_tokens,
        total_gateways=len(target_gateways),
        now=now,
    )


__all__ = [
    "collect_gateway_routes",
]
