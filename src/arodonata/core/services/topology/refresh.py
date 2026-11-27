"""Targeted and full-domain topology refresh orchestration and streaming progress handlers."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_write_session
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.events import (
    DomainSyncCompletedEvent,
    DomainSyncFailedEvent,
    DomainSyncStartedEvent,
    SyncCompletedEvent,
    SyncProgressEvent,
    SyncStartedEvent,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.models.scripts import CpridScriptMode
from arodonata.core.models.topology import STATIC_TOPOLOGY_SOURCES
from arodonata.core.ports import ApiPort, RulebaseRefreshPort
from arodonata.core.primitives import normalize_str_sequence
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.sync_coordinator import DomainSyncCoordinator
from arodonata.core.services.topology._shared import (
    RepositoryScriptArgsCallable,
    _CollectRoutesFn,
    _matches_gateway_filter,
    _normalize_gateway_filter_tokens,
    _run_single_flight,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
    logger,
)
from arodonata.core.services.topology.extractor import (
    _compute_trusted_object_domains,
    _extract_domain_topology_entries,
    _sync_domain_topology,
)
from arodonata.core.services.topology.objects import (
    _fetch_asset_detail_on_demand,
    _load_domain_scoped_objects,
)
from arodonata.core.telemetry import span_attrs


async def _collect_routes_for_refresh(
    *,
    settings: ArodonataSettings,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    now_fn: Callable[[], datetime],
    collect_routes_fn: _CollectRoutesFn,
    mgmt_name: str | None,
    domains: Sequence[str] | str | None,
    include_global: bool,
    mode: CacheMode,
    refreshed_domain_labels: Sequence[str],
    cache_ttl: float | None = None,
    cprid_script_mode: CpridScriptMode | None = None,
    repository_script_name: str | None = None,
    repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
) -> None:
    """Collect live gateway routes during `refresh_topology`, skipping domains whose routes are already fresh in `smart` mode."""
    if mode == "cache":
        return
    if mode == "force":
        force_domains = await coordinator.resolve_target_domains(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode="cache",
        )
        inv_before_force = {
            (dom.mgmt_name, dom.name): coordinator._effective_invalidation(dom.mgmt_name, dom.name)
            for dom in force_domains
        }
        outcome = await collect_routes_fn(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )
        failed_doms = (
            {(st.mgmt_name, st.domain_name) for st in outcome.gateways if not st.success}
            if hasattr(outcome, "gateways")
            else set()
        )
        for (m_name, d_name), inv_before in inv_before_force.items():
            if (m_name, d_name) not in failed_doms and coordinator._effective_invalidation(
                m_name, d_name
            ) == inv_before:
                coordinator._record_slice_synced(
                    m_name,
                    d_name,
                    "topology",
                    ["routes"],
                    target_seq=inv_before[1],
                )
        return

    target_domains = await coordinator.resolve_target_domains(
        mgmt_name=mgmt_name,
        domains=domains,
        include_global=include_global,
        mode="cache",
    )
    all_assets = await cache.get_assets(mgmt_name=mgmt_name)
    domains_with_gateways: set[tuple[str, str]] = {
        (a.mgmt_name, a.domain_name) for a in all_assets if is_policy_enforcing_gateway(a)
    }
    refreshed_set = set(refreshed_domain_labels)
    now = now_fn()
    eff_ttl = float(cache_ttl) if cache_ttl is not None else float(settings.cache_ttl)
    domains_to_collect: dict[str, list[str]] = defaultdict(list)

    for dom in target_domains:
        if (dom.mgmt_name, dom.name) not in domains_with_gateways:
            continue
        dom_label = f"{dom.mgmt_name}:{dom.name}"
        route_state = await cache.get_sync_state(
            dom.mgmt_name,
            dom.name,
            "topology",
            "routes",
        )
        if dom_label in refreshed_set or coordinator.is_domain_invalidated(
            dom.mgmt_name,
            dom.name,
            scope="topology",
            item_type="routes",
            synced_at=route_state.synced_at if route_state is not None else None,
        ):
            domains_to_collect[dom.mgmt_name].append(dom.name)
            continue
        if route_state is None or route_state.status != "ok" or route_state.synced_at is None:
            domains_to_collect[dom.mgmt_name].append(dom.name)
            continue
        if eff_ttl > 0:
            age = (now - route_state.synced_at).total_seconds()
            if age >= eff_ttl:
                domains_to_collect[dom.mgmt_name].append(dom.name)

    for m_name, dom_names in domains_to_collect.items():
        inv_before_by_dom = {d_name: coordinator._effective_invalidation(m_name, d_name) for d_name in dom_names}
        outcome = await collect_routes_fn(
            mgmt_name=m_name,
            domains=dom_names,
            include_global=include_global or ("Global" in dom_names),
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )
        failed_dom_names = (
            {st.domain_name for st in outcome.gateways if not st.success and st.mgmt_name == m_name}
            if hasattr(outcome, "gateways")
            else set()
        )
        for d_name, inv_before in inv_before_by_dom.items():
            if d_name not in failed_dom_names and coordinator._effective_invalidation(m_name, d_name) == inv_before:
                coordinator._record_slice_synced(
                    m_name,
                    d_name,
                    "topology",
                    ["routes"],
                    target_seq=inv_before[1],
                )


async def _stream_targeted_gateway_refresh(
    *,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    collect_routes_fn: _CollectRoutesFn,
    mgmt_name: str | None,
    domains: Sequence[str] | str | None,
    gw_tokens: set[str],
    collect_routes: bool,
    include_global: bool,
    mode: CacheMode,
    cache_ttl: float | None,
    cprid_script_mode: CpridScriptMode | None = None,
    repository_script_name: str | None = None,
    repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
) -> AsyncIterator[SyncProgressEvent]:
    """Refresh static topology (and optionally live routes) ONLY for the specified `gw_tokens` without rewriting other gateways."""
    target_domains = await coordinator.resolve_target_domains(
        mgmt_name=mgmt_name,
        domains=domains,
        include_global=include_global,
        mode=mode,
    )
    yield SyncStartedEvent(
        scope="topology",
        mgmt_name=mgmt_name,
        message=f"Starting targeted gateway topology refresh across {len(target_domains)} domain(s).",
        total=len(target_domains),
        details={"mode": mode, "gateways": sorted(gw_tokens)},
    )

    refreshed_domains: list[str] = []
    skipped_domains: list[str] = []
    failed_domains: dict[str, str] = {}
    total_items = 0
    global_obj_cache: dict[str, list[CPObject]] = {}
    global_trusted_cache: dict[str, bool] = {}
    global_obj_lock = asyncio.Lock()

    for dom in target_domains:
        dom_label = f"{dom.mgmt_name}:{dom.name}"
        try:
            domain_assets = await cache.get_assets(mgmt_name=dom.mgmt_name, domain_name=dom.name)
            if not domain_assets and mode != "cache":
                domain_assets = await asset_service.get_assets(
                    mgmt_name=dom.mgmt_name,
                    domain=dom.name,
                    cache_mode=mode,
                    cache_ttl=cache_ttl,
                )

            matched_gateways = [
                a for a in domain_assets if is_policy_enforcing_gateway(a) and _matches_gateway_filter(a, gw_tokens)
            ]
            if not matched_gateways:
                skipped_domains.append(dom_label)
                continue

            yield DomainSyncStartedEvent(
                scope="topology",
                mgmt_name=dom.mgmt_name,
                domain=dom.name,
                item_type="gateway-topology",
                message=f"Refreshing {len(matched_gateways)} targeted gateway(s) in {dom_label}.",
            )

            refreshed_gw_map: dict[str, Asset] = {}
            if mode != "cache":
                await coordinator.verify_session_clean(dom.mgmt_name, dom.name)
                # Force on-demand detail fetch for each targeted gateway so modified interface definitions are pulled
                for gw_asset in matched_gateways:
                    enriched = await _fetch_asset_detail_on_demand(api, dom.mgmt_name, dom.name, gw_asset)
                    if enriched is not None:
                        refreshed_gw_map[enriched.uid] = enriched
                if refreshed_gw_map:
                    await cache.upsert_assets(list(refreshed_gw_map.values()))
                    domain_assets = [refreshed_gw_map.get(a.uid, a) for a in domain_assets]

            all_objects = await _load_domain_scoped_objects(
                cache,
                dom.mgmt_name,
                dom.name,
                global_cache=global_obj_cache,
                global_lock=global_obj_lock,
            )
            trusted_domains = (
                await _compute_trusted_object_domains(
                    cache,
                    coordinator,
                    dom.mgmt_name,
                    dom.name,
                    dom_info=dom,
                    mode=mode,
                    cache_ttl=cache_ttl,
                    force_object_refresh=(mode == "force"),
                    global_trusted_cache=global_trusted_cache,
                    global_lock=global_obj_lock,
                )
                if mode != "cache"
                else None
            )

            target_gw_uids = [g.uid for g in matched_gateways]
            entries, updated_assets = await _extract_domain_topology_entries(
                api=api,
                cache=cache,
                rulebase_refresh=rulebase_refresh,
                now_fn=now_fn,
                mgmt_name=dom.mgmt_name,
                domain_name=dom.name,
                assets=domain_assets,
                objects=all_objects,
                target_gateway_uids=set(target_gw_uids),
                allow_live_detail=mode != "cache",
                force_object_refresh=(mode == "force"),
                trusted_object_domains=trusted_domains,
                already_detailed_uids=set(refreshed_gw_map),
                global_cache=global_obj_cache,
                global_lock=global_obj_lock,
            )
            if updated_assets:
                await cache.upsert_assets(updated_assets)

            count = await cache.replace_domain_topology(
                dom.mgmt_name,
                dom.name,
                entries,
                gateway_uids=target_gw_uids,
                source_types=list(STATIC_TOPOLOGY_SOURCES),
            )
            if collect_routes and mode != "cache":
                route_outcome = await collect_routes_fn(
                    mgmt_name=dom.mgmt_name,
                    domain=dom.name,
                    gateways=target_gw_uids,
                    cprid_script_mode=cprid_script_mode,
                    repository_script_name=repository_script_name,
                    repository_script_args_fn=repository_script_args_fn,
                )
                count += route_outcome.total_routes

            refreshed_domains.append(dom_label)
            total_items += count
            yield DomainSyncCompletedEvent(
                scope="topology",
                mgmt_name=dom.mgmt_name,
                domain=dom.name,
                item_type="gateway-topology",
                processed=count,
                total=count,
                message=f"Refreshed {count} topology interval(s) for {len(target_gw_uids)} gateway(s) in {dom_label}.",
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            known_sid_list = await coordinator._collect_known_sids(dom.mgmt_name)
            active_ws = get_write_session(mgmt_name=dom.mgmt_name, domain_name=dom.name)
            if active_ws is not None and active_ws.sid and active_ws.sid not in known_sid_list:
                known_sid_list.append(active_ws.sid)
            err_str = redact_sid(str(exc), known_sids=known_sid_list or None)
            failed_domains[dom_label] = err_str
            logger.warning(
                f"Targeted gateway topology refresh failed in {dom_label}: {err_str}",
                mgmt_name=dom.mgmt_name,
                domain_name=dom.name,
            )
            yield DomainSyncFailedEvent(
                scope="topology",
                mgmt_name=dom.mgmt_name,
                domain=dom.name,
                item_type="gateway-topology",
                error=err_str,
                message=f"Targeted gateway topology refresh failed in {dom_label}: {err_str}",
            )

    yield SyncCompletedEvent(
        scope="topology",
        mgmt_name=mgmt_name,
        processed=total_items,
        total=total_items,
        message=(
            f"Completed targeted topology refresh: {len(refreshed_domains)} refreshed, "
            f"{len(skipped_domains)} skipped, {len(failed_domains)} failed."
        ),
        details={
            "refreshed_domains": refreshed_domains,
            "skipped_domains": skipped_domains,
            "failed_domains": failed_domains,
            "total_items": total_items,
        },
    )


async def _refresh_topology_impl(
    *,
    settings: ArodonataSettings,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    collect_routes_fn: _CollectRoutesFn,
    mgmt_name: str | None,
    domains: Sequence[str] | str | None,
    gw_tokens: list[str],
    collect_routes: bool,
    include_global: bool,
    mode: CacheMode,
    cache_ttl: float | None,
    cprid_script_mode: CpridScriptMode | None = None,
    repository_script_name: str | None = None,
    repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
) -> RefreshOutcome:
    """Execute targeted or whole-domain topology synchronization and optional live route collection."""
    if gw_tokens:
        refreshed_domains: list[str] = []
        skipped_domains: list[str] = []
        failed_domains: dict[str, str] = {}
        total_items = 0
        async for event in _stream_targeted_gateway_refresh(
            api=api,
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            collect_routes_fn=collect_routes_fn,
            mgmt_name=mgmt_name,
            domains=domains,
            gw_tokens=set(gw_tokens),
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        ):
            if isinstance(event, SyncCompletedEvent):
                refreshed_domains = list(event.details.get("refreshed_domains") or [])
                skipped_domains = list(event.details.get("skipped_domains") or [])
                failed_domains = dict(event.details.get("failed_domains") or {})
                total_items = int(event.details.get("total_items") or 0)
        return RefreshOutcome(
            scope="topology",
            refreshed_domains=refreshed_domains,
            skipped_domains=skipped_domains,
            failed_domains=failed_domains,
            total_items=total_items,
        )

    if mode != "cache":
        await asset_service.refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    global_obj_cache: dict[str, list[CPObject]] = {}
    global_trusted_cache: dict[str, bool] = {}
    global_obj_lock = asyncio.Lock()
    outcome = await coordinator.ensure(
        scope="topology",
        item_types=["*"],
        handler=lambda probe, emit: _sync_domain_topology(
            api=api,
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            probe=probe,
            emit=emit,
            global_cache=global_obj_cache,
            global_trusted_cache=global_trusted_cache,
            global_lock=global_obj_lock,
            force_object_refresh=(mode == "force"),
            cache_ttl=cache_ttl,
        ),
        mgmt_name=mgmt_name,
        domains=domains,
        include_global=include_global,
        mode=mode,
        cache_ttl=cache_ttl,
    )
    if collect_routes and mode != "cache":
        await _collect_routes_for_refresh(
            settings=settings,
            cache=cache,
            coordinator=coordinator,
            now_fn=now_fn,
            collect_routes_fn=collect_routes_fn,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            refreshed_domain_labels=outcome.refreshed_domains,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )
    return outcome


async def stream_refresh_topology(
    *,
    settings: ArodonataSettings,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    collect_routes_fn: _CollectRoutesFn,
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
    gw_tokens = _normalize_gateway_filter_tokens(gateways)
    if gw_tokens:
        async for event in _stream_targeted_gateway_refresh(
            api=api,
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            collect_routes_fn=collect_routes_fn,
            mgmt_name=mgmt_name,
            domains=domains,
            gw_tokens=set(gw_tokens),
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        ):
            yield event
        return

    if mode != "cache":
        async for event in asset_service.stream_refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    global_obj_cache: dict[str, list[CPObject]] = {}
    global_trusted_cache: dict[str, bool] = {}
    global_obj_lock = asyncio.Lock()
    refreshed_labels: list[str] = []
    pending_completed: SyncCompletedEvent | None = None
    async for event in coordinator.stream_ensure(
        scope="topology",
        item_types=["*"],
        handler=lambda probe, emit: _sync_domain_topology(
            api=api,
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            probe=probe,
            emit=emit,
            global_cache=global_obj_cache,
            global_trusted_cache=global_trusted_cache,
            global_lock=global_obj_lock,
            force_object_refresh=(mode == "force"),
            cache_ttl=cache_ttl,
        ),
        mgmt_name=mgmt_name,
        domains=domains,
        include_global=include_global,
        mode=mode,
        cache_ttl=cache_ttl,
    ):
        if isinstance(event, SyncCompletedEvent):
            refreshed_labels = list(event.details.get("refreshed_domains") or [])
            pending_completed = event
            continue
        yield event

    if collect_routes and mode != "cache":
        await _collect_routes_for_refresh(
            settings=settings,
            cache=cache,
            coordinator=coordinator,
            now_fn=now_fn,
            collect_routes_fn=collect_routes_fn,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            refreshed_domain_labels=refreshed_labels,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    if pending_completed is not None:
        yield pending_completed


async def refresh_topology(
    *,
    settings: ArodonataSettings,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    collect_routes_fn: _CollectRoutesFn,
    refresh_flights: dict[tuple[Any, ...], asyncio.Future[RefreshOutcome]],
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
    eff_script_mode = cprid_script_mode if cprid_script_mode is not None else settings.cprid_script_mode
    eff_script_name = (repository_script_name or settings.cprid_repository_script_name).strip()
    span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global, collect_routes=collect_routes)
    gw_tokens = _normalize_gateway_filter_tokens(gateways)

    norm_domains: tuple[str, ...] | None = (
        tuple(sorted(set(normalize_str_sequence(domains)))) if domains is not None else None
    )

    can_coalesce = get_write_session() is None
    flight_key = (
        mgmt_name or "",
        norm_domains,
        tuple(sorted(set(gw_tokens))),
        bool(collect_routes),
        bool(include_global),
        mode,
        eff_script_mode,
        eff_script_name,
        id(repository_script_args_fn) if repository_script_args_fn is not None else None,
    )

    return await _run_single_flight(
        refresh_flights,
        flight_key,
        can_coalesce=can_coalesce,
        is_reusable=lambda out: not out.failed_domains,
        clone_result=lambda out: out.model_copy(deep=True),
        work=lambda: _refresh_topology_impl(
            settings=settings,
            api=api,
            cache=cache,
            coordinator=coordinator,
            asset_service=asset_service,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            collect_routes_fn=collect_routes_fn,
            mgmt_name=mgmt_name,
            domains=domains,
            gw_tokens=gw_tokens,
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        ),
    )
