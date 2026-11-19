"""Static topology vs live routing reconciliation and gateway-targeted policy verification."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from arodonata.core.config import TopologyConfidenceWeights
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.scripts import CpridScriptMode
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    STATIC_TOPOLOGY_SOURCES,
    GatewayTopologyEntry,
    TopologyAnnotation,
    TopologyDiagnosticSeverity,
    TopologyDiscrepancy,
    TopologyDiscrepancyType,
    TopologyReconciliationReport,
)
from arodonata.core.ports import GatewayCliCallable, GatewayCliPort, RulebaseRefreshPort
from arodonata.core.primitives import MAX_IPV4_INT
from arodonata.core.services.topology._shared import (
    RepositoryScriptArgsCallable,
    _CollectRoutesFn,
    _ExpandedPolicyRule,
    _matches_gateway_filter,
    _normalize_gateway_filter_tokens,
    _NormalizedInterface,
    _RefreshTopologyFn,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology.diagnostics import get_topology_diagnostics
from arodonata.core.services.topology.normalizer import _normalize_gateway_interfaces
from arodonata.core.services.topology.objects import _index_objects, _load_domain_scoped_objects
from arodonata.core.services.topology.policy_rules import (
    _expand_domain_policy_rules,
    _filter_rules_for_gateway,
    _resolve_gateway_policy_metadata,
)
from arodonata.core.services.topology.scoring import (
    _build_effective_gateway_entries,
    _index_annotations_for_gateway,
    _is_cidr_covered_by_entries,
)
from arodonata.core.telemetry import span_attrs


def _make_discrepancy(
    gw_asset: Asset,
    *,
    discrepancy_type: TopologyDiscrepancyType,
    severity: TopologyDiagnosticSeverity,
    interface_name: str,
    cidr_or_range: str,
    static_sources: Sequence[str],
    route_sources: Sequence[str],
    message: str,
    routed_interface_name: str | None = None,
    annotation_disposition: Any = None,
    suppressed_by_annotation: bool = False,
    confidence_delta: float = 0.0,
    member_details: dict[str, Any] | None = None,
) -> TopologyDiscrepancy:
    """Build a `TopologyDiscrepancy` with shared gateway identity fields."""
    return TopologyDiscrepancy(
        mgmt_name=gw_asset.mgmt_name,
        domain_name=gw_asset.domain_name,
        gateway_id=gw_asset.id,
        gateway_asset_id=gw_asset.asset_id,
        gateway_uid=gw_asset.uid,
        gateway_name=gw_asset.name,
        gateway_type=gw_asset.type,
        discrepancy_type=discrepancy_type,
        severity=severity,
        interface_name=interface_name,
        routed_interface_name=routed_interface_name,
        cidr_or_range=cidr_or_range,
        static_sources=list(static_sources),
        route_sources=list(route_sources),
        annotation_disposition=annotation_disposition,
        suppressed_by_annotation=suppressed_by_annotation,
        confidence_delta=confidence_delta,
        member_details=member_details or {},
        message=message,
    )


def _reconcile_default_route(
    gw_asset: Asset,
    *,
    static_entries: Sequence[GatewayTopologyEntry],
    route_entries: Sequence[GatewayTopologyEntry],
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    gw_trust_static: bool | None,
    if_trust_static: dict[str, bool],
    weights: TopologyConfidenceWeights,
) -> list[TopologyDiscrepancy]:
    """Phase 1: Compare SmartConsole external interface flag against live `0.0.0.0/0` default routes."""
    static_external = [e for e in static_entries if e.topology_zone == "external"]
    default_routes = [
        e for e in route_entries if e.prefix_len == 0 and e.ip_first_int == 0 and e.ip_last_int == MAX_IPV4_INT
    ]
    if not static_external or not default_routes:
        return []

    static_ext_ifs = {e.interface_name for e in static_external}
    route_ext_ifs = {e.interface_name for e in default_routes}
    if static_ext_ifs.intersection(route_ext_ifs):
        return []

    s_if = sorted(static_ext_ifs)[0]
    r_if = sorted(route_ext_ifs)[0]
    ann_match = ann_by_if_cidr.get((s_if, "0.0.0.0/0")) or ann_by_if_cidr.get(("*", "0.0.0.0/0"))
    disp = ann_match.disposition if ann_match else None
    if_untrusted = if_trust_static.get(s_if, gw_trust_static) is False
    suppressed = disp in ("confirmed", "standby_dynamic", "ignore") or if_untrusted
    return [
        _make_discrepancy(
            gw_asset,
            discrepancy_type="default_route_mismatch",
            severity="info" if suppressed else "warning",
            interface_name=s_if,
            routed_interface_name=r_if,
            cidr_or_range="0.0.0.0/0",
            static_sources=sorted({e.source_type for e in static_external}),
            route_sources=sorted({e.source_type for e in default_routes}),
            annotation_disposition=disp,
            suppressed_by_annotation=suppressed,
            confidence_delta=weights.conflict_routed_to_other_interface_static,
            message=(
                f"SmartConsole marks {s_if!r} as External on {gw_asset.name!r}, "
                f"but live default route 0.0.0.0/0 egresses via {r_if!r}."
            ),
        )
    ]


def _reconcile_static_against_routes(
    gw_asset: Asset,
    *,
    static_internal: Sequence[GatewayTopologyEntry],
    route_internal: Sequence[GatewayTopologyEntry],
    route_by_if: dict[str, list[GatewayTopologyEntry]],
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    gw_trust_static: bool | None,
    if_trust_static: dict[str, bool],
    weights: TopologyConfidenceWeights,
) -> tuple[list[TopologyDiscrepancy], set[tuple[str, str]]]:
    """Phase 2: Check each static internal interval against live route intervals."""
    discrepancies: list[TopologyDiscrepancy] = []
    seen_static_pairs: set[tuple[str, str]] = set()
    mismatched_routed_if_cidrs: set[tuple[str, str]] = set()

    for se in static_internal:
        pair_key = (se.interface_name, se.cidr_or_range)
        if pair_key in seen_static_pairs:
            continue
        seen_static_pairs.add(pair_key)

        same_if_routes = route_internal if se.interface_name == "vpn-domain" else route_by_if.get(se.interface_name, [])
        if _is_cidr_covered_by_entries(se.ip_first_int, se.ip_last_int, same_if_routes):
            continue

        other_if_matches: list[GatewayTopologyEntry] = []
        if se.interface_name != "vpn-domain":
            for other_if, r_list in route_by_if.items():
                if other_if == se.interface_name:
                    continue
                for r_entry in r_list:
                    if r_entry.ip_first_int <= se.ip_first_int and se.ip_last_int <= r_entry.ip_last_int:
                        other_if_matches.append(r_entry)

        ann_match = ann_by_if_cidr.get((se.interface_name, se.cidr_or_range)) or ann_by_if_cidr.get(
            ("*", se.cidr_or_range)
        )
        disp = ann_match.disposition if ann_match else None
        if_untrusted = if_trust_static.get(se.interface_name, gw_trust_static) is False
        suppressed = disp in ("confirmed", "standby_dynamic", "ignore") or if_untrusted

        if other_if_matches:
            routed_if = other_if_matches[0].interface_name
            mismatched_routed_if_cidrs.add((routed_if, se.cidr_or_range))
            discrepancies.append(
                _make_discrepancy(
                    gw_asset,
                    discrepancy_type="interface_mismatch",
                    severity="info" if suppressed else "warning",
                    interface_name=se.interface_name,
                    routed_interface_name=routed_if,
                    cidr_or_range=se.cidr_or_range,
                    static_sources=[se.source_type],
                    route_sources=sorted({m.source_type for m in other_if_matches}),
                    annotation_disposition=disp,
                    suppressed_by_annotation=suppressed,
                    confidence_delta=weights.conflict_routed_to_other_interface_static,
                    message=(
                        f"Prefix {se.cidr_or_range} is listed in static topology on {se.interface_name!r} "
                        f"of {gw_asset.name!r}, but live routing directs it to {routed_if!r}."
                    ),
                )
            )
        else:
            discrepancies.append(
                _make_discrepancy(
                    gw_asset,
                    discrepancy_type="stale_in_topology",
                    severity="info" if suppressed else "warning",
                    interface_name=se.interface_name,
                    routed_interface_name=None,
                    cidr_or_range=se.cidr_or_range,
                    static_sources=[se.source_type],
                    route_sources=[],
                    annotation_disposition=disp,
                    suppressed_by_annotation=suppressed,
                    confidence_delta=(
                        weights.admin_standby_dynamic
                        if disp == "standby_dynamic"
                        else weights.conflict_missing_in_live_routes
                    ),
                    message=(
                        f"Prefix {se.cidr_or_range} is configured in static topology on {se.interface_name!r} "
                        f"of {gw_asset.name!r}, but is absent from live routing tables."
                    ),
                )
            )

    return discrepancies, mismatched_routed_if_cidrs


def _reconcile_routes_against_static(
    gw_asset: Asset,
    *,
    route_entries: Sequence[GatewayTopologyEntry],
    static_by_if: dict[str, list[GatewayTopologyEntry]],
    norm_ifs_by_name: dict[str, _NormalizedInterface],
    mismatched_routed_if_cidrs: set[tuple[str, str]],
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    weights: TopologyConfidenceWeights,
) -> list[TopologyDiscrepancy]:
    """Phase 3: Check each live route interval against static topology and cluster member drift."""
    discrepancies: list[TopologyDiscrepancy] = []
    seen_route_pairs: set[tuple[str, str]] = set()

    for re_entry in route_entries:
        r_pair = (re_entry.interface_name, re_entry.cidr_or_range)
        if r_pair in seen_route_pairs:
            continue
        seen_route_pairs.add(r_pair)

        # Check cluster member drift encoded in `source_ref` (`;members:node1;drift:1/2`)
        if ";drift:" in re_entry.source_ref:
            present_members: list[str] = []
            for part in re_entry.source_ref.split(";"):
                if part.startswith("members:"):
                    present_members = [m for m in part.removeprefix("members:").split(",") if m]
            discrepancies.append(
                _make_discrepancy(
                    gw_asset,
                    discrepancy_type="cluster_member_drift",
                    severity="warning",
                    interface_name=re_entry.interface_name,
                    cidr_or_range=re_entry.cidr_or_range,
                    static_sources=[],
                    route_sources=[re_entry.source_type],
                    confidence_delta=weights.conflict_cluster_member_drift,
                    member_details={"present_on_members": present_members},
                    message=(
                        f"Route {re_entry.cidr_or_range} on {re_entry.interface_name!r} of cluster "
                        f"{gw_asset.name!r} is present only on member(s): {', '.join(present_members)}."
                    ),
                )
            )

        if re_entry.topology_zone == "external":
            continue

        same_if_static = static_by_if.get(re_entry.interface_name, [])
        if _is_cidr_covered_by_entries(re_entry.ip_first_int, re_entry.ip_last_int, same_if_static):
            continue

        # If already reported as `interface_mismatch` from the static side, skip duplicate in O(1)
        if (re_entry.interface_name, re_entry.cidr_or_range) in mismatched_routed_if_cidrs:
            continue

        nif = norm_ifs_by_name.get(re_entry.interface_name)
        mode_lower = (nif.behind_mode if nif else "").lower()
        ann_match = ann_by_if_cidr.get((re_entry.interface_name, re_entry.cidr_or_range)) or ann_by_if_cidr.get(
            ("*", re_entry.cidr_or_range)
        )
        disp = ann_match.disposition if ann_match else None
        suppressed = disp in ("confirmed", "standby_dynamic", "ignore")

        if "routing" in mode_lower or not mode_lower or "not defined" in mode_lower:
            discrepancies.append(
                _make_discrepancy(
                    gw_asset,
                    discrepancy_type="resolved_by_routing",
                    severity="info",
                    interface_name=re_entry.interface_name,
                    cidr_or_range=re_entry.cidr_or_range,
                    static_sources=[],
                    route_sources=[re_entry.source_type],
                    annotation_disposition=disp,
                    suppressed_by_annotation=suppressed,
                    confidence_delta=(
                        weights.route_connected
                        if re_entry.source_type == "connected_route"
                        else (
                            weights.route_static
                            if re_entry.source_type in ("gaia_static_route", "clish_route")
                            else weights.route_dynamic
                        )
                    ),
                    message=(
                        f"Prefix {re_entry.cidr_or_range} on {re_entry.interface_name!r} of {gw_asset.name!r} "
                        f"was resolved via live routing ({re_entry.source_type})."
                    ),
                )
            )
        else:
            discrepancies.append(
                _make_discrepancy(
                    gw_asset,
                    discrepancy_type="missing_in_topology",
                    severity="info" if suppressed else "warning",
                    interface_name=re_entry.interface_name,
                    cidr_or_range=re_entry.cidr_or_range,
                    static_sources=[s.source_type for s in same_if_static[:1]],
                    route_sources=[re_entry.source_type],
                    annotation_disposition=disp,
                    suppressed_by_annotation=suppressed,
                    confidence_delta=0.0,
                    message=(
                        f"Live route {re_entry.cidr_or_range} ({re_entry.source_type}) egresses via "
                        f"{re_entry.interface_name!r} on {gw_asset.name!r}, but is missing from "
                        "SmartConsole static topology."
                    ),
                )
            )

    return discrepancies


async def _reconcile_policy_against_topology(
    *,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    gw_asset: Asset,
    gw_entries: Sequence[GatewayTopologyEntry],
    gw_anns: Sequence[TopologyAnnotation],
    static_internal: Sequence[GatewayTopologyEntry],
    route_internal: Sequence[GatewayTopologyEntry],
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    ann_by_if_wildcard: dict[str, TopologyAnnotation],
    assets_by_dom: dict[tuple[str, str], list[Asset]],
    global_obj_cache: dict[str, list[CPObject]],
    state: dict[str, Any],
) -> list[TopologyDiscrepancy]:
    """Phase 4: Flag gateway-targeted rules whose explicit networks overlap zero internal intervals."""
    eff_gw_entries, _, _, _, _, _ = _build_effective_gateway_entries(
        gw_entries,
        gw_anns,
        gateway_asset=gw_asset,
    )
    effective_internal = [e for e in eff_gw_entries if e.topology_zone == "internal"]
    if not effective_internal:
        return []

    indexed_objs_by_dom: dict[tuple[str, str], tuple[dict[str, CPObject], dict[str, CPObject]]] = state[
        "indexed_objs_by_dom"
    ]
    snapshots_by_dom: dict[tuple[str, str], DomainRulebaseSnapshot] = state["snapshots_by_dom"]
    expanded_rules_by_dom: dict[tuple[str, str], list[_ExpandedPolicyRule]] = state["expanded_rules_by_dom"]

    dom_key = (gw_asset.mgmt_name, gw_asset.domain_name)
    if state["active_dom_key"] != dom_key:
        indexed_objs_by_dom.clear()
        snapshots_by_dom.clear()
        expanded_rules_by_dom.clear()
        state["active_dom_key"] = dom_key

    if dom_key not in snapshots_by_dom:
        snapshots_by_dom[dom_key] = await cache.get_domain_rulebase(
            gw_asset.mgmt_name,
            gw_asset.domain_name,
        )
    dom_snapshot = snapshots_by_dom[dom_key]
    if dom_key not in expanded_rules_by_dom:
        if not dom_snapshot.access_rules and not dom_snapshot.nat_rules:
            expanded_rules_by_dom[dom_key] = []
        else:
            if dom_key not in indexed_objs_by_dom:
                scoped_objs = await _load_domain_scoped_objects(
                    cache,
                    gw_asset.mgmt_name,
                    gw_asset.domain_name,
                    global_cache=global_obj_cache,
                )
                indexed_objs_by_dom[dom_key] = _index_objects(scoped_objs, domain_name=gw_asset.domain_name)
            obj_by_uid, obj_by_name = indexed_objs_by_dom[dom_key]
            expanded_rules_by_dom[dom_key] = _expand_domain_policy_rules(
                dom_snapshot,
                domain_assets=assets_by_dom.get(dom_key, []),
                obj_by_uid=obj_by_uid,
                obj_by_name=obj_by_name,
                for_reconciliation=True,
            )

    inst_pol, pkg_names, _ = await _resolve_gateway_policy_metadata(
        cache,
        rulebase_refresh,
        gw_asset.mgmt_name,
        gw_asset.domain_name,
        gw_asset,
        gw_asset.uid,
        gw_asset.name,
        all_assets=assets_by_dom.get(dom_key, []),
        snapshot=dom_snapshot,
    )
    targeted_rules = _filter_rules_for_gateway(
        expanded_rules_by_dom[dom_key],
        gateway_uid=gw_asset.uid,
        gateway_name=gw_asset.name,
        gateway_id=gw_asset.id,
        gateway_asset_id=gw_asset.asset_id,
        installed_policy=inst_pol,
        policy_packages=pkg_names,
        require_gateway_specific_install_on=True,
    )

    discrepancies: list[TopologyDiscrepancy] = []
    seen_mismatch_rules: set[str] = set()
    for rule in targeted_rules:
        if rule.rule_uid in seen_mismatch_rules:
            continue
        any_internal_overlap = any(
            not (ie.ip_last_int < ep.ip_first_int or ie.ip_first_int > ep.ip_last_int)
            for ep in (*rule.source_intervals, *rule.destination_intervals)
            for ie in effective_internal
        )
        if any_internal_overlap:
            continue

        seen_mismatch_rules.add(rule.rule_uid)
        src_cidrs = ", ".join(dict.fromkeys(ep.cidr_or_range for ep in rule.source_intervals)) or "Any"
        dst_cidrs = ", ".join(dict.fromkeys(ep.cidr_or_range for ep in rule.destination_intervals)) or "Any"
        cidr_summary = f"{src_cidrs} -> {dst_cidrs}"
        ann_match = (
            ann_by_if_cidr.get(("policy", cidr_summary))
            or ann_by_if_cidr.get(("*", cidr_summary))
            or ann_by_if_wildcard.get("policy")
        )
        disp = ann_match.disposition if ann_match else None
        suppressed = disp in ("confirmed", "standby_dynamic", "ignore")
        discrepancies.append(
            _make_discrepancy(
                gw_asset,
                discrepancy_type="policy_topology_mismatch",
                severity="info" if suppressed else "warning",
                interface_name="policy",
                cidr_or_range=cidr_summary,
                static_sources=sorted({e.source_type for e in static_internal}),
                route_sources=sorted({e.source_type for e in route_internal}),
                annotation_disposition=disp,
                suppressed_by_annotation=suppressed,
                confidence_delta=0.0,
                message=(
                    f"Rule {rule.rule_label!r} ({rule.rule_kind}) explicitly targets {gw_asset.name!r} "
                    f"via install-on, but neither source ({src_cidrs}) nor destination ({dst_cidrs}) "
                    "overlaps any internal interface topology or route on this gateway."
                ),
            )
        )
    return discrepancies


async def reconcile_gateway_topology(
    *,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    weights: TopologyConfidenceWeights,
    refresh_topology_fn: _RefreshTopologyFn,
    collect_routes_fn: _CollectRoutesFn,
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
    """Compare SmartConsole static topology against live gateway routing tables (and optionally gateway-targeted policy rules) and return `TopologyReconciliationReport`."""
    eff_collect = collect_routes or collect_live_routes
    span_attrs(
        mgmt_name=mgmt_name,
        domain=domain,
        collect_routes=eff_collect,
        check_policy=check_policy,
        cache_mode=cache_mode,
    )
    if cache_mode != "cache":
        await refresh_topology_fn(
            mgmt_name=mgmt_name,
            domains=[domain] if domain else None,
            gateways=gateways if cache_mode == "force" else None,
            collect_routes=False,
            include_global=domain == "Global",
            mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    if eff_collect:
        await collect_routes_fn(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            cprid_script_mode=cprid_script_mode,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
        )

    diagnostics = await get_topology_diagnostics(
        cache,
        refresh_topology_fn=refresh_topology_fn,
        mgmt_name=mgmt_name,
        domain=domain,
        gateways=gateways,
        cache_mode="cache",
    )

    topo_entries = await cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)
    all_assets = await cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
    annotations = await cache.get_topology_annotations(mgmt_name=mgmt_name, domain_name=domain)

    global_obj_cache: dict[str, list[CPObject]] = {}
    assets_by_dom: dict[tuple[str, str], list[Asset]] = defaultdict(list)
    for a in all_assets:
        assets_by_dom[(a.mgmt_name, a.domain_name)].append(a)
    policy_state: dict[str, Any] = {
        "active_dom_key": None,
        "indexed_objs_by_dom": {},
        "snapshots_by_dom": {},
        "expanded_rules_by_dom": {},
    }

    gw_tokens = set(_normalize_gateway_filter_tokens(gateways))
    policy_gateways = [
        a for a in all_assets if is_policy_enforcing_gateway(a) and _matches_gateway_filter(a, gw_tokens)
    ]

    entries_by_gw_uid: dict[tuple[str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
    for entry in topo_entries:
        entries_by_gw_uid[(entry.mgmt_name, entry.domain_name, entry.gateway_uid)].append(entry)

    anns_by_gw_uid: dict[tuple[str, str, str], list[TopologyAnnotation]] = defaultdict(list)
    for ann in annotations:
        anns_by_gw_uid[(ann.mgmt_name, ann.domain_name, ann.gateway_uid)].append(ann)

    discrepancies: list[TopologyDiscrepancy] = []

    for gw_asset in sorted(policy_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name)):
        gw_key = (gw_asset.mgmt_name, gw_asset.domain_name, gw_asset.uid)
        gw_entries = entries_by_gw_uid.get(gw_key, [])
        gw_anns = anns_by_gw_uid.get(gw_key, [])
        gw_trust_static, if_trust_static, ann_by_if_cidr, ann_by_if_wildcard = _index_annotations_for_gateway(gw_anns)

        static_entries = [e for e in gw_entries if e.source_type in STATIC_TOPOLOGY_SOURCES]
        route_entries = [e for e in gw_entries if e.source_type in LIVE_ROUTE_SOURCES]
        static_internal = [e for e in static_entries if e.topology_zone == "internal"]
        route_internal = [e for e in route_entries if e.topology_zone == "internal"]

        if not route_entries and not check_policy:
            continue

        if route_entries:
            norm_ifs_by_name: dict[str, _NormalizedInterface] = {
                norm.interface_name: norm for norm in _normalize_gateway_interfaces(gw_asset)
            }
            static_by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
            for se in static_internal:
                static_by_if[se.interface_name].append(se)

            route_by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
            for re_entry in route_internal:
                route_by_if[re_entry.interface_name].append(re_entry)

            discrepancies.extend(
                _reconcile_default_route(
                    gw_asset,
                    static_entries=static_entries,
                    route_entries=route_entries,
                    ann_by_if_cidr=ann_by_if_cidr,
                    gw_trust_static=gw_trust_static,
                    if_trust_static=if_trust_static,
                    weights=weights,
                )
            )
            static_discs, mismatched_routed_if_cidrs = _reconcile_static_against_routes(
                gw_asset,
                static_internal=static_internal,
                route_internal=route_internal,
                route_by_if=route_by_if,
                ann_by_if_cidr=ann_by_if_cidr,
                gw_trust_static=gw_trust_static,
                if_trust_static=if_trust_static,
                weights=weights,
            )
            discrepancies.extend(static_discs)
            discrepancies.extend(
                _reconcile_routes_against_static(
                    gw_asset,
                    route_entries=route_entries,
                    static_by_if=static_by_if,
                    norm_ifs_by_name=norm_ifs_by_name,
                    mismatched_routed_if_cidrs=mismatched_routed_if_cidrs,
                    ann_by_if_cidr=ann_by_if_cidr,
                    weights=weights,
                )
            )

        if check_policy:
            discrepancies.extend(
                await _reconcile_policy_against_topology(
                    cache=cache,
                    rulebase_refresh=rulebase_refresh,
                    gw_asset=gw_asset,
                    gw_entries=gw_entries,
                    gw_anns=gw_anns,
                    static_internal=static_internal,
                    route_internal=route_internal,
                    ann_by_if_cidr=ann_by_if_cidr,
                    ann_by_if_wildcard=ann_by_if_wildcard,
                    assets_by_dom=assets_by_dom,
                    global_obj_cache=global_obj_cache,
                    state=policy_state,
                )
            )

    return TopologyReconciliationReport(
        mgmt_name=mgmt_name,
        domain_name=domain,
        gateway_count=len(policy_gateways),
        diagnostics=diagnostics,
        discrepancies=discrepancies,
    )
