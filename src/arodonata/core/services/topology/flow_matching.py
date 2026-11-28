"""Cross-interface LPM flow matching, policy rule confidence boosting, one-arm inference, and candidate assembly."""

from __future__ import annotations

from collections.abc import Sequence

from arodonata.core.config import TopologyConfidenceWeights
from arodonata.core.models.assets import Asset
from arodonata.core.models.topology import (
    AffectedGatewayCandidate,
    ConfidenceDelta,
    FlowMatchType,
    GatewayTopologyEntry,
    TopologyAnnotation,
    TopologyZone,
    TrafficFlowMatch,
)
from arodonata.core.services.topology._shared import (
    _ExpandedPolicyRule,
    _NormalizedInterface,
    _ResolvedEndpointInterval,
)
from arodonata.core.services.topology.policy_rules import _match_endpoints_against_policy_rules
from arodonata.core.services.topology.scoring import _locate_intervals_on_gateway


def _match_l3_cross_interface_flows(
    *,
    src_intervals: Sequence[_ResolvedEndpointInterval],
    dst_intervals: Sequence[_ResolvedEndpointInterval],
    gw_entries: Sequence[GatewayTopologyEntry],
    external_if_names: set[str],
    has_live_routes: bool,
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    weights: TopologyConfidenceWeights,
    gw_trust_static: bool | None,
    if_trust_static: dict[str, bool],
    internal_live: Sequence[GatewayTopologyEntry],
    internal_static: Sequence[GatewayTopologyEntry],
    include_standby: bool,
    seen_flow_keys: set[tuple[str, str, str, str, str, str]],
    ann_by_if_wildcard: dict[str, TopologyAnnotation] | None = None,
) -> list[TrafficFlowMatch]:
    """Match source and destination intervals onto distinct gateway interfaces via LPM."""
    matched_flows: list[TrafficFlowMatch] = []
    for src_ep in src_intervals:
        src_matches = _locate_intervals_on_gateway(
            src_ep,
            gw_entries,
            external_if_names,
            has_live_routes=has_live_routes,
            ann_by_if_cidr=ann_by_if_cidr,
            ann_by_if_wildcard=ann_by_if_wildcard,
            weights=weights,
            gw_trust_static=gw_trust_static,
            if_trust_static=if_trust_static,
            internal_live_entries=internal_live,
            internal_static_entries=internal_static,
        )
        if not src_matches:
            continue
        for dst_ep in dst_intervals:
            dst_matches = _locate_intervals_on_gateway(
                dst_ep,
                gw_entries,
                external_if_names,
                has_live_routes=has_live_routes,
                ann_by_if_cidr=ann_by_if_cidr,
                ann_by_if_wildcard=ann_by_if_wildcard,
                weights=weights,
                gw_trust_static=gw_trust_static,
                if_trust_static=if_trust_static,
                internal_live_entries=internal_live,
                internal_static_entries=internal_static,
            )
            if not dst_matches:
                continue

            for src_match in src_matches:
                for dst_match in dst_matches:
                    # Core Exclusion Invariant:
                    # 1. Source and Destination behind the SAME interface (`src_interface == dst_interface`)
                    # 2. Both Source and Destination falling back to `external` (`external == external`)
                    if src_match.interface_name == dst_match.interface_name:
                        continue
                    if src_match.topology_zone == "external" and dst_match.topology_zone == "external":
                        continue

                    flow_conf = round(min(src_match.confidence, dst_match.confidence), 4)
                    flow_standby = src_match.is_standby_path or dst_match.is_standby_path
                    if not include_standby and flow_standby:
                        continue

                    if src_match.topology_zone == "internal" and dst_match.topology_zone == "internal":
                        m_type: FlowMatchType = "internal_to_internal"
                    elif src_match.topology_zone == "internal" and dst_match.topology_zone == "external":
                        m_type = "internal_to_external"
                    else:
                        m_type = "external_to_internal"

                    flow_key = (
                        src_ep.query_raw,
                        dst_ep.query_raw,
                        src_ep.cidr_or_range,
                        dst_ep.cidr_or_range,
                        src_match.interface_name,
                        dst_match.interface_name,
                    )
                    if flow_key in seen_flow_keys:
                        continue
                    seen_flow_keys.add(flow_key)

                    flow_factors: list[ConfidenceDelta] = []
                    for f_delta in (*src_match.confidence_factors, *dst_match.confidence_factors):
                        if f_delta not in flow_factors:
                            flow_factors.append(f_delta)

                    flow_warns = list(dict.fromkeys([*src_match.warnings, *dst_match.warnings]))

                    matched_flows.append(
                        TrafficFlowMatch(
                            source_query=src_ep.query_raw,
                            destination_query=dst_ep.query_raw,
                            source_cidr_or_range=src_ep.cidr_or_range,
                            destination_cidr_or_range=dst_ep.cidr_or_range,
                            src_interface=src_match.interface_name,
                            dst_interface=dst_match.interface_name,
                            src_topology_zone=src_match.topology_zone,
                            dst_topology_zone=dst_match.topology_zone,
                            src_matched_cidr=src_match.matched_cidr,
                            dst_matched_cidr=dst_match.matched_cidr,
                            src_source_type=src_match.source_type,
                            dst_source_type=dst_match.source_type,
                            src_source_ref=src_match.source_ref,
                            dst_source_ref=dst_match.source_ref,
                            match_type=m_type,
                            src_confidence=src_match.confidence,
                            dst_confidence=dst_match.confidence,
                            confidence=flow_conf,
                            is_standby_path=flow_standby,
                            confidence_factors=flow_factors,
                            warnings=flow_warns,
                        )
                    )
    return matched_flows


def _apply_policy_rule_evidence(
    *,
    matched_flows: list[TrafficFlowMatch],
    src_intervals: Sequence[_ResolvedEndpointInterval],
    dst_intervals: Sequence[_ResolvedEndpointInterval],
    gw_rules: Sequence[_ExpandedPolicyRule],
    gw_name: str,
    weights: TopologyConfidenceWeights,
    min_confidence: float,
    match_types_seen: list[str],
) -> list[TrafficFlowMatch]:
    """Boost L3 flow confidence when covered by installed Access/NAT rules and apply `min_confidence` filter."""
    if gw_rules:
        src_ep_by_key = {(ep.query_raw, ep.cidr_or_range): ep for ep in src_intervals}
        dst_ep_by_key = {(ep.query_raw, ep.cidr_or_range): ep for ep in dst_intervals}
        for flow in matched_flows:
            s_ep = src_ep_by_key.get((flow.source_query, flow.source_cidr_or_range))
            d_ep = dst_ep_by_key.get((flow.destination_query, flow.destination_cidr_or_range))
            if s_ep is None or d_ep is None:
                continue
            rule_hit = _match_endpoints_against_policy_rules(s_ep, d_ep, gw_rules)
            if rule_hit is not None:
                matched_rule, _, _ = rule_hit
                rule_delta = ConfidenceDelta(
                    code="policy_rule_evidence",
                    delta=weights.policy_rule_evidence,
                    detail=(
                        f"Installed {matched_rule.rule_kind} {matched_rule.rule_label!r} "
                        f"on {gw_name} covers traffic flow"
                    ),
                )
                if rule_delta not in flow.confidence_factors:
                    flow.confidence_factors.append(rule_delta)
                flow.src_confidence = round(max(0.0, min(1.0, flow.src_confidence + weights.policy_rule_evidence)), 4)
                flow.dst_confidence = round(max(0.0, min(1.0, flow.dst_confidence + weights.policy_rule_evidence)), 4)
                flow.confidence = round(max(0.0, min(1.0, flow.confidence + weights.policy_rule_evidence)), 4)

    filtered = [f for f in matched_flows if f.confidence >= min_confidence]
    for f in filtered:
        if f.match_type not in match_types_seen:
            match_types_seen.append(f.match_type)
    return filtered


def _infer_one_arm_policy_flows(
    *,
    first_entry: GatewayTopologyEntry | None,
    gw_norm_ifs: Sequence[_NormalizedInterface] | None,
    external_if_names: set[str],
    src_intervals: Sequence[_ResolvedEndpointInterval],
    dst_intervals: Sequence[_ResolvedEndpointInterval],
    gw_rules: Sequence[_ExpandedPolicyRule],
    gw_name: str,
    weights: TopologyConfidenceWeights,
    min_confidence: float,
    seen_flow_keys: set[tuple[str, str, str, str, str, str]],
    match_types_seen: list[str],
) -> list[TrafficFlowMatch]:
    """Infer `policy_inferred` flows for one-arm / incomplete-topology gateways from explicit installed rules."""
    inferred_if_name = first_entry.interface_name if first_entry is not None else "policy"
    inferred_zone: TopologyZone = first_entry.topology_zone if first_entry is not None else "internal"
    if first_entry is None and gw_norm_ifs:
        first_nif = gw_norm_ifs[0]
        inferred_if_name = first_nif.interface_name
        inferred_zone = "external" if first_nif.is_external else "internal"

    has_ext_if = bool(external_if_names) or inferred_zone == "external"
    inferred_flows: list[TrafficFlowMatch] = []
    for src_ep in src_intervals:
        for dst_ep in dst_intervals:
            rule_hit = _match_endpoints_against_policy_rules(src_ep, dst_ep, gw_rules)
            if rule_hit is None:
                continue
            matched_rule, matched_r_src, matched_r_dst = rule_hit
            flow_key = (
                src_ep.query_raw,
                dst_ep.query_raw,
                src_ep.cidr_or_range,
                dst_ep.cidr_or_range,
                inferred_if_name,
                inferred_if_name,
            )
            if flow_key in seen_flow_keys:
                continue
            seen_flow_keys.add(flow_key)

            inferred_factors: list[ConfidenceDelta] = []
            if has_ext_if:
                inferred_factors.append(
                    ConfidenceDelta(
                        code="topology_external_fallback",
                        delta=weights.topology_external_fallback,
                        detail=f"One-arm / external interface {inferred_if_name} on {gw_name}",
                    )
                )
            inferred_factors.append(
                ConfidenceDelta(
                    code="policy_rule_evidence",
                    delta=weights.policy_rule_evidence,
                    detail=(
                        f"Installed {matched_rule.rule_kind} {matched_rule.rule_label!r} "
                        f"on {gw_name} covers traffic flow"
                    ),
                )
            )
            inferred_conf = round(max(0.0, min(1.0, sum(d.delta for d in inferred_factors))), 4)
            if inferred_conf < min_confidence:
                continue

            if "policy_inferred" not in match_types_seen:
                match_types_seen.append("policy_inferred")

            rule_ref = f"{matched_rule.rule_kind}:{matched_rule.rule_label}"
            inferred_flows.append(
                TrafficFlowMatch(
                    source_query=src_ep.query_raw,
                    destination_query=dst_ep.query_raw,
                    source_cidr_or_range=src_ep.cidr_or_range,
                    destination_cidr_or_range=dst_ep.cidr_or_range,
                    src_interface=inferred_if_name,
                    dst_interface=inferred_if_name,
                    src_topology_zone=inferred_zone,
                    dst_topology_zone=inferred_zone,
                    src_matched_cidr=matched_r_src.cidr_or_range,
                    dst_matched_cidr=matched_r_dst.cidr_or_range,
                    src_source_type="policy_rule",
                    dst_source_type="policy_rule",
                    src_source_ref=rule_ref,
                    dst_source_ref=rule_ref,
                    match_type="policy_inferred",
                    src_confidence=inferred_conf,
                    dst_confidence=inferred_conf,
                    confidence=inferred_conf,
                    is_standby_path=False,
                    confidence_factors=inferred_factors,
                    warnings=[],
                )
            )
    return inferred_flows


def _build_affected_gateway_candidate(
    *,
    gw_mgmt: str,
    gw_dom: str,
    eff_gw_id: str,
    eff_gw_asset_id: str,
    gw_uid: str,
    gw_name: str,
    gw_type: str,
    gw_asset: Asset | None,
    installed_pol: str | None,
    pkg_names: Sequence[str],
    layer_names: Sequence[str],
    match_types_seen: Sequence[str],
    src_list: Sequence[str],
    dst_list: Sequence[str],
    matched_flows: Sequence[TrafficFlowMatch],
) -> AffectedGatewayCandidate:
    """Assemble `AffectedGatewayCandidate` preserving caller input ordering for matched sources/destinations."""
    matched_src_set = {f.source_query for f in matched_flows}
    matched_dst_set = {f.destination_query for f in matched_flows}
    matched_sources = [s for s in dict.fromkeys(src_list) if s in matched_src_set]
    matched_destinations = [d for d in dict.fromkeys(dst_list) if d in matched_dst_set]

    gw_conf = round(max(f.confidence for f in matched_flows), 4)
    gw_standby = all(f.is_standby_path for f in matched_flows)
    gw_factors: list[ConfidenceDelta] = []
    gw_warns: list[str] = []
    for f in matched_flows:
        for fd in f.confidence_factors:
            if fd not in gw_factors:
                gw_factors.append(fd)
        for fw in f.warnings:
            if fw not in gw_warns:
                gw_warns.append(fw)

    return AffectedGatewayCandidate(
        mgmt_name=gw_mgmt,
        domain_name=gw_dom,
        gateway_id=eff_gw_id,
        gateway_asset_id=eff_gw_asset_id,
        gateway_uid=gw_uid,
        gateway_name=gw_name,
        gateway_type=gw_type,
        ipv4_address=gw_asset.ipv4_address if gw_asset else None,
        parent_id=gw_asset.parent_id if gw_asset else None,
        parent_asset_id=gw_asset.parent_asset_id if gw_asset else None,
        installed_access_policy=installed_pol,
        policy_packages=list(pkg_names),
        access_layers=list(layer_names),
        match_types=list(match_types_seen),
        matched_sources=matched_sources,
        matched_destinations=matched_destinations,
        matched_flows=list(matched_flows),
        confidence=gw_conf,
        is_standby_path=gw_standby,
        confidence_factors=gw_factors,
        warnings=gw_warns,
    )
