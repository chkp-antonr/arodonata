"""Annotation indexing, effective interval assembly, evidence delta scoring, endpoint resolution, and IPAM export."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Sequence

from arodonata.core.config import TopologyConfidenceWeights
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.objects import CPObject
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    STATIC_TOPOLOGY_SOURCES,
    ConfidenceDelta,
    ExportedTopologyPrefix,
    GatewayTopologyEntry,
    TopologyAnnotation,
    TopologyZone,
)
from arodonata.core.ports import TopologyCachePort
from arodonata.core.primitives import parse_cidr_or_range_bounds
from arodonata.core.services.search_service import classify_search_term
from arodonata.core.services.topology._shared import (
    _InterfaceMatch,
    _normalize_gateway_filter_tokens,
    _RefreshTopologyFn,
    _ResolvedEndpointInterval,
)
from arodonata.core.services.topology.objects import _expand_cp_object, _lookup_indexed_object
from arodonata.core.telemetry import span_attrs


def _index_annotations_for_gateway(
    annotations: Sequence[TopologyAnnotation],
) -> tuple[
    bool | None,
    dict[str, bool],
    dict[tuple[str, str], TopologyAnnotation],
    dict[str, TopologyAnnotation],
]:
    """Index a gateway's annotations into `(gw_trust_static, if_trust_static, by_if_cidr, by_if_wildcard)`."""
    gw_trust_static: bool | None = None
    if_trust_static: dict[str, bool] = {}
    by_if_cidr: dict[tuple[str, str], TopologyAnnotation] = {}
    by_if_wildcard: dict[str, TopologyAnnotation] = {}

    for ann in annotations:
        if ann.interface_name == "*" and ann.cidr_or_range == "*":
            if ann.trust_static_topology is not None:
                gw_trust_static = ann.trust_static_topology
        elif ann.interface_name != "*" and ann.cidr_or_range == "*":
            by_if_wildcard[ann.interface_name] = ann
            if ann.trust_static_topology is not None:
                if_trust_static[ann.interface_name] = ann.trust_static_topology
        elif ann.cidr_or_range != "*":
            by_if_cidr[(ann.interface_name, ann.cidr_or_range)] = ann
            if ann.trust_static_topology is not None and ann.interface_name != "*":
                if_trust_static[ann.interface_name] = ann.trust_static_topology

    return gw_trust_static, if_trust_static, by_if_cidr, by_if_wildcard


def _is_range_covered_by_intervals(
    q_lo: int,
    q_hi: int,
    intervals: Sequence[tuple[int, int]],
) -> bool:
    """Return `True` if `[q_lo, q_hi]` is completely covered by the union of `intervals`."""
    clipped = sorted((max(q_lo, lo), min(q_hi, hi)) for lo, hi in intervals if hi >= q_lo and lo <= q_hi)
    if not clipped or clipped[0][0] > q_lo:
        return False
    curr_end = clipped[0][1]
    for lo, hi in clipped[1:]:
        if lo > curr_end + 1:
            return False
        curr_end = max(curr_end, hi)
        if curr_end >= q_hi:
            return True
    return curr_end >= q_hi


def _is_cidr_covered_by_entries(
    lo: int,
    hi: int,
    entries: Sequence[GatewayTopologyEntry],
) -> bool:
    """Return `True` if `[lo, hi]` is covered by any single entry or the union of `entries`."""
    for e in entries:
        if e.ip_first_int <= lo and hi <= e.ip_last_int:
            return True
    return _is_range_covered_by_intervals(lo, hi, [(e.ip_first_int, e.ip_last_int) for e in entries])


def _build_effective_gateway_entries(
    gw_entries: Sequence[GatewayTopologyEntry],
    gw_annotations: Sequence[TopologyAnnotation],
    *,
    gateway_asset: Asset | None = None,
) -> tuple[
    list[GatewayTopologyEntry],
    bool,
    dict[tuple[str, str], TopologyAnnotation],
    dict[str, TopologyAnnotation],
    bool | None,
    dict[str, bool],
]:
    """Filter and augment `gw_entries` using persistent `TopologyAnnotation` records.

    Returns `(effective_entries, has_live_routes, ann_by_if_cidr, ann_by_if_wildcard, gw_trust_static, if_trust_static)`:
    - `disposition="ignore"` drops matching entries completely.
    - `disposition="manual"` synthesizes a `source_type="manual"` `GatewayTopologyEntry` if not already present.
    - `trust_static_topology=False` is preserved in `(gw_trust_static, if_trust_static)` so `_score_interface_group`
      skips positive `topology_specific_*` deltas and suppresses the `-0.10` static-conflict penalty on live routes
      without discarding connected-subnet evidence.
    """
    has_live_routes = any(e.source_type in LIVE_ROUTE_SOURCES for e in gw_entries)
    gw_trust_static, if_trust_static, ann_by_if_cidr, ann_by_if_wildcard = _index_annotations_for_gateway(
        gw_annotations
    )

    first = gw_entries[0] if gw_entries else None
    filtered: list[GatewayTopologyEntry] = []

    for entry in gw_entries:
        ann = (
            ann_by_if_cidr.get((entry.interface_name, entry.cidr_or_range))
            or ann_by_if_cidr.get(("*", entry.cidr_or_range))
            or ann_by_if_wildcard.get(entry.interface_name)
        )
        if ann is not None and ann.disposition == "ignore":
            continue

        filtered.append(entry)

    # Synthesize manual entries from annotations with `disposition="manual"`
    if first is not None or gateway_asset is not None or gw_annotations:
        if first is not None:
            mgmt_val = first.mgmt_name
            dom_val = first.domain_name
            gw_id_val = first.gateway_id
            gw_aid_val = first.gateway_asset_id
            gw_uid_val = first.gateway_uid
            gw_name_val = first.gateway_name
            gw_type_val = first.gateway_type
            inst_pol_val = first.installed_access_policy
            pkgs_val = list(first.policy_packages)
        elif gateway_asset is not None:
            mgmt_val = gateway_asset.mgmt_name
            dom_val = gateway_asset.domain_name
            gw_id_val = gateway_asset.id
            gw_aid_val = gateway_asset.asset_id
            gw_uid_val = gateway_asset.uid
            gw_name_val = gateway_asset.name
            gw_type_val = gateway_asset.type
            inst_pol_val = None
            pkgs_val = []
        else:
            ann0 = gw_annotations[0]
            mgmt_val = ann0.mgmt_name
            dom_val = ann0.domain_name
            gw_id_val = f"{ann0.mgmt_name}:{ann0.domain_name}:{ann0.gateway_uid}"
            gw_uid_val = ann0.gateway_uid
            gw_name_val = ann0.gateway_name or ann0.gateway_uid
            gw_aid_val = f"{ann0.mgmt_name}:{ann0.domain_name}:{gw_name_val}"
            gw_type_val = "simple-gateway"
            inst_pol_val = None
            pkgs_val = []
        existing_if_cidrs = {(e.interface_name, e.cidr_or_range) for e in filtered}
        for (if_name, cidr_str), ann in sorted(ann_by_if_cidr.items()):
            if ann.disposition != "manual" or if_name == "*" or cidr_str == "*":
                continue
            if (if_name, cidr_str) in existing_if_cidrs:
                continue
            bounds = parse_cidr_or_range_bounds(cidr_str)
            if bounds is None:
                continue
            lo_int, hi_int, plen = bounds
            zone: TopologyZone = ann.topology_zone or ("external" if plen == 0 and lo_int == 0 else "internal")
            filtered.append(
                GatewayTopologyEntry(
                    mgmt_name=mgmt_val,
                    domain_name=dom_val,
                    gateway_id=gw_id_val,
                    gateway_asset_id=gw_aid_val,
                    gateway_uid=gw_uid_val,
                    gateway_name=gw_name_val,
                    gateway_type=gw_type_val,
                    interface_name=if_name,
                    topology_zone=zone,
                    anti_spoofing_mode="unknown",
                    source_type="manual",
                    source_ref=ann.comment or "manual_annotation",
                    cidr_or_range=cidr_str,
                    ip_first_int=lo_int,
                    ip_last_int=hi_int,
                    prefix_len=plen,
                    installed_access_policy=inst_pol_val,
                    policy_packages=pkgs_val,
                    updated_at=ann.updated_at,
                )
            )
            existing_if_cidrs.add((if_name, cidr_str))

    return filtered, has_live_routes, ann_by_if_cidr, ann_by_if_wildcard, gw_trust_static, if_trust_static


def _score_interface_group(
    *,
    if_name: str,
    matching_entries: Sequence[GatewayTopologyEntry],
    all_gw_entries: Sequence[GatewayTopologyEntry],
    has_live_routes: bool,
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation],
    weights: TopologyConfidenceWeights,
    gw_trust_static: bool | None = None,
    if_trust_static: dict[str, bool] | None = None,
    internal_live_entries: Sequence[GatewayTopologyEntry] | None = None,
    internal_static_entries: Sequence[GatewayTopologyEntry] | None = None,
    ann_by_if_wildcard: dict[str, TopologyAnnotation] | None = None,
) -> tuple[GatewayTopologyEntry, float, bool, list[ConfidenceDelta], list[str]]:
    """Compute the cumulative clamped `[0.0, 1.0]` confidence score and deltas for `matching_entries` on `if_name`."""
    eff_if_trust_map = if_trust_static or {}
    if_trust = eff_if_trust_map.get(if_name, gw_trust_static)

    # Pick the primary representative entry (prefer live routes or manual over static, then smallest span)
    best_entry = min(
        matching_entries,
        key=lambda e: (
            0 if e.source_type in (*LIVE_ROUTE_SOURCES, "manual") else 1,
            (e.ip_last_int - e.ip_first_int),
            -e.prefix_len,
            e.cidr_or_range,
        ),
    )
    src_types = {e.source_type for e in matching_entries}
    deltas: list[ConfidenceDelta] = []
    warnings: list[str] = []
    is_standby = False

    # Match prefix annotations against the LPM `best_entry` CIDR (or entries sharing its exact span).
    matched_ann: TopologyAnnotation | None = ann_by_if_cidr.get((if_name, best_entry.cidr_or_range)) or (
        ann_by_if_cidr.get(("*", best_entry.cidr_or_range))
    )
    if matched_ann is None:
        for e in matching_entries:
            if e.ip_first_int == best_entry.ip_first_int and e.ip_last_int == best_entry.ip_last_int:
                cand_ann = ann_by_if_cidr.get((if_name, e.cidr_or_range)) or ann_by_if_cidr.get(("*", e.cidr_or_range))
                if cand_ann is not None:
                    matched_ann = cand_ann
                    break
    if matched_ann is None and ann_by_if_wildcard:
        matched_ann = ann_by_if_wildcard.get(if_name)

    # 1. Live Route Evidence Deltas (highest single route delta on this interface)
    if "connected_route" in src_types:
        deltas.append(
            ConfidenceDelta(
                code="route_connected",
                delta=weights.route_connected,
                detail=f"Direct kernel connected route on {if_name}",
            )
        )
    elif "gaia_static_route" in src_types or "clish_route" in src_types or "vs_static_route" in src_types:
        deltas.append(
            ConfidenceDelta(
                code="route_static",
                delta=weights.route_static,
                detail=f"Static route on {if_name}",
            )
        )
    elif "bgp_route" in src_types or "ospf_route" in src_types:
        proto = "bgp_route" if "bgp_route" in src_types else "ospf_route"
        deltas.append(
            ConfidenceDelta(
                code="route_dynamic",
                delta=weights.route_dynamic,
                detail=f"Dynamic route ({proto}) on {if_name}",
            )
        )

    # 2. Static SmartConsole Topology Evidence Deltas
    if "interface_connected" in src_types:
        deltas.append(
            ConfidenceDelta(
                code="topology_connected",
                delta=weights.topology_connected,
                detail=f"SmartConsole connected subnet on {if_name}",
            )
        )
    elif "interface_specific" in src_types:
        if if_trust is False:
            warnings.append(f"Interface {if_name!r} static topology is marked untrusted (trust_static_topology=False).")
        else:
            spoof_modes = {e.anti_spoofing_mode for e in matching_entries if e.source_type == "interface_specific"}
            if "detect" in spoof_modes or "off" in spoof_modes:
                mode_label = "detect" if "detect" in spoof_modes else "off"
                deltas.append(
                    ConfidenceDelta(
                        code="topology_specific_detect",
                        delta=weights.topology_specific_detect,
                        detail=f"SmartConsole specific group on {if_name} (anti-spoofing={mode_label})",
                    )
                )
                warnings.append(f"Interface {if_name!r} uses specific topology with Anti-Spoofing={mode_label!r}.")
            else:
                deltas.append(
                    ConfidenceDelta(
                        code="topology_specific_prevent",
                        delta=weights.topology_specific_prevent,
                        detail=f"SmartConsole specific group on {if_name} (anti-spoofing=prevent)",
                    )
                )

    if "vpn_domain" in src_types:
        deltas.append(
            ConfidenceDelta(
                code="vpn_encryption_domain",
                delta=weights.vpn_encryption_domain,
                detail=f"Gateway VPN encryption domain on {if_name}",
            )
        )

    # 3. Administrator Annotation Evidence Deltas
    if "manual" in src_types or (matched_ann is not None and matched_ann.disposition == "manual"):
        deltas.append(
            ConfidenceDelta(
                code="admin_manual",
                delta=weights.admin_manual,
                detail=f"Manual administrator topology override on {if_name}",
            )
        )
    elif matched_ann is not None and matched_ann.disposition == "confirmed":
        deltas.append(
            ConfidenceDelta(
                code="admin_confirmed",
                delta=weights.admin_confirmed,
                detail=f"Administrator confirmed prefix on {if_name}",
            )
        )
    elif matched_ann is not None and matched_ann.disposition == "standby_dynamic":
        is_standby = True
        deltas.append(
            ConfidenceDelta(
                code="admin_standby_dynamic",
                delta=weights.admin_standby_dynamic,
                detail=f"Administrator marked standby/asymmetric dynamic path on {if_name}",
            )
        )

    # 4. Negative Conflict / Anomaly Deltas when live routes exist on this gateway
    has_live_on_this_if = bool(src_types.intersection(LIVE_ROUTE_SOURCES))
    if has_live_routes and not is_standby and (matched_ann is None or matched_ann.disposition != "confirmed"):
        q_lo = best_entry.ip_first_int
        q_hi = best_entry.ip_last_int
        live_pool = (
            internal_live_entries
            if internal_live_entries is not None
            else [e for e in all_gw_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"]
        )
        other_live_routes = [
            e for e in live_pool if e.interface_name != if_name and e.ip_first_int <= q_lo and q_hi <= e.ip_last_int
        ]
        same_if_live_routes = [e for e in live_pool if e.interface_name == if_name]
        if not has_live_on_this_if and "manual" not in src_types:
            if (
                if_name == "vpn-domain"
                and other_live_routes
                or _is_cidr_covered_by_entries(q_lo, q_hi, same_if_live_routes)
            ):
                pass
            elif other_live_routes:
                other_if = other_live_routes[0].interface_name
                deltas.append(
                    ConfidenceDelta(
                        code="conflict_routed_to_other_interface_static",
                        delta=weights.conflict_routed_to_other_interface_static,
                        detail=f"Static topology says {if_name}, but live route points to {other_if}",
                    )
                )
                warnings.append(
                    f"Static topology on {if_name!r} ({best_entry.cidr_or_range}) conflicts with live route on {other_if!r}."
                )
            else:
                deltas.append(
                    ConfidenceDelta(
                        code="conflict_missing_in_live_routes",
                        delta=weights.conflict_missing_in_live_routes,
                        detail=f"Prefix {best_entry.cidr_or_range} on {if_name} is absent from live routes",
                    )
                )
                warnings.append(
                    f"Prefix {best_entry.cidr_or_range} on {if_name!r} is in static topology but missing from live routing table."
                )
        elif has_live_on_this_if:
            static_pool = (
                internal_static_entries
                if internal_static_entries is not None
                else [
                    e
                    for e in all_gw_entries
                    if e.source_type in ("interface_connected", "interface_specific", "vpn_domain")
                    and e.topology_zone == "internal"
                ]
            )
            other_static_entries = [
                e
                for e in static_pool
                if e.interface_name not in (if_name, "vpn-domain")
                and eff_if_trust_map.get(e.interface_name, gw_trust_static) is not False
                and e.ip_first_int <= q_lo
                and q_hi <= e.ip_last_int
            ]
            if other_static_entries:
                static_if = other_static_entries[0].interface_name
                deltas.append(
                    ConfidenceDelta(
                        code="conflict_routed_to_other_interface_route",
                        delta=weights.conflict_routed_to_other_interface_route,
                        detail=f"Live route on {if_name} differs from static topology on {static_if}",
                    )
                )
                warnings.append(
                    f"Live route on {if_name!r} ({best_entry.cidr_or_range}) differs from static topology on {static_if!r}."
                )

    # 5. Cluster Member Drift Penalty
    if any(";drift:" in e.source_ref for e in matching_entries):
        deltas.append(
            ConfidenceDelta(
                code="conflict_cluster_member_drift",
                delta=weights.conflict_cluster_member_drift,
                detail=f"Route {best_entry.cidr_or_range} on {if_name} is missing on one or more cluster members",
            )
        )
        warnings.append(f"Cluster member route drift detected on {if_name!r} ({best_entry.cidr_or_range}).")

    raw_score = sum(d.delta for d in deltas)
    clamped = round(max(0.0, min(1.0, raw_score)), 4)
    return best_entry, clamped, is_standby, deltas, warnings


def _resolve_endpoint_intervals(
    raw_terms: Sequence[str],
    *,
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
) -> list[_ResolvedEndpointInterval]:
    """Resolve caller-supplied IP/CIDR/range/object/group terms into `_ResolvedEndpointInterval` items."""
    resolved: list[_ResolvedEndpointInterval] = []
    for raw in raw_terms:
        term = classify_search_term(raw)
        if term.kind == "ipv4" and term.ip is not None:
            ip_int = int(term.ip)
            resolved.append(
                _ResolvedEndpointInterval(
                    query_raw=term.raw,
                    cidr_or_range=f"{term.ip}/32",
                    ip_first_int=ip_int,
                    ip_last_int=ip_int,
                )
            )
        elif term.kind == "cidr" and term.network is not None:
            resolved.append(
                _ResolvedEndpointInterval(
                    query_raw=term.raw,
                    cidr_or_range=str(term.network),
                    ip_first_int=int(term.network.network_address),
                    ip_last_int=int(term.network.broadcast_address),
                )
            )
        elif term.kind == "range" and term.range_bounds is not None:
            lo, hi = term.range_bounds
            resolved.append(
                _ResolvedEndpointInterval(
                    query_raw=term.raw,
                    cidr_or_range=f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}",
                    ip_first_int=lo,
                    ip_last_int=hi,
                )
            )
        else:
            target_obj = _lookup_indexed_object(term.raw, term.raw, obj_by_uid, obj_by_name)
            if target_obj is None:
                lower_raw = term.raw.lower()
                # Case-insensitive fallback when caller passes a custom dict without pre-indexed lowercase keys
                for k, candidate in obj_by_name.items():
                    if k.lower() == lower_raw:
                        target_obj = candidate
                        break
                if target_obj is None:
                    for k, candidate in obj_by_uid.items():
                        if k.lower() == lower_raw:
                            target_obj = candidate
                            break
            if target_obj is not None:
                expanded = _expand_cp_object(
                    target_obj,
                    obj_by_uid=obj_by_uid,
                    obj_by_name=obj_by_name,
                )
                for cidr_str, lo_int, hi_int, _, _ in expanded:
                    resolved.append(
                        _ResolvedEndpointInterval(
                            query_raw=term.raw,
                            cidr_or_range=cidr_str,
                            ip_first_int=lo_int,
                            ip_last_int=hi_int,
                        )
                    )
    return resolved


def _locate_intervals_on_gateway(
    endpoint: _ResolvedEndpointInterval,
    gw_entries: Sequence[GatewayTopologyEntry],
    external_if_names: set[str],
    *,
    has_live_routes: bool = False,
    ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation] | None = None,
    weights: TopologyConfidenceWeights | None = None,
    gw_trust_static: bool | None = None,
    if_trust_static: dict[str, bool] | None = None,
    internal_live_entries: Sequence[GatewayTopologyEntry] | None = None,
    internal_static_entries: Sequence[GatewayTopologyEntry] | None = None,
    ann_by_if_wildcard: dict[str, TopologyAnnotation] | None = None,
) -> list[_InterfaceMatch]:
    """Resolve `endpoint` to matching gateway interfaces with Evidence Delta Confidence Scoring."""
    q_lo = endpoint.ip_first_int
    q_hi = endpoint.ip_last_int
    eff_anns = ann_by_if_cidr or {}
    eff_ann_wild = ann_by_if_wildcard or {}
    eff_weights = weights or TopologyConfidenceWeights()
    eff_if_trust_map = if_trust_static or {}

    overlapping_internal: list[GatewayTopologyEntry] = []
    containing_internal: list[GatewayTopologyEntry] = []
    for entry in gw_entries:
        if entry.topology_zone != "internal":
            continue
        if not (entry.ip_last_int < q_lo or entry.ip_first_int > q_hi):
            overlapping_internal.append(entry)
            if entry.ip_first_int <= q_lo and q_hi <= entry.ip_last_int:
                containing_internal.append(entry)

    # Case 1: The query interval is completely contained inside at least one internal subnet/range.
    if containing_internal:
        by_if_containing: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
        for entry in containing_internal:
            by_if_containing[entry.interface_name].append(entry)

        scored_candidates: list[tuple[tuple[int, int, int, int, float, str, str], _InterfaceMatch]] = []
        for if_name, if_entries in by_if_containing.items():
            best_e, conf, is_standby, deltas, warns = _score_interface_group(
                if_name=if_name,
                matching_entries=if_entries,
                all_gw_entries=gw_entries,
                has_live_routes=has_live_routes,
                ann_by_if_cidr=eff_anns,
                ann_by_if_wildcard=eff_ann_wild,
                weights=eff_weights,
                gw_trust_static=gw_trust_static,
                if_trust_static=eff_if_trust_map,
                internal_live_entries=internal_live_entries,
                internal_static_entries=internal_static_entries,
            )
            best_span = best_e.ip_last_int - best_e.ip_first_int
            best_plen = best_e.prefix_len
            has_live_or_manual = best_e.source_type in (*LIVE_ROUTE_SOURCES, "manual")
            # Longest-Prefix Match (best_span, -best_plen) takes precedence over confidence (-conf)
            # within the same source tier so a wider /8 summary never overrides a more specific /16 or /24 route.
            sort_key = (
                0 if has_live_or_manual else 1,
                1 if if_name in external_if_names else 0,
                best_span,
                -best_plen,
                -conf,
                if_name,
                best_e.cidr_or_range,
            )
            scored_candidates.append(
                (
                    sort_key,
                    _InterfaceMatch(
                        interface_name=if_name,
                        topology_zone="internal",
                        matched_cidr=best_e.cidr_or_range,
                        source_type=best_e.source_type,
                        source_ref=best_e.source_ref,
                        confidence=conf,
                        is_standby_path=is_standby,
                        confidence_factors=tuple(deltas),
                        warnings=tuple(warns),
                    ),
                )
            )

        scored_candidates.sort(key=lambda item: item[0])
        return [scored_candidates[0][1]]

    # Case 2: The query interval is broader than any single internal entry (e.g. `10.0.0.0/8` or `0.0.0.0/0`).
    matches: list[_InterfaceMatch] = []
    if overlapping_internal:
        by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
        for entry in overlapping_internal:
            by_if[entry.interface_name].append(entry)
        for if_name in sorted(by_if):
            best_if_entry, conf, is_standby, deltas, warns = _score_interface_group(
                if_name=if_name,
                matching_entries=by_if[if_name],
                all_gw_entries=gw_entries,
                has_live_routes=has_live_routes,
                ann_by_if_cidr=eff_anns,
                ann_by_if_wildcard=eff_ann_wild,
                weights=eff_weights,
                gw_trust_static=gw_trust_static,
                if_trust_static=eff_if_trust_map,
                internal_live_entries=internal_live_entries,
                internal_static_entries=internal_static_entries,
            )
            matches.append(
                _InterfaceMatch(
                    interface_name=best_if_entry.interface_name,
                    topology_zone="internal",
                    matched_cidr=best_if_entry.cidr_or_range,
                    source_type=best_if_entry.source_type,
                    source_ref=best_if_entry.source_ref,
                    confidence=conf,
                    is_standby_path=is_standby,
                    confidence_factors=tuple(deltas),
                    warnings=tuple(warns),
                )
            )

    fully_covered_internally = bool(overlapping_internal) and _is_range_covered_by_intervals(
        q_lo,
        q_hi,
        [(e.ip_first_int, e.ip_last_int) for e in overlapping_internal],
    )
    if not fully_covered_internally:
        external_entries = [e for e in gw_entries if e.topology_zone == "external"]
        if external_entries:
            # Prefer live default route (`0.0.0.0/0`) over static external interface if both exist
            default_live_ext = [
                e
                for e in external_entries
                if e.source_type in LIVE_ROUTE_SOURCES and e.prefix_len == 0 and e.ip_first_int == 0
            ]
            static_ext = [e for e in external_entries if e.source_type in STATIC_TOPOLOGY_SOURCES]
            ext = default_live_ext[0] if default_live_ext else (static_ext[0] if static_ext else external_entries[0])
            if not any(m.interface_name == ext.interface_name for m in matches):
                ext_deltas: list[ConfidenceDelta] = []
                ext_warns: list[str] = []
                if any(e.interface_name == ext.interface_name for e in default_live_ext):
                    ext_deltas.append(
                        ConfidenceDelta(
                            code="route_static",
                            delta=eff_weights.route_static,
                            detail=f"Live default route 0.0.0.0/0 on {ext.interface_name}",
                        )
                    )
                if any(e.interface_name == ext.interface_name for e in static_ext):
                    ext_deltas.append(
                        ConfidenceDelta(
                            code="topology_external_fallback",
                            delta=eff_weights.topology_external_fallback,
                            detail=f"External topology fallback on {ext.interface_name}",
                        )
                    )
                if not ext_deltas:
                    ext_deltas.append(
                        ConfidenceDelta(
                            code="topology_external_fallback",
                            delta=eff_weights.topology_external_fallback,
                            detail=f"External fallback on {ext.interface_name}",
                        )
                    )
                ext_conf = round(max(0.0, min(1.0, sum(d.delta for d in ext_deltas))), 4)
                matches.append(
                    _InterfaceMatch(
                        interface_name=ext.interface_name,
                        topology_zone="external",
                        matched_cidr="0.0.0.0/0",
                        source_type="external_fallback",
                        source_ref=ext.source_ref or ext.source_type,
                        confidence=ext_conf,
                        is_standby_path=False,
                        confidence_factors=tuple(ext_deltas),
                        warnings=tuple(ext_warns),
                    )
                )

    return matches


async def export_topology_prefixes(
    cache: TopologyCachePort,
    weights: TopologyConfidenceWeights,
    *,
    refresh_topology_fn: _RefreshTopologyFn,
    mgmt_name: str | None = None,
    domain: str | None = None,
    gateways: Sequence[str] | str | None = None,
    gateway: str | None = None,
    include_external: bool = False,
    include_ignored: bool = False,
    cache_mode: CacheMode = "smart",
    cache_ttl: float | None = None,
) -> list[ExportedTopologyPrefix]:
    """Export deduplicated gateway/interface prefixes with confidence scores and IPAM annotations."""
    eff_gateways = gateways if gateways is not None else gateway
    span_attrs(mgmt_name=mgmt_name, domain=domain, include_external=include_external, cache_mode=cache_mode)
    if cache_mode != "cache":
        await refresh_topology_fn(
            mgmt_name=mgmt_name,
            domains=[domain] if domain else None,
            gateways=eff_gateways if cache_mode == "force" else None,
            include_global=domain == "Global",
            mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    topo_entries = await cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)
    annotations = await cache.get_topology_annotations(mgmt_name=mgmt_name, domain_name=domain)
    gw_tokens = set(_normalize_gateway_filter_tokens(eff_gateways))

    entries_by_gw: dict[tuple[str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
    for e in topo_entries:
        if gw_tokens and not (
            {
                e.gateway_uid.lower(),
                e.gateway_name.lower(),
                e.gateway_id.lower(),
                e.gateway_asset_id.lower(),
            }
            & gw_tokens
        ):
            continue
        entries_by_gw[(e.mgmt_name, e.domain_name, e.gateway_uid)].append(e)

    anns_by_gw: dict[tuple[str, str, str], list[TopologyAnnotation]] = defaultdict(list)
    for ann in annotations:
        anns_by_gw[(ann.mgmt_name, ann.domain_name, ann.gateway_uid)].append(ann)

    exported: list[ExportedTopologyPrefix] = []

    def _ann_group_matches_tokens(gw_key: tuple[str, str, str], gw_anns: Sequence[TopologyAnnotation]) -> bool:
        m_name, d_name, gw_uid = gw_key
        tokens: set[str] = {gw_uid.lower(), f"{m_name}:{d_name}:{gw_uid}".lower()}
        for ann in gw_anns:
            if ann.gateway_name:
                tokens.add(ann.gateway_name.lower())
                tokens.add(f"{m_name}:{d_name}:{ann.gateway_name}".lower())
        return bool(tokens & gw_tokens)

    all_gw_keys = sorted(
        set(entries_by_gw)
        | {k for k in anns_by_gw if not gw_tokens or k in entries_by_gw or _ann_group_matches_tokens(k, anns_by_gw[k])}
    )
    for gw_key in all_gw_keys:
        raw_gw_entries = entries_by_gw.get(gw_key, [])
        gw_anns = anns_by_gw.get(gw_key, [])
        (
            eff_entries,
            has_live,
            ann_by_if_cidr,
            ann_by_if_wild,
            gw_trust_static,
            if_trust_static,
        ) = _build_effective_gateway_entries(
            raw_gw_entries,
            gw_anns,
        )
        internal_live = [
            e for e in eff_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"
        ]
        internal_static = [
            e
            for e in eff_entries
            if e.source_type in ("interface_connected", "interface_specific", "vpn_domain")
            and e.topology_zone == "internal"
        ]
        if include_ignored:
            manual_entries = [e for e in eff_entries if e.source_type == "manual"]
            source_pool = [*raw_gw_entries, *manual_entries]
        else:
            source_pool = eff_entries
        grouped: dict[tuple[str, str], list[GatewayTopologyEntry]] = defaultdict(list)
        for e in source_pool:
            if not include_external and e.topology_zone == "external":
                continue
            grouped[(e.interface_name, e.cidr_or_range)].append(e)

        for (if_name, cidr_str), group in sorted(grouped.items()):
            best_e, conf, is_standby, deltas, _ = _score_interface_group(
                if_name=if_name,
                matching_entries=group,
                all_gw_entries=eff_entries,
                has_live_routes=has_live,
                ann_by_if_cidr=ann_by_if_cidr,
                ann_by_if_wildcard=ann_by_if_wild,
                weights=weights,
                gw_trust_static=gw_trust_static,
                if_trust_static=if_trust_static,
                internal_live_entries=internal_live,
                internal_static_entries=internal_static,
            )
            matched_ann: TopologyAnnotation | None = (
                ann_by_if_cidr.get((if_name, cidr_str))
                or ann_by_if_cidr.get(("*", cidr_str))
                or ann_by_if_wild.get(if_name)
            )
            src_types: list[str] = []
            src_refs: list[str] = []
            for item in group:
                if item.source_type not in src_types:
                    src_types.append(item.source_type)
                if item.source_ref and item.source_ref not in src_refs:
                    src_refs.append(item.source_ref)

            exported.append(
                ExportedTopologyPrefix(
                    mgmt_name=best_e.mgmt_name,
                    domain_name=best_e.domain_name,
                    gateway_id=best_e.gateway_id,
                    gateway_asset_id=best_e.gateway_asset_id,
                    gateway_uid=best_e.gateway_uid,
                    gateway_name=best_e.gateway_name,
                    gateway_type=best_e.gateway_type,
                    interface_name=if_name,
                    interface_ipv4=best_e.interface_ipv4,
                    interface_mask_length=best_e.interface_mask_length,
                    cidr_or_range=cidr_str,
                    prefix_len=best_e.prefix_len,
                    topology_zone=best_e.topology_zone,
                    leads_to_dmz=any(x.leads_to_dmz for x in group),
                    source_types=src_types,
                    source_refs=src_refs,
                    anti_spoofing_mode=next(
                        (x.anti_spoofing_mode for x in group if x.anti_spoofing_mode != "unknown"),
                        best_e.anti_spoofing_mode,
                    ),
                    disposition=matched_ann.disposition if matched_ann else None,
                    is_standby_path=is_standby,
                    confidence=conf,
                    confidence_factors=deltas,
                    zone=matched_ann.zone if matched_ann else "",
                    site=matched_ann.site if matched_ann else "",
                    comment=matched_ann.comment if matched_ann else "",
                    custom_metadata=dict(matched_ann.custom_metadata) if matched_ann else {},
                )
            )

    return exported
