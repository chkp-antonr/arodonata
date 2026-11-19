"""Affected gateway LPM flow matching, policy rule evidence scoring, and one-arm gateway inference."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime

from arodonata.core.config import TopologyConfidenceWeights
from arodonata.core.errors import ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    AffectedGatewayCandidate,
    GatewayTopologyEntry,
    TopologyAnnotation,
    TopologySourceType,
)
from arodonata.core.ports import ApiPort, RulebaseRefreshPort
from arodonata.core.primitives import is_uuid, normalize_str_sequence
from arodonata.core.services.search_service import classify_search_term
from arodonata.core.services.topology._shared import (
    _ExpandedPolicyRule,
    _NormalizedInterface,
    _RefreshTopologyFn,
    _ResolvedEndpointInterval,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology.extractor import _extract_domain_topology_entries
from arodonata.core.services.topology.flow_matching import (
    _apply_policy_rule_evidence,
    _build_affected_gateway_candidate,
    _infer_one_arm_policy_flows,
    _match_l3_cross_interface_flows,
)
from arodonata.core.services.topology.normalizer import _normalize_gateway_interfaces
from arodonata.core.services.topology.objects import (
    _index_objects,
    _load_domain_scoped_objects,
    _resolve_topology_objects_on_demand,
)
from arodonata.core.services.topology.policy_rules import (
    _expand_domain_policy_rules as _expand_domain_policy_rules,
)
from arodonata.core.services.topology.policy_rules import (
    _filter_rules_for_gateway as _filter_rules_for_gateway,
)
from arodonata.core.services.topology.policy_rules import (
    _is_explicit_rule_terms as _is_explicit_rule_terms,
)
from arodonata.core.services.topology.policy_rules import (
    _is_one_arm_or_incomplete_topology_gateway as _is_one_arm_or_incomplete_topology_gateway,
)
from arodonata.core.services.topology.policy_rules import (
    _load_domain_package_snapshot as _load_domain_package_snapshot,
)
from arodonata.core.services.topology.policy_rules import (
    _match_endpoints_against_policy_rules as _match_endpoints_against_policy_rules,
)
from arodonata.core.services.topology.policy_rules import (
    _normalize_install_on_tokens as _normalize_install_on_tokens,
)
from arodonata.core.services.topology.policy_rules import (
    _resolve_gateway_policy_metadata as _resolve_gateway_policy_metadata,
)
from arodonata.core.services.topology.scoring import (
    _build_effective_gateway_entries,
    _resolve_endpoint_intervals,
)
from arodonata.core.telemetry import span_attrs


async def _load_fallback_topology_entries(
    *,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    all_assets: Sequence[Asset],
    allowed_source_types: set[str] | None,
    global_obj_cache: dict[str, list[CPObject]],
    global_obj_lock: asyncio.Lock,
) -> list[GatewayTopologyEntry]:
    """Compute topology entries strictly from cached assets/objects when topology cache is cold."""
    by_dom_assets: dict[tuple[str, str], list[Asset]] = defaultdict(list)
    for a in all_assets:
        by_dom_assets[(a.mgmt_name, a.domain_name)].append(a)
    computed: list[GatewayTopologyEntry] = []
    for (m_name, d_name), dom_assets in by_dom_assets.items():
        dom_objs = await _load_domain_scoped_objects(
            cache,
            m_name,
            d_name,
            global_cache=global_obj_cache,
            global_lock=global_obj_lock,
        )
        dom_entries, _ = await _extract_domain_topology_entries(
            api=api,
            cache=cache,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            mgmt_name=m_name,
            domain_name=d_name,
            assets=dom_assets,
            objects=dom_objs,
            allow_live_detail=False,
        )
        computed.extend(dom_entries)
    if allowed_source_types is not None:
        computed = [e for e in computed if e.source_type in allowed_source_types]
    return computed


def _group_and_order_gateways(
    *,
    topo_entries: Sequence[GatewayTopologyEntry],
    annotations: Sequence[TopologyAnnotation],
    all_assets: Sequence[Asset],
    include_policy_inferred: bool,
) -> tuple[
    dict[str, Asset],
    dict[tuple[str, str], list[Asset]],
    dict[str, list[GatewayTopologyEntry]],
    dict[str, list[TopologyAnnotation]],
    list[str],
]:
    """Index assets, entries, and annotations by gateway and return deterministically sorted gateway IDs."""
    assets_by_id: dict[str, Asset] = {a.id: a for a in all_assets}
    assets_by_uid: dict[tuple[str, str, str], Asset] = {(a.mgmt_name, a.domain_name, a.uid): a for a in all_assets}
    assets_by_dom: dict[tuple[str, str], list[Asset]] = defaultdict(list)
    for a in all_assets:
        assets_by_dom[(a.mgmt_name, a.domain_name)].append(a)
    entries_by_gw_id: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
    for entry in topo_entries:
        entries_by_gw_id[entry.gateway_id].append(entry)

    anns_by_gw_id: dict[str, list[TopologyAnnotation]] = defaultdict(list)
    for ann in annotations:
        ann_gw_id = f"{ann.mgmt_name}:{ann.domain_name}:{ann.gateway_uid}"
        matched_asset = assets_by_uid.get((ann.mgmt_name, ann.domain_name, ann.gateway_uid))
        if matched_asset is not None:
            ann_gw_id = matched_asset.id
        anns_by_gw_id[ann_gw_id].append(ann)

    policy_gw_asset_ids = (
        [a.id for a in all_assets if is_policy_enforcing_gateway(a)] if include_policy_inferred else []
    )
    all_gw_ids = list(dict.fromkeys([*entries_by_gw_id.keys(), *anns_by_gw_id.keys(), *policy_gw_asset_ids]))

    def _gw_dom_sort_key(gid: str) -> tuple[str, str, str]:
        g_entries = entries_by_gw_id.get(gid)
        if g_entries:
            return (g_entries[0].mgmt_name, g_entries[0].domain_name, gid)
        g_asset = assets_by_id.get(gid)
        if g_asset is not None:
            return (g_asset.mgmt_name, g_asset.domain_name, gid)
        g_anns = anns_by_gw_id.get(gid)
        if g_anns:
            return (g_anns[0].mgmt_name, g_anns[0].domain_name, gid)
        return ("", "", gid)

    all_gw_ids.sort(key=_gw_dom_sort_key)
    return assets_by_id, assets_by_dom, entries_by_gw_id, anns_by_gw_id, all_gw_ids


async def find_affected_gateways(
    *,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    weights: TopologyConfidenceWeights,
    now_fn: Callable[[], datetime],
    refresh_topology_fn: _RefreshTopologyFn,
    sources: Sequence[str] | str,
    destinations: Sequence[str] | str,
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
    src_list = normalize_str_sequence(sources)
    dst_list = normalize_str_sequence(destinations)
    if not src_list:
        raise ValidationError("sources must contain at least one IPv4 address, subnet, range, or object name")
    if not dst_list:
        raise ValidationError("destinations must contain at least one IPv4 address, subnet, range, or object name")

    allowed_source_types: set[str] | None = (
        {str(st).strip() for st in source_types if str(st).strip()} if source_types is not None else None
    )

    span_attrs(
        mgmt_name=mgmt_name,
        domain=domain,
        source_count=len(src_list),
        destination_count=len(dst_list),
        include_annotations=include_annotations,
        min_confidence=min_confidence,
        include_standby=include_standby,
        include_policy_inferred=include_policy_inferred,
        cache_mode=cache_mode,
    )

    if cache_mode != "cache":
        await refresh_topology_fn(
            mgmt_name=mgmt_name,
            domains=[domain] if domain else None,
            include_global=domain == "Global",
            mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    topo_entries = await cache.get_gateway_topology(
        mgmt_name=mgmt_name,
        domain_name=domain,
        source_types=list(allowed_source_types) if allowed_source_types is not None else None,
    )
    annotations: list[TopologyAnnotation] = (
        await cache.get_topology_annotations(
            mgmt_name=mgmt_name,
            domain_name=domain,
        )
        if include_annotations
        else []
    )
    all_assets = await cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
    global_obj_cache: dict[str, list[CPObject]] = {}
    global_obj_lock = asyncio.Lock()

    # Fallback: if cache_mode="cache" was used on a database with cached assets/objects but
    # topology has not been extracted yet, extract topology on the fly strictly from cached data
    # (allow_live_detail=False so cache mode never makes live API calls).
    if not topo_entries and all_assets:
        topo_entries = await _load_fallback_topology_entries(
            api=api,
            cache=cache,
            rulebase_refresh=rulebase_refresh,
            now_fn=now_fn,
            all_assets=all_assets,
            allowed_source_types=allowed_source_types,
            global_obj_cache=global_obj_cache,
            global_obj_lock=global_obj_lock,
        )

    if not topo_entries and not annotations and not (include_policy_inferred and all_assets):
        return []

    endpoint_object_terms = [
        raw_term
        for raw_term in (*src_list, *dst_list)
        if classify_search_term(raw_term).kind not in ("ipv4", "cidr", "range")
    ]
    static_endpoints: tuple[list[_ResolvedEndpointInterval], list[_ResolvedEndpointInterval]] | None = None
    if not endpoint_object_terms:
        static_endpoints = (
            _resolve_endpoint_intervals(src_list, obj_by_uid={}, obj_by_name={}),
            _resolve_endpoint_intervals(dst_list, obj_by_uid={}, obj_by_name={}),
        )
        if not static_endpoints[0] or not static_endpoints[1]:
            return []

    assets_by_id, assets_by_dom, entries_by_gw_id, anns_by_gw_id, all_gw_ids = _group_and_order_gateways(
        topo_entries=topo_entries,
        annotations=annotations,
        all_assets=all_assets,
        include_policy_inferred=include_policy_inferred,
    )

    active_dom_key: tuple[str, str] | None = None
    indexed_objs_by_dom: dict[tuple[str, str], tuple[dict[str, CPObject], dict[str, CPObject]]] = {}
    resolved_endpoints_by_dom: dict[
        tuple[str, str],
        tuple[list[_ResolvedEndpointInterval], list[_ResolvedEndpointInterval]],
    ] = {}
    snapshots_by_dom: dict[tuple[str, str], DomainRulebaseSnapshot] = {}
    expanded_rules_by_dom: dict[tuple[str, str], list[_ExpandedPolicyRule]] = {}
    norm_ifs_by_gw_id: dict[str, list[_NormalizedInterface]] = {}

    async def _ensure_domain_index(
        target_mgmt: str,
        target_dom: str,
        *,
        resolve_endpoints: bool = False,
    ) -> tuple[dict[str, CPObject], dict[str, CPObject]]:
        d_key = (target_mgmt, target_dom)
        if d_key not in indexed_objs_by_dom:
            scoped_objs = await _load_domain_scoped_objects(
                cache,
                target_mgmt,
                target_dom,
                global_cache=global_obj_cache,
                global_lock=global_obj_lock,
            )
            if resolve_endpoints and cache_mode != "cache" and endpoint_object_terms:
                scoped_objs = await _resolve_topology_objects_on_demand(
                    api,
                    cache,
                    target_mgmt,
                    target_dom,
                    seed_refs=[(t if is_uuid(t) else None, t) for t in endpoint_object_terms],
                    existing_objects=scoped_objs,
                    force_refresh=(cache_mode == "force"),
                    global_cache=global_obj_cache,
                    global_lock=global_obj_lock,
                )
            indexed_objs_by_dom[d_key] = _index_objects(scoped_objs, domain_name=target_dom)
        return indexed_objs_by_dom[d_key]

    candidates: list[AffectedGatewayCandidate] = []

    for gw_id in all_gw_ids:
        raw_gw_entries = entries_by_gw_id.get(gw_id, [])
        gw_anns = anns_by_gw_id.get(gw_id, [])
        gw_asset = assets_by_id.get(gw_id)
        (
            gw_entries,
            has_live_routes,
            ann_by_if_cidr,
            _,
            gw_trust_static,
            if_trust_static,
        ) = _build_effective_gateway_entries(
            raw_gw_entries,
            gw_anns,
            gateway_asset=gw_asset,
        )
        if allowed_source_types is not None:
            gw_entries = [e for e in gw_entries if e.source_type in allowed_source_types]
            has_live_routes = any(e.source_type in LIVE_ROUTE_SOURCES for e in gw_entries)
        if not gw_entries and not (include_policy_inferred and gw_asset is not None):
            continue

        first_entry = gw_entries[0] if gw_entries else None
        if first_entry is not None:
            gw_mgmt = first_entry.mgmt_name
            gw_dom = first_entry.domain_name
            gw_uid = first_entry.gateway_uid
            gw_name = first_entry.gateway_name
            gw_type = first_entry.gateway_type
            eff_gw_id = first_entry.gateway_id
            eff_gw_asset_id = first_entry.gateway_asset_id
        elif gw_asset is not None:
            gw_mgmt = gw_asset.mgmt_name
            gw_dom = gw_asset.domain_name
            gw_uid = gw_asset.uid
            gw_name = gw_asset.name
            gw_type = gw_asset.type
            eff_gw_id = gw_asset.id
            eff_gw_asset_id = gw_asset.asset_id
        else:
            continue

        dom_key = (gw_mgmt, gw_dom)
        if active_dom_key != dom_key:
            indexed_objs_by_dom.clear()
            resolved_endpoints_by_dom.clear()
            snapshots_by_dom.clear()
            expanded_rules_by_dom.clear()
            active_dom_key = dom_key

        if static_endpoints is not None:
            src_intervals, dst_intervals = static_endpoints
        else:
            if dom_key not in resolved_endpoints_by_dom:
                obj_by_uid, obj_by_name = await _ensure_domain_index(
                    gw_mgmt,
                    gw_dom,
                    resolve_endpoints=True,
                )
                resolved_endpoints_by_dom[dom_key] = (
                    _resolve_endpoint_intervals(src_list, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name),
                    _resolve_endpoint_intervals(dst_list, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name),
                )
            src_intervals, dst_intervals = resolved_endpoints_by_dom[dom_key]
        if not src_intervals or not dst_intervals:
            continue

        internal_live = [e for e in gw_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"]
        internal_static = [
            e
            for e in gw_entries
            if e.source_type in ("interface_connected", "interface_specific", "vpn_domain")
            and e.topology_zone == "internal"
        ]

        external_if_names = {e.interface_name for e in gw_entries if e.topology_zone == "external"}
        seen_flow_keys: set[tuple[str, str, str, str, str, str]] = set()
        match_types_seen: list[str] = []

        matched_flows = (
            _match_l3_cross_interface_flows(
                src_intervals=src_intervals,
                dst_intervals=dst_intervals,
                gw_entries=gw_entries,
                external_if_names=external_if_names,
                has_live_routes=has_live_routes,
                ann_by_if_cidr=ann_by_if_cidr,
                weights=weights,
                gw_trust_static=gw_trust_static,
                if_trust_static=if_trust_static,
                internal_live=internal_live,
                internal_static=internal_static,
                include_standby=include_standby,
                seen_flow_keys=seen_flow_keys,
            )
            if gw_entries
            else []
        )

        gw_norm_ifs: list[_NormalizedInterface] | None = None
        if gw_asset is not None and not matched_flows and include_policy_inferred:
            if gw_id not in norm_ifs_by_gw_id:
                norm_ifs_by_gw_id[gw_id] = _normalize_gateway_interfaces(gw_asset)
            gw_norm_ifs = norm_ifs_by_gw_id[gw_id]

        need_policy_check = bool(matched_flows) or (
            include_policy_inferred
            and _is_one_arm_or_incomplete_topology_gateway(gw_asset, gw_entries, norm_ifs=gw_norm_ifs)
        )
        if not need_policy_check:
            continue

        if dom_key not in snapshots_by_dom:
            dom_snap = await cache.get_domain_rulebase(gw_mgmt, gw_dom)
            if cache_mode != "cache" and not dom_snap.package_layers:
                pkg_snap = await _load_domain_package_snapshot(
                    cache,
                    rulebase_refresh,
                    gw_mgmt,
                    gw_dom,
                    allow_refresh=True,
                    cache_ttl=cache_ttl,
                )
                if pkg_snap.package_layers:
                    dom_snap = dom_snap.model_copy(update={"package_layers": pkg_snap.package_layers})
            snapshots_by_dom[dom_key] = dom_snap
        dom_snapshot = snapshots_by_dom[dom_key]

        installed_pol, pkg_names, layer_names = await _resolve_gateway_policy_metadata(
            cache,
            rulebase_refresh,
            gw_mgmt,
            gw_dom,
            gw_asset,
            gw_uid,
            gw_name,
            all_assets=assets_by_dom.get(dom_key, []),
            snapshot=dom_snapshot,
        )

        if dom_key not in expanded_rules_by_dom:
            if not dom_snapshot.access_rules and not dom_snapshot.nat_rules:
                expanded_rules_by_dom[dom_key] = []
            else:
                obj_by_uid, obj_by_name = await _ensure_domain_index(gw_mgmt, gw_dom)
                expanded_rules_by_dom[dom_key] = _expand_domain_policy_rules(
                    dom_snapshot,
                    domain_assets=assets_by_dom.get(dom_key, []),
                    obj_by_uid=obj_by_uid,
                    obj_by_name=obj_by_name,
                )
        gw_rules = _filter_rules_for_gateway(
            expanded_rules_by_dom[dom_key],
            gateway_uid=gw_uid,
            gateway_name=gw_name,
            gateway_id=eff_gw_id,
            gateway_asset_id=eff_gw_asset_id,
            installed_policy=installed_pol,
            policy_packages=pkg_names,
        )

        if matched_flows:
            matched_flows = _apply_policy_rule_evidence(
                matched_flows=matched_flows,
                src_intervals=src_intervals,
                dst_intervals=dst_intervals,
                gw_rules=gw_rules,
                gw_name=gw_name,
                weights=weights,
                min_confidence=min_confidence,
                match_types_seen=match_types_seen,
            )
        elif include_policy_inferred and gw_rules:
            matched_flows = _infer_one_arm_policy_flows(
                first_entry=first_entry,
                gw_norm_ifs=gw_norm_ifs,
                external_if_names=external_if_names,
                src_intervals=src_intervals,
                dst_intervals=dst_intervals,
                gw_rules=gw_rules,
                gw_name=gw_name,
                weights=weights,
                min_confidence=min_confidence,
                seen_flow_keys=seen_flow_keys,
                match_types_seen=match_types_seen,
            )

        if not matched_flows:
            continue

        candidates.append(
            _build_affected_gateway_candidate(
                gw_mgmt=gw_mgmt,
                gw_dom=gw_dom,
                eff_gw_id=eff_gw_id,
                eff_gw_asset_id=eff_gw_asset_id,
                gw_uid=gw_uid,
                gw_name=gw_name,
                gw_type=gw_type,
                gw_asset=gw_asset,
                installed_pol=installed_pol,
                pkg_names=pkg_names,
                layer_names=layer_names,
                match_types_seen=match_types_seen,
                src_list=src_list,
                dst_list=dst_list,
                matched_flows=matched_flows,
            )
        )

    candidates.sort(
        key=lambda c: (
            0 if "internal_to_internal" in c.match_types else (2 if c.match_types == ["policy_inferred"] else 1),
            1 if c.is_standby_path else 0,
            -c.confidence,
            -len(c.matched_flows),
            c.mgmt_name,
            c.domain_name,
            c.gateway_name,
        )
    )
    return candidates
