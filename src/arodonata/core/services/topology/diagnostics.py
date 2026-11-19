"""Gateway topology query/summarization, static health diagnostics, and persistent annotation CRUD."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    AntiSpoofingMode,
    GatewayInterfaceSummary,
    GatewayTopologyEntry,
    TopologyAnnotation,
    TopologyDiagnostic,
    TopologyDiagnosticCode,
    TopologyDiagnosticSeverity,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import RulebaseRefreshPort
from arodonata.core.services.topology._shared import (
    _matches_gateway_filter,
    _normalize_gateway_filter_tokens,
    _NormalizedInterface,
    _RefreshTopologyFn,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology.normalizer import _normalize_gateway_interfaces
from arodonata.core.services.topology.objects import (
    _expand_specific_reference,
    _index_objects,
    _load_domain_scoped_objects,
)
from arodonata.core.services.topology.policy_rules import (
    _load_domain_package_snapshot,
    _resolve_gateway_policy_metadata,
)
from arodonata.core.telemetry import span_attrs


async def get_gateway_topology(
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    *,
    refresh_topology_fn: _RefreshTopologyFn,
    mgmt_name: str | None = None,
    domain: str | None = None,
    gateway: str | None = None,
    topology_zone: TopologyZone | None = None,
    source_types: Sequence[TopologySourceType | str] | None = None,
    cache_mode: CacheMode = "smart",
    cache_ttl: float | None = None,
) -> list[GatewayTopologyEntry]:
    """Ensure topology is synchronized (unless `cache_mode="cache"`) and return cached `GatewayTopologyEntry` rows."""
    span_attrs(mgmt_name=mgmt_name, domain=domain, gateway=gateway, cache_mode=cache_mode)
    if cache_mode != "cache":
        await refresh_topology_fn(
            mgmt_name=mgmt_name,
            domains=[domain] if domain else None,
            include_global=domain == "Global",
            mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    entries = await cache.get_gateway_topology(
        mgmt_name=mgmt_name,
        domain_name=domain,
        topology_zone=topology_zone,
        source_types=list(source_types) if source_types is not None else None,
    )
    if gateway:
        gw_clean = gateway.strip().lower()
        entries = [
            e
            for e in entries
            if gw_clean
            in (
                e.gateway_uid.lower(),
                e.gateway_name.lower(),
                e.gateway_id.lower(),
                e.gateway_asset_id.lower(),
            )
        ]
    if not entries:
        return []

    all_assets = await cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
    assets_by_id: dict[str, Asset] = {a.id: a for a in all_assets}
    assets_by_dom: dict[tuple[str, str], list[Asset]] = defaultdict(list)
    for a in all_assets:
        assets_by_dom[(a.mgmt_name, a.domain_name)].append(a)

    policy_by_gw_id: dict[str, tuple[str | None, list[str]]] = {}
    snapshots_by_dom: dict[tuple[str, str], DomainRulebaseSnapshot] = {}
    enriched_entries: list[GatewayTopologyEntry] = []
    for entry in entries:
        if entry.gateway_id not in policy_by_gw_id:
            gw_asset = assets_by_id.get(entry.gateway_id)
            dom_key = (entry.mgmt_name, entry.domain_name)
            if dom_key not in snapshots_by_dom:
                snapshots_by_dom[dom_key] = await _load_domain_package_snapshot(
                    cache,
                    rulebase_refresh,
                    entry.mgmt_name,
                    entry.domain_name,
                )
            dom_assets = assets_by_dom.get(dom_key, [])
            inst_pol, pkg_names, _ = await _resolve_gateway_policy_metadata(
                cache,
                rulebase_refresh,
                entry.mgmt_name,
                entry.domain_name,
                gw_asset,
                entry.gateway_uid,
                entry.gateway_name,
                all_assets=dom_assets,
                snapshot=snapshots_by_dom[dom_key],
            )
            policy_by_gw_id[entry.gateway_id] = (inst_pol, pkg_names)
        inst_pol, pkg_names = policy_by_gw_id[entry.gateway_id]
        enriched_entries.append(
            entry.model_copy(
                update={
                    "installed_access_policy": inst_pol,
                    "policy_packages": list(pkg_names),
                }
            )
        )
    return enriched_entries


def summarize_gateway_interfaces(
    entries: Sequence[GatewayTopologyEntry],
) -> list[GatewayInterfaceSummary]:
    """Aggregate flat `GatewayTopologyEntry` rows into per-interface `GatewayInterfaceSummary` models."""
    grouped: dict[tuple[str, str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
    for entry in entries:
        key = (entry.mgmt_name, entry.domain_name, entry.gateway_uid, entry.interface_name)
        grouped[key].append(entry)

    summaries: list[GatewayInterfaceSummary] = []
    for (_, _, _, _), group_entries in sorted(grouped.items()):
        first = group_entries[0]
        zone: TopologyZone = "external" if any(e.topology_zone == "external" for e in group_entries) else "internal"
        src_types: list[str] = []
        cidrs: list[str] = []
        for e in group_entries:
            if e.source_type not in src_types:
                src_types.append(e.source_type)
            if e.cidr_or_range not in cidrs:
                cidrs.append(e.cidr_or_range)

        summaries.append(
            GatewayInterfaceSummary(
                mgmt_name=first.mgmt_name,
                domain_name=first.domain_name,
                gateway_id=first.gateway_id,
                gateway_asset_id=first.gateway_asset_id,
                gateway_uid=first.gateway_uid,
                gateway_name=first.gateway_name,
                gateway_type=first.gateway_type,
                interface_name=first.interface_name,
                interface_ipv4=first.interface_ipv4,
                interface_mask_length=first.interface_mask_length,
                topology_zone=zone,
                leads_to_dmz=any(e.leads_to_dmz for e in group_entries),
                anti_spoofing_mode=next(
                    (e.anti_spoofing_mode for e in group_entries if e.anti_spoofing_mode != "unknown"),
                    first.anti_spoofing_mode,
                ),
                source_types=src_types,
                cidrs_and_ranges=cidrs,
            )
        )
    return summaries


def _make_diagnostic(
    gw: Asset,
    *,
    if_name: str | None,
    code: TopologyDiagnosticCode,
    severity: TopologyDiagnosticSeverity,
    message: str,
    behind_mode: str = "",
    anti_spoofing_mode: AntiSpoofingMode = "unknown",
    specific_network_ref: str | None = None,
) -> TopologyDiagnostic:
    return TopologyDiagnostic(
        mgmt_name=gw.mgmt_name,
        domain_name=gw.domain_name,
        gateway_id=gw.id,
        gateway_asset_id=gw.asset_id,
        gateway_uid=gw.uid,
        gateway_name=gw.name,
        gateway_type=gw.type,
        interface_name=if_name,
        code=code,
        severity=severity,
        behind_mode=behind_mode,
        anti_spoofing_mode=anti_spoofing_mode,
        specific_network_ref=specific_network_ref,
        message=message,
    )


def _diagnose_gateway_interface(
    asset: Asset,
    nif: _NormalizedInterface,
    *,
    if_entries: Sequence[GatewayTopologyEntry],
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
) -> list[TopologyDiagnostic]:
    """Emit static topology diagnostics for a single normalized gateway interface."""
    diags: list[TopologyDiagnostic] = []
    non_connected_route_entries = [
        e
        for e in if_entries
        if (e.source_type in LIVE_ROUTE_SOURCES and e.source_type != "connected_route")
        or e.source_type == "vs_static_route"
    ]
    mode_lower = nif.behind_mode.lower()

    if not nif.is_external and nif.anti_spoofing_mode in ("detect", "off"):
        diags.append(
            _make_diagnostic(
                asset,
                if_name=nif.interface_name,
                code="anti_spoofing_detect_or_off",
                severity="warning",
                behind_mode=nif.behind_mode,
                anti_spoofing_mode=nif.anti_spoofing_mode,
                specific_network_ref=nif.specific_network_ref,
                message=(
                    f"Interface {nif.interface_name!r} on {asset.name!r} has Anti-Spoofing in "
                    f"{nif.anti_spoofing_mode!r} mode; static topology may be stale or unverified."
                ),
            )
        )

    if nif.is_external:
        return diags

    if "specific" in mode_lower:
        ref_uid = nif.specific_network_uid
        ref_name = nif.specific_network_ref
        root_obj = (
            (obj_by_uid.get(ref_uid) if ref_uid else None)
            or (obj_by_name.get(ref_name) if ref_name else None)
            or (obj_by_name.get(ref_uid) if ref_uid else None)
        )
        expanded = _expand_specific_reference(
            ref_uid=ref_uid,
            ref_name=ref_name,
            obj_by_uid=obj_by_uid,
            obj_by_name=obj_by_name,
        )
        if not expanded and not nif.specific_inline_cidr:
            if root_obj is None:
                diags.append(
                    _make_diagnostic(
                        asset,
                        if_name=nif.interface_name,
                        code="unresolved_specific",
                        severity="warning",
                        behind_mode=nif.behind_mode,
                        anti_spoofing_mode=nif.anti_spoofing_mode,
                        specific_network_ref=ref_name or ref_uid,
                        message=(
                            f"Interface {nif.interface_name!r} on {asset.name!r} references specific "
                            f"object {ref_name or ref_uid!r} which could not be found."
                        ),
                    )
                )
            else:
                diags.append(
                    _make_diagnostic(
                        asset,
                        if_name=nif.interface_name,
                        code="empty_specific",
                        severity="warning",
                        behind_mode=nif.behind_mode,
                        anti_spoofing_mode=nif.anti_spoofing_mode,
                        specific_network_ref=root_obj.name,
                        message=(
                            f"Interface {nif.interface_name!r} on {asset.name!r} references group "
                            f"{root_obj.name!r} which expands to zero IPv4 addresses or subnets."
                        ),
                    )
                )
    elif "interface ip and net mask" in mode_lower or mode_lower == "connected":
        if nif.ipv4_address is None or nif.mask_length is None:
            diags.append(
                _make_diagnostic(
                    asset,
                    if_name=nif.interface_name,
                    code="missing_ip_mask",
                    severity="warning",
                    behind_mode=nif.behind_mode,
                    anti_spoofing_mode=nif.anti_spoofing_mode,
                    message=(
                        f"Interface {nif.interface_name!r} on {asset.name!r} uses connected IP/netmask "
                        "topology but is missing a valid IPv4 address or mask length."
                    ),
                )
            )
    elif "routing" in mode_lower:
        if not non_connected_route_entries:
            diags.append(
                _make_diagnostic(
                    asset,
                    if_name=nif.interface_name,
                    code="routing_defined_without_routes",
                    severity="warning",
                    behind_mode=nif.behind_mode,
                    anti_spoofing_mode=nif.anti_spoofing_mode,
                    message=(
                        f"Interface {nif.interface_name!r} on {asset.name!r} has topology "
                        f"{nif.behind_mode!r} without collected static or dynamic routes."
                    ),
                )
            )
    elif not non_connected_route_entries:
        diags.append(
            _make_diagnostic(
                asset,
                if_name=nif.interface_name,
                code="not_defined",
                severity="warning",
                behind_mode=nif.behind_mode or "not defined",
                anti_spoofing_mode=nif.anti_spoofing_mode,
                message=(
                    f"Interface {nif.interface_name!r} on {asset.name!r} has undefined topology "
                    f"({nif.behind_mode or 'not defined'!r})."
                ),
            )
        )

    return diags


async def get_topology_diagnostics(
    cache: _TopologyServiceCachePort,
    *,
    refresh_topology_fn: _RefreshTopologyFn,
    mgmt_name: str | None = None,
    domain: str | None = None,
    gateways: Sequence[str] | str | None = None,
    gateway: str | None = None,
    min_severity: TopologyDiagnosticSeverity = "info",
    cache_mode: CacheMode = "smart",
    cache_ttl: float | None = None,
) -> list[TopologyDiagnostic]:
    """Inspect gateway and interface definitions and return `TopologyDiagnostic` items."""
    eff_gateways = gateways if gateways is not None else gateway
    span_attrs(mgmt_name=mgmt_name, domain=domain, min_severity=min_severity, cache_mode=cache_mode)
    if cache_mode != "cache":
        await refresh_topology_fn(
            mgmt_name=mgmt_name,
            domains=[domain] if domain else None,
            gateways=eff_gateways if cache_mode == "force" else None,
            include_global=domain == "Global",
            mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    all_assets = await cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
    topo_entries = await cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)

    gw_tokens = set(_normalize_gateway_filter_tokens(eff_gateways))
    policy_gateways = [
        a for a in all_assets if is_policy_enforcing_gateway(a) and _matches_gateway_filter(a, gw_tokens)
    ]

    global_obj_cache: dict[str, list[CPObject]] = {}
    active_dom_key: tuple[str, str] | None = None
    active_obj_index: tuple[dict[str, CPObject], dict[str, CPObject]] | None = None

    entries_by_gw_if: dict[tuple[str, str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
    for entry in topo_entries:
        entries_by_gw_if[(entry.mgmt_name, entry.domain_name, entry.gateway_uid, entry.interface_name)].append(entry)

    diagnostics: list[TopologyDiagnostic] = []
    for asset in sorted(policy_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name)):
        norm_ifs = _normalize_gateway_interfaces(asset)

        if not norm_ifs:
            diagnostics.append(
                _make_diagnostic(
                    asset,
                    if_name=None,
                    code="no_interfaces",
                    severity="warning",
                    message=f"Gateway {asset.name!r} has no network interfaces defined in SmartConsole.",
                )
            )
            continue

        # One-arm informational classification (single interface or external-only, e.g. Cisco ACI service graph).
        # Internal-only gateways (multiple internal interfaces, no external interface) are normal and emit zero warnings.
        has_internal_if = any(not nif.is_external for nif in norm_ifs)
        if len(norm_ifs) == 1 or not has_internal_if:
            diagnostics.append(
                _make_diagnostic(
                    asset,
                    if_name=norm_ifs[0].interface_name if len(norm_ifs) == 1 else None,
                    code="one_arm_topology",
                    severity="info",
                    message=(
                        f"Gateway {asset.name!r} has a one-arm / external-only interface layout "
                        f"({len(norm_ifs)} interface(s)); traffic paths depend on external fabric/PBR redirection."
                    ),
                )
            )

        dom_key = (asset.mgmt_name, asset.domain_name)
        needs_specific_lookup = any(not nif.is_external and "specific" in nif.behind_mode.lower() for nif in norm_ifs)
        if needs_specific_lookup:
            if active_dom_key != dom_key or active_obj_index is None:
                scoped_objs = await _load_domain_scoped_objects(
                    cache,
                    asset.mgmt_name,
                    asset.domain_name,
                    global_cache=global_obj_cache,
                )
                active_obj_index = _index_objects(scoped_objs, domain_name=asset.domain_name)
                active_dom_key = dom_key
            obj_by_uid, obj_by_name = active_obj_index
        else:
            obj_by_uid, obj_by_name = {}, {}

        for nif in norm_ifs:
            if_entries = entries_by_gw_if.get(
                (asset.mgmt_name, asset.domain_name, asset.uid, nif.interface_name),
                [],
            )
            diagnostics.extend(
                _diagnose_gateway_interface(
                    asset,
                    nif,
                    if_entries=if_entries,
                    obj_by_uid=obj_by_uid,
                    obj_by_name=obj_by_name,
                )
            )

    if min_severity == "warning":
        return [d for d in diagnostics if d.severity == "warning"]
    return diagnostics


async def get_topology_annotations(
    cache: _TopologyServiceCachePort,
    mgmt_name: str | None = None,
    domain: str | None = None,
    *,
    gateway: str | None = None,
    interface_name: str | None = None,
) -> list[TopologyAnnotation]:
    """Return persistent `TopologyAnnotation` records from `arodonata_topology_annotations`."""
    annotations = await cache.get_topology_annotations(
        mgmt_name=mgmt_name,
        domain_name=domain,
        interface_name=interface_name,
    )
    if gateway and gateway.strip():
        gw_clean = gateway.strip().lower()
        annotations = [a for a in annotations if gw_clean in (a.gateway_uid.lower(), a.gateway_name.lower())]
    return annotations


async def upsert_topology_annotations(
    cache: _TopologyServiceCachePort,
    annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any],
) -> list[TopologyAnnotation]:
    """Insert or update persistent `TopologyAnnotation` records and return the normalized models."""
    items: Sequence[TopologyAnnotation | dict[str, Any]] = (
        [annotations] if isinstance(annotations, (TopologyAnnotation, dict)) else annotations
    )
    normalized: list[TopologyAnnotation] = [
        a if isinstance(a, TopologyAnnotation) else TopologyAnnotation.model_validate(a) for a in items
    ]
    await cache.upsert_topology_annotations(normalized)
    return normalized


async def delete_topology_annotations(
    cache: _TopologyServiceCachePort,
    annotation_ids: Sequence[str] | str | None = None,
    *,
    mgmt_name: str | None = None,
    domain: str | None = None,
    gateway_uid: str | None = None,
) -> int:
    """Delete persistent `TopologyAnnotation` records by ID or filter."""
    if annotation_ids is not None:
        ids = [annotation_ids] if isinstance(annotation_ids, str) else list(annotation_ids)
        return await cache.delete_topology_annotations(ids)
    matching = await cache.get_topology_annotations(
        mgmt_name=mgmt_name,
        domain_name=domain,
        gateway_uids=[gateway_uid] if gateway_uid else None,
    )
    if not matching:
        return 0
    return await cache.delete_topology_annotations([a.id for a in matching])
