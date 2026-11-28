"""Domain topology sync-head checks, trusted object domain analysis, and static/VSX extraction."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.topology import (
    STATIC_TOPOLOGY_SOURCES,
    AntiSpoofingMode,
    GatewayTopologyEntry,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import ApiPort, RulebaseRefreshPort
from arodonata.core.primitives import MAX_IPV4_INT
from arodonata.core.services._asset_linking import (
    VSX_CHILD_TYPES,
    _extract_interfaces_from_generic,
)
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.services.topology._shared import (
    _TOPOLOGY_OBJECT_SYNC_TYPES,
    _NormalizedInterface,
    _TopologyServiceCachePort,
    is_policy_enforcing_gateway,
    logger,
)
from arodonata.core.services.topology.normalizer import (
    _extract_raw_routes,
    _extract_vpn_domain_refs,
    _normalize_gateway_interfaces,
    _parse_route_destination,
    _parse_route_nexthop_and_interface,
)
from arodonata.core.services.topology.objects import (
    _expand_specific_reference,
    _fetch_asset_detail_on_demand,
    _index_objects,
    _load_domain_scoped_objects,
    _lookup_indexed_object,
    _resolve_topology_objects_on_demand,
)
from arodonata.core.services.topology.policy_rules import (
    _load_domain_package_snapshot,
    _resolve_gateway_policy_metadata,
)


def _does_sync_state_match_head(
    st: DomainSyncState | None,
    remote_published_at: datetime | None,
    remote_session_uid: str | None,
) -> bool:
    """Return `True` when cached sync state `st` matches the remote published head."""
    if st is None or st.status != "ok":
        return False
    if remote_published_at is not None:
        if st.last_published_at is None or st.last_published_at != remote_published_at:
            return False
        return not (remote_session_uid is not None and st.last_session_uid != remote_session_uid)
    if remote_session_uid is not None:
        return st.last_session_uid == remote_session_uid
    return st.synced_at is not None and st.last_published_at is None and st.last_session_uid is None


async def _has_complete_object_sync_states(
    cache: _TopologyServiceCachePort,
    mgmt_name: str,
    domain_name: str,
) -> list[DomainSyncState] | None:
    """Return `DomainSyncState` records if all topology object types are marked `ok`, else `None`."""
    states: list[DomainSyncState] = []
    for item_type in _TOPOLOGY_OBJECT_SYNC_TYPES:
        st = await cache.get_sync_state(mgmt_name, domain_name, "objects", item_type)
        if st is None or st.status != "ok":
            return None
        states.append(st)
    return states


async def _compute_trusted_object_domains(
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    mgmt_name: str,
    domain_name: str,
    *,
    probe: DomainProbeResult | None = None,
    dom_info: DomainInfo | None = None,
    mode: CacheMode = "smart",
    cache_ttl: float | None = None,
    force_object_refresh: bool = False,
    global_trusted_cache: dict[str, bool] | None = None,
    global_lock: asyncio.Lock | None = None,
) -> set[str]:
    """Return the subset of `{domain_name, 'Global'}` whose full object cache matches the current published head."""
    if force_object_refresh:
        return set()
    trusted: set[str] = set()

    dom_states = await _has_complete_object_sync_states(cache, mgmt_name, domain_name)
    if dom_states is not None:
        if probe is not None:
            if not any(
                coordinator.is_slice_invalidated(mgmt_name, domain_name, "objects", st.item_type, st.synced_at)
                for st in dom_states
            ) and all(
                _does_sync_state_match_head(st, probe.remote_published_at, probe.remote_session_uid)
                for st in dom_states
            ):
                trusted.add(domain_name)
        elif dom_info is not None:
            obj_probe = await coordinator.probe_domain_staleness(
                dom_info,
                scope="objects",
                item_types=_TOPOLOGY_OBJECT_SYNC_TYPES,
                mode=mode,
                cache_ttl=cache_ttl,
            )
            if not obj_probe.is_stale:
                trusted.add(domain_name)

    if domain_name != "Global":

        async def _check_global_fresh() -> bool:
            if global_trusted_cache is not None and mgmt_name in global_trusted_cache:
                return global_trusted_cache[mgmt_name]
            g_states = await _has_complete_object_sync_states(cache, mgmt_name, "Global")
            if g_states is None:
                if global_trusted_cache is not None:
                    global_trusted_cache[mgmt_name] = False
                return False
            global_dom = await cache.get_domain(mgmt_name, "Global")
            if global_dom is None:
                if global_trusted_cache is not None:
                    global_trusted_cache[mgmt_name] = False
                return False
            g_probe = await coordinator.probe_domain_staleness(
                global_dom,
                scope="objects",
                item_types=_TOPOLOGY_OBJECT_SYNC_TYPES,
                mode="smart",
                cache_ttl=cache_ttl,
            )
            is_fresh = not g_probe.is_stale
            if global_trusted_cache is not None:
                global_trusted_cache[mgmt_name] = is_fresh
            return is_fresh

        if global_lock is not None:
            async with global_lock:
                if await _check_global_fresh():
                    trusted.add("Global")
        elif await _check_global_fresh():
            trusted.add("Global")

    return trusted


def _make_topology_entry(
    *,
    mgmt_name: str,
    domain_name: str,
    asset: Asset,
    interface_name: str,
    interface_ipv4: str | None,
    interface_mask_length: int | None,
    topology_zone: TopologyZone,
    leads_to_dmz: bool,
    anti_spoofing_mode: AntiSpoofingMode,
    source_type: TopologySourceType,
    source_ref: str,
    cidr_or_range: str,
    ip_first_int: int,
    ip_last_int: int,
    prefix_len: int,
    installed_pol: str | None,
    pkg_names: Sequence[str],
    now: datetime,
) -> GatewayTopologyEntry:
    """Construct a `GatewayTopologyEntry` with shared gateway and policy metadata."""
    return GatewayTopologyEntry(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        gateway_uid=asset.uid,
        gateway_name=asset.name,
        gateway_type=asset.type,
        interface_name=interface_name,
        interface_ipv4=interface_ipv4,
        interface_mask_length=interface_mask_length,
        topology_zone=topology_zone,
        leads_to_dmz=leads_to_dmz,
        anti_spoofing_mode=anti_spoofing_mode,
        source_type=source_type,
        source_ref=source_ref,
        cidr_or_range=cidr_or_range,
        ip_first_int=ip_first_int,
        ip_last_int=ip_last_int,
        prefix_len=prefix_len,
        installed_access_policy=installed_pol,
        policy_packages=list(pkg_names),
        updated_at=now,
    )


async def _prepare_domain_gateways(
    *,
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    policy_gateways: Sequence[Asset],
    objects: Sequence[CPObject],
    allow_live_detail: bool,
    force_object_refresh: bool,
    trusted_object_domains: set[str] | None,
    already_detailed_uids: set[str] | None,
) -> tuple[
    list[tuple[Asset, bool, list[dict[str, object]], list[_NormalizedInterface]]],
    list[tuple[str | None, str | None]],
    list[Asset],
]:
    """Enrich gateway details on demand, normalize interfaces, and collect seed object references."""
    pre_by_uid, pre_by_name = (
        _index_objects(objects, domain_name=domain_name)
        if allow_live_detail and objects and trusted_object_domains is not None
        else ({}, {})
    )

    prepared_gateways: list[tuple[Asset, bool, list[dict[str, object]], list[_NormalizedInterface]]] = []
    seed_object_refs: list[tuple[str | None, str | None]] = []
    updated_assets: list[Asset] = []

    for asset in policy_gateways:
        is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
        raw_ifs = list(asset.interfaces) or _extract_interfaces_from_generic(asset.raw_data)
        raw_routes = _extract_raw_routes(asset.raw_data)

        needs_detail = (
            allow_live_detail
            and (already_detailed_uids is None or asset.uid not in already_detailed_uids)
            and (
                not raw_ifs
                or (
                    not is_vs
                    and not any(
                        isinstance(i.get("topology"), (dict, str)) or isinstance(i.get("topology-settings"), dict)
                        for i in raw_ifs
                        if isinstance(i, dict)
                    )
                )
            )
        )
        if needs_detail:
            enriched = await _fetch_asset_detail_on_demand(api, mgmt_name, domain_name, asset)
            if enriched is not None:
                asset = enriched
                updated_assets.append(asset)
                raw_routes = _extract_raw_routes(asset.raw_data)

        norm_ifs = _normalize_gateway_interfaces(asset)
        if allow_live_detail:
            for nif in norm_ifs:
                has_untrusted_cached = False
                if not force_object_refresh and nif.specific_inline_cidr and trusted_object_domains is not None:
                    cached_spec = _lookup_indexed_object(
                        nif.specific_network_uid,
                        nif.specific_network_ref,
                        pre_by_uid,
                        pre_by_name,
                    )
                    if cached_spec is not None and cached_spec.domain_name not in trusted_object_domains:
                        has_untrusted_cached = True
                if (
                    not nif.is_external
                    and "specific" in nif.behind_mode.lower()
                    and (nif.specific_network_uid or nif.specific_network_ref)
                    and (force_object_refresh or not nif.specific_inline_cidr or has_untrusted_cached)
                ):
                    seed_object_refs.append((nif.specific_network_uid, nif.specific_network_ref))
            vpn_uid, vpn_name = _extract_vpn_domain_refs(asset.raw_data)
            if vpn_uid or vpn_name:
                seed_object_refs.append((vpn_uid, vpn_name))

        prepared_gateways.append((asset, is_vs, list(raw_routes), norm_ifs))

    return prepared_gateways, seed_object_refs, updated_assets


def _extract_vs_static_route_entries(
    *,
    mgmt_name: str,
    domain_name: str,
    asset: Asset,
    raw_routes: Sequence[dict[str, object]],
    norm_ifs: Sequence[_NormalizedInterface],
    connected_by_if: dict[str, tuple[_NormalizedInterface, ipaddress.IPv4Network]],
    installed_pol: str | None,
    pkg_names: Sequence[str],
    now: datetime,
) -> tuple[list[GatewayTopologyEntry], set[str], set[str]]:
    """Extract VSX Virtual System static route entries and track routed / default-routed interfaces."""
    routed_if_names: set[str] = set()
    external_routed_if_names: set[str] = set()
    vs_route_entries: list[GatewayTopologyEntry] = []

    for route in raw_routes:
        dest_net = _parse_route_destination(route)
        if dest_net is None:
            continue
        nh_ip, explicit_if = _parse_route_nexthop_and_interface(route)
        target_if_name: str | None = explicit_if
        target_nif: _NormalizedInterface | None = None

        if target_if_name:
            for nif in norm_ifs:
                if nif.interface_name == target_if_name:
                    target_nif = nif
                    break
        elif nh_ip is not None:
            # Find the VS interface whose connected subnet contains the next-hop IP
            best_plen = -1
            for if_name, (nif, c_net) in connected_by_if.items():
                if nh_ip in c_net and c_net.prefixlen > best_plen:
                    best_plen = c_net.prefixlen
                    target_if_name = if_name
                    target_nif = nif

        if not target_if_name:
            continue

        routed_if_names.add(target_if_name)
        nh_ref = f"nexthop:{nh_ip}" if nh_ip is not None else "static-route"
        is_default = dest_net.prefixlen == 0 and int(dest_net.network_address) == 0
        if is_default:
            external_routed_if_names.add(target_if_name)
        vs_route_entries.append(
            _make_topology_entry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                asset=asset,
                interface_name=target_if_name,
                interface_ipv4=target_nif.ipv4_address if target_nif else None,
                interface_mask_length=target_nif.mask_length if target_nif else None,
                topology_zone="external" if is_default else "internal",
                leads_to_dmz=target_nif.leads_to_dmz if target_nif else False,
                anti_spoofing_mode=target_nif.anti_spoofing_mode if target_nif else "unknown",
                source_type="vs_static_route",
                source_ref=nh_ref,
                cidr_or_range="0.0.0.0/0" if is_default else str(dest_net),
                ip_first_int=0 if is_default else int(dest_net.network_address),
                ip_last_int=MAX_IPV4_INT if is_default else int(dest_net.broadcast_address),
                prefix_len=0 if is_default else dest_net.prefixlen,
                installed_pol=installed_pol,
                pkg_names=pkg_names,
                now=now,
            )
        )

    return vs_route_entries, routed_if_names, external_routed_if_names


def _extract_interface_and_vpn_entries(
    *,
    mgmt_name: str,
    domain_name: str,
    asset: Asset,
    norm_ifs: Sequence[_NormalizedInterface],
    connected_by_if: dict[str, tuple[_NormalizedInterface, ipaddress.IPv4Network]],
    routed_if_names: set[str],
    external_routed_if_names: set[str],
    vs_route_entries: Sequence[GatewayTopologyEntry],
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
    installed_pol: str | None,
    pkg_names: Sequence[str],
    now: datetime,
) -> list[GatewayTopologyEntry]:
    """Build static interface entries (`external`, `specific`, `connected`), merge VS routes, and expand VPN domains."""
    gw_entries: list[GatewayTopologyEntry] = []

    for nif in norm_ifs:
        if nif.is_external:
            gw_entries.append(
                _make_topology_entry(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    asset=asset,
                    interface_name=nif.interface_name,
                    interface_ipv4=nif.ipv4_address,
                    interface_mask_length=nif.mask_length,
                    topology_zone="external",
                    leads_to_dmz=nif.leads_to_dmz,
                    anti_spoofing_mode=nif.anti_spoofing_mode,
                    source_type="external_interface",
                    source_ref="leads-to-internet",
                    cidr_or_range="0.0.0.0/0",
                    ip_first_int=0,
                    ip_last_int=MAX_IPV4_INT,
                    prefix_len=0,
                    installed_pol=installed_pol,
                    pkg_names=pkg_names,
                    now=now,
                )
            )
            continue

        mode_lower = nif.behind_mode.lower()
        if "specific" in mode_lower:
            expanded = _expand_specific_reference(
                ref_uid=nif.specific_network_uid,
                ref_name=nif.specific_network_ref,
                obj_by_uid=obj_by_uid,
                obj_by_name=obj_by_name,
            )
            if not expanded and nif.specific_inline_cidr:
                try:
                    inline_net = ipaddress.IPv4Network(nif.specific_inline_cidr, strict=False)
                    inline_ref = nif.specific_network_ref or nif.specific_network_uid or str(inline_net)
                    expanded = [
                        (
                            str(inline_net),
                            int(inline_net.network_address),
                            int(inline_net.broadcast_address),
                            inline_net.prefixlen,
                            inline_ref,
                        )
                    ]
                except ValueError:
                    pass
            if not expanded:
                spec_target = nif.specific_network_ref or nif.specific_network_uid
                logger.warning(
                    "Gateway interface specific topology object could not be resolved: "
                    f"{mgmt_name}:{domain_name}:{asset.name} :: {nif.interface_name} "
                    f"(specific_network={spec_target!r})",
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    gateway_name=asset.name,
                    interface_name=nif.interface_name,
                    specific_network=spec_target,
                )
            for cidr_str, lo_int, hi_int, plen, src_ref in expanded:
                gw_entries.append(
                    _make_topology_entry(
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        asset=asset,
                        interface_name=nif.interface_name,
                        interface_ipv4=nif.ipv4_address,
                        interface_mask_length=nif.mask_length,
                        topology_zone="internal",
                        leads_to_dmz=nif.leads_to_dmz,
                        anti_spoofing_mode=nif.anti_spoofing_mode,
                        source_type="interface_specific",
                        source_ref=src_ref,
                        cidr_or_range=cidr_str,
                        ip_first_int=lo_int,
                        ip_last_int=hi_int,
                        prefix_len=plen,
                        installed_pol=installed_pol,
                        pkg_names=pkg_names,
                        now=now,
                    )
                )
        elif "interface ip and net mask" in mode_lower or mode_lower == "connected":
            # If this VS interface was marked external via a 0.0.0.0/0 default route,
            # still record its connected subnet unless it is purely an external warp link.
            if nif.interface_name in connected_by_if:
                _, c_net = connected_by_if[nif.interface_name]
                gw_entries.append(
                    _make_topology_entry(
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        asset=asset,
                        interface_name=nif.interface_name,
                        interface_ipv4=nif.ipv4_address,
                        interface_mask_length=nif.mask_length,
                        topology_zone="internal",
                        leads_to_dmz=nif.leads_to_dmz,
                        anti_spoofing_mode=nif.anti_spoofing_mode,
                        source_type="interface_connected",
                        source_ref="connected",
                        cidr_or_range=str(c_net),
                        ip_first_int=int(c_net.network_address),
                        ip_last_int=int(c_net.broadcast_address),
                        prefix_len=c_net.prefixlen,
                        installed_pol=installed_pol,
                        pkg_names=pkg_names,
                        now=now,
                    )
                )
        elif nif.interface_name not in routed_if_names and nif.interface_name not in external_routed_if_names:
            behind_label = nif.behind_mode or "not defined"
            logger.warning(
                "Gateway interface has dynamic routing or undefined topology without static routes; skipping: "
                f"{mgmt_name}:{domain_name}:{asset.name} :: {nif.interface_name} "
                f"(behind_mode={behind_label!r})",
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                gateway_name=asset.name,
                interface_name=nif.interface_name,
                behind_mode=behind_label,
            )

    gw_entries.extend(vs_route_entries)

    vpn_uid, vpn_name = _extract_vpn_domain_refs(asset.raw_data)
    if vpn_uid or vpn_name:
        vpn_expanded = _expand_specific_reference(
            ref_uid=vpn_uid,
            ref_name=vpn_name,
            obj_by_uid=obj_by_uid,
            obj_by_name=obj_by_name,
        )
        if vpn_expanded:
            internal_nifs = [n for n in norm_ifs if not n.is_external]
            internal_gw_entries = [e for e in gw_entries if e.topology_zone == "internal"]
            norm_if_by_name = {n.interface_name: n for n in norm_ifs}
            for cidr_str, lo_int, hi_int, plen, src_ref in vpn_expanded:
                covering_internal = [
                    e for e in internal_gw_entries if e.ip_first_int <= lo_int and hi_int <= e.ip_last_int
                ]
                overlapping_internal = [
                    e for e in internal_gw_entries if not (e.ip_last_int < lo_int or e.ip_first_int > hi_int)
                ]
                if covering_internal:
                    best_cov = min(
                        covering_internal,
                        key=lambda e: (e.ip_last_int - e.ip_first_int, -e.prefix_len, e.interface_name),
                    )
                    vpn_if_name = best_cov.interface_name
                elif overlapping_internal:
                    vpn_if_name = overlapping_internal[0].interface_name
                elif len(internal_nifs) == 1:
                    vpn_if_name = internal_nifs[0].interface_name
                else:
                    vpn_if_name = "vpn-domain"

                bound_nif = norm_if_by_name.get(vpn_if_name)
                gw_entries.append(
                    _make_topology_entry(
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        asset=asset,
                        interface_name=vpn_if_name,
                        interface_ipv4=bound_nif.ipv4_address if bound_nif else None,
                        interface_mask_length=bound_nif.mask_length if bound_nif else None,
                        topology_zone="internal",
                        leads_to_dmz=bound_nif.leads_to_dmz if bound_nif else False,
                        anti_spoofing_mode=bound_nif.anti_spoofing_mode if bound_nif else "unknown",
                        source_type="vpn_domain",
                        source_ref=src_ref,
                        cidr_or_range=cidr_str,
                        ip_first_int=lo_int,
                        ip_last_int=hi_int,
                        prefix_len=plen,
                        installed_pol=installed_pol,
                        pkg_names=pkg_names,
                        now=now,
                    )
                )

    return gw_entries


async def _extract_domain_topology_entries(
    *,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    mgmt_name: str,
    domain_name: str,
    assets: Sequence[Asset],
    objects: Sequence[CPObject],
    target_gateway_uids: set[str] | None = None,
    allow_live_detail: bool = True,
    force_object_refresh: bool = False,
    trusted_object_domains: set[str] | None = None,
    already_detailed_uids: set[str] | None = None,
    global_cache: dict[str, list[CPObject]] | None = None,
    global_lock: asyncio.Lock | None = None,
    apply_overlay: bool = True,
    emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
) -> tuple[list[GatewayTopologyEntry], list[Asset]]:
    """Extract `GatewayTopologyEntry` rows for all policy-enforcing gateways in `(mgmt_name, domain_name)`."""
    entries: list[GatewayTopologyEntry] = []
    now = now_fn()

    policy_gateways = [
        a
        for a in assets
        if is_policy_enforcing_gateway(a) and (target_gateway_uids is None or a.uid in target_gateway_uids)
    ]
    total_gateways = len(policy_gateways)
    dom_snapshot = (
        await _load_domain_package_snapshot(
            cache, rulebase_refresh, mgmt_name, domain_name, allow_refresh=allow_live_detail
        )
        if policy_gateways
        else None
    )

    prepared_gateways, seed_object_refs, updated_assets = await _prepare_domain_gateways(
        api=api,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        policy_gateways=policy_gateways,
        objects=objects,
        allow_live_detail=allow_live_detail,
        force_object_refresh=force_object_refresh,
        trusted_object_domains=trusted_object_domains,
        already_detailed_uids=already_detailed_uids,
    )

    eff_objects: Sequence[CPObject] = objects
    if allow_live_detail and seed_object_refs:
        eff_objects = await _resolve_topology_objects_on_demand(
            api,
            cache,
            mgmt_name,
            domain_name,
            seed_refs=seed_object_refs,
            existing_objects=objects,
            force_refresh=force_object_refresh,
            trusted_object_domains=trusted_object_domains,
            global_cache=global_cache,
            global_lock=global_lock,
            apply_overlay=apply_overlay,
        )

    obj_by_uid, obj_by_name = _index_objects(eff_objects, domain_name=domain_name)

    for gw_idx, (asset, is_vs, raw_routes, norm_ifs) in enumerate(prepared_gateways, start=1):
        installed_pol, pkg_names, _ = await _resolve_gateway_policy_metadata(
            cache,
            rulebase_refresh,
            mgmt_name,
            domain_name,
            asset,
            asset.uid,
            asset.name,
            all_assets=assets,
            snapshot=dom_snapshot,
        )

        # Map connected subnets per interface so VS static routes can resolve next-hop IPs
        connected_by_if: dict[str, tuple[_NormalizedInterface, ipaddress.IPv4Network]] = {}
        for nif in norm_ifs:
            if nif.ipv4_address is not None and nif.mask_length is not None:
                try:
                    c_net = ipaddress.IPv4Network(f"{nif.ipv4_address}/{nif.mask_length}", strict=False)
                    connected_by_if[nif.interface_name] = (nif, c_net)
                except ValueError:
                    pass

        vs_route_entries: list[GatewayTopologyEntry] = []
        routed_if_names: set[str] = set()
        external_routed_if_names: set[str] = set()
        if is_vs and raw_routes:
            vs_route_entries, routed_if_names, external_routed_if_names = _extract_vs_static_route_entries(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                asset=asset,
                raw_routes=raw_routes,
                norm_ifs=norm_ifs,
                connected_by_if=connected_by_if,
                installed_pol=installed_pol,
                pkg_names=pkg_names,
                now=now,
            )

        gw_entries = _extract_interface_and_vpn_entries(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            asset=asset,
            norm_ifs=norm_ifs,
            connected_by_if=connected_by_if,
            routed_if_names=routed_if_names,
            external_routed_if_names=external_routed_if_names,
            vs_route_entries=vs_route_entries,
            obj_by_uid=obj_by_uid,
            obj_by_name=obj_by_name,
            installed_pol=installed_pol,
            pkg_names=pkg_names,
            now=now,
        )
        entries.extend(gw_entries)

        if emit is not None:
            pol_suffix = f" [policy: {installed_pol}]" if installed_pol else ""
            await emit(
                DomainSyncProgressEvent(
                    scope="topology",
                    mgmt_name=mgmt_name,
                    domain=domain_name,
                    item_type="gateway-topology",
                    processed=gw_idx,
                    total=total_gateways,
                    message=f"Processed gateway {asset.name} in {domain_name} ({gw_idx}/{total_gateways}){pol_suffix}",
                    details={
                        "gateway_uid": asset.uid,
                        "gateway_name": asset.name,
                        "gateway_type": asset.type,
                        "installed_access_policy": installed_pol,
                        "interval_count": len(gw_entries),
                    },
                )
            )

    return entries, updated_assets


async def _sync_domain_topology(
    *,
    api: ApiPort,
    cache: _TopologyServiceCachePort,
    coordinator: DomainSyncCoordinator,
    asset_service: AssetRefreshService,
    rulebase_refresh: RulebaseRefreshPort | None,
    now_fn: Callable[[], datetime],
    probe: DomainProbeResult,
    emit: Callable[[SyncProgressEvent], Awaitable[None]],
    global_cache: dict[str, list[CPObject]] | None = None,
    global_trusted_cache: dict[str, bool] | None = None,
    global_lock: asyncio.Lock | None = None,
    force_object_refresh: bool = False,
    cache_ttl: float | None = None,
) -> int:
    """Synchronize static topology intervals for a single probed domain."""
    mgmt_name = probe.mgmt_name
    dom_name = probe.domain.name

    domain_assets = await cache.get_assets(mgmt_name=mgmt_name, domain_name=dom_name)
    if not domain_assets:
        domain_assets = await asset_service.get_assets(
            mgmt_name=mgmt_name,
            domain=dom_name,
            cache_mode="smart",
        )

    all_objects = await _load_domain_scoped_objects(
        cache,
        mgmt_name,
        dom_name,
        global_cache=global_cache,
        global_lock=global_lock,
        apply_overlay=False,
    )
    trusted_domains = await _compute_trusted_object_domains(
        cache,
        coordinator,
        mgmt_name,
        dom_name,
        probe=probe,
        cache_ttl=cache_ttl,
        force_object_refresh=force_object_refresh,
        global_trusted_cache=global_trusted_cache,
        global_lock=global_lock,
    )

    entries, updated_assets = await _extract_domain_topology_entries(
        api=api,
        cache=cache,
        rulebase_refresh=rulebase_refresh,
        now_fn=now_fn,
        mgmt_name=mgmt_name,
        domain_name=dom_name,
        assets=domain_assets,
        objects=all_objects,
        force_object_refresh=force_object_refresh,
        trusted_object_domains=trusted_domains,
        global_cache=global_cache,
        global_lock=global_lock,
        apply_overlay=False,
        emit=emit,
    )
    if updated_assets:
        await cache.upsert_assets(updated_assets)

    await emit(
        DomainSyncProgressEvent(
            scope="topology",
            mgmt_name=mgmt_name,
            domain=dom_name,
            item_type="gateway-topology",
            processed=len(entries),
            total=len(entries),
            message=f"Extracted {len(entries)} topology interval(s) for {mgmt_name}:{dom_name}.",
        )
    )

    synced_at = probe.probe_started_at or now_fn()
    sync_state = DomainSyncState(
        mgmt_name=mgmt_name,
        domain_name=dom_name,
        scope="topology",
        item_type="*",
        last_published_at=probe.remote_published_at,
        last_session_uid=probe.remote_session_uid,
        synced_at=synced_at,
        status="ok",
        object_count=len(entries),
        last_error=None,
    )
    active_gw_uids = [a.uid for a in domain_assets if is_policy_enforcing_gateway(a)]
    return await cache.replace_domain_topology(
        mgmt_name,
        dom_name,
        entries,
        source_types=list(STATIC_TOPOLOGY_SOURCES),
        active_gateway_uids=active_gw_uids,
        sync_states=[sync_state],
    )
