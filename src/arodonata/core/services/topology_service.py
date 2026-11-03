"""Gateway interface topology extraction, caching, and affected gateway candidate matching (`TopologyService`).

Provides:
- Policy-enforcing gateway target filtering (`simple-gateway`, `simple-cluster` / `CpmiGatewayCluster`,
  and VSX Virtual Systems `virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj`), skipping cluster
  members, physical VSX hosts (`VS0`), and management servers.
- Multi-format Check Point interface normalization (`show-gateways-and-servers`, `show-simple-gateway`,
  `show-simple-cluster`, `show-generic-object`, and `CpmiVsSlotObj`) with on-demand detail fallback.
- Phase 1 static & API-based topology interval extraction:
  1. `"external_interface"` (`leads-to-internet: true` or `topology == "external"` -> `0.0.0.0/0`).
  2. `"interface_connected"` (`"network defined by the interface ip and net mask"`).
  3. `"interface_specific"` (`"specific"` network/group recursively expanded via `arodonata_objects`
     with `"Global"` fallback and cycle protection).
  4. `"vs_static_route"` (VSX Virtual System static routes mapped to VS interfaces by explicit interface
     name or next-hop IP containment in connected VS subnets, including `0.0.0.0/0` external marking).
- `find_affected_gateways(sources, destinations, ...)`: resolves IPv4 addresses, CIDRs, ranges, or
  object/group names against gateway topology intervals (longest-prefix internal match first, external
  fallback second), excludes any gateway where source and destination resolve to the same interface
  (`src_interface == dst_interface`), and enriches candidates with domain, policy package, and access
  layer metadata.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import arlogi

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import DEFAULT_OBJECT_TYPES, CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.models.topology import (
    AffectedGatewayCandidate,
    FlowMatchType,
    GatewayInterfaceSummary,
    GatewayTopologyEntry,
    TopologySourceType,
    TopologyZone,
    TrafficFlowMatch,
)
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.asset_service import (
    VSX_CHILD_TYPES,
    AssetRefreshService,
    _extract_interfaces_from_generic,
)
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.search_service import classify_search_term
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced
from arodonata.rulebase.numbering import extract_policy_packages

logger = arlogi.get_logger(__name__)

MAX_IPV4_INT = 4294967295

POLICY_GATEWAY_TYPES: frozenset[str] = frozenset(
    {
        "simple-gateway",
        "gateway",
        "CpmiGatewayPlain",
        "CpmiHostCkp",
        "simple-cluster",
        "cluster",
        "CpmiGatewayCluster",
        "virtual-system",
        "vs-netobj",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    }
)

EXCLUDED_GATEWAY_TYPES: frozenset[str] = frozenset(
    {
        "cluster-member",
        "vsx-cluster-member",
        "CpmiClusterMember",
        "CpmiVsxClusterMember",
        "vsx-gateway",
        "vsx-cluster",
        "CpmiVsxNetobj",
        "CpmiVsxClusterNetobj",
        "checkpoint-host",
        "mds",
        "interoperable-device",
    }
)


def is_policy_enforcing_gateway(asset: Asset) -> bool:
    """Return `True` if `asset` is a policy-enforcing gateway, cluster, or VSX Virtual System."""
    a_type = asset.type.strip()
    if a_type in EXCLUDED_GATEWAY_TYPES:
        return False
    if a_type == "CpmiHostCkp":
        # CpmiHostCkp is used for management hosts unless the firewall blade is explicitly enabled
        return asset.network_security_blades.get("firewall") is True
    if a_type in POLICY_GATEWAY_TYPES:
        return True
    lower_type = a_type.lower()
    if "member" in lower_type or "vsx" in lower_type or "checkpoint-host" in lower_type:
        return False
    return "gateway" in lower_type or "cluster" in lower_type or "virtual-system" in lower_type


def _mask_to_prefix_len(mask_val: str | int | None) -> int | None:
    """Convert a netmask string (`255.255.255.0`) or integer prefix length (`24`) to `0..32`."""
    if mask_val is None or mask_val == "":
        return None
    if isinstance(mask_val, int):
        return mask_val if 0 <= mask_val <= 32 else None
    clean = str(mask_val).strip()
    if not clean:
        return None
    if clean.isdigit():
        plen = int(clean)
        return plen if 0 <= plen <= 32 else None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{clean}", strict=False).prefixlen
    except ValueError:
        return None


def _effective_range_prefix_len(ip_first_int: int, ip_last_int: int) -> int:
    """Compute an effective specificity (`0..32`) from an IPv4 integer interval span."""
    span = max(0, ip_last_int - ip_first_int)
    if span == 0:
        return 32
    bits = span.bit_length()
    return max(0, 32 - bits)


@dataclass(frozen=True)
class _NormalizedInterface:
    """Internal normalized representation of a gateway/cluster/VS network interface."""

    interface_name: str
    ipv4_address: str | None
    mask_length: int | None
    is_external: bool
    leads_to_dmz: bool
    behind_mode: str
    specific_network_ref: str | None
    specific_network_uid: str | None
    has_explicit_topology: bool


@dataclass(frozen=True)
class _ResolvedEndpointInterval:
    """Resolved query IPv4 interval derived from a caller-supplied source or destination string."""

    query_raw: str
    cidr_or_range: str
    ip_first_int: int
    ip_last_int: int


@dataclass(frozen=True)
class _InterfaceMatch:
    """Resolution of a single query interval onto a gateway interface."""

    interface_name: str
    topology_zone: TopologyZone
    matched_cidr: str
    source_type: str
    source_ref: str


def _normalize_interface(raw_if: dict[str, Any], *, is_vs_asset: bool = False) -> _NormalizedInterface | None:
    """Normalize a Check Point interface dictionary across `show-gateways-and-servers`, `show-simple-*`, and CPMI formats."""
    owned = raw_if.get("owned-object") or raw_if.get("owned_object")
    if isinstance(owned, dict):
        merged = dict(raw_if)
        merged.update(owned)
        raw_if = merged

    if_name = str(
        raw_if.get("interface-name")
        or raw_if.get("interface_name")
        or raw_if.get("name")
        or raw_if.get("officialname")
        or raw_if.get("OfficialName")
        or raw_if.get("iffullname")
        or ""
    ).strip()
    if not if_name:
        return None

    ipv4_raw = (
        raw_if.get("ipv4-address") or raw_if.get("ipv4_address") or raw_if.get("ipaddr") or raw_if.get("ip-address")
    )
    ipv4_address: str | None = None
    if ipv4_raw and str(ipv4_raw).strip():
        candidate_ip = str(ipv4_raw).strip()
        try:
            ipaddress.IPv4Address(candidate_ip)
            ipv4_address = candidate_ip
        except ValueError:
            ipv4_address = None

    mask_len = _mask_to_prefix_len(
        raw_if.get("ipv4-mask-length")
        or raw_if.get("ipv4_mask_length")
        or raw_if.get("mask-length")
        or raw_if.get("ipv4-network-mask")
        or raw_if.get("ipv4_network_mask")
        or raw_if.get("netmask")
        or raw_if.get("subnet-mask")
    )

    is_external = False
    leads_to_dmz = False
    behind_mode = ""
    specific_ref: str | None = None
    specific_uid: str | None = None
    has_explicit_topology = False

    topo_field = raw_if.get("topology")
    topo_settings = (
        raw_if.get("topology-settings")
        or raw_if.get("topology_settings")
        or raw_if.get("topology-settings-automatic")
        or raw_if.get("antiSpoofing")
        or raw_if.get("anti-spoofing")
    )

    if isinstance(topo_field, dict):
        has_explicit_topology = True
        if bool(topo_field.get("leads-to-internet") or topo_field.get("leads_to_internet")):
            is_external = True
        leads_to_dmz = bool(
            topo_field.get("leads-to-dmz") or topo_field.get("leads_to_dmz") or topo_field.get("interface-leads-to-dmz")
        )
        behind_mode = str(
            topo_field.get("ip-address-behind-this-interface")
            or topo_field.get("ip_address_behind_this_interface")
            or ""
        ).strip()
        spec_val = (
            topo_field.get("specific-network") or topo_field.get("specific_network") or topo_field.get("specificGroup")
        )
        if isinstance(spec_val, dict):
            specific_uid = str(spec_val.get("uid") or "") or None
            specific_ref = str(spec_val.get("name") or spec_val.get("uid") or "") or None
        elif isinstance(spec_val, str) and spec_val.strip():
            specific_ref = spec_val.strip()
        spec_uid_val = topo_field.get("specific-network-uid") or topo_field.get("specific_network_uid")
        if isinstance(spec_uid_val, str) and spec_uid_val.strip():
            specific_uid = spec_uid_val.strip()
    elif isinstance(topo_field, str) and topo_field.strip():
        has_explicit_topology = True
        t_clean = topo_field.strip().lower()
        if t_clean == "automatic":
            auto_calc = (
                str(raw_if.get("topology-automatic-calculation") or raw_if.get("topology_automatic_calculation") or "")
                .strip()
                .lower()
            )
            if auto_calc == "external":
                is_external = True
        elif t_clean == "external":
            is_external = True

    if isinstance(topo_settings, dict):
        has_explicit_topology = True
        if bool(topo_settings.get("leads-to-internet") or topo_settings.get("leads_to_internet")):
            is_external = True
        if bool(
            topo_settings.get("interface-leads-to-dmz")
            or topo_settings.get("leads-to-dmz")
            or topo_settings.get("leads_to_dmz")
        ):
            leads_to_dmz = True
        if not behind_mode:
            behind_mode = str(
                topo_settings.get("ip-address-behind-this-interface")
                or topo_settings.get("ip_address_behind_this_interface")
                or topo_settings.get("netaccess")
                or ""
            ).strip()
        spec_val2 = (
            topo_settings.get("specific-network")
            or topo_settings.get("specific_network")
            or topo_settings.get("specificGroup")
        )
        if isinstance(spec_val2, dict):
            specific_uid = specific_uid or str(spec_val2.get("uid") or "") or None
            specific_ref = specific_ref or str(spec_val2.get("name") or spec_val2.get("uid") or "") or None
        elif isinstance(spec_val2, str) and spec_val2.strip() and not specific_ref:
            specific_ref = spec_val2.strip()
        spec_uid2 = topo_settings.get("specific-network-uid") or topo_settings.get("specific_network_uid")
        if isinstance(spec_uid2, str) and spec_uid2.strip() and not specific_uid:
            specific_uid = spec_uid2.strip()

    # For CPMI / VSX Virtual System interfaces that provide ipaddr + netmask without an explicit
    # `topology` block, default `behind_mode` to the connected interface IP/netmask.
    if (
        not is_external
        and not behind_mode
        and ipv4_address is not None
        and mask_len is not None
        and (is_vs_asset or not has_explicit_topology)
    ):
        behind_mode = "network defined by the interface ip and net mask"

    return _NormalizedInterface(
        interface_name=if_name,
        ipv4_address=ipv4_address,
        mask_length=mask_len,
        is_external=is_external,
        leads_to_dmz=leads_to_dmz,
        behind_mode=behind_mode,
        specific_network_ref=specific_ref,
        specific_network_uid=specific_uid,
        has_explicit_topology=has_explicit_topology,
    )


def _extract_raw_routes(raw_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract static route dictionaries from `routes`, `routes_installed`, or `routing_table`."""
    for key in ("routes", "routes_installed", "routing_table", "static-routes", "static_routes"):
        val = raw_data.get(key)
        if isinstance(val, dict) and isinstance(val.get("objects"), list):
            val = val["objects"]
        if isinstance(val, list):
            routes: list[dict[str, Any]] = []
            for item in val:
                if isinstance(item, dict):
                    owned = item.get("owned-object") or item.get("owned_object")
                    if isinstance(owned, dict):
                        merged = dict(item)
                        merged.update(owned)
                        routes.append(merged)
                    else:
                        routes.append(item)
            if routes:
                return routes
    return []


def _parse_route_destination(route: dict[str, Any]) -> ipaddress.IPv4Network | None:
    """Parse a static route destination into an `IPv4Network` (including `0.0.0.0/0` default routes)."""
    dest_raw = (
        route.get("dest")
        or route.get("destination")
        or route.get("subnet")
        or route.get("address")
        or route.get("network")
    )
    if dest_raw is None:
        if route.get("type") == "default" or route.get("default") is True:
            return ipaddress.IPv4Network("0.0.0.0/0")
        return None

    dest_str = str(dest_raw).strip()
    if not dest_str or dest_str.lower() == "default" or dest_str == "0.0.0.0/0":
        return ipaddress.IPv4Network("0.0.0.0/0")

    if "/" in dest_str:
        try:
            return ipaddress.IPv4Network(dest_str, strict=False)
        except ValueError:
            return None

    mask_val = (
        route.get("mask")
        or route.get("netmask")
        or route.get("subnet-mask")
        or route.get("mask-length")
        or route.get("mask_length")
        or route.get("prefix-length")
    )
    if mask_val is None and dest_str == "0.0.0.0":
        return ipaddress.IPv4Network("0.0.0.0/0")

    plen = _mask_to_prefix_len(mask_val)
    if plen is None:
        plen = 0 if dest_str == "0.0.0.0" else 32
    try:
        return ipaddress.IPv4Network(f"{dest_str}/{plen}", strict=False)
    except ValueError:
        return None


def _parse_route_nexthop_and_interface(route: dict[str, Any]) -> tuple[ipaddress.IPv4Address | None, str | None]:
    """Return `(nexthop_ipv4_or_None, explicit_interface_name_or_None)` from a static route dictionary."""
    if_raw = (
        route.get("interface")
        or route.get("ifname")
        or route.get("interface-name")
        or route.get("interface_name")
        or route.get("dev")
    )
    explicit_if: str | None = None
    if isinstance(if_raw, dict):
        explicit_if = str(if_raw.get("name") or if_raw.get("officialname") or "").strip() or None
    elif isinstance(if_raw, str) and if_raw.strip():
        explicit_if = if_raw.strip()

    nh_raw = (
        route.get("nexthop")
        or route.get("next-hop")
        or route.get("next_hop")
        or route.get("gateway")
        or route.get("via")
    )
    # Check nested next-hop gateway list if formatted like Gaia / CPMI next-hop object
    if nh_raw is None and isinstance(route.get("next-hop"), list) and route["next-hop"]:
        nh_raw = route["next-hop"][0]

    nh_str = ""
    if isinstance(nh_raw, dict):
        nh_str = str(
            nh_raw.get("ipv4-address")
            or nh_raw.get("ipaddr")
            or nh_raw.get("address")
            or nh_raw.get("gateway")
            or nh_raw.get("name")
            or ""
        ).strip()
        if not explicit_if:
            nh_if = nh_raw.get("interface") or nh_raw.get("interface-name")
            if isinstance(nh_if, str) and nh_if.strip():
                explicit_if = nh_if.strip()
    elif isinstance(nh_raw, str):
        nh_str = nh_raw.strip()

    nh_ip: ipaddress.IPv4Address | None = None
    if nh_str:
        try:
            nh_ip = ipaddress.IPv4Address(nh_str)
        except ValueError:
            nh_ip = None

    return nh_ip, explicit_if


class TopologyService:
    """Extracts, caches, and matches gateway interface topology across domains."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        coordinator: DomainSyncCoordinator,
        asset_service: AssetRefreshService,
        object_service: ObjectService,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._asset_service = asset_service
        self._object_service = object_service
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    async def stream_refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing gateway topology across domains."""
        if mode != "cache":
            await self._asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            )
            await self._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=domains,
                types=list(DEFAULT_OBJECT_TYPES),
                include_global=True,
                mode=mode,
                cache_ttl=cache_ttl,
            )

        async for event in self._coordinator.stream_ensure(
            scope="topology",
            item_types=["*"],
            handler=self._sync_domain_topology,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    @traced
    async def refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh gateway topology across domains and return `RefreshOutcome`."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        if mode != "cache":
            await self._asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            )
            await self._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=domains,
                types=list(DEFAULT_OBJECT_TYPES),
                include_global=True,
                mode=mode,
                cache_ttl=cache_ttl,
            )

        return await self._coordinator.ensure(
            scope="topology",
            item_types=["*"],
            handler=self._sync_domain_topology,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def _sync_domain_topology(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name

        domain_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=dom_name)
        if not domain_assets:
            domain_assets = await self._asset_service.get_assets(
                mgmt_name=mgmt_name,
                domain=dom_name,
                cache_mode="smart",
            )

        domain_objects = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=dom_name)
        global_objects = (
            await self._cache.get_objects(mgmt_name=mgmt_name, domain_name="Global") if dom_name != "Global" else []
        )
        all_objects = ObjectService.apply_context_overlay(
            [*domain_objects, *global_objects],
            mgmt_name=mgmt_name,
            domain_name=dom_name,
        )

        entries, updated_assets = await self._extract_domain_topology_entries(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            assets=domain_assets,
            objects=all_objects,
        )
        if updated_assets:
            await self._cache.upsert_assets(updated_assets)

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

        now = self._now()
        sync_state = DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope="topology",
            item_type="*",
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=now,
            status="ok",
            object_count=len(entries),
            last_error=None,
        )
        return await self._cache.replace_domain_topology(
            mgmt_name,
            dom_name,
            entries,
            sync_states=[sync_state],
        )

    async def _fetch_asset_detail_on_demand(
        self,
        mgmt_name: str,
        domain_name: str,
        asset: Asset,
    ) -> Asset | None:
        """Query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` when summary lacks interfaces."""
        a_type = asset.type
        commands: list[str] = []
        if a_type in ("simple-cluster", "cluster", "CpmiGatewayCluster"):
            commands = ["show-simple-cluster", "show-generic-object"]
        elif a_type in ("simple-gateway", "gateway", "CpmiGatewayPlain", "CpmiHostCkp"):
            commands = ["show-simple-gateway", "show-generic-object"]
        else:
            commands = ["show-generic-object"]

        for cmd in commands:
            try:
                res = await self._api.api_call(
                    mgmt_name,
                    cmd,
                    {"uid": asset.uid, "details-level": "full"},
                    domain=domain_name,
                )
            except ServerIdentityError:
                raise
            except Exception:
                continue

            if not res.success or not isinstance(res.data, dict) or not res.data:
                continue

            detail_ifs = _extract_interfaces_from_generic(res.data)
            detail_routes = _extract_raw_routes(res.data)
            if not detail_ifs and not detail_routes:
                continue

            merged_raw = dict(asset.raw_data)
            merged_raw.update(res.data)
            new_ifs = detail_ifs if detail_ifs else list(asset.interfaces)
            if detail_ifs:
                merged_raw["interfaces"] = detail_ifs
            return asset.model_copy(update={"interfaces": new_ifs, "raw_data": merged_raw})

        return None

    async def _extract_domain_topology_entries(
        self,
        *,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
        objects: Sequence[CPObject],
        allow_live_detail: bool = True,
    ) -> tuple[list[GatewayTopologyEntry], list[Asset]]:
        """Extract `GatewayTopologyEntry` rows for all policy-enforcing gateways in `(mgmt_name, domain_name)`."""
        obj_by_uid, obj_by_name = self._index_objects(objects, domain_name=domain_name)
        entries: list[GatewayTopologyEntry] = []
        updated_assets: list[Asset] = []
        now = self._now()

        for asset in assets:
            if not is_policy_enforcing_gateway(asset):
                continue

            is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
            raw_ifs = list(asset.interfaces) or _extract_interfaces_from_generic(asset.raw_data)
            raw_routes = _extract_raw_routes(asset.raw_data)

            # Check if we need an on-demand detail call (missing interfaces or missing explicit topology on non-VS)
            needs_detail = allow_live_detail and (
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
            if needs_detail:
                enriched = await self._fetch_asset_detail_on_demand(mgmt_name, domain_name, asset)
                if enriched is not None:
                    asset = enriched
                    updated_assets.append(asset)
                    raw_ifs = list(asset.interfaces) or _extract_interfaces_from_generic(asset.raw_data)
                    raw_routes = _extract_raw_routes(asset.raw_data)

            norm_ifs: list[_NormalizedInterface] = []
            for raw_if in raw_ifs:
                if isinstance(raw_if, dict):
                    norm = _normalize_interface(raw_if, is_vs_asset=is_vs)
                    if norm is not None:
                        norm_ifs.append(norm)

            # Map connected subnets per interface so VS static routes can resolve next-hop IPs
            connected_by_if: dict[str, tuple[_NormalizedInterface, ipaddress.IPv4Network]] = {}
            for nif in norm_ifs:
                if nif.ipv4_address is not None and nif.mask_length is not None:
                    try:
                        c_net = ipaddress.IPv4Network(f"{nif.ipv4_address}/{nif.mask_length}", strict=False)
                        connected_by_if[nif.interface_name] = (nif, c_net)
                    except ValueError:
                        pass

            # Track which interfaces receive VS static routes (and whether a 0.0.0.0/0 route marks them external)
            routed_if_names: set[str] = set()
            external_routed_if_names: set[str] = set()
            vs_route_entries: list[GatewayTopologyEntry] = []

            if is_vs and raw_routes:
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
                    if dest_net.prefixlen == 0 and int(dest_net.network_address) == 0:
                        external_routed_if_names.add(target_if_name)
                        vs_route_entries.append(
                            GatewayTopologyEntry(
                                mgmt_name=mgmt_name,
                                domain_name=domain_name,
                                gateway_uid=asset.uid,
                                gateway_name=asset.name,
                                gateway_type=asset.type,
                                interface_name=target_if_name,
                                interface_ipv4=target_nif.ipv4_address if target_nif else None,
                                interface_mask_length=target_nif.mask_length if target_nif else None,
                                topology_zone="external",
                                leads_to_dmz=target_nif.leads_to_dmz if target_nif else False,
                                source_type="vs_static_route",
                                source_ref=nh_ref,
                                cidr_or_range="0.0.0.0/0",
                                ip_first_int=0,
                                ip_last_int=MAX_IPV4_INT,
                                prefix_len=0,
                                updated_at=now,
                            )
                        )
                    else:
                        vs_route_entries.append(
                            GatewayTopologyEntry(
                                mgmt_name=mgmt_name,
                                domain_name=domain_name,
                                gateway_uid=asset.uid,
                                gateway_name=asset.name,
                                gateway_type=asset.type,
                                interface_name=target_if_name,
                                interface_ipv4=target_nif.ipv4_address if target_nif else None,
                                interface_mask_length=target_nif.mask_length if target_nif else None,
                                topology_zone="internal",
                                leads_to_dmz=target_nif.leads_to_dmz if target_nif else False,
                                source_type="vs_static_route",
                                source_ref=nh_ref,
                                cidr_or_range=str(dest_net),
                                ip_first_int=int(dest_net.network_address),
                                ip_last_int=int(dest_net.broadcast_address),
                                prefix_len=dest_net.prefixlen,
                                updated_at=now,
                            )
                        )

            for nif in norm_ifs:
                if nif.is_external:
                    entries.append(
                        GatewayTopologyEntry(
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            gateway_uid=asset.uid,
                            gateway_name=asset.name,
                            gateway_type=asset.type,
                            interface_name=nif.interface_name,
                            interface_ipv4=nif.ipv4_address,
                            interface_mask_length=nif.mask_length,
                            topology_zone="external",
                            leads_to_dmz=nif.leads_to_dmz,
                            source_type="external_interface",
                            source_ref="leads-to-internet",
                            cidr_or_range="0.0.0.0/0",
                            ip_first_int=0,
                            ip_last_int=MAX_IPV4_INT,
                            prefix_len=0,
                            updated_at=now,
                        )
                    )
                    continue

                mode_lower = nif.behind_mode.lower()
                if "specific" in mode_lower:
                    expanded = self._expand_specific_reference(
                        ref_uid=nif.specific_network_uid,
                        ref_name=nif.specific_network_ref,
                        obj_by_uid=obj_by_uid,
                        obj_by_name=obj_by_name,
                    )
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
                        entries.append(
                            GatewayTopologyEntry(
                                mgmt_name=mgmt_name,
                                domain_name=domain_name,
                                gateway_uid=asset.uid,
                                gateway_name=asset.name,
                                gateway_type=asset.type,
                                interface_name=nif.interface_name,
                                interface_ipv4=nif.ipv4_address,
                                interface_mask_length=nif.mask_length,
                                topology_zone="internal",
                                leads_to_dmz=nif.leads_to_dmz,
                                source_type="interface_specific",
                                source_ref=src_ref,
                                cidr_or_range=cidr_str,
                                ip_first_int=lo_int,
                                ip_last_int=hi_int,
                                prefix_len=plen,
                                updated_at=now,
                            )
                        )
                elif "interface ip and net mask" in mode_lower or mode_lower == "connected":
                    # If this VS interface was marked external via a 0.0.0.0/0 default route,
                    # still record its connected subnet unless it is purely an external warp link.
                    if nif.interface_name in connected_by_if:
                        _, c_net = connected_by_if[nif.interface_name]
                        entries.append(
                            GatewayTopologyEntry(
                                mgmt_name=mgmt_name,
                                domain_name=domain_name,
                                gateway_uid=asset.uid,
                                gateway_name=asset.name,
                                gateway_type=asset.type,
                                interface_name=nif.interface_name,
                                interface_ipv4=nif.ipv4_address,
                                interface_mask_length=nif.mask_length,
                                topology_zone="internal",
                                leads_to_dmz=nif.leads_to_dmz,
                                source_type="interface_connected",
                                source_ref="connected",
                                cidr_or_range=str(c_net),
                                ip_first_int=int(c_net.network_address),
                                ip_last_int=int(c_net.broadcast_address),
                                prefix_len=c_net.prefixlen,
                                updated_at=now,
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

            entries.extend(vs_route_entries)

        return entries, updated_assets

    @staticmethod
    def _index_objects(
        objects: Sequence[CPObject],
        *,
        domain_name: str | None = None,
    ) -> tuple[dict[str, CPObject], dict[str, CPObject]]:
        """Index `CPObject` records by `uid` and `name`, restricted to `domain_name` and `"Global"` (local winning over Global)."""
        by_uid: dict[str, CPObject] = {}
        by_name: dict[str, CPObject] = {}
        scoped = (
            [o for o in objects if o.domain_name in (domain_name, "Global")]
            if domain_name is not None
            else list(objects)
        )
        # Insert Global first, then domain_name last so local objects win on name collisions
        sorted_objs = sorted(
            scoped,
            key=lambda o: 1 if (domain_name and o.domain_name == domain_name) else 0,
        )
        for obj in sorted_objs:
            by_uid[obj.uid] = obj
            by_name[obj.name] = obj
            by_name[obj.object_id] = obj
            by_name[obj.id] = obj
        return by_uid, by_name

    def _expand_specific_reference(
        self,
        *,
        ref_uid: str | None,
        ref_name: str | None,
        obj_by_uid: dict[str, CPObject],
        obj_by_name: dict[str, CPObject],
    ) -> list[tuple[str, int, int, int, str]]:
        """Recursively expand a Check Point network object or group into `(cidr_or_range, lo, hi, prefix_len, source_ref)` tuples."""
        root_obj: CPObject | None = None
        if ref_uid and ref_uid in obj_by_uid:
            root_obj = obj_by_uid[ref_uid]
        elif ref_name and ref_name in obj_by_name:
            root_obj = obj_by_name[ref_name]
        elif ref_uid and ref_uid in obj_by_name:
            root_obj = obj_by_name[ref_uid]

        if root_obj is None:
            return []

        return self._expand_cp_object(root_obj, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name)

    @staticmethod
    def _expand_cp_object(
        root_obj: CPObject,
        *,
        obj_by_uid: dict[str, CPObject],
        obj_by_name: dict[str, CPObject],
    ) -> list[tuple[str, int, int, int, str]]:
        """Cycle-safe BFS expansion of a `CPObject` (`host`, `network`, `address-range`, or nested `group`)."""
        results: list[tuple[str, int, int, int, str]] = []
        seen_intervals: set[str] = set()
        visited_uids: set[str] = set()
        queue: deque[CPObject] = deque([root_obj])
        root_ref = root_obj.name

        while queue:
            curr = queue.popleft()
            if curr.uid in visited_uids:
                continue
            visited_uids.add(curr.uid)

            if curr.ipv4_address:
                try:
                    ip_obj = ipaddress.IPv4Address(curr.ipv4_address.strip())
                    ip_int = int(ip_obj)
                    cidr_str = f"{ip_obj}/32"
                    if cidr_str not in seen_intervals:
                        seen_intervals.add(cidr_str)
                        results.append((cidr_str, ip_int, ip_int, 32, root_ref))
                except ValueError:
                    pass
            elif curr.subnet4:
                plen = _mask_to_prefix_len(curr.mask_length4 if curr.mask_length4 is not None else curr.subnet_mask)
                if plen is not None:
                    try:
                        net = ipaddress.IPv4Network(f"{curr.subnet4.strip()}/{plen}", strict=False)
                        cidr_str = str(net)
                        if cidr_str not in seen_intervals:
                            seen_intervals.add(cidr_str)
                            results.append(
                                (
                                    cidr_str,
                                    int(net.network_address),
                                    int(net.broadcast_address),
                                    net.prefixlen,
                                    root_ref,
                                )
                            )
                    except ValueError:
                        pass
            elif curr.ipv4_address_first and curr.ipv4_address_last:
                try:
                    ip1 = ipaddress.IPv4Address(curr.ipv4_address_first.strip())
                    ip2 = ipaddress.IPv4Address(curr.ipv4_address_last.strip())
                    lo = min(int(ip1), int(ip2))
                    hi = max(int(ip1), int(ip2))
                    range_str = f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}"
                    if range_str not in seen_intervals:
                        seen_intervals.add(range_str)
                        results.append((range_str, lo, hi, _effective_range_prefix_len(lo, hi), root_ref))
                except ValueError:
                    pass

            if curr.members:
                for m_ref in curr.members:
                    child = obj_by_uid.get(m_ref) or obj_by_name.get(m_ref)
                    if child is not None and child.uid not in visited_uids:
                        queue.append(child)

        return results

    @traced
    async def get_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        topology_zone: TopologyZone | None = None,
        source_types: Sequence[TopologySourceType | str] | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[GatewayTopologyEntry]:
        """Ensure topology is synchronized (unless `cache_mode="cache"`) and return cached `GatewayTopologyEntry` rows."""
        span_attrs(mgmt_name=mgmt_name, domain=domain, gateway=gateway, cache_mode=cache_mode)
        if cache_mode != "cache":
            await self.refresh_topology(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                include_global=domain == "Global",
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        entries = await self._cache.get_gateway_topology(
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
        return entries

    @staticmethod
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
                    source_types=src_types,
                    cidrs_and_ranges=cidrs,
                )
            )
        return summaries

    def _resolve_endpoint_intervals(
        self,
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
                target_obj = obj_by_uid.get(term.raw) or obj_by_name.get(term.raw)
                if target_obj is None:
                    # Case-insensitive lookup fallback
                    lower_raw = term.raw.lower()
                    for k, candidate in obj_by_name.items():
                        if k.lower() == lower_raw:
                            target_obj = candidate
                            break
                if target_obj is not None:
                    expanded = self._expand_cp_object(
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

    @staticmethod
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

    @classmethod
    def _locate_intervals_on_gateway(
        cls,
        endpoint: _ResolvedEndpointInterval,
        gw_entries: Sequence[GatewayTopologyEntry],
        external_if_names: set[str],
    ) -> list[_InterfaceMatch]:
        """Resolve `endpoint` to all matching gateway interfaces (longest-prefix internal match when contained, or all overlapping internal + external fallback when partially covered)."""
        q_lo = endpoint.ip_first_int
        q_hi = endpoint.ip_last_int

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
        # Select the single most specific (longest-prefix / smallest-span) containing internal entry.
        if containing_internal:
            best = min(
                containing_internal,
                key=lambda e: (
                    1 if e.interface_name in external_if_names else 0,
                    (e.ip_last_int - e.ip_first_int),
                    -e.prefix_len,
                    e.interface_name,
                    e.cidr_or_range,
                ),
            )
            return [
                _InterfaceMatch(
                    interface_name=best.interface_name,
                    topology_zone="internal",
                    matched_cidr=best.cidr_or_range,
                    source_type=best.source_type,
                    source_ref=best.source_ref,
                )
            ]

        # Case 2: The query interval is broader than any single internal entry (e.g. `10.0.0.0/8` or `0.0.0.0/0`).
        # Collect the best overlapping entry per internal interface, and also include the external fallback
        # if the union of overlapping internal intervals does not completely cover `[q_lo, q_hi]`.
        matches: list[_InterfaceMatch] = []
        if overlapping_internal:
            by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
            for entry in overlapping_internal:
                by_if[entry.interface_name].append(entry)
            for if_name in sorted(by_if):
                best_if_entry = min(
                    by_if[if_name],
                    key=lambda e: (
                        (e.ip_last_int - e.ip_first_int),
                        -e.prefix_len,
                        e.cidr_or_range,
                    ),
                )
                matches.append(
                    _InterfaceMatch(
                        interface_name=best_if_entry.interface_name,
                        topology_zone="internal",
                        matched_cidr=best_if_entry.cidr_or_range,
                        source_type=best_if_entry.source_type,
                        source_ref=best_if_entry.source_ref,
                    )
                )

        fully_covered_internally = bool(overlapping_internal) and cls._is_range_covered_by_intervals(
            q_lo,
            q_hi,
            [(e.ip_first_int, e.ip_last_int) for e in overlapping_internal],
        )
        if not fully_covered_internally:
            external_entries = [e for e in gw_entries if e.topology_zone == "external"]
            if external_entries:
                ext = external_entries[0]
                if not any(m.interface_name == ext.interface_name for m in matches):
                    matches.append(
                        _InterfaceMatch(
                            interface_name=ext.interface_name,
                            topology_zone="external",
                            matched_cidr=ext.cidr_or_range or "0.0.0.0/0",
                            source_type="external_fallback",
                            source_ref=ext.source_ref or ext.source_type,
                        )
                    )

        return matches

    async def _resolve_gateway_policy_metadata(
        self,
        mgmt_name: str,
        domain_name: str,
        asset: Asset | None,
        gateway_uid: str,
        gateway_name: str,
    ) -> tuple[str | None, list[str], list[str]]:
        """Resolve `(installed_access_policy, policy_packages, access_layers)` for a candidate gateway."""
        installed_policy: str | None = None
        if asset is not None:
            raw_pol = asset.raw_data.get("policy")
            if isinstance(raw_pol, dict):
                pol_name = raw_pol.get("access-policy-name") or raw_pol.get("access_policy_name")
                if isinstance(pol_name, str) and pol_name.strip():
                    installed_policy = pol_name.strip()
            elif isinstance(raw_pol, str) and raw_pol.strip():
                installed_policy = raw_pol.strip()
            if not installed_policy:
                alt_pol = asset.raw_data.get("access-policy-name") or asset.raw_data.get("access_policy_name")
                if isinstance(alt_pol, str) and alt_pol.strip():
                    installed_policy = alt_pol.strip()

        policy_packages: list[str] = []
        access_layers: list[str] = []
        if installed_policy:
            policy_packages.append(installed_policy)

        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain_name)
        if snapshot.package_layers or snapshot.nat_rules:
            packages = extract_policy_packages(snapshot)
            gw_tokens = {gateway_uid.lower(), gateway_name.lower()}
            if asset is not None:
                gw_tokens.add(asset.id.lower())
                gw_tokens.add(asset.asset_id.lower())

            matched_pkgs = []
            for pkg in packages:
                if installed_policy and pkg.name.lower() == installed_policy.lower():
                    matched_pkgs.append(pkg)
                    continue
                targets = pkg.raw_data.get("installation-targets") or pkg.raw_data.get("installation_targets")
                if isinstance(targets, str) and targets.strip().lower() == "all":
                    matched_pkgs.append(pkg)
                elif isinstance(targets, list):
                    for t in targets:
                        if isinstance(t, str) and t.strip().lower() in gw_tokens:
                            matched_pkgs.append(pkg)
                            break
                        if isinstance(t, dict):
                            t_uid = str(t.get("uid") or "").lower()
                            t_name = str(t.get("name") or "").lower()
                            if (t_uid and t_uid in gw_tokens) or (t_name and t_name in gw_tokens):
                                matched_pkgs.append(pkg)
                                break

            if not matched_pkgs and len(packages) == 1:
                matched_pkgs = [packages[0]]

            for pkg in matched_pkgs:
                if pkg.name not in policy_packages:
                    policy_packages.append(pkg.name)
                if installed_policy is None:
                    installed_policy = pkg.name
                for layer_entry in pkg.access_layers:
                    if layer_entry.layer_name not in access_layers:
                        access_layers.append(layer_entry.layer_name)

        return installed_policy, policy_packages, access_layers

    @traced
    async def find_affected_gateways(
        self,
        sources: Sequence[str] | str,
        destinations: Sequence[str] | str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[AffectedGatewayCandidate]:
        """Locate all policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces (`src_interface != dst_interface`)."""
        src_list = (
            [s.strip() for s in sources.split(",") if s.strip()]
            if isinstance(sources, str)
            else [str(s).strip() for s in sources if str(s).strip()]
        )
        dst_list = (
            [d.strip() for d in destinations.split(",") if d.strip()]
            if isinstance(destinations, str)
            else [str(d).strip() for d in destinations if str(d).strip()]
        )
        if not src_list:
            raise ValidationError("sources must contain at least one IPv4 address, subnet, range, or object name")
        if not dst_list:
            raise ValidationError("destinations must contain at least one IPv4 address, subnet, range, or object name")

        span_attrs(
            mgmt_name=mgmt_name,
            domain=domain,
            source_count=len(src_list),
            destination_count=len(dst_list),
            cache_mode=cache_mode,
        )

        if cache_mode != "cache":
            await self.refresh_topology(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                include_global=domain == "Global",
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        topo_entries = await self._cache.get_gateway_topology(
            mgmt_name=mgmt_name,
            domain_name=domain,
        )
        all_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
        all_objects = await self._cache.get_objects(mgmt_name=mgmt_name)
        all_objects = ObjectService.apply_context_overlay(all_objects, mgmt_name=mgmt_name, domain_name=domain)

        # Fallback: if cache_mode="cache" was used on a database with cached assets/objects but
        # topology has not been extracted yet, extract topology on the fly strictly from cached data
        # (allow_live_detail=False so cache mode never makes live API calls).
        if not topo_entries and all_assets:
            by_dom_assets: dict[tuple[str, str], list[Asset]] = defaultdict(list)
            for a in all_assets:
                by_dom_assets[(a.mgmt_name, a.domain_name)].append(a)
            computed: list[GatewayTopologyEntry] = []
            for (m_name, d_name), dom_assets in by_dom_assets.items():
                dom_objs = [o for o in all_objects if o.mgmt_name == m_name and o.domain_name in (d_name, "Global")]
                dom_entries, _ = await self._extract_domain_topology_entries(
                    mgmt_name=m_name,
                    domain_name=d_name,
                    assets=dom_assets,
                    objects=dom_objs,
                    allow_live_detail=False,
                )
                computed.extend(dom_entries)
            topo_entries = computed

        if not topo_entries:
            return []

        assets_by_id: dict[str, Asset] = {a.id: a for a in all_assets}
        entries_by_gw_id: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
        for entry in topo_entries:
            entries_by_gw_id[entry.gateway_id].append(entry)

        # Pre-group objects by (mgmt_name, domain_name) and cache resolved endpoint intervals per domain
        objs_by_mgmt_dom: dict[tuple[str, str], list[CPObject]] = defaultdict(list)
        for obj in all_objects:
            objs_by_mgmt_dom[(obj.mgmt_name, obj.domain_name)].append(obj)

        resolved_endpoints_by_dom: dict[
            tuple[str, str],
            tuple[list[_ResolvedEndpointInterval], list[_ResolvedEndpointInterval]],
        ] = {}

        candidates: list[AffectedGatewayCandidate] = []

        for gw_id, gw_entries in entries_by_gw_id.items():
            first_entry = gw_entries[0]
            gw_mgmt = first_entry.mgmt_name
            gw_dom = first_entry.domain_name
            dom_key = (gw_mgmt, gw_dom)

            if dom_key not in resolved_endpoints_by_dom:
                scoped_objs = [
                    *objs_by_mgmt_dom.get((gw_mgmt, "Global"), []),
                    *(objs_by_mgmt_dom.get((gw_mgmt, gw_dom), []) if gw_dom != "Global" else []),
                ]
                obj_by_uid, obj_by_name = self._index_objects(scoped_objs, domain_name=gw_dom)
                resolved_endpoints_by_dom[dom_key] = (
                    self._resolve_endpoint_intervals(
                        src_list,
                        obj_by_uid=obj_by_uid,
                        obj_by_name=obj_by_name,
                    ),
                    self._resolve_endpoint_intervals(
                        dst_list,
                        obj_by_uid=obj_by_uid,
                        obj_by_name=obj_by_name,
                    ),
                )

            src_intervals, dst_intervals = resolved_endpoints_by_dom[dom_key]
            if not src_intervals or not dst_intervals:
                continue

            external_if_names = {e.interface_name for e in gw_entries if e.topology_zone == "external"}
            matched_flows: list[TrafficFlowMatch] = []
            seen_flow_keys: set[tuple[str, str, str, str, str, str]] = set()
            match_types_seen: list[str] = []

            for src_ep in src_intervals:
                src_matches = self._locate_intervals_on_gateway(src_ep, gw_entries, external_if_names)
                if not src_matches:
                    continue
                for dst_ep in dst_intervals:
                    dst_matches = self._locate_intervals_on_gateway(dst_ep, gw_entries, external_if_names)
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

                            if m_type not in match_types_seen:
                                match_types_seen.append(m_type)

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
                                )
                            )

            if not matched_flows:
                continue

            gw_asset = assets_by_id.get(gw_id)
            installed_pol, pkg_names, layer_names = await self._resolve_gateway_policy_metadata(
                gw_mgmt,
                gw_dom,
                gw_asset,
                first_entry.gateway_uid,
                first_entry.gateway_name,
            )

            candidates.append(
                AffectedGatewayCandidate(
                    mgmt_name=gw_mgmt,
                    domain_name=gw_dom,
                    gateway_id=first_entry.gateway_id,
                    gateway_asset_id=first_entry.gateway_asset_id,
                    gateway_uid=first_entry.gateway_uid,
                    gateway_name=first_entry.gateway_name,
                    gateway_type=first_entry.gateway_type,
                    ipv4_address=gw_asset.ipv4_address if gw_asset else None,
                    parent_id=gw_asset.parent_id if gw_asset else None,
                    parent_asset_id=gw_asset.parent_asset_id if gw_asset else None,
                    installed_access_policy=installed_pol,
                    policy_packages=pkg_names,
                    access_layers=layer_names,
                    match_types=match_types_seen,
                    matched_flows=matched_flows,
                )
            )

        candidates.sort(
            key=lambda c: (
                0 if "internal_to_internal" in c.match_types else 1,
                -len(c.matched_flows),
                c.mgmt_name,
                c.domain_name,
                c.gateway_name,
            )
        )
        return candidates


__all__ = [
    "EXCLUDED_GATEWAY_TYPES",
    "POLICY_GATEWAY_TYPES",
    "TopologyService",
    "is_policy_enforcing_gateway",
]
