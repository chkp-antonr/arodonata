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

import asyncio
import ipaddress
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import arlogi

from arodonata.core.config import ArodonataSettings, TopologyConfidenceWeights
from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.events import (
    DomainSyncCompletedEvent,
    DomainSyncFailedEvent,
    DomainSyncProgressEvent,
    DomainSyncStartedEvent,
    SyncCompletedEvent,
    SyncProgressEvent,
    SyncStartedEvent,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import DEFAULT_OBJECT_TYPES, CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.models.objects import CPObject
from arodonata.core.models.topology import (
    LIVE_ROUTE_SOURCES,
    STATIC_TOPOLOGY_SOURCES,
    AffectedGatewayCandidate,
    AntiSpoofingMode,
    ConfidenceDelta,
    ExportedTopologyPrefix,
    FlowMatchType,
    GatewayInterfaceSummary,
    GatewayRouteCollectionStatus,
    GatewayTopologyEntry,
    RouteCollectionOutcome,
    TopologyAnnotation,
    TopologyDiagnostic,
    TopologyDiagnosticCode,
    TopologyDiagnosticSeverity,
    TopologyDiscrepancy,
    TopologyReconciliationReport,
    TopologySourceType,
    TopologyZone,
    TrafficFlowMatch,
)
from arodonata.core.ports import ApiPort, CachePort, GatewayCliCallable, GatewayCliPort
from arodonata.core.services.asset_service import (
    VSX_CHILD_TYPES,
    AssetRefreshService,
    _extract_interfaces_from_generic,
)
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.route_collector import (
    ParsedCliRoute,
    build_route_collection_script,
    execute_gateway_cli,
    parse_combined_cli_routes,
    resolve_gateway_cli_targets,
    routes_to_topology_entries,
)
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
    specific_inline_cidr: str | None
    has_explicit_topology: bool
    anti_spoofing_mode: AntiSpoofingMode = "unknown"


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
    confidence: float = 1.0
    is_standby_path: bool = False
    confidence_factors: tuple[ConfidenceDelta, ...] = ()
    warnings: tuple[str, ...] = ()


def _extract_anti_spoofing_mode(raw_if: dict[str, Any], *extra_dicts: dict[str, Any] | None) -> AntiSpoofingMode:
    """Extract normalized `AntiSpoofingMode` (`'prevent' | 'detect' | 'off' | 'unknown'`) from interface dictionaries."""
    containers: list[dict[str, Any]] = [raw_if]
    for d in extra_dicts:
        if isinstance(d, dict):
            containers.append(d)
    for key in (
        "anti-spoofing",
        "anti_spoofing",
        "antiSpoofing",
        "anti-spoofing-settings",
        "anti_spoofing_settings",
        "antiSpoofingSettings",
        "topology-settings",
        "topology_settings",
        "topology",
    ):
        sub = raw_if.get(key)
        if isinstance(sub, dict) and sub not in containers:
            containers.append(sub)
            for nested_key in ("anti-spoofing", "anti_spoofing", "anti-spoofing-settings", "anti_spoofing_settings"):
                nested_sub = sub.get(nested_key)
                if isinstance(nested_sub, dict) and nested_sub not in containers:
                    containers.append(nested_sub)

    perform_val: bool | None = None
    if isinstance(raw_if.get("anti-spoofing"), bool):
        perform_val = raw_if["anti-spoofing"]
    elif isinstance(raw_if.get("anti_spoofing"), bool):
        perform_val = raw_if["anti_spoofing"]
    action_str = ""

    for c in containers:
        for p_key in (
            "perform-anti-spoofing",
            "perform_anti_spoofing",
            "performAntiSpoofing",
            "anti-spoofing-enabled",
            "anti_spoofing_enabled",
            "enabled",
        ):
            if p_key in c and isinstance(c[p_key], bool):
                # Do not treat interface-level `enabled` as anti-spoofing enabled unless inside an anti-spoofing dict
                if p_key == "enabled" and c is raw_if:
                    continue
                perform_val = c[p_key]
                break

        for a_key in (
            "action",
            "anti-spoofing-action",
            "anti_spoofing_action",
            "antiSpoofingAction",
        ):
            val = c.get(a_key)
            if isinstance(val, str) and val.strip():
                action_str = val.strip().lower()
                break

    if perform_val is False or action_str in ("off", "none", "disabled", "false", "inactive"):
        return "off"
    if "detect" in action_str:
        return "detect"
    if "prevent" in action_str:
        return "prevent"
    if perform_val is True:
        return "prevent"
    return "unknown"


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
    specific_inline_cidr: str | None = None
    has_explicit_topology = False

    def _extract_inline_cidr(spec_dict: dict[str, Any]) -> str | None:
        sub4 = spec_dict.get("subnet4") or spec_dict.get("subnet")
        if sub4 and str(sub4).strip():
            plen = _mask_to_prefix_len(
                spec_dict.get("mask-length4")
                or spec_dict.get("mask_length4")
                or spec_dict.get("mask-length")
                or spec_dict.get("subnet-mask")
                or spec_dict.get("netmask")
            )
            if plen is not None:
                try:
                    return str(ipaddress.IPv4Network(f"{str(sub4).strip()}/{plen}", strict=False))
                except ValueError:
                    pass
        ip4 = spec_dict.get("ipv4-address") or spec_dict.get("ipv4_address") or spec_dict.get("ipaddr")
        if ip4 and str(ip4).strip():
            try:
                return f"{ipaddress.IPv4Address(str(ip4).strip())}/32"
            except ValueError:
                pass
        return None

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
            topo_field.get("leads-to-specific-network")
            or topo_field.get("leads_to_specific_network")
            or topo_field.get("specific-network")
            or topo_field.get("specific_network")
            or topo_field.get("specificGroup")
        )
        if isinstance(spec_val, dict):
            specific_uid = str(spec_val.get("uid") or "") or None
            specific_ref = str(spec_val.get("name") or spec_val.get("uid") or "") or None
            specific_inline_cidr = _extract_inline_cidr(spec_val)
        elif isinstance(spec_val, str) and spec_val.strip():
            specific_ref = spec_val.strip()
        spec_uid_val = (
            topo_field.get("leads-to-specific-network-uid")
            or topo_field.get("leads_to_specific_network_uid")
            or topo_field.get("specific-network-uid")
            or topo_field.get("specific_network_uid")
        )
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
            topo_settings.get("leads-to-specific-network")
            or topo_settings.get("leads_to_specific_network")
            or topo_settings.get("specific-network")
            or topo_settings.get("specific_network")
            or topo_settings.get("specificGroup")
        )
        if isinstance(spec_val2, dict):
            specific_uid = specific_uid or str(spec_val2.get("uid") or "") or None
            specific_ref = specific_ref or str(spec_val2.get("name") or spec_val2.get("uid") or "") or None
            specific_inline_cidr = specific_inline_cidr or _extract_inline_cidr(spec_val2)
        elif isinstance(spec_val2, str) and spec_val2.strip() and not specific_ref:
            specific_ref = spec_val2.strip()
        spec_uid2 = (
            topo_settings.get("leads-to-specific-network-uid")
            or topo_settings.get("leads_to_specific_network_uid")
            or topo_settings.get("specific-network-uid")
            or topo_settings.get("specific_network_uid")
        )
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

    anti_spoof = _extract_anti_spoofing_mode(
        raw_if,
        topo_field if isinstance(topo_field, dict) else None,
        topo_settings if isinstance(topo_settings, dict) else None,
    )

    return _NormalizedInterface(
        interface_name=if_name,
        ipv4_address=ipv4_address,
        mask_length=mask_len,
        is_external=is_external,
        leads_to_dmz=leads_to_dmz,
        behind_mode=behind_mode,
        specific_network_ref=specific_ref,
        specific_network_uid=specific_uid,
        specific_inline_cidr=specific_inline_cidr,
        has_explicit_topology=has_explicit_topology,
        anti_spoofing_mode=anti_spoof,
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

    mask_from_dest: Any = None
    if isinstance(dest_raw, dict):
        mask_from_dest = (
            dest_raw.get("netmask")
            or dest_raw.get("mask")
            or dest_raw.get("subnet-mask")
            or dest_raw.get("mask-length")
            or dest_raw.get("mask_length")
            or dest_raw.get("prefix-length")
        )
        dest_raw = (
            dest_raw.get("ipaddr")
            or dest_raw.get("ipv4-address")
            or dest_raw.get("address")
            or dest_raw.get("subnet")
            or dest_raw.get("network")
            or ""
        )

    dest_str = str(dest_raw).strip()
    if not dest_str or dest_str.lower() == "default" or dest_str == "0.0.0.0/0":
        return ipaddress.IPv4Network("0.0.0.0/0")

    if "/" in dest_str:
        try:
            return ipaddress.IPv4Network(dest_str, strict=False)
        except ValueError:
            return None

    mask_val = (
        mask_from_dest
        or route.get("mask")
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
        or route.get("interfaceName")
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
        or route.get("nextHop")
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


def _extract_timestamp_posix(val: Any) -> int:
    """Extract a comparable POSIX timestamp integer from a Check Point date dict, int, or ISO-8601 string."""
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, dict):
        posix = val.get("posix")
        if isinstance(posix, (int, float)):
            return int(posix)
        if isinstance(posix, str) and posix.strip().isdigit():
            return int(posix.strip())
        iso_str = val.get("iso-8601") or val.get("iso_8601")
        if isinstance(iso_str, str) and iso_str.strip():
            try:
                return int(datetime.fromisoformat(iso_str.strip()).timestamp() * 1000)
            except ValueError:
                pass
    if isinstance(val, str) and val.strip():
        clean = val.strip()
        if clean.isdigit():
            return int(clean)
        try:
            return int(datetime.fromisoformat(clean).timestamp() * 1000)
        except ValueError:
            pass
    return 0


def _extract_policy_candidates_from_raw(
    raw_data: dict[str, Any],
    *,
    priority: int = 1,
) -> list[tuple[int, int, str]]:
    """Extract `(timestamp_posix, priority, policy_name)` candidates from a Check Point gateway/cluster `raw_data` dict."""
    candidates: list[tuple[int, int, str]] = []
    raw_pol = raw_data.get("policy")
    if isinstance(raw_pol, dict):
        pol_name = raw_pol.get("access-policy-name") or raw_pol.get("access_policy_name")
        if isinstance(pol_name, str) and pol_name.strip():
            install_ts = _extract_timestamp_posix(
                raw_pol.get("access-policy-installation-date")
                or raw_pol.get("access_policy_installation_date")
                or (
                    raw_pol.get("access-policy-revision", {}).get("publish-time")
                    if isinstance(raw_pol.get("access-policy-revision"), dict)
                    else None
                )
            )
            candidates.append((install_ts, priority, pol_name.strip()))

        member_revs = raw_pol.get("cluster-members-access-policy-revision") or raw_pol.get(
            "cluster_members_access_policy_revision"
        )
        if isinstance(member_revs, list):
            for rev_item in member_revs:
                if not isinstance(rev_item, dict):
                    continue
                m_pol = (
                    rev_item.get("policy-name")
                    or rev_item.get("policy_name")
                    or rev_item.get("access-policy-name")
                    or rev_item.get("access_policy_name")
                )
                if isinstance(m_pol, str) and m_pol.strip():
                    rev_dict = rev_item.get("revision")
                    m_ts = _extract_timestamp_posix(
                        rev_item.get("access-policy-installation-date")
                        or rev_item.get("access_policy_installation_date")
                        or rev_item.get("installation-date")
                        or (rev_dict.get("publish-time") if isinstance(rev_dict, dict) else None)
                    )
                    candidates.append((m_ts, priority - 1, m_pol.strip()))
    elif isinstance(raw_pol, str) and raw_pol.strip():
        candidates.append((0, priority, raw_pol.strip()))

    alt_pol = raw_data.get("access-policy-name") or raw_data.get("access_policy_name")
    if isinstance(alt_pol, str) and alt_pol.strip():
        alt_ts = _extract_timestamp_posix(
            raw_data.get("access-policy-installation-date") or raw_data.get("access_policy_installation_date")
        )
        candidates.append((alt_ts, priority, alt_pol.strip()))

    return candidates


class TopologyService:
    """Extracts, caches, reconciles, and matches gateway interface topology and live routes across domains."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        coordinator: DomainSyncCoordinator,
        asset_service: AssetRefreshService,
        object_service: ObjectService,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._asset_service = asset_service
        self._object_service = object_service
        self._gateway_cli = gateway_cli
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    @property
    def gateway_cli(self) -> GatewayCliPort | GatewayCliCallable | None:
        """Configured `GatewayCliPort` or async callable for executing CLI commands on gateways."""
        return self._gateway_cli

    def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None:
        """Set or replace the runtime `GatewayCliPort` or async callable."""
        self._gateway_cli = gateway_cli

    @staticmethod
    def _normalize_gateway_filter_tokens(gateways: Sequence[str] | str | None) -> list[str]:
        if gateways is None:
            return []
        if isinstance(gateways, str):
            return [g.strip().lower() for g in gateways.split(",") if g.strip()]
        return [str(g).strip().lower() for g in gateways if str(g).strip()]

    @staticmethod
    def _matches_gateway_filter(asset: Asset, tokens: set[str]) -> bool:
        if not tokens:
            return True
        return bool(
            tokens.intersection(
                {
                    asset.uid.lower(),
                    asset.name.lower(),
                    asset.id.lower(),
                    asset.asset_id.lower(),
                }
            )
        )

    async def stream_refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing gateway topology across domains (or targeted `gateways`)."""
        gw_tokens = self._normalize_gateway_filter_tokens(gateways)
        if gw_tokens:
            async for event in self._stream_targeted_gateway_refresh(
                mgmt_name=mgmt_name,
                domains=domains,
                gw_tokens=set(gw_tokens),
                collect_routes=collect_routes,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            ):
                yield event
            return

        if mode != "cache":
            async for event in self._asset_service.stream_refresh_assets(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
            ):
                yield event

            async for event in self._object_service.stream_refresh_objects(
                mgmt_name=mgmt_name,
                domains=domains,
                types=list(DEFAULT_OBJECT_TYPES),
                include_global=True,
                mode=mode,
                cache_ttl=cache_ttl,
            ):
                yield event

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

        if collect_routes and mode != "cache":
            await self.collect_gateway_routes(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
            )

    @traced
    async def refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh gateway topology across domains (or targeted `gateways`) and return `RefreshOutcome`."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global, collect_routes=collect_routes)
        gw_tokens = self._normalize_gateway_filter_tokens(gateways)
        if gw_tokens:
            refreshed_domains: list[str] = []
            skipped_domains: list[str] = []
            failed_domains: dict[str, str] = {}
            total_items = 0
            async for event in self._stream_targeted_gateway_refresh(
                mgmt_name=mgmt_name,
                domains=domains,
                gw_tokens=set(gw_tokens),
                collect_routes=collect_routes,
                include_global=include_global,
                mode=mode,
                cache_ttl=cache_ttl,
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

        outcome = await self._coordinator.ensure(
            scope="topology",
            item_types=["*"],
            handler=self._sync_domain_topology,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )
        if collect_routes and mode != "cache":
            await self.collect_gateway_routes(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
            )
        return outcome

    async def _stream_targeted_gateway_refresh(
        self,
        *,
        mgmt_name: str | None,
        domains: Sequence[str] | str | None,
        gw_tokens: set[str],
        collect_routes: bool,
        include_global: bool,
        mode: CacheMode,
        cache_ttl: float | None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Refresh static topology (and optionally live routes) ONLY for the specified `gw_tokens` without rewriting other gateways."""
        target_domains = await self._coordinator.resolve_target_domains(
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

        for dom in target_domains:
            dom_label = f"{dom.mgmt_name}:{dom.name}"
            try:
                domain_assets = await self._cache.get_assets(mgmt_name=dom.mgmt_name, domain_name=dom.name)
                if not domain_assets and mode != "cache":
                    domain_assets = await self._asset_service.get_assets(
                        mgmt_name=dom.mgmt_name,
                        domain=dom.name,
                        cache_mode=mode,
                        cache_ttl=cache_ttl,
                    )

                matched_gateways = [
                    a
                    for a in domain_assets
                    if is_policy_enforcing_gateway(a) and self._matches_gateway_filter(a, gw_tokens)
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

                if mode != "cache":
                    # Refresh objects with smart caching so newly added group members are picked up if domain was published
                    await self._object_service.refresh_objects(
                        mgmt_name=dom.mgmt_name,
                        domains=[dom.name],
                        types=list(DEFAULT_OBJECT_TYPES),
                        include_global=True,
                        mode="smart" if mode == "force" else mode,
                        cache_ttl=cache_ttl,
                    )
                    # Force on-demand detail fetch for each targeted gateway so modified interface definitions are pulled
                    refreshed_gw_map: dict[str, Asset] = {}
                    for gw_asset in matched_gateways:
                        enriched = await self._fetch_asset_detail_on_demand(dom.mgmt_name, dom.name, gw_asset)
                        if enriched is not None:
                            refreshed_gw_map[enriched.uid] = enriched
                    if refreshed_gw_map:
                        await self._cache.upsert_assets(list(refreshed_gw_map.values()))
                        domain_assets = [refreshed_gw_map.get(a.uid, a) for a in domain_assets]

                domain_objects = await self._cache.get_objects(mgmt_name=dom.mgmt_name, domain_name=dom.name)
                global_objects = (
                    await self._cache.get_objects(mgmt_name=dom.mgmt_name, domain_name="Global")
                    if dom.name != "Global"
                    else []
                )
                all_objects = ObjectService.apply_context_overlay(
                    [*domain_objects, *global_objects],
                    mgmt_name=dom.mgmt_name,
                    domain_name=dom.name,
                )

                target_gw_uids = [g.uid for g in matched_gateways]
                entries, updated_assets = await self._extract_domain_topology_entries(
                    mgmt_name=dom.mgmt_name,
                    domain_name=dom.name,
                    assets=domain_assets,
                    objects=all_objects,
                    target_gateway_uids=set(target_gw_uids),
                    allow_live_detail=mode != "cache",
                )
                if updated_assets:
                    await self._cache.upsert_assets(updated_assets)

                count = await self._cache.replace_domain_topology(
                    dom.mgmt_name,
                    dom.name,
                    entries,
                    gateway_uids=target_gw_uids,
                    source_types=list(STATIC_TOPOLOGY_SOURCES),
                )
                if collect_routes and mode != "cache":
                    route_outcome = await self.collect_gateway_routes(
                        mgmt_name=dom.mgmt_name,
                        domain=dom.name,
                        gateways=target_gw_uids,
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
            except Exception as exc:
                err_str = str(exc)
                failed_domains[dom_label] = err_str
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
            emit=emit,
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
        active_gw_uids = [a.uid for a in domain_assets if is_policy_enforcing_gateway(a)]
        return await self._cache.replace_domain_topology(
            mgmt_name,
            dom_name,
            entries,
            source_types=list(STATIC_TOPOLOGY_SOURCES),
            active_gateway_uids=active_gw_uids,
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
        target_gateway_uids: set[str] | None = None,
        allow_live_detail: bool = True,
        emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
    ) -> tuple[list[GatewayTopologyEntry], list[Asset]]:
        """Extract `GatewayTopologyEntry` rows for all policy-enforcing gateways in `(mgmt_name, domain_name)`."""
        obj_by_uid, obj_by_name = self._index_objects(objects, domain_name=domain_name)
        entries: list[GatewayTopologyEntry] = []
        updated_assets: list[Asset] = []
        now = self._now()

        policy_gateways = [
            a
            for a in assets
            if is_policy_enforcing_gateway(a) and (target_gateway_uids is None or a.uid in target_gateway_uids)
        ]
        total_gateways = len(policy_gateways)

        for gw_idx, asset in enumerate(policy_gateways, start=1):
            gw_entries: list[GatewayTopologyEntry] = []
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

            installed_pol, pkg_names, _ = await self._resolve_gateway_policy_metadata(
                mgmt_name,
                domain_name,
                asset,
                asset.uid,
                asset.name,
                all_assets=assets,
            )

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
                                anti_spoofing_mode=target_nif.anti_spoofing_mode if target_nif else "unknown",
                                source_type="vs_static_route",
                                source_ref=nh_ref,
                                cidr_or_range="0.0.0.0/0",
                                ip_first_int=0,
                                ip_last_int=MAX_IPV4_INT,
                                prefix_len=0,
                                installed_access_policy=installed_pol,
                                policy_packages=list(pkg_names),
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
                                anti_spoofing_mode=target_nif.anti_spoofing_mode if target_nif else "unknown",
                                source_type="vs_static_route",
                                source_ref=nh_ref,
                                cidr_or_range=str(dest_net),
                                ip_first_int=int(dest_net.network_address),
                                ip_last_int=int(dest_net.broadcast_address),
                                prefix_len=dest_net.prefixlen,
                                installed_access_policy=installed_pol,
                                policy_packages=list(pkg_names),
                                updated_at=now,
                            )
                        )

            for nif in norm_ifs:
                if nif.is_external:
                    gw_entries.append(
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
                            anti_spoofing_mode=nif.anti_spoofing_mode,
                            source_type="external_interface",
                            source_ref="leads-to-internet",
                            cidr_or_range="0.0.0.0/0",
                            ip_first_int=0,
                            ip_last_int=MAX_IPV4_INT,
                            prefix_len=0,
                            installed_access_policy=installed_pol,
                            policy_packages=list(pkg_names),
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
                                anti_spoofing_mode=nif.anti_spoofing_mode,
                                source_type="interface_specific",
                                source_ref=src_ref,
                                cidr_or_range=cidr_str,
                                ip_first_int=lo_int,
                                ip_last_int=hi_int,
                                prefix_len=plen,
                                installed_access_policy=installed_pol,
                                policy_packages=list(pkg_names),
                                updated_at=now,
                            )
                        )
                elif "interface ip and net mask" in mode_lower or mode_lower == "connected":
                    # If this VS interface was marked external via a 0.0.0.0/0 default route,
                    # still record its connected subnet unless it is purely an external warp link.
                    if nif.interface_name in connected_by_if:
                        _, c_net = connected_by_if[nif.interface_name]
                        gw_entries.append(
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
                                anti_spoofing_mode=nif.anti_spoofing_mode,
                                source_type="interface_connected",
                                source_ref="connected",
                                cidr_or_range=str(c_net),
                                ip_first_int=int(c_net.network_address),
                                ip_last_int=int(c_net.broadcast_address),
                                prefix_len=c_net.prefixlen,
                                installed_access_policy=installed_pol,
                                policy_packages=list(pkg_names),
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

            gw_entries.extend(vs_route_entries)
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
        if not entries:
            return []

        all_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
        assets_by_id: dict[str, Asset] = {a.id: a for a in all_assets}
        assets_by_dom: dict[tuple[str, str], list[Asset]] = defaultdict(list)
        for a in all_assets:
            assets_by_dom[(a.mgmt_name, a.domain_name)].append(a)

        policy_by_gw_id: dict[str, tuple[str | None, list[str]]] = {}
        enriched_entries: list[GatewayTopologyEntry] = []
        for entry in entries:
            if entry.gateway_id not in policy_by_gw_id:
                gw_asset = assets_by_id.get(entry.gateway_id)
                dom_assets = assets_by_dom.get((entry.mgmt_name, entry.domain_name), [])
                inst_pol, pkg_names, _ = await self._resolve_gateway_policy_metadata(
                    entry.mgmt_name,
                    entry.domain_name,
                    gw_asset,
                    entry.gateway_uid,
                    entry.gateway_name,
                    all_assets=dom_assets,
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
                    anti_spoofing_mode=next(
                        (e.anti_spoofing_mode for e in group_entries if e.anti_spoofing_mode != "unknown"),
                        first.anti_spoofing_mode,
                    ),
                    source_types=src_types,
                    cidrs_and_ranges=cidrs,
                )
            )
        return summaries

    @staticmethod
    def _parse_cidr_or_range_bounds(cidr_or_range: str) -> tuple[int, int, int] | None:
        """Parse a CIDR (`10.0.0.0/24`), single IPv4 (`10.0.0.1`), or range (`10.0.0.1-10.0.0.10`) into `(lo, hi, prefix_len)`."""
        clean = cidr_or_range.strip()
        if not clean or clean == "*":
            return None
        if clean.lower() == "default" or clean == "0.0.0.0/0":
            return 0, MAX_IPV4_INT, 0
        if "-" in clean and "/" not in clean:
            parts = clean.split("-", 1)
            try:
                ip1 = ipaddress.IPv4Address(parts[0].strip())
                ip2 = ipaddress.IPv4Address(parts[1].strip())
                lo = min(int(ip1), int(ip2))
                hi = max(int(ip1), int(ip2))
                return lo, hi, _effective_range_prefix_len(lo, hi)
            except ValueError:
                return None
        try:
            net = ipaddress.IPv4Network(clean, strict=False) if "/" in clean else ipaddress.IPv4Network(f"{clean}/32")
            return int(net.network_address), int(net.broadcast_address), net.prefixlen
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Static Topology Health Diagnostics (`get_topology_diagnostics`)
    # ------------------------------------------------------------------

    @traced
    async def get_topology_diagnostics(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
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
            await self.refresh_topology(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                gateways=eff_gateways if cache_mode == "force" else None,
                include_global=domain == "Global",
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        all_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
        all_objects = await self._cache.get_objects(mgmt_name=mgmt_name)
        all_objects = ObjectService.apply_context_overlay(all_objects, mgmt_name=mgmt_name, domain_name=domain)
        topo_entries = await self._cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)

        gw_tokens = set(self._normalize_gateway_filter_tokens(eff_gateways))
        policy_gateways = [
            a for a in all_assets if is_policy_enforcing_gateway(a) and self._matches_gateway_filter(a, gw_tokens)
        ]

        objs_by_dom: dict[tuple[str, str], list[CPObject]] = defaultdict(list)
        for obj in all_objects:
            objs_by_dom[(obj.mgmt_name, obj.domain_name)].append(obj)

        indexed_objs_by_dom: dict[tuple[str, str], tuple[dict[str, CPObject], dict[str, CPObject]]] = {}

        entries_by_gw_if: dict[tuple[str, str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
        for entry in topo_entries:
            entries_by_gw_if[(entry.mgmt_name, entry.domain_name, entry.gateway_uid, entry.interface_name)].append(
                entry
            )

        def _make_diag(
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

        diagnostics: list[TopologyDiagnostic] = []
        for asset in sorted(policy_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name)):
            is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
            raw_ifs = list(asset.interfaces) or _extract_interfaces_from_generic(asset.raw_data)
            norm_ifs: list[_NormalizedInterface] = []
            for raw_if in raw_ifs:
                if isinstance(raw_if, dict):
                    norm = _normalize_interface(raw_if, is_vs_asset=is_vs)
                    if norm is not None:
                        norm_ifs.append(norm)

            if not norm_ifs:
                diagnostics.append(
                    _make_diag(
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
                    _make_diag(
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
            if dom_key not in indexed_objs_by_dom:
                scoped_objs = [
                    *objs_by_dom.get((asset.mgmt_name, "Global"), []),
                    *(objs_by_dom.get(dom_key, []) if asset.domain_name != "Global" else []),
                ]
                indexed_objs_by_dom[dom_key] = self._index_objects(scoped_objs, domain_name=asset.domain_name)
            obj_by_uid, obj_by_name = indexed_objs_by_dom[dom_key]

            for nif in norm_ifs:
                if_entries = entries_by_gw_if.get(
                    (asset.mgmt_name, asset.domain_name, asset.uid, nif.interface_name),
                    [],
                )
                non_connected_route_entries = [
                    e
                    for e in if_entries
                    if (e.source_type in LIVE_ROUTE_SOURCES and e.source_type != "connected_route")
                    or e.source_type == "vs_static_route"
                ]
                mode_lower = nif.behind_mode.lower()

                if not nif.is_external and nif.anti_spoofing_mode in ("detect", "off"):
                    diagnostics.append(
                        _make_diag(
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
                    continue

                if "specific" in mode_lower:
                    ref_uid = nif.specific_network_uid
                    ref_name = nif.specific_network_ref
                    root_obj = (
                        (obj_by_uid.get(ref_uid) if ref_uid else None)
                        or (obj_by_name.get(ref_name) if ref_name else None)
                        or (obj_by_name.get(ref_uid) if ref_uid else None)
                    )
                    expanded = self._expand_specific_reference(
                        ref_uid=ref_uid,
                        ref_name=ref_name,
                        obj_by_uid=obj_by_uid,
                        obj_by_name=obj_by_name,
                    )
                    if not expanded and not nif.specific_inline_cidr:
                        if root_obj is None:
                            diagnostics.append(
                                _make_diag(
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
                            diagnostics.append(
                                _make_diag(
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
                        diagnostics.append(
                            _make_diag(
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
                        diagnostics.append(
                            _make_diag(
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
                else:
                    if not non_connected_route_entries:
                        diagnostics.append(
                            _make_diag(
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

        if min_severity == "warning":
            return [d for d in diagnostics if d.severity == "warning"]
        return diagnostics

    # ------------------------------------------------------------------
    # Live Gateway Route Collection (`collect_gateway_routes`)
    # ------------------------------------------------------------------

    @traced
    async def collect_gateway_routes(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        include_global: bool = True,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        timeout: float = 30.0,
        concurrency: int = 8,
    ) -> RouteCollectionOutcome:
        """Collect live IPv4 routing tables (`ip -4 route show` and `clish -c "show route"`) from gateways via SSH DI or `cprid` `run-script`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain, fallback_to_cprid=fallback_to_cprid, concurrency=concurrency)
        eff_cli = gateway_cli if gateway_cli is not None else self._gateway_cli

        domain_set: set[str] | None = None
        if domains is not None:
            if isinstance(domains, str):
                domain_set = {d.strip() for d in domains.split(",") if d.strip()}
            else:
                domain_set = {str(d).strip() for d in domains if str(d).strip()}
        elif domain is not None and domain.strip():
            domain_set = {domain.strip()}

        # Load all assets across the management server so VSX parents in other domains and cluster members are visible
        all_mgmt_assets = await self._cache.get_assets(mgmt_name=mgmt_name)
        if not all_mgmt_assets:
            all_mgmt_assets = await self._asset_service.get_assets(
                mgmt_name=mgmt_name,
                domain=domain,
                cache_mode="smart",
            )

        gw_tokens = set(self._normalize_gateway_filter_tokens(gateways))
        target_gateways = [
            a
            for a in all_mgmt_assets
            if is_policy_enforcing_gateway(a)
            and (domain_set is None or a.domain_name in domain_set)
            and (include_global or domain_set is not None or a.domain_name != "Global")
            and self._matches_gateway_filter(a, gw_tokens)
        ]

        now = self._now()
        sem = asyncio.Semaphore(max(1, concurrency))
        sorted_gateways = sorted(target_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name))

        dom_assets_by_key: dict[tuple[str, str], list[Asset]] = defaultdict(list)
        for a in all_mgmt_assets:
            dom_assets_by_key[(a.mgmt_name, a.domain_name)].append(a)

        async def _run_target(target: Any) -> tuple[Any, Any]:
            async with sem:
                script = build_route_collection_script(vsid=target.vsid, vs_name=target.vs_name)
                res = await execute_gateway_cli(
                    target,
                    script,
                    api=self._api,
                    gateway_cli=eff_cli,
                    fallback_to_cprid=fallback_to_cprid,
                    timeout=timeout,
                )
                return target, res

        async def _collect_for_gateway(gw_asset: Asset) -> tuple[GatewayRouteCollectionStatus, int]:
            cli_targets = resolve_gateway_cli_targets(gw_asset, all_mgmt_assets)
            target_results = await asyncio.gather(*(_run_target(t) for t in cli_targets))

            parsed_by_node: dict[str, list[ParsedCliRoute]] = {}
            node_errors: list[str] = []
            executors_used: list[str] = []

            for target, cli_res in target_results:
                if cli_res.executor and cli_res.executor not in executors_used:
                    executors_used.append(cli_res.executor)
                if not cli_res.success:
                    node_errors.append(
                        f"{target.node_name}: {cli_res.error_message or cli_res.stderr or 'CLI command failed'}"
                    )
                    continue
                parsed_by_node[target.node_name] = parse_combined_cli_routes(cli_res.stdout)

            if not parsed_by_node:
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
                        error="; ".join(node_errors) if node_errors else "No routes returned",
                    ),
                    0,
                )

            is_vs = gw_asset.type in VSX_CHILD_TYPES or "virtual-system" in gw_asset.type.lower()
            raw_ifs = list(gw_asset.interfaces) or _extract_interfaces_from_generic(gw_asset.raw_data)
            if_meta: dict[str, tuple[str | None, int | None, bool, str, bool]] = {}
            for raw_if in raw_ifs:
                if isinstance(raw_if, dict):
                    norm = _normalize_interface(raw_if, is_vs_asset=is_vs)
                    if norm is not None:
                        if_meta[norm.interface_name] = (
                            norm.ipv4_address,
                            norm.mask_length,
                            norm.leads_to_dmz,
                            norm.anti_spoofing_mode,
                            norm.is_external,
                        )

            dom_assets = dom_assets_by_key.get((gw_asset.mgmt_name, gw_asset.domain_name), [])
            inst_pol, pkg_names, _ = await self._resolve_gateway_policy_metadata(
                gw_asset.mgmt_name,
                gw_asset.domain_name,
                gw_asset,
                gw_asset.uid,
                gw_asset.name,
                all_assets=dom_assets,
            )

            route_entries, drift_detected, drift_map = routes_to_topology_entries(
                gateway_asset=gw_asset,
                parsed_routes_by_node=parsed_by_node,
                interface_meta=if_meta,
                installed_access_policy=inst_pol,
                policy_packages=pkg_names,
                now=now,
            )

            route_sync_state = DomainSyncState(
                mgmt_name=gw_asset.mgmt_name,
                domain_name=gw_asset.domain_name,
                scope="topology",
                item_type="routes",
                synced_at=now,
                status="ok",
                object_count=len(route_entries),
                last_error=None,
            )
            await self._cache.replace_domain_topology(
                gw_asset.mgmt_name,
                gw_asset.domain_name,
                route_entries,
                gateway_uids=[gw_asset.uid],
                source_types=list(LIVE_ROUTE_SOURCES),
                sync_states=[route_sync_state],
            )

            gw_warnings: list[str] = []
            if drift_detected:
                for (d_if, d_cidr), present_nodes in sorted(drift_map.items()):
                    gw_warnings.append(
                        f"Cluster member route drift on {gw_asset.name} :: {d_if} ({d_cidr}): "
                        f"present only on {', '.join(present_nodes)}"
                    )
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
                    routes_collected=len(route_entries),
                    member_drift_detected=drift_detected,
                    warnings=gw_warnings,
                    error=None,
                ),
                len(route_entries),
            )

        results = await asyncio.gather(*(_collect_for_gateway(gw) for gw in sorted_gateways))
        statuses = [st for st, _ in results]
        succeeded_count = sum(1 for st in statuses if st.success)
        failed_count = len(statuses) - succeeded_count
        total_routes_count = sum(cnt for _, cnt in results)

        return RouteCollectionOutcome(
            total_gateways=len(target_gateways),
            succeeded_gateways=succeeded_count,
            failed_gateways=failed_count,
            total_routes=total_routes_count,
            gateways=statuses,
        )

    # ------------------------------------------------------------------
    # Persistent Annotations, Reconciliation, and IPAM Export
    # ------------------------------------------------------------------

    @traced
    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Return persistent `TopologyAnnotation` records from `arodonata_topology_annotations`."""
        annotations = await self._cache.get_topology_annotations(
            mgmt_name=mgmt_name,
            domain_name=domain,
            interface_name=interface_name,
        )
        if gateway and gateway.strip():
            gw_clean = gateway.strip().lower()
            annotations = [a for a in annotations if gw_clean in (a.gateway_uid.lower(), a.gateway_name.lower())]
        return annotations

    @traced
    async def upsert_topology_annotations(
        self,
        annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any],
    ) -> list[TopologyAnnotation]:
        """Insert or update persistent `TopologyAnnotation` records and return the normalized models."""
        items: Sequence[TopologyAnnotation | dict[str, Any]] = (
            [annotations] if isinstance(annotations, (TopologyAnnotation, dict)) else annotations
        )
        normalized: list[TopologyAnnotation] = [
            a if isinstance(a, TopologyAnnotation) else TopologyAnnotation.model_validate(a) for a in items
        ]
        await self._cache.upsert_topology_annotations(normalized)
        return normalized

    @traced
    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str] | str | None = None,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateway_uid: str | None = None,
    ) -> int:
        """Delete persistent `TopologyAnnotation` records by ID or filter."""
        if annotation_ids is not None:
            ids = [annotation_ids] if isinstance(annotation_ids, str) else list(annotation_ids)
            return await self._cache.delete_topology_annotations(ids)
        matching = await self._cache.get_topology_annotations(
            mgmt_name=mgmt_name,
            domain_name=domain,
            gateway_uids=[gateway_uid] if gateway_uid else None,
        )
        if not matching:
            return 0
        return await self._cache.delete_topology_annotations([a.id for a in matching])

    @staticmethod
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

    @classmethod
    def _is_cidr_covered_by_entries(
        cls,
        lo: int,
        hi: int,
        entries: Sequence[GatewayTopologyEntry],
    ) -> bool:
        """Return `True` if `[lo, hi]` is covered by any single entry or the union of `entries`."""
        for e in entries:
            if e.ip_first_int <= lo and hi <= e.ip_last_int:
                return True
        return cls._is_range_covered_by_intervals(lo, hi, [(e.ip_first_int, e.ip_last_int) for e in entries])

    @traced
    async def reconcile_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        collect_live_routes: bool = False,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> TopologyReconciliationReport:
        """Compare SmartConsole static topology against live gateway routing tables and return `TopologyReconciliationReport`."""
        eff_collect = collect_routes or collect_live_routes
        span_attrs(mgmt_name=mgmt_name, domain=domain, collect_routes=eff_collect, cache_mode=cache_mode)
        if cache_mode != "cache":
            await self.refresh_topology(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                gateways=gateways if cache_mode == "force" else None,
                collect_routes=False,
                include_global=domain == "Global",
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        if eff_collect:
            await self.collect_gateway_routes(
                mgmt_name=mgmt_name,
                domain=domain,
                gateways=gateways,
                gateway_cli=gateway_cli,
                fallback_to_cprid=fallback_to_cprid,
            )

        diagnostics = await self.get_topology_diagnostics(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            cache_mode="cache",
        )

        topo_entries = await self._cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)
        all_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain)
        annotations = await self._cache.get_topology_annotations(mgmt_name=mgmt_name, domain_name=domain)

        gw_tokens = set(self._normalize_gateway_filter_tokens(gateways))
        policy_gateways = [
            a for a in all_assets if is_policy_enforcing_gateway(a) and self._matches_gateway_filter(a, gw_tokens)
        ]

        entries_by_gw_uid: dict[tuple[str, str, str], list[GatewayTopologyEntry]] = defaultdict(list)
        for entry in topo_entries:
            entries_by_gw_uid[(entry.mgmt_name, entry.domain_name, entry.gateway_uid)].append(entry)

        anns_by_gw_uid: dict[tuple[str, str, str], list[TopologyAnnotation]] = defaultdict(list)
        for ann in annotations:
            anns_by_gw_uid[(ann.mgmt_name, ann.domain_name, ann.gateway_uid)].append(ann)

        weights = self._settings.topology_confidence_weights
        discrepancies: list[TopologyDiscrepancy] = []

        for gw_asset in sorted(policy_gateways, key=lambda a: (a.mgmt_name, a.domain_name, a.name)):
            gw_key = (gw_asset.mgmt_name, gw_asset.domain_name, gw_asset.uid)
            gw_entries = entries_by_gw_uid.get(gw_key, [])
            gw_anns = anns_by_gw_uid.get(gw_key, [])
            gw_trust_static, if_trust_static, ann_by_if_cidr, _ = self._index_annotations_for_gateway(gw_anns)

            static_entries = [e for e in gw_entries if e.source_type in STATIC_TOPOLOGY_SOURCES]
            route_entries = [e for e in gw_entries if e.source_type in LIVE_ROUTE_SOURCES]
            if not route_entries:
                continue

            is_vs = gw_asset.type in VSX_CHILD_TYPES or "virtual-system" in gw_asset.type.lower()
            raw_ifs = list(gw_asset.interfaces) or _extract_interfaces_from_generic(gw_asset.raw_data)
            norm_ifs_by_name: dict[str, _NormalizedInterface] = {}
            for raw_if in raw_ifs:
                if isinstance(raw_if, dict):
                    norm = _normalize_interface(raw_if, is_vs_asset=is_vs)
                    if norm is not None:
                        norm_ifs_by_name[norm.interface_name] = norm

            static_internal = [e for e in static_entries if e.topology_zone == "internal"]
            route_internal = [e for e in route_entries if e.topology_zone == "internal"]
            static_external = [e for e in static_entries if e.topology_zone == "external"]
            default_routes = [
                e for e in route_entries if e.prefix_len == 0 and e.ip_first_int == 0 and e.ip_last_int == MAX_IPV4_INT
            ]

            static_by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
            for se in static_internal:
                static_by_if[se.interface_name].append(se)

            route_by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
            for re_entry in route_internal:
                route_by_if[re_entry.interface_name].append(re_entry)

            # 1. Default route (`0.0.0.0/0`) vs static external interface check
            if static_external and default_routes:
                static_ext_ifs = {e.interface_name for e in static_external}
                route_ext_ifs = {e.interface_name for e in default_routes}
                if not static_ext_ifs.intersection(route_ext_ifs):
                    s_if = sorted(static_ext_ifs)[0]
                    r_if = sorted(route_ext_ifs)[0]
                    ann_match = ann_by_if_cidr.get((s_if, "0.0.0.0/0")) or ann_by_if_cidr.get(("*", "0.0.0.0/0"))
                    disp = ann_match.disposition if ann_match else None
                    if_untrusted = if_trust_static.get(s_if, gw_trust_static) is False
                    suppressed = disp in ("confirmed", "standby_dynamic", "ignore") or if_untrusted
                    discrepancies.append(
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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
                    )

            # 2. Check each static internal interval against live route intervals
            seen_static_pairs: set[tuple[str, str]] = set()
            mismatched_routed_if_cidrs: set[tuple[str, str]] = set()
            for se in static_internal:
                pair_key = (se.interface_name, se.cidr_or_range)
                if pair_key in seen_static_pairs:
                    continue
                seen_static_pairs.add(pair_key)

                same_if_routes = route_by_if.get(se.interface_name, [])
                if self._is_cidr_covered_by_entries(se.ip_first_int, se.ip_last_int, same_if_routes):
                    continue

                # Check if routed on a different interface
                other_if_matches: list[GatewayTopologyEntry] = []
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
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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

            # 3. Check each live route interval against static topology and cluster member drift
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
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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
                if self._is_cidr_covered_by_entries(re_entry.ip_first_int, re_entry.ip_last_int, same_if_static):
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
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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
                        TopologyDiscrepancy(
                            mgmt_name=gw_asset.mgmt_name,
                            domain_name=gw_asset.domain_name,
                            gateway_id=gw_asset.id,
                            gateway_asset_id=gw_asset.asset_id,
                            gateway_uid=gw_asset.uid,
                            gateway_name=gw_asset.name,
                            gateway_type=gw_asset.type,
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

        return TopologyReconciliationReport(
            mgmt_name=mgmt_name,
            domain_name=domain,
            gateway_count=len(policy_gateways),
            diagnostics=diagnostics,
            discrepancies=discrepancies,
        )

    # ------------------------------------------------------------------
    # Evidence Delta Confidence Scoring & IPAM Export
    # ------------------------------------------------------------------

    @classmethod
    def _build_effective_gateway_entries(
        cls,
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
        gw_trust_static, if_trust_static, ann_by_if_cidr, ann_by_if_wildcard = cls._index_annotations_for_gateway(
            gw_annotations
        )

        first = gw_entries[0] if gw_entries else None
        filtered: list[GatewayTopologyEntry] = []

        for entry in gw_entries:
            ann = ann_by_if_cidr.get((entry.interface_name, entry.cidr_or_range)) or ann_by_if_cidr.get(
                ("*", entry.cidr_or_range)
            )
            if ann is not None and ann.disposition == "ignore":
                continue

            filtered.append(entry)

        # Synthesize manual entries from annotations with `disposition="manual"`
        if first is not None or gateway_asset is not None:
            mgmt_val = first.mgmt_name if first is not None else gateway_asset.mgmt_name  # type: ignore[union-attr]
            dom_val = first.domain_name if first is not None else gateway_asset.domain_name  # type: ignore[union-attr]
            gw_id_val = first.gateway_id if first is not None else gateway_asset.id  # type: ignore[union-attr]
            gw_aid_val = first.gateway_asset_id if first is not None else gateway_asset.asset_id  # type: ignore[union-attr]
            gw_uid_val = first.gateway_uid if first is not None else gateway_asset.uid  # type: ignore[union-attr]
            gw_name_val = first.gateway_name if first is not None else gateway_asset.name  # type: ignore[union-attr]
            gw_type_val = first.gateway_type if first is not None else gateway_asset.type  # type: ignore[union-attr]
            inst_pol_val = first.installed_access_policy if first is not None else None
            pkgs_val = list(first.policy_packages) if first is not None else []
            existing_if_cidrs = {(e.interface_name, e.cidr_or_range) for e in filtered}
            for (if_name, cidr_str), ann in sorted(ann_by_if_cidr.items()):
                if ann.disposition != "manual" or if_name == "*" or cidr_str == "*":
                    continue
                if (if_name, cidr_str) in existing_if_cidrs:
                    continue
                bounds = cls._parse_cidr_or_range_bounds(cidr_str)
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

    @classmethod
    def _score_interface_group(
        cls,
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

        # Find any matching prefix annotation across the matched entries
        matched_ann: TopologyAnnotation | None = None
        for e in matching_entries:
            cand_ann = ann_by_if_cidr.get((if_name, e.cidr_or_range)) or ann_by_if_cidr.get(("*", e.cidr_or_range))
            if cand_ann is not None:
                matched_ann = cand_ann
                break

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
                warnings.append(
                    f"Interface {if_name!r} static topology is marked untrusted (trust_static_topology=False)."
                )
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
                else [
                    e for e in all_gw_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"
                ]
            )
            other_live_routes = [
                e for e in live_pool if e.interface_name != if_name and e.ip_first_int <= q_lo and q_hi <= e.ip_last_int
            ]
            if not has_live_on_this_if and "manual" not in src_types:
                if other_live_routes:
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
                        if e.source_type in ("interface_connected", "interface_specific")
                        and e.topology_zone == "internal"
                    ]
                )
                other_static_entries = [
                    e
                    for e in static_pool
                    if e.interface_name != if_name
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

    @traced
    async def export_topology_prefixes(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
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
            await self.refresh_topology(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                gateways=eff_gateways if cache_mode == "force" else None,
                include_global=domain == "Global",
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        topo_entries = await self._cache.get_gateway_topology(mgmt_name=mgmt_name, domain_name=domain)
        annotations = await self._cache.get_topology_annotations(mgmt_name=mgmt_name, domain_name=domain)
        gw_tokens = set(self._normalize_gateway_filter_tokens(eff_gateways))

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

        weights = self._settings.topology_confidence_weights
        exported: list[ExportedTopologyPrefix] = []

        for gw_key, raw_gw_entries in sorted(entries_by_gw.items()):
            gw_anns = anns_by_gw.get(gw_key, [])
            (
                eff_entries,
                has_live,
                ann_by_if_cidr,
                ann_by_if_wild,
                gw_trust_static,
                if_trust_static,
            ) = self._build_effective_gateway_entries(
                raw_gw_entries,
                gw_anns,
            )
            internal_live = [
                e for e in eff_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"
            ]
            internal_static = [
                e
                for e in eff_entries
                if e.source_type in ("interface_connected", "interface_specific") and e.topology_zone == "internal"
            ]
            source_pool = raw_gw_entries if include_ignored else eff_entries
            grouped: dict[tuple[str, str], list[GatewayTopologyEntry]] = defaultdict(list)
            for e in source_pool:
                if not include_external and e.topology_zone == "external":
                    continue
                grouped[(e.interface_name, e.cidr_or_range)].append(e)

            for (if_name, cidr_str), group in sorted(grouped.items()):
                best_e, conf, is_standby, deltas, _ = self._score_interface_group(
                    if_name=if_name,
                    matching_entries=group,
                    all_gw_entries=eff_entries,
                    has_live_routes=has_live,
                    ann_by_if_cidr=ann_by_if_cidr,
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
        *,
        has_live_routes: bool = False,
        ann_by_if_cidr: dict[tuple[str, str], TopologyAnnotation] | None = None,
        weights: TopologyConfidenceWeights | None = None,
        gw_trust_static: bool | None = None,
        if_trust_static: dict[str, bool] | None = None,
        internal_live_entries: Sequence[GatewayTopologyEntry] | None = None,
        internal_static_entries: Sequence[GatewayTopologyEntry] | None = None,
    ) -> list[_InterfaceMatch]:
        """Resolve `endpoint` to matching gateway interfaces with Evidence Delta Confidence Scoring."""
        q_lo = endpoint.ip_first_int
        q_hi = endpoint.ip_last_int
        eff_anns = ann_by_if_cidr or {}
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
                best_e, conf, is_standby, deltas, warns = cls._score_interface_group(
                    if_name=if_name,
                    matching_entries=if_entries,
                    all_gw_entries=gw_entries,
                    has_live_routes=has_live_routes,
                    ann_by_if_cidr=eff_anns,
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
                best_if_entry, conf, is_standby, deltas, warns = cls._score_interface_group(
                    if_name=if_name,
                    matching_entries=by_if[if_name],
                    all_gw_entries=gw_entries,
                    has_live_routes=has_live_routes,
                    ann_by_if_cidr=eff_anns,
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

        fully_covered_internally = bool(overlapping_internal) and cls._is_range_covered_by_intervals(
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
                ext = (
                    default_live_ext[0] if default_live_ext else (static_ext[0] if static_ext else external_entries[0])
                )
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

    async def _resolve_gateway_policy_metadata(
        self,
        mgmt_name: str,
        domain_name: str,
        asset: Asset | None,
        gateway_uid: str,
        gateway_name: str,
        all_assets: Sequence[Asset] | None = None,
    ) -> tuple[str | None, list[str], list[str]]:
        """Resolve `(installed_access_policy, policy_packages, access_layers)` for a single gateway/cluster."""
        candidates: list[tuple[int, int, str]] = []
        if asset is not None:
            candidates.extend(_extract_policy_candidates_from_raw(asset.raw_data, priority=2))
            if all_assets:
                member_uid_set = set(asset.member_uids)
                member_asset_id_set = set(asset.member_asset_ids)
                for other in all_assets:
                    if other.uid == asset.uid:
                        continue
                    if (
                        other.uid in member_uid_set
                        or other.asset_id in member_asset_id_set
                        or other.parent_uid == asset.uid
                        or other.parent_id == asset.id
                        or other.parent_asset_id == asset.asset_id
                    ):
                        candidates.extend(_extract_policy_candidates_from_raw(other.raw_data, priority=1))

        installed_policy: str | None = None
        if candidates:
            best = max(candidates, key=lambda item: (item[0], item[1]))
            installed_policy = best[2]

        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain_name)
        packages = extract_policy_packages(snapshot) if (snapshot.package_layers or snapshot.nat_rules) else []

        # Fallback when gateway/cluster asset does not report an installed policy:
        # match ONLY explicit non-"all" gateway installation-targets (or a single-package domain).
        if not installed_policy and packages:
            gw_tokens = {gateway_uid.lower(), gateway_name.lower()}
            if asset is not None:
                gw_tokens.add(asset.id.lower())
                gw_tokens.add(asset.asset_id.lower())

            explicit_matches = []
            for pkg in packages:
                targets = pkg.raw_data.get("installation-targets") or pkg.raw_data.get("installation_targets")
                if isinstance(targets, list):
                    for t in targets:
                        if isinstance(t, str) and t.strip().lower() in gw_tokens:
                            explicit_matches.append(pkg)
                            break
                        if isinstance(t, dict):
                            t_uid = str(t.get("uid") or "").lower()
                            t_name = str(t.get("name") or "").lower()
                            if (t_uid and t_uid in gw_tokens) or (t_name and t_name in gw_tokens):
                                explicit_matches.append(pkg)
                                break

            if explicit_matches:
                best_pkg = max(
                    explicit_matches,
                    key=lambda p: (
                        _extract_timestamp_posix(
                            p.raw_data.get("meta-info", {}).get("last-modify-time")
                            if isinstance(p.raw_data.get("meta-info"), dict)
                            else None
                        ),
                        p.updated_at,
                    ),
                )
                installed_policy = best_pkg.name
            elif len(packages) == 1:
                installed_policy = packages[0].name

        policy_packages: list[str] = [installed_policy] if installed_policy else []
        access_layers: list[str] = []

        if installed_policy and packages:
            for pkg in packages:
                if pkg.name.lower() == installed_policy.lower():
                    installed_policy = pkg.name
                    policy_packages = [pkg.name]
                    for layer_entry in pkg.access_layers:
                        if layer_entry.layer_name not in access_layers:
                            access_layers.append(layer_entry.layer_name)
                    break

        return installed_policy, policy_packages, access_layers

    @traced
    async def find_affected_gateways(
        self,
        sources: Sequence[str] | str,
        destinations: Sequence[str] | str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        min_confidence: float = 0.0,
        include_standby: bool = True,
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
            min_confidence=min_confidence,
            include_standby=include_standby,
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
        annotations = await self._cache.get_topology_annotations(
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

        if not topo_entries and not annotations:
            return []

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

        # Include gateways that have manual annotations even if they had no static/live topology rows
        all_gw_ids = list(dict.fromkeys([*entries_by_gw_id.keys(), *anns_by_gw_id.keys()]))

        # Pre-group objects by (mgmt_name, domain_name) and cache resolved endpoint intervals per domain
        objs_by_mgmt_dom: dict[tuple[str, str], list[CPObject]] = defaultdict(list)
        for obj in all_objects:
            objs_by_mgmt_dom[(obj.mgmt_name, obj.domain_name)].append(obj)

        resolved_endpoints_by_dom: dict[
            tuple[str, str],
            tuple[list[_ResolvedEndpointInterval], list[_ResolvedEndpointInterval]],
        ] = {}

        weights = self._settings.topology_confidence_weights
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
            ) = self._build_effective_gateway_entries(
                raw_gw_entries,
                gw_anns,
                gateway_asset=gw_asset,
            )
            if not gw_entries:
                continue

            internal_live = [
                e for e in gw_entries if e.source_type in LIVE_ROUTE_SOURCES and e.topology_zone == "internal"
            ]
            internal_static = [
                e
                for e in gw_entries
                if e.source_type in ("interface_connected", "interface_specific") and e.topology_zone == "internal"
            ]

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
                src_matches = self._locate_intervals_on_gateway(
                    src_ep,
                    gw_entries,
                    external_if_names,
                    has_live_routes=has_live_routes,
                    ann_by_if_cidr=ann_by_if_cidr,
                    weights=weights,
                    gw_trust_static=gw_trust_static,
                    if_trust_static=if_trust_static,
                    internal_live_entries=internal_live,
                    internal_static_entries=internal_static,
                )
                if not src_matches:
                    continue
                for dst_ep in dst_intervals:
                    dst_matches = self._locate_intervals_on_gateway(
                        dst_ep,
                        gw_entries,
                        external_if_names,
                        has_live_routes=has_live_routes,
                        ann_by_if_cidr=ann_by_if_cidr,
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
                            if flow_conf < min_confidence:
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

            if not matched_flows:
                continue

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

            installed_pol, pkg_names, layer_names = await self._resolve_gateway_policy_metadata(
                gw_mgmt,
                gw_dom,
                gw_asset,
                first_entry.gateway_uid,
                first_entry.gateway_name,
                all_assets=assets_by_dom.get((gw_mgmt, gw_dom), []),
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
                    matched_sources=matched_sources,
                    matched_destinations=matched_destinations,
                    matched_flows=matched_flows,
                    confidence=gw_conf,
                    is_standby_path=gw_standby,
                    confidence_factors=gw_factors,
                    warnings=gw_warns,
                )
            )

        candidates.sort(
            key=lambda c: (
                0 if "internal_to_internal" in c.match_types else 1,
                1 if c.is_standby_path else 0,
                -c.confidence,
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
