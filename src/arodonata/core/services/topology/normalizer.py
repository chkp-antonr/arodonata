"""Multi-format Check Point gateway interface, static route, VPN domain, and policy metadata normalization."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from arodonata.core.models.assets import Asset
from arodonata.core.models.topology import AntiSpoofingMode
from arodonata.core.primitives import mask_to_prefix_len
from arodonata.core.services._asset_linking import VSX_CHILD_TYPES, _extract_interfaces_from_generic
from arodonata.core.services.topology._shared import _NormalizedInterface


def _first_present(*values: Any) -> Any:
    """Return the first value that is neither ``None`` nor an empty string."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


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


def _merge_topology_dict(
    topo_dict: dict[str, Any],
    *,
    is_external: bool,
    leads_to_dmz: bool,
    behind_mode: str,
    specific_ref: str | None,
    specific_uid: str | None,
    specific_inline_cidr: str | None,
    extract_inline_cidr: Any,
) -> tuple[bool, bool, str, str | None, str | None, str | None]:
    """Merge Check Point `topology` / `topology-settings` dictionary fields with uniform precedence."""
    if bool(topo_dict.get("leads-to-internet") or topo_dict.get("leads_to_internet")):
        is_external = True
    if bool(topo_dict.get("leads-to-dmz") or topo_dict.get("leads_to_dmz") or topo_dict.get("interface-leads-to-dmz")):
        leads_to_dmz = True
    if not behind_mode:
        behind_mode = str(
            topo_dict.get("ip-address-behind-this-interface")
            or topo_dict.get("ip_address_behind_this_interface")
            or topo_dict.get("netaccess")
            or ""
        ).strip()
    spec_val = (
        topo_dict.get("leads-to-specific-network")
        or topo_dict.get("leads_to_specific_network")
        or topo_dict.get("specific-network")
        or topo_dict.get("specific_network")
        or topo_dict.get("specificGroup")
    )
    if isinstance(spec_val, dict):
        specific_uid = specific_uid or (str(spec_val.get("uid") or "") or None)
        specific_ref = specific_ref or (str(spec_val.get("name") or spec_val.get("uid") or "") or None)
        specific_inline_cidr = specific_inline_cidr or extract_inline_cidr(spec_val)
    elif isinstance(spec_val, str) and spec_val.strip() and not specific_ref:
        specific_ref = spec_val.strip()
    spec_uid_val = (
        topo_dict.get("leads-to-specific-network-uid")
        or topo_dict.get("leads_to_specific_network_uid")
        or topo_dict.get("specific-network-uid")
        or topo_dict.get("specific_network_uid")
    )
    if isinstance(spec_uid_val, str) and spec_uid_val.strip() and not specific_uid:
        specific_uid = spec_uid_val.strip()
    return is_external, leads_to_dmz, behind_mode, specific_ref, specific_uid, specific_inline_cidr


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

    mask_len = mask_to_prefix_len(
        _first_present(
            raw_if.get("ipv4-mask-length"),
            raw_if.get("ipv4_mask_length"),
            raw_if.get("mask-length"),
            raw_if.get("ipv4-network-mask"),
            raw_if.get("ipv4_network_mask"),
            raw_if.get("netmask"),
            raw_if.get("subnet-mask"),
        )
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
            plen = mask_to_prefix_len(
                _first_present(
                    spec_dict.get("mask-length4"),
                    spec_dict.get("mask_length4"),
                    spec_dict.get("mask-length"),
                    spec_dict.get("subnet-mask"),
                    spec_dict.get("netmask"),
                )
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
        is_external, leads_to_dmz, behind_mode, specific_ref, specific_uid, specific_inline_cidr = _merge_topology_dict(
            topo_field,
            is_external=is_external,
            leads_to_dmz=leads_to_dmz,
            behind_mode=behind_mode,
            specific_ref=specific_ref,
            specific_uid=specific_uid,
            specific_inline_cidr=specific_inline_cidr,
            extract_inline_cidr=_extract_inline_cidr,
        )
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
        is_external, leads_to_dmz, behind_mode, specific_ref, specific_uid, specific_inline_cidr = _merge_topology_dict(
            topo_settings,
            is_external=is_external,
            leads_to_dmz=leads_to_dmz,
            behind_mode=behind_mode,
            specific_ref=specific_ref,
            specific_uid=specific_uid,
            specific_inline_cidr=specific_inline_cidr,
            extract_inline_cidr=_extract_inline_cidr,
        )

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


def _normalize_gateway_interfaces(asset: Asset) -> list[_NormalizedInterface]:
    """Extract and normalize all valid `_NormalizedInterface` entries from `asset`."""
    is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
    raw_ifs = list(asset.interfaces) or _extract_interfaces_from_generic(asset.raw_data)
    norm_ifs: list[_NormalizedInterface] = []
    for raw_if in raw_ifs:
        if isinstance(raw_if, dict):
            norm = _normalize_interface(raw_if, is_vs_asset=is_vs)
            if norm is not None:
                norm_ifs.append(norm)
    return norm_ifs


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


_BUILTIN_VPN_DOMAIN_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "none",
        "not-defined",
        "not_defined",
        "not defined",
        "empty",
        "addresses_behind_gw",
        "addresses-behind-gw",
        "all_ip_addresses_behind_gateway_based_on_topology_information",
        "manual",
    }
)

_DISABLED_VPN_DOMAIN_TYPES: frozenset[str] = frozenset(
    {
        "none",
        "not-defined",
        "not_defined",
        "not defined",
        "empty",
        "addresses_behind_gw",
        "addresses-behind-gw",
        "all_ip_addresses_behind_gateway_based_on_topology_information",
    }
)


def _extract_vpn_domain_refs(raw_data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract `(ref_uid, ref_name)` for a gateway or cluster `vpn-domain` (`encryption-domain`)."""
    containers: list[dict[str, Any]] = [raw_data]
    for sub_key in ("vpn", "vpn-settings", "vpn_settings", "vpnSettings"):
        sub = raw_data.get(sub_key)
        if isinstance(sub, dict):
            containers.append(sub)

    for container in containers:
        for type_key in (
            "vpn-domain-type",
            "vpn_domain_type",
            "vpnDomainType",
            "encryption-domain-type",
            "encryption_domain_type",
        ):
            raw_type = container.get(type_key)
            if isinstance(raw_type, str) and raw_type.strip().lower() in _DISABLED_VPN_DOMAIN_TYPES:
                return None, None

    for container in containers:
        for key in (
            "vpn-domain",
            "vpn_domain",
            "vpnDomain",
            "encryption-domain",
            "encryption_domain",
            "encryptionDomain",
            "manual-vpn-domain",
            "manual_vpn_domain",
        ):
            val = container.get(key)
            if isinstance(val, dict):
                owned = val.get("owned-object") or val.get("owned_object")
                if isinstance(owned, dict):
                    merged = dict(val)
                    merged.update(owned)
                    val = merged
                uid = str(val.get("uid") or "").strip() or None
                name = str(val.get("name") or "").strip() or None
                if name and name.lower() in _BUILTIN_VPN_DOMAIN_TOKENS and not uid:
                    continue
                if uid or name:
                    return uid, name
            elif isinstance(val, str) and val.strip():
                clean = val.strip()
                if clean.lower() in _BUILTIN_VPN_DOMAIN_TOKENS:
                    continue
                return None, clean
    return None, None


def _parse_route_destination(route: dict[str, Any]) -> ipaddress.IPv4Network | None:
    """Parse a static route destination into an `IPv4Network` (including `0.0.0.0/0` default routes)."""
    dest_raw = (
        route.get("dest")
        or route.get("destination")
        or route.get("subnet")
        or route.get("subnet4")
        or route.get("address")
        or route.get("network")
    )
    if dest_raw is None:
        if route.get("type") == "default" or route.get("default") is True:
            return ipaddress.IPv4Network("0.0.0.0/0")
        return None

    mask_from_dest: Any = None
    if isinstance(dest_raw, dict):
        mask_from_dest = _first_present(
            dest_raw.get("netmask"),
            dest_raw.get("mask"),
            dest_raw.get("subnet-mask"),
            dest_raw.get("mask-length"),
            dest_raw.get("mask_length"),
            dest_raw.get("mask-length4"),
            dest_raw.get("mask_length4"),
            dest_raw.get("prefix-length"),
        )
        dest_raw = (
            dest_raw.get("ipaddr")
            or dest_raw.get("ipv4-address")
            or dest_raw.get("address")
            or dest_raw.get("subnet")
            or dest_raw.get("subnet4")
            or dest_raw.get("network")
            or ""
        )

    dest_str = str(dest_raw).strip()
    if not dest_str:
        if route.get("type") == "default" or route.get("default") is True:
            return ipaddress.IPv4Network("0.0.0.0/0")
        return None
    if dest_str.lower() == "default" or dest_str == "0.0.0.0/0":
        return ipaddress.IPv4Network("0.0.0.0/0")

    if "/" in dest_str:
        try:
            return ipaddress.IPv4Network(dest_str, strict=False)
        except ValueError:
            return None

    mask_val = _first_present(
        mask_from_dest,
        route.get("mask"),
        route.get("netmask"),
        route.get("subnet-mask"),
        route.get("mask-length"),
        route.get("mask_length"),
        route.get("mask-length4"),
        route.get("mask_length4"),
        route.get("prefix-length"),
    )
    if mask_val is None and dest_str == "0.0.0.0":
        return ipaddress.IPv4Network("0.0.0.0/0")

    plen = mask_to_prefix_len(mask_val)
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
    if isinstance(nh_raw, list) and nh_raw:
        nh_raw = nh_raw[0]

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
