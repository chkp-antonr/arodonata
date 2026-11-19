"""Parsers for Check Point `run-script` task output, Gaia `ip route` / `clish` tables, and topology entry conversion."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from arodonata.core.models.assets import Asset
from arodonata.core.models.common import utc_now
from arodonata.core.models.scripts import decode_base64_task_message
from arodonata.core.models.topology import GatewayCliResult, GatewayTopologyEntry, TopologySourceType, TopologyZone
from arodonata.core.primitives import MAX_IPV4_INT
from arodonata.core.services.topology.route_scripts import (
    ROUTE_LIMIT_MARKER,
    VS_END_MARKER,
    VSX_BUNDLE_END_MARKER,
    VSX_BUNDLE_START_MARKER,
    ParsedCliRoute,
)

_CLISH_PROTOCOL_MAP: dict[str, TopologySourceType] = {
    "C": "connected_route",
    "S": "gaia_static_route",
    "R": "clish_route",
    "B": "bgp_route",
    "O": "ospf_route",
    "A": "clish_route",
    "K": "gaia_static_route",
    "I": "clish_route",
}

_IP_ROUTE_PROTO_MAP: dict[str, TopologySourceType] = {
    "kernel": "connected_route",
    "bgp": "bgp_route",
    "ospf": "ospf_route",
    "rip": "clish_route",
    "routed": "clish_route",
    "gated": "gaia_static_route",
    "static": "gaia_static_route",
    "boot": "gaia_static_route",
    "zebra": "clish_route",
}

_SKIP_IF_NAMES: frozenset[str] = frozenset({"lo", "loopback"})
_SKIP_ROUTE_KEYWORDS: frozenset[str] = frozenset(
    {
        "local",
        "broadcast",
        "unreachable",
        "prohibit",
        "blackhole",
        "throw",
        "nat",
        "multicast",
    }
)

_CLISH_ROUTE_RE = re.compile(
    r"^(?P<code>[CSRBOKAI])\s+"
    r"(?P<dest>\d+\.\d+\.\d+\.\d+(?:/\d+)?|default)\s+"
    r"(?:is\s+directly\s+connected,\s*(?P<conn_if>\S+)"
    r"|via\s+(?P<nh>\d+\.\d+\.\d+\.\d+),\s*(?P<via_if>[^,\s]+))",
    re.IGNORECASE,
)


_VS_START_RE = re.compile(r"^===ARODONATA_VS_START\s+vsid=(?P<vsid>\d+)\s+name=(?P<name>.*?)===$")
_VS_ERROR_RE = re.compile(r"^===ARODONATA_VS_ERROR\s+vsid=\d+\s+name=\S+\s+error=(?P<err>.*?)===$")


@dataclass(slots=True)
class VsxBundleSlice:
    """Parsed Virtual System slice from a zero-argument VSX repository bundle."""

    vsid: int
    vs_name: str
    raw_output: str
    error: str | None = None


def parse_vsx_bundle_output(stdout: str) -> list[VsxBundleSlice]:
    """Parse a multi-VS text bundle emitted by zero-argument `arodonata-collect-routes-v1`."""
    if VSX_BUNDLE_START_MARKER not in stdout:
        return []

    slices: list[VsxBundleSlice] = []
    in_bundle = False
    in_slice = False
    cur_vsid: int = 0
    cur_name: str = ""
    cur_error: str | None = None
    cur_lines: list[str] = []

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line == VSX_BUNDLE_START_MARKER:
            in_bundle = True
            continue
        if not in_bundle:
            continue
        if line == VSX_BUNDLE_END_MARKER:
            if in_slice:
                slices.append(
                    VsxBundleSlice(
                        vsid=cur_vsid,
                        vs_name=cur_name,
                        raw_output="\n".join(cur_lines).strip(),
                        error=cur_error,
                    )
                )
                in_slice = False
            break

        start_match = _VS_START_RE.match(line)
        if start_match:
            if in_slice:
                slices.append(
                    VsxBundleSlice(
                        vsid=cur_vsid,
                        vs_name=cur_name,
                        raw_output="\n".join(cur_lines).strip(),
                        error=cur_error,
                    )
                )
            in_slice = True
            cur_vsid = int(start_match.group("vsid"))
            cur_name = start_match.group("name").strip()
            cur_error = None
            cur_lines = []
            continue

        if line == VS_END_MARKER:
            if in_slice:
                slices.append(
                    VsxBundleSlice(
                        vsid=cur_vsid,
                        vs_name=cur_name,
                        raw_output="\n".join(cur_lines).strip(),
                        error=cur_error,
                    )
                )
                in_slice = False
                cur_vsid = 0
                cur_name = ""
                cur_error = None
                cur_lines = []
            continue

        if in_slice:
            err_match = _VS_ERROR_RE.match(line)
            if err_match:
                cur_error = err_match.group("err").strip()
            cur_lines.append(raw_line)

    return slices


def extract_vs_slice_from_bundle(
    stdout: str,
    *,
    vsid: int | None = None,
    vs_name: str | None = None,
    executor: Literal["ssh", "cprid"] = "cprid",
    base_result: GatewayCliResult | None = None,
) -> GatewayCliResult:
    """Extract a specific Virtual System slice from VSX bundle output, or return original output if not bundled."""
    is_vs = (vsid is not None and int(vsid) > 0) or bool(vs_name and vs_name.strip())
    if VSX_BUNDLE_START_MARKER not in stdout:
        if is_vs:
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=base_result.stderr if base_result else "",
                exit_code=base_result.exit_code if base_result and base_result.exit_code else 1,
                executor=executor,
                error_code="vsx_bundle_missing",
                error_message=(
                    f"Virtual System vsid={vsid} vs_name={vs_name!r} expected VSX bundle output "
                    f"from {executor}, but no VSX bundle start marker was found. The repository script "
                    "may be outdated or failed to detect VSX."
                ),
            )
        if base_result is not None and not base_result.success:
            return base_result
        return GatewayCliResult(success=True, stdout=stdout, executor=executor)

    if VSX_BUNDLE_END_MARKER not in stdout:
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=base_result.stderr if base_result else "",
            exit_code=base_result.exit_code if base_result and base_result.exit_code else 1,
            executor=executor,
            error_code="vsx_bundle_truncated",
            error_message=f"VSX bundle output from {executor} is truncated (missing bundle end marker)",
        )

    slices = parse_vsx_bundle_output(stdout)

    matched: VsxBundleSlice | None = None
    if vsid is not None and int(vsid) > 0:
        target_vsid = int(vsid)
        for s in slices:
            if s.vsid == target_vsid:
                matched = s
                break

    if matched is None and vs_name is not None and vs_name.strip():
        norm_name = vs_name.strip().lower()
        for s in slices:
            if s.vs_name.lower() == norm_name:
                matched = s
                break
        if matched is None and norm_name.startswith("vs_"):
            short_name = norm_name[3:]
            for s in slices:
                if s.vs_name.lower() == short_name:
                    matched = s
                    break

    if matched is None:
        avail = [f"{s.vsid}:{s.vs_name}" for s in slices]
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=base_result.stderr if base_result else "",
            exit_code=base_result.exit_code if base_result and base_result.exit_code else 1,
            executor=executor,
            error_code="vs_not_found_in_bundle",
            error_message=(
                f"Virtual System vsid={vsid} vs_name={vs_name!r} not found in VSX bundle (available: {avail})"
            ),
        )

    if base_result is not None and not base_result.success:
        err_code = base_result.error_code or (matched.error and "vs_context_error") or "vsx_bundle_run_failed"
        err_msg = base_result.error_message or (matched.error if matched else "") or "Underlying run-script task failed"
        return GatewayCliResult(
            success=False,
            stdout=matched.raw_output,
            stderr=base_result.stderr or matched.error or "",
            exit_code=base_result.exit_code or 1,
            executor=executor,
            error_code=err_code,
            error_message=err_msg,
        )

    if matched.error:
        return GatewayCliResult(
            success=False,
            stdout=matched.raw_output,
            stderr=matched.error,
            exit_code=1,
            executor=executor,
            error_code="vs_context_error",
            error_message=f"Virtual System vsid={matched.vsid} ({matched.vs_name}) error: {matched.error}",
        )

    return GatewayCliResult(
        success=True,
        stdout=matched.raw_output,
        stderr="",
        exit_code=0,
        executor=executor,
    )


def decode_cprid_task_output(data: dict[str, Any]) -> tuple[bool, str, str]:
    """Extract and Base64-decode `responseMessage` / `responseError` from Check Point `run-script` / `show-task`."""
    if not isinstance(data, dict):
        return False, "", "Empty task response payload"

    tasks: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        tasks = [t for t in data["tasks"] if isinstance(t, dict)]
    elif "task-details" in data or "status" in data:
        tasks = [data]

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    any_failed = False

    for task in tasks:
        st = str(task.get("status") or "").strip().lower()
        if st and st not in ("succeeded", "ok"):
            any_failed = True
        details = task.get("task-details")
        if isinstance(details, list):
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                resp_msg = detail.get("responseMessage") or detail.get("response-message")
                if isinstance(resp_msg, str) and resp_msg.strip():
                    stdout_parts.append(decode_base64_task_message(resp_msg))
                resp_err = (
                    detail.get("responseError")
                    or detail.get("response-error")
                    or detail.get("fault-message")
                    or detail.get("error-message")
                )
                if isinstance(resp_err, str) and resp_err.strip():
                    stderr_parts.append(decode_base64_task_message(resp_err))
                status_desc = detail.get("statusDescription")
                if isinstance(status_desc, str) and status_desc.strip() and not resp_msg:
                    if st and st not in ("succeeded", "ok"):
                        stderr_parts.append(status_desc.strip())
                    else:
                        stdout_parts.append(status_desc.strip())

    # Direct `responseMessage` at top level (some mocks/versions)
    top_msg = data.get("responseMessage") or data.get("response-message") or data.get("output")
    if isinstance(top_msg, str) and top_msg.strip() and not stdout_parts:
        stdout_parts.append(decode_base64_task_message(top_msg))

    stdout_str = "\n".join(stdout_parts).strip()
    stderr_str = "\n".join(stderr_parts).strip()
    if "_vs_error=" in stdout_str:
        return False, stdout_str, stderr_str or stdout_str
    return not any_failed, stdout_str, stderr_str


def parse_ip_route_show(output: str) -> list[ParsedCliRoute]:
    """Parse Linux/Gaia `ip -4 route show` output into `ParsedCliRoute` items."""
    routes: list[ParsedCliRoute] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("===") or line.startswith("_vs_error=") or line.startswith("#"):
            continue

        tokens = line.split()
        if not tokens:
            continue

        first_tok = tokens[0].lower()
        if first_tok in _SKIP_ROUTE_KEYWORDS:
            continue

        dest_tok = tokens[0]
        if dest_tok.lower() == "default":
            dest_net = ipaddress.IPv4Network("0.0.0.0/0")
        else:
            try:
                if "/" in dest_tok:
                    dest_net = ipaddress.IPv4Network(dest_tok, strict=False)
                else:
                    addr = ipaddress.IPv4Address(dest_tok)
                    dest_net = (
                        ipaddress.IPv4Network("0.0.0.0/0")
                        if str(addr) == "0.0.0.0"
                        else ipaddress.IPv4Network(f"{addr}/32", strict=False)
                    )
            except ValueError:
                continue

        if dest_net.is_loopback or dest_net.is_multicast:
            continue

        dev_name: str | None = None
        via_ip: ipaddress.IPv4Address | None = None
        proto_str = ""
        scope_str = ""

        idx = 1
        while idx < len(tokens):
            tok = tokens[idx].lower()
            if tok == "dev" and idx + 1 < len(tokens):
                dev_name = tokens[idx + 1].strip()
                idx += 2
            elif tok == "via" and idx + 1 < len(tokens):
                try:
                    via_ip = ipaddress.IPv4Address(tokens[idx + 1].strip())
                except ValueError:
                    via_ip = None
                idx += 2
            elif tok == "proto" and idx + 1 < len(tokens):
                proto_str = tokens[idx + 1].strip().lower()
                idx += 2
            elif tok == "scope" and idx + 1 < len(tokens):
                scope_str = tokens[idx + 1].strip().lower()
                idx += 2
            else:
                idx += 1

        if not dev_name or dev_name.lower() in _SKIP_IF_NAMES:
            continue

        if proto_str in _IP_ROUTE_PROTO_MAP:
            src_type = _IP_ROUTE_PROTO_MAP[proto_str]
        elif scope_str == "link" or (via_ip is None and dest_net.prefixlen > 0):
            src_type = "connected_route"
        else:
            src_type = "gaia_static_route"

        routes.append(
            ParsedCliRoute(
                destination=dest_net,
                interface_name=dev_name,
                nexthop=via_ip,
                source_type=src_type,
                protocol_label=proto_str or ("connected" if src_type == "connected_route" else "static"),
            )
        )
    return routes


def parse_clish_show_route(output: str) -> list[ParsedCliRoute]:
    """Parse Gaia `clish -c "show route"` output into `ParsedCliRoute` items."""
    routes: list[ParsedCliRoute] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("===") or line.startswith("Codes:") or line.startswith("_vs_error="):
            continue

        m = _CLISH_ROUTE_RE.match(line)
        if not m:
            continue

        code = m.group("code").upper()
        dest_raw = m.group("dest")
        conn_if = m.group("conn_if")
        nh_raw = m.group("nh")
        via_if = m.group("via_if")

        if dest_raw.lower() == "default" or dest_raw == "0.0.0.0/0" or dest_raw == "0.0.0.0":
            dest_net = ipaddress.IPv4Network("0.0.0.0/0")
        else:
            try:
                dest_net = (
                    ipaddress.IPv4Network(dest_raw, strict=False)
                    if "/" in dest_raw
                    else ipaddress.IPv4Network(f"{dest_raw}/32", strict=False)
                )
            except ValueError:
                continue

        if dest_net.is_loopback or dest_net.is_multicast:
            continue

        if_name = (conn_if or via_if or "").strip().rstrip(",")
        if not if_name or if_name.lower() in _SKIP_IF_NAMES:
            continue

        nh_ip: ipaddress.IPv4Address | None = None
        if nh_raw:
            try:
                nh_ip = ipaddress.IPv4Address(nh_raw)
            except ValueError:
                nh_ip = None

        src_type = _CLISH_PROTOCOL_MAP.get(code, "clish_route")
        routes.append(
            ParsedCliRoute(
                destination=dest_net,
                interface_name=if_name,
                nexthop=nh_ip,
                source_type=src_type,
                protocol_label=f"clish:{code}",
            )
        )
    return routes


def parse_combined_cli_routes_with_status(
    stdout: str,
    *,
    max_routes: int | None = None,
) -> tuple[list[ParsedCliRoute], bool]:
    """Parse combined `ip -4 route show` and `clish -c "show route"` stdout and report whether `max_routes` truncated any entry."""
    ip_section = stdout
    clish_section = ""

    if "===ARODONATA_IP_ROUTE_START===" in stdout:
        after_start = stdout.split("===ARODONATA_IP_ROUTE_START===", 1)[1]
        ip_section = after_start.split("===ARODONATA_IP_ROUTE_END===", 1)[0]

    if "===ARODONATA_CLISH_ROUTE_START===" in stdout:
        after_clish = stdout.split("===ARODONATA_CLISH_ROUTE_START===", 1)[1]
        clish_section = after_clish.split("===ARODONATA_CLISH_ROUTE_END===", 1)[0]
    elif "===ARODONATA_IP_ROUTE_START===" not in stdout:
        clish_section = stdout

    ip_routes = parse_ip_route_show(ip_section)
    clish_routes = parse_clish_show_route(clish_section) if clish_section else []

    by_key: dict[tuple[str, str], ParsedCliRoute] = {}
    eff_max = int(max_routes) if max_routes is not None and int(max_routes) > 0 else None
    truncated = ROUTE_LIMIT_MARKER in stdout
    for r in ip_routes:
        key = (str(r.destination), r.interface_name)
        if eff_max is not None and key not in by_key and len(by_key) >= eff_max:
            truncated = True
            break
        by_key[key] = r

    for cr in clish_routes:
        key = (str(cr.destination), cr.interface_name)
        existing = by_key.get(key)
        if existing is None:
            if eff_max is not None and len(by_key) >= eff_max:
                truncated = True
                continue
            by_key[key] = cr
        elif existing.source_type == "gaia_static_route" and cr.source_type in (
            "bgp_route",
            "ospf_route",
            "clish_route",
        ):
            # Upgrade generic kernel/static route to specific dynamic protocol discovered by clish
            by_key[key] = cr

    return list(by_key.values()), truncated


def parse_combined_cli_routes(
    stdout: str,
    *,
    max_routes: int | None = None,
) -> list[ParsedCliRoute]:
    """Parse combined `ip -4 route show` and `clish -c "show route"` stdout, upgrading protocol specificity from clish when both report the same `(destination, interface)`."""
    routes, _ = parse_combined_cli_routes_with_status(stdout, max_routes=max_routes)
    return routes


def routes_to_topology_entries(
    *,
    gateway_asset: Asset,
    parsed_routes_by_node: dict[str, list[ParsedCliRoute]],
    interface_meta: Mapping[
        str,
        tuple[str | None, int | None, bool, str] | tuple[str | None, int | None, bool, str, bool],
    ],
    installed_access_policy: str | None,
    policy_packages: list[str],
    now: datetime | None = None,
) -> tuple[list[GatewayTopologyEntry], bool, dict[tuple[str, str], list[str]]]:
    """Convert per-node `ParsedCliRoute` lists into `GatewayTopologyEntry` rows and detect cluster member drift.

    Returns `(entries, member_drift_detected, drift_map)` where `drift_map` maps `(interface_name, cidr_or_range)`
    to the subset of cluster node names that reported the route whenever not all nodes reported it.
    """
    ts = now or utc_now()
    node_names = sorted(parsed_routes_by_node.keys())
    total_nodes = len(node_names)

    # Group by (interface_name, cidr_str) -> list of (node_name, ParsedCliRoute)
    by_if_cidr: dict[tuple[str, str], list[tuple[str, ParsedCliRoute]]] = {}
    for node_name in node_names:
        for r in parsed_routes_by_node[node_name]:
            key = (r.interface_name, str(r.destination))
            by_if_cidr.setdefault(key, []).append((node_name, r))

    entries: list[GatewayTopologyEntry] = []
    drift_map: dict[tuple[str, str], list[str]] = {}
    member_drift_detected = False

    for (if_name, cidr_str), node_route_pairs in sorted(by_if_cidr.items()):
        present_nodes = sorted({n for n, _ in node_route_pairs})
        sample_route = node_route_pairs[0][1]
        dest_net = sample_route.destination
        is_default = dest_net.prefixlen == 0 and int(dest_net.network_address) == 0

        # Do not flag connected interface subnet mismatches across cluster member physical IPs if they share the same CIDR,
        # only flag when a prefix is missing on one or more cluster members.
        if total_nodes > 1 and len(present_nodes) < total_nodes:
            member_drift_detected = True
            drift_map[(if_name, cidr_str)] = present_nodes

        meta_val = interface_meta.get(if_name)
        if meta_val is None:
            if_ip, if_mask, leads_dmz, anti_spoof, is_ext_if = None, None, False, "unknown", False
        elif len(meta_val) == 5:
            if_ip, if_mask, leads_dmz, anti_spoof, is_ext_if = meta_val
        else:
            if_ip, if_mask, leads_dmz, anti_spoof = meta_val
            is_ext_if = False

        zone: TopologyZone = "external" if (is_default or is_ext_if) else "internal"

        nh_part = f"nexthop:{sample_route.nexthop}" if sample_route.nexthop is not None else sample_route.protocol_label
        if total_nodes > 1:
            members_tag = ",".join(present_nodes)
            drift_tag = f";drift:{len(present_nodes)}/{total_nodes}" if len(present_nodes) < total_nodes else ""
            src_ref = f"{nh_part};members:{members_tag}{drift_tag}"
        else:
            src_ref = nh_part

        entries.append(
            GatewayTopologyEntry(
                mgmt_name=gateway_asset.mgmt_name,
                domain_name=gateway_asset.domain_name,
                gateway_id=gateway_asset.id,
                gateway_asset_id=gateway_asset.asset_id,
                gateway_uid=gateway_asset.uid,
                gateway_name=gateway_asset.name,
                gateway_type=gateway_asset.type,
                interface_name=if_name,
                interface_ipv4=if_ip,
                interface_mask_length=if_mask,
                topology_zone=zone,
                leads_to_dmz=leads_dmz,
                anti_spoofing_mode=anti_spoof,  # type: ignore[arg-type]
                source_type=sample_route.source_type,
                source_ref=src_ref,
                cidr_or_range="0.0.0.0/0" if is_default else str(dest_net),
                ip_first_int=0 if is_default else int(dest_net.network_address),
                ip_last_int=MAX_IPV4_INT if is_default else int(dest_net.broadcast_address),
                prefix_len=0 if is_default else dest_net.prefixlen,
                installed_access_policy=installed_access_policy,
                policy_packages=list(policy_packages),
                updated_at=ts,
            )
        )

    return entries, member_drift_detected, drift_map


__all__ = [
    "VsxBundleSlice",
    "decode_cprid_task_output",
    "extract_vs_slice_from_bundle",
    "parse_clish_show_route",
    "parse_combined_cli_routes",
    "parse_combined_cli_routes_with_status",
    "parse_ip_route_show",
    "parse_vsx_bundle_output",
    "routes_to_topology_entries",
]
