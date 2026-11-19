"""Shared constants, IO helpers, specs, and build context for the enterprise raw dataset generator."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

import platformdirs

DATASET_VERSION = "1.2.0"
DEFAULT_SEED = 20261108

USER_DOMAINS: tuple[str, ...] = (
    "Branch",
    "Regional",
    "WAN_Core",
    "Perimeter",
    "Transit",
    "DC_Spine",
    "DC_Pod",
    "DB_Seg",
    "Partner_DMZ",
)
ALL_DOMAINS: tuple[str, ...] = ("Global", *USER_DOMAINS)

_REPO_ROOT_CANDIDATE = Path(__file__).resolve().parents[3]
DEFAULT_DATASET_DIR = (
    _REPO_ROOT_CANDIDATE / "tests" / "fixtures" / "enterprise_raw_dataset"
    if (_REPO_ROOT_CANDIDATE / "pyproject.toml").is_file()
    else Path(platformdirs.user_cache_dir("arodonata")) / "enterprise_raw_dataset"
)

DOMAIN_PKG_NAMES: dict[str, str] = {
    "Global": "Global_Standard_Pkg",
    "Branch": "Branch_Standard_Pkg",
    "Regional": "Regional_Hub_Pkg",
    "WAN_Core": "WAN_Core_Transit_Pkg",
    "Perimeter": "Perimeter_Edge_Pkg",
    "Transit": "Transit_Interconnect_Pkg",
    "DC_Spine": "DC_Spine_VS_Pkg",
    "DC_Pod": "DC_Pod_Tier_Pkg",
    "DB_Seg": "DB_Vault_Seg_Pkg",
    "Partner_DMZ": "Partner_DMZ_Pkg",
}

POLICY_GW_TYPES: frozenset[str] = frozenset(
    {
        "simple-gateway",
        "simple-cluster",
        "CpmiGatewayCluster",
        "virtual-system",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    }
)

GLOBAL_DOMAIN_META_RAW: dict[str, str] = {
    "uid": "uid-dom-global",
    "name": "Global",
    "domain-type": "global domain",
}

RULE_104_GLOBAL_UIDS: tuple[str, ...] = (
    "uid-glob-grp-branches",
    "uid-glob-host-001",
    "uid-glob-grp-dc",
    "uid-global-svc-udp-53",
    "uid-global-svc-tcp-53",
)


def write_json(path: Path, data: Any) -> None:
    """Serialize `data` as pretty JSON with trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    """Write UTF-8 text content to `path`, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def encode_task_payload(task_id: str, node_name: str, stdout: str, *, status: str = "succeeded") -> dict[str, Any]:
    """Build a Check Point `show-task` JSON payload with Base64-encoded CLI stdout."""
    b64_msg = base64.b64encode(stdout.encode("utf-8")).decode("ascii")
    return {
        "tasks": [
            {
                "task-id": task_id,
                "task-name": f"arodonata-route-collect-{node_name}",
                "status": status,
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [
                    {
                        "uid": f"td-{task_id}",
                        "gatewayId": node_name,
                        "statusCode": status,
                        "statusDescription": status,
                        "responseMessage": b64_msg,
                        "responseError": "",
                    }
                ],
            }
        ]
    }


def make_cli_output(ip_routes: list[str], clish_routes: list[str] | None = None) -> str:
    """Render delimited `ip -4 route show` and optional `clish -c "show route"` CLI output."""
    parts = [
        "===ARODONATA_IP_ROUTE_START===",
        *ip_routes,
        "===ARODONATA_IP_ROUTE_END===",
    ]
    if clish_routes is not None:
        parts.extend(
            [
                "===ARODONATA_CLISH_ROUTE_START===",
                "Codes: C - Connected, S - Static, R - RIP, B - BGP, O - OSPF, I - IS-IS, A - Aggregate, K - Kernel",
                *clish_routes,
                "===ARODONATA_CLISH_ROUTE_END===",
            ]
        )
    return "\n".join(parts) + "\n"


def make_internal_if(name: str, ip_addr: str) -> dict[str, Any]:
    """Build a standard anti-spoofing-enabled internal gateway interface dictionary."""
    return {
        "name": name,
        "ipv4-address": ip_addr,
        "ipv4-mask-length": 24,
        "topology": "internal",
        "topology-settings": {
            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
        },
        "anti-spoofing": True,
        "anti-spoofing-settings": {"action": "prevent"},
    }


class ExtraGatewaySpec(NamedTuple):
    """Descriptor for an extra standalone simple gateway."""

    domain: str
    name: str
    host_id: int


class ExtraClusterSpec(NamedTuple):
    """Descriptor for an extra HA cluster and its two cluster members."""

    domain: str
    name: str
    m1_name: str
    m2_name: str
    base: int
    internal_only: bool = False


class ExtraVsxHostSpec(NamedTuple):
    """Descriptor for an extra physical VSX chassis host."""

    domain: str
    name: str
    mgmt_ip: str
    wrp_idx: int


class ExtraVsSpec(NamedTuple):
    """Descriptor for an extra local or cross-domain Virtual System."""

    host_name: str
    domain: str
    name: str
    vsid: int
    internal_only: bool = False


def _domain_buckets() -> dict[str, list[dict[str, Any]]]:
    return {d: [] for d in ALL_DOMAINS}


def _domain_dicts() -> dict[str, dict[str, dict[str, Any]]]:
    return {d: {} for d in ALL_DOMAINS}


@dataclass
class DatasetBuildContext:
    """Mutable per-domain accumulators shared across deterministic dataset generation stages."""

    domains_raw: list[dict[str, Any]] = field(default_factory=list)
    global_domain_raw: dict[str, Any] = field(default_factory=dict)
    domain_sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    gateways_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    simple_gw_details: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
    simple_cl_details: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
    generic_by_class: dict[str, dict[str, list[dict[str, Any]]]] = field(
        default_factory=lambda: {d: {} for d in ALL_DOMAINS}
    )
    generic_by_uid: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)

    hosts_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    networks_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    ranges_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    groups_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    dns_domains_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)

    services_tcp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    services_udp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    services_icmp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    service_groups_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)

    packages_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    access_layers_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
    access_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
    nat_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)

    cli_outputs: dict[tuple[str, int | None], str] = field(default_factory=dict)
    vsx_stat_lines_by_host: dict[str, list[str]] = field(default_factory=dict)
    vsx_stat_outputs: dict[str, str] = field(default_factory=dict)
    chassis1_vs_uids: list[str] = field(default_factory=list)
    chassis2_vs_uids: list[str] = field(default_factory=list)

    def init_vsx_stat(self, host_name: str) -> None:
        """Initialize `vsx stat -l` output buffer for VSX chassis `host_name`."""
        self.vsx_stat_lines_by_host[host_name] = [
            "VSX Gateway Status",
            "==================",
            "VSID:            0",
            f"Name:            {host_name}",
            "Type:            VSX Gateway",
        ]

    def append_vsx_stat(self, host_name: str, vs_id: int, vs_name: str) -> None:
        """Append a Virtual System entry to `vsx stat -l` output for `host_name`."""
        self.vsx_stat_lines_by_host[host_name].extend(
            [
                "",
                f"VSID:            {vs_id}",
                f"Name:            {vs_name}",
                "Type:            Virtual System",
            ]
        )

    def add_gw(self, domain: str, gw: dict[str, Any], *, full_detail: dict[str, Any] | None = None) -> None:
        """Register a gateway or cluster object across summary, detail, and generic indexes."""
        self.gateways_by_domain[domain].append(gw)
        detail_obj = full_detail if full_detail is not None else gw
        uid = str(gw["uid"])
        g_type = str(gw.get("type") or "")
        if g_type in ("simple-gateway", "gateway", "CpmiGatewayPlain", "CpmiHostCkp"):
            self.simple_gw_details[domain][uid] = detail_obj
        elif g_type in ("simple-cluster", "cluster", "CpmiGatewayCluster"):
            self.simple_cl_details[domain][uid] = detail_obj
        self.generic_by_uid[domain][uid] = detail_obj

    def add_generic(self, domain: str, class_name: str, obj: dict[str, Any]) -> None:
        """Register a generic Check Point object by class name and UID."""
        self.generic_by_class[domain].setdefault(class_name, []).append(obj)
        uid = str(obj.get("uid") or "")
        if uid:
            self.generic_by_uid[domain][uid] = obj
