"""Deterministic enterprise raw dataset generator for Check Point MDSM API & CLI replay testing.

Generates `tests/fixtures/enterprise_raw_dataset/` with fixed seed (`20261108`) containing:
- 9 user MDSM domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`,
  `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- 276 policy-enforcing gateways (286 total assets including cluster members and physical VSX chassis).
- 2,600+ network and service objects across domains, including 7-level nested object groups and address ranges.
- 1,050+ access and NAT rules across domain and Global policy packages with sections and inline layers.
- Raw CLI routing outputs (`ip -4 route show`, `clish -c "show route"`, `vsx stat -l`) covering
  `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP, and cluster member drift.
- Base64-encoded `run-script` / `show-task` JSON payloads for `cprid` fallback verification.
"""

from __future__ import annotations

import base64
import json
import random
import shutil
from pathlib import Path
from typing import Any

import platformdirs

DATASET_VERSION = "1.0.0"
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


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _encode_task_payload(task_id: str, node_name: str, stdout: str, *, status: str = "succeeded") -> dict[str, Any]:
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


def _make_cli_output(ip_routes: list[str], clish_routes: list[str] | None = None) -> str:
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


def generate_enterprise_raw_dataset(
    output_dir: Path | str | None = None,
    *,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    """Generate the complete raw Check Point MDSM API and CLI dataset on disk and return its manifest."""
    root = Path(output_dir) if output_dir is not None else DEFAULT_DATASET_DIR
    rng = random.Random(seed)

    # Per-domain accumulators
    domains_raw: list[dict[str, Any]] = []
    domain_sessions: dict[str, dict[str, Any]] = {}
    gateways_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    simple_gw_details: dict[str, dict[str, dict[str, Any]]] = {d: {} for d in ALL_DOMAINS}
    simple_cl_details: dict[str, dict[str, dict[str, Any]]] = {d: {} for d in ALL_DOMAINS}
    generic_by_class: dict[str, dict[str, list[dict[str, Any]]]] = {d: {} for d in ALL_DOMAINS}
    generic_by_uid: dict[str, dict[str, dict[str, Any]]] = {d: {} for d in ALL_DOMAINS}

    hosts_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    networks_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    ranges_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    groups_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    dns_domains_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}

    services_tcp_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    services_udp_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    services_icmp_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    service_groups_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}

    packages_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    access_layers_by_domain: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DOMAINS}
    access_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = {d: {} for d in ALL_DOMAINS}
    nat_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = {d: {} for d in ALL_DOMAINS}

    cli_outputs: dict[tuple[str, int | None], str] = {}
    vsx_stat_outputs: dict[str, str] = {}

    def _add_gw(domain: str, gw: dict[str, Any], *, full_detail: dict[str, Any] | None = None) -> None:
        gateways_by_domain[domain].append(gw)
        detail_obj = full_detail if full_detail is not None else gw
        uid = str(gw["uid"])
        g_type = str(gw.get("type") or "")
        if g_type in ("simple-gateway", "gateway", "CpmiGatewayPlain", "CpmiHostCkp"):
            simple_gw_details[domain][uid] = detail_obj
        elif g_type in ("simple-cluster", "cluster", "CpmiGatewayCluster"):
            simple_cl_details[domain][uid] = detail_obj
        generic_by_uid[domain][uid] = detail_obj

    def _add_generic(domain: str, class_name: str, obj: dict[str, Any]) -> None:
        generic_by_class[domain].setdefault(class_name, []).append(obj)
        uid = str(obj.get("uid") or "")
        if uid:
            generic_by_uid[domain][uid] = obj

    # ------------------------------------------------------------------
    # 1. MDSM Domains & Published Sessions
    # ------------------------------------------------------------------
    for idx, dom_name in enumerate(USER_DOMAINS, start=1):
        cma_ip = f"10.250.1.{10 + idx}"
        standby_ip = f"10.250.2.{10 + idx}"
        domains_raw.append(
            {
                "uid": f"uid-dom-{dom_name.lower()}",
                "name": dom_name,
                "type": "domain",
                "domain-type": "domain",
                "servers": [
                    {
                        "name": f"{dom_name.lower()}-cma-primary",
                        "ipv4-address": cma_ip,
                        "multi-domain-server": {
                            "uid": "uid-mds-primary",
                            "name": "mds-ent-primary",
                            "ipv4-address": "10.250.0.10",
                        },
                        "active": True,
                    },
                    {
                        "name": f"{dom_name.lower()}-cma-standby",
                        "ipv4-address": standby_ip,
                        "multi-domain-server": {
                            "uid": "uid-mds-standby",
                            "name": "mds-ent-standby",
                            "ipv4-address": "10.250.0.11",
                        },
                        "active": False,
                    },
                ],
            }
        )

    global_domain_raw = {
        "uid": "uid-dom-global",
        "name": "Global",
        "type": "global",
        "domain-type": "global domain",
        "servers": [
            {
                "name": "global-cma-primary",
                "ipv4-address": "10.250.0.10",
                "multi-domain-server": {
                    "uid": "uid-mds-primary",
                    "name": "mds-ent-primary",
                    "ipv4-address": "10.250.0.10",
                },
                "active": True,
            }
        ],
    }

    for idx, dom_name in enumerate(ALL_DOMAINS):
        pub_iso = f"2026-11-08T1{idx}:00:00Z"
        pub_posix = 1794139200000 + idx * 3600000
        sess_uid = f"sess-pub-{dom_name.lower()}-001"
        domain_sessions[dom_name] = {
            "last_published": {
                "uid": sess_uid,
                "name": f"AutoPublish-{dom_name}",
                "user-name": "admin",
                "publish-time": {"posix": pub_posix, "iso-8601": pub_iso},
                "last-modify-time": {"posix": pub_posix, "iso-8601": pub_iso},
                "changes": 0,
                "locks": 0,
                "number-of-published-changes": 12,
            },
            "current_session": {
                "uid": f"sess-ro-{dom_name.lower()}",
                "user-name": "ro-automation",
                "locks": 0,
                "changes": 0,
                "number-of-published-changes": 0,
            },
        }

    # ------------------------------------------------------------------
    # 2. Global Domain Objects, Services, and Global Policy Package
    # ------------------------------------------------------------------
    networks_by_domain["Global"].extend(
        [
            {
                "uid": "uid-glob-net-branches",
                "name": "N_Global_All_Branches",
                "type": "network",
                "subnet4": "10.11.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-glob-net-dc-vault",
                "name": "N_Global_DC_Vault_Super",
                "type": "network",
                "subnet4": "10.220.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-glob-net-rfc1918-10",
                "name": "N_Global_RFC1918_10",
                "type": "network",
                "subnet4": "10.0.0.0",
                "mask-length4": 8,
            },
        ]
    )
    groups_by_domain["Global"].extend(
        [
            {
                "uid": "uid-glob-grp-branches",
                "name": "G_Global_Branch_Supernet",
                "type": "group",
                "members": ["uid-glob-net-branches"],
            },
            {
                "uid": "uid-glob-grp-dc",
                "name": "G_Global_DC_Supernet",
                "type": "group",
                "members": ["uid-glob-net-dc-vault"],
            },
        ]
    )
    for p_idx in range(1, 81):
        hosts_by_domain["Global"].append(
            {
                "uid": f"uid-glob-host-{p_idx:03d}",
                "name": f"H_Global_DNS_{p_idx:03d}",
                "type": "host",
                "ipv4-address": f"10.253.0.{p_idx}",
            }
        )

    # Services in Global and domains
    for dom in ALL_DOMAINS:
        d_slug = dom.lower()
        for port in (22, 53, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9092, 9200):
            services_tcp_by_domain[dom].append(
                {
                    "uid": f"uid-{d_slug}-svc-tcp-{port}",
                    "name": f"TCP_{port}" if dom == "Global" else f"SVC_{dom}_TCP_{port}",
                    "type": "service-tcp",
                    "port": str(port),
                }
            )
        for uport in (53, 123, 161, 500, 514, 1812, 4500):
            services_udp_by_domain[dom].append(
                {
                    "uid": f"uid-{d_slug}-svc-udp-{uport}",
                    "name": f"UDP_{uport}" if dom == "Global" else f"SVC_{dom}_UDP_{uport}",
                    "type": "service-udp",
                    "port": str(uport),
                }
            )
        services_icmp_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-svc-icmp-echo",
                "name": "icmp-proto" if dom == "Global" else f"ICMP_{dom}_Echo",
                "type": "service-icmp",
                "icmp-type": 8,
            }
        )
        service_groups_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-svc-grp-web",
                "name": "G_Web_Services" if dom == "Global" else f"G_{dom}_App_Services",
                "type": "service-group",
                "members": [
                    f"uid-{d_slug}-svc-tcp-80",
                    f"uid-{d_slug}-svc-tcp-443",
                    f"uid-{d_slug}-svc-tcp-8443",
                ],
            }
        )
        dns_domains_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-dns-corp",
                "name": f".{d_slug}.enterprise.internal",
                "type": "dns-domain",
                "is-sub-domain": True,
            }
        )

    # ------------------------------------------------------------------
    # 3. Domain 1: `Branch` (140 gateways: `br-spb-gw-01` + `br-reg-gw-002..140`)
    #    - `br-spb-gw-01` is Hop 1 in the 9-hop chain (`10.11.1.0/24` on `eth1`, `0.0.0.0/0` on `eth0`).
    #    - `br-reg-gw-138..140` are designated for SSH failure -> `cprid` `run-script` fallback!
    # ------------------------------------------------------------------
    for b_idx in range(1, 141):
        gw_name = "br-spb-gw-01" if b_idx == 1 else f"br-reg-gw-{b_idx:03d}"
        gw_uid = f"uid-branch-gw-{b_idx:03d}"
        lan_subnet = f"10.11.{b_idx}.0"
        lan_ip = f"10.11.{b_idx}.1"
        voip_subnet = f"10.12.{b_idx}.0"
        wan_ip = f"172.21.{b_idx // 100}.{b_idx % 100 + 10}"
        wan_nh = f"172.21.{b_idx // 100}.1"

        net_lan_uid = f"uid-br-net-lan-{b_idx:03d}"
        net_voip_uid = f"uid-br-net-voip-{b_idx:03d}"
        host_prn_uid = f"uid-br-host-srv-{b_idx:03d}"
        networks_by_domain["Branch"].extend(
            [
                {
                    "uid": net_lan_uid,
                    "name": f"N_Branch_{b_idx:03d}_LAN",
                    "type": "network",
                    "subnet4": lan_subnet,
                    "mask-length4": 24,
                },
                {
                    "uid": net_voip_uid,
                    "name": f"N_Branch_{b_idx:03d}_VoIP",
                    "type": "network",
                    "subnet4": voip_subnet,
                    "mask-length4": 24,
                },
            ]
        )
        hosts_by_domain["Branch"].append(
            {
                "uid": host_prn_uid,
                "name": f"H_Branch_{b_idx:03d}_Server",
                "type": "host",
                "ipv4-address": f"10.11.{b_idx}.10",
            }
        )
        if b_idx <= 30:
            ranges_by_domain["Branch"].append(
                {
                    "uid": f"uid-br-rng-dhcp-{b_idx:03d}",
                    "name": f"R_Branch_{b_idx:03d}_DHCP",
                    "type": "address-range",
                    "ipv4-address-first": f"10.11.{b_idx}.100",
                    "ipv4-address-last": f"10.11.{b_idx}.199",
                }
            )

        gw_obj = {
            "uid": gw_uid,
            "name": gw_name,
            "type": "simple-gateway",
            "ipv4-address": wan_ip,
            "network-security-blades": {"firewall": True},
            "policy": {
                "access-policy-installed": True,
                "access-policy-name": "Branch_Standard_Pkg",
            },
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": wan_ip,
                    "ipv4-mask-length": 24,
                    "topology": "external",
                    "topology-settings": {
                        "leads-to-internet": True,
                    },
                },
                {
                    "name": "eth1",
                    "ipv4-address": lan_ip,
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        "interface-leads-to-dmz": False,
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": f"10.13.{b_idx}.1",
                    "ipv4-mask-length": 30,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by routing",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        }
        _add_gw("Branch", gw_obj)
        cli_outputs[(gw_name, None)] = _make_cli_output(
            ip_routes=[
                f"default via {wan_nh} dev eth0 proto static",
                f"{lan_subnet}/24 dev eth1 proto kernel scope link src {lan_ip}",
                f"{voip_subnet}/24 via 10.13.{b_idx}.2 dev eth2 proto ospf",
            ],
            clish_routes=[
                f"S 0.0.0.0/0 via {wan_nh}, eth0",
                f"C {lan_subnet}/24 is directly connected, eth1",
                f"O {voip_subnet}/24 via 10.13.{b_idx}.2, eth2",
            ],
        )

    # ------------------------------------------------------------------
    # 4. Domain 2: `Regional` (20 gateways: `reg-nw-cluster` + 19 `reg-hub-gw-02..20`)
    #    - `reg-nw-cluster` is Hop 2 in the 9-hop chain (`simple-cluster` with 2 members:
    #      `reg-nw-node-1`, `reg-nw-node-2`).
    #    - Its `eth1` references a 7-level nested group `G_Reg_NW_L1_Root` -> ... -> `G_Reg_NW_L7_Leaf`
    #      which expands to `10.11.1.0/24` .. `10.11.20.0/24` and `10.12.1.0/24` .. `10.12.20.0/24`.
    # ------------------------------------------------------------------
    reg_leaf_member_uids: list[str] = []
    for b_idx in range(1, 21):
        n1_uid = f"uid-reg-net-b-lan-{b_idx:03d}"
        n2_uid = f"uid-reg-net-b-voip-{b_idx:03d}"
        networks_by_domain["Regional"].extend(
            [
                {
                    "uid": n1_uid,
                    "name": f"N_Reg_Branch_{b_idx:03d}_LAN",
                    "type": "network",
                    "subnet4": f"10.11.{b_idx}.0",
                    "mask-length4": 24,
                },
                {
                    "uid": n2_uid,
                    "name": f"N_Reg_Branch_{b_idx:03d}_VoIP",
                    "type": "network",
                    "subnet4": f"10.12.{b_idx}.0",
                    "mask-length4": 24,
                },
            ]
        )
        reg_leaf_member_uids.extend([n1_uid, n2_uid])

    # Build 7-level nested group hierarchy in `Regional`: L7 -> L6 -> L5 -> L4 -> L3 -> L2 -> L1
    groups_by_domain["Regional"].extend(
        [
            {
                "uid": "uid-reg-grp-l7",
                "name": "G_Reg_NW_L7_Leaf",
                "type": "group",
                "members": reg_leaf_member_uids,
            },
            {
                "uid": "uid-reg-grp-l6",
                "name": "G_Reg_NW_L6_SubZone",
                "type": "group",
                "members": ["uid-reg-grp-l7"],
            },
            {
                "uid": "uid-reg-grp-l5",
                "name": "G_Reg_NW_L5_District",
                "type": "group",
                "members": ["uid-reg-grp-l6"],
            },
            {
                "uid": "uid-reg-grp-l4",
                "name": "G_Reg_NW_L4_Metro",
                "type": "group",
                "members": ["uid-reg-grp-l5"],
            },
            {
                "uid": "uid-reg-grp-l3",
                "name": "G_Reg_NW_L3_Province",
                "type": "group",
                "members": ["uid-reg-grp-l4"],
            },
            {
                "uid": "uid-reg-grp-l2",
                "name": "G_Reg_NW_L2_Division",
                "type": "group",
                "members": ["uid-reg-grp-l3"],
            },
            {
                "uid": "uid-reg-grp-l1-root",
                "name": "G_Reg_NW_L1_Root",
                "type": "group",
                "members": ["uid-reg-grp-l2"],
            },
        ]
    )

    reg_node1 = {
        "uid": "uid-reg-nw-node-1",
        "name": "reg-nw-node-1",
        "type": "cluster-member",
        "ipv4-address": "172.22.1.11",
        "cluster-uid": "uid-reg-nw-cluster",
    }
    reg_node2 = {
        "uid": "uid-reg-nw-node-2",
        "name": "reg-nw-node-2",
        "type": "cluster-member",
        "ipv4-address": "172.22.1.12",
        "cluster-uid": "uid-reg-nw-cluster",
    }
    reg_nw_cluster = {
        "uid": "uid-reg-nw-cluster",
        "name": "reg-nw-cluster",
        "type": "simple-cluster",
        "ipv4-address": "172.22.1.10",
        "cluster-members": [reg_node1, reg_node2],
        "policy": {"access-policy-installed": True, "access-policy-name": "Regional_Hub_Pkg"},
        "interfaces": [
            {
                "name": "eth0",
                "ipv4-address": "172.22.1.10",
                "ipv4-mask-length": 24,
                "topology": "external",
            },
            {
                "name": "eth1",
                "ipv4-address": "172.22.101.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "specific",
                    "specific-network": "G_Reg_NW_L1_Root",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
        ],
    }
    _add_gw("Regional", reg_nw_cluster)
    _add_gw("Regional", reg_node1)
    _add_gw("Regional", reg_node2)

    reg_nw_routes = [
        "default via 172.22.1.1 dev eth0 proto static",
        *[f"10.11.{b_i}.0/24 via 172.22.101.254 dev eth1 proto ospf" for b_i in range(1, 21)],
        *[f"10.12.{b_i}.0/24 via 172.22.101.254 dev eth1 proto ospf" for b_i in range(1, 21)],
    ]
    cli_outputs[("reg-nw-node-1", None)] = _make_cli_output(reg_nw_routes)
    cli_outputs[("reg-nw-node-2", None)] = _make_cli_output(reg_nw_routes)

    for r_idx in range(2, 21):
        hub_name = f"reg-hub-gw-{r_idx:02d}"
        hub_uid = f"uid-reg-hub-{r_idx:02d}"
        sub_net = f"10.30.{r_idx}.0"
        networks_by_domain["Regional"].append(
            {
                "uid": f"uid-reg-net-hub-{r_idx:02d}",
                "name": f"N_Reg_Hub_{r_idx:02d}",
                "type": "network",
                "subnet4": sub_net,
                "mask-length4": 24,
            }
        )
        _add_gw(
            "Regional",
            {
                "uid": hub_uid,
                "name": hub_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.22.{r_idx}.10",
                "policy": {"access-policy-installed": True, "access-policy-name": "Regional_Hub_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.22.{r_idx}.10",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": f"10.30.{r_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(hub_name, None)] = _make_cli_output(
            [
                f"default via 172.22.{r_idx}.1 dev eth0 proto static",
                f"{sub_net}/24 dev eth1 proto kernel scope link src 10.30.{r_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 5. Domain 3: `WAN_Core` (15 gateways: `wan-core-ecmp-a`, `wan-core-ecmp-b`,
    #    `wan-core-bgp-standby` + 12 `wan-core-rtr-01..12`)
    #    - Hop 3 in the 9-hop chain: parallel active ECMP gateways (`wan-core-ecmp-a`, `wan-core-ecmp-b`)
    #      and a Standby BGP gateway (`wan-core-bgp-standby`).
    # ------------------------------------------------------------------
    networks_by_domain["WAN_Core"].extend(
        [
            {
                "uid": "uid-wan-net-branches",
                "name": "N_WAN_Branch_Agg",
                "type": "network",
                "subnet4": "10.11.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-wan-net-dc-vault",
                "name": "N_WAN_DC_Vault_Agg",
                "type": "network",
                "subnet4": "10.220.0.0",
                "mask-length4": 16,
            },
        ]
    )
    groups_by_domain["WAN_Core"].extend(
        [
            {
                "uid": "uid-wan-grp-branches",
                "name": "G_WAN_Branches",
                "type": "group",
                "members": ["uid-wan-net-branches"],
            },
            {
                "uid": "uid-wan-grp-dc-target",
                "name": "G_WAN_DC_Target",
                "type": "group",
                "members": ["uid-wan-net-dc-vault"],
            },
        ]
    )

    for leg_idx, leg_suffix in enumerate(("a", "b"), start=1):
        ecmp_name = f"wan-core-ecmp-{leg_suffix}"
        ecmp_uid = f"uid-wan-core-ecmp-{leg_suffix}"
        _add_gw(
            "WAN_Core",
            {
                "uid": ecmp_uid,
                "name": ecmp_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.23.0.{10 + leg_idx}",
                "policy": {"access-policy-installed": True, "access-policy-name": "WAN_Core_Transit_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.23.0.{10 + leg_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "bond0.10",
                        "ipv4-address": f"172.23.10.{leg_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_WAN_Branches",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                    {
                        "name": "bond0.20",
                        "ipv4-address": f"172.23.20.{leg_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_WAN_DC_Target",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        # Include ECMP multi-next-hop lines in `ip -4 route show` and `clish -c "show route"`
        cli_outputs[(ecmp_name, None)] = _make_cli_output(
            ip_routes=[
                "default via 172.23.0.1 dev eth0 proto static",
                "10.11.0.0/16 via 172.23.10.253 dev bond0.10 proto bgp",
                "10.11.0.0/16 via 172.23.10.254 dev bond0.10 proto bgp",
                "10.220.0.0/16 via 172.23.20.253 dev bond0.20 proto bgp",
                "10.220.0.0/16 via 172.23.20.254 dev bond0.20 proto bgp",
            ],
            clish_routes=[
                "S 0.0.0.0/0 via 172.23.0.1, eth0",
                "B 10.11.0.0/16 via 172.23.10.253, bond0.10",
                "B 10.220.0.0/16 via 172.23.20.253, bond0.20",
            ],
        )

    # Standby BGP Gateway (`wan-core-bgp-standby`):
    # Has `10.220.0.0/16` in SmartConsole static topology on `eth2`, but absent from live routing table
    # (will be annotated with `disposition="standby_dynamic"` in Step 4).
    _add_gw(
        "WAN_Core",
        {
            "uid": "uid-wan-core-bgp-standby",
            "name": "wan-core-bgp-standby",
            "type": "simple-gateway",
            "ipv4-address": "172.23.0.30",
            "policy": {"access-policy-installed": True, "access-policy-name": "WAN_Core_Transit_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "172.23.0.30",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "172.23.11.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "G_WAN_Branches",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "172.23.21.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "G_WAN_DC_Target",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        },
    )
    cli_outputs[("wan-core-bgp-standby", None)] = _make_cli_output(
        ip_routes=[
            "default via 172.23.0.1 dev eth0 proto static",
            "10.11.0.0/16 via 172.23.11.254 dev eth1 proto bgp",
        ]
    )

    for w_idx in range(1, 13):
        rtr_name = f"wan-core-rtr-{w_idx:02d}"
        _add_gw(
            "WAN_Core",
            {
                "uid": f"uid-wan-rtr-{w_idx:02d}",
                "name": rtr_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.23.100.{w_idx}",
                "policy": {"access-policy-installed": True, "access-policy-name": "WAN_Core_Transit_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.23.100.{w_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": f"10.40.{w_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(rtr_name, None)] = _make_cli_output(
            [
                "default via 172.23.100.254 dev eth0 proto static",
                f"10.40.{w_idx}.0/24 dev eth1 proto kernel scope link src 10.40.{w_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 6. Domain 4: `Perimeter` (15 gateways: `perim-edge-cluster` + 14 `perim-dmz-gw-01..14`)
    #    - `perim-edge-cluster` is Hop 4 in the 9-hop chain (`CpmiGatewayCluster`).
    #    - In `show-gateways-and-servers`, `perim-edge-cluster` has `interfaces: []` so
    #      `TopologyService` exercises on-demand detail fetch via `show-simple-cluster`!
    #    - References Global groups `G_Global_Branch_Supernet` and `G_Global_DC_Supernet`.
    # ------------------------------------------------------------------
    perim_m1 = {
        "uid": "uid-perim-edge-1a",
        "name": "perim-edge-1a",
        "type": "cluster-member",
        "ipv4-address": "172.24.0.11",
        "cluster-uid": "uid-perim-edge-cluster",
    }
    perim_m2 = {
        "uid": "uid-perim-edge-1b",
        "name": "perim-edge-1b",
        "type": "cluster-member",
        "ipv4-address": "172.24.0.12",
        "cluster-uid": "uid-perim-edge-cluster",
    }
    perim_summary = {
        "uid": "uid-perim-edge-cluster",
        "name": "perim-edge-cluster",
        "type": "CpmiGatewayCluster",
        "ipv4-address": "172.24.0.10",
        "cluster-members": [perim_m1, perim_m2],
        "policy": {"access-policy-installed": True, "access-policy-name": "Perimeter_Edge_Pkg"},
        "interfaces": [],  # Empty in summary to force `show-simple-cluster` on-demand fallback!
    }
    perim_full_detail = {
        **perim_summary,
        "interfaces": [
            {
                "name": "eth0",
                "ipv4-address": "172.24.0.10",
                "ipv4-mask-length": 24,
                "topology": {"leads-to-internet": True},
            },
            {
                "name": "eth1",
                "ipv4-address": "172.24.10.1",
                "ipv4-mask-length": 24,
                "topology": {
                    "leads-to-internet": False,
                    "ip-address-behind-this-interface": "specific",
                    "leads-to-specific-network": "G_Global_Branch_Supernet",
                },
                "anti-spoofing": {"perform-anti-spoofing": True, "action": "prevent"},
            },
            {
                "name": "eth2",
                "ipv4-address": "172.24.20.1",
                "ipv4-mask-length": 24,
                "topology": {
                    "leads-to-internet": False,
                    "ip-address-behind-this-interface": "specific",
                    "leads-to-specific-network": "G_Global_DC_Supernet",
                },
                "anti-spoofing": {"perform-anti-spoofing": True, "action": "prevent"},
            },
        ],
    }
    _add_gw("Perimeter", perim_summary, full_detail=perim_full_detail)
    _add_gw("Perimeter", perim_m1)
    _add_gw("Perimeter", perim_m2)

    perim_routes = [
        "default via 172.24.0.1 dev eth0 proto static",
        "10.11.0.0/16 via 172.24.10.254 dev eth1 proto bgp",
        "10.220.0.0/16 via 172.24.20.254 dev eth2 proto bgp",
    ]
    cli_outputs[("perim-edge-1a", None)] = _make_cli_output(perim_routes)
    cli_outputs[("perim-edge-1b", None)] = _make_cli_output(perim_routes)

    for p_idx in range(1, 15):
        dmz_gw_name = f"perim-dmz-gw-{p_idx:02d}"
        _add_gw(
            "Perimeter",
            {
                "uid": f"uid-perim-dmz-{p_idx:02d}",
                "name": dmz_gw_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.24.100.{p_idx}",
                "policy": {"access-policy-installed": True, "access-policy-name": "Perimeter_Edge_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.24.100.{p_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": f"10.50.{p_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            "interface-leads-to-dmz": True,
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(dmz_gw_name, None)] = _make_cli_output(
            [
                "default via 172.24.100.254 dev eth0 proto static",
                f"10.50.{p_idx}.0/24 dev eth1 proto kernel scope link src 10.50.{p_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 7. Domain 5: `Transit` (13 gateways: `ix-transit-gw-01`, `lpm-matryoshka-gw`,
    #    `anomaly-audit-gw` + 10 `ix-transit-gw-02..11`)
    #    - `ix-transit-gw-01`: Hop 5 in the 9-hop chain (`internal_to_internal` with IS-IS `clish` routes).
    #    - `lpm-matryoshka-gw`: 7 nested prefixes (`/8`, `/12`, `/16`, `/22`, `/24`, `/28`, `/32`) across `eth1..eth7`.
    #    - `anomaly-audit-gw`: `not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`,
    #      `default_route_mismatch`.
    # ------------------------------------------------------------------
    networks_by_domain["Transit"].extend(
        [
            {
                "uid": "uid-tr-net-west",
                "name": "N_Transit_West_10_11",
                "type": "network",
                "subnet4": "10.11.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-tr-net-east",
                "name": "N_Transit_East_10_220",
                "type": "network",
                "subnet4": "10.220.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-tr-net-audit-detect",
                "name": "N_Audit_Detect_Sub",
                "type": "network",
                "subnet4": "10.254.2.0",
                "mask-length4": 24,
            },
            {
                "uid": "uid-lpm-net-8",
                "name": "N_Matryoshka_Slash8",
                "type": "network",
                "subnet4": "10.0.0.0",
                "mask-length4": 8,
            },
            {
                "uid": "uid-lpm-net-12",
                "name": "N_Matryoshka_Slash12",
                "type": "network",
                "subnet4": "10.64.0.0",
                "mask-length4": 12,
            },
            {
                "uid": "uid-lpm-net-16",
                "name": "N_Matryoshka_Slash16",
                "type": "network",
                "subnet4": "10.70.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-lpm-net-22",
                "name": "N_Matryoshka_Slash22",
                "type": "network",
                "subnet4": "10.70.4.0",
                "mask-length4": 22,
            },
            {
                "uid": "uid-lpm-net-24",
                "name": "N_Matryoshka_Slash24",
                "type": "network",
                "subnet4": "10.70.5.0",
                "mask-length4": 24,
            },
            {
                "uid": "uid-lpm-net-28",
                "name": "N_Matryoshka_Slash28",
                "type": "network",
                "subnet4": "10.70.5.16",
                "mask-length4": 28,
            },
        ]
    )
    hosts_by_domain["Transit"].append(
        {
            "uid": "uid-lpm-host-32",
            "name": "H_Matryoshka_Slash32",
            "type": "host",
            "ipv4-address": "10.70.5.20",
        }
    )

    _add_gw(
        "Transit",
        {
            "uid": "uid-ix-transit-gw-01",
            "name": "ix-transit-gw-01",
            "type": "simple-gateway",
            "ipv4-address": "172.25.0.10",
            "policy": {"access-policy-installed": True, "access-policy-name": "Transit_Interconnect_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "172.25.0.10",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "172.25.10.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Transit_West_10_11",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "172.25.20.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Transit_East_10_220",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        },
    )
    cli_outputs[("ix-transit-gw-01", None)] = _make_cli_output(
        ip_routes=[
            "default via 172.25.0.1 dev eth0 proto static",
            "10.11.0.0/16 via 172.25.10.254 dev eth1 proto gated",
            "10.220.0.0/16 via 172.25.20.254 dev eth2 proto gated",
        ],
        clish_routes=[
            "S 0.0.0.0/0 via 172.25.0.1, eth0",
            "I 10.11.0.0/16 via 172.25.10.254, eth1",
            "I 10.220.0.0/16 via 172.25.20.254, eth2",
        ],
    )

    # LPM Matryoshka Gateway (`lpm-matryoshka-gw`):
    # `/8`, `/12`, `/16`, `/22`, `/24`, `/28`, `/32` on `eth1..eth7`
    _add_gw(
        "Transit",
        {
            "uid": "uid-lpm-matryoshka-gw",
            "name": "lpm-matryoshka-gw",
            "type": "simple-gateway",
            "ipv4-address": "198.51.100.1",
            "policy": {"access-policy-installed": True, "access-policy-name": "Transit_Interconnect_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "198.51.100.1",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "172.25.101.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash8",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "172.25.102.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash12",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth3",
                    "ipv4-address": "172.25.103.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash16",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth4",
                    "ipv4-address": "172.25.104.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash22",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth5",
                    "ipv4-address": "172.25.105.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash24",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth6",
                    "ipv4-address": "172.25.106.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Matryoshka_Slash28",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth7",
                    "ipv4-address": "172.25.107.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "H_Matryoshka_Slash32",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        },
    )
    cli_outputs[("lpm-matryoshka-gw", None)] = _make_cli_output(
        ip_routes=[
            "default via 198.51.100.254 dev eth0 proto static",
            "10.0.0.0/8 via 172.25.101.254 dev eth1 proto bgp",
            "10.64.0.0/12 via 172.25.102.254 dev eth2 proto bgp",
            "10.70.0.0/16 via 172.25.103.254 dev eth3 proto ospf",
            "10.70.4.0/22 via 172.25.104.254 dev eth4 proto ospf",
            "10.70.5.0/24 via 172.25.105.254 dev eth5 proto ospf",
            "10.70.5.16/28 via 172.25.106.254 dev eth6 proto static",
            "10.70.5.20/32 via 172.25.107.254 dev eth7 proto static",
        ]
    )

    # Anomaly Audit Gateway (`anomaly-audit-gw`):
    _add_gw(
        "Transit",
        {
            "uid": "uid-anomaly-audit-gw",
            "name": "anomaly-audit-gw",
            "type": "simple-gateway",
            "ipv4-address": "203.0.113.10",
            "policy": {"access-policy-installed": True, "access-policy-name": "Transit_Interconnect_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "203.0.113.10",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "10.254.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "10.254.2.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_Audit_Detect_Sub",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "detect"},
                },
                {
                    "name": "eth3",
                    "ipv4-address": "10.254.3.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "not defined",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth4",
                    "ipv4-address": "10.254.4.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by routing",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth5",
                    "ipv4-address": "10.254.254.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        },
    )
    # Note: default route on `anomaly-audit-gw` points to `eth5` (`internal`) instead of `eth0` (`external`) -> `default_route_mismatch`!
    cli_outputs[("anomaly-audit-gw", None)] = _make_cli_output(
        ip_routes=[
            "default via 10.254.254.254 dev eth5 proto static",
            "10.254.1.0/24 dev eth1 proto kernel scope link src 10.254.1.1",
            "10.254.2.0/24 dev eth2 proto kernel scope link src 10.254.2.1",
            "10.254.254.0/24 dev eth5 proto kernel scope link src 10.254.254.1",
        ]
    )

    for t_idx in range(2, 12):
        tr_name = f"ix-transit-gw-{t_idx:02d}"
        _add_gw(
            "Transit",
            {
                "uid": f"uid-ix-transit-{t_idx:02d}",
                "name": tr_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.25.100.{t_idx}",
                "policy": {"access-policy-installed": True, "access-policy-name": "Transit_Interconnect_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.25.100.{t_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": f"10.80.{t_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(tr_name, None)] = _make_cli_output(
            [
                "default via 172.25.100.254 dev eth0 proto static",
                f"10.80.{t_idx}.0/24 dev eth1 proto kernel scope link src 10.80.{t_idx}.1",
                f"10.81.{t_idx}.0/24 via 10.80.{t_idx}.254 dev eth1 proto routed",
            ],
            clish_routes=[
                "S 0.0.0.0/0 via 172.25.100.254, eth0",
                f"C 10.80.{t_idx}.0/24 is directly connected, eth1",
                f"R 10.81.{t_idx}.0/24 via 10.80.{t_idx}.254, eth1",
            ],
        )

    # ------------------------------------------------------------------
    # 8. Domain 6: `DC_Spine` (2 physical VSX chassis + 15 VS gateways `dc-vsx-spine-vs01..15`)
    #    - `dc-vsx-chassis-01` (`CpmiVsxNetobj`, VS0) hosts `dc-vsx-spine-vs01` (`vsid=1`) in `DC_Spine`
    #      AND cross-domain Virtual Systems in `DC_Pod` (`dc-vs-tier1-web` `vsid=11`, `dc-vs-tier2-app` `vsid=12`,
    #      and `dc-vs-pod-21..45` `vsid=21..45`)!
    #    - `dc-vsx-spine-vs01` is Hop 6 in the 9-hop chain (`wrp0` external via `0.0.0.0/0` `vs_static_route`,
    #      `eth1.100` internal with `10.220.0.0/16` `vs_static_route`).
    # ------------------------------------------------------------------
    chassis1_vs_uids = [
        "uid-dc-vsx-spine-vs01",
        "uid-dc-vs-tier1-web",
        "uid-dc-vs-tier2-app",
        *[f"uid-dc-vs-pod-{p:02d}" for p in range(21, 46)],
    ]
    chassis1_obj = {
        "uid": "uid-dc-vsx-chassis-01",
        "name": "dc-vsx-chassis-01",
        "type": "CpmiVsxNetobj",
        "ipv4-address": "172.26.0.10",
        "virtual-systems": chassis1_vs_uids,
    }
    _add_gw("DC_Spine", chassis1_obj)
    _add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj", chassis1_obj)
    _add_generic(
        "DC_Spine",
        "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
        {
            "uid": "uid-slot0-chassis-01",
            "name": "dc-vsx-chassis-01",
            "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
            "vsid": 0,
            "vsxGateway": "uid-dc-vsx-chassis-01",
        },
    )

    spine_vs01_summary = {
        "uid": "uid-dc-vsx-spine-vs01",
        "name": "dc-vsx-spine-vs01",
        "type": "CpmiVsNetobj",
        "vsid": 1,
        "parent-uid": "uid-dc-vsx-chassis-01",
        "ipv4-address": "10.215.0.1",
        "policy": {"access-policy-installed": True, "access-policy-name": "DC_Spine_VS_Pkg"},
        "interfaces": [],
    }
    spine_vs01_slot = {
        "uid": "uid-slot-spine-vs01",
        "name": "dc-vsx-chassis-01_dc-vsx-spine-vs01",
        "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
        "vsid": 1,
        "vsxGateway": "uid-slot0-chassis-01",
        "targetCustomer": {"name": "DC_Spine", "uid": "uid-dom-dc_spine"},
        "interfaces_installed": [
            {
                "owned-object": {
                    "officialname": "wrp0",
                    "ipaddr": "192.168.250.2",
                    "netmask": "255.255.255.252",
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                }
            },
            {
                "owned-object": {
                    "officialname": "eth1.100",
                    "ipaddr": "10.215.0.1",
                    "netmask": "255.255.255.0",
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                }
            },
        ],
        "routes_installed": [
            {
                "dest_ip": "0.0.0.0",
                "dest_mask": "0.0.0.0",
                "next_hop": "192.168.250.1",
            },
            {
                "dest_ip": "10.220.0.0",
                "dest_mask": "255.255.0.0",
                "next_hop": "10.215.0.2",
            },
        ],
    }
    _add_gw("DC_Spine", spine_vs01_summary)
    _add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", spine_vs01_summary)
    _add_generic("DC_Spine", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj", spine_vs01_slot)
    cli_outputs[("dc-vsx-chassis-01", 1)] = _make_cli_output(
        [
            "default via 192.168.250.1 dev wrp0 proto static",
            "10.215.0.0/24 dev eth1.100 proto kernel scope link src 10.215.0.1",
            "10.220.0.0/16 via 10.215.0.2 dev eth1.100 proto bgp",
        ]
    )

    # Also register cross-domain `CpmiVsSlotObj` entries on `DC_Spine` for `dc-vs-tier1-web` (`vsid=11`) and `dc-vs-tier2-app` (`vsid=12`)
    _add_generic(
        "DC_Spine",
        "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
        {
            "uid": "uid-slot-pod-tier1",
            "name": "dc-vsx-chassis-01_dc-vs-tier1-web",
            "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
            "vsid": 11,
            "vsxGateway": "uid-slot0-chassis-01",
            "targetCustomer": {"name": "DC_Pod", "uid": "uid-dom-dc_pod"},
        },
    )

    # Second VSX chassis `dc-vsx-chassis-02` in `DC_Spine` hosting `dc-vsx-spine-vs02..15` (`vsid=2..15`)
    chassis2_vs_uids = [f"uid-dc-vsx-spine-vs{idx:02d}" for idx in range(2, 16)]
    chassis2_obj = {
        "uid": "uid-dc-vsx-chassis-02",
        "name": "dc-vsx-chassis-02",
        "type": "CpmiVsxNetobj",
        "ipv4-address": "172.26.0.20",
        "virtual-systems": chassis2_vs_uids,
    }
    _add_gw("DC_Spine", chassis2_obj)
    _add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj", chassis2_obj)

    for s_idx in range(2, 16):
        s_vs_name = f"dc-vsx-spine-vs{s_idx:02d}"
        s_vs_uid = f"uid-dc-vsx-spine-vs{s_idx:02d}"
        s_vs_obj = {
            "uid": s_vs_uid,
            "name": s_vs_name,
            "type": "CpmiVsNetobj",
            "vsid": s_idx,
            "parent-uid": "uid-dc-vsx-chassis-02",
            "ipv4-address": f"10.215.{s_idx}.1",
            "policy": {"access-policy-installed": True, "access-policy-name": "DC_Spine_VS_Pkg"},
            "interfaces": [
                {
                    "name": "wrp0",
                    "ipv4-address": f"192.168.250.{s_idx * 4 + 2}",
                    "ipv4-mask-length": 30,
                    "topology": "external",
                },
                {
                    "name": f"eth1.{100 + s_idx}",
                    "ipv4-address": f"10.215.{s_idx}.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        }
        _add_gw("DC_Spine", s_vs_obj)
        _add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", s_vs_obj)
        cli_outputs[("dc-vsx-chassis-02", s_idx)] = _make_cli_output(
            [
                f"default via 192.168.250.{s_idx * 4 + 1} dev wrp0 proto static",
                f"10.215.{s_idx}.0/24 dev eth1.{100 + s_idx} proto kernel scope link src 10.215.{s_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 9. Domain 7: `DC_Pod` (27 Virtual Systems: `dc-vs-tier1-web`, `dc-vs-tier2-app`,
    #    and `dc-vs-pod-21..45` hosted on `dc-vsx-chassis-01`)
    #    - `dc-vs-tier1-web` (`vsid=11`, Hop 7)
    #    - `dc-vs-tier2-app` (NO static `vsid` in object JSON — resolved dynamically via `vsx stat -l` -> `vsid=12`, Hop 8!)
    # ------------------------------------------------------------------
    networks_by_domain["DC_Pod"].append(
        {
            "uid": "uid-dcpod-net-db-vault",
            "name": "N_DC_DB_Vault_Sub",
            "type": "network",
            "subnet4": "10.220.77.0",
            "mask-length4": 24,
        }
    )

    tier1_vs = {
        "uid": "uid-dc-vs-tier1-web",
        "name": "dc-vs-tier1-web",
        "type": "CpmiVsNetobj",
        "vsid": 11,
        "vsx-gateway": {"uid": "uid-dc-vsx-chassis-01", "name": "dc-vsx-chassis-01"},
        "ipv4-address": "10.216.11.1",
        "policy": {"access-policy-installed": True, "access-policy-name": "DC_Pod_Tier_Pkg"},
        "interfaces": [
            {
                "name": "wrp11",
                "ipv4-address": "192.168.251.2",
                "ipv4-mask-length": 30,
                "topology": "external",
            },
            {
                "name": "eth2.11",
                "ipv4-address": "10.216.11.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "specific",
                    "specific-network": "N_DC_DB_Vault_Sub",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
        ],
    }
    _add_gw("DC_Pod", tier1_vs)
    _add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", tier1_vs)
    cli_outputs[("dc-vsx-chassis-01", 11)] = _make_cli_output(
        [
            "default via 192.168.251.1 dev wrp11 proto static",
            "10.216.11.0/24 dev eth2.11 proto kernel scope link src 10.216.11.1",
            "10.220.77.0/24 via 10.216.11.254 dev eth2.11 proto ospf",
        ]
    )

    # `dc-vs-tier2-app`: intentionally omits `vsid` in object JSON so `RouteCollector` builds a
    # `vsx stat -l` resolution script (`vs_name="dc-vs-tier2-app"`) and resolves `vsid=12`!
    tier2_vs = {
        "uid": "uid-dc-vs-tier2-app",
        "name": "dc-vs-tier2-app",
        "type": "CpmiVsNetobj",
        "vsx-gateway": {"uid": "uid-dc-vsx-chassis-01", "name": "dc-vsx-chassis-01"},
        "ipv4-address": "10.216.12.1",
        "policy": {"access-policy-installed": True, "access-policy-name": "DC_Pod_Tier_Pkg"},
        "interfaces": [
            {
                "name": "eth1.12",
                "ipv4-address": "10.216.12.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "specific",
                    "specific-network": "G_Global_Branch_Supernet",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
            {
                "name": "eth2.12",
                "ipv4-address": "10.217.12.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "specific",
                    "specific-network": "N_DC_DB_Vault_Sub",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
        ],
    }
    _add_gw("DC_Pod", tier2_vs)
    _add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", tier2_vs)
    cli_outputs[("dc-vsx-chassis-01", 12)] = _make_cli_output(
        [
            "10.11.0.0/16 via 10.216.12.254 dev eth1.12 proto ospf",
            "10.220.77.0/24 via 10.217.12.254 dev eth2.12 proto ospf",
        ]
    )

    vsx_stat_lines = [
        "VSX Gateway Status",
        "==================",
        "VSID:            0",
        "Name:            dc-vsx-chassis-01",
        "Type:            VSX Gateway",
        "",
        "VSID:            1",
        "Name:            dc-vsx-spine-vs01",
        "Type:            Virtual System",
        "",
        "VSID:            11",
        "Name:            dc-vs-tier1-web",
        "Type:            Virtual System",
        "",
        "VSID:            12",
        "Name:            dc-vs-tier2-app",
        "Type:            Virtual System",
    ]

    for pod_vsid in range(21, 46):
        pod_name = f"dc-vs-pod-{pod_vsid:02d}"
        pod_uid = f"uid-dc-vs-pod-{pod_vsid:02d}"
        pod_cidr = f"10.218.{pod_vsid}.0/24"
        pod_ip = f"10.218.{pod_vsid}.1"
        networks_by_domain["DC_Pod"].append(
            {
                "uid": f"uid-dcpod-net-{pod_vsid:02d}",
                "name": f"N_DC_Pod_{pod_vsid:02d}",
                "type": "network",
                "subnet4": f"10.218.{pod_vsid}.0",
                "mask-length4": 24,
            }
        )
        pod_obj = {
            "uid": pod_uid,
            "name": pod_name,
            "type": "CpmiVsNetobj",
            "vsid": pod_vsid,
            "parent-uid": "uid-dc-vsx-chassis-01",
            "ipv4-address": pod_ip,
            "policy": {"access-policy-installed": True, "access-policy-name": "DC_Pod_Tier_Pkg"},
            "interfaces": [
                {
                    "name": "wrp0",
                    "ipv4-address": f"192.168.252.{pod_vsid}",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": f"eth1.{pod_vsid}",
                    "ipv4-address": pod_ip,
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        }
        _add_gw("DC_Pod", pod_obj)
        _add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", pod_obj)
        cli_outputs[("dc-vsx-chassis-01", pod_vsid)] = _make_cli_output(
            [
                "default via 192.168.252.1 dev wrp0 proto static",
                f"{pod_cidr} dev eth1.{pod_vsid} proto kernel scope link src {pod_ip}",
            ]
        )
        vsx_stat_lines.extend(
            [
                "",
                f"VSID:            {pod_vsid}",
                f"Name:            {pod_name}",
                "Type:            Virtual System",
            ]
        )

    vsx_stat_outputs["dc-vsx-chassis-01"] = "\n".join(vsx_stat_lines) + "\n"

    # ------------------------------------------------------------------
    # 10. Domain 8: `DB_Seg` (15 internal-only segmentation gateways: `db-seg-internal-fw-01..15`)
    #     - Zero `external` interfaces on all 15 gateways (must emit ZERO diagnostic warnings!).
    #     - `db-seg-internal-fw-01` is Hop 9 in the 9-hop chain (`eth1` `10.11.0.0/16` -> `eth2` `10.220.77.0/24`).
    # ------------------------------------------------------------------
    groups_by_domain["DB_Seg"].append(
        {
            "uid": "uid-dbseg-grp-clients",
            "name": "G_DB_Allowed_Clients",
            "type": "group",
            "members": ["G_Global_Branch_Supernet"],
        }
    )
    _add_gw(
        "DB_Seg",
        {
            "uid": "uid-db-seg-fw-01",
            "name": "db-seg-internal-fw-01",
            "type": "simple-gateway",
            "ipv4-address": "10.210.1.1",
            "policy": {"access-policy-installed": True, "access-policy-name": "DB_Vault_Seg_Pkg"},
            "interfaces": [
                {
                    "name": "eth1",
                    "ipv4-address": "10.210.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "G_DB_Allowed_Clients",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "10.220.77.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent"},
                },
            ],
        },
    )
    cli_outputs[("db-seg-internal-fw-01", None)] = _make_cli_output(
        [
            "10.11.0.0/16 via 10.210.1.254 dev eth1 proto static",
            "10.210.1.0/24 dev eth1 proto kernel scope link src 10.210.1.1",
            "10.220.77.0/24 dev eth2 proto kernel scope link src 10.220.77.1",
        ]
    )

    for db_idx in range(2, 16):
        fw_name = f"db-seg-internal-fw-{db_idx:02d}"
        _add_gw(
            "DB_Seg",
            {
                "uid": f"uid-db-seg-fw-{db_idx:02d}",
                "name": fw_name,
                "type": "simple-gateway",
                "ipv4-address": f"10.210.{db_idx}.1",
                "policy": {"access-policy-installed": True, "access-policy-name": "DB_Vault_Seg_Pkg"},
                "interfaces": [
                    {
                        "name": "eth1",
                        "ipv4-address": f"10.210.{db_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": f"10.220.{db_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(fw_name, None)] = _make_cli_output(
            [
                f"10.210.{db_idx}.0/24 dev eth1 proto kernel scope link src 10.210.{db_idx}.1",
                f"10.220.{db_idx}.0/24 dev eth2 proto kernel scope link src 10.220.{db_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 11. Domain 9: `Partner_DMZ` (16 gateways: 10 `partner-onearm-gw-01..10`,
    #     `partner-b2b-cluster` with 2 members, and 5 `partner-ext-gw-01..05`)
    #     - 10 One-Arm gateways -> `one_arm_topology` (`severity="info"`).
    #     - `partner-b2b-cluster` -> `stale_in_topology`, `missing_in_topology`,
    #       `interface_mismatch`, `resolved_by_routing`, and `cluster_member_drift`.
    # ------------------------------------------------------------------
    networks_by_domain["Partner_DMZ"].extend(
        [
            {
                "uid": "uid-part-net-active",
                "name": "N_Partner_B2B_Active",
                "type": "network",
                "subnet4": "172.30.1.0",
                "mask-length4": 24,
            },
            {
                "uid": "uid-part-net-stale",
                "name": "N_Partner_B2B_Stale",
                "type": "network",
                "subnet4": "172.30.2.0",
                "mask-length4": 24,
            },
            {
                "uid": "uid-part-net-rerouted",
                "name": "N_Partner_B2B_Rerouted",
                "type": "network",
                "subnet4": "172.30.3.0",
                "mask-length4": 24,
            },
        ]
    )
    groups_by_domain["Partner_DMZ"].append(
        {
            "uid": "uid-part-grp-b2b-static",
            "name": "G_Partner_B2B_Static",
            "type": "group",
            "members": [
                "uid-part-net-active",
                "uid-part-net-stale",
                "uid-part-net-rerouted",
            ],
        }
    )

    for oa_idx in range(1, 11):
        oa_name = f"partner-onearm-gw-{oa_idx:02d}"
        _add_gw(
            "Partner_DMZ",
            {
                "uid": f"uid-part-onearm-{oa_idx:02d}",
                "name": oa_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.31.{oa_idx}.1",
                "policy": {"access-policy-installed": True, "access-policy-name": "Partner_DMZ_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.31.{oa_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    }
                ],
            },
        )
        cli_outputs[(oa_name, None)] = _make_cli_output(
            [f"172.31.{oa_idx}.0/24 dev eth0 proto kernel scope link src 172.31.{oa_idx}.1"]
        )

    b2b_m1 = {
        "uid": "uid-partner-b2b-1a",
        "name": "partner-b2b-1a",
        "type": "cluster-member",
        "ipv4-address": "172.30.0.11",
        "cluster-uid": "uid-partner-b2b-cluster",
    }
    b2b_m2 = {
        "uid": "uid-partner-b2b-1b",
        "name": "partner-b2b-1b",
        "type": "cluster-member",
        "ipv4-address": "172.30.0.12",
        "cluster-uid": "uid-partner-b2b-cluster",
    }
    b2b_cluster = {
        "uid": "uid-partner-b2b-cluster",
        "name": "partner-b2b-cluster",
        "type": "simple-cluster",
        "ipv4-address": "172.30.0.10",
        "cluster-members": [b2b_m1, b2b_m2],
        "policy": {"access-policy-installed": True, "access-policy-name": "Partner_DMZ_Pkg"},
        "interfaces": [
            {
                "name": "eth0",
                "ipv4-address": "172.30.0.10",
                "ipv4-mask-length": 24,
                "topology": "external",
            },
            {
                "name": "eth1",
                "ipv4-address": "172.30.10.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "specific",
                    "specific-network": "G_Partner_B2B_Static",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
            {
                "name": "eth2",
                "ipv4-address": "172.30.20.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "network defined by routing",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
        ],
    }
    _add_gw("Partner_DMZ", b2b_cluster)
    _add_gw("Partner_DMZ", b2b_m1)
    _add_gw("Partner_DMZ", b2b_m2)

    # `partner-b2b-1a` has `172.30.6.0/24` (drift route), `172.30.5.0/24` (missing in static topology on `eth1`),
    # `172.30.3.0/24` on `eth2` (interface mismatch vs `eth1` in static), and `172.30.4.0/24` on `eth2` (`resolved_by_routing`).
    # `172.30.2.0/24` is absent on both nodes (`stale_in_topology`).
    cli_outputs[("partner-b2b-1a", None)] = _make_cli_output(
        [
            "default via 172.30.0.1 dev eth0 proto static",
            "172.30.10.0/24 dev eth1 proto kernel scope link src 172.30.10.1",
            "172.30.20.0/24 dev eth2 proto kernel scope link src 172.30.20.1",
            "172.30.1.0/24 via 172.30.10.254 dev eth1 proto ospf",
            "172.30.3.0/24 via 172.30.20.254 dev eth2 proto ospf",
            "172.30.4.0/24 via 172.30.20.254 dev eth2 proto bgp",
            "172.30.5.0/24 via 172.30.10.254 dev eth1 proto ospf",
            "172.30.6.0/24 via 172.30.20.254 dev eth2 proto bgp",
        ]
    )
    cli_outputs[("partner-b2b-1b", None)] = _make_cli_output(
        [
            "default via 172.30.0.1 dev eth0 proto static",
            "172.30.10.0/24 dev eth1 proto kernel scope link src 172.30.10.1",
            "172.30.20.0/24 dev eth2 proto kernel scope link src 172.30.20.1",
            "172.30.1.0/24 via 172.30.10.254 dev eth1 proto ospf",
            "172.30.3.0/24 via 172.30.20.254 dev eth2 proto ospf",
            "172.30.4.0/24 via 172.30.20.254 dev eth2 proto bgp",
            "172.30.5.0/24 via 172.30.10.254 dev eth1 proto ospf",
        ]
    )

    for ext_idx in range(1, 6):
        ext_name = f"partner-ext-gw-{ext_idx:02d}"
        _add_gw(
            "Partner_DMZ",
            {
                "uid": f"uid-part-ext-{ext_idx:02d}",
                "name": ext_name,
                "type": "simple-gateway",
                "ipv4-address": f"172.30.100.{ext_idx}",
                "policy": {"access-policy-installed": True, "access-policy-name": "Partner_DMZ_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.30.100.{ext_idx}",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": f"172.30.{110 + ext_idx}.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        cli_outputs[(ext_name, None)] = _make_cli_output(
            [
                "default via 172.30.100.254 dev eth0 proto static",
                f"172.30.{110 + ext_idx}.0/24 dev eth1 proto kernel scope link src 172.30.{110 + ext_idx}.1",
            ]
        )

    # ------------------------------------------------------------------
    # 12. Bulk Enterprise Objects (2,500+ total objects across all domains)
    # ------------------------------------------------------------------
    for d_idx, dom in enumerate(USER_DOMAINS, start=1):
        d_slug = dom.lower()
        # Generate 150 hosts, 60 networks, 20 address ranges, and 25 groups per domain
        dom_host_uids: list[str] = []
        for h_i in range(1, 151):
            h_uid = f"uid-{d_slug}-bulk-host-{h_i:03d}"
            dom_host_uids.append(h_uid)
            hosts_by_domain[dom].append(
                {
                    "uid": h_uid,
                    "name": f"H_{dom}_AppNode_{h_i:03d}",
                    "type": "host",
                    "ipv4-address": f"10.{120 + d_idx}.{h_i // 250}.{h_i % 250 + 1}",
                    "comments": f"Enterprise host #{h_i} in {dom}",
                }
            )
        dom_net_uids: list[str] = []
        for n_i in range(1, 61):
            n_uid = f"uid-{d_slug}-bulk-net-{n_i:03d}"
            dom_net_uids.append(n_uid)
            networks_by_domain[dom].append(
                {
                    "uid": n_uid,
                    "name": f"N_{dom}_Segment_{n_i:03d}",
                    "type": "network",
                    "subnet4": f"10.{140 + d_idx}.{n_i}.0",
                    "mask-length4": 24,
                }
            )
        for r_i in range(1, 21):
            r_uid = f"uid-{d_slug}-bulk-rng-{r_i:03d}"
            ranges_by_domain[dom].append(
                {
                    "uid": r_uid,
                    "name": f"R_{dom}_Pool_{r_i:03d}",
                    "type": "address-range",
                    "ipv4-address-first": f"10.{160 + d_idx}.{r_i}.10",
                    "ipv4-address-last": f"10.{160 + d_idx}.{r_i}.50",
                }
            )
        for g_i in range(1, 26):
            g_uid = f"uid-{d_slug}-bulk-grp-{g_i:03d}"
            sample_members = rng.sample(dom_host_uids, k=5) + rng.sample(dom_net_uids, k=2)
            groups_by_domain[dom].append(
                {
                    "uid": g_uid,
                    "name": f"G_{dom}_TierGroup_{g_i:03d}",
                    "type": "group",
                    "members": sample_members,
                }
            )

    # ------------------------------------------------------------------
    # 13. Policy Packages, Access Rulebases (1,000+ rules), and NAT Rulebases
    # ------------------------------------------------------------------
    domain_pkg_names: dict[str, str] = {
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

    total_access_rules = 0
    total_nat_rules = 0

    for dom in ALL_DOMAINS:
        d_slug = dom.lower()
        pkg_name = domain_pkg_names[dom]
        pkg_uid = f"uid-pkg-{d_slug}"
        layer_uid = f"uid-layer-{d_slug}-security"
        layer_name = f"{pkg_name} Network"

        dom_gw_targets = [
            {"uid": g["uid"], "name": g["name"], "type": g["type"]}
            for g in gateways_by_domain[dom]
            if g.get("type") not in ("cluster-member", "CpmiVsxNetobj")
        ]

        pkg_obj = {
            "uid": pkg_uid,
            "name": pkg_name,
            "type": "package",
            "access": True,
            "nat-policy": True,
            "installation-targets": dom_gw_targets,
            "access-layers": [
                {
                    "uid": layer_uid,
                    "name": layer_name,
                    "type": "access-layer",
                    "position": 1,
                }
            ],
        }
        packages_by_domain[dom].append(pkg_obj)
        access_layers_by_domain[dom].append(
            {
                "uid": layer_uid,
                "name": layer_name,
                "type": "access-layer",
                "firewall": True,
                "applications-and-url-filtering": True,
            }
        )

        # Build 105 access rules per domain (10 domains * 105 = 1,050 access rules!)
        # grouped into 3 sections of 35 rules each, plus `objects-dictionary`.
        obj_dict: list[dict[str, Any]] = [
            {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any", "type": "CpmiAnyObject"},
            {"uid": "6c488338-8eec-4103-ad21-cd461ac2c472", "name": "Accept", "type": "RulebaseAction"},
            {"uid": "6c488338-8eec-4103-ad21-cd461ac2c473", "name": "Drop", "type": "RulebaseAction"},
            {"uid": "598ead32-aa42-4615-90ed-f51a5928d41d", "name": "Log", "type": "Track"},
        ]
        dom_hosts = hosts_by_domain[dom][:30]
        dom_nets = networks_by_domain[dom][:20]
        dom_svcs = services_tcp_by_domain[dom]
        for item in (*dom_hosts, *dom_nets, *dom_svcs):
            obj_dict.append(item)

        sections: list[dict[str, Any]] = []
        rule_num = 1
        for sec_idx in range(1, 4):
            sec_rules: list[dict[str, Any]] = []
            sec_start = rule_num
            for _ in range(35):
                src_obj = (
                    dom_hosts[(rule_num - 1) % len(dom_hosts)]
                    if dom_hosts
                    else {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any"}
                )
                dst_obj = (
                    dom_nets[(rule_num - 1) % len(dom_nets)]
                    if dom_nets
                    else {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any"}
                )
                svc_obj = (
                    dom_svcs[(rule_num - 1) % len(dom_svcs)]
                    if dom_svcs
                    else {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any"}
                )
                act_uid = (
                    "6c488338-8eec-4103-ad21-cd461ac2c473"
                    if rule_num == 105
                    else "6c488338-8eec-4103-ad21-cd461ac2c472"
                )
                sec_rules.append(
                    {
                        "uid": f"uid-arule-{d_slug}-{rule_num:04d}",
                        "name": f"{dom}_Rule_{rule_num:03d}",
                        "type": "access-rule",
                        "rule-number": rule_num,
                        "enabled": True,
                        "source": [src_obj["uid"]],
                        "source-negate": False,
                        "destination": [dst_obj["uid"]],
                        "destination-negate": False,
                        "service": [svc_obj["uid"]],
                        "service-negate": False,
                        "action": act_uid,
                        "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
                        "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "comments": f"Generated enterprise access rule #{rule_num} in {dom}",
                    }
                )
                rule_num += 1
                total_access_rules += 1
            sections.append(
                {
                    "uid": f"uid-asec-{d_slug}-{sec_idx:02d}",
                    "name": f"Section {sec_idx} - {dom} Traffic",
                    "type": "access-section",
                    "from": sec_start,
                    "to": rule_num - 1,
                    "rulebase": sec_rules,
                }
            )

        access_rulebases_by_domain[dom][layer_uid] = {
            "uid": layer_uid,
            "name": layer_name,
            "rulebase": sections,
            "objects-dictionary": obj_dict,
            "from": 1,
            "to": 105,
            "total": 105,
        }

        # Build 12 NAT rules per domain (10 domains * 12 = 120 NAT rules)
        nat_rules: list[dict[str, Any]] = []
        for n_r in range(1, 13):
            orig_src = (
                dom_hosts[(n_r - 1) % len(dom_hosts)]["uid"] if dom_hosts else "97aeb369-9aea-11d5-bd16-0090272ccb30"
            )
            nat_rules.append(
                {
                    "uid": f"uid-nrule-{d_slug}-{n_r:03d}",
                    "name": f"{dom}_NAT_{n_r:03d}",
                    "type": "nat-rule",
                    "rule-number": n_r,
                    "enabled": True,
                    "method": "hide",
                    "original-source": orig_src,
                    "original-destination": "97aeb369-9aea-11d5-bd16-0090272ccb30",
                    "original-service": "97aeb369-9aea-11d5-bd16-0090272ccb30",
                    "translated-source": orig_src,
                    "translated-destination": "97aeb369-9aea-11d5-bd16-0090272ccb30",
                    "translated-service": "97aeb369-9aea-11d5-bd16-0090272ccb30",
                    "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                }
            )
            total_nat_rules += 1

        nat_rulebases_by_domain[dom][pkg_name] = {
            "package": pkg_name,
            "uid": f"nat:{pkg_uid}",
            "rulebase": [
                {
                    "uid": f"uid-nsec-{d_slug}-01",
                    "name": f"{dom} Automatic & Manual NAT",
                    "type": "nat-section",
                    "from": 1,
                    "to": 12,
                    "rulebase": nat_rules,
                }
            ],
            "objects-dictionary": obj_dict,
            "from": 1,
            "to": 12,
            "total": 12,
        }

    # ------------------------------------------------------------------
    # 14. Write All Raw Files to Disk (`tests/fixtures/enterprise_raw_dataset/`)
    # ------------------------------------------------------------------
    for subdir in ("mds", "domains", "cli", "tasks"):
        shutil.rmtree(root / subdir, ignore_errors=True)

    _write_json(
        root / "mds" / "show-domains.json",
        {
            "objects": domains_raw,
            "from": 1,
            "to": len(domains_raw),
            "total": len(domains_raw),
        },
    )
    _write_json(
        root / "mds" / "show-global-domain.json",
        global_domain_raw,
    )
    _write_json(
        root / "mds" / "show-mdss.json",
        {
            "objects": [
                {
                    "uid": "uid-mds-primary",
                    "name": "mds-ent-primary",
                    "type": "mds",
                    "ipv4-address": "10.250.0.10",
                },
                {
                    "uid": "uid-mds-standby",
                    "name": "mds-ent-standby",
                    "type": "mds",
                    "ipv4-address": "10.250.0.11",
                },
            ],
            "from": 1,
            "to": 2,
            "total": 2,
        },
    )

    total_assets_count = 0
    policy_enforcing_count = 0
    total_objects_count = 0
    total_services_count = 0
    policy_gw_types = {
        "simple-gateway",
        "simple-cluster",
        "CpmiGatewayCluster",
        "virtual-system",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    }

    for dom in ALL_DOMAINS:
        dom_dir = root / "domains" / dom
        sess_info = domain_sessions[dom]
        _write_json(dom_dir / "show-last-published-session.json", sess_info["last_published"])
        _write_json(dom_dir / "show-session.json", sess_info["current_session"])
        _write_json(
            dom_dir / "show-sessions.json",
            {
                "objects": [sess_info["last_published"]],
                "from": 1,
                "to": 1,
                "total": 1,
            },
        )

        gws = gateways_by_domain[dom]
        total_assets_count += len(gws)
        policy_enforcing_count += sum(1 for g in gws if str(g.get("type", "")) in policy_gw_types)
        _write_json(
            dom_dir / "show-gateways-and-servers.json",
            {
                "objects": gws,
                "from": 1 if gws else 0,
                "to": len(gws),
                "total": len(gws),
            },
        )
        _write_json(dom_dir / "show-simple-gateway.json", simple_gw_details[dom])
        _write_json(dom_dir / "show-simple-cluster.json", simple_cl_details[dom])
        _write_json(dom_dir / "show-generic-objects.json", generic_by_class[dom])
        _write_json(dom_dir / "show-generic-object.json", generic_by_uid[dom])

        for cmd_name, items in (
            ("show-hosts", hosts_by_domain[dom]),
            ("show-networks", networks_by_domain[dom]),
            ("show-address-ranges", ranges_by_domain[dom]),
            ("show-groups", groups_by_domain[dom]),
            ("show-dns-domains", dns_domains_by_domain[dom]),
        ):
            total_objects_count += len(items)
            _write_json(
                dom_dir / f"{cmd_name}.json",
                {
                    "objects": items,
                    "from": 1 if items else 0,
                    "to": len(items),
                    "total": len(items),
                },
            )

        for svc_cmd, svc_items in (
            ("show-services-tcp", services_tcp_by_domain[dom]),
            ("show-services-udp", services_udp_by_domain[dom]),
            ("show-services-icmp", services_icmp_by_domain[dom]),
            ("show-service-groups", service_groups_by_domain[dom]),
        ):
            total_services_count += len(svc_items)
            _write_json(
                dom_dir / f"{svc_cmd}.json",
                {
                    "objects": svc_items,
                    "from": 1 if svc_items else 0,
                    "to": len(svc_items),
                    "total": len(svc_items),
                },
            )

        pkgs = packages_by_domain[dom]
        _write_json(
            dom_dir / "show-packages.json",
            {
                "packages": pkgs,
                "objects": pkgs,
                "from": 1 if pkgs else 0,
                "to": len(pkgs),
                "total": len(pkgs),
            },
        )
        layers = access_layers_by_domain[dom]
        _write_json(
            dom_dir / "show-access-layers.json",
            {
                "access-layers": layers,
                "objects": layers,
                "from": 1 if layers else 0,
                "to": len(layers),
                "total": len(layers),
            },
        )
        _write_json(dom_dir / "show-access-rulebase.json", access_rulebases_by_domain[dom])
        _write_json(dom_dir / "show-nat-rulebase.json", nat_rulebases_by_domain[dom])

    # Write CLI stdout files and Base64 `show-task` payloads
    for (node_name, vsid), stdout_text in sorted(cli_outputs.items(), key=lambda x: (x[0][0], x[0][1] or 0)):
        suffix = f"__vs_{vsid}" if vsid is not None else "__vs_none"
        _write_text(root / "cli" / f"{node_name}{suffix}.txt", stdout_text)
        task_id = f"task-{node_name}-{vsid if vsid is not None else 0}"
        _write_json(
            root / "tasks" / f"{node_name}{suffix}.json",
            _encode_task_payload(task_id, node_name, stdout_text),
        )

    for chassis_name, stat_text in sorted(vsx_stat_outputs.items()):
        _write_text(root / "cli" / f"{chassis_name}__vsx_stat_l.txt", stat_text)

    manifest = {
        "version": DATASET_VERSION,
        "seed": seed,
        "domains": list(ALL_DOMAINS),
        "user_domains": list(USER_DOMAINS),
        "counts": {
            "total_domains": len(ALL_DOMAINS),
            "user_domains": len(USER_DOMAINS),
            "total_assets": total_assets_count,
            "policy_enforcing_gateways": policy_enforcing_count,
            "total_network_objects": total_objects_count,
            "total_service_objects": total_services_count,
            "total_access_rules": total_access_rules,
            "total_nat_rules": total_nat_rules,
            "total_cli_targets": len(cli_outputs),
        },
        "cprid_fallback_gateways": [
            "br-reg-gw-138",
            "br-reg-gw-139",
            "br-reg-gw-140",
        ],
        "nine_hop_chain": [
            {"hop": 1, "domain": "Branch", "gateway": "br-spb-gw-01"},
            {"hop": 2, "domain": "Regional", "gateway": "reg-nw-cluster"},
            {
                "hop": 3,
                "domain": "WAN_Core",
                "gateways_ecmp": ["wan-core-ecmp-a", "wan-core-ecmp-b"],
                "standby": "wan-core-bgp-standby",
            },
            {"hop": 4, "domain": "Perimeter", "gateway": "perim-edge-cluster"},
            {"hop": 5, "domain": "Transit", "gateway": "ix-transit-gw-01"},
            {"hop": 6, "domain": "DC_Spine", "gateway": "dc-vsx-spine-vs01"},
            {"hop": 7, "domain": "DC_Pod", "gateway": "dc-vs-tier1-web"},
            {"hop": 8, "domain": "DC_Pod", "gateway": "dc-vs-tier2-app"},
            {"hop": 9, "domain": "DB_Seg", "gateway": "db-seg-internal-fw-01"},
        ],
    }
    _write_json(root / "manifest.json", manifest)
    return manifest


def ensure_enterprise_raw_dataset(
    output_dir: Path | str | None = None,
    *,
    seed: int = DEFAULT_SEED,
    force: bool = False,
) -> Path:
    """Ensure `tests/fixtures/enterprise_raw_dataset/` exists and matches `DATASET_VERSION` and `seed`."""
    root = Path(output_dir) if output_dir is not None else DEFAULT_DATASET_DIR
    manifest_path = root / "manifest.json"
    if not force and manifest_path.is_file():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            if existing.get("version") == DATASET_VERSION and existing.get("seed") == seed:
                return root
        except Exception:
            pass
    generate_enterprise_raw_dataset(root, seed=seed)
    return root
