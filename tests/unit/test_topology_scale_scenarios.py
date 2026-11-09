"""Synthetic multi-hundred-gateway enterprise scale & complex scenario test suite (`test_topology_scale_scenarios`).

Validates:
- 250+ policy-enforcing gateways across 3 domains (`Corp`, `DC`, `Branch`) with deterministic synthetic topology:
  - Perimeter clusters (`simple-cluster`) with `cluster-member` nodes (including member route drift).
  - Multi-hop transit chains (`Branch -> Regional -> Core -> DC Spine -> DC Leaf VSX Virtual System -> Partner Extranet`, 5+ hops).
  - VSX physical chassis (`VS0`) + 40 VSX Virtual Systems (`CpmiVsNetobj`) with `vsenv` CLI route collection.
  - Internal-only segmentation gateways (zero external interfaces, emitting zero false warnings).
  - One-arm Cisco ACI service-graph gateways (`one_arm_topology`, `severity="info"`, excluded from path candidates).
  - Stale anti-spoofing groups (`stale_in_topology`), `Detect`-mode interfaces (`anti_spoofing_detect_or_off`),
    `network defined by routing` interfaces resolved via BGP/OSPF (`resolved_by_routing`), and interface reroute
    conflicts (`interface_mismatch`).
  - Persistent administrator overrides (`TopologyAnnotation`: `standby_dynamic`, `ignore`, `manual`,
    `trust_static_topology=False`) and IPAM prefix export (`export_topology_prefixes`).
  - Targeted per-gateway refresh (`refresh_topology(gateways=["branch-gw-142"], collect_routes=True)`) verifying
    only 1 gateway is re-queried out of 250+ gateways.
  - Sub-second query performance for `find_affected_gateways` across 250+ gateways and thousands of topology rows.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata import (
    ArodonataClient,
    ArodonataSettings,
    AuthContext,
    DomainInfo,
    GatewayCliResult,
    GatewayCliTarget,
    TopologyAnnotation,
)
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
)


class EnterpriseScaleFakeApi:
    """Deterministic 250+ gateway multi-domain synthetic Check Point Management API double."""

    def __init__(self) -> None:
        self.api_call_log: list[tuple[str, str, dict[str, Any] | None]] = []
        self.api_query_log: list[tuple[str, str]] = []
        self.ssh_call_log: list[tuple[str, int | None]] = []

        self.gateways_by_domain: dict[str, list[dict[str, Any]]] = {
            "Corp": [],
            "DC": [],
            "Branch": [],
        }
        self.gateway_by_uid: dict[str, dict[str, Any]] = {}
        self.objects_by_domain_and_cmd: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("Global", "show-networks"): [],
            ("Global", "show-groups"): [],
            ("Corp", "show-networks"): [],
            ("Corp", "show-groups"): [],
            ("DC", "show-networks"): [],
            ("DC", "show-groups"): [],
            ("Branch", "show-networks"): [],
            ("Branch", "show-groups"): [],
        }
        self.cli_stdout_by_node: dict[tuple[str, int | None], str] = {}
        self._build_synthetic_enterprise()

    def _register_gw(self, domain: str, gw: dict[str, Any]) -> None:
        self.gateways_by_domain[domain].append(gw)
        self.gateway_by_uid[gw["uid"]] = gw

    def _build_synthetic_enterprise(self) -> None:
        # ------------------------------------------------------------------
        # 1. Domain `Branch`: 180 Branch Gateways (`branch-gw-001` .. `branch-gw-180`)
        #    Each branch gateway has:
        #    - `eth0` (external -> 0.0.0.0/0)
        #    - `eth1` (internal connected `10.100.<idx>.0/24`, Prevent)
        #    - `eth2` (internal `network defined by routing`, resolved via OSPF `10.101.<idx>.0/24`)
        # ------------------------------------------------------------------
        for idx in range(1, 181):
            uid = f"uid-branch-gw-{idx:03d}"
            name = f"branch-gw-{idx:03d}"
            lan_cidr = f"10.100.{idx}.0/24"
            lan_ip = f"10.100.{idx}.1"
            ospf_cidr = f"10.101.{idx}.0/24"
            gw_dict = {
                "uid": uid,
                "name": name,
                "type": "simple-gateway",
                "ipv4-address": f"172.25.{idx // 250}.{idx % 250 + 1}",
                "policy": {
                    "access-policy-installed": True,
                    "access-policy-name": f"Branch_Policy_{idx:03d}",
                },
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": f"172.25.{idx // 250}.{idx % 250 + 1}",
                        "ipv4-mask-length": 30,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": lan_ip,
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
                        "ipv4-address": f"10.102.{idx}.1",
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
            self._register_gw("Branch", gw_dict)
            self.cli_stdout_by_node[(name, None)] = (
                "===ARODONATA_IP_ROUTE_START===\n"
                f"default via 172.25.{idx // 250}.254 dev eth0 proto static\n"
                f"{lan_cidr} dev eth1 proto kernel scope link src {lan_ip}\n"
                f"{ospf_cidr} via 10.102.{idx}.2 dev eth2 proto ospf\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            )

        # ------------------------------------------------------------------
        # 2. Domain `Corp`:
        #    - 15 Regional Aggregation Gateways (`corp-reg-gw-01` .. `corp-reg-gw-15`)
        #    - 15 Internal-Only Segmentation Gateways (`corp-seg-gw-01` .. `corp-seg-gw-15`, NO external interface)
        #    - 10 One-Arm Cisco ACI Service-Graph Appliances (`corp-aci-onearm-01` .. `corp-aci-onearm-10`)
        #    - 1 Core Transit Cluster (`corp-core-cluster` with members `corp-core-1a`, `corp-core-1b`)
        #    - 1 DR Standby Perimeter Cluster (`corp-dr-cluster`)
        # ------------------------------------------------------------------
        for r_idx in range(1, 16):
            # Each regional gateway aggregates 12 branches (`(r_idx-1)*12 + 1` .. `r_idx*12`)
            b_start = (r_idx - 1) * 12 + 1
            net_uid = f"net-reg-branches-{r_idx:02d}"
            net_name = f"G_Reg_{r_idx:02d}_Branches"
            member_uids: list[str] = []
            for b_i in range(b_start, b_start + 12):
                n_uid = f"net-b-lan-{b_i:03d}"
                o_uid = f"net-b-ospf-{b_i:03d}"
                self.objects_by_domain_and_cmd[("Corp", "show-networks")].extend(
                    [
                        {
                            "uid": n_uid,
                            "name": f"N_Branch_{b_i:03d}_LAN",
                            "type": "network",
                            "subnet4": f"10.100.{b_i}.0",
                            "mask-length4": 24,
                        },
                        {
                            "uid": o_uid,
                            "name": f"N_Branch_{b_i:03d}_OSPF",
                            "type": "network",
                            "subnet4": f"10.101.{b_i}.0",
                            "mask-length4": 24,
                        },
                    ]
                )
                member_uids.extend([n_uid, o_uid])

            self.objects_by_domain_and_cmd[("Corp", "show-groups")].append(
                {
                    "uid": net_uid,
                    "name": net_name,
                    "type": "group",
                    "members": member_uids,
                }
            )
            reg_name = f"corp-reg-gw-{r_idx:02d}"
            reg_uid = f"uid-corp-reg-{r_idx:02d}"
            self._register_gw(
                "Corp",
                {
                    "uid": reg_uid,
                    "name": reg_name,
                    "type": "simple-gateway",
                    "ipv4-address": f"10.10.{r_idx}.1",
                    "policy": {"access-policy-installed": True, "access-policy-name": "Corp_Regional_Pkg"},
                    "interfaces": [
                        {
                            "name": "eth0",
                            "ipv4-address": f"10.10.{r_idx}.1",
                            "ipv4-mask-length": 30,
                            "topology": "external",
                        },
                        {
                            "name": "eth1",
                            "ipv4-address": f"10.11.{r_idx}.1",
                            "ipv4-mask-length": 24,
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": net_name,
                            },
                            "anti-spoofing": True,
                            "anti-spoofing-settings": {"action": "prevent"},
                        },
                    ],
                },
            )
            route_lines = [
                f"default via 10.10.{r_idx}.2 dev eth0 proto static",
            ]
            for b_i in range(b_start, b_start + 12):
                route_lines.append(f"10.100.{b_i}.0/24 via 10.11.{r_idx}.254 dev eth1 proto bgp")
                route_lines.append(f"10.101.{b_i}.0/24 via 10.11.{r_idx}.254 dev eth1 proto bgp")
            self.cli_stdout_by_node[(reg_name, None)] = (
                "===ARODONATA_IP_ROUTE_START===\n" + "\n".join(route_lines) + "\n===ARODONATA_IP_ROUTE_END===\n"
            )

        # 15 Internal-Only Segmentation Gateways (NO external interface!)
        for s_idx in range(1, 16):
            seg_name = f"corp-seg-gw-{s_idx:02d}"
            self._register_gw(
                "Corp",
                {
                    "uid": f"uid-corp-seg-{s_idx:02d}",
                    "name": seg_name,
                    "type": "simple-gateway",
                    "ipv4-address": f"10.150.{s_idx}.1",
                    "policy": {"access-policy-installed": True, "access-policy-name": "Corp_Internal_Seg"},
                    "interfaces": [
                        {
                            "name": "eth1",
                            "ipv4-address": f"10.150.{s_idx}.1",
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
                            "ipv4-address": f"10.151.{s_idx}.1",
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
            self.cli_stdout_by_node[(seg_name, None)] = (
                "===ARODONATA_IP_ROUTE_START===\n"
                f"10.150.{s_idx}.0/24 dev eth1 proto kernel scope link src 10.150.{s_idx}.1\n"
                f"10.151.{s_idx}.0/24 dev eth2 proto kernel scope link src 10.151.{s_idx}.1\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            )

        # 10 One-Arm Cisco ACI Service-Graph Gateways (single external interface)
        for a_idx in range(1, 11):
            aci_name = f"corp-aci-onearm-{a_idx:02d}"
            self._register_gw(
                "Corp",
                {
                    "uid": f"uid-corp-aci-{a_idx:02d}",
                    "name": aci_name,
                    "type": "simple-gateway",
                    "ipv4-address": f"172.30.{a_idx}.10",
                    "policy": {"access-policy-installed": True, "access-policy-name": "ACI_ServiceGraph_Pkg"},
                    "interfaces": [
                        {
                            "name": "bond0.400",
                            "ipv4-address": f"172.30.{a_idx}.10",
                            "ipv4-mask-length": 24,
                            "topology": "external",
                        }
                    ],
                },
            )
            self.cli_stdout_by_node[(aci_name, None)] = (
                "===ARODONATA_IP_ROUTE_START===\n"
                f"default via 172.30.{a_idx}.1 dev bond0.400 proto static\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            )

        # Core Transit Cluster `corp-core-cluster` (Hop 3 in transit chain):
        # - `eth1`: All Branch supernets (`10.100.0.0/16`, `10.101.0.0/16`) + a STALE legacy subnet `10.199.99.0/24`
        #   that was actually moved to `eth3` in live routing (`interface_mismatch`)!
        # - `eth2`: DC supernet (`10.200.0.0/16`) with Anti-Spoofing in `detect` mode + a drifted BGP route `10.200.250.0/24`
        # - `eth3`: Partner Extranet (`172.18.0.0/16` via live BGP + `10.199.99.0/24` moved here)
        self.objects_by_domain_and_cmd[("Corp", "show-networks")].extend(
            [
                {
                    "uid": "net-all-branches-100",
                    "name": "N_All_Branches_100",
                    "type": "network",
                    "subnet4": "10.100.0.0",
                    "mask-length4": 16,
                },
                {
                    "uid": "net-all-branches-101",
                    "name": "N_All_Branches_101",
                    "type": "network",
                    "subnet4": "10.101.0.0",
                    "mask-length4": 16,
                },
                {
                    "uid": "net-legacy-moved",
                    "name": "N_Legacy_Moved_199",
                    "type": "network",
                    "subnet4": "10.199.99.0",
                    "mask-length4": 24,
                },
                {
                    "uid": "net-dc-supernet",
                    "name": "N_DC_Supernet_200",
                    "type": "network",
                    "subnet4": "10.200.0.0",
                    "mask-length4": 16,
                },
                {
                    "uid": "net-stale-decommissioned",
                    "name": "N_Stale_Decommissioned_188",
                    "type": "network",
                    "subnet4": "10.188.0.0",
                    "mask-length4": 24,
                },
                {
                    "uid": "net-aci-epg-web-160-10",
                    "name": "N_ACI_EPG_Web_160_10",
                    "type": "network",
                    "subnet4": "10.160.10.0",
                    "mask-length4": 24,
                },
                {
                    "uid": "net-aci-epg-app-160-20",
                    "name": "N_ACI_EPG_App_160_20",
                    "type": "network",
                    "subnet4": "10.160.20.0",
                    "mask-length4": 24,
                },
            ]
        )
        self.objects_by_domain_and_cmd[("Corp", "show-groups")].extend(
            [
                {
                    "uid": "grp-core-west",
                    "name": "G_Core_West_Branches",
                    "type": "group",
                    "members": [
                        "net-all-branches-100",
                        "net-all-branches-101",
                        "net-legacy-moved",
                        "net-stale-decommissioned",
                    ],
                },
                {
                    "uid": "grp-core-east-dc",
                    "name": "G_Core_East_DC",
                    "type": "group",
                    "members": ["net-dc-supernet"],
                },
            ]
        )
        self._register_gw(
            "Corp",
            {
                "uid": "uid-corp-core-cl",
                "name": "corp-core-cluster",
                "type": "CpmiGatewayCluster",
                "ipv4-address": "10.0.100.1",
                "cluster-member-names": ["corp-core-1a", "corp-core-1b"],
                "policy": {"access-policy-installed": True, "access-policy-name": "Corp_Core_Transit_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": "198.51.100.10",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.0.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Core_West_Branches",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": "10.0.2.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Core_East_DC",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "detect"},
                    },
                    {
                        "name": "eth3",
                        "ipv4-address": "10.0.3.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by routing",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        self._register_gw(
            "Corp",
            {
                "uid": "uid-corp-core-1a",
                "name": "corp-core-1a",
                "type": "cluster-member",
                "ipv4-address": "10.0.100.2",
            },
        )
        self._register_gw(
            "Corp",
            {
                "uid": "uid-corp-core-1b",
                "name": "corp-core-1b",
                "type": "cluster-member",
                "ipv4-address": "10.0.100.3",
            },
        )
        # Member 1a has `10.200.250.0/24` on `eth2`; Member 1b is missing it (`cluster_member_drift`)
        # Also `10.199.99.0/24` is routed on `eth3` instead of `eth1` (`interface_mismatch`),
        # and `10.188.0.0/24` is completely absent from live routes (`stale_in_topology`).
        self.cli_stdout_by_node[("corp-core-1a", None)] = (
            "===ARODONATA_IP_ROUTE_START===\n"
            "default via 198.51.100.1 dev eth0 proto static\n"
            "10.100.0.0/16 via 10.0.1.254 dev eth1 proto bgp\n"
            "10.101.0.0/16 via 10.0.1.254 dev eth1 proto bgp\n"
            "10.200.0.0/16 via 10.0.2.254 dev eth2 proto bgp\n"
            "10.200.250.0/24 via 10.0.2.253 dev eth2 proto bgp\n"
            "172.18.0.0/16 via 10.0.3.254 dev eth3 proto bgp\n"
            "10.199.99.0/24 via 10.0.3.250 dev eth3 proto ospf\n"
            "===ARODONATA_IP_ROUTE_END===\n"
        )
        self.cli_stdout_by_node[("corp-core-1b", None)] = (
            "===ARODONATA_IP_ROUTE_START===\n"
            "default via 198.51.100.1 dev eth0 proto static\n"
            "10.100.0.0/16 via 10.0.1.254 dev eth1 proto bgp\n"
            "10.101.0.0/16 via 10.0.1.254 dev eth1 proto bgp\n"
            "10.200.0.0/16 via 10.0.2.254 dev eth2 proto bgp\n"
            "172.18.0.0/16 via 10.0.3.254 dev eth3 proto bgp\n"
            "10.199.99.0/24 via 10.0.3.250 dev eth3 proto ospf\n"
            "===ARODONATA_IP_ROUTE_END===\n"
        )

        # DR Standby Cluster (`corp-dr-cluster`): has `10.200.0.0/16` in SmartConsole static topology on `eth2`,
        # but currently NOT in live BGP routes (will be annotated with `disposition="standby_dynamic"`).
        self._register_gw(
            "Corp",
            {
                "uid": "uid-corp-dr-cl",
                "name": "corp-dr-cluster",
                "type": "simple-cluster",
                "ipv4-address": "10.0.200.1",
                "policy": {"access-policy-installed": True, "access-policy-name": "Corp_DR_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": "203.0.113.10",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.0.11.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Core_West_Branches",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": "10.0.12.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Core_East_DC",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        self.cli_stdout_by_node[("corp-dr-cluster", None)] = (
            "===ARODONATA_IP_ROUTE_START===\n"
            "default via 203.0.113.1 dev eth0 proto static\n"
            "10.100.0.0/16 via 10.0.11.254 dev eth1 proto bgp\n"
            "10.101.0.0/16 via 10.0.11.254 dev eth1 proto bgp\n"
            "===ARODONATA_IP_ROUTE_END===\n"
        )

        # ------------------------------------------------------------------
        # 3. Domain `DC`:
        #    - 1 DC Spine Cluster (`dc-spine-cluster`, Hop 4 in transit chain)
        #    - 1 Physical VSX Chassis (`dc-vsx-chassis-01`, `CpmiVsxNetobj`, must be skipped!)
        #    - 40 VSX Virtual Systems (`dc-vs-01` .. `dc-vs-40`, `CpmiVsNetobj`, Hop 5 in transit chain)
        # ------------------------------------------------------------------
        self.objects_by_domain_and_cmd[("DC", "show-networks")].append(
            {
                "uid": "dc-net-all-pods",
                "name": "N_DC_All_Pods_200",
                "type": "network",
                "subnet4": "10.200.0.0",
                "mask-length4": 16,
            }
        )
        self._register_gw(
            "DC",
            {
                "uid": "uid-dc-spine-cl",
                "name": "dc-spine-cluster",
                "type": "simple-cluster",
                "ipv4-address": "10.200.0.1",
                "policy": {"access-policy-installed": True, "access-policy-name": "DC_Spine_Pkg"},
                "interfaces": [
                    {
                        "name": "eth0",
                        "ipv4-address": "10.0.2.254",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "bond1",
                        "ipv4-address": "10.200.254.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "N_DC_All_Pods_200",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            },
        )
        self.cli_stdout_by_node[("dc-spine-cluster", None)] = (
            "===ARODONATA_IP_ROUTE_START===\n"
            "default via 10.0.2.1 dev eth0 proto bgp\n"
            "10.200.0.0/16 via 10.200.254.254 dev bond1 proto ospf\n"
            "===ARODONATA_IP_ROUTE_END===\n"
        )

        vs_uids = [f"uid-dc-vs-{v_idx:02d}" for v_idx in range(1, 41)]
        self._register_gw(
            "DC",
            {
                "uid": "uid-dc-vsx-chassis-01",
                "name": "dc-vsx-chassis-01",
                "type": "CpmiVsxNetobj",
                "ipv4-address": "172.16.200.10",
                "virtual-systems": vs_uids,
            },
        )
        for v_idx in range(1, 41):
            vs_uid = f"uid-dc-vs-{v_idx:02d}"
            vs_name = f"dc-vs-{v_idx:02d}"
            pod_cidr = f"10.200.{v_idx}.0/24"
            pod_ip = f"10.200.{v_idx}.1"
            self._register_gw(
                "DC",
                {
                    "uid": vs_uid,
                    "name": vs_name,
                    "type": "CpmiVsNetobj",
                    "ipv4-address": pod_ip,
                    "vsid": v_idx,
                    "parent-uid": "uid-dc-vsx-chassis-01",
                    "policy": {"access-policy-installed": True, "access-policy-name": f"DC_VS_{v_idx:02d}_Pkg"},
                    "interfaces": [
                        {
                            "name": "wrp0",
                            "ipv4-address": f"10.200.254.{v_idx + 10}",
                            "ipv4-mask-length": 24,
                            "topology": "external",
                        },
                        {
                            "name": f"eth1.{v_idx}",
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
                },
            )
            self.cli_stdout_by_node[("dc-vsx-chassis-01", v_idx)] = (
                "===ARODONATA_IP_ROUTE_START===\n"
                "default via 10.200.254.1 dev wrp0 proto static\n"
                f"{pod_cidr} dev eth1.{v_idx} proto kernel scope link src {pod_ip}\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            )

    async def ssh_execute(
        self,
        target: GatewayCliTarget,
        script: str,
        timeout: float = 30.0,
    ) -> GatewayCliResult:
        self.ssh_call_log.append((target.node_name, target.vsid))
        out = self.cli_stdout_by_node.get((target.node_name, target.vsid), "")
        return GatewayCliResult(success=True, stdout=out, executor="ssh")

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        self.api_call_log.append((domain or "Corp", command, payload))
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": f"sess-{domain}", "publish-time": {"iso-8601": "2026-11-07T08:00:00Z"}},
            )
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command in ("show-simple-gateway", "show-simple-cluster", "show-generic-object") and payload:
            uid = str(payload.get("uid") or "")
            name = str(payload.get("name") or "")
            if uid in self.gateway_by_uid:
                return ApiCallResult(success=True, data=self.gateway_by_uid[uid])
            for gw in self.gateway_by_uid.values():
                if gw["name"] == name:
                    return ApiCallResult(success=True, data=gw)
        return ApiCallResult(success=True, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        dom = domain or "Corp"
        self.api_query_log.append((dom, command))
        if command == "show-gateways-and-servers":
            objs = self.gateways_by_domain.get(dom, [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        objs = self.objects_by_domain_and_cmd.get((dom, command), [])
        return ApiQueryResult(success=True, objects=objs, total=len(objs))

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "ded-sid", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _noop() -> bool:
            return True

        return _noop()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_enterprise_scale_260_gateways_multi_hop_transit_reconciliation_and_overrides() -> None:
    """Verify 260+ gateway topology sync, live route collection, 5-hop transit discovery, overrides, targeted single-gateway refresh, and fast query performance."""
    api = EnterpriseScaleFakeApi()
    settings = ArodonataSettings(mgmt_name="mds-ent", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    client = ArodonataClient(settings=settings, api=api, gateway_cli=api.ssh_execute)
    await client.initialize(run_startup_cleanup=False)

    client.domain_service.tracker.mark_refreshed("mds-ent")
    await client.cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds-ent", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds-ent", uid="d-branch", name="Branch", active_ip="10.1.0.1"),
            DomainInfo(mgmt_name="mds-ent", uid="d-corp", name="Corp", active_ip="10.2.0.1"),
            DomainInfo(mgmt_name="mds-ent", uid="d-dc", name="DC", active_ip="10.3.0.1"),
        ]
    )

    # 1. Full static topology sync + live route collection across all 263 policy-enforcing gateways:
    #    - Branch: 180 simple gateways
    #    - Corp: 15 regional + 15 internal-seg + 10 one-arm ACI + 1 core cluster + 1 DR cluster = 42 policy gateways
    #    - DC: 1 spine cluster + 40 VSX Virtual Systems = 41 policy gateways (VS0 chassis skipped!)
    #    Total policy-enforcing gateways = 180 + 42 + 41 = 263 gateways!
    await client.refresh_topology(mgmt_name="mds-ent", mode="force")
    route_outcome = await client.collect_gateway_routes(mgmt_name="mds-ent")
    assert route_outcome.total_gateways == 263
    assert route_outcome.succeeded_gateways == 263
    assert route_outcome.failed_gateways == 0

    # Verify VSX Virtual Systems executed via `dc-vsx-chassis-01` with `vsid=1..40`
    for v_idx in range(1, 41):
        assert ("dc-vsx-chassis-01", v_idx) in api.ssh_call_log

    # 2. Verify Static Topology Diagnostics across 263 gateways:
    #    - 15 Internal-only segmentation gateways (`corp-seg-gw-01..15`) MUST emit ZERO diagnostics!
    #    - 10 One-arm ACI gateways (`corp-aci-onearm-01..10`) MUST emit `one_arm_topology` (`severity="info"`).
    #    - `corp-core-cluster` `eth2` MUST emit `anti_spoofing_detect_or_off` (`severity="warning"`).
    #    - All 180 `branch-gw-*` `eth2` ("network defined by routing") now have collected OSPF routes, so they
    #      must NOT emit `routing_defined_without_routes`!
    all_diags = await client.get_topology_diagnostics(mgmt_name="mds-ent", cache_mode="cache")
    diag_gw_names = {d.gateway_name for d in all_diags}
    for s_idx in range(1, 16):
        assert f"corp-seg-gw-{s_idx:02d}" not in diag_gw_names

    one_arm_diags = [d for d in all_diags if d.code == "one_arm_topology"]
    assert len(one_arm_diags) == 10
    assert all(d.severity == "info" for d in one_arm_diags)

    detect_diags = [d for d in all_diags if d.code == "anti_spoofing_detect_or_off"]
    assert len(detect_diags) == 1
    assert detect_diags[0].gateway_name == "corp-core-cluster"
    assert detect_diags[0].interface_name == "eth2"

    assert [d for d in all_diags if d.code == "routing_defined_without_routes"] == []

    # 3. Verify Reconciliation on `Corp`:
    corp_rec = await client.reconcile_gateway_topology(
        mgmt_name="mds-ent",
        domain="Corp",
        cache_mode="cache",
    )
    corp_disc_map = {(d.gateway_name, d.discrepancy_type, d.cidr_or_range): d for d in corp_rec.discrepancies}
    # Stale decommissioned subnet `10.188.0.0/24` on `corp-core-cluster` `eth1`
    assert ("corp-core-cluster", "stale_in_topology", "10.188.0.0/24") in corp_disc_map
    # Moved subnet `10.199.99.0/24` (static says `eth1`, live OSPF routes via `eth3`)
    assert ("corp-core-cluster", "interface_mismatch", "10.199.99.0/24") in corp_disc_map
    assert corp_disc_map[("corp-core-cluster", "interface_mismatch", "10.199.99.0/24")].routed_interface_name == "eth3"
    # BGP route `172.18.0.0/16` on `eth3` ("network defined by routing") -> `resolved_by_routing`
    assert ("corp-core-cluster", "resolved_by_routing", "172.18.0.0/16") in corp_disc_map
    # Cluster member drift on `corp-core-cluster` (`10.200.250.0/24` only on `corp-core-1a`)
    assert ("corp-core-cluster", "cluster_member_drift", "10.200.250.0/24") in corp_disc_map
    # DR cluster has `10.200.0.0/16` in static topology on `eth2`, absent from live routes
    assert ("corp-dr-cluster", "stale_in_topology", "10.200.0.0/16") in corp_disc_map

    # 4. Apply Persistent Administrator Annotations (`TopologyAnnotation`):
    #    - Mark `corp-dr-cluster` `eth2` `10.200.0.0/16` as `standby_dynamic`
    #    - Mark `corp-core-cluster` `eth1` `10.188.0.0/24` as `ignore` (decommissioned network)
    #    - Add `manual` prefix `192.0.2.0/24` on `dc-vs-07` `eth1.7` (NAT pool behind VS7)
    await client.upsert_topology_annotations(
        [
            TopologyAnnotation(
                mgmt_name="mds-ent",
                domain_name="Corp",
                gateway_uid="uid-corp-dr-cl",
                gateway_name="corp-dr-cluster",
                interface_name="eth2",
                cidr_or_range="10.200.0.0/16",
                disposition="standby_dynamic",
                zone="DC-DR-Interconnect",
                site="DR-Site",
                comment="BGP standby link to DC Spine",
            ),
            TopologyAnnotation(
                mgmt_name="mds-ent",
                domain_name="Corp",
                gateway_uid="uid-corp-core-cl",
                gateway_name="corp-core-cluster",
                interface_name="eth1",
                cidr_or_range="10.188.0.0/24",
                disposition="ignore",
                comment="Decommissioned legacy range still in G_Core_West_Branches",
            ),
            TopologyAnnotation(
                mgmt_name="mds-ent",
                domain_name="DC",
                gateway_uid="uid-dc-vs-07",
                gateway_name="dc-vs-07",
                interface_name="eth1.7",
                cidr_or_range="192.0.2.0/24",
                disposition="manual",
                zone="DC-Pod7-VIP",
                site="DC1",
                comment="VIP range behind load balancer in VS 7",
            ),
        ]
    )

    # 5. Test 5-Hop Transit Path Discovery & Performance:
    #    Flow from Branch 25 OSPF subnet (`10.101.25.44`, behind `branch-gw-025` `eth2`)
    #    to DC VS 7 pod subnet (`10.200.7.88`, behind `dc-vs-07` `eth1.7`):
    #    Expected active hops across the 263 gateways:
    #    - Hop 1: `branch-gw-025` (`Branch`: `eth2` internal OSPF -> `eth0` external)
    #    - Hop 2: `corp-reg-gw-03` (`Corp`, aggregates branches 25..36: `eth1` internal -> `eth0` external)
    #    - Hop 3: `corp-core-cluster` (`Corp`: `eth1` internal -> `eth2` internal, `internal_to_internal`!)
    #    - Hop 4: `dc-spine-cluster` (`DC`: `eth0` external -> `bond1` internal)
    #    - Hop 5: `dc-vs-07` (`DC`: `wrp0` external -> `eth1.7` internal)
    #    Plus standby hop:
    #    - Standby Hop: `corp-dr-cluster` (`Corp`: `eth1` internal -> `eth2` internal `is_standby_path=True`)
    #    All other 257 gateways (including all 10 one-arm ACI gateways and all 15 internal-seg gateways) MUST be excluded!
    t0 = time.perf_counter()
    cands_with_standby = await client.find_affected_gateways(
        sources=["10.101.25.44"],
        destinations=["10.200.7.88"],
        mgmt_name="mds-ent",
        include_standby=True,
        cache_mode="cache",
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert elapsed_ms < 1000.0  # Fast in-memory interval resolution across 263 gateways

    matched_names = [c.gateway_name for c in cands_with_standby]
    assert set(matched_names) == {
        "corp-core-cluster",
        "corp-dr-cluster",
        "branch-gw-025",
        "corp-reg-gw-03",
        "dc-spine-cluster",
        "dc-vs-07",
    }
    # Primary `internal_to_internal` gateway (`corp-core-cluster`, `is_standby_path=False`) must sort before standby `corp-dr-cluster`
    assert matched_names[0] == "corp-core-cluster"
    assert cands_with_standby[0].is_standby_path is False

    dr_cand = next(c for c in cands_with_standby if c.gateway_name == "corp-dr-cluster")
    assert dr_cand.is_standby_path is True

    # With `include_standby=False`, only the 5 active hops are returned
    active_cands = await client.find_affected_gateways(
        sources=["10.101.25.44"],
        destinations=["10.200.7.88"],
        mgmt_name="mds-ent",
        include_standby=False,
        cache_mode="cache",
    )
    assert {c.gateway_name for c in active_cands} == {
        "corp-core-cluster",
        "branch-gw-025",
        "corp-reg-gw-03",
        "dc-spine-cluster",
        "dc-vs-07",
    }

    # 6. Verify `disposition="ignore"` on `10.188.0.0/24` drops `eth1` internal match on `corp-core-cluster`:
    #    Because `10.188.0.0/24` was ignored on `eth1`, `10.188.0.50` no longer matches `eth1` (`internal_to_internal`)
    #    and instead falls back to `eth0` (`external_to_internal`).
    ignored_cands = await client.find_affected_gateways(
        sources=["10.188.0.50"],
        destinations=["10.200.7.88"],
        mgmt_name="mds-ent",
        domain="Corp",
        include_standby=False,
        cache_mode="cache",
    )
    core_after_ignore = next(c for c in ignored_cands if c.gateway_name == "corp-core-cluster")
    assert all(f.src_interface != "eth1" for f in core_after_ignore.matched_flows)
    assert core_after_ignore.matched_flows[0].src_interface == "eth0"
    assert core_after_ignore.matched_flows[0].match_type == "external_to_internal"

    # 7. Verify `interface_mismatch` resolution on `corp-core-cluster`:
    #    `10.199.99.0/24` is in `G_Core_West_Branches` (`eth1`) in static topology, but live OSPF routes it on `eth3`
    #    (where Partner Extranet `172.18.0.0/16` also lives).
    #    - Traffic `10.100.25.10` (`eth1`) -> `10.199.99.10` (`eth3` via live OSPF) MUST match `corp-core-cluster` (`eth1 -> eth3`)!
    rerouted_cands = await client.find_affected_gateways(
        sources=["10.100.25.10"],
        destinations=["10.199.99.10"],
        mgmt_name="mds-ent",
        domain="Corp",
        include_standby=False,
        cache_mode="cache",
    )
    core_rerouted = next(c for c in rerouted_cands if c.gateway_name == "corp-core-cluster")
    assert core_rerouted.matched_flows[0].src_interface == "eth1"
    assert core_rerouted.matched_flows[0].dst_interface == "eth3"
    assert core_rerouted.matched_flows[0].dst_source_type == "ospf_route"

    # 8. Verify Targeted Single-Gateway Refresh (`gateways=["branch-gw-142"], collect_routes=True`):
    #    Modify `branch-gw-142` live routes to add a new subnet `10.242.142.0/24` on `eth2`,
    #    clear call logs, and run targeted refresh for ONLY `branch-gw-142`.
    api.cli_stdout_by_node[("branch-gw-142", None)] = api.cli_stdout_by_node[("branch-gw-142", None)].replace(
        "===ARODONATA_IP_ROUTE_END===",
        "10.242.142.0/24 via 10.102.142.2 dev eth2 proto ospf\n===ARODONATA_IP_ROUTE_END===",
    )
    api.api_call_log.clear()
    api.api_query_log.clear()
    api.ssh_call_log.clear()

    targeted_outcome = await client.refresh_topology(
        mgmt_name="mds-ent",
        domains=["Branch"],
        gateways=["branch-gw-142"],
        collect_routes=True,
    )
    assert targeted_outcome.refreshed_domains == ["mds-ent:Branch"]
    # Must NOT have run full domain `show-gateways-and-servers` pagination!
    assert ("Branch", "show-gateways-and-servers") not in api.api_query_log
    # Must have executed SSH CLI route collection ONLY on `branch-gw-142` (1 call, not 180!)
    assert api.ssh_call_log == [("branch-gw-142", None)]

    # Verify the new route `10.242.142.0/24` on `branch-gw-142` is immediately searchable while other branch gateways remain intact
    b142_cands = await client.find_affected_gateways(
        sources=["10.242.142.10"],
        destinations=["8.8.8.8"],
        mgmt_name="mds-ent",
        domain="Branch",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in b142_cands] == ["branch-gw-142"]

    # 9. Verify One-Arm Cisco ACI Service-Graph Policy Inference (`corp-aci-onearm-03`):
    #    Seed `ACI_ServiceGraph_Pkg` in `Corp` with an explicit Access rule between two EPG subnets
    #    (`N_ACI_EPG_Web_160_10` `10.160.10.0/24` -> `N_ACI_EPG_App_160_20` `10.160.20.0/24`)
    #    installed specifically on `corp-aci-onearm-03` (`install_on=["corp-aci-onearm-03"]`),
    #    plus a generic `Any -> Any` cleanup rule on `Policy Targets`.
    await client.cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds-ent",
            domain_name="Corp",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds-ent",
                    domain_name="Corp",
                    package_uid="pkg-aci-sg",
                    package_name="ACI_ServiceGraph_Pkg",
                    rulebase_type="access",
                    layer_uid="layer-aci-sg",
                    layer_name="ACI_ServiceGraph_Layer",
                    position=1,
                ),
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds-ent",
                    domain_name="Corp",
                    uid="layer-aci-sg",
                    name="ACI_ServiceGraph_Layer",
                    rulebase_type="access",
                ),
            ],
            access_rules=[
                AccessRuleEntry(
                    mgmt_name="mds-ent",
                    domain_name="Corp",
                    layer_uid="layer-aci-sg",
                    layer_name="ACI_ServiceGraph_Layer",
                    uid="rule-aci-epg-03",
                    name="ACI_EPG_Web_to_App_Contract",
                    position=1,
                    rule_number="1",
                    enabled=True,
                    action="Accept",
                    source=["N_ACI_EPG_Web_160_10"],
                    destination=["N_ACI_EPG_App_160_20"],
                    install_on=["corp-aci-onearm-03"],
                ),
                AccessRuleEntry(
                    mgmt_name="mds-ent",
                    domain_name="Corp",
                    layer_uid="layer-aci-sg",
                    layer_name="ACI_ServiceGraph_Layer",
                    uid="rule-aci-cleanup",
                    name="ACI_Cleanup_Any",
                    position=2,
                    rule_number="2",
                    enabled=True,
                    action="Accept",
                    source=["Any"],
                    destination=["Any"],
                    install_on=["Policy Targets"],
                ),
            ],
        ),
    )

    aci_inferred_cands = await client.find_affected_gateways(
        sources=["10.160.10.15"],
        destinations=["10.160.20.25"],
        mgmt_name="mds-ent",
        domain="Corp",
        include_policy_inferred=True,
        cache_mode="cache",
    )
    # Only `corp-aci-onearm-03` must be discovered; the other 9 one-arm ACI gateways (`01..02`, `04..10`) are excluded!
    assert [c.gateway_name for c in aci_inferred_cands] == ["corp-aci-onearm-03"]
    aci_03 = aci_inferred_cands[0]
    assert aci_03.match_types == ["policy_inferred"]
    assert aci_03.installed_access_policy == "ACI_ServiceGraph_Pkg"
    assert aci_03.matched_flows[0].match_type == "policy_inferred"
    assert aci_03.matched_flows[0].src_interface == "bond0.400"
    assert aci_03.matched_flows[0].dst_interface == "bond0.400"
    assert aci_03.matched_flows[0].src_matched_cidr == "10.160.10.0/24"
    assert aci_03.matched_flows[0].dst_matched_cidr == "10.160.20.0/24"
    assert any(d.code == "policy_rule_evidence" for d in aci_03.confidence_factors)
    assert aci_03.confidence == pytest.approx(0.55)

    # With `include_policy_inferred=False`, `corp-aci-onearm-03` is not returned
    aci_disabled_cands = await client.find_affected_gateways(
        sources=["10.160.10.15"],
        destinations=["10.160.20.25"],
        mgmt_name="mds-ent",
        domain="Corp",
        include_policy_inferred=False,
        cache_mode="cache",
    )
    assert aci_disabled_cands == []

    await client.close()
