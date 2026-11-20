"""Dataset builders for `Branch`, `Regional`, and `WAN_Core` domains."""

from __future__ import annotations

from ._dataset_common import DatasetBuildContext, make_cli_output


def populate_branch_domain(ctx: DatasetBuildContext) -> None:
    """Populate `Branch` domain objects, 140 simple gateways, and CLI outputs."""
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
        ctx.networks_by_domain["Branch"].extend(
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
        ctx.hosts_by_domain["Branch"].append(
            {
                "uid": host_prn_uid,
                "name": f"H_Branch_{b_idx:03d}_Server",
                "type": "host",
                "ipv4-address": f"10.11.{b_idx}.10",
            }
        )
        if b_idx <= 30:
            ctx.ranges_by_domain["Branch"].append(
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
        ctx.add_gw("Branch", gw_obj)
        ctx.cli_outputs[(gw_name, None)] = make_cli_output(
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


def populate_regional_domain(ctx: DatasetBuildContext) -> None:
    """Populate `Regional` domain 7-level nested groups, HA cluster, hub gateways, and CLI outputs."""
    reg_leaf_member_uids: list[str] = []
    for b_idx in range(1, 21):
        n1_uid = f"uid-reg-net-b-lan-{b_idx:03d}"
        n2_uid = f"uid-reg-net-b-voip-{b_idx:03d}"
        ctx.networks_by_domain["Regional"].extend(
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

    ctx.groups_by_domain["Regional"].extend(
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
    ctx.add_gw("Regional", reg_nw_cluster)
    ctx.add_gw("Regional", reg_node1)
    ctx.add_gw("Regional", reg_node2)

    reg_nw_routes = [
        "default via 172.22.1.1 dev eth0 proto static",
        *[f"10.11.{b_i}.0/24 via 172.22.101.254 dev eth1 proto ospf" for b_i in range(1, 21)],
        *[f"10.12.{b_i}.0/24 via 172.22.101.254 dev eth1 proto ospf" for b_i in range(1, 21)],
    ]
    ctx.cli_outputs[("reg-nw-node-1", None)] = make_cli_output(reg_nw_routes)
    ctx.cli_outputs[("reg-nw-node-2", None)] = make_cli_output(reg_nw_routes)

    for r_idx in range(2, 21):
        hub_name = f"reg-hub-gw-{r_idx:02d}"
        hub_uid = f"uid-reg-hub-{r_idx:02d}"
        sub_net = f"10.30.{r_idx}.0"
        ctx.networks_by_domain["Regional"].append(
            {
                "uid": f"uid-reg-net-hub-{r_idx:02d}",
                "name": f"N_Reg_Hub_{r_idx:02d}",
                "type": "network",
                "subnet4": sub_net,
                "mask-length4": 24,
            }
        )
        ctx.add_gw(
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
        ctx.cli_outputs[(hub_name, None)] = make_cli_output(
            [
                f"default via 172.22.{r_idx}.1 dev eth0 proto static",
                f"{sub_net}/24 dev eth1 proto kernel scope link src 10.30.{r_idx}.1",
            ]
        )


def populate_wan_core_domain(ctx: DatasetBuildContext) -> None:
    """Populate `WAN_Core` domain ECMP legs, standby BGP gateway, core routers, and CLI outputs."""
    ctx.networks_by_domain["WAN_Core"].extend(
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
    ctx.groups_by_domain["WAN_Core"].extend(
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
        ctx.add_gw(
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
        ctx.cli_outputs[(ecmp_name, None)] = make_cli_output(
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

    ctx.add_gw(
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
    ctx.cli_outputs[("wan-core-bgp-standby", None)] = make_cli_output(
        ip_routes=[
            "default via 172.23.0.1 dev eth0 proto static",
            "10.11.0.0/16 via 172.23.11.254 dev eth1 proto bgp",
        ]
    )

    for w_idx in range(1, 13):
        rtr_name = f"wan-core-rtr-{w_idx:02d}"
        ctx.add_gw(
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
        ctx.cli_outputs[(rtr_name, None)] = make_cli_output(
            [
                "default via 172.23.100.254 dev eth0 proto static",
                f"10.40.{w_idx}.0/24 dev eth1 proto kernel scope link src 10.40.{w_idx}.1",
            ]
        )
