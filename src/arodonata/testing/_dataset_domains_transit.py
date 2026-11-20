"""Dataset builders for `Perimeter` and `Transit` domains."""

from __future__ import annotations

from ._dataset_common import DatasetBuildContext, make_cli_output


def populate_perimeter_domain(ctx: DatasetBuildContext) -> None:
    """Populate `Perimeter` edge cluster (with empty summary interfaces), DMZ gateways, and CLI outputs."""
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
        "interfaces": [],
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
    ctx.add_gw("Perimeter", perim_summary, full_detail=perim_full_detail)
    ctx.add_gw("Perimeter", perim_m1)
    ctx.add_gw("Perimeter", perim_m2)

    perim_routes = [
        "default via 172.24.0.1 dev eth0 proto static",
        "10.11.0.0/16 via 172.24.10.254 dev eth1 proto bgp",
        "10.220.0.0/16 via 172.24.20.254 dev eth2 proto bgp",
    ]
    ctx.cli_outputs[("perim-edge-1a", None)] = make_cli_output(perim_routes)
    ctx.cli_outputs[("perim-edge-1b", None)] = make_cli_output(perim_routes)

    for p_idx in range(1, 15):
        dmz_gw_name = f"perim-dmz-gw-{p_idx:02d}"
        ctx.add_gw(
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
        ctx.cli_outputs[(dmz_gw_name, None)] = make_cli_output(
            [
                "default via 172.24.100.254 dev eth0 proto static",
                f"10.50.{p_idx}.0/24 dev eth1 proto kernel scope link src 10.50.{p_idx}.1",
            ]
        )


def populate_transit_domain(ctx: DatasetBuildContext) -> None:
    """Populate `Transit` domain LPM Matryoshka, anomaly audit, interconnect gateways, and CLI outputs."""
    ctx.networks_by_domain["Transit"].extend(
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
    ctx.hosts_by_domain["Transit"].append(
        {
            "uid": "uid-lpm-host-32",
            "name": "H_Matryoshka_Slash32",
            "type": "host",
            "ipv4-address": "10.70.5.20",
        }
    )

    ctx.add_gw(
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
    ctx.cli_outputs[("ix-transit-gw-01", None)] = make_cli_output(
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

    ctx.add_gw(
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
    ctx.cli_outputs[("lpm-matryoshka-gw", None)] = make_cli_output(
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

    ctx.add_gw(
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
    ctx.cli_outputs[("anomaly-audit-gw", None)] = make_cli_output(
        ip_routes=[
            "default via 10.254.254.254 dev eth5 proto static",
            "10.254.1.0/24 dev eth1 proto kernel scope link src 10.254.1.1",
            "10.254.2.0/24 dev eth2 proto kernel scope link src 10.254.2.1",
            "10.254.254.0/24 dev eth5 proto kernel scope link src 10.254.254.1",
        ]
    )

    for t_idx in range(2, 12):
        tr_name = f"ix-transit-gw-{t_idx:02d}"
        ctx.add_gw(
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
        ctx.cli_outputs[(tr_name, None)] = make_cli_output(
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
