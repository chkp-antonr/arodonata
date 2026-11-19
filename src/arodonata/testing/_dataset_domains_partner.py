"""Dataset builders for `DB_Seg` and `Partner_DMZ` domains."""

from __future__ import annotations

from ._dataset_common import DatasetBuildContext, make_cli_output


def populate_db_seg_domain(ctx: DatasetBuildContext) -> None:
    """Populate `DB_Seg` internal-only segmentation gateways and CLI outputs."""
    ctx.groups_by_domain["DB_Seg"].append(
        {
            "uid": "uid-dbseg-grp-clients",
            "name": "G_DB_Allowed_Clients",
            "type": "group",
            "members": ["G_Global_Branch_Supernet"],
        }
    )
    ctx.add_gw(
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
    ctx.cli_outputs[("db-seg-internal-fw-01", None)] = make_cli_output(
        [
            "10.11.0.0/16 via 10.210.1.254 dev eth1 proto static",
            "10.210.1.0/24 dev eth1 proto kernel scope link src 10.210.1.1",
            "10.220.77.0/24 dev eth2 proto kernel scope link src 10.220.77.1",
        ]
    )

    for db_idx in range(2, 16):
        fw_name = f"db-seg-internal-fw-{db_idx:02d}"
        ctx.add_gw(
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
        ctx.cli_outputs[(fw_name, None)] = make_cli_output(
            [
                f"10.210.{db_idx}.0/24 dev eth1 proto kernel scope link src 10.210.{db_idx}.1",
                f"10.220.{db_idx}.0/24 dev eth2 proto kernel scope link src 10.220.{db_idx}.1",
            ]
        )


def populate_partner_dmz_domain(ctx: DatasetBuildContext) -> None:
    """Populate `Partner_DMZ` one-arm gateways, drifting B2B cluster, external gateways, and CLI outputs."""
    ctx.networks_by_domain["Partner_DMZ"].extend(
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
    ctx.groups_by_domain["Partner_DMZ"].append(
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
        ctx.add_gw(
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
        ctx.cli_outputs[(oa_name, None)] = make_cli_output(
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
    ctx.add_gw("Partner_DMZ", b2b_cluster)
    ctx.add_gw("Partner_DMZ", b2b_m1)
    ctx.add_gw("Partner_DMZ", b2b_m2)

    ctx.cli_outputs[("partner-b2b-1a", None)] = make_cli_output(
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
    ctx.cli_outputs[("partner-b2b-1b", None)] = make_cli_output(
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
        ctx.add_gw(
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
        ctx.cli_outputs[(ext_name, None)] = make_cli_output(
            [
                "default via 172.30.100.254 dev eth0 proto static",
                f"172.30.{110 + ext_idx}.0/24 dev eth1 proto kernel scope link src 172.30.{110 + ext_idx}.1",
            ]
        )
