"""Dataset builders for `DC_Spine` and `DC_Pod` VSX domains."""

from __future__ import annotations

from ._dataset_common import DatasetBuildContext, make_cli_output


def populate_dc_spine_domain(ctx: DatasetBuildContext) -> None:
    """Populate `DC_Spine` physical VSX chassis (`dc-vsx-chassis-01`, `dc-vsx-chassis-02`) and spine VSs."""
    ctx.chassis1_vs_uids = [
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
        "virtual-systems": ctx.chassis1_vs_uids,
    }
    ctx.add_gw("DC_Spine", chassis1_obj)
    ctx.add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj", chassis1_obj)
    ctx.init_vsx_stat("dc-vsx-chassis-01")
    ctx.add_generic(
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
    ctx.add_gw("DC_Spine", spine_vs01_summary)
    ctx.add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", spine_vs01_summary)
    ctx.add_generic("DC_Spine", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj", spine_vs01_slot)
    ctx.append_vsx_stat("dc-vsx-chassis-01", 1, "dc-vsx-spine-vs01")
    ctx.cli_outputs[("dc-vsx-chassis-01", 1)] = make_cli_output(
        [
            "default via 192.168.250.1 dev wrp0 proto static",
            "10.215.0.0/24 dev eth1.100 proto kernel scope link src 10.215.0.1",
            "10.220.0.0/16 via 10.215.0.2 dev eth1.100 proto bgp",
        ]
    )

    ctx.add_generic(
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

    ctx.chassis2_vs_uids = [f"uid-dc-vsx-spine-vs{idx:02d}" for idx in range(2, 16)]
    chassis2_obj = {
        "uid": "uid-dc-vsx-chassis-02",
        "name": "dc-vsx-chassis-02",
        "type": "CpmiVsxNetobj",
        "ipv4-address": "172.26.0.20",
        "virtual-systems": ctx.chassis2_vs_uids,
    }
    ctx.add_gw("DC_Spine", chassis2_obj)
    ctx.add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj", chassis2_obj)
    ctx.init_vsx_stat("dc-vsx-chassis-02")
    ctx.add_generic(
        "DC_Spine",
        "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
        {
            "uid": "uid-slot0-chassis-02",
            "name": "dc-vsx-chassis-02",
            "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
            "vsid": 0,
            "vsxGateway": "uid-dc-vsx-chassis-02",
        },
    )

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
        ctx.add_gw("DC_Spine", s_vs_obj)
        ctx.add_generic("DC_Spine", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", s_vs_obj)
        ctx.add_generic(
            "DC_Spine",
            "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
            {
                "uid": f"uid-slot-spine-vs{s_idx:02d}",
                "name": f"dc-vsx-chassis-02_{s_vs_name}",
                "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
                "vsid": s_idx,
                "vsxGateway": "uid-slot0-chassis-02",
                "targetCustomer": {"name": "DC_Spine", "uid": "uid-dom-dc_spine"},
            },
        )
        ctx.append_vsx_stat("dc-vsx-chassis-02", s_idx, s_vs_name)
        ctx.cli_outputs[("dc-vsx-chassis-02", s_idx)] = make_cli_output(
            [
                f"default via 192.168.250.{s_idx * 4 + 1} dev wrp0 proto static",
                f"10.215.{s_idx}.0/24 dev eth1.{100 + s_idx} proto kernel scope link src 10.215.{s_idx}.1",
            ]
        )


def populate_dc_pod_domain(ctx: DatasetBuildContext) -> None:
    """Populate `DC_Pod` cross-domain Virtual Systems (`dc-vs-tier1-web`, `dc-vs-tier2-app`, `dc-vs-pod-21..45`)."""
    ctx.networks_by_domain["DC_Pod"].append(
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
    ctx.add_gw("DC_Pod", tier1_vs)
    ctx.add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", tier1_vs)
    ctx.cli_outputs[("dc-vsx-chassis-01", 11)] = make_cli_output(
        [
            "default via 192.168.251.1 dev wrp11 proto static",
            "10.216.11.0/24 dev eth2.11 proto kernel scope link src 10.216.11.1",
            "10.220.77.0/24 via 10.216.11.254 dev eth2.11 proto ospf",
        ]
    )

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
    ctx.add_gw("DC_Pod", tier2_vs)
    ctx.add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", tier2_vs)
    ctx.cli_outputs[("dc-vsx-chassis-01", 12)] = make_cli_output(
        [
            "10.11.0.0/16 via 10.216.12.254 dev eth1.12 proto ospf",
            "10.220.77.0/24 via 10.217.12.254 dev eth2.12 proto ospf",
        ]
    )

    ctx.append_vsx_stat("dc-vsx-chassis-01", 11, "dc-vs-tier1-web")
    ctx.append_vsx_stat("dc-vsx-chassis-01", 12, "dc-vs-tier2-app")

    for pod_vsid in range(21, 46):
        pod_name = f"dc-vs-pod-{pod_vsid:02d}"
        pod_uid = f"uid-dc-vs-pod-{pod_vsid:02d}"
        pod_cidr = f"10.218.{pod_vsid}.0/24"
        pod_ip = f"10.218.{pod_vsid}.1"
        ctx.networks_by_domain["DC_Pod"].append(
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
        ctx.add_gw("DC_Pod", pod_obj)
        ctx.add_generic("DC_Pod", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", pod_obj)
        ctx.cli_outputs[("dc-vsx-chassis-01", pod_vsid)] = make_cli_output(
            [
                "default via 192.168.252.1 dev wrp0 proto static",
                f"{pod_cidr} dev eth1.{pod_vsid} proto kernel scope link src {pod_ip}",
            ]
        )
        ctx.append_vsx_stat("dc-vsx-chassis-01", pod_vsid, pod_name)
