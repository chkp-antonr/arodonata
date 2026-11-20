"""Heterogeneous multi-domain gateways, HA clusters, VSX hosts, and cross-domain Virtual Systems."""

from __future__ import annotations

from typing import Any

from ._dataset_common import (
    DOMAIN_PKG_NAMES,
    USER_DOMAINS,
    DatasetBuildContext,
    ExtraClusterSpec,
    ExtraGatewaySpec,
    ExtraVsSpec,
    ExtraVsxHostSpec,
    make_cli_output,
    make_internal_if,
)


def populate_heterogeneous_mix(ctx: DatasetBuildContext) -> None:
    """Populate the +57 heterogeneous gateway/cluster/VSX/cross-domain VS assets and render `vsx stat -l`."""
    domain_idx_map = {dom_name: idx for idx, dom_name in enumerate(USER_DOMAINS, start=1)}

    extra_simple_gws: tuple[ExtraGatewaySpec, ...] = (
        ExtraGatewaySpec("DC_Spine", "dc-spine-oob-gw-01", 1),
        ExtraGatewaySpec("DC_Spine", "dc-spine-oob-gw-02", 2),
        ExtraGatewaySpec("DC_Spine", "dc-spine-scale-gw-03", 3),
        ExtraGatewaySpec("DC_Pod", "dc-pod-bm-gw-01", 1),
        ExtraGatewaySpec("DC_Pod", "dc-pod-bm-gw-02", 2),
        ExtraGatewaySpec("DC_Pod", "dc-pod-vm-gw-03", 3),
        ExtraGatewaySpec("DC_Pod", "dc-pod-maestro-sg-04", 4),
    )
    for gw_spec in extra_simple_gws:
        d_i = domain_idx_map[gw_spec.domain]
        ext_ip = f"172.29.{d_i}.{gw_spec.host_id}"
        int_ip = f"10.{180 + d_i}.{gw_spec.host_id}.1"
        ctx.add_gw(
            gw_spec.domain,
            {
                "uid": f"uid-{gw_spec.name}",
                "name": gw_spec.name,
                "type": "simple-gateway",
                "ipv4-address": ext_ip,
                "policy": {"access-policy-installed": True, "access-policy-name": DOMAIN_PKG_NAMES[gw_spec.domain]},
                "interfaces": [
                    {"name": "eth0", "ipv4-address": ext_ip, "ipv4-mask-length": 24, "topology": "external"},
                    make_internal_if("eth1", int_ip),
                ],
            },
        )
        ctx.cli_outputs[(gw_spec.name, None)] = make_cli_output(
            [
                f"default via 172.29.{d_i}.254 dev eth0 proto static",
                f"10.{180 + d_i}.{gw_spec.host_id}.0/24 dev eth1 proto kernel scope link src {int_ip}",
            ]
        )

    extra_clusters: tuple[ExtraClusterSpec, ...] = (
        ExtraClusterSpec("Branch", "br-hq-cluster-01", "br-hq-node-1a", "br-hq-node-1b", 10),
        ExtraClusterSpec("Branch", "br-metro-cluster-02", "br-metro-node-2a", "br-metro-node-2b", 20),
        ExtraClusterSpec("WAN_Core", "wan-core-edge-cluster", "wan-core-edge-1a", "wan-core-edge-1b", 10),
        ExtraClusterSpec("Transit", "transit-ix-cluster", "transit-ix-1a", "transit-ix-1b", 10),
        ExtraClusterSpec("DC_Spine", "dc-spine-core-cluster", "dc-spine-core-1a", "dc-spine-core-1b", 10),
        ExtraClusterSpec("DC_Pod", "dc-pod-east-cluster", "dc-pod-east-1a", "dc-pod-east-1b", 10),
        ExtraClusterSpec(
            "DB_Seg", "db-seg-vault-cluster", "db-seg-vault-1a", "db-seg-vault-1b", 10, internal_only=True
        ),
    )
    for cl_spec in extra_clusters:
        d_i = domain_idx_map[cl_spec.domain]
        cl_uid = f"uid-{cl_spec.name}"
        m1_uid = f"uid-{cl_spec.m1_name}"
        m2_uid = f"uid-{cl_spec.m2_name}"
        if cl_spec.internal_only:
            vip = f"10.{180 + d_i}.{cl_spec.base}.1"
            m1_ip = f"10.{180 + d_i}.{cl_spec.base}.11"
            m2_ip = f"10.{180 + d_i}.{cl_spec.base}.12"
            sec_net = f"10.{180 + d_i}.{cl_spec.base + 10}"
            ifs = [make_internal_if("eth1", vip), make_internal_if("eth2", f"{sec_net}.1")]
            routes = [
                f"10.{180 + d_i}.{cl_spec.base}.0/24 dev eth1 proto kernel scope link src {vip}",
                f"{sec_net}.0/24 dev eth2 proto kernel scope link src {sec_net}.1",
            ]
        else:
            vip = f"172.29.{d_i}.{cl_spec.base}"
            m1_ip = f"172.29.{d_i}.{cl_spec.base + 1}"
            m2_ip = f"172.29.{d_i}.{cl_spec.base + 2}"
            int_ip = f"10.{180 + d_i}.{cl_spec.base}.1"
            ifs = [
                {"name": "eth0", "ipv4-address": vip, "ipv4-mask-length": 24, "topology": "external"},
                make_internal_if("eth1", int_ip),
            ]
            routes = [
                f"default via 172.29.{d_i}.254 dev eth0 proto static",
                f"10.{180 + d_i}.{cl_spec.base}.0/24 dev eth1 proto kernel scope link src {int_ip}",
            ]
        m1 = {
            "uid": m1_uid,
            "name": cl_spec.m1_name,
            "type": "cluster-member",
            "ipv4-address": m1_ip,
            "cluster-uid": cl_uid,
        }
        m2 = {
            "uid": m2_uid,
            "name": cl_spec.m2_name,
            "type": "cluster-member",
            "ipv4-address": m2_ip,
            "cluster-uid": cl_uid,
        }
        cl_obj = {
            "uid": cl_uid,
            "name": cl_spec.name,
            "type": "CpmiGatewayCluster",
            "ipv4-address": vip,
            "cluster-members": [m1, m2],
            "policy": {"access-policy-installed": True, "access-policy-name": DOMAIN_PKG_NAMES[cl_spec.domain]},
            "interfaces": ifs,
        }
        ctx.add_gw(cl_spec.domain, cl_obj)
        ctx.add_gw(cl_spec.domain, m1)
        ctx.add_gw(cl_spec.domain, m2)
        ctx.cli_outputs[(cl_spec.m1_name, None)] = make_cli_output(routes)
        ctx.cli_outputs[(cl_spec.m2_name, None)] = make_cli_output(routes)

    extra_vsx_hosts: tuple[ExtraVsxHostSpec, ...] = (
        ExtraVsxHostSpec("Regional", "reg-vsx-hub-01", "172.29.2.50", 3),
        ExtraVsxHostSpec("Branch", "br-vsx-campus-01", "172.29.1.50", 4),
        ExtraVsxHostSpec("Perimeter", "perim-vsx-chassis-01", "172.29.4.50", 5),
        ExtraVsxHostSpec("DC_Pod", "dc-pod-vsx-local-01", "172.29.7.50", 6),
    )
    vsx_host_meta: dict[str, dict[str, Any]] = {
        "dc-vsx-chassis-01": {
            "domain": "DC_Spine",
            "uid": "uid-dc-vsx-chassis-01",
            "slot0_uid": "uid-slot0-chassis-01",
            "wrp_idx": 1,
            "vs_list": ctx.chassis1_vs_uids,
        },
        "dc-vsx-chassis-02": {
            "domain": "DC_Spine",
            "uid": "uid-dc-vsx-chassis-02",
            "slot0_uid": "uid-slot0-chassis-02",
            "wrp_idx": 2,
            "vs_list": ctx.chassis2_vs_uids,
        },
    }
    for host_spec in extra_vsx_hosts:
        host_uid = f"uid-{host_spec.name}"
        slot0_uid = f"uid-slot0-{host_spec.name}"
        vs_uids: list[str] = []
        vsx_obj = {
            "uid": host_uid,
            "name": host_spec.name,
            "type": "CpmiVsxNetobj",
            "ipv4-address": host_spec.mgmt_ip,
            "virtual-systems": vs_uids,
        }
        ctx.add_gw(host_spec.domain, vsx_obj)
        ctx.add_generic(host_spec.domain, "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj", vsx_obj)
        ctx.add_generic(
            host_spec.domain,
            "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
            {
                "uid": slot0_uid,
                "name": host_spec.name,
                "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
                "vsid": 0,
                "vsxGateway": host_uid,
            },
        )
        vsx_host_meta[host_spec.name] = {
            "domain": host_spec.domain,
            "uid": host_uid,
            "slot0_uid": slot0_uid,
            "wrp_idx": host_spec.wrp_idx,
            "vs_list": vs_uids,
        }
        ctx.init_vsx_stat(host_spec.name)

    extra_virtual_systems: tuple[ExtraVsSpec, ...] = (
        ExtraVsSpec("dc-vsx-chassis-01", "DB_Seg", "db-seg-vs-vault-01", 51, internal_only=True),
        ExtraVsSpec("dc-vsx-chassis-01", "DB_Seg", "db-seg-vs-vault-02", 52, internal_only=True),
        ExtraVsSpec("dc-vsx-chassis-01", "Partner_DMZ", "partner-vs-extranet-01", 61),
        ExtraVsSpec("dc-vsx-chassis-02", "WAN_Core", "wan-vs-backbone-02", 21),
        ExtraVsSpec("dc-vsx-chassis-02", "Transit", "transit-vs-ix-01", 22),
        ExtraVsSpec("dc-vsx-chassis-02", "Transit", "transit-vs-ix-02", 23),
        ExtraVsSpec("dc-vsx-chassis-02", "Perimeter", "perim-vs-dmz-01", 31),
        ExtraVsSpec("dc-vsx-chassis-02", "Perimeter", "perim-vs-dmz-02", 32),
        ExtraVsSpec("reg-vsx-hub-01", "Regional", "reg-vs-campus-01", 1),
        ExtraVsSpec("reg-vsx-hub-01", "Regional", "reg-vs-campus-02", 2),
        ExtraVsSpec("reg-vsx-hub-01", "Branch", "br-vs-hub-01", 11),
        ExtraVsSpec("reg-vsx-hub-01", "Branch", "br-vs-hub-02", 12),
        ExtraVsSpec("reg-vsx-hub-01", "Branch", "br-vs-hub-03", 13),
        ExtraVsSpec("reg-vsx-hub-01", "WAN_Core", "wan-vs-peering-01", 21),
        ExtraVsSpec("br-vsx-campus-01", "Branch", "br-vs-guest-01", 1),
        ExtraVsSpec("br-vsx-campus-01", "Branch", "br-vs-iot-02", 2),
        ExtraVsSpec("br-vsx-campus-01", "Regional", "reg-vs-branch-agg-03", 11),
        ExtraVsSpec("perim-vsx-chassis-01", "Perimeter", "perim-vs-waf-01", 1),
        ExtraVsSpec("perim-vsx-chassis-01", "Perimeter", "perim-vs-b2c-02", 2),
        ExtraVsSpec("perim-vsx-chassis-01", "Partner_DMZ", "partner-vs-b2b-02", 11),
        ExtraVsSpec("perim-vsx-chassis-01", "Partner_DMZ", "partner-vs-api-03", 12),
        ExtraVsSpec("perim-vsx-chassis-01", "Transit", "transit-vs-peering-03", 21),
        ExtraVsSpec("dc-pod-vsx-local-01", "DC_Pod", "dc-pod-local-vs01", 1),
        ExtraVsSpec("dc-pod-vsx-local-01", "DC_Pod", "dc-pod-local-vs02", 2),
        ExtraVsSpec("dc-pod-vsx-local-01", "DB_Seg", "db-seg-vs-pod-03", 11, internal_only=True),
    )
    for vs_seq, vs_spec in enumerate(extra_virtual_systems, start=1):
        meta = vsx_host_meta[vs_spec.host_name]
        vs_uid = f"uid-{vs_spec.name}"
        meta["vs_list"].append(vs_uid)
        vs_dom_idx = domain_idx_map[vs_spec.domain]
        sub_octet = 40 + vs_seq
        int_ip = f"10.{180 + vs_dom_idx}.{sub_octet}.1"
        if vs_spec.internal_only:
            sec_ip = f"10.198.{sub_octet}.1"
            vs_ifs = [
                make_internal_if(f"eth1.{vs_spec.vsid}", int_ip),
                make_internal_if(f"eth2.{vs_spec.vsid}", sec_ip),
            ]
            vs_routes = [
                f"10.{180 + vs_dom_idx}.{sub_octet}.0/24 dev eth1.{vs_spec.vsid} proto kernel scope link src {int_ip}",
                f"10.198.{sub_octet}.0/24 dev eth2.{vs_spec.vsid} proto kernel scope link src {sec_ip}",
            ]
        else:
            wrp_net = f"192.168.{240 + meta['wrp_idx']}"
            wrp_ip = f"{wrp_net}.{10 + vs_spec.vsid}"
            vs_ifs = [
                {"name": "wrp0", "ipv4-address": wrp_ip, "ipv4-mask-length": 24, "topology": "external"},
                make_internal_if(f"eth1.{vs_spec.vsid}", int_ip),
            ]
            vs_routes = [
                f"default via {wrp_net}.1 dev wrp0 proto static",
                f"10.{180 + vs_dom_idx}.{sub_octet}.0/24 dev eth1.{vs_spec.vsid} proto kernel scope link src {int_ip}",
            ]
        vs_obj = {
            "uid": vs_uid,
            "name": vs_spec.name,
            "type": "CpmiVsNetobj",
            "vsid": vs_spec.vsid,
            "parent-uid": meta["uid"],
            "vsx-gateway": {"uid": meta["uid"], "name": vs_spec.host_name},
            "ipv4-address": int_ip,
            "policy": {"access-policy-installed": True, "access-policy-name": DOMAIN_PKG_NAMES[vs_spec.domain]},
            "interfaces": vs_ifs,
        }
        ctx.add_gw(vs_spec.domain, vs_obj)
        ctx.add_generic(vs_spec.domain, "com.checkpoint.objects.classes.dummy.CpmiVsNetobj", vs_obj)
        ctx.add_generic(
            meta["domain"],
            "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
            {
                "uid": f"uid-slot-{vs_spec.name}",
                "name": f"{vs_spec.host_name}_{vs_spec.name}",
                "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
                "vsid": vs_spec.vsid,
                "vsxGateway": meta["slot0_uid"],
                "targetCustomer": {"name": vs_spec.domain, "uid": f"uid-dom-{vs_spec.domain.lower()}"},
            },
        )
        ctx.cli_outputs[(vs_spec.host_name, vs_spec.vsid)] = make_cli_output(vs_routes)
        ctx.append_vsx_stat(vs_spec.host_name, vs_spec.vsid, vs_spec.name)

    for host_name, lines in ctx.vsx_stat_lines_by_host.items():
        ctx.vsx_stat_outputs[host_name] = "\n".join(lines) + "\n"
