"""Bulk object generation, Global domain tagging, and policy/rulebase builders."""

from __future__ import annotations

import random
from typing import Any

from arodonata.core.models.sentinels import ACCEPT_UID, ANY_UID, DROP_UID, LOG_TRACK_UID

from ._dataset_common import (
    ALL_DOMAINS,
    DOMAIN_PKG_NAMES,
    GLOBAL_DOMAIN_META_RAW,
    RULE_104_GLOBAL_UIDS,
    USER_DOMAINS,
    DatasetBuildContext,
)


def populate_bulk_objects(ctx: DatasetBuildContext, rng: random.Random) -> None:
    """Populate bulk hosts/networks/ranges/groups across user domains and tag Global ownership metadata."""
    for d_idx, dom in enumerate(USER_DOMAINS, start=1):
        d_slug = dom.lower()
        dom_host_uids: list[str] = []
        for h_i in range(1, 151):
            h_uid = f"uid-{d_slug}-bulk-host-{h_i:03d}"
            dom_host_uids.append(h_uid)
            ctx.hosts_by_domain[dom].append(
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
            ctx.networks_by_domain[dom].append(
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
            ctx.ranges_by_domain[dom].append(
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
            ctx.groups_by_domain[dom].append(
                {
                    "uid": g_uid,
                    "name": f"G_{dom}_TierGroup_{g_i:03d}",
                    "type": "group",
                    "members": sample_members,
                }
            )

    for global_coll in (
        ctx.hosts_by_domain["Global"],
        ctx.networks_by_domain["Global"],
        ctx.ranges_by_domain["Global"],
        ctx.groups_by_domain["Global"],
        ctx.dns_domains_by_domain["Global"],
        ctx.services_tcp_by_domain["Global"],
        ctx.services_udp_by_domain["Global"],
        ctx.services_icmp_by_domain["Global"],
        ctx.service_groups_by_domain["Global"],
    ):
        for global_item in global_coll:
            global_item.setdefault("domain", dict(GLOBAL_DOMAIN_META_RAW))


def populate_policies_and_rulebases(ctx: DatasetBuildContext) -> tuple[int, int]:
    """Build policy packages, access layers, access rulebases, and NAT rulebases for all domains."""
    global_lookup: dict[str, dict[str, Any]] = {}
    for global_coll in (
        ctx.hosts_by_domain["Global"],
        ctx.networks_by_domain["Global"],
        ctx.groups_by_domain["Global"],
        ctx.services_tcp_by_domain["Global"],
        ctx.services_udp_by_domain["Global"],
    ):
        for global_item in global_coll:
            if global_item.get("uid"):
                global_lookup[str(global_item["uid"])] = global_item

    total_access_rules = 0
    total_nat_rules = 0

    for dom in ALL_DOMAINS:
        d_slug = dom.lower()
        pkg_name = DOMAIN_PKG_NAMES[dom]
        pkg_uid = f"uid-pkg-{d_slug}"
        layer_uid = f"uid-layer-{d_slug}-security"
        layer_name = f"{pkg_name} Network"

        dom_gw_targets = [
            {"uid": g["uid"], "name": g["name"], "type": g["type"]}
            for g in ctx.gateways_by_domain[dom]
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
        ctx.packages_by_domain[dom].append(pkg_obj)
        ctx.access_layers_by_domain[dom].append(
            {
                "uid": layer_uid,
                "name": layer_name,
                "type": "access-layer",
                "firewall": True,
                "applications-and-url-filtering": True,
            }
        )

        obj_dict: list[dict[str, Any]] = [
            {"uid": ANY_UID, "name": "Any", "type": "CpmiAnyObject"},
            {"uid": ACCEPT_UID, "name": "Accept", "type": "RulebaseAction"},
            {"uid": DROP_UID, "name": "Drop", "type": "RulebaseAction"},
            {"uid": LOG_TRACK_UID, "name": "Log", "type": "Track"},
        ]
        dom_hosts = ctx.hosts_by_domain[dom][:30]
        dom_nets = ctx.networks_by_domain[dom][:20]
        dom_svcs = ctx.services_tcp_by_domain[dom]
        seen_dict_uids: set[str] = {str(item["uid"]) for item in obj_dict}
        for item in (*dom_hosts, *dom_nets, *dom_svcs):
            obj_dict.append(item)
            seen_dict_uids.add(str(item["uid"]))
        if dom != "Global":
            for g_uid in RULE_104_GLOBAL_UIDS:
                g_item = global_lookup.get(g_uid)
                if g_item is not None and g_uid not in seen_dict_uids:
                    obj_dict.append(g_item)
                    seen_dict_uids.add(g_uid)

        sections: list[dict[str, Any]] = []
        rule_num = 1
        for sec_idx in range(1, 4):
            sec_rules: list[dict[str, Any]] = []
            sec_start = rule_num
            for _ in range(35):
                src_obj = dom_hosts[(rule_num - 1) % len(dom_hosts)] if dom_hosts else {"uid": ANY_UID, "name": "Any"}
                dst_obj = dom_nets[(rule_num - 1) % len(dom_nets)] if dom_nets else {"uid": ANY_UID, "name": "Any"}
                svc_obj = dom_svcs[(rule_num - 1) % len(dom_svcs)] if dom_svcs else {"uid": ANY_UID, "name": "Any"}
                act_uid = DROP_UID if rule_num == 105 else ACCEPT_UID
                if dom != "Global" and rule_num == 104:
                    src_list = ["uid-glob-grp-branches", src_obj["uid"]]
                    dst_list = ["uid-glob-host-001", "uid-glob-grp-dc"]
                    svc_list = ["uid-global-svc-udp-53", "uid-global-svc-tcp-53"]
                    rule_comment = f"Enterprise global DNS & branch-to-DC access rule #104 in {dom}"
                else:
                    src_list = [src_obj["uid"]]
                    dst_list = [dst_obj["uid"]]
                    svc_list = [svc_obj["uid"]]
                    rule_comment = f"Generated enterprise access rule #{rule_num} in {dom}"
                sec_rules.append(
                    {
                        "uid": f"uid-arule-{d_slug}-{rule_num:04d}",
                        "name": f"{dom}_Rule_{rule_num:03d}",
                        "type": "access-rule",
                        "rule-number": rule_num,
                        "enabled": True,
                        "source": src_list,
                        "source-negate": False,
                        "destination": dst_list,
                        "destination-negate": False,
                        "service": svc_list,
                        "service-negate": False,
                        "action": act_uid,
                        "track": {"type": LOG_TRACK_UID},
                        "install-on": [ANY_UID],
                        "comments": rule_comment,
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

        ctx.access_rulebases_by_domain[dom][layer_uid] = {
            "uid": layer_uid,
            "name": layer_name,
            "rulebase": sections,
            "objects-dictionary": obj_dict,
            "from": 1,
            "to": 105,
            "total": 105,
        }

        nat_rules: list[dict[str, Any]] = []
        for n_r in range(1, 13):
            orig_src = dom_hosts[(n_r - 1) % len(dom_hosts)]["uid"] if dom_hosts else ANY_UID
            nat_rules.append(
                {
                    "uid": f"uid-nrule-{d_slug}-{n_r:03d}",
                    "name": f"{dom}_NAT_{n_r:03d}",
                    "type": "nat-rule",
                    "rule-number": n_r,
                    "enabled": True,
                    "method": "hide",
                    "original-source": orig_src,
                    "original-destination": ANY_UID,
                    "original-service": ANY_UID,
                    "translated-source": orig_src,
                    "translated-destination": ANY_UID,
                    "translated-service": ANY_UID,
                    "install-on": [ANY_UID],
                }
            )
            total_nat_rules += 1

        ctx.nat_rulebases_by_domain[dom][pkg_name] = {
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

    return total_access_rules, total_nat_rules
