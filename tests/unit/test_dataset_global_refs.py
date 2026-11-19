"""Unit tests verifying Enterprise Raw Dataset v1.2.0 Global cross-domain references and invariants."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from arodonata.testing.dataset_generator import (
    ALL_DOMAINS,
    DATASET_VERSION,
    DEFAULT_DATASET_DIR,
    USER_DOMAINS,
    ensure_enterprise_raw_dataset,
)


@pytest.mark.spec("SCN-ITEST-006-1", "SCN-ITEST-006-2", "SCN-ITEST-014-1")
def test_dataset_v120_global_refs_and_assignments() -> None:
    """Dataset v1.2.0 includes `show-global-assignments.json`, Global refs, and heterogeneous domain mix."""
    root = ensure_enterprise_raw_dataset()
    assert root == Path(DEFAULT_DATASET_DIR)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == DATASET_VERSION == "1.2.0"
    assert manifest["counts"]["total_domains"] == 10
    assert manifest["counts"]["total_assets"] == 341
    assert manifest["counts"]["policy_enforcing_gateways"] == 315
    assert manifest["counts"]["total_network_objects"] == 2951
    assert manifest["counts"]["total_service_objects"] == 210
    assert manifest["counts"]["total_access_rules"] == 1050
    assert manifest["counts"]["total_nat_rules"] == 120
    assert manifest["counts"]["total_cli_targets"] == 325

    ga_payload = json.loads((root / "mds" / "show-global-assignments.json").read_text(encoding="utf-8"))
    assert ga_payload["total"] == len(USER_DOMAINS) == 9
    assert {obj["dependent-domain"]["name"] for obj in ga_payload["objects"]} == set(USER_DOMAINS)
    for obj in ga_payload["objects"]:
        assert obj["global-domain"]["name"] == "Global"
        assert obj["global-access-policy"] == "Global_Standard_Pkg"
        assert obj["assignment-status"] == "assigned"

    expected_global_uids = {
        "uid-glob-grp-branches",
        "uid-glob-host-001",
        "uid-glob-grp-dc",
        "uid-global-svc-udp-53",
        "uid-global-svc-tcp-53",
    }
    for dom in USER_DOMAINS:
        d_slug = dom.lower()
        rb_path = root / "domains" / dom / "show-access-rulebase.json"
        rb_data = json.loads(rb_path.read_text(encoding="utf-8"))
        layer_payload = next(iter(rb_data.values()))
        assert layer_payload["total"] == 105

        dict_by_uid = {entry["uid"]: entry for entry in layer_payload["objects-dictionary"]}
        for g_uid in expected_global_uids:
            assert g_uid in dict_by_uid
            assert dict_by_uid[g_uid]["domain"] == {
                "uid": "uid-dom-global",
                "name": "Global",
                "domain-type": "global domain",
            }

        sec3_rules = layer_payload["rulebase"][2]["rulebase"]
        rule_104 = next(r for r in sec3_rules if r["uid"] == f"uid-arule-{d_slug}-0104")
        assert rule_104["rule-number"] == 104
        assert "uid-glob-grp-branches" in rule_104["source"]
        assert set(rule_104["destination"]) == {"uid-glob-host-001", "uid-glob-grp-dc"}
        assert set(rule_104["service"]) == {"uid-global-svc-udp-53", "uid-global-svc-tcp-53"}

    # Perimeter Rule #1 fixtures remain untouched for backward-compatible where-used assertions
    perim_rb = json.loads((root / "domains" / "Perimeter" / "show-access-rulebase.json").read_text(encoding="utf-8"))
    perim_layer = perim_rb["uid-layer-perimeter-security"]
    perim_rule_1 = perim_layer["rulebase"][0]["rulebase"][0]
    assert perim_rule_1["uid"] == "uid-arule-perimeter-0001"
    assert perim_rule_1["source"] == ["uid-perimeter-bulk-host-001"]

    # Every user domain contains heterogeneous gateway types (appliance, cluster, Virtual System) and cross-domain VSs
    cluster_types = {"CpmiGatewayCluster", "simple-cluster"}
    host_domain_by_uid: dict[str, str] = {}
    host_name_by_uid: dict[str, str] = {}
    vs_parent_pairs: list[tuple[str, str]] = []
    vs_entries_by_host: dict[str, list[tuple[int, str]]] = {}

    for dom in ALL_DOMAINS:
        gws_payload = json.loads(
            (root / "domains" / dom / "show-gateways-and-servers.json").read_text(encoding="utf-8")
        )
        for obj in gws_payload["objects"]:
            if obj.get("type") == "CpmiVsxNetobj":
                host_domain_by_uid[str(obj["uid"])] = dom
                host_name_by_uid[str(obj["uid"])] = str(obj["name"])
                vs_entries_by_host.setdefault(str(obj["name"]), [])

    for dom in ALL_DOMAINS:
        gws_payload = json.loads(
            (root / "domains" / dom / "show-gateways-and-servers.json").read_text(encoding="utf-8")
        )
        seen_gw_ips: set[str] = set()
        seen_if_ips: set[str] = set()
        seen_vs_subnets: set[str] = set()
        for obj in gws_payload["objects"]:
            gw_ip = obj.get("ipv4-address")
            if gw_ip:
                assert gw_ip not in seen_gw_ips, f"{dom}: duplicate gateway IP {gw_ip}"
                seen_gw_ips.add(str(gw_ip))
            for iface in obj.get("interfaces") or []:
                if_ip = iface.get("ipv4-address")
                if if_ip:
                    assert if_ip not in seen_if_ips, f"{dom}: duplicate interface IP {if_ip}"
                    seen_if_ips.add(str(if_ip))
                if obj.get("type") == "CpmiVsNetobj" and iface.get("topology") == "internal":
                    mask_len = iface.get("ipv4-mask-length")
                    if if_ip and mask_len is not None:
                        subnet = str(ipaddress.ip_network(f"{if_ip}/{mask_len}", strict=False))
                        assert subnet not in seen_vs_subnets, f"{dom}: duplicate VS internal subnet {subnet}"
                        seen_vs_subnets.add(subnet)

            obj_type = str(obj.get("type") or "")
            if obj_type in ("simple-gateway", "cluster-member"):
                assert (root / "cli" / f"{obj['name']}__vs_none.txt").is_file()
                assert (root / "tasks" / f"{obj['name']}__vs_none.json").is_file()
            elif obj_type == "CpmiVsNetobj":
                p_uid = str(obj.get("parent-uid") or (obj.get("vsx-gateway") or {}).get("uid") or "")
                vs_parent_pairs.append((dom, p_uid))
                host_name = host_name_by_uid[p_uid]
                vsid = 12 if obj["name"] == "dc-vs-tier2-app" else int(obj["vsid"])
                vs_entries_by_host.setdefault(host_name, []).append((vsid, str(obj["name"])))
                assert (root / "cli" / f"{host_name}__vs_{vsid}.txt").is_file()
                assert (root / "tasks" / f"{host_name}__vs_{vsid}.json").is_file()

        if dom in USER_DOMAINS:
            gw_types = {str(obj.get("type") or "") for obj in gws_payload["objects"]}
            assert "simple-gateway" in gw_types, f"{dom} missing simple-gateway"
            assert gw_types & cluster_types, f"{dom} missing cluster gateway"
            assert "CpmiVsNetobj" in gw_types, f"{dom} missing Virtual System"

        generics_payload = json.loads(
            (root / "domains" / dom / "show-generic-objects.json").read_text(encoding="utf-8")
        )
        for objs in generics_payload.values():
            assert not any(str(g.get("uid") or "").startswith("uid-slot-uid-") for g in objs)

    assert len(vs_entries_by_host) == 6
    for host_name, vs_entries in vs_entries_by_host.items():
        stat_path = root / "cli" / f"{host_name}__vsx_stat_l.txt"
        assert stat_path.is_file()
        stat_text = stat_path.read_text(encoding="utf-8")
        for vsid, vs_name in vs_entries:
            assert f"VSID:            {vsid}" in stat_text
            assert f"Name:            {vs_name}" in stat_text

    dc_spine_generics = json.loads(
        (root / "domains" / "DC_Spine" / "show-generic-objects.json").read_text(encoding="utf-8")
    )
    vsx_slot0_objs = dc_spine_generics.get("com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj", [])
    chassis2_slot0 = [g for g in vsx_slot0_objs if g.get("uid") == "uid-slot0-chassis-02"]
    assert len(chassis2_slot0) == 1
    vs_slot_objs = dc_spine_generics.get("com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj", [])
    chassis2_vs_slots = [g for g in vs_slot_objs if g.get("vsxGateway") == "uid-slot0-chassis-02"]
    assert {int(g["vsid"]) for g in chassis2_vs_slots} == {*range(2, 16), 21, 22, 23, 31, 32}

    cross_domain_vs = [
        (dom, host_domain_by_uid[p_uid])
        for dom, p_uid in vs_parent_pairs
        if host_domain_by_uid.get(p_uid) and host_domain_by_uid[p_uid] != dom
    ]
    assert len(cross_domain_vs) >= 15
    assert ("DB_Seg", "DC_Spine") in cross_domain_vs
    assert ("Branch", "Regional") in cross_domain_vs
    assert ("Regional", "Branch") in cross_domain_vs
