"""parse_layer_response: recorded show-*-rulebase responses become LayerSnapshots (sections, rules, place-holders)."""

from __future__ import annotations

import pytest

from arodonata.rulebase.model import RuleItem
from arodonata.rulebase.parse import (
    find_parent_rule,
    link_placeholder,
    objects_map,
    parse_layer_response,
    parse_packages,
)
from tests.unit.rulebase.fakes import load_fixture


def test_parse_domain_layer_sections_and_items():
    snap = parse_layer_response(
        load_fixture("domain_layer_fpcr_uat_active_network.json"), "access", layer_domain_type="domain"
    )
    assert snap.layer_uid.startswith("f97e1159") and snap.layer_name == "FPCR_UAT_Active Network"
    assert snap.rulebase_type == "access" and snap.total == 6 and snap.layer_domain_type == "domain"
    assert [s.name for s in snap.sections] == [
        "FPCR_UAT_Section_4",
        "FPCR_UAT_Section_3",
        "FPCR_UAT_Section_2",
        "FPCR_UAT_Section_1",
        "Cleanup",
    ]
    assert [(s.from_number, s.to_number, s.rules_before, s.seq) for s in snap.sections] == [
        (1, 2, 0, 0),
        (3, 3, 2, 1),
        (4, 4, 3, 2),
        (5, 5, 4, 3),
        (6, 6, 5, 4),
    ]
    assert "rulebase" not in snap.sections[0].raw
    assert [i.rule_number for i in snap.items] == [1, 2, 3, 4, 5, 6]
    assert {i.kind for i in snap.items} == {"rule"} and {i.domain_type for i in snap.items} == {"domain"}
    assert snap.items[1].inline_layer_uid.startswith("dbfa273a")
    assert snap.items[0].section_uid == snap.sections[0].uid and snap.items[5].section_uid == snap.sections[4].uid


def test_parse_global_layer_keeps_placeholder():
    snap = parse_layer_response(load_fixture("global_layer_no_package.json"), "access")
    assert [(i.rule_number, i.kind) for i in snap.items] == [(1, "rule"), (2, "place-holder"), (3, "rule")]
    assert snap.items[1].uid.startswith("7381ddc0") and snap.items[1].domain_type == "global domain"


def test_parse_nat_layer_name_sections_and_auto_generated():
    snap = parse_layer_response(load_fixture("nat_fpcr_uat_active.json"), "nat", layer_name="FPCR_UAT_Active")
    assert snap.layer_name == "FPCR_UAT_Active" and snap.layer_uid.startswith("25d7c8f1")
    assert len(snap.sections) == 7
    assert [(s.from_number, s.to_number) for s in snap.sections[:5]] == [(None, None)] * 5
    assert (snap.sections[5].name, snap.sections[5].from_number, snap.sections[5].to_number) == (
        "Automatic Generated Rules : Network Hide NAT",
        1,
        2,
    )
    lower = snap.sections[6]
    assert (lower.name, lower.from_number, lower.rules_before, lower.seq) == ("Manual Lower Rules", None, 2, 6)
    assert [i.auto_generated for i in snap.items] == [True, True]


def test_parse_nat_manual_rule_outside_section():
    snap = parse_layer_response(load_fixture("nat_manual_and_auto.json"), "nat", layer_name="FPCR_UAT_Active")
    first, last = snap.items[0], snap.items[-1]
    assert (first.rule_number, first.section_uid, first.auto_generated) == (1, None, False)
    assert last.rule_number == 4 and last.auto_generated is False
    assert last.section_uid == next(s.uid for s in snap.sections if s.name == "Manual Lower Rules")


def test_parse_empty_layer():
    snap = parse_layer_response(load_fixture("threat_ips_empty.json"), "threat")
    assert (snap.layer_name, snap.total, snap.items, snap.sections) == ("IPS", 0, (), ())


def test_parse_threat_rule_without_name():
    snap = parse_layer_response(load_fixture("threat_fpcr_uat_active.json"), "threat")
    assert [(i.rule_number, i.name) for i in snap.items] == [(1, "")]


def test_parse_skips_unknown_item_types_and_tolerates_dict_inline_layer():
    data = {
        "uid": "L",
        "name": "L",
        "total": 2,
        "rulebase": [
            {"uid": "x", "type": "something-else", "rule-number": 9},
            {"uid": "r1", "type": "access-rule", "rule-number": 1, "inline-layer": {"uid": "IN", "name": "In"}},
            {"uid": "r2", "type": "access-rule", "rule-number": 2, "enabled": False},
        ],
    }
    snap = parse_layer_response(data, "access")
    assert [i.uid for i in snap.items] == ["r1", "r2"]
    assert snap.items[0].inline_layer_uid == "IN" and snap.items[1].enabled is False


def test_parse_objects_dictionary_trimmed_and_mapped():
    snap = parse_layer_response(load_fixture("domain_layer_fpcr_uat_active_network.json"), "access")
    assert snap.objects_dictionary and all(set(o) == {"uid", "name", "type"} for o in snap.objects_dictionary)
    names = objects_map(snap.objects_dictionary)
    assert "Accept" in names.values() and "Inner Layer" in names.values()


def test_parse_requires_uid():
    with pytest.raises(ValueError, match="no uid"):
        parse_layer_response({"name": "L", "rulebase": []}, "access")


def test_rule_item_is_frozen():
    item = parse_layer_response(load_fixture("inline_layer_fpcr_uat_active_inline.json"), "access").items[0]
    assert isinstance(item, RuleItem)
    with pytest.raises(AttributeError):
        item.name = "x"  # type: ignore[misc]


def _fpcr_package() -> dict:
    return next(p for p in load_fixture("packages_domain4_after_assign.json") if p["name"] == "FPCR_UAT_Active")


def _layers(layout, rulebase_type):
    return [
        (o.position, o.slot, o.layer_uid[:8], o.layer_name, o.layer_domain_type)
        for o in layout.layers
        if o.rulebase_type == rulebase_type
    ]


def test_parse_packages_domain4_after_assignment():
    [layout] = parse_packages([_fpcr_package()])
    assert layout.package_name == "FPCR_UAT_Active"
    assert _layers(layout, "access") == [
        (0, "", "6ce00050", "arod-global-pkg Network", "global domain"),
        (1, "", "70d7954f", "FPCR_UAT_Active AppControl", "domain"),
        (2, "", "f97e1159", "FPCR_UAT_Active Network", "domain"),
    ]
    assert _layers(layout, "threat") == [
        (0, "", "8fb547ec", "IPS", "domain"),
        (1, "", "872c5651", "FPCR_UAT_Active Threat Prevention", "domain"),
    ]
    assert _layers(layout, "https") == [
        (0, "inbound", "26cdf190", "Default Inbound Layer", "domain"),
        (1, "outbound", "22ab8418", "Default Outbound Layer", "domain"),
    ]
    assert _layers(layout, "nat") == []  # no NAT read recorded for it


def test_parse_packages_nat_layer_from_nat_read():
    pkg = _fpcr_package()
    [layout] = parse_packages([pkg], nat_layer_uids={pkg["uid"]: "nat-uid"})
    assert [(o.layer_uid, o.layer_name) for o in layout.layers if o.rulebase_type == "nat"] == [
        ("nat-uid", "FPCR_UAT_Active")
    ]


def test_parse_packages_layers_sorted_by_type_then_position():
    [layout] = parse_packages([_fpcr_package()])
    keys = [(o.rulebase_type, o.position) for o in layout.layers]
    assert keys == sorted(keys)


def test_parse_packages_blade_flags_off():
    pkg = {
        "uid": "p",
        "name": "P",
        "access": True,
        "threat-prevention": False,
        "nat-policy": False,
        "https-inspection-policy": False,
        "access-layers": [{"uid": "a", "name": "P Network", "domain": {"domain-type": "domain"}}],
        "threat-layers": [{"uid": "t", "name": "IPS"}],
        "https-inspection-layers": {"inbound-https-layer": {"uid": "h", "name": "In"}},
    }
    [layout] = parse_packages([pkg], nat_layer_uids={"p": "n"})
    assert {o.rulebase_type for o in layout.layers} == {"access"}


def test_parse_packages_missing_threat_layers_key():
    pkg = {"uid": "p", "name": "P", "threat-prevention": False, "access-layers": []}
    assert parse_packages([pkg])[0].layers == ()


def test_parse_packages_global_domain_layout():
    layouts = {p.package_name: p for p in parse_packages(load_fixture("packages_global.json"))}
    assert _layers(layouts["Standard"], "access")[0][3:] == ("Network", "global domain")
    assert _layers(layouts["t-global-pkg"], "threat") == []


def test_parse_packages_rejects_layer_without_uid():
    with pytest.raises(ValueError, match="without uid"):
        parse_packages([{"uid": "p", "name": "P", "access-layers": [{"name": "X"}]}])


def test_parse_packages_rejects_package_without_uid():
    with pytest.raises(ValueError, match="invalid package"):
        parse_packages([{"name": "P"}])


def test_find_parent_rule_in_package_read():
    parent = find_parent_rule(load_fixture("global_layer_with_package.json"), "access", 2)
    assert parent is not None
    assert parent.uid.startswith("b11ecb3c") and parent.name == "Parent rule for Domain's policy"
    assert parent.domain_layer_uid.startswith("f97e1159")


def test_find_parent_rule_rejects_global_rule_and_missing_number():
    data = load_fixture("global_layer_with_package.json")
    assert find_parent_rule(data, "access", 1) is None  # domain-type 'global domain'
    assert find_parent_rule(data, "access", 9) is None
    assert find_parent_rule(load_fixture("global_layer_no_package.json"), "access", 2) is None  # place-holder type


def test_parent_rule_uid_differs_per_package():
    fpcr = find_parent_rule(load_fixture("global_layer_with_package.json"), "access", 2)
    std = find_parent_rule(load_fixture("global_layer_with_package_standard.json"), "access", 2)
    assert fpcr and std and std.uid.startswith("be70cc8b") and std.uid != fpcr.uid
    assert std.domain_layer_uid.startswith("0a0a023e")


def test_link_placeholder_drops_nested_layer_and_renumbers():
    [layout] = parse_packages([_fpcr_package()])
    glb = next(o for o in layout.layers if o.layer_domain_type == "global domain")
    parent = find_parent_rule(load_fixture("global_layer_with_package.json"), "access", 2)
    assert parent is not None
    placeholder = parse_layer_response(load_fixture("global_layer_no_package.json"), "access").items[1]
    linked = link_placeholder(layout, "access", glb.layer_uid, placeholder.uid, parent)
    access = [o for o in linked.layers if o.rulebase_type == "access"]
    assert [(o.position, o.layer_name) for o in access] == [
        (0, "arod-global-pkg Network"),
        (1, "FPCR_UAT_Active AppControl"),
    ]
    assert access[0].placeholder_uid == placeholder.uid and access[0].parent_rule_uid == parent.uid
    assert access[0].parent_rule_name == "Parent rule for Domain's policy"
    assert access[0].domain_layer_uid == parent.domain_layer_uid
    assert [o for o in linked.layers if o.rulebase_type == "threat"] == [
        o for o in layout.layers if o.rulebase_type == "threat"
    ]
