"""number_layer / number_package: SmartConsole numbering over parsed snapshots."""

from __future__ import annotations

from arodonata.rulebase.model import LayerSnapshot, OrderedLayer, PackageLayout, RuleItem, SectionItem
from arodonata.rulebase.numbering import number_layer, number_package, section_range
from arodonata.rulebase.parse import find_parent_rule, link_placeholder, parse_layer_response, parse_packages
from tests.unit.rulebase.fakes import load_fixture
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize


def rule(uid, n, *, section=None, inline=None, kind="rule", enabled=True):
    return RuleItem(
        uid=uid,
        name=uid,
        kind=kind,
        rule_number=n,
        enabled=enabled,
        section_uid=section,
        inline_layer_uid=inline,
        domain_type="domain",
        auto_generated=False,
        raw={},
    )


def section(uid, frm, to, before, seq):
    return SectionItem(uid=uid, name=uid, from_number=frm, to_number=to, rules_before=before, seq=seq, raw={})


def snap(uid, items=(), sections=(), rulebase_type="access"):
    return LayerSnapshot(
        rulebase_type=rulebase_type,
        layer_uid=uid,
        layer_name=uid,
        layer_domain_type="domain",
        total=len(items),
        sections=tuple(sections),
        items=tuple(items),
        objects_dictionary=(),
    )


def ordered(uid, position=0, rulebase_type="access", **link):
    return OrderedLayer(
        rulebase_type=rulebase_type,
        position=position,
        slot="",
        layer_uid=uid,
        layer_name=uid,
        layer_domain_type="domain",
        **link,
    )


def numbers(entries):
    return [e.number for e in entries if e.kind != "section"]


def domain4_layers() -> dict[str, LayerSnapshot]:
    parsed = [
        parse_layer_response(load_fixture("global_layer_no_package.json"), "access", layer_domain_type="global domain"),
        parse_layer_response(
            load_fixture("domain_layer_fpcr_uat_active_network.json"), "access", layer_domain_type="domain"
        ),
        parse_layer_response(load_fixture("inline_layer_fpcr_uat_active_inline.json"), "access"),
    ]
    return {layer.layer_uid: layer for layer in parsed}


def fpcr_layout(layers) -> PackageLayout:
    pkg = next(p for p in load_fixture("packages_domain4_after_assign.json") if p["name"] == "FPCR_UAT_Active")
    [layout] = parse_packages([pkg])
    glb = next(o for o in layout.layers if o.layer_domain_type == "global domain")
    placeholder = next(i for i in layers[glb.layer_uid].items if i.kind == "place-holder")
    parent = find_parent_rule(load_fixture("global_layer_with_package.json"), "access", placeholder.rule_number)
    assert parent is not None
    return link_placeholder(layout, "access", glb.layer_uid, placeholder.uid, parent)


def test_fpcr_uat_active_matches_smartconsole():
    layers = domain4_layers()
    first = number_package(fpcr_layout(layers), "access", layers)[0]
    assert summarize(first) == FPCR_UAT_ACTIVE_ACCESS
    parent = first[1]
    assert (
        parent.inline_layer_uid.startswith("f97e1159")
        and parent.item is not None
        and parent.item.kind == "place-holder"
    )
    inline_child = first[5]
    assert inline_child.layer_name == "FPCR_UAT_Active Inline" and inline_child.rule_number == 1
    assert first[3].section_name == "FPCR_UAT_Section_4" and first[3].section_uid == first[2].uid


def test_layers_without_package_context():
    layers = domain4_layers()
    glb = next(u for u, lyr in layers.items() if lyr.layer_name == "arod-global-pkg Network")
    dom = next(u for u, lyr in layers.items() if lyr.layer_name == "FPCR_UAT_Active Network")
    assert [(e.number, e.kind) for e in number_layer(glb, layers)] == [
        ("1", "rule"),
        ("2", "place-holder"),
        ("3", "rule"),
    ]
    assert numbers(number_layer(dom, layers)) == ["1", "2", "2.1", "2.2", "3", "4", "5", "6"]


def test_appcontrol_ordered_layer_restarts_at_1():
    layers = {"A": snap("A", [rule("a1", 1), rule("a2", 2)]), "B": snap("B", [rule("b1", 1), rule("b2", 2)])}
    layout = PackageLayout("p", "P", (ordered("A", 0), ordered("B", 1)))
    assert [numbers(e) for e in number_package(layout, "access", layers)] == [["1", "2"], ["1", "2"]]


def test_shared_inline_layer_used_by_two_rules_is_expanded_twice():
    layers = {"L": snap("L", [rule("r1", 1, inline="X"), rule("r2", 2, inline="X")]), "X": snap("X", [rule("x1", 1)])}
    assert numbers(number_layer("L", layers)) == ["1", "1.1", "2", "2.1"]


def test_inline_cycle_stops_on_path():
    layers = {"A": snap("A", [rule("a1", 1, inline="B")]), "B": snap("B", [rule("b1", 1, inline="A")])}
    assert numbers(number_layer("A", layers)) == ["1", "1.1"]


def test_missing_inline_layer_yields_no_children():
    layers = {"L": snap("L", [rule("r1", 1, inline="GONE"), rule("r2", 2)])}
    assert numbers(number_layer("L", layers)) == ["1", "2"]


def test_empty_section_between_populated_sections_keeps_order():
    layers = {
        "L": snap(
            "L",
            [rule("r1", 1, section="S1"), rule("r2", 2, section="S2")],
            [section("S1", 1, 1, 0, 0), section("E", None, None, 1, 1), section("S2", 2, 2, 1, 2)],
        )
    }
    assert [(e.kind, e.name, e.number, e.range) for e in number_layer("L", layers)] == [
        ("section", "S1", "", "1"),
        ("rule", "r1", "1", ""),
        ("section", "E", "", "No Rules"),
        ("section", "S2", "", "2"),
        ("rule", "r2", "2", ""),
    ]


def test_empty_sections_before_first_and_after_last_rule():
    """Shape of Anton's L5 illustration (temporary, never published): Sect1 (No Rules), Sect2 (2.1), Sect3 (No Rules)."""
    layers = {
        "G": snap("G", [rule("g1", 1), rule("ph", 2, kind="place-holder"), rule("g3", 3)]),
        "D": snap(
            "D",
            [rule("d1", 1, section="Sect2")],
            [section("Sect1", None, None, 0, 0), section("Sect2", 1, 1, 0, 1), section("Sect3", None, None, 1, 2)],
        ),
    }
    link = ordered("G", placeholder_uid="ph", parent_rule_uid="pr", parent_rule_name="Parent", domain_layer_uid="D")
    entries = number_layer("G", layers, ordered_layer=link)
    assert [(e.number, e.kind, e.name, e.range) for e in entries] == [
        ("1", "rule", "g1", ""),
        ("2", "parent-rule", "Parent", ""),
        ("", "section", "Sect1", "No Rules"),
        ("", "section", "Sect2", "2.1"),
        ("2.1", "rule", "d1", ""),
        ("", "section", "Sect3", "No Rules"),
        ("3", "rule", "g3", ""),
    ]
    assert entries[1].uid == "pr"


def test_section_range_formats():
    assert section_range("", 1, 2) == "1-2"
    assert section_range("2.", 1, 2) == "2.1-2.2"
    assert section_range("2.", 3, 3) == "2.3"
    assert section_range("", None, None) == "No Rules"
    assert section_range("2.", 4, None) == "No Rules"


def test_threat_and_https_ordered_layers_restart():
    layers = {
        u: snap(u, [rule(f"{u}1", 1)], rulebase_type=t)
        for u, t in (("IPS", "threat"), ("TP", "threat"), ("IN", "https"), ("OUT", "https"))
    }
    layout = PackageLayout(
        "p",
        "P",
        (
            ordered("IN", 0, "https"),
            ordered("OUT", 1, "https"),
            ordered("IPS", 0, "threat"),
            ordered("TP", 1, "threat"),
        ),
    )
    assert [numbers(e) for e in number_package(layout, "threat", layers)] == [["1"], ["1"]]
    assert [numbers(e) for e in number_package(layout, "https", layers)] == [["1"], ["1"]]


def test_package_without_global_layer():
    layers = domain4_layers()
    dom = next(u for u, lyr in layers.items() if lyr.layer_name == "FPCR_UAT_Active Network")
    layout = PackageLayout("p", "P", (ordered(dom),))
    assert numbers(number_package(layout, "access", layers)[0]) == ["1", "2", "2.1", "2.2", "3", "4", "5", "6"]


def test_global_layer_without_placeholder_is_plain_ordered_layer():
    layers = {"G": snap("G", [rule("g1", 1), rule("g2", 2)])}
    assert numbers(number_package(PackageLayout("p", "P", (ordered("G"),)), "access", layers)[0]) == ["1", "2"]


def test_global_domain_placeholder_not_descended():
    layers = domain4_layers()
    glb = next(u for u, lyr in layers.items() if lyr.layer_name == "arod-global-pkg Network")
    entries = number_package(PackageLayout("p", "P", (ordered(glb),)), "access", layers)[0]
    assert [(e.number, e.kind) for e in entries] == [("1", "rule"), ("2", "place-holder"), ("3", "rule")]


def test_failed_link_numbers_placeholder_without_descent():
    layers = {"G": snap("G", [rule("g1", 1), rule("ph", 2, kind="place-holder")]), "D": snap("D", [rule("d1", 1)])}
    entries = number_layer("G", layers, ordered_layer=ordered("G"))  # no link fields: the link read failed
    assert [(e.number, e.kind) for e in entries] == [("1", "rule"), ("2", "place-holder")]


def test_placeholder_inside_global_section():
    layers = {
        "G": snap(
            "G",
            [
                rule("g1", 1, section="GS"),
                rule("ph", 2, section="GS", kind="place-holder"),
                rule("g3", 3, section="GS"),
            ],
            [section("GS", 1, 3, 0, 0)],
        ),
        "D": snap("D", [rule("d1", 1)]),
    }
    link = ordered("G", placeholder_uid="ph", parent_rule_uid="pr", parent_rule_name="Parent", domain_layer_uid="D")
    entries = number_layer("G", layers, ordered_layer=link)
    assert [(e.number, e.kind, e.range) for e in entries] == [
        ("", "section", "1-3"),
        ("1", "rule", ""),
        ("2", "parent-rule", ""),
        ("2.1", "rule", ""),
        ("3", "rule", ""),
    ]
    assert entries[2].section_name == "GS"


def test_nat_numbering_is_flat_rule_number():
    nat = parse_layer_response(load_fixture("nat_manual_and_auto.json"), "nat", layer_name="FPCR_UAT_Active")
    entries = number_layer(nat.layer_uid, {nat.layer_uid: nat})
    assert numbers(entries) == ["1", "2", "3", "4"]
    assert [(e.kind, e.range) for e in entries if e.kind == "section"][-2:] == [("section", "2-3"), ("section", "4")]
    assert entries[0].kind == "rule" and entries[0].section_name is None
