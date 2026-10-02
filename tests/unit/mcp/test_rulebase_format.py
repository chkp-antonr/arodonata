from __future__ import annotations

import dataclasses
import re

import pytest

from arodonata.mcp.rulebase_format import (
    drop_disabled,
    package_layers,
    raw_entries,
    raw_package_entries,
    render_markdown,
    render_model_friendly,
    rows_from_entries,
    rows_from_live,
    rows_from_package,
)
from arodonata.rulebase.source import layer_rulebase_from_snapshot, package_rulebase_from_snapshot
from tests.unit.rulebase.fakes import domain4_snapshot

LIVE = {
    "name": "Network",
    "uid": "L1",
    "objects-dictionary": [
        {"uid": "s1", "name": "Any", "type": "CpmiAnyObject"},
        {"uid": "d1", "name": "web-srv", "type": "host"},
        {"uid": "v1", "name": "https", "type": "service-tcp"},
        {"uid": "a1", "name": "Accept", "type": "RulebaseAction"},
        {"uid": "t1", "name": "Log", "type": "Track"},
        {"uid": "g1", "name": "Very-Long-Group-Name-That-Would-Not-Fit-In-A-Column", "type": "group"},
        {"uid": "IL", "name": "Web-Inline", "type": "access-layer"},
    ],
    "rulebase": [
        {
            "type": "access-section",
            "uid": "sec-web",
            "name": "Web",
            "from": 1,
            "to": 2,
            "rulebase": [
                {
                    "type": "access-rule",
                    "rule-number": 1,
                    "name": "allow web",
                    "enabled": True,
                    "source": ["s1"],
                    "destination": ["d1"],
                    "service": ["v1"],
                    "action": "a1",
                    "track": {"type": "t1"},
                    "comments": "ok",
                    "inline-layer": "IL",
                },
                {
                    "type": "access-rule",
                    "rule-number": 2,
                    "name": "",
                    "enabled": False,
                    "source": ["s1"],
                    "destination": ["g1"],
                    "service": ["s1"],
                    "action": "a1",
                    "track": {"type": "t1"},
                    "source-negate": True,
                },
            ],
        },
    ],
}


def test_rows_from_live_numbered_with_section_row_and_named_inline_layer():
    rows = rows_from_live(LIVE)
    assert [(r.kind, r.number) for r in rows] == [("section", ""), ("rule", "1"), ("rule", "2")]
    assert (rows[0].name, rows[0].section_range) == ("Web", "1-2")
    assert rows[1].section == "Web" and rows[1].sources == ["Any"] and rows[1].destinations == ["web-srv"]
    assert rows[1].action == "Accept" and rows[1].track == "Log" and rows[1].inline_layer == "Web-Inline"
    assert rows[2].name == "" and rows[2].negate == {"source": True}


def test_rows_from_live_without_uid_still_numbers():
    rows = rows_from_live({k: v for k, v in LIVE.items() if k != "uid"})
    assert [r.number for r in rows if r.kind == "rule"] == ["1", "2"]


def test_rows_from_live_filtered_response_keeps_section_order():
    """A ``filter`` read is sparse: section A holds rule 3, section B rules 7-8."""

    def r(n):
        return {"type": "access-rule", "uid": f"r{n}", "name": f"r{n}", "rule-number": n}

    filtered = {
        "uid": "L1",
        "name": "Network",
        "rulebase": [
            {"type": "access-section", "uid": "A", "name": "A", "from": 3, "to": 3, "rulebase": [r(3)]},
            {"type": "access-section", "uid": "B", "name": "B", "from": 7, "to": 8, "rulebase": [r(7), r(8)]},
        ],
    }
    assert [(row.kind, row.name) for row in rows_from_live(filtered)] == [
        ("section", "A"),
        ("rule", "r3"),
        ("section", "B"),
        ("rule", "r7"),
        ("rule", "r8"),
    ]


def test_rows_from_live_keeps_inline_layer_name_from_the_rule():
    response = {
        "uid": "L1",
        "name": "Network",
        "rulebase": [
            {
                "type": "access-rule",
                "uid": "r1",
                "rule-number": 1,
                "name": "to inline",
                "inline-layer": {"uid": "IL", "name": "My Inline"},
            }
        ],
    }
    [row] = rows_from_live(response)
    assert row.inline_layer == "My Inline"


def test_cached_layer_rows_render_names_not_uids():
    result = layer_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active Network", "access")
    rows = rows_from_entries(result.entries, result.layer_names, result.layer_dictionaries)
    first = next(r for r in rows if r.number == "1")
    assert (first.sources, first.destinations, first.services, first.action, first.track) == (
        ["hostA_8"],
        ["hostA_0"],
        ["https"],
        "Accept",
        "Log",
    )
    jump = next(r for r in rows if r.number == "2")
    assert jump.action == "Inner Layer" and jump.inline_layer == "FPCR_UAT_Active Inline"
    assert [r.number for r in rows if r.kind == "rule"] == ["1", "2", "2.1", "2.2", "3", "4", "5", "6"]
    assert [(r.name, r.section_range) for r in rows if r.kind == "section"][0] == ("FPCR_UAT_Section_4", "1-2")


def test_package_rows_mark_parent_rule_and_layers():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    rows = rows_from_package(result)
    assert [r.name for r in rows if r.kind == "layer"] == ["arod-global-pkg Network", "FPCR_UAT_Active AppControl"]
    parent = next(r for r in rows if r.kind == "parent-rule")
    assert (parent.number, parent.action, parent.inline_layer) == ("2", "Domain Layer", "FPCR_UAT_Active Network")
    assert [r.number for r in rows if r.kind == "rule"][:5] == ["1", "2.1", "2.2", "2.2.1", "2.2.2"]
    only_app = rows_from_package(result, package_layers(result, "FPCR_UAT_Active AppControl"))
    assert [r.kind for r in only_app] == ["rule", "rule"]


def test_package_layers_selects_by_name_or_uid_and_lists_layers_when_unknown():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    app = result.layers[1][0]
    assert [o.layer_name for o, _ in package_layers(result)] == ["arod-global-pkg Network", app.layer_name]
    assert package_layers(result, app.layer_uid) == package_layers(result, app.layer_name) == [result.layers[1]]
    with pytest.raises(LookupError) as err:
        package_layers(result, "Nope")
    assert str(err.value) == (
        "'Nope' is not a access ordered layer of package FPCR_UAT_Active; "
        "its layers: arod-global-pkg Network, FPCR_UAT_Active AppControl"
    )


def test_package_layers_enabled_only_drops_disabled_rules_per_layer():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    ordered, entries = result.layers[1]
    first = entries[0]
    off = dataclasses.replace(first, item=dataclasses.replace(first.item, enabled=False))
    result = dataclasses.replace(result, layers=(result.layers[0], (ordered, (off, *entries[1:]))))
    [(_, kept)] = package_layers(result, ordered.layer_name, enabled_only=True)
    assert [e.number for e in kept] == [e.number for e in entries[1:]]


def test_raw_package_entries_announce_ordered_layers_only_when_several():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    both = raw_package_entries(package_layers(result), "standard")
    assert [(e["name"], e["position"]) for e in both if e["type"] == "ordered-layer"] == [
        ("arod-global-pkg Network", 0),
        ("FPCR_UAT_Active AppControl", 1),
    ]
    one = raw_package_entries(package_layers(result, "FPCR_UAT_Active AppControl"), "standard")
    assert [e["number"] for e in one] == ["1", "2"] and not [e for e in one if e.get("type") == "ordered-layer"]


def test_drop_disabled_removes_rule_and_its_inline_subtree():
    result = layer_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active Network", "access")
    jump = next(e for e in result.entries if e.number == "2")
    off = dataclasses.replace(jump, item=dataclasses.replace(jump.item, enabled=False))
    kept = drop_disabled([off if e is jump else e for e in result.entries])
    assert [e.number for e in kept if e.kind == "rule"] == ["1", "3", "4", "5", "6"]
    assert [e.name for e in kept if e.kind == "section"] == [e.name for e in result.entries if e.kind == "section"]


def test_raw_entries_shapes():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    entries = list(result.layers[0][1])
    raw = raw_entries(entries, "standard")
    assert raw[0]["number"] == "1" and raw[0]["layer"] == "arod-global-pkg Network" and raw[0]["depth"] == 0
    assert raw[1] == {
        "type": "parent-rule",
        "uid": entries[1].uid,
        "name": "Parent rule for Domain's policy",
        "number": "2",
        "depth": 0,
        "layer": "arod-global-pkg Network",
        "inline-layer": entries[1].inline_layer_uid,
    }
    assert raw[2]["range"] == "2.1-2.2" and raw[2]["depth"] == 1 and raw[2]["name"] == "FPCR_UAT_Section_4"


def test_markdown_has_no_padding_keeps_full_names_and_section_rows():
    md = render_markdown(rows_from_live(LIVE), "Network")
    assert md.startswith("# Rulebase: Network")
    assert "| # | Name | Source | Destination | Service | Action | Track | Enabled |" in md
    assert "Very-Long-Group-Name-That-Would-Not-Fit-In-A-Column" in md
    assert not re.search(r" {3,}\|", md), "cells must not be padded"
    assert "| 2 |" in md and "**Section: Web** (1-2)" in md and "`!Any`" in md


def test_markdown_marks_parent_rule_place_holder_and_nested_sections():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access")
    md = render_markdown(rows_from_package(result), "FPCR_UAT_Active")
    assert "**Layer: arod-global-pkg Network**" in md and "→ domain layer *FPCR_UAT_Active Network*" in md
    assert "↳ **Section: FPCR_UAT_Section_4** (2.1-2.2)" in md
    glb = layer_rulebase_from_snapshot(domain4_snapshot(), "arod-global-pkg Network", "access")
    md_glb = render_markdown(rows_from_entries(glb.entries, glb.layer_names, glb.layer_dictionaries), "g")
    assert "*(place-holder)*" in md_glb


def test_model_friendly_structure():
    out = render_model_friendly(rows_from_live(LIVE), "Network")
    assert "SECTION: Web (1-2)" in out and "RULE 1: allow web" in out and "  Sources: Any" in out
    assert "  Inline layer: Web-Inline" in out and "RULE 2: (unnamed) [DISABLED]" in out and "Sources: NOT Any" in out
    assert "Rules: 2" in out


def test_empty_rulebase_renders_message():
    assert "no rules" in render_markdown([], "Empty").lower()
