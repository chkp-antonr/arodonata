from __future__ import annotations

import re

from arodonata.mcp.rulebase_format import (
    render_markdown,
    render_model_friendly,
    rows_from_cached,
    rows_from_live,
)

from .fake_client import rule

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
    ],
    "rulebase": [
        {
            "type": "access-section",
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
                    "inline-layer": {"uid": "IL", "name": "Web-Inline"},
                    "inline-layer-rulebase": [
                        {
                            "type": "access-rule",
                            "rule-number": 1,
                            "name": "inner",
                            "enabled": False,
                            "source": ["g1"],
                            "destination": ["d1"],
                            "service": ["v1"],
                            "action": "a1",
                            "track": {"type": "t1"},
                        }
                    ],
                },
                {
                    "type": "access-rule",
                    "rule-number": 2,
                    "name": "",
                    "enabled": True,
                    "source": ["s1"],
                    "destination": ["s1"],
                    "service": ["s1"],
                    "action": "a1",
                    "track": {"type": "t1"},
                    "source-negate": True,
                },
            ],
        },
    ],
}


def test_rows_from_live_resolves_dictionary_sections_and_inline_rules():
    rows = rows_from_live(LIVE)
    assert [r.number for r in rows] == ["1", "1.1", "2"]
    assert rows[0].section == "Web" and rows[0].sources == ["Any"] and rows[0].destinations == ["web-srv"]
    assert rows[0].action == "Accept" and rows[0].track == "Log" and rows[0].inline_layer == "Web-Inline"
    assert rows[1].depth == 1 and rows[1].enabled is False and rows[1].sources[0].startswith("Very-Long")
    assert rows[2].name == "" and rows[2].negate == {"source": True}


def test_rows_from_cached_uses_model_fields_and_inline_lookup():
    parent = rule(1, "outer", inline="Web-Inline")
    inner = rule(1, "inner", layer="Web-Inline")
    rows = rows_from_cached(
        [parent, rule(2, "plain")], inline_lookup=lambda layer: [inner] if layer == "Web-Inline" else []
    )
    assert [r.number for r in rows] == ["1", "1.1", "2"] and rows[1].depth == 1 and rows[0].inline_layer == "Web-Inline"


def test_markdown_has_no_padding_and_keeps_full_names():
    md = render_markdown(rows_from_live(LIVE), "Network")
    assert md.startswith("# Rulebase: Network")
    assert "| # | Name | Source | Destination | Service | Action | Track | Enabled |" in md
    assert "Very-Long-Group-Name-That-Would-Not-Fit-In-A-Column" in md
    assert not re.search(r" {3,}\|", md), "cells must not be padded"
    assert "| 1.1 |" in md and "**Section: Web**" in md and "`!Any`" in md


def test_model_friendly_structure():
    out = render_model_friendly(rows_from_live(LIVE), "Network")
    assert "RULE 1: allow web" in out and "  Sources: Any" in out and "  Inline layer: Web-Inline" in out
    assert "  RULE 1.1: inner [DISABLED]" in out and "Sources: NOT Any" in out


def test_empty_rulebase_renders_message():
    assert "no rules" in render_markdown([], "Empty").lower()
