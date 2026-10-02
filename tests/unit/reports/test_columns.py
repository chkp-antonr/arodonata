from __future__ import annotations

import json
from pathlib import Path

from arodonata.reports.changes.build import build_session
from arodonata.reports.changes.columns import COLUMNS, RULEBASE_ORDER, visible_columns
from tests.unit.reports.entries import access_rule, entry, ref, session_meta, threat_rule

FIELD_NAMES = json.loads((Path(__file__).parent / "fixtures" / "rule_field_names.json").read_text())


def test_column_fields_exist_in_recordings():
    for kind, columns in COLUMNS.items():
        recorded = set(FIELD_NAMES[f"{kind}-rule"])
        for column in columns:
            for field in (column.field, column.negate_field):
                assert field is None or field in recorded, f"{kind}: {field} not in any recording"


def _rules(*bodies):
    return build_session(entry(session_meta("s1"), added=bodies)).rules


def test_default_column_hidden_when_default_in_every_row():
    h1 = ref("h1", "web-1")
    rules = _rules(
        access_rule("r1", "a", layer="L", position=1, source=[h1]), access_rule("r2", "b", layer="L", position=2)
    )
    assert visible_columns("access", rules) == ["enabled", "number", "name", "source", "action", "track"]
    nameless = _rules(threat_rule("t1", layer="T", position=1), threat_rule("t2", layer="T", position=2))
    assert "name" not in visible_columns("threat", nameless)
    no_action = access_rule("r3", "c", layer="L", position=3)
    del no_action["action"]
    assert "action" not in visible_columns("access", _rules(no_action))
    # a value only one rule carries (the rule that will land in "Not placed in a package") keeps the column
    vpn = access_rule("r4", "d", layer="L", position=4, vpn=[ref("c1", "Community", "vpn-community-star")])
    assert "vpn" in visible_columns("access", [*rules, *_rules(vpn)])


def test_structural_columns_never_hidden():
    assert visible_columns("nat", []) == ["enabled", "number"]
    assert all(c.structural == (c.key in ("enabled", "number")) for cols in COLUMNS.values() for c in cols)


def test_rulebase_order_is_access_nat_threat_https():
    assert RULEBASE_ORDER == ("access", "nat", "threat", "https")
