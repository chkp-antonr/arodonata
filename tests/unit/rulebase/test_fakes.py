"""The paging fake serves layers the way CP did in Gate L (L2 and Run B): compared with recorded pages."""

from __future__ import annotations

from typing import Any

import pytest

from tests.unit.rulebase.fakes import load_fixture, page_by_rule_offset


def shape(page: dict[str, Any]) -> tuple:
    top = [
        (e.get("type"), e.get("uid"), e.get("from"), e.get("to"), [c.get("uid") for c in e.get("rulebase", [])])
        for e in page["rulebase"]
    ]
    return top, page.get("from"), page.get("to"), page.get("total")


@pytest.mark.parametrize("offset", [0, 2, 4])
def test_fake_pages_access_like_cp(offset):
    layer = load_fixture("domain_layer_fpcr_uat_active_network.json")
    recorded = load_fixture(f"paging_access_limit2_offset{offset}.json")
    assert shape(page_by_rule_offset(layer, 2, offset)) == shape(recorded)


@pytest.mark.parametrize(
    ("limit", "offset", "fixture"),
    [
        (1, 0, "paging_nat_limit1_offset0.json"),
        (1, 1, "paging_nat_limit1_offset1.json"),
        (2, 0, "paging_nat_limit2_offset0.json"),
        (3, 0, "paging_nat_limit3_offset0.json"),
    ],
)
def test_fake_pages_nat_like_cp(limit, offset, fixture):
    layer = load_fixture("nat_fpcr_uat_active.json")
    assert shape(page_by_rule_offset(layer, limit, offset)) == shape(load_fixture(fixture))


def test_full_last_page_omits_trailing_empty_section():
    layer = load_fixture("nat_fpcr_uat_active.json")
    names = [e["name"] for e in page_by_rule_offset(layer, 2, 0)["rulebase"]]
    assert "Manual Lower Rules" not in names
    assert "Manual Lower Rules" in [e["name"] for e in page_by_rule_offset(layer, 3, 0)["rulebase"]]
