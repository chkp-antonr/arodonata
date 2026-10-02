"""fetch_full_rulebase: pages until total, offset from the previous page's ``to``, never a partial layer."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from arodonata.api.schemas import ApiCallResult
from arodonata.rulebase.pager import RULEBASE_PAGE_SIZE, UNSUPPORTED_CODES, RulebaseFetchError, fetch_full_rulebase
from tests.unit.rulebase.fakes import FakeRulebaseClient, flatten_rules, load_fixture, page_by_top_level_offset

CMD = "show-access-rulebase"
NETWORK = "FPCR_UAT_Active Network"
BASE = {"name": NETWORK, "details-level": "full", "use-object-dictionary": True}


def _client(page=None) -> FakeRulebaseClient:
    client = FakeRulebaseClient() if page is None else FakeRulebaseClient(page=page)
    client.add_layer(CMD, load_fixture("domain_layer_fpcr_uat_active_network.json"))
    return client


async def test_pages_until_total_with_offset_from_to():
    client = _client()
    data = await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE, page_size=2)
    assert [payload for _, payload in client.calls] == [
        {**BASE, "limit": 2, "offset": 0},
        {**BASE, "limit": 2, "offset": 2},
        {**BASE, "limit": 2, "offset": 4},
        {**BASE, "limit": 2, "offset": 5},
    ]
    assert [r["rule-number"] for r in flatten_rules(data["rulebase"])] == [1, 2, 3, 4, 5, 6]
    assert [s["name"] for s in data["rulebase"]] == [
        "FPCR_UAT_Section_4",
        "FPCR_UAT_Section_3",
        "FPCR_UAT_Section_2",
        "FPCR_UAT_Section_1",
        "Cleanup",
    ]
    assert data["uid"].startswith("f97e1159") and data["name"] == NETWORK and data["total"] == 6


async def test_default_page_size_is_100():
    client = _client()
    await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE)
    assert RULEBASE_PAGE_SIZE == 100
    assert [payload["limit"] for _, payload in client.calls] == [100]


async def test_failed_second_page_raises_not_partial():
    client = _client()
    real = client.api_call

    async def flaky(**kwargs):
        if kwargs["payload"]["offset"] > 0:
            return ApiCallResult(success=False, code="generic_error", message="boom")
        return await real(**kwargs)

    client.api_call = flaky  # type: ignore[method-assign]
    with pytest.raises(RulebaseFetchError) as err:
        await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE, page_size=2)
    assert err.value.code == "generic_error" and err.value.message == "boom"


async def test_non_dict_page_raises():
    class Client:
        async def api_call(self, **_):
            return SimpleNamespace(success=True, data=["not", "a", "dict"], code="", message="")

    with pytest.raises(RulebaseFetchError, match="non-dict"):
        await fetch_full_rulebase(Client(), "m1", "Domain4", CMD, BASE)


async def test_non_advancing_to_raises():
    client = _client()
    real = client.api_call

    async def stuck(**kwargs):
        kwargs["payload"] = {**kwargs["payload"], "offset": 0}  # always serves the first page
        return await real(**kwargs)

    client.api_call = stuck  # type: ignore[method-assign]
    with pytest.raises(RulebaseFetchError, match="did not advance"):
        await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE, page_size=2)


async def test_page_gap_raises():
    client = _client(page=page_by_top_level_offset)
    with pytest.raises(RulebaseFetchError, match="expected 4"):
        await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE, page_size=2)


async def test_section_split_across_pages_is_merged_by_uid():
    client = _client()
    data = await fetch_full_rulebase(client, "m1", "Domain4", CMD, BASE, page_size=1)
    assert len(client.calls) == 7
    first = data["rulebase"][0]
    assert first["name"] == "FPCR_UAT_Section_4"
    assert [r["rule-number"] for r in first["rulebase"]] == [1, 2]
    assert (first["from"], first["to"]) == (1, 2)
    assert len(data["rulebase"]) == 5


async def test_objects_dictionary_merged_by_uid():
    pages = {
        0: {
            "uid": "L",
            "name": "L",
            "from": 1,
            "to": 1,
            "total": 2,
            "rulebase": [{"uid": "r1", "type": "access-rule", "rule-number": 1}],
            "objects-dictionary": [{"uid": "a", "name": "A"}, {"uid": "b", "name": "B"}],
        },
        1: {
            "uid": "L",
            "name": "L",
            "from": 2,
            "to": 2,
            "total": 2,
            "rulebase": [{"uid": "r2", "type": "access-rule", "rule-number": 2}],
            "objects-dictionary": [{"uid": "b", "name": "B"}, {"uid": "c", "name": "C"}],
        },
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    data = await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"}, page_size=1)
    assert [o["uid"] for o in data["objects-dictionary"]] == ["a", "b", "c"]
    assert [r["uid"] for r in data["rulebase"]] == ["r1", "r2"]


async def test_empty_layer_returns_empty_rulebase():
    client = FakeRulebaseClient()
    client.add_layer(
        CMD, {"uid": "E", "name": "Empty", "rulebase": [], "objects-dictionary": [], "from": 0, "to": 0, "total": 0}
    )
    data = await fetch_full_rulebase(client, "m1", "D", CMD, {"name": "Empty"})
    assert data["rulebase"] == [] and data["name"] == "Empty" and len(client.calls) == 1


async def test_total_0_after_earlier_pages_raises():
    """total 0 reported on a second page is an error, never valid."""
    pages = {
        0: {
            "uid": "L",
            "name": "L",
            "from": 1,
            "to": 2,
            "total": 4,
            "rulebase": [
                {"uid": "r1", "type": "access-rule", "rule-number": 1},
                {"uid": "r2", "type": "access-rule", "rule-number": 2},
            ],
            "objects-dictionary": [],
        },
        2: {
            "uid": "L",
            "name": "L",
            "from": 3,
            "to": 3,
            "total": 0,  # INVALID: says 0 after having 2 rules
            "rulebase": [],
            "objects-dictionary": [],
        },
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    with pytest.raises(RulebaseFetchError, match="reported total 0 after 2 rules"):
        await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"}, page_size=2)


async def test_total_0_with_non_empty_rulebase_raises():
    """total 0 but page has items: contradiction, must raise."""
    pages = {
        0: {
            "uid": "L",
            "name": "L",
            "from": 1,
            "to": 1,
            "total": 0,  # INVALID: says 0 but has items
            "rulebase": [{"uid": "r1", "type": "access-rule", "rule-number": 1}],
            "objects-dictionary": [],
        }
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    with pytest.raises(RulebaseFetchError, match="reported total 0 with 1 items"):
        await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"})


def _single_page_client(page):
    class Client:
        def __init__(self) -> None:
            self.calls = 0

        async def api_call(self, **kwargs):
            self.calls += 1
            return ApiCallResult(success=True, data=page)

    return Client()


async def test_total_0_with_only_empty_sections_is_empty_layer():
    section = {"type": "nat-section", "uid": "s1", "name": "Automatic", "rulebase": []}
    page = {"uid": "N", "name": "Pkg", "total": 0, "rulebase": [section], "objects-dictionary": []}
    client = _single_page_client(page)
    data = await fetch_full_rulebase(client, "m1", "D", "show-nat-rulebase", {"package": "Pkg"})
    assert data["rulebase"] == [section] and client.calls == 1


async def test_total_0_with_nested_rule_raises():
    section = {
        "type": "nat-section",
        "uid": "s1",
        "name": "Automatic",
        "rulebase": [{"type": "nat-rule", "uid": "r1", "rule-number": 1}],
    }
    page = {"uid": "N", "name": "Pkg", "total": 0, "rulebase": [section], "objects-dictionary": []}
    with pytest.raises(RulebaseFetchError, match="reported total 0 with 1 items"):
        await fetch_full_rulebase(_single_page_client(page), "m1", "D", "show-nat-rulebase", {"package": "Pkg"})


async def test_page_missing_from_to_total_raises():
    """Page with no from/to/total keys must raise."""
    pages = {
        0: {
            "uid": "L",
            "name": "L",
            # Missing from, to, total
            "rulebase": [{"uid": "r1", "type": "access-rule", "rule-number": 1}],
            "objects-dictionary": [],
        }
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    with pytest.raises(RulebaseFetchError, match="has no from/to/total"):
        await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"})


async def test_non_dict_in_objects_dictionary_is_skipped():
    """Non-dict entries in objects-dictionary are safely ignored."""
    pages = {
        0: {
            "uid": "L",
            "name": "L",
            "from": 1,
            "to": 1,
            "total": 1,
            "rulebase": [{"uid": "r1", "type": "access-rule", "rule-number": 1}],
            "objects-dictionary": [
                {"uid": "a", "name": "A"},
                "not-a-dict",  # Invalid
                {"uid": "b", "name": "B"},
                None,  # Invalid
                {"uid": "c"},  # Valid but no name (still stored)
            ],
        }
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    data = await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"})
    assert [o["uid"] for o in data["objects-dictionary"]] == ["a", "b", "c"]


NAT_CMD = "show-nat-rulebase"
NAT_BASE = {"package": "FPCR_UAT_Active", "details-level": "full", "use-object-dictionary": True}


def _nat_client() -> FakeRulebaseClient:
    client = FakeRulebaseClient()
    client.add_layer(NAT_CMD, load_fixture("nat_fpcr_uat_active.json"), key="FPCR_UAT_Active")
    return client


async def test_trailing_empty_section_recovered_on_full_last_page():
    client = _nat_client()
    data = await fetch_full_rulebase(client, "m1", "Domain4", NAT_CMD, NAT_BASE, page_size=2)
    assert [payload for _, payload in client.calls] == [
        {**NAT_BASE, "limit": 2, "offset": 0},
        {**NAT_BASE, "limit": 2, "offset": 1},
    ]
    names = [e["name"] for e in data["rulebase"]]
    assert names[-1] == "Manual Lower Rules" and names.count("Manual Lower Rules") == 1
    assert [r["rule-number"] for r in flatten_rules(data["rulebase"])] == [1, 2]


async def test_no_extra_read_when_last_page_has_room():
    client = _nat_client()
    data = await fetch_full_rulebase(client, "m1", "Domain4", NAT_CMD, NAT_BASE, page_size=3)
    assert len(client.calls) == 1
    assert data["rulebase"][-1]["name"] == "Manual Lower Rules"


async def test_trailing_read_must_return_only_the_last_rule():
    pages = {
        0: {
            "uid": "L",
            "from": 1,
            "to": 2,
            "total": 2,
            "objects-dictionary": [],
            "rulebase": [
                {"uid": "r1", "type": "access-rule", "rule-number": 1},
                {"uid": "r2", "type": "access-rule", "rule-number": 2},
            ],
        },
        1: {"uid": "L", "from": 1, "to": 2, "total": 2, "objects-dictionary": [], "rulebase": []},
    }

    class Client:
        async def api_call(self, **kwargs):
            return ApiCallResult(success=True, data=pages[kwargs["payload"]["offset"]])

    with pytest.raises(RulebaseFetchError, match="trailing read"):
        await fetch_full_rulebase(Client(), "m1", "D", CMD, {"name": "L"}, page_size=2)


def test_unsupported_codes_are_command_not_found_only():
    assert UNSUPPORTED_CODES == frozenset({"generic_err_command_not_found"})
