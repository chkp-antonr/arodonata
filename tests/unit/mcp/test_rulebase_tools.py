from __future__ import annotations

import json

import pytest

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.core.cache_mode import CacheMode
from arodonata.rulebase.source import AmbiguousLayerName, RulebaseCacheNotReady
from tests.unit.rulebase.fakes import domain4_snapshot, load_fixture, make_layer, page_by_rule_offset

from .fake_client import FakeArodonataClient, mcp_snapshot
from .helpers import cache_mode_enum, call_tool, make_server, payload, text, tool_input_schema

_RULEBASE_TOOLS = {
    # tool -> (addressing args, facade method)
    "show_access_rulebase": ({"name": "Network"}, "get_layer_rulebase"),
    "show_nat_rulebase": ({"package": "Standard"}, "get_package_rulebase"),
    "show_https_rulebase": ({"name": "Default Layer"}, "get_layer_rulebase"),
    "show_threat_rulebase": ({"name": "Standard Threat Prevention"}, "get_layer_rulebase"),
}


async def test_live_only_parameter_switches_to_api_call():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": [], "from": 0, "to": 0, "total": 0}
    )
    await call_tool(
        make_server(fake),
        "show_access_rulebase",
        {"name": "Network", "show_hits": True, "hits_settings": {"from_date": "2026-01-01"}},
    )
    name, kw = fake.calls[0]
    assert name == "api_call" and kw["command"] == "show-access-rulebase"
    assert kw["payload"] == {
        "name": "Network",
        "show-hits": True,
        "hits-settings": {"from-date": "2026-01-01"},
        "use-object-dictionary": True,
        "details-level": "full",
        "limit": 100,
        "offset": 0,
    }


async def test_offset_and_limit_slice_rows_before_rendering():
    fake = FakeArodonataClient()
    body = text(
        await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "limit": 1, "offset": 2})
    )
    assert "rows 3-3 of 3" in body and "| 2 |" in body


async def test_nat_schema_has_package_not_name_or_uid_while_access_has_both():
    server = make_server(FakeArodonataClient())
    nat_props = (await tool_input_schema(server, "show_nat_rulebase"))["properties"]
    access_props = (await tool_input_schema(server, "show_access_rulebase"))["properties"]
    https_props = (await tool_input_schema(server, "show_https_rulebase"))["properties"]
    threat_props = (await tool_input_schema(server, "show_threat_rulebase"))["properties"]
    assert "package" in nat_props and "name" not in nat_props and "uid" not in nat_props
    for props in (access_props, https_props, threat_props):
        assert "name" in props and "uid" in props and "package" in props


async def test_live_path_forwards_package():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": [], "from": 0, "to": 0, "total": 0}
    )
    await call_tool(
        make_server(fake),
        "show_access_rulebase",
        {"name": "Network", "package": "Standard", "show_hits": True},
    )
    name, kw = fake.calls[0]
    assert name == "api_call" and kw["payload"]["package"] == "Standard"


async def test_uid_on_live_path_is_sent_unchanged():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": [], "from": 0, "to": 0, "total": 0}
    )
    await call_tool(make_server(fake), "show_access_rulebase", {"uid": "layer-uid-1", "show_hits": True})
    assert [c[0] for c in fake.calls] == ["api_call"] and fake.calls[0][1]["payload"]["uid"] == "layer-uid-1"


@pytest.mark.parametrize(("tool", "spec"), _RULEBASE_TOOLS.items())
async def test_rulebase_cache_path_default_cache_mode_is_none(tool, spec):
    args, method = spec
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, args)
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == method and fake.calls[0][1]["cache_mode"] is None


@pytest.mark.parametrize(("tool", "spec"), _RULEBASE_TOOLS.items())
async def test_rulebase_cache_path_forwards_force_cache_mode(tool, spec):
    args, method = spec
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, {**args, "cache_mode": "force"})
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == method and fake.calls[0][1]["cache_mode"] == "force"


@pytest.mark.parametrize("tool", _RULEBASE_TOOLS)
async def test_rulebase_schema_publishes_read_cache_vocabulary(tool):
    schema = await tool_input_schema(make_server(FakeArodonataClient()), tool)
    assert cache_mode_enum(schema) == [m.value for m in CacheMode]
    assert schema["properties"]["cache_mode"].get("default") is None


async def test_rulebase_live_path_ignores_read_cache_mode_and_uses_session_default():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": [], "from": 0, "to": 0, "total": 0}
    )
    res = await call_tool(
        make_server(fake), "show_access_rulebase", {"name": "Network", "show_hits": True, "cache_mode": "force"}
    )
    assert res.is_error is False, text(res)
    name, kw = fake.calls[0]
    assert name == "api_call" and kw["cache_mode"] == "auto"


NETWORK = load_fixture("domain_layer_fpcr_uat_active_network.json")


def _serve_network(payload):
    return ApiCallResult(
        success=True, data=page_by_rule_offset(NETWORK, payload.get("limit"), payload.get("offset", 0))
    )


async def test_live_rulebase_keeps_objects_dictionary():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = _serve_network
    # What today's api_query path receives: include_container_key=False turns data into the bare rule list.
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data=NETWORK["rulebase"], objects=NETWORK["rulebase"], total=6
    )
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": NETWORK["name"], "show_hits": True})
    body = text(res)
    assert "hostA_8" in body and "Accept" in body and "FPCR_UAT_Active Inline" in body
    assert "79cd922f" not in body  # rule 1's source uid is resolved
    assert not any(name == "api_query" for name, _ in fake.calls)


async def test_live_rulebase_raw_format_includes_objects_dictionary():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = _serve_network
    res = await call_tool(
        make_server(fake), "show_access_rulebase", {"name": NETWORK["name"], "show_hits": True, "format": "raw"}
    )
    body = json.loads(text(res))
    assert any(o.get("name") == "hostA_8" for o in body["objects-dictionary"])
    assert isinstance(body["rulebase"], list)
    assert body["source"] == "live"
    # The envelope total counts rendered rows, not rules.
    assert body["total"] == 11


async def test_live_rulebase_api_call_payloads_default_and_explicit_limit():
    payloads, bodies = [], []
    for args in ({}, {"limit": 2, "offset": 1}):
        fake = FakeArodonataClient()
        fake.responses["api_call"] = _serve_network
        res = await call_tool(
            make_server(fake), "show_access_rulebase", {"name": NETWORK["name"], "show_hits": True, **args}
        )
        payloads.append([kw["payload"] for name, kw in fake.calls if name == "api_call"])
        bodies.append(text(res))
    expected = [
        {
            "name": NETWORK["name"],
            "show-hits": True,
            "use-object-dictionary": True,
            "details-level": "full",
            "limit": 100,
            "offset": 0,
        }
    ]
    assert payloads[0] == expected and payloads[1] == expected
    assert "rows 1-11 of 11" in bodies[0] and "rows 2-3 of 11" in bodies[1]


async def test_live_rulebase_fetch_error_is_tool_failure():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(success=False, code="generic_err_object_not_found", message="no layer")
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Nope", "show_hits": True})
    assert res.is_error is True and text(res) == "generic_err_object_not_found: no layer"


async def test_cache_path_uses_get_layer_rulebase():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "domain": "General"})
    assert res.is_error is False and text(res).startswith("# Rulebase: Network") and "Source: cache" in text(res)
    assert fake.calls == [
        (
            "get_layer_rulebase",
            {
                "mgmt_name": "mgmt1",
                "domain_name": "General",
                "layer": "Network",
                "rulebase_type": "access",
                "cache_mode": None,
                "cache_ttl": None,
            },
        )
    ]


async def test_cache_path_shows_layer_relative_numbers_and_sections():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    body = text(
        await call_tool(
            make_server(fake),
            "show_access_rulebase",
            {"name": "FPCR_UAT_Active Network", "domain": "Domain4", "limit": 0},
        )
    )
    assert "| 2.1 |" in body and "| 2.2 |" in body and "**Section: FPCR_UAT_Section_4** (1-2)" in body
    assert "| 2.2.1 |" not in body  # layer-relative: no package context


async def test_cache_path_renders_names_not_uids():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    body = text(
        await call_tool(
            make_server(fake),
            "show_access_rulebase",
            {"name": "FPCR_UAT_Active Network", "domain": "Domain4", "limit": 0},
        )
    )
    assert "hostA_8" in body and "Inner Layer" in body and "inline layer *FPCR_UAT_Active Inline*" in body
    assert "79cd922f" not in body


async def test_cache_path_domainless_call_sms_and_mds_shapes():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network"})
    assert res.is_error is False and fake.calls[0][1]["domain_name"] is None
    fake.responses["get_layer_rulebase"] = RulebaseCacheNotReady("'Network' is not in any cached domain of mgmt1")
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network"})
    assert res.is_error is True and "refresh_rulebases" in text(res) and "domain" in text(res)


async def test_ambiguous_layer_name_is_tool_failure_listing_uids():
    fake = FakeArodonataClient()
    fake.responses["get_layer_rulebase"] = AmbiguousLayerName("Network", (("Domain4", "u-1"), ("Global", "u-2")))
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network"})
    assert res.is_error is True and "Domain4/u-1" in text(res) and "Global/u-2" in text(res)
    assert "uid" in text(res) and "domain" in text(res)


async def test_ambiguous_layer_name_in_one_domain_asks_for_uid():
    fake = FakeArodonataClient()
    fake.responses["get_layer_rulebase"] = AmbiguousLayerName("Network", (("Domain4", "u-1"), ("Domain4", "u-2")))
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "domain": "Domain4"})
    assert res.is_error is True
    assert text(res) == "'Network' matches several layers (Domain4/u-1, Domain4/u-2); pass uid"


async def test_ambiguous_uid_held_by_several_domains_asks_for_domain_only():
    fake = FakeArodonataClient()
    fake.responses["get_layer_rulebase"] = AmbiguousLayerName("u-1", (("Domain4", "u-1"), ("Domain5", "u-1")))
    res = await call_tool(make_server(fake), "show_access_rulebase", {"uid": "u-1"})
    assert res.is_error is True
    assert text(res) == "'u-1' matches several layers (Domain4/u-1, Domain5/u-1); pass domain"


async def test_ambiguous_package_name_asks_for_domain():
    fake = FakeArodonataClient()
    fake.responses["get_package_rulebase"] = AmbiguousLayerName("Standard", (("Domain4", "p-1"), ("Domain5", "p-2")))
    res = await call_tool(make_server(fake), "show_nat_rulebase", {"package": "Standard"})
    assert res.is_error is True
    assert text(res) == "package 'Standard' matches several packages (Domain4/p-1, Domain5/p-2); pass domain"


async def test_unknown_layer_is_tool_failure():
    res = await call_tool(
        make_server(FakeArodonataClient()), "show_access_rulebase", {"name": "Nope", "domain": "General"}
    )
    assert res.is_error is True and "Nope" in text(res) and "refresh_rulebases" in text(res)


async def test_cache_path_failed_status_renders_last_snapshot_with_note():
    fake = FakeArodonataClient()
    fake.status, fake.last_error = "failed", "dirty session"
    body = text(await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "domain": "General"}))
    assert "| 1 |" in body and "dirty session" in body and "last good snapshot" in body


async def test_cache_path_nat_by_package():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), "show_nat_rulebase", {})
    assert res.is_error is True and "package" in text(res)
    body = text(
        await call_tool(make_server(fake), "show_nat_rulebase", {"package": "Standard", "format": "model_friendly"})
    )
    assert "RULE 1: nat 1" in body
    assert fake.calls[-1][0] == "get_package_rulebase" and fake.calls[-1][1]["rulebase_type"] == "nat"


async def test_enabled_only_filters_after_numbering_numbers_unchanged():
    fake = FakeArodonataClient()
    fake.snapshot = mcp_snapshot()
    body = text(await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "enabled_only": True}))
    assert "| 1 |" in body and "| 1.1 |" in body and "| 2 |" not in body and "rows 1-2 of 2" in body


async def test_cache_age_from_sync_state():
    out = payload(
        await call_tool(
            make_server(FakeArodonataClient()), "show_access_rulebase", {"name": "Network", "format": "raw"}
        )
    )
    assert 595 <= out["cache_age_seconds"] <= 605


@pytest.mark.parametrize(("status", "last_error"), [("failed", "dirty session"), ("ok", None)])
async def test_raw_format_envelope_carries_sync_status(status, last_error):
    fake = FakeArodonataClient()
    fake.status, fake.last_error = status, last_error
    out = payload(await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "format": "raw"}))
    assert (out["status"], out["last_error"]) == (status, last_error)


async def test_raw_format_numbered_entries_and_dictionary():
    out = payload(
        await call_tool(
            make_server(FakeArodonataClient()), "show_access_rulebase", {"name": "Network", "format": "raw", "limit": 0}
        )
    )
    assert [e["number"] for e in out["rulebase"]] == ["1", "1.1", "2"] and out["total"] == 3
    assert out["rulebase"][1]["layer"] == "Inner" and out["source"] == "cache"
    assert {o["uid"] for o in out["objects-dictionary"]} >= {"any", "acc", "log"}


async def test_package_param_renders_smartconsole_numbers():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    body = text(
        await call_tool(
            make_server(fake), "show_access_rulebase", {"package": "FPCR_UAT_Active", "domain": "Domain4", "limit": 0}
        )
    )
    for number in ("| 1 |", "| 2 |", "| 2.1 |", "| 2.2.1 |", "| 3 |"):
        assert number in body
    assert fake.calls[-1][0] == "get_package_rulebase" and fake.calls[-1][1]["package"] == "FPCR_UAT_Active"


async def test_package_param_raw_format_marks_each_ordered_layer():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    out = payload(
        await call_tool(
            make_server(fake),
            "show_access_rulebase",
            {"package": "FPCR_UAT_Active", "domain": "Domain4", "format": "raw", "limit": 0},
        )
    )
    layers = [e["name"] for e in out["rulebase"] if e["type"] == "ordered-layer"]
    assert layers == ["arod-global-pkg Network", "FPCR_UAT_Active AppControl"]
    assert out["rulebase"][0]["type"] == "ordered-layer" and out["total"] == len(out["rulebase"])
    assert any(e.get("type") == "parent-rule" and e["number"] == "2" for e in out["rulebase"])


async def test_package_param_with_layer_filters_to_that_layer():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    body = text(
        await call_tool(
            make_server(fake),
            "show_access_rulebase",
            {"package": "FPCR_UAT_Active", "name": "FPCR_UAT_Active AppControl", "domain": "Domain4"},
        )
    )
    assert (
        body.startswith("# Rulebase: FPCR_UAT_Active AppControl") and "| 2.1 |" not in body and "rows 1-2 of 2" in body
    )


async def test_package_param_unknown_layer_is_tool_failure():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    res = await call_tool(
        make_server(fake), "show_access_rulebase", {"package": "FPCR_UAT_Active", "name": "Nope", "domain": "Domain4"}
    )
    assert res.is_error is True and "arod-global-pkg Network" in text(res)


async def test_without_package_numbers_unchanged():
    fake = FakeArodonataClient()
    fake.snapshot = domain4_snapshot("mgmt1", "Domain4")
    body = text(
        await call_tool(
            make_server(fake),
            "show_access_rulebase",
            {"name": "FPCR_UAT_Active Network", "domain": "Domain4", "limit": 0},
        )
    )
    assert "| 1 |" in body and "| 2.2.1 |" not in body


async def test_live_rows_numbered_with_sections():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = _serve_network
    body = text(
        await call_tool(
            make_server(fake), "show_access_rulebase", {"name": NETWORK["name"], "show_hits": True, "limit": 0}
        )
    )
    assert "**Section: FPCR_UAT_Section_4** (1-2)" in body and "| 2 |" in body and "Source: live" in body


def _serve_one_section_layer(rulebase_type: str):
    """Serve, paged like CP, a complete live layer: one ``<type>-section`` holding one ``<type>-rule``."""
    layer = make_layer(
        f"{rulebase_type}-live-uid", f"{rulebase_type} live", 1, rules_per_section=1, rule_type=f"{rulebase_type}-rule"
    )
    return lambda payload: ApiCallResult(
        success=True, data=page_by_rule_offset(layer, payload.get("limit"), payload.get("offset", 0))
    )


async def test_live_nat_rows_numbered():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = _serve_one_section_layer("nat")
    body = text(await call_tool(make_server(fake), "show_nat_rulebase", {"package": "Standard", "show_hits": True}))
    assert "**Section: nat live section 0** (1)" in body and "| 1 | nat live rule 1 |" in body
    assert "rows 1-2 of 2" in body and "Source: live" in body


async def test_live_https_rows_numbered():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = _serve_one_section_layer("https")
    body = text(await call_tool(make_server(fake), "show_https_rulebase", {"name": "https live", "show_hits": True}))
    assert "**Section: https live section 0** (1)" in body and "| 1 | https live rule 1 |" in body
    assert "rows 1-2 of 2" in body and "Source: live" in body


async def test_named_tool_needs_a_layer_or_on_the_cache_path_a_package():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), "show_access_rulebase", {})
    assert res.is_error is True and text(res) == "show_access_rulebase requires name or uid (or package)"
    res = await call_tool(make_server(fake), "show_access_rulebase", {"package": "Standard", "show_hits": True})
    assert res.is_error is True and text(res) == "show_access_rulebase requires name or uid"
    assert fake.calls == []
