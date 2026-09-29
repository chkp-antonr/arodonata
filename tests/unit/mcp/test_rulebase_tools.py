from __future__ import annotations

from types import SimpleNamespace

import pytest

from arodonata.api.schemas import ApiQueryResult
from arodonata.core.cache_mode import CacheMode

from .fake_client import FakeArodonataClient, rule
from .helpers import cache_mode_enum, call_tool, make_server, payload, text, tool_input_schema

_RULEBASE_TOOLS = {
    # tool -> (addressing args, cached getter)
    "show_access_rulebase": ({"name": "Network"}, "get_access_rules"),
    "show_nat_rulebase": ({"package": "Standard"}, "get_nat_rules"),
    "show_https_rulebase": ({"name": "Default Layer"}, "get_https_rules"),
    "show_threat_rulebase": ({"name": "Standard Threat Prevention"}, "get_threat_rules"),
}


def _fake() -> FakeArodonataClient:
    fake = FakeArodonataClient()
    fake.responses["get_access_rules"] = {
        "Network": [rule(1, "allow web", inline="Inner"), rule(2, "deny all", enabled=False)],
        "Inner": [rule(1, "inner", layer="Inner")],
    }
    return fake


async def test_cache_path_by_default_renders_markdown_with_source_footer():
    fake = _fake()
    res = await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network"})
    body = text(res)
    assert (
        res.is_error is False and body.startswith("# Rulebase: Network") and "| 1 |" in body and "Source: cache" in body
    )
    first = fake.calls[0]
    assert (
        first[0] == "get_access_rules" and first[1]["layer_name"] == "Network" and first[1]["mgmt_names"] == ["mgmt1"]
    )
    assert (
        "get_access_rules",
        {
            "layer_name": "Inner",
            "mgmt_names": ["mgmt1"],
            "domain_names": None,
            "enabled_only": None,
            "cache_mode": None,
            "cache_ttl": None,
        },
    ) in fake.calls


async def test_cache_path_raw_format_returns_envelope_with_rulebase_key():
    out = payload(
        await call_tool(make_server(_fake()), "show_access_rulebase", {"name": "Network", "format": "raw", "limit": 1})
    )
    assert out["rulebase"][0]["name"] == "allow web" and out["total"] == 2 and out["source"] == "cache"


async def test_live_only_parameter_switches_to_api_query():
    fake = _fake()
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": []}, objects=[], total=0
    )
    await call_tool(
        make_server(fake),
        "show_access_rulebase",
        {"name": "Network", "show_hits": True, "hits_settings": {"from_date": "2026-01-01"}},
    )
    name, kw = fake.calls[0]
    assert name == "api_query" and kw["command"] == "show-access-rulebase" and kw["container_key"] == "rulebase"
    assert kw["payload"] == {
        "name": "Network",
        "show-hits": True,
        "hits-settings": {"from-date": "2026-01-01"},
        "use-object-dictionary": True,
    }
    assert kw["details_level"] == "full"


async def test_nat_requires_package_and_uses_get_nat_rules():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), "show_nat_rulebase", {})
    assert res.is_error is True and "package" in text(res)
    await call_tool(make_server(fake), "show_nat_rulebase", {"package": "Standard", "format": "model_friendly"})
    assert fake.calls[0][0] == "get_nat_rules" and fake.calls[0][1]["layer_name"] == "Standard"


async def test_https_and_threat_tools_exist_and_route():
    fake = FakeArodonataClient()
    await call_tool(make_server(fake), "show_https_rulebase", {"name": "Default Layer"})
    await call_tool(make_server(fake), "show_threat_rulebase", {"name": "Standard Threat Prevention"})
    assert [c[0] for c in fake.calls] == ["get_https_rules", "get_threat_rules"]


async def test_offset_and_limit_slice_rows_before_rendering():
    fake = _fake()
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


async def test_raw_format_cache_path_makes_exactly_one_getter_call():
    fake = _fake()
    await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "format": "raw"})
    assert [c[0] for c in fake.calls] == ["get_access_rules"]


async def test_live_path_access_rulebase_includes_package_in_payload():
    fake = _fake()
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": []}, objects=[], total=0
    )
    await call_tool(
        make_server(fake),
        "show_access_rulebase",
        {"name": "Network", "package": "Standard", "show_hits": True},
    )
    _, kw = fake.calls[0]
    assert kw["payload"]["package"] == "Standard"


async def test_cache_path_reports_rulebase_cache_age_for_the_right_type():
    fake = _fake()
    out = payload(
        await call_tool(make_server(fake), "show_access_rulebase", {"name": "Network", "format": "raw", "domain": "D1"})
    )
    assert out["cache_age_seconds"] == 600
    body = text(await call_tool(make_server(fake), "show_nat_rulebase", {"package": "Standard"}))
    assert "(age 600s)" in body
    rulebase_calls = [c for c in fake.cache.calls if c[0] == "get_rulebase_last_update"]
    assert rulebase_calls == [
        ("get_rulebase_last_update", {"rulebase_type": "access", "mgmt_names": ["mgmt1"], "domain_names": ["D1"]}),
        ("get_rulebase_last_update", {"rulebase_type": "nat", "mgmt_names": ["mgmt1"], "domain_names": None}),
    ]
    assert not [c for c in fake.cache.calls if c[0] == "get_objects_last_update"]


async def test_https_and_threat_cache_age_use_their_own_type():
    fake = FakeArodonataClient()
    await call_tool(make_server(fake), "show_https_rulebase", {"name": "Default Layer"})
    await call_tool(make_server(fake), "show_threat_rulebase", {"name": "Standard Threat Prevention"})
    assert [c[1]["rulebase_type"] for c in fake.cache.calls] == ["https", "threat"]


async def test_uid_only_on_cache_path_resolves_layer_name():
    fake = _fake()
    fake.responses["get_object_by_uid"] = SimpleNamespace(name="Network", raw_data={"name": "Network"})
    body = text(await call_tool(make_server(fake), "show_access_rulebase", {"uid": "layer-uid-1", "domain": "General"}))
    assert body.startswith("# Rulebase: Network") and "| 1 |" in body
    assert fake.calls[0] == (
        "get_object_by_uid",
        {"uid": "layer-uid-1", "mgmt_name": "mgmt1", "domain_name": "General"},
    )
    assert fake.calls[1][0] == "get_access_rules" and fake.calls[1][1]["layer_name"] == "Network"


async def test_uid_only_on_cache_path_not_found_is_a_tool_failure():
    fake = _fake()
    res = await call_tool(make_server(fake), "show_access_rulebase", {"uid": "missing-uid"})
    assert res.is_error is True
    assert "layer uid 'missing-uid' not found in cache" in text(res) and "name" in text(res)
    assert [c[0] for c in fake.calls] == ["get_object_by_uid"]


async def test_uid_on_live_path_is_sent_unchanged():
    fake = _fake()
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": []}, objects=[], total=0
    )
    await call_tool(make_server(fake), "show_access_rulebase", {"uid": "layer-uid-1", "show_hits": True})
    assert [c[0] for c in fake.calls] == ["api_query"] and fake.calls[0][1]["payload"]["uid"] == "layer-uid-1"


@pytest.mark.parametrize(("tool", "spec"), _RULEBASE_TOOLS.items())
async def test_rulebase_cache_path_default_cache_mode_is_none(tool, spec):
    args, getter = spec
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, args)
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == getter and fake.calls[0][1]["cache_mode"] is None


@pytest.mark.parametrize(("tool", "spec"), _RULEBASE_TOOLS.items())
async def test_rulebase_cache_path_forwards_force_cache_mode(tool, spec):
    args, getter = spec
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, {**args, "cache_mode": "force"})
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == getter and fake.calls[0][1]["cache_mode"] == "force"


@pytest.mark.parametrize("tool", _RULEBASE_TOOLS)
async def test_rulebase_schema_publishes_read_cache_vocabulary(tool):
    schema = await tool_input_schema(make_server(FakeArodonataClient()), tool)
    assert cache_mode_enum(schema) == [m.value for m in CacheMode]
    assert schema["properties"]["cache_mode"].get("default") is None


async def test_rulebase_live_path_ignores_read_cache_mode_and_uses_session_default():
    fake = _fake()
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data={"name": "Network", "rulebase": [], "objects-dictionary": []}, objects=[], total=0
    )
    res = await call_tool(
        make_server(fake), "show_access_rulebase", {"name": "Network", "show_hits": True, "cache_mode": "force"}
    )
    assert res.is_error is False, text(res)
    name, kw = fake.calls[0]
    assert name == "api_query" and kw["cache_mode"] == "auto"
