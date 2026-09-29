from __future__ import annotations

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.mcp.manifest import MANIFEST

from .fake_client import FakeArodonataClient
from .helpers import call_tool, make_server, payload, text, tool_input_schema


async def test_list_tool_builds_kebab_payload_and_envelope():
    fake = FakeArodonataClient()
    fake.responses["api_query"] = ApiQueryResult(
        success=True,
        data={"objects": [{"uid": "1", "name": "http"}, {"uid": "2", "name": "https"}]},
        objects=[{"uid": "1", "name": "http"}, {"uid": "2", "name": "https"}],
        total=2,
    )
    res = await call_tool(
        make_server(fake),
        "show_services_tcp",
        {"filter": "http", "show_membership": True, "limit": 1, "details_level": "full", "domain": "General"},
    )
    assert res.is_error is False
    out = payload(res)
    assert [o["name"] for o in out["objects"]] == ["http"] and out["total"] == 2 and out["source"] == "live"
    name, kw = fake.calls[0]
    assert name == "api_query" and kw["command"] == "show-services-tcp" and kw["domain"] == "General"
    assert kw["details_level"] == "full" and kw["container_key"] == "objects"
    assert kw["cache_mode"] == "auto"  # session-cache library default; the tool does not pass one
    assert kw["payload"] == {"filter": "http", "show-membership": True}


async def test_list_tool_uses_container_key_from_manifest():
    fake = FakeArodonataClient()
    await call_tool(make_server(fake), "show_packages", {})
    assert fake.calls[0][1]["container_key"] == "packages"


async def test_single_tool_calls_api_call_and_returns_data():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=True, data={"uid": "g1", "name": "gw1", "type": "simple-gateway"}
    )
    out = payload(await call_tool(make_server(fake), "show_simple_gateway", {"name": "gw1"}))
    assert out["object"]["name"] == "gw1" and out["source"] == "live"
    name, kw = fake.calls[0]
    assert name == "api_call" and kw["command"] == "show-simple-gateway" and kw["payload"] == {"name": "gw1"}


async def test_single_tool_requires_name_or_uid():
    res = await call_tool(make_server(FakeArodonataClient()), "show_simple_gateway", {})
    assert res.is_error is True and "name or uid" in text(res)


async def test_api_error_maps_to_tool_error():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(
        success=False, code="generic_err_object_not_found", message="Requested object [gwX] not found"
    )
    res = await call_tool(make_server(fake), "show_simple_gateway", {"name": "gwX"})
    assert res.is_error is True and text(res) == "generic_err_object_not_found: Requested object [gwX] not found"


async def test_where_used_passes_indirect_params():
    fake = FakeArodonataClient()
    await call_tool(make_server(fake), "where_used", {"name": "web1", "indirect": True, "indirect_max_depth": 3})
    assert fake.calls[0][1]["payload"] == {"name": "web1", "indirect": True, "indirect-max-depth": 3}


async def test_oversized_result_is_truncated_with_hint():
    fake = FakeArodonataClient()
    big = [{"uid": str(i), "name": "x" * 200} for i in range(200)]
    fake.responses["api_query"] = ApiQueryResult(success=True, data={"objects": big}, objects=big, total=200)
    server = make_server(fake, max_result_chars=2000)
    res = await call_tool(server, "show_services_udp", {"limit": 0})
    assert res.is_error is False and "truncated" in text(res) and len(text(res)) < 2600


def _array_item_type(prop: dict) -> str | None:
    for option in prop.get("anyOf", [prop]):
        if option.get("type") == "array":
            return option.get("items", {}).get("type")
    return None


async def test_order_is_sent_as_list_of_objects():
    fake = FakeArodonataClient()
    await call_tool(make_server(fake), "show_services_tcp", {"order": [{"ASC": "name"}]})
    assert fake.calls[0][1]["payload"]["order"] == [{"ASC": "name"}]


async def test_order_schema_is_array_of_objects_for_compat_and_rulebase_tools():
    server = make_server(FakeArodonataClient())
    for tool in ("show_services_tcp", "show_access_rulebase", "show_nat_rulebase"):
        prop = (await tool_input_schema(server, tool))["properties"]["order"]
        assert _array_item_type(prop) == "object", (tool, prop)
        assert '[{"ASC": "name"}]' in prop.get("description", ""), (tool, prop)


async def test_no_live_compat_tool_or_api_call_publishes_cache_mode():
    server = make_server(FakeArodonataClient())
    offenders = [
        tool
        for tool in [entry.name for entry in MANIFEST] + ["api_call"]
        if "cache_mode" in (await tool_input_schema(server, tool))["properties"]
    ]
    assert offenders == []
