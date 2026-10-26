"""Bucket 7 — MCP server smoke test (`create_mcp_server`, `create_asgi_app`, tool listing, and initial queries)."""

from __future__ import annotations

import json
from typing import Any

from mcp.types import CallToolResult, TextContent

from arodonata import ArodonataClient
from arodonata.mcp import ArodonataMCPSettings, create_asgi_app, create_mcp_server


def _parse_json(result: CallToolResult) -> dict[str, Any]:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    parsed: dict[str, Any] = json.loads(first.text)
    return parsed


async def test_mcp_server_smoke_and_asgi_factory(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``create_mcp_server`` and ``create_asgi_app`` wire all core tools against the live MDSM."""
    mcp_settings = ArodonataMCPSettings(auth_mode="host", live_compat=True, cpcrud=True)
    server = create_mcp_server(apikey_client, mcp_settings=mcp_settings)
    asgi_app = create_asgi_app(apikey_client, mcp_server=server)
    assert asgi_app.mcp_server is server

    tools = await server.list_tools()
    tool_names = {t.name for t in tools}
    expected_tools = {
        "list_domains",
        "list_objects",
        "list_services",
        "list_assets",
        "show_object",
        "show_rulebase",
        "locate_rules",
        "search_objects",
        "get_group_members",
        "query_objects",
        "cache_control",
        "change_report",
        "api_call",
        "cpcrud_validate",
        "cpcrud_plan",
        "cpcrud_apply",
        "cpcrud_inverse",
        "cpcrud_staged_session",
    }
    assert expected_tools <= tool_names

    # 1. list_domains
    dom_res = await server.call_tool("list_domains", {"mgmt_name": mgmt_name})
    assert isinstance(dom_res, CallToolResult)
    assert dom_res.is_error is False
    dom_data = _parse_json(dom_res)
    assert dom_data["source"] == "cache"
    domain_names = {d["name"] for d in dom_data["objects"]}
    assert test_domain_a in domain_names

    # 2. list_objects(types=["host"]) in TEST_DOMAIN_A
    hosts_res = await server.call_tool(
        "list_objects",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "types": ["host"], "limit": 5},
    )
    assert isinstance(hosts_res, CallToolResult)
    assert hosts_res.is_error is False
    hosts_data = _parse_json(hosts_res)
    assert hosts_data["source"] == "cache"
    assert isinstance(hosts_data["cache_age_seconds"], float)
    assert len(hosts_data["objects"]) >= 1
