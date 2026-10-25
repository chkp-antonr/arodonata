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
        "show_domains",
        "show_hosts",
        "show_networks",
        "show_gateways_and_servers",
        "show_policy_packages",
        "show_access_rulebase",
        "show_nat_rulebase",
        "search_objects",
        "query_objects",
        "describe_objects",
        "cache_status",
        "change_report",
        "api_call",
        "where_used",
        "cpcrud_validate",
        "cpcrud_plan",
    }
    assert expected_tools <= tool_names

    # 1. show_domains
    dom_res = await server.call_tool("show_domains", {"mgmt_name": mgmt_name})
    assert isinstance(dom_res, CallToolResult)
    assert dom_res.is_error is False
    dom_data = _parse_json(dom_res)
    assert dom_data["source"] == "cache"
    domain_names = {d["name"] for d in dom_data["objects"]}
    assert test_domain_a in domain_names

    # 2. show_hosts in TEST_DOMAIN_A
    hosts_res = await server.call_tool(
        "show_hosts",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "limit": 5},
    )
    assert isinstance(hosts_res, CallToolResult)
    assert hosts_res.is_error is False
    hosts_data = _parse_json(hosts_res)
    assert hosts_data["source"] == "cache"
    assert isinstance(hosts_data["cache_age_seconds"], float)
    assert len(hosts_data["objects"]) >= 1
