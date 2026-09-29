"""MCP server smoke test against the lab: tool listing, init, a cached list and a rulebase render."""

from __future__ import annotations

import json

from mcp.client import Client

from arodonata.mcp import ArodonataMCPSettings, create_mcp_server


async def test_mcp_smoke(apikey_client):
    client, mgmt_name = apikey_client
    server = create_mcp_server(client, ArodonataMCPSettings(auth_mode="host"))
    async with Client(server) as mcp:
        names = {t.name for t in (await mcp.list_tools()).tools}
        assert {"arodonata_init", "show_hosts", "show_access_rulebase", "search_objects"} <= names

        init = await mcp.call_tool("arodonata_init", {})
        assert init.is_error is False
        servers = {s["mgmt_name"]: s for s in json.loads(init.content[0].text)["servers"]}  # type: ignore[union-attr]
        assert mgmt_name in servers and servers[mgmt_name]["domains"]
        domain = servers[mgmt_name]["domains"][0]

        hosts = await mcp.call_tool("show_hosts", {"mgmt_name": mgmt_name, "domain": domain, "limit": 5})
        assert hosts.is_error is False and json.loads(hosts.content[0].text)["source"] == "cache"  # type: ignore[union-attr]

        layers = await mcp.call_tool("show_access_layers", {"mgmt_name": mgmt_name, "domain": domain, "limit": 1})
        assert layers.is_error is False
        layer_name = json.loads(layers.content[0].text)["objects"][0]["name"]  # type: ignore[union-attr]
        rb = await mcp.call_tool(
            "show_access_rulebase", {"mgmt_name": mgmt_name, "domain": domain, "name": layer_name, "limit": 10}
        )
        assert rb.is_error is False and rb.content[0].text.startswith("# Rulebase:")  # type: ignore[union-attr]
