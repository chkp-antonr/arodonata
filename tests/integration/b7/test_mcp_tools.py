"""MCP tool shapes against the lab: one test per way a tool reaches the management server.

The smoke test (test_mcp_server.py) covers init, a cache-backed list, one live list and the cached rulebase path.
These tests cover the remaining seams between the MCP layer and the real API: a live single-object call, a live
list with its own container key, the live rulebase path, search over the real event stream, and api_call. All of
them are read-only.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp.client import Client
from mcp.types import CallToolResult

from arodonata.mcp import ArodonataMCPSettings, create_mcp_server

# Cached gateway type -> live tool that shows one object of that type.
_SINGLE_OBJECT_TOOLS = {"simple-gateway": "show_simple_gateway", "simple-cluster": "show_simple_cluster"}


@asynccontextmanager
async def _mcp(apikey_client: tuple[Any, str]) -> AsyncIterator[tuple[Client, str, list[str]]]:
    """In-process MCP client over a real ArodonataClient, plus the mgmt name and its domains from arodonata_init."""
    client, mgmt_name = apikey_client
    server = create_mcp_server(client, ArodonataMCPSettings(auth_mode="host"))
    async with Client(server) as mcp:
        init = await mcp.call_tool("arodonata_init", {})
        assert init.is_error is False, _text(init)
        servers = {s["mgmt_name"]: s for s in json.loads(_text(init))["servers"]}
        assert servers[mgmt_name]["domains"], "lab server reports no domains"
        yield mcp, mgmt_name, servers[mgmt_name]["domains"]


def _text(result: CallToolResult) -> str:
    return result.content[0].text  # type: ignore[union-attr]


async def _ok(mcp: Client, name: str, args: dict[str, Any]) -> Any:
    """Call a tool, fail with its error text if it errored, and return the parsed JSON result."""
    result = await mcp.call_tool(name, args)
    assert result.is_error is False, f"{name} failed: {_text(result)}"
    return json.loads(_text(result))


async def _domain_with_hosts(mcp: Client, mgmt_name: str, domains: list[str]) -> tuple[str, list[dict[str, Any]]]:
    for domain in domains:
        out = await _ok(mcp, "show_hosts", {"mgmt_name": mgmt_name, "domain": domain, "limit": 5})
        if out["objects"]:
            return domain, out["objects"]
    pytest.skip("no domain on the lab server has cached hosts")


async def test_live_single_object_tool(apikey_client):
    """show_simple_gateway / show_simple_cluster go through api_call with a name payload."""
    async with _mcp(apikey_client) as (mcp, mgmt_name, _domains):
        gateways = await _ok(mcp, "show_gateways_and_servers", {"mgmt_name": mgmt_name, "limit": 0})
        target = next((g for g in gateways["objects"] if g.get("type") in _SINGLE_OBJECT_TOOLS), None)
        if target is None:
            pytest.skip("lab has no simple gateway or simple cluster")
        domain = (target.get("domain") or {}).get("name", "")
        args = {"mgmt_name": mgmt_name, "name": target["name"], "details_level": "full"}
        if domain and domain != "SMC User":
            args["domain"] = domain
        out = await _ok(mcp, _SINGLE_OBJECT_TOOLS[target["type"]], args)
        assert out["source"] == "live"
        assert out["object"]["name"] == target["name"] and out["object"]["uid"] == target["uid"]


async def test_live_list_with_container_key(apikey_client):
    """show_packages reads its objects from the 'packages' container, not 'objects'."""
    async with _mcp(apikey_client) as (mcp, mgmt_name, domains):
        out = await _ok(mcp, "show_packages", {"mgmt_name": mgmt_name, "domain": domains[0], "limit": 5})
        assert out["source"] == "live" and out["cache_age_seconds"] is None
        assert out["objects"], "expected at least one policy package"
        assert all("name" in p and "uid" in p for p in out["objects"])
        assert out["total"] >= len(out["objects"])


async def test_live_rulebase_path(apikey_client):
    """A live-only parameter (show_hits) switches show_access_rulebase to a live query with an objects dictionary."""
    async with _mcp(apikey_client) as (mcp, mgmt_name, domains):
        layers = await _ok(mcp, "show_access_layers", {"mgmt_name": mgmt_name, "domain": domains[0], "limit": 1})
        layer = layers["objects"][0]["name"]
        base = {"mgmt_name": mgmt_name, "domain": domains[0], "name": layer, "show_hits": True, "limit": 5}

        raw = await _ok(mcp, "show_access_rulebase", {**base, "format": "raw"})
        assert raw["source"] == "live"
        assert "objects-dictionary" in raw and isinstance(raw["rulebase"], list)

        rendered = await mcp.call_tool("show_access_rulebase", {**base, "format": "markdown"})
        assert rendered.is_error is False, _text(rendered)
        assert _text(rendered).startswith(f"# Rulebase: {layer}") and "Source: live" in _text(rendered)


async def test_search_objects_returns_matches(apikey_client):
    """search_objects must collect per-domain matches from the real search event stream."""
    async with _mcp(apikey_client) as (mcp, mgmt_name, domains):
        domain, hosts = await _domain_with_hosts(mcp, mgmt_name, domains)
        name = hosts[0]["name"]
        out = await _ok(
            mcp, "search_objects", {"search_input": name, "mgmt_names": [mgmt_name], "domain_names": [domain]}
        )
        assert out["errors"] == [], out["errors"]
        assert out["results"], "search returned no matches for a host that is in the cache"
        found = {obj.get("name") for match in out["results"] for obj in match["objects"]}
        assert name in found
        assert all(match["mgmt_name"] == mgmt_name and match["domain"] == domain for match in out["results"])


async def test_api_call_gate_and_pagination(apikey_client):
    """api_call refuses writes by default and collects every page for a show- command when paginate=true."""
    async with _mcp(apikey_client) as (mcp, mgmt_name, domains):
        refused = await mcp.call_tool(
            "api_call",
            {
                "command": "add-host",
                "mgmt_name": mgmt_name,
                "domain": domains[0],
                "payload": {"name": "must-not-exist"},
            },
        )
        assert refused.is_error is True and "ARODONATA_MCP_ALLOW_WRITE_API" in _text(refused)

        out = await _ok(
            mcp,
            "api_call",
            {
                "command": "show-hosts",
                "mgmt_name": mgmt_name,
                "domain": domains[0],
                "paginate": True,
                "details_level": "standard",
            },
        )
        assert out["source"] == "live" and out["total"] == len(out["objects"])
        assert all(set(o) >= {"uid", "name"} for o in out["objects"])


async def test_cached_rulebase_path_renders_rows(apikey_client, test_domain_a):
    """The cache path of show_access_rulebase renders rows on real data (it rendered an empty table before)."""
    client, mgmt_name = apikey_client
    async for _ in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass
    rules = await client.get_access_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    if not rules:
        pytest.skip(f"{test_domain_a} has no access rules")
    async with _mcp(apikey_client) as (mcp, _, _):
        res = await mcp.call_tool(
            "show_access_rulebase",
            {"mgmt_name": mgmt_name, "domain": test_domain_a, "name": rules[0].layer_name, "cache_mode": "cache"},
        )
    body = _text(res)
    assert res.is_error is False, body
    assert int(body.rsplit(" of ", 1)[1].split()[0]) > 0, body


async def test_live_rulebase_filter_pages_consistently(apikey_client, test_domain_a):
    """A filtered live read goes through the pager; its from/to continuity check must hold for filtered results."""
    if test_domain_a != "Domain4":
        pytest.skip("uses the home-lab Domain4 layer")
    _, mgmt_name = apikey_client
    async with _mcp(apikey_client) as (mcp, _, _):
        res = await mcp.call_tool(
            "show_access_rulebase",
            {"mgmt_name": mgmt_name, "domain": test_domain_a, "name": "FPCR_UAT_Active Network", "filter": "Cleanup"},
        )
    body = _text(res)
    assert res.is_error is False, body
    assert "Source: live" in body and "Cleanup rule" in body, body
