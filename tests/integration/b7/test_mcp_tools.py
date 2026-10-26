"""Bucket 7 — Live MCP tool surface tests (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `search_objects`, `query_objects`, `cache_control`, `show_rulebase`, `change_report`, and `api_call` write gate)."""

from __future__ import annotations

import json
from typing import Any

from mcp.types import CallToolResult, TextContent

from arodonata import ArodonataClient
from arodonata.mcp import create_mcp_server
from tests.integration.cp_revision import last_published_session


def _parse_json(result: CallToolResult) -> dict[str, Any]:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    parsed: dict[str, Any] = json.loads(first.text)
    return parsed


def _text(result: CallToolResult) -> str:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    return first.text


async def test_mcp_listing_search_query_and_cache_control_tools(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``list_objects``, ``list_services``, ``list_assets``, ``show_object``, ``search_objects``, ``query_objects``, and ``cache_control``."""
    server = create_mcp_server(apikey_client, auth_mode="host", cpcrud=True)

    # 1. list_objects(types=["host"])
    hosts_res = await server.call_tool(
        "list_objects",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "types": ["host"], "limit": 10},
    )
    assert isinstance(hosts_res, CallToolResult)
    assert hosts_res.is_error is False
    hosts_data = _parse_json(hosts_res)
    assert hosts_data["objects"], f"Expected hosts in {test_domain_a}"
    sample_host = hosts_data["objects"][0]

    # 2. show_object (exact match)
    obj_res = await server.call_tool(
        "show_object",
        {
            "uid_or_name": sample_host["name"],
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
        },
    )
    assert isinstance(obj_res, CallToolResult)
    assert obj_res.is_error is False
    obj_data = _parse_json(obj_res)
    assert obj_data["object"]["uid"] == sample_host["uid"]
    assert obj_data["match_type"] == "exact"

    # 3. list_services(types=["tcp"])
    svcs_res = await server.call_tool(
        "list_services",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "types": ["tcp"], "limit": 10},
    )
    assert isinstance(svcs_res, CallToolResult)
    assert svcs_res.is_error is False
    svcs_data = _parse_json(svcs_res)
    assert svcs_data["source"] == "cache"

    # 4. list_assets
    gws_res = await server.call_tool(
        "list_assets",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "limit": 10},
    )
    assert isinstance(gws_res, CallToolResult)
    assert gws_res.is_error is False
    gws_data = _parse_json(gws_res)
    assert gws_data["source"] == "cache"

    # 5. search_objects
    search_res = await server.call_tool(
        "search_objects",
        {
            "query": sample_host["name"],
            "mgmt_name": mgmt_name,
            "domains": [test_domain_a],
            "cache_mode": "cache",
        },
    )
    assert isinstance(search_res, CallToolResult)
    assert search_res.is_error is False
    search_data = _parse_json(search_res)
    assert any(m["uid"] == sample_host["uid"] for m in search_data["objects"])

    # 6. query_objects(aggregate="describe" and aggregate="count")
    desc_res = await server.call_tool(
        "query_objects",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "aggregate": "describe"},
    )
    assert isinstance(desc_res, CallToolResult)
    assert desc_res.is_error is False
    desc_data = _parse_json(desc_res)
    assert desc_data["total_objects"] >= 1
    assert "host" in desc_data["object_types"]

    q_res = await server.call_tool(
        "query_objects",
        {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "types": ["host"],
            "group_by": ["type"],
            "aggregate": "count",
        },
    )
    assert isinstance(q_res, CallToolResult)
    assert q_res.is_error is False
    q_data = _parse_json(q_res)
    assert q_data["total"] >= 1

    # 7. cache_control(action="status")
    cs_res = await server.call_tool(
        "cache_control",
        {"action": "status", "mgmt_name": mgmt_name, "domain": test_domain_a},
    )
    assert isinstance(cs_res, CallToolResult)
    assert cs_res.is_error is False
    cs_data = _parse_json(cs_res)
    assert cs_data["total_entries"] >= 1
    assert "objects" in cs_data["by_scope"]


async def test_mcp_rulebase_and_change_report_tools(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``show_rulebase`` (catalog discovery + cached access/NAT + live ``show_hits=True``) and ``change_report``."""
    await apikey_client.refresh_rulebases(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="force",
    )
    server = create_mcp_server(apikey_client, auth_mode="host")

    # 1. show_rulebase catalog discovery when package and layer are omitted
    pkgs_res = await server.call_tool(
        "show_rulebase",
        {"mgmt_name": mgmt_name, "domain": test_domain_a, "cache_mode": "cache"},
    )
    assert isinstance(pkgs_res, CallToolResult)
    assert pkgs_res.is_error is False
    pkgs_data = _parse_json(pkgs_res)
    assert pkgs_data["mode"] == "catalog"
    assert pkgs_data["packages"], f"Expected policy package in {test_domain_a}"
    pkg = pkgs_data["packages"][0]
    layer_name = next(
        (
            lyr["layer_name"]
            for lyr in pkg["access_layers"]
            if lyr["layer_name"] != "Global" and not lyr["layer_name"].startswith("Global")
        ),
        pkg["access_layers"][-1]["layer_name"],
    )

    # 2. show_rulebase(rulebase_type="access") from cache
    rb_cached = await server.call_tool(
        "show_rulebase",
        {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "rulebase_type": "access",
            "layer": layer_name,
            "format": "markdown",
            "cache_mode": "cache",
        },
    )
    assert isinstance(rb_cached, CallToolResult)
    assert rb_cached.is_error is False
    rb_cached_data = _parse_json(rb_cached)
    assert rb_cached_data["source"] == "cache"
    assert rb_cached_data["total"] >= 1
    assert rb_cached_data["rendered_text"]

    # 3. show_rulebase live path (show_hits=True)
    rb_live = await server.call_tool(
        "show_rulebase",
        {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "rulebase_type": "access",
            "layer": layer_name,
            "show_hits": True,
            "limit": 5,
        },
    )
    assert isinstance(rb_live, CallToolResult)
    assert rb_live.is_error is False
    rb_live_data = _parse_json(rb_live)
    assert rb_live_data["source"] == "live"

    # 4. show_rulebase(rulebase_type="nat") from cache
    nat_res = await server.call_tool(
        "show_rulebase",
        {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "rulebase_type": "nat",
            "package": pkg["name"],
            "format": "markdown",
            "cache_mode": "cache",
        },
    )
    assert isinstance(nat_res, CallToolResult)
    assert nat_res.is_error is False
    nat_data = _parse_json(nat_res)
    assert nat_data["source"] == "cache"

    # 5. change_report tool on the last published session
    rev = await last_published_session(apikey_client, mgmt_name, test_domain_a)
    rep_res = await server.call_tool(
        "change_report",
        {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "session_uids": [rev.session_uid],
            "format": "markdown",
        },
    )
    assert isinstance(rep_res, CallToolResult)
    assert rep_res.is_error is False
    rep_data = _parse_json(rep_res)
    assert rep_data["session_count"] == 1
    assert rev.session_uid in rep_data["rendered"]


async def test_mcp_api_call_write_gate_and_domain_validation(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``api_call`` blocks write commands when ``allow_write_api=False`` and unknown domains fail cleanly."""
    server = create_mcp_server(apikey_client, auth_mode="host", allow_write_api=False)

    # 1. Write command blocked
    refused = await server.call_tool(
        "api_call",
        {
            "command": "add-host",
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "payload": {"name": "must-not-be-created", "ipv4-address": "198.51.100.254"},
        },
    )
    assert isinstance(refused, CallToolResult)
    assert refused.is_error is True
    assert "ARODONATA_MCP_ALLOW_WRITE_API=false" in _text(refused)

    # 2. Read-only show-hosts command succeeds
    allowed = await server.call_tool(
        "api_call",
        {
            "command": "show-hosts",
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "payload": {"limit": 5},
        },
    )
    assert isinstance(allowed, CallToolResult)
    assert allowed.is_error is False
    allowed_data = _parse_json(allowed)
    assert allowed_data["source"] == "live"

    # 3. Unknown domain returns actionable error listing known domains
    unknown_dom = await server.call_tool(
        "list_objects",
        {
            "mgmt_name": mgmt_name,
            "domain": "NonExistentDomainXYZ",
            "types": ["host"],
        },
    )
    assert isinstance(unknown_dom, CallToolResult)
    assert unknown_dom.is_error is True
    assert "Unknown domain 'NonExistentDomainXYZ'" in _text(unknown_dom)
    assert test_domain_a in _text(unknown_dom)
