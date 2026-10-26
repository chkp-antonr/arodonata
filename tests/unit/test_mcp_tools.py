"""Comprehensive unit tests for the consolidated Arodonata MCP tool surface, cache-aligned envelopes,
three-tier `show_object` matching, `show_rulebase` catalog discovery and local filtering,
domain pre-validation, `InvalidCredentialsError` mapping, and write/SID/CPCRUD guards.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from arodonata import ArodonataClient
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.errors import REDACTED_PLACEHOLDER, InvalidCredentialsError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.mcp import create_mcp_server


class MCPFakeApi:
    """In-memory `ApiPort` double for MCP tool tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None]] = []
        self.call_details: list[dict[str, Any]] = []
        self.queries: list[tuple[str, str, str | None]] = []
        self.dedicated_sessions_created: list[tuple[str, str | None]] = []
        self.logged_out_sids: list[tuple[str, str]] = []
        self.published_uid = "pub-mcp-1"
        self.published_iso = "2026-10-24T10:00:00Z"
        self.raise_invalid_creds_for_domain: str | None = None
        self.raise_unexpected_for_command: str | None = None
        self.fail_command_with_sid: tuple[str, str] | None = None
        self._active_dedicated_sids: set[tuple[str, str]] = set()

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        self.calls.append((mgmt_name, command, payload, domain))
        self.call_details.append(
            {
                "mgmt_name": mgmt_name,
                "command": command,
                "payload": payload,
                "domain": domain,
                "sid": sid,
                "server_ip": server_ip,
                "timeout": timeout,
            }
        )

        if self.raise_unexpected_for_command == command:
            raise KeyError("simulated-unexpected-key-failure")

        if self.raise_invalid_creds_for_domain and domain == self.raise_invalid_creds_for_domain:
            raise InvalidCredentialsError(f"Login rejected for domain {domain}")

        if self.fail_command_with_sid and self.fail_command_with_sid[0] == command:
            leaked_sid = self.fail_command_with_sid[1]
            return ApiCallResult(
                success=False,
                status_code=400,
                error_message=f"Command failed under X-chkp-sid: {leaked_sid}",
                data={"sid": leaked_sid},
            )

        if command == "show-domains":
            return ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {
                            "uid": "dom-corp",
                            "name": "Corp",
                            "type": "domain",
                            "color": "blue",
                            "comments": "Corporate domain",
                            "servers": [
                                {
                                    "name": "corp-cma-1",
                                    "ipv4-address": "10.1.0.1",
                                    "active": True,
                                    "multi-domain-server": {"ipv4-address": "10.0.0.1"},
                                }
                            ],
                        },
                        {
                            "uid": "dom-branch",
                            "name": "Branch",
                            "type": "domain",
                            "servers": [
                                {
                                    "name": "branch-cma-1",
                                    "ipv4-address": "10.2.0.1",
                                    "active": True,
                                    "multi-domain-server": {"ipv4-address": "10.0.0.1"},
                                }
                            ],
                        },
                    ]
                },
            )
        if command == "show-global-domain":
            return ApiCallResult(
                success=True,
                data={"uid": "dom-global", "name": "Global", "type": "global"},
            )
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )
        if command == "show-session":
            if payload and payload.get("uid") == "sess-100":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "sess-100",
                        "name": "Ticket-100",
                        "user-name": "secadmin",
                        "state": "published",
                        "publish-time": {"iso-8601": "2026-10-24T10:00:00Z"},
                    },
                )
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-changes":
            return ApiCallResult(
                success=True,
                data={
                    "tasks": [
                        {
                            "task-details": [
                                {
                                    "operations": {
                                        "added-objects": [
                                            {"uid": "h-1", "name": "web-srv-1", "type": "host"},
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                },
            )
        if command == "show-packages":
            return ApiCallResult(
                success=True,
                data={
                    "packages": [
                        {
                            "uid": "pkg-std",
                            "name": "Standard",
                            "access": True,
                            "nat-policy": True,
                            "access-layers": [{"uid": "lay-net", "name": "Network", "position": 1}],
                        }
                    ],
                    "to": 1,
                    "total": 1,
                },
            )
        if command == "show-access-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "lay-net",
                    "name": "Network",
                    "rulebase": [
                        {
                            "uid": "rule-web-1",
                            "name": "Allow Web Server",
                            "type": "access-rule",
                            "rule-number": 1,
                            "enabled": True,
                            "source": [{"uid": "any", "name": "Any"}],
                            "destination": [{"uid": "h-1", "name": "web-srv-1"}],
                            "service": [{"uid": "svc-https", "name": "https"}],
                            "action": {"name": "Accept"},
                            "track": {"type": {"name": "Log"}},
                            "comments": "Prod HTTPS",
                        },
                        {
                            "uid": "rule-cleanup",
                            "name": "Cleanup rule",
                            "type": "access-rule",
                            "rule-number": 2,
                            "enabled": True,
                            "source": [{"uid": "any", "name": "Any"}],
                            "destination": [{"uid": "any", "name": "Any"}],
                            "service": [{"uid": "any", "name": "Any"}],
                            "action": {"name": "Drop"},
                        },
                    ],
                    "to": 2,
                    "total": 2,
                },
            )
        if command == "show-nat-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "package": "Standard",
                    "rulebase": [
                        {
                            "uid": "nat-1",
                            "name": "Web Static NAT",
                            "type": "nat-rule",
                            "rule-number": 1,
                            "enabled": True,
                            "method": "static",
                            "original-source": {"name": "Any"},
                            "original-destination": {"name": "web-srv-1"},
                            "original-service": {"name": "Any"},
                            "translated-source": {"name": "Original"},
                            "translated-destination": {"name": "web-srv-1"},
                            "translated-service": {"name": "Original"},
                        }
                    ],
                    "to": 1,
                    "total": 1,
                },
            )
        if command == "where-used":
            return ApiCallResult(
                success=True,
                data={"used-directly": {"total": 1, "objects": [], "access-control-rules": [{"uid": "rule-web-1"}]}},
            )
        if command.startswith(("add-", "set-")) and payload:
            _, _, obj_type = command.partition("-")
            name = str(payload.get("name") or payload.get("new-name") or "unnamed")
            uid = str(payload.get("uid") or f"uid-{obj_type}-{name}")
            return ApiCallResult(success=True, data={**payload, "uid": uid, "name": name, "type": obj_type})
        if command in ("publish", "discard"):
            return ApiCallResult(success=True, data={"message": "OK"})
        if command.startswith("show-"):
            obj_ident = (payload or {}).get("name") or (payload or {}).get("uid") or "unknown"
            return ApiCallResult(
                success=False,
                status_code=404,
                code="generic_err_object_not_found",
                error_message=f"Requested object [{obj_ident}] not found",
            )
        return ApiCallResult(success=True, data={"ok": True})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        self.queries.append((mgmt_name, command, domain))
        if command == "show-hosts":
            if domain == "Global":
                return ApiQueryResult(
                    success=True,
                    objects=[
                        {
                            "uid": "h-glob-1",
                            "name": "global-dns-1",
                            "type": "host",
                            "ipv4-address": "8.8.8.8",
                            "domain": {"name": "Global"},
                        }
                    ],
                    total=1,
                )
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "h-1",
                        "name": "web-srv-1",
                        "type": "host",
                        "ipv4-address": "10.10.1.10",
                        "domain": {"name": domain or "Corp"},
                    },
                    {
                        "uid": "h-2",
                        "name": "web-srv-2",
                        "type": "host",
                        "ipv4-address": "10.10.1.11",
                        "domain": {"name": domain or "Corp"},
                    },
                    {
                        "uid": "h-glob-1",
                        "name": "global-dns-1",
                        "type": "host",
                        "ipv4-address": "8.8.8.8",
                        "domain": {"name": "Global"},
                    },
                ],
                total=3,
            )
        if command == "show-networks":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "n-1",
                        "name": "net-web",
                        "type": "network",
                        "subnet4": "10.10.1.0",
                        "mask-length4": 24,
                        "domain": {"name": domain or "Corp"},
                    }
                ],
                total=1,
            )
        if command == "show-groups":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "g-1",
                        "name": "grp-web-servers",
                        "type": "group",
                        "members": ["h-1"],
                        "domain": {"name": domain or "Corp"},
                    }
                ],
                total=1,
            )
        if command == "show-services-tcp":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "svc-https",
                        "name": "https",
                        "type": "service-tcp",
                        "port": "443",
                        "protocol": "tcp",
                        "domain": {"name": domain or "Corp"},
                    }
                ],
                total=1,
            )
        if command == "show-gateways-and-servers":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "gw-corp-1",
                        "name": "corp-gw-01",
                        "type": "simple-gateway",
                        "ipv4-address": "10.10.0.1",
                        "interfaces": [{"name": "eth0", "ipv4-address": "10.10.0.1"}],
                        "network-security-blades": {"firewall": True},
                    },
                    {
                        "uid": "cl-corp-1",
                        "name": "corp-cluster-01",
                        "type": "simple-cluster",
                        "ipv4-address": "10.10.0.10",
                        "cluster-members": [
                            {"uid": "cm-1", "name": "corp-cluster-01-m1", "type": "cluster-member"},
                            {"uid": "cm-2", "name": "corp-cluster-01-m2", "type": "cluster-member"},
                        ],
                    },
                    {
                        "uid": "srv-mgmt-1",
                        "name": "corp-cma-srv",
                        "type": "checkpoint-host",
                        "ipv4-address": "10.1.0.1",
                    },
                ],
                total=3,
            )
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        self.dedicated_sessions_created.append((mgmt_name, domain))
        self._active_dedicated_sids.add((mgmt_name, "dedicated-sid-999"))
        return "dedicated-sid-999", "10.1.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _done() -> bool:
            self.logged_out_sids.append((mgmt_name, sid))
            self._active_dedicated_sids.discard((mgmt_name, sid))
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


def _parse_tool_json(result: CallToolResult) -> dict[str, Any]:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    parsed: dict[str, Any] = json.loads(first.text)
    return parsed


def _get_tool_text(result: CallToolResult) -> str:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    return first.text


@pytest.mark.asyncio
async def test_consolidated_tool_count_and_cached_list_tools_envelopes() -> None:
    """Verify the consolidated tool surface (13 base tools, 18 with `cpcrud=True`),
    `list_*` envelopes (`from`, `to`, `total`, `source`, `cache_age_seconds`),
    short type alias normalization, and `list_assets(parent=...)` filtering.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        base_server = create_mcp_server(client, auth_mode="host", cpcrud=False)
        base_tools = await base_server.list_tools()
        base_tool_names = {t.name for t in base_tools}
        assert len(base_tool_names) == 13
        assert base_tool_names == {
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
        }

        cpcrud_server = create_mcp_server(client, auth_mode="host", cpcrud=True)
        cpcrud_tools = await cpcrud_server.list_tools()
        cpcrud_tool_names = {t.name for t in cpcrud_tools}
        assert len(cpcrud_tool_names) == 18
        assert cpcrud_tool_names - base_tool_names == {
            "cpcrud_validate",
            "cpcrud_plan",
            "cpcrud_apply",
            "cpcrud_inverse",
            "cpcrud_staged_session",
        }

        server = base_server

        # 1. list_domains preserves server-level fields (`servers`, `color`, `comments`)
        dom_res = await server.call_tool("list_domains", {"mgmt_name": "mds1", "details_level": "standard"})
        assert isinstance(dom_res, CallToolResult)
        assert dom_res.is_error is False
        dom_data = _parse_tool_json(dom_res)
        assert dom_data["from"] == 1
        assert dom_data["to"] == 2
        assert dom_data["total"] == 2
        assert dom_data["source"] == "cache"
        assert isinstance(dom_data["cache_age_seconds"], float)
        corp_dom = next(d for d in dom_data["objects"] if d["name"] == "Corp")
        assert corp_dom["name"] == "Corp"
        assert corp_dom["color"] == "blue"
        assert corp_dom["servers"][0]["name"] == "corp-cma-1"
        assert corp_dom["active_ip"] == "10.1.0.1"

        # 2. list_objects with types=["host"], types=["network"], types=["group"]
        hosts_res = await server.call_tool(
            "list_objects",
            {"mgmt_name": "mds1", "domain": "Corp", "types": ["host"]},
        )
        assert isinstance(hosts_res, CallToolResult)
        hosts_data = _parse_tool_json(hosts_res)
        assert hosts_data["from"] == 1
        assert hosts_data["to"] == 3
        assert hosts_data["total"] == 3
        assert hosts_data["source"] == "cache"
        assert isinstance(hosts_data["cache_age_seconds"], float)

        nets_res = await server.call_tool(
            "list_objects",
            {"mgmt_name": "mds1", "domain": "Corp", "types": ["network"]},
        )
        nets_data = _parse_tool_json(nets_res)
        assert nets_data["total"] == 1
        assert nets_data["source"] == "cache"

        grps_res = await server.call_tool(
            "list_objects",
            {"mgmt_name": "mds1", "domain": "Corp", "types": ["group"]},
        )
        grps_data = _parse_tool_json(grps_res)
        assert grps_data["total"] == 1
        assert grps_data["objects"][0]["name"] == "grp-web-servers"

        # 3. list_services with short alias types=["tcp"]
        svcs_res = await server.call_tool(
            "list_services",
            {"mgmt_name": "mds1", "domain": "Corp", "types": ["tcp"]},
        )
        svcs_data = _parse_tool_json(svcs_res)
        assert svcs_data["total"] == 1
        assert svcs_data["objects"][0]["name"] == "https"
        assert svcs_data["source"] == "cache"

        # 4. list_assets with alias types=["gateway", "server"] and parent="corp-cluster-01"
        assets_res = await server.call_tool(
            "list_assets",
            {"mgmt_name": "mds1", "domain": "Corp", "types": ["gateway", "server"]},
        )
        assets_data = _parse_tool_json(assets_res)
        assert {a["name"] for a in assets_data["objects"]} == {"corp-gw-01", "corp-cma-srv"}

        members_res = await server.call_tool(
            "list_assets",
            {"mgmt_name": "mds1", "domain": "Corp", "parent": "corp-cluster-01"},
        )
        members_data = _parse_tool_json(members_res)
        assert [a["name"] for a in members_data["objects"]] == ["corp-cluster-01-m1", "corp-cluster-01-m2"]

        # 5. get_group_members works on cluster assets as well as network groups
        cl_members_res = await server.call_tool(
            "get_group_members",
            {"group_name_or_uid": "corp-cluster-01", "mgmt_name": "mds1", "domain": "Corp"},
        )
        cl_members_data = _parse_tool_json(cl_members_res)
        assert [m["name"] for m in cl_members_data["objects"]] == ["corp-cluster-01-m1", "corp-cluster-01-m2"]


@pytest.mark.asyncio
async def test_show_object_three_tier_matching_and_pagination() -> None:
    """Verify `show_object` resolves across objects, services, assets, and layers with:
    - Tier 1: exact match (`match_type="exact"`, full details including asset `interfaces` and `network_security_blades`);
    - Tier 2: strict anchored wildcard (`*` or `?`) via `fnmatchcase` without implicit prefix/suffix `*`;
    - Tier 3: bounded substring candidate fallback (`match_type="substring_candidates"`, paginated by `limit` and `offset`).
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(client, auth_mode="host")
        await client.refresh_rulebases(mgmt_name="mds1", domains=["Corp"])

        # Tier 1: Exact match on gateway asset returns cached interfaces and blades without extra live call
        gw_res = await server.call_tool(
            "show_object",
            {"uid_or_name": "corp-gw-01", "mgmt_name": "mds1", "domain": "Corp"},
        )
        assert gw_res.is_error is False
        gw_data = _parse_tool_json(gw_res)
        assert gw_data["match_type"] == "exact"
        assert gw_data["total"] == 1
        assert gw_data["object"]["uid"] == "gw-corp-1"
        assert gw_data["object"]["interfaces"][0]["name"] == "eth0"
        assert gw_data["object"]["network_security_blades"]["firewall"] is True

        # Tier 1: Exact match on rulebase layer
        lyr_res = await server.call_tool(
            "show_object",
            {"uid_or_name": "Network", "mgmt_name": "mds1", "domain": "Corp", "obj_type": "layer"},
        )
        assert lyr_res.is_error is False
        lyr_data = _parse_tool_json(lyr_res)
        assert lyr_data["match_type"] == "exact"
        assert lyr_data["object"]["uid"] == "lay-net"

        # Tier 2: Explicit wildcard (`web*1`) is anchored strictly as written (matches `web-srv-1`, NOT `web-srv-2`)
        wild_single = await server.call_tool(
            "show_object",
            {"uid_or_name": "web*1", "mgmt_name": "mds1", "domain": "Corp"},
        )
        assert wild_single.is_error is False
        wild_single_data = _parse_tool_json(wild_single)
        assert wild_single_data["match_type"] == "wildcard"
        assert wild_single_data["total"] == 1
        assert wild_single_data["object"]["name"] == "web-srv-1"

        # Tier 2: Explicit wildcard matching multiple objects (`web-srv-*`) with pagination (`limit=1, offset=1`)
        wild_multi = await server.call_tool(
            "show_object",
            {"uid_or_name": "web-srv-*", "mgmt_name": "mds1", "domain": "Corp", "limit": 1, "offset": 1},
        )
        assert wild_multi.is_error is False
        wild_multi_data = _parse_tool_json(wild_multi)
        assert wild_multi_data["match_type"] == "wildcard"
        assert wild_multi_data["total"] == 2
        assert wild_multi_data["from"] == 2
        assert wild_multi_data["to"] == 2
        assert [o["name"] for o in wild_multi_data["objects"]] == ["web-srv-2"]

        # Tier 3: Substring candidate fallback when no exact match exists ("web" matches web-srv-1, web-srv-2, net-web, grp-web-servers)
        sub_res = await server.call_tool(
            "show_object",
            {"uid_or_name": "web", "mgmt_name": "mds1", "domain": "Corp", "limit": 2, "offset": 0},
        )
        assert sub_res.is_error is False
        sub_data = _parse_tool_json(sub_res)
        assert sub_data["match_type"] == "substring_candidates"
        assert sub_data["total"] == 4
        assert sub_data["from"] == 1
        assert sub_data["to"] == 2
        assert len(sub_data["objects"]) == 2
        assert "hint" in sub_data


@pytest.mark.asyncio
async def test_query_objects_describe_and_cache_control_tools() -> None:
    """Scenario: Aggregate object counts across domains in a single tool call (`query_objects` supporting
    `aggregate='describe'`, `'count'`, `'list'`) and inspect/refresh via `cache_control(action='status'|'refresh')`.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(client, auth_mode="host")

        # Warm objects, services, assets, rulebase in Corp and Branch via cache_control(action="refresh")
        await server.call_tool(
            "cache_control",
            {"action": "refresh", "mgmt_name": "mds1", "domains": ["Corp", "Branch"], "scope": "objects"},
        )
        await server.call_tool(
            "cache_control",
            {"action": "refresh", "mgmt_name": "mds1", "domain": "Corp", "scope": "services"},
        )
        await server.call_tool(
            "cache_control",
            {"action": "refresh", "mgmt_name": "mds1", "domain": "Corp", "scope": "assets"},
        )
        await server.call_tool(
            "cache_control",
            {"action": "refresh", "mgmt_name": "mds1", "domain": "Corp", "scope": "rulebase"},
        )

        # 1. query_objects with aggregate="describe"
        desc_res = await server.call_tool(
            "query_objects",
            {"mgmt_name": "mds1", "include_global": True, "aggregate": "describe"},
        )
        assert isinstance(desc_res, CallToolResult)
        desc_data = _parse_tool_json(desc_res)
        assert "Corp" in desc_data["domains"]
        assert "Branch" in desc_data["domains"]
        assert desc_data["object_types"]["host"] == 6  # 3 in Corp + 3 in Branch
        assert desc_data["asset_types"]["simple-gateway"] == 1
        assert "original_domain" in desc_data["groupable_fields"]

        # 2. query_objects with group_by=["domain_name", "type"], aggregate="count"
        agg_res = await server.call_tool(
            "query_objects",
            {
                "mgmt_name": "mds1",
                "types": ["host", "network"],
                "group_by": ["domain_name", "type"],
                "aggregate": "count",
            },
        )
        assert isinstance(agg_res, CallToolResult)
        agg_data = _parse_tool_json(agg_res)
        assert agg_data["total"] == 8
        assert agg_data["group_by"] == ["domain_name", "type"]
        groups_map = {(g["domain_name"], g["type"]): g["count"] for g in agg_data["groups"]}
        assert groups_map[("Corp", "host")] == 3
        assert groups_map[("Corp", "network")] == 1
        assert groups_map[("Branch", "host")] == 3

        # 3. query_objects distinguishing domain-owned ("local") vs Global ("global") via original_domain
        local_only_res = await server.call_tool(
            "query_objects",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "types": ["host"],
                "scope_origin": "local",
                "aggregate": "list",
            },
        )
        local_data = _parse_tool_json(local_only_res)
        assert local_data["total"] == 2
        assert {o["name"] for o in local_data["objects"]} == {"web-srv-1", "web-srv-2"}

        global_only_res = await server.call_tool(
            "query_objects",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "types": ["host"],
                "scope_origin": "global",
                "aggregate": "list",
            },
        )
        global_data = _parse_tool_json(global_only_res)
        assert global_data["total"] == 1
        assert global_data["objects"][0]["name"] == "global-dns-1"
        assert global_data["objects"][0]["original_domain"] == "Global"

        # 4. cache_control(action="status") across all 5 scopes ("domains", "objects", "services", "assets", "rulebase")
        cs_res = await server.call_tool("cache_control", {"mgmt_name": "mds1", "action": "status"})
        assert isinstance(cs_res, CallToolResult)
        cs_data = _parse_tool_json(cs_res)
        assert cs_data["total_entries"] > 0
        for expected_scope in ("domains", "objects", "services", "assets", "rulebase"):
            assert expected_scope in cs_data["by_scope"]
            first_entry = cs_data["by_scope"][expected_scope][0]
            assert "item_type" in first_entry
            assert "last_published_at" in first_entry
            assert "last_session_uid" in first_entry
            assert "synced_at" in first_entry
            assert isinstance(first_entry["cache_age_seconds"], float)


@pytest.mark.asyncio
async def test_show_rulebase_catalog_discovery_local_filter_and_live_parameters() -> None:
    """Scenario: `show_rulebase`:
    - returns the domain's cached `packages` and `layers` when `package` and `layer` are omitted or unmatched;
    - evaluates `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, or `raw` format;
    - executes a live Management API query when live-only parameters (`show_hits`, `order`, etc.) or `cache_mode='live'` are passed.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(client, auth_mode="host")

        # Warm hosts, services, and rulebase for Corp
        await client.get_hosts("mds1", "Corp")
        await client.get_services("mds1", "Corp")
        await client.refresh_rulebases(mgmt_name="mds1", domains=["Corp"])

        call_count_before = len(fake_api.calls)

        # 0. Catalog mode when package and layer are omitted
        cat_res = await server.call_tool(
            "show_rulebase",
            {"mgmt_name": "mds1", "domain": "Corp", "cache_mode": "cache"},
        )
        assert cat_res.is_error is False
        cat_data = _parse_tool_json(cat_res)
        assert cat_data["mode"] == "catalog"
        assert [p["name"] for p in cat_data["packages"]] == ["Standard"]
        assert [l_item["name"] for l_item in cat_data["layers"]] == ["Network"]

        # 0b. Catalog fallback when an unknown layer name is requested
        unmatched_res = await server.call_tool(
            "show_rulebase",
            {"mgmt_name": "mds1", "domain": "Corp", "layer": "NonExistentLayer", "cache_mode": "cache"},
        )
        assert unmatched_res.is_error is False
        unmatched_data = _parse_tool_json(unmatched_res)
        assert unmatched_data["mode"] == "catalog"
        assert "hint" in unmatched_data
        assert [l_item["name"] for l_item in unmatched_data["layers"]] == ["Network"]

        # 1. Local cache filter by IP ("10.10.1.10" resolves to host "web-srv-1" on rule #1!)
        rb_cached = await server.call_tool(
            "show_rulebase",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "rulebase_type": "access",
                "layer": "Network",
                "filter": "10.10.1.10",
                "format": "model_friendly",
                "cache_mode": "cache",
            },
        )
        assert isinstance(rb_cached, CallToolResult)
        assert rb_cached.is_error is False
        rb_data = _parse_tool_json(rb_cached)
        assert rb_data["source"] == "cache"
        assert isinstance(rb_data["cache_age_seconds"], float)
        assert rb_data["total"] == 1
        assert rb_data["rules"][0]["uid"] == "rule-web-1"
        assert "#1 'Allow Web Server'" in rb_data["rendered_text"]
        # Zero live API calls were made during cached catalog & filter evaluation!
        assert len(fake_api.calls) == call_count_before

        # 2. NAT rulebase local filter in markdown format
        nat_cached = await server.call_tool(
            "show_rulebase",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "rulebase_type": "nat",
                "package": "Standard",
                "filter": "web-srv-1",
                "format": "markdown",
                "cache_mode": "cache",
            },
        )
        assert isinstance(nat_cached, CallToolResult)
        nat_data = _parse_tool_json(nat_cached)
        assert nat_data["source"] == "cache"
        assert nat_data["total"] == 1
        assert "| 1 | Web Static NAT |" in nat_data["rendered_text"]
        assert len(fake_api.calls) == call_count_before

        # 3. Passing live-only parameter `show_hits=True` triggers live Management API query
        rb_live = await server.call_tool(
            "show_rulebase",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "rulebase_type": "access",
                "layer": "Network",
                "show_hits": True,
            },
        )
        assert isinstance(rb_live, CallToolResult)
        rb_live_data = _parse_tool_json(rb_live)
        assert rb_live_data["source"] == "live"
        assert rb_live_data["cache_age_seconds"] is None
        assert any(c[1] == "show-access-rulebase" and c[2] and c[2].get("show-hits") is True for c in fake_api.calls)


@pytest.mark.asyncio
async def test_unknown_domain_prevalidation_and_invalid_credentials_tool_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: Unknown domain or rejected login (`InvalidCredentialsError`) logs `ToolFailure` at WARNING
    (without arguments or secrets) and returns an actionable error listing known domains on that management server
    rather than `'internal error: InvalidCredentialsError'`.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="super-secret-api-key-val")

    warning_logs: list[tuple[str, dict[str, Any]]] = []

    def capture_warning(msg: str, **kwargs: Any) -> None:
        warning_logs.append((msg, kwargs))

    monkeypatch.setattr("arodonata.mcp.errors.logger.warning", capture_warning)

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(client, auth_mode="host")

        # 1. Calling list_objects with unknown domain "NonExistentDom":
        #    Performs a single domain-list refresh (`show-domains`), sees ["Corp", "Branch", "Global"],
        #    and fails BEFORE attempting any login or `show-hosts` query on "NonExistentDom"!
        res_unknown = await server.call_tool(
            "list_objects",
            {
                "mgmt_name": "mds1",
                "domain": "NonExistentDom",
                "types": ["host"],
                "filter": "sensitive-arg-should-not-be-logged",
            },
        )
        assert isinstance(res_unknown, CallToolResult)
        assert res_unknown.is_error is True
        err_text = _get_tool_text(res_unknown)
        assert "Unknown domain 'NonExistentDom'" in err_text
        assert "Corp" in err_text
        assert "Branch" in err_text
        assert ("mds1", "show-hosts", "NonExistentDom") not in fake_api.queries

        # Verify WARNING log was recorded without raw tool arguments or secrets
        assert len(warning_logs) == 1
        assert warning_logs[0][1]["tool"] == "list_objects"
        assert "sensitive-arg-should-not-be-logged" not in repr(warning_logs)
        assert "super-secret-api-key-val" not in repr(warning_logs)

        # 2. If login raises InvalidCredentialsError on a known domain ("Branch"), returns actionable
        #    message listing known domains rather than "internal error: InvalidCredentialsError"
        fake_api.raise_invalid_creds_for_domain = "Branch"
        res_cred = await server.call_tool(
            "list_objects",
            {"mgmt_name": "mds1", "domain": "Branch", "types": ["host"]},
        )
        assert isinstance(res_cred, CallToolResult)
        assert res_cred.is_error is True
        cred_text = _get_tool_text(res_cred)
        assert "internal error: InvalidCredentialsError" not in cred_text
        assert "Authentication rejected" in cred_text
        assert "Corp" in cred_text
        assert "Branch" in cred_text


@pytest.mark.asyncio
async def test_write_api_protection_sid_masking_and_unexpected_exception_handling() -> None:
    """Scenario: `api_call` rejects non-read-only commands when `ARODONATA_MCP_ALLOW_WRITE_API=false`,
    masks any echoed SID in error messages, and returns `'internal error: <ExceptionClass>'` on unexpected exceptions.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(
            client,
            auth_mode="host",
            allow_write_api=False,
            cpcrud=True,
        )

        # 1. Non-show-* command in api_call is rejected before execution
        calls_before = len(fake_api.calls)
        res_write = await server.call_tool(
            "api_call",
            {
                "command": "add-host",
                "payload": {"name": "rogue-host", "ipv4-address": "10.9.9.9"},
                "mgmt_name": "mds1",
                "domain": "Corp",
            },
        )
        assert isinstance(res_write, CallToolResult)
        assert res_write.is_error is True
        write_err = _get_tool_text(res_write)
        assert "ARODONATA_MCP_ALLOW_WRITE_API=false" in write_err
        assert len(fake_api.calls) == calls_before

        # 2. Echoed SID in Management API error message is masked
        await client.get_domains("mds1")
        leaked_sid = "leaked-session-token-987654321"
        fake_api.fail_command_with_sid = ("show-generic-objects", leaked_sid)
        res_sid_err = await server.call_tool(
            "api_call",
            {
                "command": "show-generic-objects",
                "mgmt_name": "mds1",
                "domain": "Corp",
            },
        )
        assert isinstance(res_sid_err, CallToolResult)
        assert res_sid_err.is_error is True
        sid_err_text = _get_tool_text(res_sid_err)
        assert leaked_sid not in sid_err_text
        assert REDACTED_PLACEHOLDER in sid_err_text
        fake_api.fail_command_with_sid = None

        # 3. Unexpected internal exception returns "internal error: <ExceptionClass>" without stack trace
        fake_api.raise_unexpected_for_command = "show-time"
        res_crash = await server.call_tool(
            "api_call",
            {"command": "show-time", "mgmt_name": "mds1", "domain": "Corp"},
        )
        assert isinstance(res_crash, CallToolResult)
        assert res_crash.is_error is True
        crash_text = _get_tool_text(res_crash)
        assert crash_text == "internal error: KeyError"
        assert "simulated-unexpected-key-failure" not in crash_text
        fake_api.raise_unexpected_for_command = None

        # 4. Change report, api_call(command="where-used"), and cpcrud tools work end-to-end
        rep_res = await server.call_tool(
            "change_report",
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "session_uids": ["sess-100"],
                "format": "markdown",
            },
        )
        assert isinstance(rep_res, CallToolResult)
        assert rep_res.is_error is False
        rep_data = _parse_tool_json(rep_res)
        assert rep_data["session_count"] == 1
        assert "Ticket-100" in rep_data["rendered"]

        wu_res = await server.call_tool(
            "api_call",
            {"command": "where-used", "payload": {"name": "web-srv-1"}, "mgmt_name": "mds1", "domain": "Corp"},
        )
        assert isinstance(wu_res, CallToolResult)
        assert wu_res.is_error is False
        wu_data = _parse_tool_json(wu_res)
        assert wu_data["source"] == "live"

        # CPCRUD validate, plan, apply, inverse
        tpl = {
            "version": 1,
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [{"type": "host", "name": "mcp-host-1", "ipv4-address": "10.50.0.10"}],
        }
        val_res = await server.call_tool("cpcrud_validate", {"template": tpl})
        assert _parse_tool_json(val_res)["valid"] is True

        plan_res = await server.call_tool("cpcrud_plan", {"template": tpl})
        plan_dict = _parse_tool_json(plan_res)
        assert plan_dict["actions"][0]["outcome"] == "create"
        assert "plan_id" in plan_dict
        assert "plan_signature" in plan_dict

        apply_res = await server.call_tool("cpcrud_apply", {"plan": plan_dict})
        apply_dict = _parse_tool_json(apply_res)
        assert apply_dict["published_domains"] == ["mds1:Corp"]

        inv_res = await server.call_tool("cpcrud_inverse", {"plan": plan_dict, "report": apply_dict})
        inv_dict = _parse_tool_json(inv_res)
        assert inv_dict["operations"][0]["operation"] == "delete"


@pytest.mark.asyncio
async def test_mcp_cpcrud_tamper_resistance_staged_sessions_and_api_call_hardening() -> None:
    """Adversarial tests for C1, C2, W12, W25, W27, W28:
    - `cpcrud_apply` rejects unsigned or tampered plans (e.g. `run-script` command injection).
    - `cpcrud_apply` rejects `retry_remaining > 3`.
    - `cpcrud_inverse` requires an `ApplyReport` or applied `plan_id`.
    - `cpcrud_staged_session(action='publish'|'discard')` adopts and publishes/discards staged sessions.
    - `show_object` rejects non-canonical or traversal `obj_type` values.
    - `api_call` with `ALLOW_WRITE_API=false` permits `where-used` and `verify-policy` and rejects `publish`/`logout`/traversal.
    - `api_call` with `ALLOW_WRITE_API=true` isolates mutating commands in dedicated sessions and caps `timeout <= 300.0`.
    """
    fake_api = MCPFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        server = create_mcp_server(
            client,
            auth_mode="host",
            allow_write_api=False,
            cpcrud=True,
        )
        await client.get_domains("mds1")

        # 1. C1: show_object rejects traversal or non-canonical obj_type
        for bad_type in ("../add-host", "host/../../run-script", "run-script", "not-a-type"):
            bad_obj_res = await server.call_tool(
                "show_object",
                {"uid_or_name": "web-srv-1", "mgmt_name": "mds1", "domain": "Corp", "obj_type": bad_type},
            )
            assert bad_obj_res.is_error is True

        # 2. C1 / W28: api_call with allow_write_api=False permits where-used, rejects publish/logout/traversal
        wu_call = await server.call_tool(
            "api_call",
            {"command": "where-used", "payload": {"name": "web-srv-1"}, "mgmt_name": "mds1", "domain": "Corp"},
        )
        assert wu_call.is_error is False

        for forbidden_cmd in ("publish", "discard", "logout", "run-script", "show-host/../run-script"):
            forb_res = await server.call_tool(
                "api_call",
                {"command": forbidden_cmd, "mgmt_name": "mds1", "domain": "Corp"},
            )
            assert forb_res.is_error is True

        # 3. C2: cpcrud_apply rejects unsigned or tampered plans
        tpl = {
            "version": 1,
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [{"type": "host", "name": "mcp-host-2", "ipv4-address": "10.50.0.20"}],
        }
        plan_res = await server.call_tool("cpcrud_plan", {"template": tpl})
        signed_plan = _parse_tool_json(plan_res)

        # Tamper with command in action
        tampered_plan = json.loads(json.dumps(signed_plan))
        tampered_plan["actions"][0]["command"] = "run-script"
        calls_before_tamper = len(fake_api.calls)
        tamper_res = await server.call_tool("cpcrud_apply", {"plan": tampered_plan})
        assert tamper_res.is_error is True
        assert "Untrusted or tampered CPCRUD plan" in _get_tool_text(tamper_res)
        assert len(fake_api.calls) == calls_before_tamper

        # Unsigned forged plan
        unsigned_plan = {k: v for k, v in signed_plan.items() if k not in ("plan_id", "plan_signature")}
        unsigned_res = await server.call_tool("cpcrud_apply", {"plan": unsigned_plan})
        assert unsigned_res.is_error is True

        # retry_remaining > 3 is rejected
        retry_res = await server.call_tool("cpcrud_apply", {"plan": signed_plan, "retry_remaining": 10})
        assert retry_res.is_error is True
        assert "retry_remaining" in _get_tool_text(retry_res)

        # 4. W27: Staged session apply + cpcrud_staged_session(action="publish" | "discard")
        staged_apply_res = await server.call_tool(
            "cpcrud_apply",
            {"plan_id": signed_plan["plan_id"], "no_publish": True, "keep_session": True},
        )
        assert staged_apply_res.is_error is False
        staged_report = _parse_tool_json(staged_apply_res)
        assert any(s["mgmt_name"] == "mds1" and s["domain_name"] == "Corp" for s in staged_report["staged_sessions"])

        pub_staged_res = await server.call_tool(
            "cpcrud_staged_session",
            {"mgmt_name": "mds1", "domain": "Corp", "session_uid": "sess-staged-1", "action": "publish"},
        )
        assert pub_staged_res.is_error is False
        assert _parse_tool_json(pub_staged_res)["published"] is True

        disc_staged_res = await server.call_tool(
            "cpcrud_staged_session",
            {"mgmt_name": "mds1", "domain": "Corp", "session_uid": "sess-staged-2", "action": "discard"},
        )
        assert disc_staged_res.is_error is False
        assert _parse_tool_json(disc_staged_res)["discarded"] is True

        # 5. W25: api_call with allow_write_api=True uses dedicated session and caps timeout <= 300s
        write_server = create_mcp_server(
            client,
            auth_mode="host",
            allow_write_api=True,
        )
        dedicated_before = len(fake_api.dedicated_sessions_created)
        write_call = await write_server.call_tool(
            "api_call",
            {
                "command": "add-host",
                "payload": {"name": "isolated-host", "ipv4-address": "10.88.0.1"},
                "mgmt_name": "mds1",
                "domain": "Corp",
                "timeout": 9999.0,
            },
        )
        assert write_call.is_error is False
        assert len(fake_api.dedicated_sessions_created) == dedicated_before + 1
        add_host_detail = next(d for d in reversed(fake_api.call_details) if d["command"] == "add-host")
        assert add_host_detail["sid"] == "dedicated-sid-999"
        assert add_host_detail["timeout"] == 300.0
        assert ("mds1", "dedicated-sid-999") in fake_api.logged_out_sids
