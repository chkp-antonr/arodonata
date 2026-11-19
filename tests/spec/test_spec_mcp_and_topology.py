"""Specification acceptance tests for `mcp-server` (`SCN-MCP-*`) and `gateway-topology` (`SCN-TOPO-*`)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from arodonata import ArodonataClient
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot, RulebaseLayerEntry, RulebasePackageLayerEntry
from arodonata.core.models.topology import GatewayTopologyEntry, TopologyAnnotation
from arodonata.mcp import cli as mcp_cli
from arodonata.mcp import config as mcp_config
from arodonata.mcp import create_mcp_server


def _parse_json(result: CallToolResult) -> dict[str, Any]:
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    return json.loads(first.text)  # type: ignore[no-any-return]


def _make_fp(seed: str = "spec-mcp") -> str:
    digest = hashlib.sha256(seed.encode()).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, 64, 2))


class _McpTopoFakeApi:
    """In-memory `ApiPort` double for MCP and Topology specification scenarios."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None]] = []
        self.queries: list[tuple[str, str, str | None]] = []
        self.domains: list[dict[str, Any]] = [
            {
                "uid": "dom-corp",
                "name": "Corp",
                "domain-type": "domain",
                "servers": [{"ipv4-address": "10.0.0.1", "active": True}],
            }
        ]
        self.hosts: list[dict[str, Any]] = [
            {
                "uid": "h-1",
                "name": "Web_Host_1",
                "type": "host",
                "ipv4-address": "10.10.1.5",
                "domain": {"name": "Corp"},
            }
        ]
        self.assets: list[dict[str, Any]] = [
            {
                "uid": "gw-1",
                "name": "gw-corp-01",
                "type": "simple-gateway",
                "ipv4-address": "198.51.100.1",
                "domain": {"name": "Corp"},
            }
        ]
        self.tcp_services: list[dict[str, Any]] = [
            {"uid": "s-https", "name": "https", "type": "service-tcp", "port": "443", "domain": {"name": "Corp"}}
        ]
        self.https_rulebase: dict[str, Any] = {
            "uid": "lay-https",
            "name": "Corp_HTTPS",
            "rulebase": [
                {
                    "uid": "https-r1",
                    "name": "Inspect_Out",
                    "type": "https-rule",
                    "rule-number": 1,
                    "enabled": True,
                    "source": [{"uid": "h-1", "name": "Web_Host_1"}],
                    "destination": [{"uid": "any", "name": "Any"}],
                    "service": [{"uid": "s-https", "name": "https"}],
                    "action": {"name": "Inspect"},
                    "blade": ["HTTPS Inspection"],
                }
            ],
            "to": 1,
            "total": 1,
        }
        self.threat_rulebase: dict[str, Any] = {
            "uid": "lay-threat",
            "name": "Corp_Threat",
            "rulebase": [
                {
                    "uid": "thr-r1",
                    "name": "Strict_IPS",
                    "type": "threat-rule",
                    "rule-number": 1,
                    "enabled": True,
                    "protected-scope": [{"uid": "any", "name": "Any"}],
                    "action": {"name": "Detect"},
                }
            ],
            "to": 1,
            "total": 1,
        }

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
        self.calls.append((mgmt_name, command, dict(payload or {}), domain))
        if command == "show-domains":
            return ApiCallResult(success=True, data={"objects": list(self.domains), "total": len(self.domains)})
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True, data={"uid": "pub-mcp-1", "publish-time": {"iso-8601": "2026-10-24T10:00:00Z"}}
            )
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-https-rulebase":
            return ApiCallResult(success=True, data=self.https_rulebase)
        if command == "show-threat-rulebase":
            return ApiCallResult(success=True, data=self.threat_rulebase)
        return ApiCallResult(success=True, data={})

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
        if command == "show-domains":
            return ApiQueryResult(success=True, objects=list(self.domains), total=len(self.domains))
        if command == "show-hosts":
            return ApiQueryResult(success=True, objects=list(self.hosts), total=len(self.hosts))
        if command == "show-services-tcp":
            return ApiQueryResult(success=True, objects=list(self.tcp_services), total=len(self.tcp_services))
        if command == "show-gateways-and-servers":
            return ApiQueryResult(success=True, objects=list(self.assets), total=len(self.assets))
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        read_only: bool = False,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return ("sid-mcp-1", "10.0.0.1")

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
        timeout: float = 5.0,
    ) -> Awaitable[bool]:
        async def _ok() -> bool:
            return True

        return _ok()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


# ==============================================================================
# MCP Server Scenarios
# ==============================================================================


@pytest.mark.spec("SCN-MCP-001-1")
def test_standalone_mcp_cli_warns_when_auth_none_with_non_loopback_or_wildcard_hosts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SCN-MCP-001-1: Standalone startup fails closed on unsafe `auth_mode='none'` by default, and emits prominent WARNING when explicitly opted in."""
    warnings_logged: list[str] = []
    monkeypatch.setattr(mcp_config.logger, "warning", lambda msg, *_a, **_kw: warnings_logged.append(str(msg)))
    monkeypatch.setattr(mcp_cli.logger, "warning", lambda msg, *_a, **_kw: warnings_logged.append(str(msg)))

    monkeypatch.setenv("MGMT_NAMES", "mds1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k1")
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "pinned")
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", f"10.0.0.1:443={_make_fp()}")

    # 1. Fail closed with exit code 2 on non-loopback host or wildcard ALLOWED_HOSTS without opt-in
    monkeypatch.setenv("ARODONATA_MCP_ALLOWED_HOSTS", "*")
    rc_blocked_wild = mcp_cli.run_cli(
        ["--host", "0.0.0.0", "--auth-mode", "none"], uvicorn_runner=lambda *_a, **_kw: None
    )
    assert rc_blocked_wild == 2
    assert "configuration error" in capsys.readouterr().err.lower()

    monkeypatch.delenv("ARODONATA_MCP_ALLOWED_HOSTS", raising=False)
    rc_blocked_host = mcp_cli.run_cli(
        ["--host", "0.0.0.0", "--auth-mode", "none"], uvicorn_runner=lambda *_a, **_kw: None
    )
    assert rc_blocked_host == 2
    assert "allow_insecure_unauthenticated" in capsys.readouterr().err

    # 2. Explicit opt-in (--allow-insecure-unauthenticated, plus DNS rebinding disabled when ALLOWED_HOSTS='*') succeeds with single WARNING
    monkeypatch.setenv("ARODONATA_MCP_ALLOWED_HOSTS", "*")
    monkeypatch.setenv("ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION", "false")
    rc_opt_in = mcp_cli.run_cli(
        ["--host", "0.0.0.0", "--auth-mode", "none", "--allow-insecure-unauthenticated"],
        uvicorn_runner=lambda *_a, **_kw: None,
    )
    assert rc_opt_in == 0
    assert len(warnings_logged) == 1
    assert any(
        "unauthenticated" in w.lower()
        or "security warning" in w.lower()
        or "allow_insecure_unauthenticated" in w.lower()
        for w in warnings_logged
    )


@pytest.mark.spec("SCN-MCP-002-1")
async def test_mcp_list_envelopes_cold_upgrade_cache_age_none_and_multi_mgmt_search() -> None:
    """SCN-MCP-002-1 (FC-04, FC-12): Cold cache_mode='cache' upgrades, uncached `cache_age_seconds` is null, search spans all mgmts."""
    api = _McpTopoFakeApi()
    settings = ArodonataSettings(mgmt_names="mds1,mds2", mgmt_servers="10.0.0.1,10.0.0.2", api_keys="k1,k2")
    async with ArodonataClient(settings, api=api) as client:
        mcp = create_mcp_server(client, auth_mode="host")

        # 1. Cold `list_domains(cache_mode="cache")` auto-upgrades empty arodonata_domains to "smart" (FC-04)
        dom_res = _parse_json(await mcp.call_tool("list_domains", {"mgmt_name": "mds1", "cache_mode": "cache"}))
        assert dom_res["source"] == "cache"
        assert dom_res["total"] == 1
        assert any(c[0] == "mds1" and c[1] == "show-domains" for c in api.calls)

        # 2. Cold `list_services` and `list_assets` with cache_mode="cache" auto-upgrade to "smart"
        svc_res = _parse_json(
            await mcp.call_tool("list_services", {"mgmt_name": "mds1", "domain": "Corp", "cache_mode": "cache"})
        )
        assert svc_res["source"] == "cache"
        assert svc_res["total"] >= 1
        assert ("mds1", "show-services-tcp", "Corp") in api.queries
        asset_res = _parse_json(
            await mcp.call_tool("list_assets", {"mgmt_name": "mds1", "domain": "Corp", "cache_mode": "cache"})
        )
        assert asset_res["source"] == "cache"
        assert asset_res["total"] >= 1
        assert ("mds1", "show-gateways-and-servers", "Corp") in api.queries
        obj_res = _parse_json(
            await mcp.call_tool(
                "list_objects", {"mgmt_name": "mds1", "domain": "Corp", "types": ["host"], "cache_mode": "cache"}
            )
        )
        assert obj_res["total"] >= 1
        assert ("mds1", "show-hosts", "Corp") in api.queries

        # 3. Cold `show_rulebase(cache_mode="cache")` without cached synced_at returns cache_age_seconds=None (FC-12), NOT 0.0
        rb_res = _parse_json(
            await mcp.call_tool("show_rulebase", {"mgmt_name": "mds1", "domain": "Corp", "cache_mode": "cache"})
        )
        assert rb_res["cache_age_seconds"] is None

        # 4. `search_objects` with mgmt_name omitted spans both mds1 and mds2
        await client.cache.upsert_domains([DomainInfo(id="mds2:DMZ", mgmt_name="mds2", name="DMZ", uid="d2")])
        await client.cache.replace_domain_objects(
            "mds2",
            "DMZ",
            [
                CPObject(
                    uid="h-m2",
                    name="mds2-app",
                    type="host",
                    mgmt_name="mds2",
                    domain_name="DMZ",
                    ipv4_address="10.20.2.2",
                )
            ],
            types=["host"],
        )
        srch_res = _parse_json(
            await mcp.call_tool("search_objects", {"query": "10.10.1.5,10.20.2.2", "cache_mode": "cache"})
        )
        mgmts = {item["mgmt_name"] for item in srch_res["objects"]}
        assert mgmts == {"mds1", "mds2"}


@pytest.mark.spec("SCN-MCP-004-2")
async def test_mcp_query_objects_describe_warms_objects_when_zero_object_sync_states() -> None:
    """SCN-MCP-004-2: `query_objects(..., aggregate='describe')` warms `arodonata_objects` even if un-synced topology rows exist."""
    api = _McpTopoFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=api) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        # Seed partial topology object + topology sync state WITHOUT any scope="objects" sync state
        await client.cache.upsert_objects(
            [
                CPObject(
                    uid="h-partial",
                    name="topo-only-host",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.1.1.1",
                )
            ]
        )
        await client.cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="topology",
                item_type="*",
                last_session_uid="pub-mcp-1",
                status="ok",
            )
        )
        assert await client.cache.list_sync_states("mds1", "Corp", scope="objects") == []

        mcp = create_mcp_server(client, auth_mode="host")
        desc = _parse_json(
            await mcp.call_tool("query_objects", {"mgmt_name": "mds1", "domain": "Corp", "aggregate": "describe"})
        )
        assert any(q[1] == "show-hosts" for q in api.queries)
        assert desc["source"] == "cache"
        assert "filterable_fields" in desc
        assert "Corp" in desc["domains"]


@pytest.mark.spec("SCN-MCP-004-3")
async def test_mcp_search_and_query_normalize_cpmi_aliases_and_mixed_case_group_by() -> None:
    """SCN-MCP-004-3 (FC-05): Normalize `Cpmi*` classes, field aliases, and mixed-case canonical `group_by`."""
    api = _McpTopoFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=api) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        await client.cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    id="mds1:Corp:gw-1",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="gw-1",
                    name="EdgeGW",
                    type="CpmiGatewayCluster",
                    asset_id="mds1:Corp:EdgeGW",
                    ipv4_address="198.51.100.10",
                )
            ],
        )
        await client.cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="assets",
                item_type="*",
                last_session_uid="pub-mcp-1",
                status="ok",
                object_count=1,
            )
        )
        await client.cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="objects",
                item_type="host",
                last_session_uid="pub-mcp-1",
                status="ok",
                object_count=0,
            )
        )

        mcp = create_mcp_server(client, auth_mode="host")
        # 1. Mixed-case canonical group_by ("Domain_Name", "Type") + short type "cluster"
        q_res = _parse_json(
            await mcp.call_tool(
                "query_objects",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "types": ["cluster"],
                    "aggregate": "count",
                    "group_by": ["Domain_Name", "Type"],
                    "cache_mode": "cache",
                },
            )
        )
        assert q_res["total"] == 1
        grp = q_res["groups"][0]
        assert grp["Domain_Name"] == "Corp"
        assert grp["Type"] == "CpmiGatewayCluster"
        assert grp["count"] == 1

        # 2. Alias group_by + search_objects CpmiGatewayCluster short type
        q_alias = _parse_json(
            await mcp.call_tool(
                "query_objects",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "types": ["cluster"],
                    "aggregate": "count",
                    "group_by": ["mgmt", "asset_type", "orig_domain"],
                    "cache_mode": "cache",
                },
            )
        )
        assert q_alias["groups"][0]["mgmt"] == "mds1"
        assert q_alias["groups"][0]["asset_type"] == "CpmiGatewayCluster"

        srch = _parse_json(
            await mcp.call_tool(
                "search_objects",
                {"query": "198.51.100.10", "mgmt_name": "mds1", "types": ["cluster"], "cache_mode": "cache"},
            )
        )
        assert srch["total"] == 1
        assert srch["objects"][0]["name"] == "EdgeGW"


@pytest.mark.spec("SCN-MCP-006-1")
async def test_mcp_show_rulebase_https_threat_cpcrud_raw_and_catalog_metadata() -> None:
    """SCN-MCP-006-1: `show_rulebase` supports HTTPS/Threat live APIs, raw/cpcrud formats, and inline/cleanup catalog metadata."""
    api = _McpTopoFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=api) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        snap = DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Corp",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="p1",
                    package_name="Corp_Pkg",
                    rulebase_type="access",
                    layer_uid="l1",
                    layer_name="Corp_Net",
                    position=1,
                ),
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="p1",
                    package_name="Corp_Pkg",
                    rulebase_type="https",
                    layer_uid="lh1",
                    layer_name="Corp_HTTPS",
                    position=1,
                ),
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="p1",
                    package_name="Corp_Pkg",
                    rulebase_type="threat",
                    layer_uid="lt1",
                    layer_name="Corp_Threat",
                    position=1,
                ),
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="l1",
                    name="Corp_Net",
                    rulebase_type="access",
                    implicit_cleanup_action="drop",
                ),
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="l-in",
                    name="Inline_Web",
                    rulebase_type="access",
                    parent_layer_uid="l1",
                    parent_rule_uid="r1",
                ),
                RulebaseLayerEntry(
                    mgmt_name="mds1", domain_name="Corp", uid="lh1", name="Corp_HTTPS", rulebase_type="https"
                ),
                RulebaseLayerEntry(
                    mgmt_name="mds1", domain_name="Corp", uid="lt1", name="Corp_Threat", rulebase_type="threat"
                ),
            ],
        )
        await client.cache.replace_domain_rulebase(snap)
        for scope_type in ("rulebase",):
            await client.cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    scope=scope_type,
                    item_type="*",
                    last_session_uid="pub-mcp-1",
                    status="ok",
                )
            )

        mcp = create_mcp_server(client, auth_mode="host")

        # 1. Catalog discovery exposes inline layer parent links and implicit_cleanup_action
        cat = _parse_json(
            await mcp.call_tool("show_rulebase", {"mgmt_name": "mds1", "domain": "Corp", "cache_mode": "cache"})
        )
        layer_by_name = {lyr["name"]: lyr for lyr in cat["layers"]}
        assert layer_by_name["Corp_Net"]["implicit_cleanup_action"] == "drop"
        assert layer_by_name["Inline_Web"]["parent_layer_uid"] == "l1"

        # 2. Local snapshot filtering in raw and cpcrud formats
        res_raw = _parse_json(
            await mcp.call_tool(
                "show_rulebase",
                {"mgmt_name": "mds1", "domain": "Corp", "package": "Corp_Pkg", "format": "raw", "cache_mode": "cache"},
            )
        )
        assert res_raw["format"] == "raw"
        res_cp = _parse_json(
            await mcp.call_tool(
                "show_rulebase",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "package": "Corp_Pkg",
                    "format": "cpcrud",
                    "cache_mode": "cache",
                },
            )
        )
        assert res_cp["format"] == "cpcrud"

        # 3. Live HTTPS and Threat queries hit show-https-rulebase / show-threat-rulebase
        https_res = _parse_json(
            await mcp.call_tool(
                "show_rulebase",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "package": "Corp_Pkg",
                    "rulebase_type": "https",
                    "cache_mode": "live",
                },
            )
        )
        assert https_res["source"] == "live"
        threat_res = _parse_json(
            await mcp.call_tool(
                "show_rulebase",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "package": "Corp_Pkg",
                    "rulebase_type": "threat",
                    "cache_mode": "live",
                },
            )
        )
        assert threat_res["source"] == "live"
        called_cmds = {c[1] for c in api.calls}
        assert "show-https-rulebase" in called_cmds
        assert "show-threat-rulebase" in called_cmds


@pytest.mark.spec("SCN-MCP-007-1")
async def test_mcp_locate_gateways_returns_policy_inferred_confidence_and_standby_fields() -> None:
    """SCN-MCP-007-1: `locate_gateways` MCP tool includes `policy_inferred`, `confidence`, `is_standby_path`, and `confidence_factors`."""
    api = _McpTopoFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=api) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        # Multi-interface L3 gateway with standby annotation on eth1
        await client.cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    id="mds1:Corp:gw-l3",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="gw-l3",
                    name="GW_L3",
                    type="CpmiGatewayPlain",
                    asset_id="mds1:Corp:GW_L3",
                    raw_data={"policy": {"access-policy-name": "Corp_Pkg"}},
                ),
                Asset(
                    id="mds1:Corp:gw-aci",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="gw-aci",
                    name="GW_ACI_OneArm",
                    type="CpmiGatewayPlain",
                    asset_id="mds1:Corp:GW_ACI_OneArm",
                    raw_data={"policy": {"access-policy-name": "ACI_Pkg"}},
                ),
            ],
        )
        await client.cache.replace_domain_topology(
            "mds1",
            "Corp",
            [
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-l3",
                    gateway_name="GW_L3",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    anti_spoofing_mode="prevent",
                    source_type="interface_specific",
                    cidr_or_range="10.10.1.0/24",
                    ip_first_int=168427776,
                    ip_last_int=168428031,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-l3",
                    gateway_name="GW_L3",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth1",
                    topology_zone="internal",
                    anti_spoofing_mode="prevent",
                    source_type="bgp_route",
                    cidr_or_range="172.16.20.0/24",
                    ip_first_int=2886734848,
                    ip_last_int=2886735103,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-aci",
                    gateway_name="GW_ACI_OneArm",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="external",
                    source_type="external_interface",
                    cidr_or_range="0.0.0.0/0",
                    ip_first_int=0,
                    ip_last_int=0xFFFFFFFF,
                    prefix_len=0,
                ),
            ],
        )
        await client.upsert_topology_annotations(
            [
                TopologyAnnotation(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-l3",
                    gateway_name="GW_L3",
                    cidr_or_range="172.16.20.0/24",
                    disposition="standby_dynamic",
                )
            ]
        )
        # Seed ACI_Pkg rulebase targeting GW_ACI_OneArm so policy_inferred discovers it
        await client.cache.replace_domain_objects(
            "mds1",
            "Corp",
            [
                CPObject(
                    uid="n-s",
                    name="N_Src",
                    type="network",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    subnet4="10.10.1.0",
                    mask_length4=24,
                ),
                CPObject(
                    uid="n-d",
                    name="N_Dst",
                    type="network",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    subnet4="172.16.20.0",
                    mask_length4=24,
                ),
            ],
            types=["network"],
        )
        from arodonata.core.models.rulebase import AccessRuleEntry

        await client.cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(
                mgmt_name="mds1",
                domain_name="Corp",
                package_layers=[
                    RulebasePackageLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_uid="p-aci",
                        package_name="ACI_Pkg",
                        rulebase_type="access",
                        layer_uid="l-aci",
                        layer_name="ACI_Net",
                        position=1,
                    ),
                ],
                layers=[
                    RulebaseLayerEntry(
                        mgmt_name="mds1", domain_name="Corp", uid="l-aci", name="ACI_Net", rulebase_type="access"
                    )
                ],
                access_rules=[
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        layer_uid="l-aci",
                        layer_name="ACI_Net",
                        uid="r-aci",
                        name="Permit_EPG",
                        position=1,
                        enabled=True,
                        action="Accept",
                        source=["N_Src"],
                        destination=["N_Dst"],
                        service=["Any"],
                        install_on=["GW_ACI_OneArm"],
                    ),
                ],
            )
        )
        for sc in ("assets", "topology", "rulebase"):
            await client.cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    scope=sc,
                    item_type="*",
                    last_session_uid="pub-mcp-1",
                    status="ok",
                )
            )

        mcp = create_mcp_server(client, auth_mode="host")
        res = _parse_json(
            await mcp.call_tool(
                "locate_gateways",
                {
                    "sources": ["10.10.1.5"],
                    "destinations": ["172.16.20.10"],
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "include_policy_inferred": True,
                    "include_standby": True,
                    "cache_mode": "cache",
                },
            )
        )
        assert res["include_policy_inferred"] is True
        by_name = {c["gateway_name"]: c for c in res["gateways"]}
        assert "GW_L3" in by_name
        assert by_name["GW_L3"]["is_standby_path"] is True
        assert any(f["code"] == "admin_standby_dynamic" for f in by_name["GW_L3"]["confidence_factors"])
        assert "GW_ACI_OneArm" in by_name
        assert any(fl["match_type"] == "policy_inferred" for fl in by_name["GW_ACI_OneArm"]["matched_flows"])


@pytest.mark.spec("SCN-MCP-011-1")
async def test_mcp_server_registers_all_four_workflow_prompt_templates() -> None:
    """SCN-MCP-011-1: MCP server registers all 4 workflow prompts with parameter interpolation."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=_McpTopoFakeApi()) as client:
        mcp = create_mcp_server(client, auth_mode="host")
        prompts = await mcp.list_prompts()
        names = {p.name for p in prompts}
        assert names == {
            "audit_access_rulebase",
            "investigate_ip_exposure",
            "summarize_recent_changes",
            "lookup_api_command",
        }

        p1 = await mcp.get_prompt("audit_access_rulebase", {"domain": "Corp", "package": "Corp_Pkg"})
        assert "Corp_Pkg" in str(p1.messages[0].content)
        p2 = await mcp.get_prompt("investigate_ip_exposure", {"ip_or_subnet": "10.20.30.0/24", "domain": "Corp"})
        assert "10.20.30.0/24" in str(p2.messages[0].content)
        p3 = await mcp.get_prompt("summarize_recent_changes", {"domain": "Corp", "from_date": "2026-10-20"})
        assert "2026-10-20" in str(p3.messages[0].content)
        p4 = await mcp.get_prompt("lookup_api_command", {"goal": "add a network host"})
        assert "add a network host" in str(p4.messages[0].content)


# ==============================================================================
# Gateway Topology Scenarios
# ==============================================================================


@pytest.mark.spec("SCN-TOPO-012-2")
async def test_find_affected_gateways_resolves_single_installed_policy_via_installation_targets() -> None:
    """SCN-TOPO-012-2: Falls back to `PolicyPackageInfo.installation_targets` when `access-policy-name` is absent."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=_McpTopoFakeApi()) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        # Asset omits raw_data["policy"]["access-policy-name"]
        await client.cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    id="mds1:Corp:gw-fb",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="gw-fb",
                    name="GW_Fallback",
                    type="CpmiGatewayPlain",
                )
            ],
        )
        await client.cache.replace_domain_topology(
            "mds1",
            "Corp",
            [
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-fb",
                    gateway_name="GW_Fallback",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    source_type="interface_connected",
                    cidr_or_range="10.1.0.0/24",
                    ip_first_int=167837696,
                    ip_last_int=167837951,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-fb",
                    gateway_name="GW_Fallback",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth1",
                    topology_zone="internal",
                    source_type="interface_connected",
                    cidr_or_range="10.2.0.0/24",
                    ip_first_int=167903232,
                    ip_last_int=167903487,
                    prefix_len=24,
                ),
            ],
        )
        await client.cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(
                mgmt_name="mds1",
                domain_name="Corp",
                package_layers=[
                    RulebasePackageLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_uid="pkg-inst",
                        package_name="Installed_Pkg",
                        rulebase_type="access",
                        layer_uid="l-inst",
                        layer_name="Installed_Layer",
                        position=1,
                        raw_data={"installation-targets": [{"name": "GW_Fallback", "uid": "gw-fb"}]},
                    )
                ],
                layers=[
                    RulebaseLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        uid="l-inst",
                        name="Installed_Layer",
                        rulebase_type="access",
                    )
                ],
            )
        )
        cands = await client.find_affected_gateways(
            ["10.1.0.10"], ["10.2.0.20"], mgmt_name="mds1", domain="Corp", cache_mode="cache"
        )
        assert len(cands) == 1
        assert cands[0].installed_access_policy == "Installed_Pkg"
        assert cands[0].policy_packages == ["Installed_Pkg"]
        assert cands[0].access_layers == ["Installed_Layer"]


@pytest.mark.spec("SCN-TOPO-013-1")
async def test_delta_confidence_clamping_conflict_penalty_and_standby_dynamic_factor() -> None:
    """SCN-TOPO-013-1: Validates upper clamp 1.0, conflict penalty + trust_static=False recovery, and `admin_standby_dynamic`."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=_McpTopoFakeApi()) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        # Case (a): Prevent topology + matching live route on eth0 and eth1 -> clamped to 1.0
        # Case (b): Live route on eth0 (10.50.0.0/24) vs static topology on eth2 (10.50.0.0/24)
        # Case (c): Standby annotation on eth1 (10.60.0.0/24)
        await client.cache.replace_domain_topology(
            "mds1",
            "Corp",
            [
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-a",
                    gateway_name="GW_A",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    anti_spoofing_mode="prevent",
                    source_type="interface_specific",
                    cidr_or_range="10.10.0.0/24",
                    ip_first_int=168427520,
                    ip_last_int=168427775,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-a",
                    gateway_name="GW_A",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    source_type="connected_route",
                    cidr_or_range="10.10.0.0/24",
                    ip_first_int=168427520,
                    ip_last_int=168427775,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-a",
                    gateway_name="GW_A",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth1",
                    topology_zone="internal",
                    anti_spoofing_mode="prevent",
                    source_type="interface_specific",
                    cidr_or_range="10.20.0.0/24",
                    ip_first_int=169082880,
                    ip_last_int=169083135,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-a",
                    gateway_name="GW_A",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth1",
                    topology_zone="internal",
                    source_type="connected_route",
                    cidr_or_range="10.20.0.0/24",
                    ip_first_int=169082880,
                    ip_last_int=169083135,
                    prefix_len=24,
                ),
            ],
        )
        await client.upsert_topology_annotations(
            [
                TopologyAnnotation(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-a",
                    gateway_name="GW_A",
                    cidr_or_range="10.20.0.0/24",
                    disposition="standby_dynamic",
                ),
            ]
        )
        cands = await client.find_affected_gateways(
            ["10.10.0.5"], ["10.20.0.5"], mgmt_name="mds1", domain="Corp", include_standby=True, cache_mode="cache"
        )
        assert len(cands) == 1
        assert cands[0].confidence <= 1.0
        assert cands[0].is_standby_path is True
        assert any(f.code == "admin_standby_dynamic" for f in cands[0].confidence_factors)

        # Without standby annotation, matching route + prevent topology clamps cleanly to 1.0
        await client.delete_topology_annotations(mgmt_name="mds1", domain="Corp", gateway_uid="gw-a")
        cands_clean = await client.find_affected_gateways(
            ["10.10.0.5"], ["10.20.0.5"], mgmt_name="mds1", domain="Corp", cache_mode="cache"
        )
        assert cands_clean[0].confidence == 1.0


@pytest.mark.spec("SCN-TOPO-016-1")
async def test_reconciliation_detects_drift_and_suppresses_stale_with_standby_annotation() -> None:
    """SCN-TOPO-016-1: `reconcile_gateway_topology` detects drift and suppresses `stale_in_topology` under `standby_dynamic`."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=_McpTopoFakeApi()) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        await client.cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    id="mds1:Corp:cl-1",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="cl-1",
                    name="Cluster_A",
                    type="CpmiGatewayCluster",
                    member_uids=["m1", "m2"],
                    interfaces=[
                        {
                            "name": "eth1",
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": "N_Static",
                            },
                        }
                    ],
                ),
                Asset(
                    id="mds1:Corp:m1",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="m1",
                    name="member-1",
                    type="CpmiClusterMember",
                    parent_uid="cl-1",
                ),
                Asset(
                    id="mds1:Corp:m2",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="m2",
                    name="member-2",
                    type="CpmiClusterMember",
                    parent_uid="cl-1",
                ),
            ],
        )
        await client.cache.replace_domain_topology(
            "mds1",
            "Corp",
            [
                # Cluster static 10.60.0.0/24 on eth1 (absent in live routes -> stale) & 10.70.0.0/24 on eth2 (live on eth1 -> mismatch)
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="cl-1",
                    gateway_name="Cluster_A",
                    gateway_type="CpmiGatewayCluster",
                    interface_name="eth1",
                    topology_zone="internal",
                    source_type="interface_specific",
                    cidr_or_range="10.60.0.0/24",
                    ip_first_int=171704320,
                    ip_last_int=171704575,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="cl-1",
                    gateway_name="Cluster_A",
                    gateway_type="CpmiGatewayCluster",
                    interface_name="eth2",
                    topology_zone="internal",
                    source_type="interface_specific",
                    cidr_or_range="10.70.0.0/24",
                    ip_first_int=172359680,
                    ip_last_int=172359935,
                    prefix_len=24,
                ),
                # Cluster live routes (with cluster member drift marker `;drift:1/2` on 10.80.0.0/24)
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="cl-1",
                    gateway_name="Cluster_A",
                    gateway_type="CpmiGatewayCluster",
                    interface_name="eth1",
                    topology_zone="internal",
                    source_type="bgp_route",
                    source_ref="cl-1:eth1;members:member-1,member-2",
                    cidr_or_range="10.70.0.0/24",
                    ip_first_int=172359680,
                    ip_last_int=172359935,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="cl-1",
                    gateway_name="Cluster_A",
                    gateway_type="CpmiGatewayCluster",
                    interface_name="eth1",
                    topology_zone="internal",
                    source_type="bgp_route",
                    source_ref="cl-1:eth1;members:member-1;drift:1/2",
                    cidr_or_range="10.80.0.0/24",
                    ip_first_int=173015040,
                    ip_last_int=173015295,
                    prefix_len=24,
                ),
            ],
        )

        rep1 = await client.reconcile_gateway_topology(
            mgmt_name="mds1", domain="Corp", collect_routes=False, cache_mode="cache"
        )
        types1 = {(d.discrepancy_type, d.cidr_or_range) for d in rep1.discrepancies}
        assert ("stale_in_topology", "10.60.0.0/24") in types1
        assert ("interface_mismatch", "10.70.0.0/24") in types1
        assert ("missing_in_topology", "10.80.0.0/24") in types1
        assert ("cluster_member_drift", "10.80.0.0/24") in types1

        # Annotate 10.60.0.0/24 as standby_dynamic -> stale_in_topology is suppressed (severity="info", suppressed_by_annotation=True)
        await client.upsert_topology_annotations(
            [
                TopologyAnnotation(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="cl-1",
                    gateway_name="Cluster_A",
                    cidr_or_range="10.60.0.0/24",
                    disposition="standby_dynamic",
                )
            ]
        )
        rep2 = await client.reconcile_gateway_topology(
            mgmt_name="mds1", domain="Corp", collect_routes=False, cache_mode="cache"
        )
        assert any(
            d.discrepancy_type == "stale_in_topology"
            and d.cidr_or_range == "10.60.0.0/24"
            and d.suppressed_by_annotation is True
            and d.severity == "info"
            for d in rep2.discrepancies
        )


@pytest.mark.spec("SCN-TOPO-019-1")
async def test_summarize_gateway_interfaces_and_get_gateway_topology_policy_enrichment() -> None:
    """SCN-TOPO-019-1: `summarize_gateway_interfaces` groups by interface and `get_gateway_topology` enriches policy metadata."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k1")
    async with ArodonataClient(settings, api=_McpTopoFakeApi()) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp")])
        await client.cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    id="mds1:Corp:gw-enr",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="gw-enr",
                    name="GW_Enriched",
                    type="CpmiGatewayPlain",
                    raw_data={"policy": {"access-policy-name": "Enriched_Pkg"}},
                )
            ],
        )
        await client.cache.replace_domain_topology(
            "mds1",
            "Corp",
            [
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-enr",
                    gateway_name="GW_Enriched",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    anti_spoofing_mode="prevent",
                    source_type="interface_connected",
                    cidr_or_range="10.1.0.0/24",
                    ip_first_int=167837696,
                    ip_last_int=167837951,
                    prefix_len=24,
                ),
                GatewayTopologyEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    gateway_uid="gw-enr",
                    gateway_name="GW_Enriched",
                    gateway_type="CpmiGatewayPlain",
                    interface_name="eth0",
                    topology_zone="internal",
                    source_type="bgp_route",
                    cidr_or_range="10.1.1.0/24",
                    ip_first_int=167837952,
                    ip_last_int=167838207,
                    prefix_len=24,
                ),
            ],
        )
        entries = await client.get_gateway_topology("mds1", "Corp", cache_mode="cache")
        assert len(entries) == 2
        assert all(e.installed_access_policy == "Enriched_Pkg" for e in entries)
        assert all(e.policy_packages == ["Enriched_Pkg"] for e in entries)

        summaries = client.topology_service.summarize_gateway_interfaces(entries)
        assert len(summaries) == 1
        s0 = summaries[0]
        assert s0.interface_name == "eth0"
        assert s0.topology_zone == "internal"
        assert s0.anti_spoofing_mode == "prevent"
        assert s0.source_types == ["interface_connected", "bgp_route"]
        assert s0.cidrs_and_ranges == ["10.1.0.0/24", "10.1.1.0/24"]
