"""MCP gateway topology matching tools (`locate_gateways`)."""

from __future__ import annotations

from collections.abc import Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.models.common import CacheMode
from arodonata.core.primitives import normalize_str_sequence
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.errors import (
    json_tool_result,
    mcp_tool_guard,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.mcp.quota import MCPToolQuotaManager
from arodonata.mcp.tools._common import (
    _compute_cache_age,
    _enforce_live_quota_if_sync_required,
    _is_live_cache_mode,
    _normalize_cache_mode,
)


def register_topology_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    _mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register `locate_gateways`."""

    @server.tool(
        name="locate_gateways",
        description=(
            "Locate candidate policy-enforcing Check Point gateways (simple gateways, clusters, and VSX Virtual "
            "Systems), domains, policy packages, and access layers affected by traffic between sources and "
            "destinations (IPv4 addresses, CIDRs, ranges, or object/group names) where source and destination "
            "reside behind distinct gateway interfaces or match explicit installed policy rules (one-arm / "
            "incomplete topology), including confidence scores, standby indicators, and topology warnings."
        ),
    )
    @mcp_tool_guard("locate_gateways", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def locate_gateways(
        sources: list[str] | str,
        destinations: list[str] | str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        min_confidence: float = 0.0,
        include_standby: bool = True,
        include_policy_inferred: bool = True,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        eff_domain = (
            await validate_domain_or_fail(client, eff_mgmt, domain)
            if eff_mgmt and domain
            else (domain.strip() if domain and domain.strip() else None)
        )
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        eff_mode: CacheMode = "force" if is_live else mode
        await _enforce_live_quota_if_sync_required(client, eff_mgmt, eff_domain, "topology", eff_mode)
        candidates = await client.find_affected_gateways(
            sources=sources,
            destinations=destinations,
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            min_confidence=min_confidence,
            include_standby=include_standby,
            include_policy_inferred=include_policy_inferred,
            cache_mode=eff_mode,
        )
        target_mgmt = eff_mgmt or (client.settings.mgmt_names[0] if client.settings.mgmt_names else "default")
        age = None if is_live else await _compute_cache_age(client, target_mgmt, eff_domain, "topology", "*")
        serialized = [c.model_dump(mode="json") for c in candidates]
        topology_warnings: list[str] = []
        for c in candidates:
            for w in c.warnings:
                entry_warn = f"[{c.gateway_name}] {w}"
                if entry_warn not in topology_warnings:
                    topology_warnings.append(entry_warn)
        src_list = normalize_str_sequence(sources)
        dst_list = normalize_str_sequence(destinations)
        return json_tool_result(
            {
                "from": 1 if serialized else 0,
                "to": len(serialized),
                "total": len(serialized),
                "source": "live" if is_live else "cache",
                "cache_age_seconds": age,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "sources": src_list,
                "destinations": dst_list,
                "min_confidence": min_confidence,
                "include_standby": include_standby,
                "include_policy_inferred": include_policy_inferred,
                "topology_warnings": topology_warnings,
                "gateways": serialized,
            }
        )
