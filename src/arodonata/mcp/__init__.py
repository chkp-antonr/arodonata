"""Streamable-HTTP Model Context Protocol (MCP) server package (`arodonata.mcp`)."""

from __future__ import annotations

from arodonata.mcp.cli import EXIT_CONFIG_ERROR, main, run_cli
from arodonata.mcp.config import (
    DEFAULT_ALLOWED_HOSTS,
    DEFAULT_ALLOWED_ORIGINS,
    LOOPBACK_HOSTS,
    ArodonataMCPSettings,
    MCPAuthMode,
    is_loopback_host,
)
from arodonata.mcp.errors import (
    ToolFailure,
    format_invalid_credentials_failure,
    get_known_domain_names,
    json_tool_result,
    mcp_tool_guard,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.mcp.prompts import register_mcp_prompts
from arodonata.mcp.quota import (
    MCPToolQuotaManager,
    QuotaBucket,
    QuotaDecision,
)
from arodonata.mcp.security import (
    MCPBearerAuthMiddleware,
    MCPOriginHostGuardMiddleware,
    StaticTokenVerifier,
    host_matches_allowed,
    origin_matches_allowed,
)
from arodonata.mcp.server import (
    ArodonataASGIApp,
    create_asgi_app,
    create_mcp_server,
)
from arodonata.mcp.tools import register_mcp_tools

__all__ = [
    "ArodonataASGIApp",
    "ArodonataMCPSettings",
    "DEFAULT_ALLOWED_HOSTS",
    "DEFAULT_ALLOWED_ORIGINS",
    "EXIT_CONFIG_ERROR",
    "LOOPBACK_HOSTS",
    "MCPAuthMode",
    "MCPBearerAuthMiddleware",
    "MCPOriginHostGuardMiddleware",
    "MCPToolQuotaManager",
    "QuotaBucket",
    "QuotaDecision",
    "StaticTokenVerifier",
    "ToolFailure",
    "create_asgi_app",
    "create_mcp_server",
    "format_invalid_credentials_failure",
    "get_known_domain_names",
    "host_matches_allowed",
    "is_loopback_host",
    "json_tool_result",
    "main",
    "mcp_tool_guard",
    "origin_matches_allowed",
    "register_mcp_prompts",
    "register_mcp_tools",
    "resolve_mgmt_name",
    "run_cli",
    "validate_domain_or_fail",
]
