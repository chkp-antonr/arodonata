"""The one module allowed to import the ``mcp`` SDK.

Every other module under ``arodonata.mcp`` imports SDK names from here so the optional
dependency is guarded in exactly one place.
"""

from __future__ import annotations

from ._messages import MISSING_EXTRA_MESSAGE

try:
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.provider import AccessToken, TokenVerifier
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.server.transport_security import TransportSecuritySettings
    from mcp.types import CallToolResult, TextContent
except ModuleNotFoundError as exc:  # pragma: no cover - exercised via monkeypatched import in tests
    raise ImportError(MISSING_EXTRA_MESSAGE) from exc

__all__ = [
    "AccessToken",
    "AuthSettings",
    "CallToolResult",
    "Context",
    "MCPServer",
    "TextContent",
    "TokenVerifier",
    "ToolError",
    "TransportSecuritySettings",
    "get_access_token",
    "MISSING_EXTRA_MESSAGE",
]
