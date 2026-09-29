from __future__ import annotations

import json
from typing import Any

from mcp.client import Client
from mcp.types import CallToolResult

from arodonata.mcp._sdk import MCPServer
from arodonata.mcp.registry import register_arodonata_tools


def make_server(fake, **toggles) -> MCPServer:
    server = MCPServer("test")
    register_arodonata_tools(server, fake, **toggles)  # type: ignore[arg-type]
    return server


async def call_tool(server: MCPServer, name: str, args: dict[str, Any] | None = None) -> CallToolResult:
    async with Client(server) as client:
        return await client.call_tool(name, args or {})


def payload(result: CallToolResult) -> Any:
    """First text block parsed as JSON (all tools register with structured_output=False)."""
    assert result.is_error is False, result.content[0].text  # type: ignore[union-attr]
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


def text(result: CallToolResult) -> str:
    return result.content[0].text  # type: ignore[union-attr]


async def tool_names(server: MCPServer) -> set[str]:
    async with Client(server) as client:
        return {t.name for t in (await client.list_tools()).tools}


async def tool_input_schema(server: MCPServer, name: str) -> dict[str, Any]:
    """The published JSON input schema for one registered tool, keyed by tool name."""
    async with Client(server) as client:
        tools = (await client.list_tools()).tools
    matches = [t for t in tools if t.name == name]
    assert matches, f"tool '{name}' not registered"
    return matches[0].input_schema


def cache_mode_enum(schema: dict[str, Any]) -> list[str]:
    """The enum values of a schema's ``cache_mode`` property, looking through an ``anyOf`` with ``null``."""
    prop = schema["properties"]["cache_mode"]
    variants = prop.get("anyOf", [prop])
    enums = [v["enum"] for v in variants if "enum" in v]
    assert len(enums) == 1, prop
    return enums[0]
