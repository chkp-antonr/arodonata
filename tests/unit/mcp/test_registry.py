from __future__ import annotations

from arodonata.mcp._sdk import MCPServer
from arodonata.mcp.registry import RegisteredTools, register_arodonata_tools

from .fake_client import FakeArodonataClient
from .helpers import tool_names


async def test_registers_native_group_and_reports_names():
    server = MCPServer("t")
    reg = register_arodonata_tools(server, FakeArodonataClient())  # type: ignore[arg-type]
    assert isinstance(reg, RegisteredTools)
    assert "arodonata_init" in reg.native and "arodonata_init" in reg.all
    assert "arodonata_init" in await tool_names(server)


async def test_tool_prefix_applies_to_every_tool():
    server = MCPServer("t")
    reg = register_arodonata_tools(server, FakeArodonataClient(), tool_prefix="cp_")  # type: ignore[arg-type]
    assert all(n.startswith("cp_") for n in reg.all)
    assert "cp_arodonata_init" in await tool_names(server)
