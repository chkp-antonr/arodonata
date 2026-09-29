from __future__ import annotations

from arodonata.mcp.manifest import MANIFEST

from .fake_client import FakeArodonataClient
from .helpers import make_server, tool_names
from .reference_tool_names import EXCLUDED, REFERENCE_TOOLS, RENAMED


def test_manifest_names_unique_and_commands_are_show_or_where_used():
    names = [t.name for t in MANIFEST]
    assert len(names) == len(set(names))
    assert all(t.command.startswith("show-") or t.command == "where-used" for t in MANIFEST)


async def test_every_reference_tool_is_covered():
    registered = await tool_names(make_server(FakeArodonataClient()))
    expected = {RENAMED.get(n, n) for n in REFERENCE_TOOLS - EXCLUDED}
    missing = expected - registered
    assert missing == set()


async def test_live_compat_can_be_disabled():
    names = await tool_names(make_server(FakeArodonataClient(), live_compat=False))
    assert "show_services_tcp" not in names and "show_hosts" in names
