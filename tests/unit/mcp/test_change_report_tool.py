from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from arodonata.mcp import register_arodonata_tools
from arodonata.mcp._sdk import MCPServer
from arodonata.reports.changes import RangeScope, SessionScope
from tests.unit.mcp.fake_client import FakeArodonataClient
from tests.unit.mcp.helpers import call_tool, make_server, text, tool_input_schema, tool_names
from tests.unit.reports.sample import rule_rows, sample_report

MARKER = "full report via the library"


def scopes_of(fake: FakeArodonataClient) -> tuple[list, dict]:
    [(_, kw)] = [c for c in fake.calls if c[0] == "collect_change_report"]
    return kw["scopes"], kw


async def test_tool_registered_without_write_flag_and_prefixed():
    assert "cp_change_report" in await tool_names(make_server(FakeArodonataClient(), tool_prefix="cp_"))
    reg = register_arodonata_tools(MCPServer("t"), FakeArodonataClient(), allow_write_api=False)  # type: ignore[arg-type]
    assert "change_report" in reg.cached


async def test_tool_registered_with_live_compat_false():
    reg = register_arodonata_tools(MCPServer("t"), FakeArodonataClient(), live_compat=False)  # type: ignore[arg-type]
    assert "change_report" in reg.cached and reg.live == ()


async def test_domain_required():
    schema = await tool_input_schema(make_server(FakeArodonataClient()), "change_report")
    assert "domain" in schema["required"]
    result = await call_tool(make_server(FakeArodonataClient()), "change_report", {"session_uids": ["s1"]})
    assert result.is_error is True


async def test_session_uids_build_session_scope():
    fake = FakeArodonataClient()
    result = await call_tool(make_server(fake), "change_report", {"domain": "Domain4", "session_uids": ["s1", "s2"]})
    assert result.is_error is False
    [scope], kw = scopes_of(fake)
    assert isinstance(scope, SessionScope) and scope.session_uids == ["s1", "s2"]
    assert (scope.mgmt_name, scope.domain, scope.owned_session, kw["max_sessions"]) == ("mgmt1", "Domain4", None, 20)


async def test_range_params_build_range_scope():
    fake = FakeArodonataClient()
    await call_tool(
        make_server(fake),
        "change_report",
        {
            "domain": "Domain4",
            "from_session": "a",
            "from_date": "2026-09-28T18:30:00+03:00",
            "to_date": "2026-09-28T15:50:00Z",
        },
    )
    [scope], _ = scopes_of(fake)
    assert isinstance(scope, RangeScope) and scope.from_session == "a"
    assert scope.from_date == datetime(2026, 9, 28, 18, 30, tzinfo=timezone(timedelta(hours=3)))
    assert scope.to_date == datetime(2026, 9, 28, 15, 50, tzinfo=UTC)


async def test_naive_or_invalid_date_is_tool_failure():
    server = make_server(FakeArodonataClient())
    naive = await call_tool(server, "change_report", {"domain": "D", "from_date": "2026-09-28T18:30:00"})
    assert naive.is_error is True and "UTC offset" in text(naive)
    bad = await call_tool(server, "change_report", {"domain": "D", "from_date": "yesterday"})
    assert bad.is_error is True and "ISO 8601" in text(bad)
    reversed_ = await call_tool(
        server,
        "change_report",
        {"domain": "D", "from_date": "2026-09-28T18:30:00Z", "to_date": "2026-09-28T17:00:00Z"},
    )
    assert reversed_.is_error is True and "invalid range" in text(reversed_)


async def test_no_scope_is_tool_failure():
    result = await call_tool(make_server(FakeArodonataClient()), "change_report", {"domain": "Domain4"})
    assert result.is_error is True and "session_uids" in text(result)


async def test_max_rules_below_one_is_tool_failure():
    result = await call_tool(
        make_server(FakeArodonataClient()),
        "change_report",
        {"domain": "Domain4", "session_uids": ["s1"], "max_rules": 0},
    )
    assert result.is_error is True and "max_rules" in text(result)


async def test_returns_markdown_with_max_rules():
    report = await sample_report()
    fake = FakeArodonataClient()
    fake.responses["collect_change_report"] = report
    result = await call_tool(
        make_server(fake), "change_report", {"domain": "Domain4", "session_uids": ["pub-1"], "max_rules": 2}
    )
    body = text(result)
    assert body.startswith("# Change report\n")
    assert f"…and {rule_rows(report) - 2} more rules, {MARKER}" in body


async def test_max_result_chars_cut_at_line_with_marker():
    report = await sample_report()
    fake = FakeArodonataClient()
    fake.responses["collect_change_report"] = report
    args = {"domain": "Domain4", "session_uids": ["pub-1"]}
    full = text(await call_tool(make_server(fake), "change_report", args))
    cut = text(await call_tool(make_server(fake, max_result_chars=600), "change_report", args))
    assert len(cut) <= 600 and cut.endswith(f"…output truncated at 600 characters, {MARKER}")
    head = cut.rsplit("\n", 1)[0]
    assert full.startswith(head + "\n")


async def test_mgmt_resolved_with_resolve_mgmt_name():
    fake = FakeArodonataClient(mgmt_names=["a", "b"])
    await call_tool(make_server(fake), "change_report", {"domain": "D", "mgmt_name": "b", "session_uids": ["s"]})
    [scope], _ = scopes_of(fake)
    assert scope.mgmt_name == "b"
    unknown = await call_tool(
        make_server(fake), "change_report", {"domain": "D", "mgmt_name": "z", "session_uids": ["s"]}
    )
    assert unknown.is_error is True and "unknown mgmt_name" in text(unknown)


async def test_mgmt_required_with_several_servers():
    result = await call_tool(
        make_server(FakeArodonataClient(mgmt_names=["a", "b"])),
        "change_report",
        {"domain": "D", "session_uids": ["s"]},
    )
    assert result.is_error is True and "mgmt_name is required" in text(result)
