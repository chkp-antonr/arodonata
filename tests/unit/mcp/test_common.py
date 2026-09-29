from __future__ import annotations

import json

import pytest

from arodonata.mcp.common import (
    ToolFailure,
    add_guarded_tool,
    dump_json,
    ensure_success,
    list_envelope,
    resolve_mgmt_name,
    to_api_payload,
    truncate_json,
)

from .fake_client import FakeArodonataClient


def test_resolve_single_server_defaults():
    assert resolve_mgmt_name(FakeArodonataClient(["only"]), None) == "only"


def test_resolve_multiple_requires_name():
    with pytest.raises(ToolFailure, match="mgmt1, mgmt2"):
        resolve_mgmt_name(FakeArodonataClient(["mgmt1", "mgmt2"]), None)


def test_resolve_unknown_lists_configured():
    with pytest.raises(ToolFailure, match="unknown mgmt_name 'x'.*mgmt1"):
        resolve_mgmt_name(FakeArodonataClient(["mgmt1"]), "x")


def test_ensure_success_raises_with_code_and_message():
    from arodonata.api.schemas import ApiCallResult, ApiQueryResult

    with pytest.raises(ToolFailure, match="generic_err_object_not_found: Requested object not found"):
        ensure_success(
            ApiCallResult(success=False, code="generic_err_object_not_found", message="Requested object not found"),
            "show-host",
        )
    ensure_success(ApiQueryResult(success=True, data=[], objects=[]), "show-hosts")


def test_to_api_payload_kebab_cases_and_drops_none():
    out = to_api_payload(
        {
            "details_level": "full",
            "show_membership": None,
            "filter_settings": {"search_mode": "packet"},
            "order": [{"ASC": "name"}],
        }
    )
    assert out == {"details-level": "full", "filter-settings": {"search-mode": "packet"}, "order": [{"ASC": "name"}]}


def test_list_envelope_slices_and_annotates():
    env = list_envelope([1, 2, 3, 4, 5], offset=1, limit=2, total=5, source="cache", cache_age_seconds=90)
    assert env == {"objects": [2, 3], "from": 2, "to": 3, "total": 5, "source": "cache", "cache_age_seconds": 90}


def test_list_envelope_limit_zero_means_all():
    env = list_envelope([1, 2, 3], offset=0, limit=0, total=3, source="live", key="rulebase")
    assert env["rulebase"] == [1, 2, 3] and env["to"] == 3 and env["cache_age_seconds"] is None


def test_truncate_json_appends_hint():
    text = dump_json({"objects": list(range(1000))})
    out = truncate_json(text, 200, offset=0, returned=1000, total=1000)
    assert len(out) < 400 and "truncated" in out and "offset" in out


async def test_add_guarded_tool_redacts_unexpected_exceptions():
    from arodonata.mcp._sdk import MCPServer

    from .helpers import call_tool, text

    async def boom() -> dict:
        raise RuntimeError("secret payload 10.0.0.1")

    async def fine() -> dict:
        return {"ok": True}

    server = MCPServer("t")
    add_guarded_tool(server, boom, name="boom", description="d")
    add_guarded_tool(server, fine, name="fine")
    res = await call_tool(server, "boom")
    assert res.is_error is True and text(res) == "internal error: RuntimeError" and "10.0.0.1" not in text(res)
    ok = await call_tool(server, "fine")
    assert ok.structured_content is None and json.loads(text(ok)) == {"ok": True}


async def test_add_guarded_tool_passes_tool_failure_through():
    from arodonata.mcp._sdk import MCPServer

    from .helpers import call_tool, text

    async def fail() -> dict:
        raise ToolFailure("mgmt_name is required")

    server = MCPServer("t")
    add_guarded_tool(server, fail, name="fail")
    assert text(await call_tool(server, "fail")) == "mgmt_name is required"


def test_dump_json_handles_datetime_and_secret():
    from datetime import UTC, datetime

    from pydantic import SecretStr

    assert json.loads(dump_json({"t": datetime(2026, 1, 1, tzinfo=UTC), "s": SecretStr("x")})) == {
        "t": "2026-01-01T00:00:00+00:00",
        "s": "**********",
    }


async def test_guarded_tool_logs_caller_once_per_call_without_arguments(caplog):
    from arodonata.mcp._sdk import MCPServer

    from .helpers import call_tool

    async def echo(secret_arg: str) -> dict:
        return {"ok": True}

    server = MCPServer("t")
    add_guarded_tool(server, echo, name="echo")
    caplog.set_level("INFO", logger="arodonata.mcp.common")
    await call_tool(server, "echo", {"secret_arg": "10.9.8.7"})
    calls = [r for r in caplog.records if r.name == "arodonata.mcp.common" and "called by" in r.getMessage()]
    assert len(calls) == 1 and calls[0].levelname == "INFO"
    assert calls[0].getMessage() == "tool echo called by anonymous"
    assert "10.9.8.7" not in caplog.text


def test_log_tool_call_uses_access_token_client_id_never_the_token(caplog):
    from arodonata.mcp._sdk import AccessToken
    from arodonata.mcp.common import log_tool_call

    caplog.set_level("INFO", logger="arodonata.mcp.common")
    token = AccessToken(token="s3cr3t-token-value", client_id="MCP_TOKEN_ALICE", scopes=[])
    log_tool_call("show_hosts", token)
    log_tool_call("show_hosts", None)
    messages = [r.getMessage() for r in caplog.records if r.name == "arodonata.mcp.common"]
    assert messages == ["tool show_hosts called by MCP_TOKEN_ALICE", "tool show_hosts called by anonymous"]
    assert "s3cr3t-token-value" not in caplog.text
