from __future__ import annotations

from mcp.client import Client

from arodonata.api.schemas import ApiCallResult, ApiQueryResult, SSEEvent, SSEEventType

from .fake_client import FakeArodonataClient
from .helpers import call_tool, make_server, payload, text


def _events(*items: SSEEvent) -> list[SSEEvent]:
    return list(items)


async def test_search_objects_returns_result_and_summary_and_forwards_filters():
    # Event shapes copied from the real ``search_service.search_objects`` stream: per-domain matches
    # travel inside LOG events' data (see ``_resolve_search_memberships``, search_service.py:~168),
    # and the final COMPLETE event carries no data (``message="Search complete"`` only).
    fake = FakeArodonataClient()
    fake.responses["search_objects"] = _events(
        SSEEvent(event_type=SSEEventType.START, message="Searching for 'web1' (name)"),
        SSEEvent(
            event_type=SSEEventType.LOG,
            message="mgmt1/General (1 object(s))",
            mgmt_name="mgmt1",
            data={
                "domain": "General",
                "mgmt_name": "mgmt1",
                "search_term": "web1",
                "search_type": "name",
                "objects": [{"name": "web1", "type": "host"}],
                "memberships": None,
            },
        ),
        SSEEvent(event_type=SSEEventType.WARNING, message="domain X skipped"),
        SSEEvent(event_type=SSEEventType.COMPLETE, message="Search complete", data={}),
    )
    out = payload(
        await call_tool(
            make_server(fake),
            "search_objects",
            {"search_input": "web1,10.0.0.1", "domain_names": ["General"], "refresh": "check", "max_depth": 3},
        )
    )
    assert out["results"] == [
        {
            "mgmt_name": "mgmt1",
            "domain": "General",
            "search_term": "web1",
            "search_type": "name",
            "objects": [{"name": "web1", "type": "host"}],
            "memberships": None,
        }
    ]
    assert out["summary"] == {} and out["warnings"] == ["domain X skipped"] and out["errors"] == []
    assert fake.calls[0] == (
        "search_objects",
        {
            "search_input": "web1,10.0.0.1",
            "mgmt_names": None,
            "domain_names": ["General"],
            "refresh": "check",
            "max_depth": 3,
        },
    )


async def test_refresh_objects_collects_errors_and_summary():
    fake = FakeArodonataClient()
    fake.responses["refresh_objects"] = _events(
        SSEEvent(event_type=SSEEventType.LOG, message="Saved 5 hosts", data={"count": 5}),
        SSEEvent(event_type=SSEEventType.ERROR, message="domain Finance failed", data={"status": "domain_failed"}),
        SSEEvent(event_type=SSEEventType.COMPLETE, data={"total_results": 40}),
    )
    out = payload(await call_tool(make_server(fake), "refresh_objects", {"mode": "incremental"}))
    assert out["summary"] == {"total_results": 40} and out["errors"] == ["domain Finance failed"]
    assert fake.calls[0][1]["mode"] == "incremental" and fake.calls[0][1]["include_global"] is False


async def test_refresh_rulebases_default_mode_force():
    fake = FakeArodonataClient()
    fake.responses["refresh_rulebases"] = _events(SSEEvent(event_type=SSEEventType.COMPLETE, data={"total_results": 3}))
    payload(await call_tool(make_server(fake), "refresh_rulebases", {}))
    assert fake.calls[0] == (
        "refresh_rulebases",
        {"mgmt_names": None, "domain_names": None, "mode": "force", "include_global": False},
    )


async def test_refresh_rulebases_forwards_include_global():
    fake = FakeArodonataClient()
    fake.responses["refresh_rulebases"] = _events(
        SSEEvent(event_type=SSEEventType.ERROR, message="access refresh failed", data={"status": "domain_failed"}),
        SSEEvent(event_type=SSEEventType.COMPLETE, data={"total_results": 0}),
    )
    out = payload(await call_tool(make_server(fake), "refresh_rulebases", {"include_global": True}))
    assert fake.calls[0][1]["include_global"] is True
    assert out["errors"] == ["access refresh failed"]


async def test_api_call_rejects_write_commands_by_default():
    res = await call_tool(
        make_server(FakeArodonataClient()),
        "api_call",
        {"command": "add-host", "payload": {"name": "x", "ip-address": "1.1.1.1"}},
    )
    assert res.is_error is True and "ARODONATA_MCP_ALLOW_WRITE_API" in text(res)


async def test_api_call_allows_write_when_enabled():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(success=True, data={"uid": "new"})
    out = payload(
        await call_tool(
            make_server(fake, allow_write_api=True), "api_call", {"command": "add-host", "payload": {"name": "x"}}
        )
    )
    assert out["data"] == {"uid": "new"} and fake.calls[0][1]["payload"] == {"name": "x"}


async def test_api_call_paginate_uses_api_query():
    fake = FakeArodonataClient()
    fake.responses["api_query"] = ApiQueryResult(
        success=True, data={"objects": [{"uid": "1"}]}, objects=[{"uid": "1"}], total=1
    )
    out = payload(
        await call_tool(
            make_server(fake), "api_call", {"command": "show-hosts", "paginate": True, "details_level": "uid"}
        )
    )
    assert out["objects"] == [{"uid": "1"}] and out["source"] == "live"
    assert fake.calls[0][0] == "api_query" and fake.calls[0][1]["details_level"] == "uid"


async def test_api_call_maps_api_error():
    fake = FakeArodonataClient()
    fake.responses["api_call"] = ApiCallResult(success=False, code="err_bad", message="boom")
    res = await call_tool(make_server(fake), "api_call", {"command": "show-host", "payload": {"name": "nope"}})
    assert res.is_error is True and text(res) == "err_bad: boom"


async def test_api_call_converts_snake_case_payload_keys_and_says_so():
    fake = FakeArodonataClient()
    await call_tool(
        make_server(fake),
        "api_call",
        {"command": "show-hosts", "payload": {"show_membership": True, "ip-only": True, "filter_settings": {"x_y": 1}}},
    )
    assert fake.calls[0][1]["payload"] == {"show-membership": True, "ip-only": True, "filter-settings": {"x-y": 1}}
    async with Client(make_server(FakeArodonataClient())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    description = tools["api_call"].description or ""
    assert "snake_case" in description and "kebab-case" in description and "must be" not in description


async def test_refresh_log_event_with_count_sends_progress_notification():
    fake = FakeArodonataClient()
    fake.responses["refresh_objects"] = _events(
        SSEEvent(event_type=SSEEventType.LOG, message="Saved 5 hosts", data={"count": 5, "total": 20}),
        SSEEvent(event_type=SSEEventType.LOG, message="no count here", data={}),
        SSEEvent(event_type=SSEEventType.COMPLETE, data={"total_results": 5}),
    )
    received: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        received.append((progress, total, message))

    async with Client(make_server(fake)) as client:
        res = await client.call_tool("refresh_objects", {}, progress_callback=on_progress)
    assert res.is_error is False
    assert received == [(5.0, 20.0, "Saved 5 hosts")]
