"""Unit tests for ``ArodonataClient.api_query`` on task-based commands (``show-changes``).

``show-changes`` answers with a task; the finished ``show-task`` response nests
the paging fields and the items under ``tasks[].task-details[]``, where the
SDK's own ``api_query`` never looks -- it returned page one and stopped (seen on
the home lab, 2026-10-01). These tests pin that ``api_query`` pages such
commands itself, through ``api_call`` so the task is awaited by arodonata.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import ApiQueryResult

from .client_test_helpers import make_client


def _session(n: int) -> dict[str, Any]:
    return {"session": {"session-uid": f"s{n}"}, "operations": {"added-objects": []}}


def _page(offset: int, limit: int, total: int) -> dict[str, Any]:
    """A finished show-task response holding sessions offset+1 .. offset+limit of `total`."""
    last = min(offset + limit, total)
    return {
        "success": True,
        "data": {
            "tasks": [
                {
                    "task-id": "t",
                    "status": "succeeded",
                    "task-details": [
                        {
                            "limit": limit,
                            "offset": offset,
                            "from": offset + 1 if last > offset else 0,
                            "to": last,
                            "total": total,
                            "changes": [_session(n) for n in range(offset + 1, last + 1)],
                        }
                    ],
                }
            ]
        },
        "message": "",
        "code": "",
    }


def _paging_mgmt(total: int) -> AsyncMock:
    """An AMgmtClient double whose api_call serves show-changes pages from `total` sessions."""
    mgmt = AsyncMock()

    async def api_call(**kwargs: Any) -> dict[str, Any]:
        payload = kwargs["payload"]
        return _page(payload["offset"], payload["limit"], total)

    mgmt.api_call.side_effect = api_call
    return mgmt


@pytest.mark.asyncio
async def test_show_changes_collects_every_page():
    mgmt = _paging_mgmt(total=5)
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes", payload={"from-session": "base", "limit": 2})

    assert isinstance(result, ApiQueryResult)
    assert result.success is True
    assert [c["session"]["session-uid"] for c in result.objects] == ["s1", "s2", "s3", "s4", "s5"]
    assert result.total == 5
    offsets = [call.kwargs["payload"]["offset"] for call in mgmt.api_call.await_args_list]
    assert offsets == [0, 2, 4]
    mgmt.api_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_show_changes_goes_through_api_call_with_caller_arguments():
    mgmt = _paging_mgmt(total=1)
    client = make_client(mgmt=mgmt)

    await client.api_query(
        "mgmt1",
        "show-changes",
        domain="Domain4",
        details_level="full",
        payload={"to-session": "s1"},
        cache_mode="refresh",
    )

    call = mgmt.api_call.await_args
    assert call.kwargs["mgmt_name"] == "mgmt1"
    assert call.kwargs["command"] == "show-changes"
    assert call.kwargs["domain"] == "Domain4"
    assert call.kwargs["details_level"] == "full"
    assert call.kwargs["cache_mode"] == "refresh"
    assert call.kwargs["payload"]["to-session"] == "s1"


@pytest.mark.asyncio
async def test_show_changes_default_page_size_is_50():
    mgmt = _paging_mgmt(total=1)
    client = make_client(mgmt=mgmt)

    await client.api_query("mgmt1", "show-changes")

    assert mgmt.api_call.await_args.kwargs["payload"]["limit"] == 50


@pytest.mark.asyncio
async def test_show_changes_page_size_is_capped_at_500():
    mgmt = _paging_mgmt(total=1)
    client = make_client(mgmt=mgmt)

    await client.api_query("mgmt1", "show-changes", payload={"limit": 5000})

    assert mgmt.api_call.await_args.kwargs["payload"]["limit"] == 500


@pytest.mark.asyncio
async def test_show_changes_starts_at_caller_offset():
    mgmt = _paging_mgmt(total=5)
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes", payload={"limit": 2, "offset": 3})

    assert [c["session"]["session-uid"] for c in result.objects] == ["s4", "s5"]


@pytest.mark.asyncio
async def test_show_changes_does_not_mutate_caller_payload():
    mgmt = _paging_mgmt(total=3)
    client = make_client(mgmt=mgmt)
    payload = {"from-session": "base", "limit": 1}

    await client.api_query("mgmt1", "show-changes", payload=payload)

    assert payload == {"from-session": "base", "limit": 1}


@pytest.mark.asyncio
async def test_show_changes_empty_result():
    mgmt = _paging_mgmt(total=0)
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes")

    assert result.success is True
    assert result.objects == []
    assert mgmt.api_call.await_count == 1


@pytest.mark.asyncio
async def test_show_changes_failed_page_fails_the_query():
    mgmt = AsyncMock()
    failure = {"success": False, "data": {}, "message": "boom", "code": "generic_server_error"}
    mgmt.api_call.side_effect = [_page(0, 1, 2), failure]
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes", payload={"limit": 1})

    assert result.success is False
    assert result.code == "generic_server_error"
    assert "boom" in result.message
    assert result.objects == []


@pytest.mark.asyncio
async def test_show_changes_page_that_does_not_advance_stops():
    """A server answer that repeats the same window must not loop forever."""
    mgmt = AsyncMock()
    stuck = _page(0, 1, 3)
    mgmt.api_call.return_value = stuck
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes", payload={"limit": 1})

    assert result.success is False
    assert mgmt.api_call.await_count == 2


@pytest.mark.asyncio
async def test_show_changes_flat_legacy_shape():
    """Older servers answer with the paging fields at the top level, no task wrapper."""
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {
        "success": True,
        "data": {"from": 1, "to": 1, "total": 1, "changes": [_session(1)]},
        "message": "",
        "code": "",
    }
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-changes")

    assert [c["session"]["session-uid"] for c in result.objects] == ["s1"]


@pytest.mark.asyncio
async def test_ordinary_query_still_uses_sdk_paging():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {"success": True, "data": {"objects": [{"name": "a"}]}}
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-hosts")

    assert result.objects == [{"name": "a"}]
    mgmt.api_call.assert_not_awaited()
