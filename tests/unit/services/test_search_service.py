"""Unit tests for SearchService: cycle detection, input parsing, grouping, and SSE streaming."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.schemas import SSEEvent, SSEEventType
from arodonata.cache.object_service import SearchType
from arodonata.services.search_service import SearchService


def _fake_obj(uid: str = "o1", mgmt: str = "m1", domain: str = "d1", name: str = "host1"):
    obj = MagicMock()
    obj.uid = uid
    obj.mgmt_name = mgmt
    obj.domain_name = domain
    obj.model_dump.return_value = {"uid": uid, "name": name, "mgmt_name": mgmt, "domain": domain}
    return obj


# ---------------------------------------------------------------------------
# Cycle detection & tree conversion
# ---------------------------------------------------------------------------


def test_convert_group_nodes_handles_direct_and_indirect_cycles():
    node_a = SimpleNamespace(uid="uid-a", name="GroupA", domain="d1", depth=1, children=[])
    node_b = SimpleNamespace(uid="uid-b", name="GroupB", domain="d1", depth=2, children=[])
    node_c = SimpleNamespace(uid="uid-c", name="GroupC", domain="d1", depth=3, children=[])

    # Circular reference: A -> B -> C -> A
    node_a.children = [node_b]
    node_b.children = [node_c]
    node_c.children = [node_a]

    svc = SearchService(object_service=MagicMock(), refresh_objects_fn=AsyncMock())
    converted = svc._convert_group_nodes([node_a])

    assert len(converted) == 1
    assert converted[0]["uid"] == "uid-a"
    assert len(converted[0]["children"]) == 1
    b_dict = converted[0]["children"][0]
    assert b_dict["uid"] == "uid-b"
    assert len(b_dict["children"]) == 1
    c_dict = b_dict["children"][0]
    assert c_dict["uid"] == "uid-c"
    # Cycle back to A is pruned
    assert c_dict["children"] == []


def test_convert_group_nodes_respects_max_depth():
    node_a = SimpleNamespace(uid="uid-a", name="GroupA", domain="d1", depth=1, children=[])
    node_b = SimpleNamespace(uid="uid-b", name="GroupB", domain="d1", depth=2, children=[])
    node_a.children = [node_b]

    svc = SearchService(object_service=MagicMock(), refresh_objects_fn=AsyncMock())
    converted = svc._convert_group_nodes([node_a], max_depth=1)

    assert len(converted) == 1
    assert converted[0]["uid"] == "uid-a"
    assert converted[0]["children"] == []


# ---------------------------------------------------------------------------
# Parsing and Grouping
# ---------------------------------------------------------------------------


def test_parse_search_input():
    svc = SearchService(object_service=MagicMock(), refresh_objects_fn=AsyncMock())
    classified, labels = svc._parse_search_input("10.0.0.1, web-srv, 192.168.1.0/24")

    assert len(classified) == 3
    assert classified[0][0] == SearchType.HOST
    assert classified[1][0] == SearchType.NAME
    assert classified[2][0] == SearchType.NETWORK
    assert "'10.0.0.1' (host)" in labels
    assert "'web-srv' (name)" in labels


def test_group_search_objects():
    svc = SearchService(object_service=MagicMock(), refresh_objects_fn=AsyncMock())
    o1 = _fake_obj("o1", mgmt="m1", domain="d1")
    o2 = _fake_obj("o2", mgmt="m1", domain="d2")
    o3 = _fake_obj("o3", mgmt="m2", domain="d1")

    grouped = svc._group_search_objects([o1, o2, o3])
    assert set(grouped.keys()) == {"m1", "m2"}
    assert set(grouped["m1"].keys()) == {"d1", "d2"}
    assert grouped["m1"]["d1"] == [o1]
    assert grouped["m1"]["d2"] == [o2]
    assert grouped["m2"]["d1"] == [o3]


# ---------------------------------------------------------------------------
# SSE search_objects streaming
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_objects_generates_sse_events():
    mock_obj_svc = MagicMock()
    fake_obj = _fake_obj("o1", mgmt="m1", domain="d1", name="host1")
    mock_obj_svc._cache.get_objects_by_name = AsyncMock(return_value=[fake_obj])
    mock_obj_svc._resolve_group_memberships = AsyncMock(return_value=[])

    svc = SearchService(object_service=mock_obj_svc, refresh_objects_fn=AsyncMock())
    events = [e async for e in svc.search_objects("host1", max_depth=0)]

    assert len(events) >= 3
    assert events[0].event_type == SSEEventType.START
    assert "Searching for 'host1' (name)" in events[0].message
    assert events[-1].event_type == SSEEventType.COMPLETE
    assert events[-1].message == "Search complete"


@pytest.mark.asyncio
async def test_search_objects_with_refresh_invokes_refresh_objects_fn():
    mock_obj_svc = MagicMock()
    mock_obj_svc._cache.get_objects_by_name = AsyncMock(return_value=[])

    async def mock_refresh(**kwargs):
        yield SSEEvent(event_type=SSEEventType.START, message="Starting refresh")
        yield SSEEvent(event_type=SSEEventType.LOG, message="Refreshing m1")
        yield SSEEvent(event_type=SSEEventType.COMPLETE, message="Refresh done")

    svc = SearchService(object_service=mock_obj_svc, refresh_objects_fn=mock_refresh)
    events = [e async for e in svc.search_objects("host1", refresh="force", max_depth=0)]

    # Sub-task START was converted to LOG, COMPLETE was filtered out
    event_messages = [e.message for e in events]
    assert "Starting refresh" in event_messages
    assert "Refreshing m1" in event_messages
    assert "Refresh done" not in event_messages
    assert events[-1].event_type == SSEEventType.COMPLETE
