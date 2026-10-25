"""Unit tests for core domain events, architectural purity, and SSEEvent adapter conversion."""

from __future__ import annotations

import ast
from collections.abc import AsyncIterator
from pathlib import Path

from arodonata.adapters.sse import SSEEvent, stream_as_sse, to_sse_event
from arodonata.core import events as core_events
from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDCompletedEvent,
    DomainSyncFailedEvent,
    DomainSyncProgressEvent,
    StagedSessionEvent,
    SyncStartedEvent,
)


def test_core_events_has_no_sse_event() -> None:
    """Verify SSEEvent is absent from arodonata.core.events."""
    assert not hasattr(core_events, "SSEEvent")


def test_core_hexagonal_purity_no_adapter_imports() -> None:
    """Verify src/arodonata/core/ has zero imports from aiohttp, sqlalchemy, sqlmodel, or mcp."""
    core_dir = Path(__file__).resolve().parents[1] / "src" / "arodonata" / "core"
    forbidden_roots = {"aiohttp", "sqlalchemy", "sqlmodel", "mcp", "asyncpg", "aiosqlite", "starlette"}
    for py_file in core_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in forbidden_roots, f"{py_file} imports forbidden module {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in forbidden_roots, f"{py_file} imports from forbidden module {node.module}"


async def test_domain_events_convert_to_sse_with_sid_redaction() -> None:
    """Verify SyncProgressEvent and CPCRUDEvent convert cleanly to SSEEvent and scrub secrets."""
    ev1 = SyncStartedEvent(
        mgmt_name="mds1",
        scope="objects",
        message="Starting object sync",
    )
    ev2 = DomainSyncProgressEvent(
        mgmt_name="mds1",
        domain="CMA1",
        scope="objects",
        item_type="host",
        processed=150,
        total=300,
    )
    ev3 = DomainSyncFailedEvent(
        mgmt_name="mds1",
        domain="CMA2",
        scope="objects",
        item_type="host",
        error='Authentication failed for {"sid": "leaked_sid_token_123"}',
        details={"sid": "leaked_sid_token_123", "attempt": 1},
    )
    ev4 = StagedSessionEvent(
        mgmt_name="mds1",
        domain="CMA1",
        server_ip="10.0.0.11",
        session_uid="sess-uid-99",
        session_name="cpcrud-stage",
        sid="raw_staged_sid_value",
    )
    ev5 = CPCRUDActionEvent(
        mgmt_name="mds1",
        domain="CMA1",
        action_id="act-1",
        operation="add",
        object_type="host",
        object_name="web-01",
        outcome="created",
    )
    ev6 = CPCRUDCompletedEvent(
        mgmt_name="mds1",
        succeeded_count=1,
        failed_count=0,
        skipped_count=0,
    )

    assert "raw_staged_sid_value" not in repr(ev4)

    async def _gen() -> AsyncIterator[core_events.DomainEvent]:
        for item in (ev1, ev2, ev3, ev4, ev5, ev6):
            yield item

    sse_items: list[SSEEvent] = [sse async for sse in stream_as_sse(_gen())]
    assert len(sse_items) == 6
    assert sse_items[0].event == "sync_started"
    assert sse_items[0].id == "1"
    assert sse_items[1].data["processed"] == 150
    assert sse_items[1].data["total"] == 300

    # Verify SID is scrubbed in error and details of failed sync event
    wire_3 = sse_items[2].encode()
    assert "leaked_sid_token_123" not in wire_3
    assert REDACTED_PLACEHOLDER in wire_3

    # Verify StagedSessionEvent omits raw sid on the SSE wire
    wire_4 = to_sse_event(ev4).encode()
    assert "raw_staged_sid_value" not in wire_4
    assert "sess-uid-99" in wire_4
