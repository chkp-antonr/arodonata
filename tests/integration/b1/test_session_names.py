"""Integration tests for session naming and identity on the live server.

Verifies that write sessions created via the policy helpers carry the
{username}-{timestamp}-{description} name onto the CP server, that
descriptions are sanitized, and that the local SID cache maps uid<->sid
consistently with what the server reports.

Sessions created here publish nothing and are discarded in-line, so the
tier stays free of cp_mutates.
"""

from __future__ import annotations

import re

from arodonata.helpers import create_session, discard_session
from arodonata.helpers._context import UserContext

_SESSION_NAME_RE = re.compile(r"^(?P<user>.+)-\d{8}-\d{6}-(?P<desc>.*)$")


async def _server_session_named(client, mgmt_name: str, session_id: str) -> dict:
    """Find the server-side session whose name matches session_id."""
    result = await client.api_call(
        mgmt_name,
        "show-sessions",
        payload={"details-level": "full", "limit": 200},
    )
    assert result.success, f"show-sessions failed: {result.message}"
    for s in (result.data or {}).get("objects", []):
        if s.get("name") == session_id:
            return s
    return {}


async def test_session_name_visible_on_server(admin_client):
    """create_session() produces a server-visible session named
    {username}-{timestamp}-{description}."""
    client, mgmt_name = admin_client
    ctx = UserContext(username="admin", source="test")

    session_id = await create_session(client, mgmt_name, "", ctx, description="fasttier naming")
    try:
        m = _SESSION_NAME_RE.match(session_id)
        assert m, f"Session id {session_id!r} does not match the expected format"
        assert m.group("user") == "admin"
        assert m.group("desc") == "fasttier_naming"  # space -> underscore

        server_session = await _server_session_named(client, mgmt_name, session_id)
        assert server_session, f"Session {session_id!r} not visible in show-sessions"
    finally:
        await discard_session(client, mgmt_name, "", session_id, ctx)


async def test_session_description_sanitized_live(admin_client):
    """Spaces and dashes in the description are sanitized to underscores."""
    client, mgmt_name = admin_client
    ctx = UserContext(username="admin", source="test")

    session_id = await create_session(client, mgmt_name, "", ctx, description="my test-run 42")
    try:
        assert session_id.endswith("my_test_run_42"), session_id
    finally:
        await discard_session(client, mgmt_name, "", session_id, ctx)


async def test_uid_sid_lookup_roundtrip(apikey_client):
    """The cached SID row maps uid<->sid consistently with show-session."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    record = await client.cache.get_sid(mgmt_name, "")
    assert record is not None and record.sid

    result = await client.api_call(mgmt_name, "show-session")
    assert result.success, result.message
    server_uid = (result.data or {}).get("uid", "")
    assert server_uid, "show-session must report the session uid"

    if record.uid:
        assert record.uid == server_uid, f"Cached uid {record.uid!r} must match server uid {server_uid!r}"
        by_uid = await client.cache.get_by_uid(server_uid)
        if by_uid is not None:
            assert by_uid.sid == record.sid
