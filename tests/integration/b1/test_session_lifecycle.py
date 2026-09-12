"""Integration tests for session lifecycle management.

Covers SID caching, reuse, logout, cache clearing, startup cleanup, and
transparent re-login when the cached SID is no longer valid on the server
(the session-expiration handling path, exercised without waiting for a
real wall-clock expiry — that belongs to the full tier).
"""

from __future__ import annotations

import asyncio
import os

import pytest

from arodonata import ArodonataClient, ArodonataSettings


async def test_sid_cached_after_login(apikey_client):
    """After the first api_call, the SID is stored in the local cache."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")

    sid_record = await client.cache.get_sid(mgmt_name, "")
    assert sid_record is not None, "SID must be cached after a successful login"
    assert sid_record.sid, "Cached SID must be non-empty"


async def test_sid_reused_on_subsequent_calls(apikey_client):
    """Consecutive calls reuse the cached SID — no second login round-trip."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    sid1 = (await client.cache.get_sid(mgmt_name, "")).sid

    await client.api_call(mgmt_name, "show-api-versions")
    sid2 = (await client.cache.get_sid(mgmt_name, "")).sid

    assert sid1 == sid2, "SID must not change between back-to-back calls"


async def test_logout_clears_local_cache(apikey_client):
    """After logout(), the SID is removed from the local cache."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    assert await client.cache.get_sid(mgmt_name, "") is not None

    success = await client.logout(mgmt_name)
    assert success, "logout() must return True on a valid session"

    assert await client.cache.get_sid(mgmt_name, "") is None, "SID must be absent from cache after logout"


async def test_new_sid_issued_after_logout_and_re_login(apikey_client):
    """After logout, the next api_call triggers a fresh login producing a new SID."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    old_sid = (await client.cache.get_sid(mgmt_name, "")).sid

    await client.logout(mgmt_name)
    await client.api_call(mgmt_name, "show-api-versions")

    new_record = await client.cache.get_sid(mgmt_name, "")
    assert new_record is not None, "SID must be re-established after re-login"
    assert new_record.sid != old_sid, "New login must produce a fresh SID"


async def test_stale_cached_sid_triggers_relogin(apikey_client):
    """A server-side-invalid cached SID is detected and replaced transparently.

    Simulates session expiration at fast-tier speed: log the session out on
    the server via the raw transport (so the client's cache still holds the
    now-dead SID), then verify the next api_call recovers by re-logging-in
    and succeeding with a fresh SID.
    """
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    record = await client.cache.get_sid(mgmt_name, "")
    assert record is not None
    dead_sid = record.sid

    # Kill the session on the server WITHOUT going through client.logout()
    # (which would clear the local cache): the cache now holds a dead SID.
    assert client._mgmt is not None
    await client._mgmt._transport.logout(record.server_ip, dead_sid)

    # The cached SID is dead on the server; the client must recover.
    result = await client.api_call(mgmt_name, "show-api-versions")
    assert result.success, f"api_call must survive a dead cached SID: {result.message}"

    new_record = await client.cache.get_sid(mgmt_name, "")
    assert new_record is not None
    assert new_record.sid != dead_sid, "Recovery must produce a fresh SID"


async def test_startup_cleanup_runs_when_enabled(db_engine):
    """Startup cleanup executes when _session_cleaner is intact.

    Creates a client WITHOUT disabling startup cleanup and verifies the cleanup
    task completes (does not raise or deadlock). The test database is fresh so
    there are no stale sessions to discard; we only verify the path runs clean.
    """
    mgmt_ip = os.environ.get("API_MGMT")
    api_key = os.environ.get("APIKEY")
    if not mgmt_ip or not api_key:
        pytest.skip("API_MGMT or APIKEY not set")

    settings = ArodonataSettings(
        mgmt_names=mgmt_ip,
        mgmt_servers=mgmt_ip,
        api_keys=api_key,
    )

    async with ArodonataClient(engine=db_engine, settings=settings) as client:
        # Give the background startup cleanup task time to complete
        await asyncio.sleep(5)
        result = await client.api_call(mgmt_ip, "show-api-versions")
        assert result.success, f"Client must work after startup cleanup: {result.message}"
        # Disable cleanup on the way out to avoid a race with db teardown
        if client._login_coordinator:
            client._login_coordinator._session_cleaner = None
