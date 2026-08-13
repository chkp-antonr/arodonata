"""Integration tests for multi-user concurrent session behavior.

Uses asyncio.gather() with multiple ArodonataClient instances to simulate
concurrent access from different credential users.

Run with: ./pytest.sh int-fast tests/integration/fast/test_concurrent_admins.py
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from arodonata import ArodonataClient


async def test_three_users_login_concurrently(admin_client, eng1_client, eng2_client):
    """Three clients sharing one server can make concurrent API calls without deadlock.

    Credential clients sharing a db_engine share the same SID cache key, so logins
    are serialised internally.  We pre-warm each client sequentially to avoid lock
    contention, then fire concurrent calls to verify no timeout or deadlock occurs.
    """
    a_client, a_mgmt = admin_client
    e1_client, e1_mgmt = eng1_client
    e2_client, e2_mgmt = eng2_client

    # Pre-warm sequentially: avoids login-lock contention between the three clients
    for c, m in [(a_client, a_mgmt), (e1_client, e1_mgmt), (e2_client, e2_mgmt)]:
        r = await c.api_call(m, "show-api-versions")
        assert r.success, f"Pre-warm failed: {r.message}"

    # Concurrent calls — each client already has a cached SID, no login contention
    results = await asyncio.gather(
        a_client.api_call(a_mgmt, "show-api-versions"),
        e1_client.api_call(e1_mgmt, "show-api-versions"),
        e2_client.api_call(e2_mgmt, "show-api-versions"),
    )

    for i, result in enumerate(results):
        assert result.success, f"User {i} failed: {result.message}"


async def test_concurrent_api_calls_same_domain(admin_client, eng1_client, eng2_client, all_domains):
    """All three clients call show-hosts on the first domain concurrently without deadlock.

    Pre-warm domain SIDs sequentially first to avoid login-lock contention, then verify
    that concurrent calls to the same domain server do not timeout or deadlock.
    """
    domain_name = all_domains[0]["name"]

    a_client, a_mgmt = admin_client
    e1_client, e1_mgmt = eng1_client
    e2_client, e2_mgmt = eng2_client

    # Pre-warm domain SIDs sequentially to avoid lock contention across three clients
    for c, m in [(a_client, a_mgmt), (e1_client, e1_mgmt), (e2_client, e2_mgmt)]:
        r = await c.api_call(m, "show-api-versions", domain=domain_name)
        assert r.success, f"Pre-warm for {domain_name} failed: {r.message}"

    # Concurrent calls — SIDs cached, no login serialisation pressure
    async def call_with_timeout(c, m):
        return await asyncio.wait_for(
            c.api_call(m, "show-hosts", domain=domain_name),
            timeout=120,
        )

    results = await asyncio.gather(
        call_with_timeout(a_client, a_mgmt),
        call_with_timeout(e1_client, e1_mgmt),
        call_with_timeout(e2_client, e2_mgmt),
    )

    for i, result in enumerate(results):
        assert result.success, f"User {i} domain call failed: {result.message}"


async def test_session_identity_matches_credential_user():
    """Credential auth binds the session to the requesting user's identity.

    Uses an isolated in-memory engine (StaticPool) so no cached SID from other
    tests can mask the result.  Verifies that show-session returns 'admin' when
    logging in with admin credentials — proving the session is not anonymous or
    shared with another user.
    """
    import os

    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    mgmt_ip = os.environ["API_MGMT"]
    password = os.environ["USER_admin"]

    # StaticPool: all async operations share the same in-memory SQLite connection.
    # Without it, initialize() creates tables on connection N but lock operations
    # run on connection M (a different empty in-memory database).
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        async with ArodonataClient(engine=engine, username="admin", password=password, mgmt_ip=mgmt_ip) as client:
            if client._login_coordinator:
                client._login_coordinator._session_cleaner = None
            result = await client.api_call(mgmt_ip, "show-session")
            assert result.success, f"show-session failed: {result.message}"
            data = result.data or {}
            session_user = data.get("user-name") or data.get("uid") or ""
            await client.logout(mgmt_ip)
    finally:
        try:
            await engine.dispose()
        except Exception:
            pass

    assert "admin" in session_user.lower(), (
        f"Expected admin session but show-session returned user_name={session_user!r}"
    )


async def test_concurrent_login_deduplication(apikey_client):
    """10 tasks sharing one client all fire login simultaneously; only 1 login reaches the server."""
    client, mgmt_name = apikey_client

    login_call_count = 0
    original_login = client._mgmt._transport.login_with_apikey

    async def counting_login(*args, **kwargs):
        nonlocal login_call_count
        login_call_count += 1
        return await original_login(*args, **kwargs)

    with patch.object(client._mgmt._transport, "login_with_apikey", side_effect=counting_login):
        # Clear cached SID so all 10 tasks must compete to re-authenticate
        await client.cache.delete_sid(mgmt_name, "")

        tasks = [client.api_call(mgmt_name, "show-api-versions") for _ in range(10)]
        results = await asyncio.gather(*tasks)

    assert all(r.success for r in results), "All 10 tasks must succeed"
    assert login_call_count == 1, (
        f"Expected exactly 1 real login request (distributed lock prevents stampede), got {login_call_count}"
    )


async def test_login_to_all_domains_concurrently(apikey_client, all_domains):
    """Login to every domain simultaneously; throttle errors must be absorbed by retry.

    Domain IP cache is warmed up sequentially first so the concurrent phase only
    needs domain-specific logins (each to a different IP, no cross-IP serialisation).
    """
    client, mgmt_name = apikey_client

    # Warm up: populate domain IP cache so concurrent logins skip show-domains calls
    for d in all_domains:
        await client.api_call(mgmt_name, "show-api-versions", domain=d["name"])

    # Clear all domain SIDs so each task must perform a fresh domain login
    for d in all_domains:
        await client.cache.delete_sid(mgmt_name, d["name"])

    async def login_to_domain(domain_name: str):
        return await asyncio.wait_for(
            client.api_call(mgmt_name, "show-api-versions", domain=domain_name),
            timeout=120,
        )

    results = await asyncio.gather(
        *[login_to_domain(d["name"]) for d in all_domains],
        return_exceptions=True,
    )

    failed = [r for r in results if isinstance(r, Exception)]
    assert not failed, f"Domain login(s) failed after throttle retry: {failed}"

    succeeded = [r for r in results if not isinstance(r, Exception) and r.success]
    assert len(succeeded) == len(all_domains), f"Expected {len(all_domains)} successes, got {len(succeeded)}"


async def test_four_engineers_login_concurrently(eng1_client, eng2_client, eng3_client, eng4_client):
    """Four distinct engineer identities operate concurrently without deadlock.

    Pre-warms each client sequentially (avoids login-lock contention on the
    shared engine), then fires concurrent calls — exercising the lab's
    capacity for simultaneous distinct-admin sessions.
    """
    clients = [eng1_client, eng2_client, eng3_client, eng4_client]

    for c, m in clients:
        r = await c.api_call(m, "show-api-versions")
        assert r.success, f"Pre-warm failed: {r.message}"

    results = await asyncio.gather(*[asyncio.wait_for(c.api_call(m, "show-session"), timeout=60) for c, m in clients])

    for i, result in enumerate(results, start=1):
        assert result.success, f"eng{i} concurrent call failed: {result.message}"

    # Each session belongs to its own user — no identity bleed between clients.
    users = [(r.data or {}).get("user-name", "") for r in results]
    assert users == ["eng1", "eng2", "eng3", "eng4"], f"Concurrent sessions must keep distinct identities, got {users}"
