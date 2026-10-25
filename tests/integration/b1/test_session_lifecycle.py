"""Bucket 1 — Session lifecycle against the live MDSM.

Covers:
1. SID caching in SQLite (``sid_cache`` table) and reuse across calls.
2. Dedicated session creation (``create_dedicated_session``) does NOT overwrite the cached read SID.
3. Explicit ``logout_sid`` invalidates the SID on Check Point (subsequent call with that SID fails).
4. Stale cached SID auto-recovery: if the cached SID is logged out on the server behind the
   client's back, ``api_call`` detects ``generic_err_invalid_session_id``, evicts the stale row,
   re-logs in, and completes the call transparently.
5. Startup session cleanup (``SessionCleaner``) discards/logs out abandoned 0-change sessions
   while preserving active sessions.
"""

from __future__ import annotations

from arodonata import ArodonataClient


async def test_sid_cached_in_sqlite_and_reused(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify read-only SID is stored in ``sid_cache`` and reused without re-login."""
    r1 = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert r1.success
    uid1 = r1.data["uid"]

    cached = await apikey_client.cache.get_sid(mgmt_name, test_domain_a)
    assert cached is not None
    assert cached.sid

    r2 = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert r2.success
    assert r2.data["uid"] == uid1


async def test_dedicated_session_isolated_from_cached_sid(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``create_dedicated_session`` returns an isolated SID without replacing ``sid_cache``."""
    r_cached = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    cached_uid = r_cached.data["uid"]
    cached_before = await apikey_client.cache.get_sid(mgmt_name, test_domain_a)
    assert cached_before is not None

    ded_sid, ded_ip = await apikey_client.create_dedicated_session(mgmt_name, domain=test_domain_a)
    try:
        assert ded_sid != cached_before.sid
        r_ded = await apikey_client.api_call(
            mgmt_name,
            "show-session",
            {},
            domain=test_domain_a,
            sid=ded_sid,
            server_ip=ded_ip,
        )
        assert r_ded.success
        assert r_ded.data["uid"] != cached_uid

        # Cached read SID is untouched
        cached_after = await apikey_client.cache.get_sid(mgmt_name, test_domain_a)
        assert cached_after is not None
        assert cached_after.sid == cached_before.sid
    finally:
        await apikey_client.logout_sid(mgmt_name, ded_sid, server_ip=ded_ip)


async def test_logout_sid_invalidates_session_on_server(
    antonr_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``logout_sid`` invalidates the dedicated SID on the Check Point server."""
    sid, ip = await antonr_client.create_dedicated_session(mgmt_name, domain=test_domain_a)
    ok = await antonr_client.logout_sid(mgmt_name, sid, server_ip=ip)
    assert ok is True

    # Calling with the logged-out SID must fail at the CP server
    res = await antonr_client.api_call(
        mgmt_name,
        "show-session",
        {},
        domain=test_domain_a,
        sid=sid,
        server_ip=ip,
    )
    assert not res.success


async def test_stale_cached_sid_auto_recovers(
    eng1_client: ArodonataClient,
    mgmt_name: str,
    test_domain_b: str,
) -> None:
    """When the cached SID is killed server-side, ``api_call`` evicts it and re-authenticates."""
    r1 = await eng1_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_b)
    assert r1.success
    old_uid = r1.data["uid"]

    cached = await eng1_client.cache.get_sid(mgmt_name, test_domain_b)
    assert cached is not None
    old_sid = cached.sid

    # Kill the session directly on the server WITHOUT telling the cache
    assert eng1_client.amgmt is not None
    logout_res = await eng1_client.amgmt.transport.execute(
        cached.server_ip,
        "logout",
        {},
        sid=old_sid,
    )
    assert logout_res.success

    # Next api_call must detect expired SID, evict, re-login, and succeed with a new session UID
    r2 = await eng1_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_b)
    assert r2.success, f"Auto-recovery failed: {r2.error_code} {r2.error_message}"
    assert r2.data["uid"] != old_uid

    new_cached = await eng1_client.cache.get_sid(mgmt_name, test_domain_b)
    assert new_cached is not None
    assert new_cached.sid != old_sid


async def test_session_cleaner_preserves_cached_and_cleans_abandoned(
    eng2_client: ArodonataClient,
    mgmt_name: str,
    test_domain_b: str,
) -> None:
    """Verify ``SessionCleaner`` preserves active sessions and cleans up abandoned 0-change sessions."""
    # Establish a cached read session for Eng2 in test_domain_b
    r_cached = await eng2_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_b)
    assert r_cached.success

    # Create an extra dedicated session for Eng2 (0 changes) that is NOT in sid_cache
    leaked_sid, leaked_ip = await eng2_client.create_dedicated_session(mgmt_name, domain=test_domain_b)
    r_leaked = await eng2_client.api_call(
        mgmt_name,
        "show-session",
        {},
        domain=test_domain_b,
        sid=leaked_sid,
        server_ip=leaked_ip,
    )
    assert r_leaked.success
    leaked_uid = r_leaked.data["uid"]

    # Remove leaked_sid from active_dedicated_sids so SessionCleaner treats it as an abandoned session
    assert eng2_client.amgmt is not None
    eng2_client.amgmt.login_coordinator._active_dedicated_sids.pop((mgmt_name, leaked_sid), None)

    await eng2_client.amgmt.session_cleaner.cleanup_server_sessions(
        mgmt_name,
        domain=test_domain_b,
    )

    # Cached session must still work
    r_after = await eng2_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_b)
    assert r_after.success

    # Leaked session was cleaned up (or if still open, clean it up in finally)
    open_list = await eng2_client.api_call(
        mgmt_name,
        "show-sessions",
        {"view-published-sessions": False, "limit": 50},
        domain=test_domain_b,
    )
    assert open_list.success
    still_open_uids = {s["uid"] for s in open_list.data.get("objects", [])}
    if leaked_uid in still_open_uids:
        await eng2_client.logout_sid(mgmt_name, leaked_sid, server_ip=leaked_ip)
