"""Integration tests for authentication — API key and credential modes.

All tests hit the real CP server. No CP state is mutated.
Run with: ./pytest.sh int-fast tests/integration/fast/test_auth.py
"""

import asyncio
import os

import pytest

from arodonata import ArodonataClient, ArodonataSettings, AuthenticationError


async def _assert_login_works(client_fixture):
    client, mgmt_name = client_fixture
    result = await client.api_call(mgmt_name, "show-api-versions")
    assert result.success, f"Expected success, got: {result.message}"
    assert result.data is not None


async def test_apikey_login_succeeds(apikey_client):
    """API-key auth produces a valid SID and server responds."""
    await _assert_login_works(apikey_client)


async def test_credential_admin_login_succeeds(admin_client):
    """Credential auth with 'admin' produces a valid SID."""
    await _assert_login_works(admin_client)


async def test_credential_antonr_login_succeeds(antonr_client):
    """Credential auth with 'AntonR' produces a valid SID."""
    await _assert_login_works(antonr_client)


async def test_credential_eng1_login_succeeds(eng1_client):
    await _assert_login_works(eng1_client)


async def test_credential_eng2_login_succeeds(eng2_client):
    await _assert_login_works(eng2_client)


async def test_credential_eng3_login_succeeds(eng3_client):
    await _assert_login_works(eng3_client)


async def test_credential_eng4_login_succeeds(eng4_client):
    await _assert_login_works(eng4_client)


async def test_invalid_apikey_rejected():
    """A wrong API key raises AuthenticationError and does not hang.

    Uses an isolated in-memory engine so no cached SID from other tests masks
    the error. StaticPool ensures all async operations share the same
    in-memory SQLite connection.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    mgmt_ip = os.environ["API_MGMT"]
    settings = ArodonataSettings(
        mgmt_names=mgmt_ip,
        mgmt_servers=mgmt_ip,
        api_keys="definitely-not-a-valid-key-0000",
        login_max_retries=1,
        login_retry_backoff=1,
    )
    fresh_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        with pytest.raises(AuthenticationError):
            async with ArodonataClient(engine=fresh_engine, settings=settings) as client:
                await asyncio.wait_for(
                    client.api_call(mgmt_ip, "show-api-versions"),
                    timeout=30,
                )
    finally:
        await fresh_engine.dispose()


async def test_invalid_password_rejected():
    """A wrong password raises AuthenticationError without infinite retry."""
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    mgmt_ip = os.environ["API_MGMT"]
    fresh_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        with pytest.raises(AuthenticationError):
            async with ArodonataClient(
                engine=fresh_engine,
                username="admin",
                password="definitely-wrong-password-0000",
                mgmt_ip=mgmt_ip,
            ) as client:
                client._settings = client._settings.model_copy(
                    update={"login_max_retries": 1, "login_retry_backoff": 1}
                )
                await asyncio.wait_for(
                    client.api_call(mgmt_ip, "show-api-versions"),
                    timeout=30,
                )
    finally:
        await fresh_engine.dispose()


async def test_session_is_cached_after_login(apikey_client):
    """The second api_call reuses the same cached SID (no second login)."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    sid_record_1 = await client.cache.get_sid(mgmt_name, "")
    assert sid_record_1 is not None
    sid1 = sid_record_1.sid

    await client.api_call(mgmt_name, "show-api-versions")
    sid_record_2 = await client.cache.get_sid(mgmt_name, "")
    assert sid_record_2 is not None
    sid2 = sid_record_2.sid

    assert sid1 == sid2, "Expected cache hit: SID should not change between calls"


async def test_logout_clears_cache(apikey_client):
    """After logout(), next api_call triggers a fresh login with a new SID."""
    client, mgmt_name = apikey_client

    await client.api_call(mgmt_name, "show-api-versions")
    sid_before = (await client.cache.get_sid(mgmt_name, "")).sid

    success = await client.logout(mgmt_name)
    assert success, "logout() should return True"

    assert await client.cache.get_sid(mgmt_name, "") is None

    await client.api_call(mgmt_name, "show-api-versions")
    sid_after_record = await client.cache.get_sid(mgmt_name, "")
    assert sid_after_record is not None
    assert sid_after_record.sid != sid_before, "Expected a new SID after logout + re-login"
