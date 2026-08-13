"""Integration tests for login throttle detection and recovery.

CP management servers throttle rapid successive login attempts with
THROTTLE_ERROR_CODE ("err_too_many_requests").  The library must detect
this, back off, and eventually succeed — or surface a clear error.

Run with: ./pytest.sh int-fast tests/integration/fast/test_throttling.py -v
"""

from __future__ import annotations

import asyncio

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.config.constants import THROTTLE_ERROR_CODE


async def test_rapid_logout_login_cycles_handled(apikey_client):
    """10 rapid logout→login cycles complete without permanent auth failure.

    Each cycle:
      1. logout() to discard the current SID
      2. api_call() to force a fresh login

    If the server throttles (err_too_many_requests), the retry logic must
    back off and eventually succeed.  We allow up to 10 cycles; the test
    passes if all 10 complete without AuthenticationError or deadlock.
    """
    client, mgmt_name = apikey_client

    MAX_CYCLES = 10
    for i in range(MAX_CYCLES):
        await client.logout(mgmt_name)
        result = await asyncio.wait_for(
            client.api_call(mgmt_name, "show-api-versions"),
            timeout=120,
        )
        assert result.success, f"Cycle {i + 1}/{MAX_CYCLES}: api_call failed after logout: {result.message}"


async def test_throttle_error_code_is_retried_not_fatal(db_engine):
    """When the server returns THROTTLE_ERROR_CODE, the client retries instead
    of surfacing an AuthenticationError.

    Strategy: capture a real SID before patching, then make the mock fully
    self-contained — call 1 returns a throttle, call 2 returns the captured SID
    directly.  This avoids calling the real transport on retry, which would fail
    with another throttle if the server is under load from preceding tests.
    """
    import os
    from unittest.mock import patch

    mgmt_ip = os.environ.get("API_MGMT")
    api_key = os.environ.get("APIKEY")
    if not mgmt_ip or not api_key:
        pytest.skip("API_MGMT or APIKEY not set")

    settings = ArodonataSettings(
        mgmt_names=mgmt_ip,
        mgmt_servers=mgmt_ip,
        api_keys=api_key,
        login_max_retries=3,
        login_retry_backoff=1,
    )

    throttle_count = 0

    async with ArodonataClient(engine=db_engine, settings=settings) as client:
        if client._login_coordinator:
            client._login_coordinator._session_cleaner = None

        # Capture a valid SID while the server is not throttled.  The mock will
        # return this SID on the retry so no real transport call is needed.
        await client.api_call(mgmt_ip, "show-api-versions")
        sid_record = await client.cache.get_sid(mgmt_ip, "")
        assert sid_record is not None, "Pre-warm must produce a cached SID"
        captured_sid = sid_record.sid

        async def throttling_login(*args, **kwargs):
            nonlocal throttle_count
            throttle_count += 1
            if throttle_count == 1:
                return {
                    "success": False,
                    "code": THROTTLE_ERROR_CODE,
                    "message": "Too many login requests",
                }
            # Retry: return the captured SID — no real network call needed
            return {"success": True, "sid": captured_sid, "uid": None}

        with patch.object(client._mgmt._transport, "login_with_apikey", side_effect=throttling_login):
            # Force a fresh login by clearing the cache
            await client.cache.delete_sid(mgmt_ip, "")

            result = await asyncio.wait_for(
                client.api_call(mgmt_ip, "show-api-versions"),
                timeout=60,
            )

    assert throttle_count == 2, f"Expected throttle on call 1 and success on call 2, got {throttle_count} calls"
    assert result.success, f"api_call must succeed after throttle retry: {result.message}"
