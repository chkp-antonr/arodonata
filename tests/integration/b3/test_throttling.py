"""Bucket 3 — Check Point login throttle detection and recovery (`err_too_many_requests`, ~70s).

Covers:
1. ``test_rapid_logout_login_cycles_handled``: 10 rapid ``logout`` -> ``api_call`` cycles
   against the live MDSM using ``apikey_client``. When the server throttles with
   ``err_too_many_requests``, ``LoginCoordinator`` waits ``login_throttle_window`` (70s)
   and automatically completes the login once the sliding window resets.
2. ``test_throttle_error_code_is_retried_not_fatal``: when the transport returns
   ``err_too_many_requests`` on the first login attempt, ``LoginCoordinator`` backs off
   and retries rather than raising ``AuthenticationError``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.core.ports import ApiCallResult

_THROTTLED_CYCLE_BUDGET_SECONDS = 300.0


async def test_rapid_logout_login_cycles_handled(
    apikey_client: ArodonataClient,
    mgmt_name: str,
) -> None:
    """Verify 10 rapid logout -> ``api_call`` cycles complete without auth failure."""
    max_cycles = 10
    for idx in range(max_cycles):
        sid_entry = await apikey_client.cache.get_sid(mgmt_name, "System Data")
        if sid_entry is not None:
            await apikey_client.logout_sid(mgmt_name, sid_entry.sid, server_ip=sid_entry.server_ip)
            await apikey_client.cache.evict_sid(mgmt_name, "System Data")
        result = await asyncio.wait_for(
            apikey_client.api_call(mgmt_name, "show-api-versions"),
            timeout=_THROTTLED_CYCLE_BUDGET_SECONDS,
        )
        assert result.success, f"Cycle {idx + 1}/{max_cycles} failed after logout: {result.error_message}"


async def test_throttle_error_code_is_retried_not_fatal(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    mgmt_ip: str,
    db_engine: AsyncEngine,
) -> None:
    """Verify ``err_too_many_requests`` on login triggers a throttle wait + retry, not a fatal error."""
    settings = ArodonataSettings(
        mgmt_name=mgmt_name,
        mgmt_ip=mgmt_ip,
        api_key=apikey_client.settings.api_keys[0],
        tls_trust=apikey_client.settings.tls_trust,
        tls_fingerprints=apikey_client.settings.tls_fingerprints,
        login_throttle_window=1.0,
        login_max_wait=30.0,
    )

    throttle_count = 0

    client = ArodonataClient(settings=settings, engine=db_engine)
    await client.initialize(run_startup_cleanup=False)
    try:
        # Warm and capture a real SID while the server is unthrottled
        warm = await client.api_call(mgmt_name, "show-api-versions")
        assert warm.success
        sid_entry = await client.cache.get_sid(mgmt_name, "System Data")
        assert sid_entry is not None
        captured_sid = sid_entry.sid

        assert client.amgmt is not None
        orig_execute = client.amgmt.transport.execute

        async def throttled_once(
            server_ip: str,
            command: str,
            payload: dict[str, object] | None = None,
            *,
            port: int = 443,
            sid: str | None = None,
            timeout: float | None = None,
        ) -> ApiCallResult:
            nonlocal throttle_count
            if command == "login":
                throttle_count += 1
                if throttle_count == 1:
                    return ApiCallResult(
                        success=False,
                        status_code=429,
                        data={"code": "err_too_many_requests", "message": "Too many login requests"},
                        error_code="err_too_many_requests",
                        error_message="Too many login requests",
                    )
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data={"sid": captured_sid, "uid": "mock-sess-uid"},
                )
            return await orig_execute(server_ip, command, payload, port=port, sid=sid, timeout=timeout)

        await client.cache.evict_sid(mgmt_name, "System Data")
        with patch.object(client.amgmt.transport, "execute", side_effect=throttled_once):
            res = await asyncio.wait_for(
                client.api_call(mgmt_name, "show-api-versions"),
                timeout=30.0,
            )
            assert res.success, f"api_call must succeed after throttle retry: {res.error_message}"
    finally:
        await client.close(logout=False)

    assert throttle_count == 2
