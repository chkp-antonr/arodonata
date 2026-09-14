"""Unit tests for LoginCoordinator retry/backoff and max-sessions cleanup paths.

Retry timing is neutralized by patching ``asyncio.sleep``; no real waits.
Transport/APIClient seam is mocked; offline only.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from arodonata.asdk.login_coordinator import LOGIN_THROTTLE_MAX_WAITS, LoginCoordinator
from arodonata.asdk.session_cleaner import CleanupResult, SessionCleaner
from arodonata.config import LOGIN_THROTTLE_WINDOW_SECONDS
from arodonata.core.exceptions import AuthenticationError, ServerUnreachableError, ThrottlingError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(*, auth_mode="api_key", username=None, password=None, max_retries=3, backoff=1):
    settings = MagicMock()
    settings.login_max_retries = max_retries
    settings.login_retry_backoff = backoff
    settings.session_expire_seconds = 3600
    settings.session_timeout = 600
    settings.login_timeout = 120
    settings.login_throttle_window = LOGIN_THROTTLE_WINDOW_SECONDS
    settings.auth_mode = auth_mode
    settings.username = username
    settings.password = password
    return settings


def _make_rate_limiter():
    rl = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=None)
    cm.__aexit__ = AsyncMock(return_value=False)
    rl.acquire = MagicMock(return_value=cm)
    return rl


def _make_coordinator(
    *, settings=None, transport=None, cache=None, session_cleaner=None, registry=None, rate_limiter=None
):
    return LoginCoordinator(
        registry=registry or MagicMock(),
        transport=transport or AsyncMock(),
        rate_limiter=rate_limiter or _make_rate_limiter(),
        cache=cache or AsyncMock(),
        settings=settings or _make_settings(),
        session_cleaner=session_cleaner,
    )


# ---------------------------------------------------------------------------
# _retry_with_backoff
# ---------------------------------------------------------------------------


async def test_retry_stops_immediately_for_server_connection_error():
    """The server did not answer: a second attempt at the same address is pointless.

    The retry loop hands off to `_acquire_new_sid`, which re-resolves the domain's
    active server and tries there instead -- see the ServerUnreachableError tests
    below. Previously this burned a second attempt (and, for a timeout, all eight)
    against an address nobody was listening on.
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=6))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise AuthenticationError(
            "Login failed: Unable to connect to server. Please make sure that all "
            "processes of the server are up and running."
        )

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ServerUnreachableError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 1
    sleep.assert_not_awaited()


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError(61, "Connection refused"),
        ConnectionResetError(54, "Connection reset by peer"),
        OSError(65, "No route to host"),
    ],
)
async def test_retry_stops_immediately_when_the_socket_was_refused(error):
    """A refused or unroutable socket is conclusive: nothing is listening there."""
    coord = _make_coordinator(settings=_make_settings(max_retries=8))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise error

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(ServerUnreachableError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 1


async def test_a_single_timeout_is_retried_at_the_same_address():
    """A slow server is not an absent one.

    A timeout is weaker evidence than a refused socket: the server may simply be
    busy -- which is exactly what happens when a bucket of concurrent tests leans
    on one management server. So a timeout keeps its place in the normal retry
    budget; the address is only treated as suspect once that budget is spent
    (test_timeouts_use_the_whole_retry_budget_before_giving_up).
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=8))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("Login timed out after 60s")
        return ("sid-1", "uid-1")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login")

    assert result == ("sid-1", "uid-1")
    assert attempts == 2


async def test_timeouts_use_the_whole_retry_budget_before_giving_up():
    """Only after the last retry is a timeout worth treating as a wrong address.

    Cutting this short is what turned three green integration buckets red on
    2026-09-13: slow-but-alive domain servers were written off after two attempts.
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=4))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise TimeoutError("Login timed out after 120s")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(ServerUnreachableError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 4


async def test_a_slow_server_that_answers_on_a_later_attempt_succeeds():
    """The case the aggressive version broke: slow is not dead."""
    coord = _make_coordinator(settings=_make_settings(max_retries=8))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            raise TimeoutError("Login timed out after 120s")
        return ("sid-1", "uid-1")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login")

    assert result == ("sid-1", "uid-1")
    assert attempts == 4


async def test_a_non_timeout_failure_after_timeouts_is_raised_as_itself():
    """Only an all-timeouts sequence hands over for re-resolution."""
    coord = _make_coordinator(settings=_make_settings(max_retries=3))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("Login timed out after 120s")
        raise AuthenticationError("Login failed: Invalid API key")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(AuthenticationError) as excinfo:
            await coord._retry_with_backoff(op, "Login")

    assert not isinstance(excinfo.value, ServerUnreachableError)
    assert attempts == 3


async def test_retry_keeps_retrying_a_transient_refusal_from_a_live_server():
    """Check Point returns this for a window after every revert-to-revision.

    The server answered, so the address is right and the condition clears on its
    own within seconds -- this MUST keep retrying, or every revert in the
    integration suite breaks at the login that follows it.
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=5))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise AuthenticationError("Login failed: Unable to connect to the Server. Database revision is in progress.")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(AuthenticationError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 5


async def test_retry_continues_full_max_for_generic_error():
    coord = _make_coordinator(settings=_make_settings(max_retries=3))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise AuthenticationError("Login failed: Invalid API key")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(AuthenticationError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 3


async def test_retry_no_retry_on_auth_to_server_failed():
    coord = _make_coordinator(settings=_make_settings(max_retries=5))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise Exception("Authentication to server failed")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(Exception, match="Authentication to server failed"):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 1


async def test_retry_no_retry_on_type_error():
    coord = _make_coordinator(settings=_make_settings(max_retries=5))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise TypeError("bad call")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(TypeError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == 1


async def test_retry_success_returns_immediately():
    coord = _make_coordinator()
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        return ("sid", "uid")

    result = await coord._retry_with_backoff(op, "Login")
    assert result == ("sid", "uid")
    assert attempts == 1


async def test_retry_returns_none_when_all_attempts_return_none():
    coord = _make_coordinator(settings=_make_settings(max_retries=2))

    async def op():
        return None

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login")
    assert result is None


async def test_retry_explicit_backoff_and_max_retries_args():
    coord = _make_coordinator()
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise ValueError("transient")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ValueError):
            await coord._retry_with_backoff(op, "Login", max_retries=4, backoff=2)

    assert attempts == 4
    assert sleep.await_count == 3  # sleeps between attempts, not after last


async def test_retry_backoff_capped_at_the_throttle_window():
    coord = _make_coordinator()

    async def op():
        raise ValueError("x")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ValueError):
            await coord._retry_with_backoff(op, "Login", max_retries=3, backoff=100)

    for call in sleep.await_args_list:
        assert call.args[0] <= LOGIN_THROTTLE_WINDOW_SECONDS


# ---------------------------------------------------------------------------
# Throttling: Check Point rate-limits logins per (user, server IP) per minute
# ---------------------------------------------------------------------------


async def test_throttling_waits_the_whole_window_instead_of_the_ramp():
    """The ramp never cleared a lockout: every one of its sleeps is shorter than it.

    Check Point rate-limits logins per user per server IP over a one-minute
    window (the allowance inside it is server-side configuration), and a rejected
    attempt re-arms that window -- so N short sleeps land back inside it N times.
    Only a single wait longer than the window gets us out.
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=3, backoff=5))

    async def op():
        raise ThrottlingError("Login throttled: err_too_many_requests")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ThrottlingError):
            await coord._retry_with_backoff(op, "Login")

    assert sleep.await_args_list, "a throttled login must wait before retrying"
    for call in sleep.await_args_list:
        assert call.args[0] >= LOGIN_THROTTLE_WINDOW_SECONDS


async def test_throttling_gives_up_after_a_few_windows_rather_than_holding_a_slot():
    """The retry sequence holds a rate-limiter slot throughout.

    Waiting out the full 8 attempts at 70 s each would pin one of three slots for
    ~9 minutes and outlive the login lock's TTL. If three full windows have not
    cleared it, the problem is systemic, not transient.
    """
    coord = _make_coordinator(settings=_make_settings(max_retries=8, backoff=5))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise ThrottlingError("Login throttled: err_too_many_requests")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ThrottlingError):
            await coord._retry_with_backoff(op, "Login")

    assert attempts == LOGIN_THROTTLE_MAX_WAITS + 1
    assert len(sleep.await_args_list) == LOGIN_THROTTLE_MAX_WAITS


async def test_the_throttle_wait_honours_the_configured_window():
    """A caller that knows no real lockout exists must not be made to wait one out.

    The mocked-throttle integration test is exactly that case: its retry is served
    from a captured SID and never reaches the server, so sitting through the full
    70 s window bought nothing and blew the test's own budget.
    """
    settings = _make_settings(max_retries=2)
    settings.login_throttle_window = 3
    coord = _make_coordinator(settings=settings)

    async def op():
        raise ThrottlingError("Login throttled: err_too_many_requests")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ThrottlingError):
            await coord._retry_with_backoff(op, "Login")

    assert sleep.await_args_list
    for call in sleep.await_args_list:
        assert 3 <= call.args[0] < LOGIN_THROTTLE_WINDOW_SECONDS


async def test_the_throttle_window_falls_back_to_the_constant_when_unset():
    """Settings objects without the field (older configs, mocks) still behave."""
    settings = _make_settings(max_retries=2)
    del settings.login_throttle_window
    coord = _make_coordinator(settings=settings)

    async def op():
        raise ThrottlingError("Login throttled: err_too_many_requests")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ThrottlingError):
            await coord._retry_with_backoff(op, "Login")

    assert sleep.await_args_list[0].args[0] >= LOGIN_THROTTLE_WINDOW_SECONDS


async def test_a_throttle_that_clears_lets_the_login_through():
    coord = _make_coordinator(settings=_make_settings(max_retries=8, backoff=5))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ThrottlingError("Login throttled: err_too_many_requests")
        return ("sid-1", "uid-1")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login")

    assert result == ("sid-1", "uid-1")
    assert attempts == 2


# ---------------------------------------------------------------------------
# _login_operation_for
# ---------------------------------------------------------------------------


async def test_login_operation_cache_hit_skips_api():
    cache = AsyncMock()
    cache.get_sid.return_value = MagicMock(sid="cached", uid="u")
    coord = _make_coordinator(cache=cache)
    coord._execute_login_request = AsyncMock()

    result = await coord._login_operation_for("m", "", "ip", "key", False, None, None, None)

    assert result == ("cached", "u")
    coord._execute_login_request.assert_not_called()


async def test_login_operation_force_skips_cache():
    cache = AsyncMock()
    coord = _make_coordinator(cache=cache)
    coord._execute_login_request = AsyncMock(return_value={"success": True, "sid": "fresh", "data": {"uid": "u"}})

    result = await coord._login_operation_for("m", "", "ip", "key", True, None, None, None)

    assert result == ("fresh", "u")
    cache.get_sid.assert_not_called()


async def test_login_operation_cache_miss_calls_api_with_session_timeout():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    coord = _make_coordinator(cache=cache, settings=_make_settings())
    coord._settings.session_timeout = 777
    coord._execute_login_request = AsyncMock(return_value={"success": True, "sid": "fresh", "data": {}})

    await coord._login_operation_for("m", "", "ip", "key", False, None, None, None)

    assert coord._execute_login_request.await_args.kwargs["session_timeout"] == 777


# ---------------------------------------------------------------------------
# _try_login_once
# ---------------------------------------------------------------------------


async def test_try_login_once_success():
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(return_value=("sid", "uid"))

    sid, uid = await coord._try_login_once("m", "", "ip", "key", False, None, None, None)
    assert (sid, uid) == ("sid", "uid")


async def test_try_login_once_none_result_raises_auth_error():
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(return_value=None)

    with pytest.raises(AuthenticationError, match="No session ID returned"):
        await coord._try_login_once("m", "", "ip", "key", False, None, None, None)


async def test_try_login_once_auth_error_passthrough():
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(side_effect=AuthenticationError("bad creds"))

    with pytest.raises(AuthenticationError, match="bad creds"):
        await coord._try_login_once("m", "", "ip", "key", False, None, None, None)


async def test_try_login_once_wraps_other_exception_as_auth_error():
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(side_effect=ValueError("weird"))

    with pytest.raises(AuthenticationError, match="Login failed after"):
        await coord._try_login_once("m", "", "ip", "key", False, None, None, None)


async def test_try_login_once_acquires_rate_limiter_once():
    rl = _make_rate_limiter()
    coord = LoginCoordinator(
        registry=MagicMock(),
        transport=AsyncMock(),
        rate_limiter=rl,
        cache=AsyncMock(),
        settings=_make_settings(),
    )
    coord._retry_with_backoff = AsyncMock(return_value=("sid", "uid"))

    await coord._try_login_once("m", "", "10.0.0.1", "key", False, None, None, None)

    rl.acquire.assert_called_once_with("10.0.0.1")


# ---------------------------------------------------------------------------
# _perform_login (cache hit + retry integration)
# ---------------------------------------------------------------------------


async def test_perform_login_cache_hit_skips_api():
    cache = AsyncMock()
    cache.get_sid.return_value = MagicMock(sid="cached-sid", uid="cached-uid")
    coord = _make_coordinator(cache=cache)
    coord._execute_login_request = AsyncMock()

    sid, uid = await coord._perform_login("m", "", "10.0.0.1", "key", force_relogin=False)

    assert (sid, uid) == ("cached-sid", "cached-uid")
    coord._execute_login_request.assert_not_called()


async def test_perform_login_retries_transient_then_succeeds():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    coord = _make_coordinator(cache=cache)

    attempts = 0

    async def fake_login(*a, **k):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return {"success": False, "sid": None, "data": {}, "message": "t", "code": "generic_err"}
        return {"success": True, "sid": "sid-final", "data": {"uid": "u"}}

    coord._execute_login_request = AsyncMock(side_effect=fake_login)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        sid, uid = await coord._perform_login("m", "", "10.0.0.1", "key")

    assert sid == "sid-final"
    assert attempts == 3


# ---------------------------------------------------------------------------
# Unreachable server -> re-resolve the domain IP and relogin (_acquire_new_sid)
# ---------------------------------------------------------------------------


def _registry_with_server(server_ip="10.0.0.1", port=443):
    registry = MagicMock()
    config = MagicMock()
    config.server_ip = server_ip
    config.port = port
    config.api_key = SecretStr("api-key-1234567890")
    registry.get_server.return_value = config
    return registry


def _coord_for_relogin(cache=None, registry=None):
    cache = cache or AsyncMock()
    cache.get_sid.return_value = None
    return _make_coordinator(cache=cache, registry=registry or _registry_with_server())


async def test_acquire_new_sid_re_resolves_the_domain_ip_and_retries_there():
    """A domain server that never answered may simply have moved.

    The cached `active_ip` is the whole reason this can go stale, and a hang
    carries no response code -- so `FAILOVER_ERROR_CODES` never fires and, before
    this, we retried the dead address eight times without ever asking
    `show-domains` where the domain actually lives now.
    """
    cache = AsyncMock()
    cache.get_sid.return_value = None
    coord = _coord_for_relogin(cache=cache)
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.9")
    coord._perform_login = AsyncMock(
        side_effect=[ServerUnreachableError("no answer", server_ip="10.0.0.1"), ("sid-new", "uid-1")]
    )

    entry = datetime.now(UTC).replace(tzinfo=None)
    sid, ip = await coord._acquire_new_sid("mgmt1", "Domain4", False, entry, "10.0.0.1", None, None)

    assert (sid, ip) == ("sid-new", "10.0.0.9")
    coord._prefetch_domain_server_ip.assert_awaited_once_with("mgmt1", "Domain4", force=True)
    cache.delete_sid.assert_awaited_once()
    # The second attempt went to the freshly resolved address, not the dead one.
    assert coord._perform_login.await_args_list[1].args[2] == "10.0.0.9"
    # ... and the SID is cached against the address that actually answered.
    assert cache.set_sid.await_args.args[3] == "10.0.0.9"


async def test_acquire_new_sid_fails_fast_when_the_re_resolved_ip_is_unchanged():
    """Nothing moved and nobody is answering: stop, do not keep knocking."""
    coord = _coord_for_relogin()
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.1")
    coord._perform_login = AsyncMock(side_effect=ServerUnreachableError("no answer", server_ip="10.0.0.1"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    with pytest.raises(AuthenticationError):
        await coord._acquire_new_sid("mgmt1", "Domain4", False, entry, "10.0.0.1", None, None)

    assert coord._perform_login.await_count == 1


async def test_acquire_new_sid_does_not_re_resolve_for_the_system_domain():
    """The system domain has no per-domain server to re-resolve -- that IS the server."""
    coord = _coord_for_relogin()
    coord._prefetch_domain_server_ip = AsyncMock()
    coord._perform_login = AsyncMock(side_effect=ServerUnreachableError("no answer", server_ip="10.0.0.1"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    with pytest.raises(AuthenticationError):
        await coord._acquire_new_sid("mgmt1", "", False, entry, "10.0.0.1", None, None)

    coord._prefetch_domain_server_ip.assert_not_awaited()
    assert coord._perform_login.await_count == 1


async def test_unreachable_login_still_surfaces_as_authentication_error():
    """Backward compatibility: callers catch AuthenticationError on login failure."""
    coord = _coord_for_relogin()
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.1")
    coord._perform_login = AsyncMock(side_effect=ServerUnreachableError("no answer", server_ip="10.0.0.1"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    with pytest.raises(AuthenticationError) as excinfo:
        await coord._acquire_new_sid("mgmt1", "Domain4", False, entry, "10.0.0.1", None, None)

    assert "10.0.0.1" in str(excinfo.value)


async def test_a_second_unreachable_at_the_new_ip_is_not_retried_again():
    """One re-resolution, not a loop: two dead addresses end the attempt."""
    coord = _coord_for_relogin()
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.9")
    coord._perform_login = AsyncMock(side_effect=ServerUnreachableError("no answer", server_ip="x"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    with pytest.raises(AuthenticationError):
        await coord._acquire_new_sid("mgmt1", "Domain4", False, entry, "10.0.0.1", None, None)

    assert coord._perform_login.await_count == 2
    coord._prefetch_domain_server_ip.assert_awaited_once()


async def test_try_login_once_passes_server_unreachable_through_unwrapped():
    """`_acquire_new_sid` needs the type to decide on re-resolution."""
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(side_effect=ServerUnreachableError("no answer", server_ip="10.0.0.1"))

    with pytest.raises(ServerUnreachableError):
        await coord._try_login_once("m", "d", "10.0.0.1", "key", False, None, None, None)


# ---------------------------------------------------------------------------
# create_dedicated_session
# ---------------------------------------------------------------------------


async def test_create_dedicated_session_retries_transient_then_succeeds():
    """create_dedicated_session (used by write-intensive workflows, e.g. CPCRUD) is a
    SEPARATE login path from login()/_perform_login -- it must retry on a transient
    failure (e.g. server-side throttling: "Too many requests in a given amount of
    time") the same way, not surface it as an immediate hard failure after a single
    attempt."""
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry, settings=_make_settings(max_retries=5))

    attempts = 0

    async def fake_login(*a, **k):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return {"success": False, "message": "Too many requests in a given amount of time", "code": "generic_err"}
        return {"success": True, "sid": "ded-sid", "data": {"uid": "u"}}

    coord._execute_login_request = AsyncMock(side_effect=fake_login)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        sid, ip = await coord.create_dedicated_session("mgmt1", "")

    assert (sid, ip) == ("ded-sid", "10.0.0.1")
    assert attempts == 3


async def test_create_dedicated_session_persistent_failure_raises_after_retries():
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry, settings=_make_settings(max_retries=3))
    transport_login = AsyncMock(return_value={"success": False, "message": "still throttled"})
    coord._execute_login_request = transport_login

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(AuthenticationError, match="still throttled"):
            await coord.create_dedicated_session("mgmt1", "")

    assert transport_login.await_count == 3


async def test_create_dedicated_session_holds_rate_limiter_for_entire_retry_sequence():
    """Matches _try_login_once's pattern: the rate limiter is acquired ONCE for the
    whole retry sequence, not re-acquired per attempt."""
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    rate_limiter = _make_rate_limiter()
    coord = _make_coordinator(registry=registry, rate_limiter=rate_limiter, settings=_make_settings(max_retries=4))

    attempts = 0

    async def fake_login(*a, **k):
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            return {"success": False, "message": "throttled"}
        return {"success": True, "sid": "ded-sid", "data": {}}

    coord._execute_login_request = AsyncMock(side_effect=fake_login)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await coord.create_dedicated_session("mgmt1", "")

    assert attempts == 2
    rate_limiter.acquire.assert_called_once()


# ---------------------------------------------------------------------------
# _cleanup_for_max_sessions
# ---------------------------------------------------------------------------


async def test_cleanup_no_session_cleaner_returns_early():
    coord = _make_coordinator(session_cleaner=None)
    # transport should never be touched
    await coord._cleanup_for_max_sessions("m", "", "10.0.0.1", "key", None)


async def test_cleanup_gets_temp_sid_runs_cleanup_logs_out():
    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.return_value = CleanupResult(discarded=2)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)

    await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)

    cleaner.cleanup_stale_sessions.assert_awaited_once_with(
        mgmt_name="mgmt1", domain="", system_sid="tmp", server_ip="10.0.0.1", port=None
    )
    transport.logout.assert_awaited_once_with("10.0.0.1", "tmp", port=None)


async def test_cleanup_logs_out_even_if_cleanup_raises():
    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.side_effect = RuntimeError("CP error")
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)

    await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)

    transport.logout.assert_awaited_once_with("10.0.0.1", "tmp", port=None)


async def test_cleanup_skips_if_temp_login_fails():
    cleaner = AsyncMock(spec=SessionCleaner)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": False, "sid": None, "message": "x"}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)

    await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)

    cleaner.cleanup_stale_sessions.assert_not_called()


async def test_cleanup_logout_failure_swallowed():
    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.return_value = CleanupResult(discarded=0)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.side_effect = Exception("logout fail")
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)

    # Must not raise
    await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)


async def test_cleanup_uses_credentials_in_credential_mode():
    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.return_value = CleanupResult(discarded=1)
    secret = MagicMock()
    secret.get_secret_value.return_value = "pw"
    transport = AsyncMock()
    transport.login_with_credentials.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(
        settings=_make_settings(auth_mode="credential", username="svc", password=secret),
        transport=transport,
        session_cleaner=cleaner,
    )

    await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "ignored", None)

    transport.login_with_credentials.assert_awaited_once_with(
        server_ip="10.0.0.1",
        username="svc",
        password="pw",
        domain=None,
        port=None,
        session_name="MMP-cleanup",
        session_description="Temporary session for stale session cleanup",
    )
    transport.login_with_apikey.assert_not_called()


# ---------------------------------------------------------------------------
# _login_with_cleanup_retry (max-sessions detection + one-shot retry)
# ---------------------------------------------------------------------------


async def test_max_sessions_error_triggers_cleanup_and_retry():
    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.return_value = CleanupResult(discarded=1)
    cache = AsyncMock()
    cache.get_sid.return_value = None
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(
        cache=cache,
        transport=transport,
        session_cleaner=cleaner,
        settings=_make_settings(max_retries=1),
    )

    calls = 0

    async def fake_login(*a, **k):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {
                "success": False,
                "sid": None,
                "data": {},
                "message": "You have reached the maximum number of active sessions",
                "code": "generic_err",
            }
        return {"success": True, "sid": "sid-after-cleanup", "data": {"uid": "u"}}

    coord._execute_login_request = AsyncMock(side_effect=fake_login)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        sid, _uid = await coord._perform_login("mgmt1", "", "10.0.0.1", "key")

    assert sid == "sid-after-cleanup"
    cleaner.cleanup_stale_sessions.assert_awaited_once()


async def test_non_max_sessions_auth_error_not_retried_with_cleanup():
    cleaner = AsyncMock(spec=SessionCleaner)
    coord = _make_coordinator(session_cleaner=cleaner)
    coord._try_login_once = AsyncMock(side_effect=AuthenticationError("Login failed: bad key"))

    with pytest.raises(AuthenticationError, match="bad key"):
        await coord._login_with_cleanup_retry("m", "", "ip", "key", False, None, None, None)

    cleaner.cleanup_stale_sessions.assert_not_called()


async def test_max_sessions_without_cleaner_raises():
    coord = _make_coordinator(session_cleaner=None)
    coord._try_login_once = AsyncMock(side_effect=AuthenticationError("maximum number of active sessions"))

    with pytest.raises(AuthenticationError, match="maximum number of active sessions"):
        await coord._login_with_cleanup_retry("m", "", "ip", "key", False, None, None, None)


# ---------------------------------------------------------------------------
# run_startup_cleanup
# ---------------------------------------------------------------------------


async def test_run_startup_cleanup_calls_each_server():
    from arodonata.asdk.server_registry import ServerConfig

    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.return_value = CleanupResult(discarded=1)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)
    coord._cache._db = MagicMock()
    coord._cache._db.initialize = AsyncMock()
    coord._registry.get_all_servers.return_value = {
        "mgmt-a": ServerConfig(name="mgmt-a", server_ip="10.0.0.1", api_key=SecretStr("a")),
        "mgmt-b": ServerConfig(name="mgmt-b", server_ip="10.0.0.2", api_key=SecretStr("b"), port=4434),
    }

    await coord.run_startup_cleanup()

    assert cleaner.cleanup_stale_sessions.await_count == 2


async def test_run_startup_cleanup_no_cleaner_does_nothing():
    coord = _make_coordinator(session_cleaner=None)
    coord._registry.get_all_servers = MagicMock()

    await coord.run_startup_cleanup()

    coord._registry.get_all_servers.assert_not_called()


async def test_run_startup_cleanup_no_servers_returns():
    cleaner = AsyncMock(spec=SessionCleaner)
    coord = _make_coordinator(session_cleaner=cleaner)
    coord._cache._db = MagicMock()
    coord._cache._db.initialize = AsyncMock()
    coord._registry.get_all_servers.return_value = {}

    await coord.run_startup_cleanup()

    cleaner.cleanup_stale_sessions.assert_not_called()


async def test_run_startup_cleanup_tolerates_per_server_failure():
    from arodonata.asdk.server_registry import ServerConfig

    cleaner = AsyncMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions.side_effect = RuntimeError("network error")
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    transport.logout.return_value = {"success": True}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner)
    coord._cache._db = MagicMock()
    coord._cache._db.initialize = AsyncMock()
    coord._registry.get_all_servers.return_value = {
        "mgmt-a": ServerConfig(name="mgmt-a", server_ip="10.0.0.1", api_key=SecretStr("a")),
    }

    # Must not raise
    await coord.run_startup_cleanup()
