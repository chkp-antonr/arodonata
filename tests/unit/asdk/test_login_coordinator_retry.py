"""Unit tests for LoginCoordinator retry/backoff and max-sessions cleanup paths.

Retry timing is neutralized by patching ``asyncio.sleep``; no real waits.
Transport/APIClient seam is mocked; offline only.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from arodonata.asdk.login_coordinator import LoginCoordinator, _login_pacing, _LoginPacing
from arodonata.asdk.login_gate import LoginGateDeadlineError
from arodonata.asdk.session_cleaner import CleanupResult, SessionCleaner
from arodonata.cache.lock_manager import LockAcquisitionError, LockOwnershipError
from arodonata.config import CREDENTIAL_REJECTION_MESSAGE, LOGIN_THROTTLE_WINDOW_SECONDS
from arodonata.core.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    ServerUnreachableError,
    ThrottlingError,
)

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
    settings.login_max_wait = 900
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


class FakeGate:
    """Stand-in for LoginGate: never sleeps, records every close and wait.

    After `give_up_after` refusals, the next wait raises LoginGateDeadlineError --
    the way the real gate does when the next window would pass the login's
    deadline. Without that, an operation that throttles forever would loop forever.
    """

    def __init__(self, give_up_after: int = 3) -> None:
        self.closed: list[str] = []
        self.waits: list[dict] = []
        self.give_up_after = give_up_after

    async def wait_open(self, mds_host, *, deadline, max_wait, keepalive=None):
        self.waits.append({"mds_host": mds_host, "deadline": deadline, "max_wait": max_wait})
        if len(self.closed) >= self.give_up_after:
            raise LoginGateDeadlineError(mds_host, waited=float(max_wait), max_wait=max_wait)
        # Faithful to the real gate: `keepalive` runs before a *sleep chunk*, so
        # only when a refusal is actually live for this host. A fake that awaited
        # it on every wait made "the lock is renewed" pass without the gate ever
        # having closed, which is the only situation the renewal exists for.
        if keepalive is not None and mds_host in self.closed:
            await keepalive()

    async def close(self, mds_host):
        self.closed.append(mds_host)


def _make_coordinator(
    *,
    settings=None,
    transport=None,
    cache=None,
    session_cleaner=None,
    registry=None,
    rate_limiter=None,
    login_gate=None,
):
    return LoginCoordinator(
        registry=registry or MagicMock(),
        transport=transport or AsyncMock(),
        rate_limiter=rate_limiter or _make_rate_limiter(),
        cache=cache or AsyncMock(),
        settings=settings or _make_settings(),
        session_cleaner=session_cleaner,
        login_gate=login_gate if login_gate is not None else FakeGate(),
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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
        result = await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
        result = await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

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
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert attempts == 1


async def test_retry_success_returns_immediately():
    coord = _make_coordinator()
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        return ("sid", "uid")

    result = await coord._retry_with_backoff(op, "Login", mds_host="mds")
    assert result == ("sid", "uid")
    assert attempts == 1


async def test_retry_returns_none_when_all_attempts_return_none():
    coord = _make_coordinator(settings=_make_settings(max_retries=2))

    async def op():
        return None

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login", mds_host="mds")
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
            await coord._retry_with_backoff(op, "Login", mds_host="mds", max_retries=4, backoff=2)

    assert attempts == 4
    assert sleep.await_count == 3  # sleeps between attempts, not after last


async def test_retry_backoff_capped_at_the_throttle_window():
    coord = _make_coordinator()

    async def op():
        raise ValueError("x")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(ValueError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds", max_retries=3, backoff=100)

    for call in sleep.await_args_list:
        assert call.args[0] <= LOGIN_THROTTLE_WINDOW_SECONDS


# ---------------------------------------------------------------------------
# Throttling: Check Point rate-limits logins per (user, server IP) per minute
# ---------------------------------------------------------------------------


async def test_a_throttle_that_clears_lets_the_login_through():
    gate = FakeGate()
    coord = _make_coordinator(settings=_make_settings(max_retries=8, backoff=5), login_gate=gate)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ThrottlingError("Login throttled: err_too_many_requests")
        return ("sid-1", "uid-1")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert result == ("sid-1", "uid-1")
    assert attempts == 2
    assert gate.closed == ["mds"]


async def test_a_throttle_closes_the_gate_and_never_sleeps_on_its_own():
    """The wait for a throttle is the gate's, sized by the row's expiry -- not a fixed 70 s.

    Check Point refuses in 0.5 s; what matters is that nobody tries again before
    the window from the *last* refusal has passed, and the gate row carries that.
    """
    gate = FakeGate(give_up_after=2)
    coord = _make_coordinator(settings=_make_settings(max_retries=3, backoff=5), login_gate=gate)

    async def op():
        raise ThrottlingError("Login throttled: err_too_many_requests")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(LoginGateDeadlineError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert gate.closed == ["mds", "mds"]
    assert len(gate.waits) == 3  # before attempt 1, attempt 2, and the one that gave up
    assert sleep.await_args_list == []


async def test_throttled_attempts_do_not_consume_the_retry_budget():
    """Pacing is not failure: a cold 21-login start at 3/min must not exhaust 8 retries."""
    gate = FakeGate(give_up_after=10)
    coord = _make_coordinator(settings=_make_settings(max_retries=2), login_gate=gate)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts <= 5:
            raise ThrottlingError("Login throttled: err_too_many_requests")
        return ("sid-1", "uid-1")

    result = await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert result == ("sid-1", "uid-1")
    assert attempts == 6
    assert len(gate.closed) == 5


async def test_a_rate_limiter_slot_timeout_is_not_retried():
    """Local contention, not a server refusal: fail in ~90 s, do not climb the ladder.

    The slot used to be taken by `_try_login_once`'s own `acquire`, outside the
    try, so a saturated server failed the login after one `rate_limit_slot_timeout`
    (90 s) with `LockAcquisitionError`. Now that the slot is taken per attempt
    inside `_execute_login_request`, an unclassified slot timeout would be a
    "refusal": one retry each, backoff sleeps, up to `login_max_retries` — fifteen
    minutes of waiting for a queue that is ours, while holding the login lock.
    """
    gate = FakeGate()
    coord = _make_coordinator(settings=_make_settings(max_retries=8), login_gate=gate)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise LockAcquisitionError("ratelimit:10.0.0.1:slot_2", 90)

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(LockAcquisitionError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert attempts == 1
    assert sleep.await_args_list == []
    assert gate.closed == []


async def test_try_login_once_passes_a_slot_timeout_through_unwrapped():
    """The exception type MMP catches for a saturated server must not change."""
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(side_effect=LockAcquisitionError("ratelimit:10.0.0.1:slot_0", 90))

    with pytest.raises(LockAcquisitionError):
        await coord._try_login_once("m", "d", "10.0.0.1", "key", False, None, None, None)


async def test_non_throttle_failures_still_use_the_ladder_and_the_budget():
    gate = FakeGate()
    coord = _make_coordinator(settings=_make_settings(max_retries=3, backoff=5), login_gate=gate)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise AuthenticationError("Login failed: Database revision is in progress")

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(AuthenticationError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert attempts == 3
    assert len(sleep.await_args_list) == 2
    assert gate.closed == []
    for call in sleep.await_args_list:
        assert 5 <= call.args[0] <= LOGIN_THROTTLE_WINDOW_SECONDS


async def test_the_lazily_built_gate_uses_the_configured_window():
    settings = _make_settings()
    settings.login_throttle_window = 3
    coord = LoginCoordinator(
        registry=MagicMock(),
        transport=AsyncMock(),
        rate_limiter=_make_rate_limiter(),
        cache=AsyncMock(),
        settings=settings,
        lock_manager=MagicMock(initialize=AsyncMock()),
    )

    gate = await coord._get_login_gate()

    assert gate._window == 3
    assert await coord._get_login_gate() is gate


async def test_the_lazily_built_gate_falls_back_to_the_constant_when_the_setting_is_absent():
    settings = _make_settings()
    del settings.login_throttle_window
    coord = LoginCoordinator(
        registry=MagicMock(),
        transport=AsyncMock(),
        rate_limiter=_make_rate_limiter(),
        cache=AsyncMock(),
        settings=settings,
        lock_manager=MagicMock(initialize=AsyncMock()),
    )

    assert (await coord._get_login_gate())._window == LOGIN_THROTTLE_WINDOW_SECONDS


def _lock_ctx(*, lock_key="login:mgmt1:dom", renew=None, age_seconds=60.0, ttl=90):
    """A LockContext stand-in old enough that a renewal is due (age > ttl * 0.5)."""
    lock = MagicMock()
    lock.lock_key = lock_key
    lock.owner_id = "owner-1"
    lock.ttl = ttl
    lock.acquired_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=age_seconds)
    lock.renew_if_needed = AsyncMock(return_value=True) if renew is None else renew
    return lock


async def test_retry_uses_the_login_pacing_deadline():
    """Inside login(), the deadline is the one login() set."""
    gate = FakeGate()
    coord = _make_coordinator(login_gate=gate)
    lock = _lock_ctx()
    # Real time, not an arbitrary sentinel: _retry_with_backoff now compares the
    # pacing deadline against asyncio.get_running_loop().time() itself (the
    # deadline-guard backstop), and that clock does not start at 0.
    deadline = asyncio.get_running_loop().time() + 12345.0

    async def op():
        return ("sid", None)

    token = _login_pacing.set(_LoginPacing(deadline=deadline, locks=(lock,)))
    try:
        await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert gate.waits[0]["deadline"] == deadline
    assert gate.waits[0]["max_wait"] == 900
    # The gate never closed, so there was no sleep to keep the lock alive through.
    lock.renew_if_needed.assert_not_awaited()


async def test_a_gate_wait_renews_every_lock_in_the_chain():
    """The nested-login case: waiting at the gate must renew the *outer* lock too.

    `login()` is re-entrant -- `_acquire_new_sid`, already inside
    `login:{mgmt}:{domain}`, reaches `_prefetch_domain_server_ip` ->
    `login(mgmt, "")`, which takes `login:{mgmt}:`. With a single-slot pacing only
    the inner lock was renewed while the inner login slept at the gate; the outer
    row lapsed after its 90 s TTL, another worker stole it, and a second
    concurrent login hit the same domain.
    """
    gate = FakeGate(give_up_after=5)
    coord = _make_coordinator(login_gate=gate)
    outer = _lock_ctx(lock_key="login:mgmt1:dom")
    inner = _lock_ctx(lock_key="login:mgmt1:")
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ThrottlingError("Login throttled: err_too_many_requests")
        return ("sid", None)

    deadline = asyncio.get_running_loop().time() + 900.0
    token = _login_pacing.set(_LoginPacing(deadline=deadline, locks=(outer, inner)))
    try:
        await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert gate.closed == ["mds"]
    outer.renew_if_needed.assert_awaited_once()
    inner.renew_if_needed.assert_awaited_once()


async def test_a_stolen_lock_aborts_the_paced_login():
    """Another owner holds our login lock: stop, do not keep logging under it.

    The lock is the only thing keeping two workers off the same domain login, so
    continuing would spend the allowance the gate exists to conserve twice over
    and end with `release_lock` operating on someone else's row.
    """
    gate = FakeGate(give_up_after=5)
    coord = _make_coordinator(login_gate=gate)
    lock = _lock_ctx(renew=AsyncMock(side_effect=LockOwnershipError("login:mgmt1:dom", "owner-1")))
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        raise ThrottlingError("Login throttled: err_too_many_requests")

    deadline = asyncio.get_running_loop().time() + 900.0
    token = _login_pacing.set(_LoginPacing(deadline=deadline, locks=(lock,)))
    try:
        with pytest.raises(LockOwnershipError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert attempts == 1  # the refused attempt, then no further ones


async def test_a_lock_that_lapsed_while_we_waited_aborts_the_paced_login(caplog):
    """`renew_if_needed` returning False *when a renewal was due* means the row is gone."""
    gate = FakeGate(give_up_after=5)
    coord = _make_coordinator(login_gate=gate)
    lock = _lock_ctx(renew=AsyncMock(return_value=False), age_seconds=60.0)

    async def op():
        raise ThrottlingError("Login throttled: err_too_many_requests")

    deadline = asyncio.get_running_loop().time() + 900.0
    token = _login_pacing.set(_LoginPacing(deadline=deadline, locks=(lock,)))
    try:
        with pytest.raises(LockOwnershipError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert any("is gone" in r.message for r in caplog.records)


async def test_a_renewal_that_was_not_due_yet_is_not_a_lost_lock():
    """The same False means "not due yet" most of the time; that must not abort anything."""
    gate = FakeGate(give_up_after=2)
    coord = _make_coordinator(login_gate=gate)
    # Young lock: elapsed is well under ttl * 0.5, so renew_if_needed declines.
    lock = _lock_ctx(renew=AsyncMock(return_value=False), age_seconds=1.0)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ThrottlingError("Login throttled: err_too_many_requests")
        return ("sid", None)

    deadline = asyncio.get_running_loop().time() + 900.0
    token = _login_pacing.set(_LoginPacing(deadline=deadline, locks=(lock,)))
    try:
        result = await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert result == ("sid", None)


async def test_retry_outside_login_starts_its_own_deadline():
    gate = FakeGate()
    coord = _make_coordinator(login_gate=gate)

    async def op():
        return ("sid", None)

    before = asyncio.get_running_loop().time()
    await coord._retry_with_backoff(op, "Login", mds_host="mds")

    assert gate.waits[0]["deadline"] >= before + 900


async def test_retry_terminates_on_an_already_passed_deadline_instead_of_spinning():
    """The deadline guard is the backstop for a gate that never shows a live refusal.

    `wait_open` only stops the loop by observing a closed row; if that row is
    never visible -- a `close()` that didn't take, a window that lapsed between a
    close and the next peek, clock skew between workers -- nothing else would end
    this loop, and it would hammer the server at full, unthrottled speed forever.
    Starting past the deadline is the simplest case that exercises the same guard:
    the loop must raise before ever reaching the gate or the operation.
    """
    gate = FakeGate()
    coord = _make_coordinator(login_gate=gate)
    attempts = 0

    async def op():
        nonlocal attempts
        attempts += 1
        return ("sid", None)

    past_deadline = asyncio.get_running_loop().time() - 1.0
    token = _login_pacing.set(_LoginPacing(deadline=past_deadline))
    try:
        with pytest.raises(LoginGateDeadlineError):
            await coord._retry_with_backoff(op, "Login", mds_host="mds")
    finally:
        _login_pacing.reset(token)

    assert attempts == 0
    assert gate.waits == []


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


async def test_try_login_once_translates_an_mds_host_failure_as_authentication_error():
    """`_mds_host` is inside the try now: a transient cache failure resolving the
    hosting member is a login failure like any other, not a raw exception past
    this method (it used to sit before the try, and would have propagated as-is).
    """
    coord = _make_coordinator()
    coord._mds_host = AsyncMock(side_effect=RuntimeError("cache backend unavailable"))

    with pytest.raises(AuthenticationError):
        await coord._try_login_once("m", "", "ip", "key", False, None, None, None)


async def test_try_login_once_takes_no_slot_itself():
    """The slot is per attempt, inside _execute_login_request -- not held across the ladder.

    Holding it across every retry and throttle wait pinned one of three domain-server
    slots for minutes while a login was paced (2026-09-14).
    """
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

    rl.acquire.assert_not_called()


async def test_try_login_once_keys_the_gate_on_the_hosting_member_not_the_target_ip():
    """Domain logins go to domain-server IPs; the allowance they spend is the hosting member's."""
    coord = _make_coordinator()
    coord._mds_host = AsyncMock(return_value="10.0.0.2")
    coord._retry_with_backoff = AsyncMock(return_value=("sid", "uid"))

    await coord._try_login_once("mgmt1", "Domain2", "10.0.0.7", "key", False, None, None, None)

    coord._mds_host.assert_awaited_once_with("mgmt1", "Domain2")
    assert coord._retry_with_backoff.call_args.kwargs["mds_host"] == "10.0.0.2"


async def test_gate_deadline_surfaces_as_authentication_error_with_the_throttle_as_cause():
    coord = _make_coordinator()
    coord._retry_with_backoff = AsyncMock(side_effect=LoginGateDeadlineError("10.0.0.2", 900.0, 900))

    with pytest.raises(AuthenticationError, match="gave up") as excinfo:
        await coord._try_login_once("mgmt1", "Domain2", "10.0.0.7", "key", False, None, None, None)

    assert isinstance(excinfo.value.__cause__, ThrottlingError)
    assert "login_max_wait=900s" in str(excinfo.value)


async def test_execute_login_request_takes_the_target_slot_around_the_transport_call():
    events: list[str] = []

    async def slot_in(*args):
        events.append("slot-in")

    async def slot_out(*args):
        events.append("slot-out")
        return False

    rl = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(side_effect=slot_in)
    cm.__aexit__ = AsyncMock(side_effect=slot_out)
    rl.acquire = MagicMock(return_value=cm)
    transport = AsyncMock()

    async def http(**kwargs):
        events.append("http")
        return {"success": True, "sid": "s"}

    transport.login_with_apikey = AsyncMock(side_effect=http)
    coord = _make_coordinator(rate_limiter=rl, transport=transport)

    await coord._execute_login_request("m", "", "10.0.0.7", "key")

    rl.acquire.assert_called_once_with("10.0.0.7")
    assert events == ["slot-in", "http", "slot-out"]


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


async def test_create_dedicated_session_throttle_closes_the_gate_and_costs_no_retry():
    """A refused dedicated-session login must publish the refusal, not burn the ladder.

    `_attempt` used to build its own AuthenticationError from `message` alone and
    drop `code`. Check Point's message for `err_too_many_requests` does not
    contain the code, so `_login_failure_kind` saw a plain "refusal": the gate
    was never closed (every other worker kept hammering), the attempt consumed
    one of `login_max_retries`, and the exponential ladder ran against a server
    that was actively rate-limiting it. This is the write path (CPCRUD,
    `helpers/policy`, `api/client`), and absorbing "Too many requests" is the
    documented reason the method retries at all.
    """
    gate = FakeGate(give_up_after=5)
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry, settings=_make_settings(max_retries=2), login_gate=gate)

    attempts = 0

    async def fake_login(*a, **k):
        nonlocal attempts
        attempts += 1
        if attempts <= 3:
            # The real refusal: the code carries the meaning, the message does not.
            return {"success": False, "code": "err_too_many_requests", "message": "Too many requests"}
        return {"success": True, "sid": "ded-sid", "data": {"uid": "u"}}

    coord._execute_login_request = AsyncMock(side_effect=fake_login)

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        sid, ip = await coord.create_dedicated_session("mgmt1", "")

    assert (sid, ip) == ("ded-sid", "10.0.0.1")
    # Three refusals, three gate closures, and the fourth attempt still happened
    # even though max_retries is 2 -- pacing is not failure.
    assert gate.closed == ["10.0.0.1"] * 3
    assert attempts == 4
    # No backoff ladder either: the wait for a throttle is the gate's.
    assert sleep.await_args_list == []


async def test_create_dedicated_session_rejected_credentials_stay_invalid_credentials_error():
    """Routing through `_parse_login_response` must keep the subclass callers switch on."""
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry, settings=_make_settings(max_retries=3))
    coord._execute_login_request = AsyncMock(
        return_value={"success": False, "code": "err_login_failed", "message": CREDENTIAL_REJECTION_MESSAGE}
    )

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(InvalidCredentialsError):
            await coord.create_dedicated_session("mgmt1", "")

    # Fatal: not retried.
    assert coord._execute_login_request.await_count == 1


async def test_create_dedicated_session_takes_one_slot_per_attempt():
    """Backoff sleeps between attempts hold no slot."""
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    rate_limiter = _make_rate_limiter()
    transport = AsyncMock()
    attempts = 0

    async def fake_login(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            return {"success": False, "message": "transient"}
        return {"success": True, "sid": "ded-sid", "data": {}}

    transport.login_with_apikey = AsyncMock(side_effect=fake_login)
    coord = _make_coordinator(
        registry=registry, rate_limiter=rate_limiter, transport=transport, settings=_make_settings(max_retries=4)
    )

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await coord.create_dedicated_session("mgmt1", "")

    assert attempts == 2
    assert rate_limiter.acquire.call_count == 2


async def test_create_dedicated_session_gate_deadline_surfaces_as_authentication_error():
    """LoginGateDeadlineError must never leave LoginCoordinator unwrapped (asdk/login_gate.py) --
    create_dedicated_session is a second call site into _retry_with_backoff and needs the
    same translation _try_login_once already has.
    """
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry)
    coord._retry_with_backoff = AsyncMock(side_effect=LoginGateDeadlineError("10.0.0.1", 900.0, 900))

    with pytest.raises(AuthenticationError, match="gave up") as excinfo:
        await coord.create_dedicated_session("mgmt1", "")

    assert isinstance(excinfo.value.__cause__, ThrottlingError)
    assert "login_max_wait=900s" in str(excinfo.value)


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
        password=secret,
        domain=None,
        port=None,
        session_name="MMP-cleanup",
        session_description="Temporary session for stale session cleanup",
        session_timeout=None,
        timeout=120,
    )
    transport.login_with_apikey.assert_not_called()


async def test_cleanup_temp_login_is_gated_and_closes_the_gate_when_refused():
    """The temporary cleanup login is a login the server counts: it waits its turn and reports refusals.

    Three distinct addresses on purpose. The login goes to the *domain server*
    (`10.0.0.1`), the configured management host is `10.9.9.9`, and the MDS member
    actually hosting the domain -- the machine Check Point rate-limits, and the only
    correct gate key -- is `10.50.50.50`. With all three equal this test could not
    tell `_mds_host` from `server_ip` and would have passed on either.
    """
    gate = FakeGate(give_up_after=1)
    cleaner = MagicMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions = AsyncMock()
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.9.9.9", api_key=SecretStr("key"), port=None)
    cache = AsyncMock()
    cache.get_domain.return_value = MagicMock(active_mds_ip="10.50.50.50")
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {
        "success": False,
        "code": "err_too_many_requests",
        "message": "Too many requests",
    }
    coord = _make_coordinator(
        registry=registry, transport=transport, cache=cache, session_cleaner=cleaner, login_gate=gate
    )

    await coord._cleanup_for_max_sessions("mgmt1", "General", "10.0.0.1", "key", None)  # must not raise

    assert gate.closed == ["10.50.50.50"]
    assert gate.waits[0]["mds_host"] == "10.50.50.50"
    # The login itself still went to the domain server, not to the gate key.
    assert transport.login_with_apikey.await_args.kwargs["server_ip"] == "10.0.0.1"
    cleaner.cleanup_stale_sessions.assert_not_called()


async def test_cleanup_temp_login_gets_a_sub_deadline_of_at_most_one_window():
    """A best-effort side quest must not eat the budget of the login it unblocks.

    `max_retries=1` bounds non-throttle failures, but a throttle does not count as
    a failure -- it closes the gate and waits for the next window -- so in the
    max-sessions path the cleanup login shared the *outer* login's deadline and
    could retry until it was gone.
    """
    gate = FakeGate(give_up_after=10)
    cleaner = MagicMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions = AsyncMock()
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    settings = _make_settings()
    settings.login_throttle_window = 70
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner, settings=settings, login_gate=gate)

    outer_deadline = asyncio.get_running_loop().time() + 900.0
    token = _login_pacing.set(_LoginPacing(deadline=outer_deadline))
    try:
        await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)
    finally:
        _login_pacing.reset(token)

    # One window, not the outer login's 900 s.
    assert gate.waits[0]["deadline"] <= outer_deadline - 800
    assert gate.waits[0]["deadline"] >= asyncio.get_running_loop().time() + 60


async def test_cleanup_temp_login_never_exceeds_the_outer_deadline():
    """When less than a window is left, the cleanup login gets only what is left."""
    gate = FakeGate(give_up_after=10)
    cleaner = MagicMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions = AsyncMock()
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "tmp", "data": {}}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner, login_gate=gate)

    outer_deadline = asyncio.get_running_loop().time() + 5.0
    token = _login_pacing.set(_LoginPacing(deadline=outer_deadline))
    try:
        await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)
    finally:
        _login_pacing.reset(token)

    assert gate.waits[0]["deadline"] <= outer_deadline


async def test_cleanup_temp_login_still_renews_the_outer_login_lock():
    """Its own deadline, but not its own lock chain: the outer lock must stay alive."""
    # Two refusals, so there is a wait with a live gate row in between -- which is
    # the only moment the real gate runs `keepalive`.
    gate = FakeGate(give_up_after=2)
    cleaner = MagicMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions = AsyncMock()
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {
        "success": False,
        "code": "err_too_many_requests",
        "message": "Too many requests",
    }
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(registry=registry, transport=transport, session_cleaner=cleaner, login_gate=gate)
    outer = _lock_ctx()

    token = _login_pacing.set(
        _LoginPacing(deadline=asyncio.get_running_loop().time() + 900.0, locks=(outer,)),
    )
    try:
        await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)
    finally:
        _login_pacing.reset(token)

    assert gate.closed == ["10.0.0.1", "10.0.0.1"]
    outer.renew_if_needed.assert_awaited()


async def test_cleanup_temp_login_makes_a_single_attempt_on_a_plain_failure():
    gate = FakeGate()
    cleaner = MagicMock(spec=SessionCleaner)
    cleaner.cleanup_stale_sessions = AsyncMock()
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": False, "code": "generic_err", "message": "nope"}
    coord = _make_coordinator(transport=transport, session_cleaner=cleaner, login_gate=gate)

    with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        await coord._cleanup_for_max_sessions("mgmt1", "", "10.0.0.1", "key", None)

    assert transport.login_with_apikey.await_count == 1
    assert sleep.await_args_list == []
    cleaner.cleanup_stale_sessions.assert_not_called()


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
