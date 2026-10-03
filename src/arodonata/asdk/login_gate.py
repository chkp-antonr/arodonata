"""Per-MDS login gate: wait out Check Point's login rate limit once, together.

Check Point rate-limits logins per management server -- every domain hosted on a
Multi-Domain Server member shares that member's allowance -- over roughly a
minute, to a server-configured count this library does not know. The gate does
not try to know it. It records one fact, "this server just refused a login", as
a row in the distributed_locks table with a TTL of one throttle window, and
makes every login attempt to that server, in every worker sharing the database,
sleep until the row lapses. One refusal per window is the price of discovery;
the gate stops it being paid more than once.

Which server a login counts against is the caller's business (see
LoginCoordinator.mds_host): the gate is keyed on whatever string it is given.

This is a *rate* concern and deliberately separate from RateLimiter, which caps
*concurrency* per MDS member, keyed like the gate (LoginCoordinator.mds_host).
Design: docs/superpowers/specs/2026-09-14-mds-login-gate-design.md
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from arlogi.otel.decorator import traced

from ..cache.lock_manager import DatabaseLockManager
from ..core.exceptions import ThrottlingError
from ..logger import lazy_logger
from ..telemetry import span_attrs

log = lazy_logger("arodonata.asdk.login_gate")

# Waiters wake spread over this many seconds after the row lapses, so a herd of
# paced logins does not all return on the same instant.
_WAKE_JITTER_SECONDS = 2.0
# A single sleep never exceeds this, so the caller's keepalive hook runs well
# inside the 90 s login-lock TTL it exists to renew.
_MAX_SLEEP_SECONDS = 30.0


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class LoginGateDeadlineError(ThrottlingError):
    """Waited at the gate until the login's deadline and never got a turn.

    A ThrottlingError, so anything that already handles throttling handles this;
    a distinct class, so LoginCoordinator can tell "the deadline passed" (end the
    sequence) from "the server refused" (close the gate, keep going) by type.
    Internal: it never leaves LoginCoordinator unwrapped.
    """

    def __init__(
        self,
        mds_host: str,
        waited: float,
        max_wait: int,
        *,
        throttles: int | None = None,
        failures: int = 0,
        timeouts: int = 0,
        last_error: BaseException | None = None,
    ) -> None:
        """
        Args:
            mds_host: The machine the login counts against.
            waited: Seconds spent before giving up.
            max_wait: The configured budget (login_max_wait).
            throttles: Throttle refusals this login received, or None when the
                raiser cannot know (the gate itself). The retry loop re-raises
                with the tally via `with_attempts`, because the deadline passes
                the same way whether the attempts were refused for rate or timed
                out, and only the tally says which.
            failures: Non-throttle failed attempts (timeouts included).
            timeouts: How many of `failures` were timeouts.
            last_error: The last attempt's exception, if any.
        """
        self.mds_host = mds_host
        self.waited = waited
        self.max_wait = max_wait
        self.throttles = throttles
        self.failures = failures
        self.timeouts = timeouts
        self.last_error = last_error
        super().__init__(self._describe())

    def with_attempts(
        self, *, throttles: int, failures: int, timeouts: int, last_error: BaseException | None
    ) -> LoginGateDeadlineError:
        """The same deadline, with what this login's attempts actually ran into."""
        return LoginGateDeadlineError(
            self.mds_host,
            self.waited,
            self.max_wait,
            throttles=throttles,
            failures=failures,
            timeouts=timeouts,
            last_error=last_error,
        )

    def _describe(self) -> str:
        budget = f"{self.waited:.0f}s (login_max_wait={self.max_wait}s)"
        allowance = "Check Point's per-minute login allowance is below the login demand"
        if self.throttles is None:
            return f"login throttled by {self.mds_host} for {budget}: {allowance}"

        last = ""
        if self.last_error is not None:
            text = str(self.last_error)
            name = type(self.last_error).__name__
            last = f"; last error: {name}: {text}" if text else f"; last error: {name}"
        failed = f"{self.failures} attempts failed ({self.timeouts} timed out)"

        if self.throttles == 0 and self.failures == 0:
            return (
                f"login to {self.mds_host} waited {budget} at a login gate kept closed by other "
                f"logins' throttle refusals; no attempt of its own was made"
            )
        if self.throttles == 0:
            return f"login to {self.mds_host} gave up after {budget}, no throttle refusals: {failed}{last}"
        if self.failures == 0:
            return f"login throttled by {self.mds_host} for {budget}: {self.throttles} throttle refusals; {allowance}"
        return f"login to {self.mds_host} gave up after {budget}: {self.throttles} throttle refusals and {failed}{last}"


class LoginGate:
    """One marker row per management server: `loginthrottle:{mds_host}`, TTL = window."""

    def __init__(
        self,
        lock_manager: DatabaseLockManager,
        window: int,
        *,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        """
        Args:
            lock_manager: Where the marker rows live (the same table as every other lock).
            window: Seconds a refusal closes the gate for, measured from the *last* refusal.
            now: Clock returning naive UTC; injectable for tests.
        """
        self._lock_manager = lock_manager
        self._window = window
        self._now = now

    @staticmethod
    def _key(mds_host: str) -> str:
        return f"loginthrottle:{mds_host}"

    @traced
    async def close(self, mds_host: str, window: int | None = None, *, target: str = "") -> None:
        """Record that `mds_host` just refused a login: nobody tries again for one window.

        Upserts the row, or -- if another task already closed the gate -- pushes its
        expiry out, because the window that matters runs from the *last* refusal.
        The row is never released; it lapses. `target` ("mgmt/domain") names the
        refused login in the log line, the only one a throttle produces.
        """
        effective_window = self._window if window is None else window
        key = self._key(mds_host)
        span_attrs(mds_host=mds_host, window=effective_window)
        taken = await self._lock_manager.try_acquire_lock(key, effective_window)
        if taken is None:
            await self._lock_manager.extend_lock(key, effective_window)
        log().warning(
            f"Login gate CLOSED for {mds_host} for {effective_window}s: Check Point refused a login"
            f"{f' to {target}' if target else ''} (err_too_many_requests); every login to this server waits"
        )

    @traced
    async def wait_open(
        self,
        mds_host: str,
        *,
        deadline: float,
        max_wait: int,
        keepalive: Callable[[], Awaitable[Any]] | None = None,
    ) -> None:
        """Return once no refusal is live for `mds_host`; raise if that would pass `deadline`.

        Args:
            mds_host: The server the login counts against (LoginCoordinator.mds_host).
            deadline: Absolute `loop.time()` after which the login gives up.
            max_wait: The setting behind `deadline`, for the error message only.
            keepalive: Awaited before every sleep chunk -- the caller's lock renewal.
        """
        key = self._key(mds_host)
        loop = asyncio.get_running_loop()
        waits = 0
        while True:
            expires_at = await self._lock_manager.peek_expiry(key)
            if expires_at is None:
                if waits:
                    span_attrs(mds_host=mds_host, waits=waits)
                    log().info(f"Login gate open for {mds_host}; proceeding")
                return

            remaining = max((expires_at - self._now()).total_seconds(), 0.0)
            remaining += random.uniform(0, _WAKE_JITTER_SECONDS)
            if loop.time() + remaining > deadline:
                waited = max_wait - (deadline - loop.time())
                span_attrs(mds_host=mds_host, waits=waits, deadline_exceeded=True)
                raise LoginGateDeadlineError(mds_host, waited, max_wait)

            waits += 1
            log().info(f"Login gate closed for {mds_host}: waiting {remaining:.0f}s for the throttle window to lapse")
            while remaining > 0:
                if keepalive is not None:
                    await keepalive()
                chunk = min(remaining, _MAX_SLEEP_SECONDS)
                await asyncio.sleep(chunk)
                remaining -= chunk


__all__ = ["LoginGate", "LoginGateDeadlineError"]
