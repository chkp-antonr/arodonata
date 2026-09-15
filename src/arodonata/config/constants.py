"""Static constants for Arodonata library."""

from __future__ import annotations

from typing import Final

# Default values
DEFAULT_SESSION_EXPIRE: Final[int] = 3600  # 1 hour in seconds
DEFAULT_SESSION_TIMEOUT: Final[int] = 600  # Session timeout in seconds (default from Check Point API)
DEFAULT_API_TIMEOUT: Final[int] = 120  # seconds
# A login is a single HTTP round trip (1-3 s on a healthy server), so it gets its
# own budget rather than inheriting DEFAULT_API_TIMEOUT. Against an unresponsive
# domain server the 2026-09-13 int-4 run burned 120 s per attempt, twice, before
# the caller's own budget expired -- and with DEFAULT_LOGIN_RETRIES that is a
# 16-minute worst case for a call that should fail in seconds.
#
# Deliberately generous, and measured rather than guessed: a domain-server login
# on a loaded MDS legitimately takes longer than a minute. Shortening this to 45 s
# on 2026-09-13 (reasoning: "a login is one round trip, it should be quick") turned
# three green integration buckets red -- slow-but-alive domain servers began
# timing out, and every bucket's baseline-snapshot fixture failed with them. The
# value is back where it was; what is new is that it is now an explicit, tunable
# setting instead of an accidental inheritance of DEFAULT_API_TIMEOUT, so a
# deployment that knows its servers are fast can lower it via
# ARODONATA_LOGIN_TIMEOUT without touching the API budget.
DEFAULT_LOGIN_TIMEOUT: Final[int] = 120  # seconds

# Check Point rate-limits logins per user per server IP over a ONE-MINUTE window.
# How many it allows in that window is server-side configuration (3 by default);
# with one shared API key the allowance is shared by every caller, no matter how
# many there are. What matters here is the window, not the allowance: exceeding it
# locks the user out for the remainder, and a rejected attempt RE-ARMS it, so the
# only wait that reliably clears it is a single one longer than a minute. 70 s is
# that wait with margin.
#
# Note this is a *rate* limit, and is NOT what RateLimiter enforces: that caps
# concurrency (DEFAULT_CONCURRENT_LIMIT simultaneous calls per IP). Concurrent
# logins are allowed by the limiter and can consume the whole per-minute login
# allowance in a few seconds -- the two limits are easy to confuse and unrelated.
#
# Tunable via ArodonataSettings.login_throttle_window, because the limit is
# server-side configuration rather than a universal constant -- and because a
# caller that knows it will not hit a real throttle (a test with a mocked one,
# say) should not be made to wait out a window that does not exist. Waiting is
# never free: a throttled login costs this much before it can even retry, so
# any budget a caller wraps around a login has to exceed it.
LOGIN_THROTTLE_WINDOW_SECONDS: Final[int] = 70  # seconds
DEFAULT_CONCURRENT_LIMIT: Final[int] = 3
DEFAULT_LOGIN_BACKOFF: Final[int] = 5  # seconds
DEFAULT_LOGIN_RETRIES: Final[int] = 8
# How long a caller waits for a free RateLimiter concurrency slot (asdk/rate_limiter.py)
# before giving up. Must comfortably exceed how long another caller can legitimately
# hold a slot: login's own retry-with-backoff (DEFAULT_LOGIN_BACKOFF * 1.3^attempt,
# capped at 60s/attempt) is held for the ENTIRE slot lease to avoid compounding
# server-side throttling, so a too-short slot-wait timeout makes concurrent callers
# fail fast even though the server would have accepted a login moments later.
DEFAULT_RATE_LIMIT_SLOT_TIMEOUT: Final[int] = 90  # seconds

# Total wall-clock one login() may spend waiting out Check Point's per-MDS login
# rate limit before giving up (asdk/login_gate.py). Also the timeout for acquiring
# the per-domain login lock, since a second caller for the same domain has to
# outlast the first one's pacing. Sized for a cold multi-domain collection at the
# default allowance: 20 domains is 21 logins, and at 3 per minute that is ~8
# minutes. A deployment with more domains per MDS raises it via
# ARODONATA_LOGIN_MAX_WAIT; the failure message says when it was exceeded.
DEFAULT_LOGIN_MAX_WAIT: Final[int] = 900  # seconds

# Self-managed `show-task` polling (asdk/task_waiter.py). Start responsive -- most
# publishes finish in seconds -- then back off to a ceiling, because a long revert's
# polls hit a CPM that is already busy doing the very work we are waiting on: a
# ten-minute revert costs ~70 polls at this schedule instead of cpapi's flat-2s ~300.
DEFAULT_TASK_POLL_INITIAL_SECONDS: Final[float] = 2.0
DEFAULT_TASK_POLL_MAX_SECONDS: Final[float] = 10.0
# Consecutive `show-task` failures tolerated before giving up, matching cpapi's five.
# A single dropped poll during a heavy revert says nothing about the task itself.
DEFAULT_TASK_POLL_FAILURE_TOLERANCE: Final[int] = 5

# Session error codes that trigger relogin
SESSION_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "generic_err_session_expired",
        "generic_err_wrong_session_id",
        "generic_err_missing_session_id",
    }
)

# Failover error codes that trigger domain cache refresh
FAILOVER_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "generic_err_no_permissions",
        "err_forbidden",
    }
)

# Throttling error code
THROTTLE_ERROR_CODE: Final[str] = "err_too_many_requests"

# Substring of the login-failure message Check Point returns for a rejected
# password/API key. This is the one login failure that never clears on retry,
# so the login coordinator raises it as InvalidCredentialsError (a subclass of
# AuthenticationError) and stops retrying immediately. Every other rejection
# ("Database revision is in progress", server restarting, ...) is transient
# and stays a plain AuthenticationError.
CREDENTIAL_REJECTION_MESSAGE: Final[str] = "Authentication to server failed"

# Check Point's answer when the server we asked cannot reach the target server at
# all -- a domain server that is down, or a domain that no longer lives where the
# cached `active_ip` says. Classed with socket timeouts and refusals as
# "unreachable": retrying the same address cannot help, so the login path
# re-resolves the domain's active server instead (see ServerUnreachableError).
SERVER_UNREACHABLE_MESSAGE: Final[str] = (
    "Unable to connect to server. Please make sure that all processes of the server are up and running."
)

# Multi-domain manager (MDM) always has an implicit Global domain. Check Point's
# `show-domains` API never returns it (it only lists manually created domains),
# so callers that populate/refresh the domain cache must add this row explicitly.
GLOBAL_DOMAIN_NAME: Final[str] = "Global"

# Valid log levels
LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {
        "TRACE",
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }
)

__all__ = [
    "DEFAULT_SESSION_EXPIRE",
    "DEFAULT_SESSION_TIMEOUT",
    "DEFAULT_API_TIMEOUT",
    "DEFAULT_LOGIN_TIMEOUT",
    "LOGIN_THROTTLE_WINDOW_SECONDS",
    "DEFAULT_CONCURRENT_LIMIT",
    "DEFAULT_LOGIN_BACKOFF",
    "DEFAULT_LOGIN_RETRIES",
    "DEFAULT_RATE_LIMIT_SLOT_TIMEOUT",
    "DEFAULT_LOGIN_MAX_WAIT",
    "DEFAULT_TASK_POLL_INITIAL_SECONDS",
    "DEFAULT_TASK_POLL_MAX_SECONDS",
    "DEFAULT_TASK_POLL_FAILURE_TOLERANCE",
    "SESSION_ERROR_CODES",
    "FAILOVER_ERROR_CODES",
    "THROTTLE_ERROR_CODE",
    "CREDENTIAL_REJECTION_MESSAGE",
    "SERVER_UNREACHABLE_MESSAGE",
    "LOG_LEVELS",
    "GLOBAL_DOMAIN_NAME",
]
