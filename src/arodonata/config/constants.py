"""Static constants for Arodonata library."""

from __future__ import annotations

from typing import Final

# Default values
DEFAULT_SESSION_EXPIRE: Final[int] = 3600  # 1 hour in seconds
DEFAULT_SESSION_TIMEOUT: Final[int] = 600  # Session timeout in seconds (default from Check Point API)
DEFAULT_API_TIMEOUT: Final[int] = 120  # seconds

# A server-side task is not an HTTP round trip and must not share its budget.
# `publish`, `install-policy`, `assign-global-assignment` and `revert-to-revision`
# return a task id in seconds and then run for minutes; the call that started them
# is over long before. Charging both to DEFAULT_API_TIMEOUT means the poller
# inherits whatever is left of an allowance sized for a round trip, so the whole
# operation is bounded by the wrong number.
#
# The failure that produces is the worst kind: the client reports a timeout while
# the server goes on to finish the task successfully, so the caller believes
# nothing happened when in fact everything did. Observed on mdsNP2 2026-09-22 with
# a deployment that had lowered ARODONATA_API_TIMEOUT to 30 - a publish sat at 0%
# after 29 s, the call raised, and the change was published moments later.
#
# Generous on purpose. The HTTP timeout stays strict, which is what actually
# detects a dead server; this one only bounds waiting for work the server has
# already accepted, and cutting it short buys nothing.
DEFAULT_TASK_TIMEOUT: Final[int] = 900  # seconds
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

# TCP connect + TLS handshake bound for every Check Point connection, and for the identity probe (spec D15).
DEFAULT_CONNECT_TIMEOUT: Final[int] = 30  # seconds
# Added to a call's own budget for the socket read timeout, so the socket never races asyncio.wait_for (spec D16).
READ_TIMEOUT_MARGIN: Final[int] = 5  # seconds
DEFAULT_TLS_TRUST: Final[str] = "tofu"

# Check Point rate-limits logins per management server machine -- every domain
# whose active server is hosted on a Multi-Domain Server member shares that
# member's allowance -- over roughly a minute, to a server-configured count (3 by
# default). Exceeding it returns err_too_many_requests in ~0.5 s. It is NOT a clean
# N-per-60 s window: probed on 2026-09-14 (tests/integration/probe_login_throttle.py)
# a server set to 10 allowed 10 logins in 18 s on one run and 18 in 43 s on the next,
# and recovered in 20 s and 41-57 s respectively. Whether a refused attempt delays
# recovery is unconfirmed (two runs, mixed evidence). This library does not model
# the allowance; it reacts to refusals (asdk/login_gate.py), and this value is how
# long a refusal closes the gate for, counted from the *last* refusal. 70 s covers
# the worst recovery seen with margin.
#
# Note this is a *rate* limit, and is NOT what RateLimiter enforces: that caps
# concurrency (DEFAULT_CONCURRENT_LIMIT simultaneous calls per MDS member). The two
# are easy to confuse and unrelated.
#
# Tunable via ArodonataSettings.login_throttle_window, because the limit is
# server-side configuration rather than a universal constant -- and because a
# caller that knows it will not hit a real throttle (a test with a mocked one,
# say) should not be made to wait out a window that does not exist.
LOGIN_THROTTLE_WINDOW_SECONDS: Final[int] = 70  # seconds
DEFAULT_LOGIN_THROTTLE_INITIAL_SECONDS: Final[int] = 7  # seconds
DEFAULT_LOGIN_THROTTLE_INCREMENT_SECONDS: Final[int] = 5  # seconds
# RateLimiter concurrency (asdk/rate_limiter.py): requests in flight per MDS *member*,
# the machine that serves the API for every domain it hosts -- the same key the login
# gate uses (LoginCoordinator.mds_host). Measured on the home lab (2026-10-03,
# docs/_AI_/2610/261003-warmup-parallelism/findings.md): one request at a time gets
# ~200 objects/s, a member tops out at ~650-700 objects/s with 4-5 in flight, and more
# adds nothing while taking headroom from SmartConsole and other clients of the member.
# A slot is held for one whole request (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT). One
# `CacheRefreshCoordinator.ensure` call starts at most `concurrent_limit - 1` domain
# refreshes per member, which leaves a slot for logins and keepalives *from that call's
# point of view*; overlapping ensure calls, other processes, long tasks and keepalives
# can still take every slot of a member.
DEFAULT_CONCURRENT_LIMIT: Final[int] = 4
# Page size for the cache's list fetches (show-hosts, show-gateways-and-servers, show-domains, ...): Check
# Point's maximum, instead of cpapi's api_query default of 50. Every page pays a round trip; on the home lab
# a 12 150-object domain loaded in 68.4 s at 500 vs 79.1 s at 50 (findings 2026-10-03), more on remote labs.
CACHE_QUERY_PAGE_SIZE: Final[int] = 500
DEFAULT_LOGIN_BACKOFF: Final[int] = 5  # seconds
DEFAULT_LOGIN_RETRIES: Final[int] = 8
# How long a caller waits for a free RateLimiter concurrency slot (asdk/rate_limiter.py)
# before giving up. A slot is held for one whole request: for `api_query` that is a
# whole listing (cpapi fetches the pages inside that one call, so the slot is held
# across all of them, not per page), and a call that waits for a task (`wait_for_task`,
# e.g. publish or revert) holds it for the whole task. Since 2026-09-14 logins take
# slots too: a login takes the hosting MDS member's slot for a single HTTP round
# trip (bounded by DEFAULT_LOGIN_TIMEOUT), never across its retry ladder or a
# throttle wait -- those happen outside the slot, and pacing belongs to the login
# gate (asdk/login_gate.py). Long-running tasks legitimately hold a slot for their
# whole run, so this stays generous.
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

# Query commands that answer with a task. The finished `show-task` response nests
# the paging fields (from/to/total) and the items under `tasks[].task-details[]`,
# where cpapi's api_query never looks -- it returns page one and stops. Command ->
# the item key inside task-details. ArodonataClient.api_query pages these itself.
TASK_QUERY_COMMANDS: Final[dict[str, str]] = {"show-changes": "changes"}
TASK_QUERY_PAGE_SIZE: Final[int] = 50  # cpapi's api_query page size
TASK_QUERY_MAX_PAGE_SIZE: Final[int] = 500  # show-changes `limit` accepts 1-500

# How long a SQLite connection waits for another writer (several processes on one cache file, or a large
# domain swap) before failing with "database is locked". SQLite's own default is 5 s. An engine created with
# its own connect_args={"timeout": ...} keeps that value.
SQLITE_BUSY_TIMEOUT_SECONDS: Final[float] = 30.0

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
    "TASK_QUERY_COMMANDS",
    "TASK_QUERY_PAGE_SIZE",
    "TASK_QUERY_MAX_PAGE_SIZE",
    "DEFAULT_SESSION_EXPIRE",
    "DEFAULT_SESSION_TIMEOUT",
    "DEFAULT_API_TIMEOUT",
    "DEFAULT_LOGIN_TIMEOUT",
    "DEFAULT_CONNECT_TIMEOUT",
    "READ_TIMEOUT_MARGIN",
    "DEFAULT_TLS_TRUST",
    "LOGIN_THROTTLE_WINDOW_SECONDS",
    "DEFAULT_LOGIN_THROTTLE_INITIAL_SECONDS",
    "DEFAULT_LOGIN_THROTTLE_INCREMENT_SECONDS",
    "CACHE_QUERY_PAGE_SIZE",
    "SQLITE_BUSY_TIMEOUT_SECONDS",
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
