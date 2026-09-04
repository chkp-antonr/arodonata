"""Static constants for Arodonata library."""

from __future__ import annotations

from typing import Final

# Default values
DEFAULT_SESSION_EXPIRE: Final[int] = 3600  # 1 hour in seconds
DEFAULT_SESSION_TIMEOUT: Final[int] = 600  # Session timeout in seconds (default from Check Point API)
DEFAULT_API_TIMEOUT: Final[int] = 120  # seconds
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
    "DEFAULT_CONCURRENT_LIMIT",
    "DEFAULT_LOGIN_BACKOFF",
    "DEFAULT_LOGIN_RETRIES",
    "DEFAULT_RATE_LIMIT_SLOT_TIMEOUT",
    "SESSION_ERROR_CODES",
    "FAILOVER_ERROR_CODES",
    "THROTTLE_ERROR_CODE",
    "LOG_LEVELS",
    "GLOBAL_DOMAIN_NAME",
]
