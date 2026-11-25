"""Check Point Web API response classifiers and domain-entry parser."""

from __future__ import annotations

from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.domains import parse_domain_entry


def is_session_expired_result(result: ApiCallResult, *, command: str | None = None) -> bool:
    """Return `True` if `result` indicates an invalid or expired Check Point session (`sid`).

    On Check Point MDSM, after `revert-to-revision` wipes sessions created after the target
    revision, calling `show-session` with no `uid` parameter on a wiped session returns
    `generic_err_object_not_found` (`Requested object [<session-uid>] not found`).
    """
    if result.success:
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    if code in (
        "generic_err_invalid_session_id",
        "err_session_expired",
        "session_expired",
        "unauthorized",
    ):
        return True
    if (
        command is not None
        and command.strip().lower().lstrip("/") == "show-session"
        and (code == "generic_err_object_not_found" or "requested object" in msg and "not found" in msg)
    ):
        return True
    return any(
        token in msg
        for token in (
            "invalid session",
            "session expired",
            "session id is invalid",
            "wrong session id",
            "session is not valid",
            "unauthorized",
        )
    )


def is_login_throttled_result(result: ApiCallResult) -> bool:
    """Return `True` if `result` indicates Check Point per-IP login rate limiting / throttling."""
    if result.success:
        return False
    if result.status_code == 429:
        return True
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "too many login",
            "too many requests",
            "err_too_many_requests",
            "login rate",
            "throttl",
            "exceeded the maximum number of login",
            "try again later",
        )
    )


def is_transient_revision_lock_result(result: ApiCallResult) -> bool:
    """Return `True` if login failed transiently due to `Database revision is in progress` or lock contention."""
    if result.success:
        return False
    msg = (result.error_message or "").lower()
    code = (result.error_code or "").lower()
    return any(
        token in msg or token in code
        for token in (
            "database revision is in progress",
            "revision is in progress",
            "temporarily unavailable",
            "server is initializing",
        )
    )


def is_invalid_credentials_result(result: ApiCallResult) -> bool:
    """Return `True` if the server explicitly rejected login credentials (non-retryable)."""
    if result.success:
        return False
    if (
        is_transient_revision_lock_result(result)
        or is_login_throttled_result(result)
        or is_max_sessions_exceeded_result(result)
    ):
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "authentication to server failed",
            "invalid credentials",
            "invalid api key",
            "invalid username or password",
            "access denied",
            "err_login_failed",
            "generic_err_login_failed",
            "administrator account is locked",
        )
    )


def is_max_sessions_exceeded_result(result: ApiCallResult) -> bool:
    """Return `True` if login was refused because max sessions limit was reached."""
    if result.success:
        return False
    msg = (result.error_message or "").lower()
    return any(
        token in msg
        for token in (
            "maximum number of open sessions",
            "too many open sessions",
            "max sessions",
            "exceeded maximum allowed sessions",
        )
    )


def is_failover_or_unreachable_result(result: ApiCallResult) -> bool:
    """Return `True` if a domain server IP returned a standby/failover or unreachable error."""
    if result.success:
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "domain is not active",
            "standby domain",
            "active domain server",
            "domain server is unreachable",
            "failover",
            "err_domain_not_active",
        )
    )


__all__ = [
    "is_failover_or_unreachable_result",
    "is_invalid_credentials_result",
    "is_login_throttled_result",
    "is_max_sessions_exceeded_result",
    "is_session_expired_result",
    "is_transient_revision_lock_result",
    "parse_domain_entry",
]
