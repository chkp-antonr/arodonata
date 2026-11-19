"""Check Point Web API response classifiers and domain-entry parser."""

from __future__ import annotations

from typing import Any

from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.domains import DomainInfo


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


def parse_domain_entry(
    mgmt_name: str,
    raw: dict[str, Any],
    *,
    mds_ip_by_name: dict[str, str] | None = None,
) -> DomainInfo:
    """Parse a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dictionary into `DomainInfo`."""
    uid = str(raw.get("uid") or "")
    name = str(raw.get("name") or "")
    dom_type = str(raw.get("type") or raw.get("domain-type") or "domain")
    is_global = dom_type in ("global", "global-domain") or name == "Global" or bool(raw.get("is_global"))

    servers_raw = raw.get("servers")
    servers_list: list[dict[str, Any]] = (
        [s for s in servers_raw if isinstance(s, dict)] if isinstance(servers_raw, list) else []
    )

    active_ip: str | None = raw.get("active_ip") or raw.get("active-ip")
    active_mds_ip: str | None = raw.get("active_mds_ip") or raw.get("active-mds-ip")
    standby_ips: list[str] = []

    for srv in servers_list:
        srv_ip = srv.get("ipv4-address") or srv.get("ipv6-address") or srv.get("ip")
        mds_obj = srv.get("multi-domain-server")
        mds_ip: str | None = None
        if isinstance(mds_obj, dict):
            mds_ip = mds_obj.get("ipv4-address") or mds_obj.get("ip")
            if not mds_ip and mds_ip_by_name and isinstance(mds_obj.get("name"), str):
                mds_ip = mds_ip_by_name.get(mds_obj["name"])
        elif isinstance(mds_obj, str) and mds_ip_by_name:
            mds_ip = mds_ip_by_name.get(mds_obj)
        elif isinstance(srv.get("multi-domain-server-ip"), str):
            mds_ip = srv.get("multi-domain-server-ip")

        is_active = bool(srv.get("active"))
        if is_active:
            if isinstance(srv_ip, str) and srv_ip:
                active_ip = srv_ip
            if isinstance(mds_ip, str) and mds_ip:
                active_mds_ip = mds_ip
        elif isinstance(srv_ip, str) and srv_ip:
            standby_ips.append(srv_ip)

    if active_ip is None and is_global and active_mds_ip:
        active_ip = active_mds_ip

    if active_ip is None and servers_list:
        first_ip = servers_list[0].get("ipv4-address") or servers_list[0].get("ip")
        if isinstance(first_ip, str) and first_ip:
            active_ip = first_ip

    return DomainInfo(
        id=f"{mgmt_name}:{name}",
        mgmt_name=mgmt_name,
        uid=uid,
        name=name,
        domain_type="global" if is_global else dom_type,
        active_ip=active_ip,
        active_mds_ip=active_mds_ip or active_ip,
        standby_ips=standby_ips,
        servers=servers_list,
        is_global=is_global,
        raw_data=dict(raw),
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
