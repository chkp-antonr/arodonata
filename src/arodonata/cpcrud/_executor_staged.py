"""Staged session verification, provenance checking, and adoption (`arodonata.cpcrud._executor_staged`)."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import suppress
from typing import Any

from arodonata.core.context import AuthContext, get_auth_context, normalize_domain_key
from arodonata.core.errors import ServerIdentityError, ValidationError, redact_sid
from arodonata.core.models.common import ApiCallResult
from arodonata.core.ports import ApiPort
from arodonata.cpcrud.models import StagedSessionInfo


async def _verify_direct_sid(
    api: ApiPort,
    mgmt_name: str,
    domain: str | None,
    *,
    session_uid: str,
    candidate_sid: str,
    candidate_ip: str | None,
    expected_name_clean: str | None,
    allow_foreign: bool,
) -> tuple[str | None, str | None, ApiCallResult] | None:
    """Verify whether `candidate_sid` already points to an open, eligible `session_uid`."""
    try:
        verify_res = await api.api_call(
            mgmt_name,
            "show-session",
            {},
            domain=domain or None,
            sid=candidate_sid,
            server_ip=candidate_ip,
        )
        if verify_res.success and isinstance(verify_res.data, dict):
            s_uid = str(verify_res.data.get("uid") or "").strip()
            s_state = str(verify_res.data.get("state") or "").strip().lower()
            has_pub = bool(verify_res.data.get("publish-time"))
            if s_uid == session_uid:
                if s_state in ("published", "discarded") or has_pub:
                    return (
                        None,
                        None,
                        ApiCallResult(
                            success=False,
                            status_code=400,
                            error_code="session_not_open",
                            error_message=f"Staged session {session_uid} is already {s_state or 'published'}.",
                        ),
                    )
                if expected_name_clean is not None and not allow_foreign:
                    v_name = (
                        str(verify_res.data.get("name") or verify_res.data.get("session-name") or "").strip().lower()
                    )
                    if v_name != expected_name_clean:
                        return (
                            None,
                            None,
                            ApiCallResult(
                                success=False,
                                status_code=403,
                                error_code="foreign_session_refused",
                                error_message=(
                                    f"Refusing to adopt session {session_uid}: session name {v_name!r} "
                                    f"does not match expected_session_name {expected_name_clean!r}."
                                ),
                            ),
                        )
                return candidate_sid, candidate_ip, verify_res
    except (ServerIdentityError, ValidationError):
        raise
    except Exception:
        pass
    return None


async def _inspect_and_verify_provenance(
    api: ApiPort,
    mgmt_name: str,
    domain: str | None,
    *,
    session_uid: str,
    fresh_sid: str,
    fresh_ip: str,
    resolved_auth: AuthContext | None,
    staged_entry: StagedSessionInfo | None,
    expected_name_clean: str | None,
    allow_foreign: bool,
    known_sids: list[str],
) -> tuple[str | None, ApiCallResult | None]:
    """Inspect helper session identity and target `session_uid` provenance before takeover.

    Returns `(initial_uid, failure_result)`. Caller handles shielded `logout_sid` on `fresh_sid`
    whenever adoption does not complete.
    """
    initial_uid: str | None = None
    current_user: str = (
        resolved_auth.username.strip().lower() if resolved_auth is not None and resolved_auth.username else ""
    )
    self_res = await api.api_call(
        mgmt_name,
        "show-session",
        {},
        domain=domain or None,
        sid=fresh_sid,
        server_ip=fresh_ip,
    )
    if self_res.success and isinstance(self_res.data, dict):
        raw_init_uid = str(self_res.data.get("uid") or "").strip()
        if raw_init_uid:
            initial_uid = raw_init_uid
        raw_self_user = str(self_res.data.get("user-name") or self_res.data.get("user") or "").strip().lower()
        if raw_self_user:
            current_user = raw_self_user
    try:
        info_res = await api.api_call(
            mgmt_name,
            "show-session",
            {"uid": session_uid},
            domain=domain or None,
            sid=fresh_sid,
            server_ip=fresh_ip,
        )
    except ServerIdentityError:
        raise
    except Exception as exc:
        safe_err = redact_sid(str(exc), known_sids=known_sids)
        return (
            None,
            ApiCallResult(
                success=False,
                status_code=500,
                error_message=f"Failed to inspect staged session {session_uid}: {safe_err}",
                error_code="session_inspect_failed",
            ),
        )

    if not info_res.success or not isinstance(info_res.data, dict):
        safe_err = redact_sid(
            info_res.error_message or info_res.error_code or f"Unable to inspect session {session_uid}",
            known_sids=known_sids,
        )
        return None, info_res.model_copy(update={"error_message": safe_err})

    s_data = info_res.data
    s_state = str(s_data.get("state") or "").strip().lower()
    has_pub = bool(s_data.get("publish-time"))
    if s_state in ("published", "discarded") or has_pub:
        return (
            None,
            ApiCallResult(
                success=False,
                status_code=400,
                error_code="session_not_open",
                error_message=f"Staged session {session_uid} is already {s_state or 'published'}.",
            ),
        )

    s_name = str(s_data.get("name") or s_data.get("session-name") or "").strip().lower()
    s_desc = str(s_data.get("description") or s_data.get("session-description") or "").strip().lower()
    s_app = str(s_data.get("application") or "").strip().lower()
    s_user = str(s_data.get("user-name") or s_data.get("user") or "").strip().lower()

    name_matches_expected = expected_name_clean is not None and s_name == expected_name_clean
    if expected_name_clean is not None and not name_matches_expected and not allow_foreign:
        return (
            None,
            ApiCallResult(
                success=False,
                status_code=403,
                error_code="foreign_session_refused",
                error_message=(
                    f"Refusing to adopt session {session_uid}: session name {s_name!r} "
                    f"does not match expected_session_name {expected_name_clean!r}."
                ),
            ),
        )

    is_web_api_app = s_app in ("web_api", "arodonata", "")
    has_known_identities = bool(current_user and s_user)
    known_creator_mismatch = has_known_identities and current_user != s_user
    same_creator = has_known_identities and current_user == s_user
    is_arodonata_tagged = (
        staged_entry is not None or s_name.startswith("arodonata") or s_app == "arodonata" or "arodonata" in s_desc
    )
    is_own_web_session = is_web_api_app and not known_creator_mismatch and (same_creator or is_arodonata_tagged)
    is_trusted_session = allow_foreign or (
        is_web_api_app and (staged_entry is not None or name_matches_expected or is_own_web_session)
    )
    if not is_trusted_session:
        return (
            None,
            ApiCallResult(
                success=False,
                status_code=403,
                error_code="foreign_session_refused",
                error_message=(
                    f"Refusing to adopt foreign or non-Web-API session {session_uid} "
                    f"(name={s_name!r}, application={s_app!r}, user={s_user!r}, current_user={current_user!r})."
                ),
            ),
        )

    return initial_uid, None


async def _takeover_or_switch_session(
    api: ApiPort,
    mgmt_name: str,
    domain: str | None,
    *,
    session_uid: str,
    fresh_sid: str,
    fresh_ip: str,
    initial_uid: str | None,
    force_disconnect: bool,
    known_sids: list[str],
) -> tuple[str | None, str | None, ApiCallResult]:
    """Execute non-disruptive `take-over-session` (with `switch-session` fallback) and discard helper session."""
    takeover_payload: dict[str, Any] = {"uid": session_uid}
    if force_disconnect:
        takeover_payload["disconnect-active-session"] = True
    switch_payload: dict[str, Any] = {"uid": session_uid}

    try:
        take_res = await api.api_call(
            mgmt_name,
            "take-over-session",
            takeover_payload,
            domain=domain or None,
            sid=fresh_sid,
            server_ip=fresh_ip,
        )
        if not take_res.success:
            sw_res = await api.api_call(
                mgmt_name,
                "switch-session",
                switch_payload,
                domain=domain or None,
                sid=fresh_sid,
                server_ip=fresh_ip,
            )
            if sw_res.success:
                take_res = sw_res
            else:
                take_err = take_res.error_message or take_res.error_code or f"HTTP {take_res.status_code}"
                sw_err = sw_res.error_message or sw_res.error_code or f"HTTP {sw_res.status_code}"
                combined_err = f"take-over-session failed ({take_err}); switch-session fallback failed ({sw_err})"
                take_res = take_res.model_copy(update={"error_message": combined_err})
    except ServerIdentityError:
        raise
    except Exception as exc:
        safe_err = redact_sid(str(exc), known_sids=known_sids)
        return (
            None,
            None,
            ApiCallResult(
                success=False,
                status_code=500,
                error_message=f"Failed to take over staged session {session_uid}: {safe_err}",
                error_code="takeover_failed",
            ),
        )

    if not take_res.success:
        safe_err = redact_sid(
            take_res.error_message or take_res.error_code or "take-over-session failed",
            known_sids=known_sids,
        )
        return None, None, take_res.model_copy(update={"error_message": safe_err})

    if initial_uid and initial_uid != session_uid:
        try:
            await api.api_call(
                mgmt_name,
                "discard",
                {"uid": initial_uid},
                domain=domain or None,
                sid=fresh_sid,
                server_ip=fresh_ip,
            )
        except ServerIdentityError:
            raise
        except Exception:
            pass

    return fresh_sid, fresh_ip, take_res


async def adopt_staged_session(
    *,
    api: ApiPort,
    staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo],
    mgmt_name: str,
    domain: str | None,
    session_uid: str,
    sid: str | None = None,
    server_ip: str | None = None,
    auth: AuthContext | None = None,
    force_disconnect: bool = False,
    expected_session_name: str | None = None,
    allow_foreign: bool = False,
) -> tuple[str | None, str | None, ApiCallResult]:
    """Adopt ownership of `session_uid` via direct SID reuse or verified `take-over-session`."""
    resolved_auth = auth or get_auth_context()
    dom_key = normalize_domain_key(domain)
    staged_entry = staged_registry.get((mgmt_name, dom_key, session_uid))

    candidate_sid = sid or (staged_entry.sid if staged_entry is not None else None)
    candidate_ip = server_ip or (staged_entry.server_ip if staged_entry is not None else None)
    expected_name_clean = (
        expected_session_name.strip().lower() if expected_session_name and expected_session_name.strip() else None
    )

    if candidate_sid:
        direct_outcome = await _verify_direct_sid(
            api,
            mgmt_name,
            domain,
            session_uid=session_uid,
            candidate_sid=candidate_sid,
            candidate_ip=candidate_ip,
            expected_name_clean=expected_name_clean,
            allow_foreign=allow_foreign,
        )
        if direct_outcome is not None:
            return direct_outcome

    try:
        fresh_sid, fresh_ip = await api.create_dedicated_session(
            mgmt_name,
            domain or None,
            auth=resolved_auth,
            session_name="arodonata-cpcrud-adopt",
        )
    except ServerIdentityError:
        raise
    except Exception as exc:
        safe_err = redact_sid(str(exc), known_sids=[candidate_sid] if candidate_sid else None)
        return (
            None,
            None,
            ApiCallResult(
                success=False,
                status_code=500,
                error_message=f"Failed to open session for staged takeover: {safe_err}",
                error_code="session_open_failed",
            ),
        )

    known_sids = [s for s in (candidate_sid, fresh_sid) if s]
    adopted = False
    try:
        initial_uid, failure_res = await _inspect_and_verify_provenance(
            api,
            mgmt_name,
            domain,
            session_uid=session_uid,
            fresh_sid=fresh_sid,
            fresh_ip=fresh_ip,
            resolved_auth=resolved_auth,
            staged_entry=staged_entry,
            expected_name_clean=expected_name_clean,
            allow_foreign=allow_foreign,
            known_sids=known_sids,
        )
        if failure_res is not None:
            return None, None, failure_res

        adopt_sid, adopt_ip, adopt_res = await _takeover_or_switch_session(
            api,
            mgmt_name,
            domain,
            session_uid=session_uid,
            fresh_sid=fresh_sid,
            fresh_ip=fresh_ip,
            initial_uid=initial_uid,
            force_disconnect=force_disconnect,
            known_sids=known_sids,
        )
        if adopt_sid is not None and adopt_res.success:
            adopted = True
        return adopt_sid, adopt_ip, adopt_res
    finally:
        if not adopted:
            with suppress(BaseException):
                await asyncio.shield(api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip))
