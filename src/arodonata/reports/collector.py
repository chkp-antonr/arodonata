"""Read-only session change collector (`arodonata.reports.collector`).

Implements `collect_change_report`:
- Validates `SessionScope` and `RangeScope` inputs strictly (raising `ValidationError` or
  `ChangeReportInputError` on invalid bounds or naive datetimes).
- Converts timezone-aware `from_date` / `to_date` to UTC, widens server query bounds safely
  (or omits server date parameters when `from_session` is also given), and filters returned
  sessions by exact UTC publish timestamp.
- Deduplicates sessions named across multiple scopes while preserving any attached `OwnedSession`.
- Resolves up to 200 distinct bare reference UIDs per report via read-only `show-object` calls,
  emitting a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails.
- Applies SmartConsole rule placement numbering via `apply_session_rule_placement`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import arlogi

from arodonata.core.errors import ChangeReportInputError, ServerIdentityError, redact_sid, sanitize_mapping
from arodonata.core.models.common import parse_cp_publish_timestamp, utc_now
from arodonata.core.ports import ApiPort, ObjectCachePort, RulebaseCachePort, ServiceCachePort, SyncStatePort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports._collector_changes import (
    _extract_session_user_from_changes,
    _filter_range_sessions,
    _parse_change_containers,
    _parse_rule_and_object_changes,
    _replace_resolved_uids_in_session,
)
from arodonata.reports._collector_diffs import is_bare_uid
from arodonata.reports.models import (
    ChangeReport,
    OwnedSession,
    RangeScope,
    RawResponse,
    RenderOptions,
    ReportScope,
    ReportWarning,
    SessionChangeReport,
    SessionScope,
)
from arodonata.reports.placement import apply_session_rule_placement

logger = arlogi.get_logger(__name__)

MAX_UID_LOOKUPS = 200

_TargetSessionEntry = tuple[str, str, str, dict[str, Any] | None, OwnedSession | None]


class _ReportCachePort(ObjectCachePort, ServiceCachePort, RulebaseCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by change report collection and placement numbering."""


def _collect_scope_known_sids(validated_scopes: Sequence[ReportScope]) -> list[str]:
    """Collect any caller-supplied `OwnedSession.sid` values for SID redaction during discovery."""
    sids: list[str] = []
    seen: set[str] = set()
    for scope in validated_scopes:
        if not isinstance(scope, SessionScope) or scope.owned_sessions is None:
            continue
        owned_raw = scope.owned_sessions
        candidates: list[OwnedSession]
        if isinstance(owned_raw, OwnedSession):
            candidates = [owned_raw]
        elif isinstance(owned_raw, dict):
            candidates = list(owned_raw.values())
        else:
            candidates = list(owned_raw)
        for owned in candidates:
            if owned.sid and owned.sid not in seen:
                seen.add(owned.sid)
                sids.append(owned.sid)
    return sids


async def _discover_target_sessions(
    api: ApiPort,
    validated_scopes: Sequence[ReportScope],
    warnings: list[ReportWarning],
    raw_responses: list[RawResponse],
    *,
    known_sids: Sequence[str] = (),
) -> tuple[dict[tuple[str, str, str], _TargetSessionEntry], list[tuple[str, str, str]]]:
    """Expand and deduplicate `SessionScope` and `RangeScope` entries into ordered target sessions."""
    target_sessions: dict[tuple[str, str, str], _TargetSessionEntry] = {}
    session_order: list[tuple[str, str, str]] = []

    for scope in validated_scopes:
        mgmt_name = scope.mgmt_name
        dom_name = (scope.domain or "").strip()

        if isinstance(scope, SessionScope):
            for s_uid in scope.session_uids:
                key = (mgmt_name, dom_name, s_uid)
                owned = scope.resolve_owned_session(s_uid)
                if key not in target_sessions:
                    target_sessions[key] = (mgmt_name, dom_name, s_uid, None, owned)
                    session_order.append(key)
                elif owned is not None and target_sessions[key][4] is None:
                    prev = target_sessions[key]
                    target_sessions[key] = (prev[0], prev[1], prev[2], prev[3], owned)

        elif isinstance(scope, RangeScope):
            payload: dict[str, Any] = {
                "details-level": "full",
                "view-published-sessions": True,
            }
            if scope.from_session is None:
                if scope.from_date is not None:
                    payload["from"] = (scope.from_date.astimezone(UTC) - timedelta(days=1)).isoformat()
                if scope.to_date is not None:
                    payload["to"] = (scope.to_date.astimezone(UTC) + timedelta(days=1)).isoformat()

            try:
                q_res = await api.api_query(
                    mgmt_name,
                    "show-sessions",
                    domain=dom_name or None,
                    details_level="full",
                    payload=payload,
                )
                if not q_res.success:
                    safe_fail = redact_sid(
                        q_res.error_message or q_res.code or "query failed",
                        known_sids=known_sids,
                    )
                    warnings.append(
                        ReportWarning(
                            code="session_fetch_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            message=f"Failed to list published sessions on {mgmt_name}:{dom_name}: {safe_fail}",
                        )
                    )
                    continue

                raw_responses.append(
                    RawResponse(
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        command="show-sessions",
                        payload=sanitize_mapping(payload, known_sids=known_sids),
                        response=sanitize_mapping(
                            {"total": q_res.total, "objects": q_res.objects},
                            known_sids=known_sids,
                        ),
                    )
                )

                candidate_sessions = [s for s in q_res.objects if isinstance(s, dict) and s.get("uid")]
                candidate_uids = {str(s.get("uid") or "") for s in candidate_sessions}
                if (scope.from_session and scope.from_session not in candidate_uids) or (
                    scope.to_session and scope.to_session not in candidate_uids
                ):
                    warnings.append(
                        ReportWarning(
                            code="range_session_not_found",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            message=(
                                f"Requested RangeScope session bound "
                                f"(from={scope.from_session!r}, to={scope.to_session!r}) not found in {mgmt_name}:{dom_name}."
                            ),
                        )
                    )
                for s_meta in _filter_range_sessions(candidate_sessions, scope):
                    s_uid = str(s_meta["uid"])
                    key = (mgmt_name, dom_name, s_uid)
                    if key not in target_sessions:
                        target_sessions[key] = (mgmt_name, dom_name, s_uid, s_meta, None)
                        session_order.append(key)
                    elif target_sessions[key][3] is None:
                        prev = target_sessions[key]
                        target_sessions[key] = (prev[0], prev[1], prev[2], s_meta, prev[4])
            except ServerIdentityError:
                raise
            except Exception as exc:
                safe_exc = redact_sid(str(exc), known_sids=known_sids)
                warnings.append(
                    ReportWarning(
                        code="session_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        message=f"Error listing sessions on {mgmt_name}:{dom_name}: {safe_exc}",
                    )
                )

    return target_sessions, session_order


async def _resolve_session_bare_uids(
    api: ApiPort,
    cache: _ReportCachePort,
    *,
    mgmt_name: str,
    dom_name: str,
    s_uid: str,
    owned: OwnedSession | None,
    known_sids: list[str],
    bare_uids: set[str],
    known_names: dict[str, str],
    global_resolved_uids: dict[tuple[str, str, str], str],
    uid_lookup_count: int,
    max_uid_lookups: int,
    lookup_cap_warned: bool,
    warnings: list[ReportWarning],
) -> tuple[int, bool]:
    """Resolve bare reference UIDs via local cache first and bounded `show-object` calls second."""
    unresolved_uids = [u for u in sorted(bare_uids) if u not in known_names]
    for u in unresolved_uids:
        cache_key = (mgmt_name, dom_name, u)
        if cache_key in global_resolved_uids:
            known_names[u] = global_resolved_uids[cache_key]
            continue

        cached_obj = await cache.get_object_by_uid(mgmt_name, dom_name, u)
        if cached_obj is not None and cached_obj.name:
            known_names[u] = cached_obj.name
            global_resolved_uids[cache_key] = cached_obj.name
            continue
        cached_svc = await cache.get_service_by_uid(mgmt_name, dom_name, u)
        if cached_svc is not None and cached_svc.name:
            known_names[u] = cached_svc.name
            global_resolved_uids[cache_key] = cached_svc.name
            continue

        if uid_lookup_count >= max_uid_lookups:
            if not lookup_cap_warned:
                lookup_cap_warned = True
                warnings.append(
                    ReportWarning(
                        code="names_unresolved",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=(
                            f"Reached maximum show-object lookup cap ({max_uid_lookups} UIDs); "
                            "remaining bare UIDs left unresolved."
                        ),
                        details={"cap": max_uid_lookups},
                    )
                )
            continue

        uid_lookup_count += 1
        try:
            obj_res = await api.api_call(
                mgmt_name,
                "show-object",
                {"uid": u, "details-level": "standard"},
                domain=dom_name or None,
                sid=owned.sid if owned is not None else None,
                server_ip=owned.server_ip if (owned is not None and owned.server_ip) else None,
            )
            if not obj_res.success and owned is not None:
                obj_res = await api.api_call(
                    mgmt_name,
                    "show-object",
                    {"uid": u, "details-level": "standard"},
                    domain=dom_name or None,
                )
            if obj_res.success and isinstance(obj_res.data, dict):
                inner = obj_res.data.get("object") if isinstance(obj_res.data.get("object"), dict) else obj_res.data
                resolved_name = inner.get("name") if isinstance(inner, dict) else None
                if isinstance(resolved_name, str) and resolved_name:
                    known_names[u] = resolved_name
                    global_resolved_uids[cache_key] = resolved_name
                else:
                    warnings.append(
                        ReportWarning(
                            code="names_unresolved",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"show-object returned no name for UID {u}.",
                            details={"uid": u},
                        )
                    )
            else:
                err_txt = redact_sid(
                    obj_res.error_message or obj_res.error_code or "show-object failed",
                    known_sids=known_sids,
                )
                warnings.append(
                    ReportWarning(
                        code="names_unresolved",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Failed to resolve object name for UID {u}: {err_txt}",
                        details={"uid": u},
                    )
                )
        except ServerIdentityError:
            raise
        except Exception as exc:
            safe_err = redact_sid(str(exc), known_sids=known_sids)
            warnings.append(
                ReportWarning(
                    code="names_unresolved",
                    mgmt_name=mgmt_name,
                    domain=dom_name or None,
                    session_uid=s_uid,
                    message=f"Error resolving object name for UID {u}: {safe_err}",
                    details={"uid": u},
                )
            )

    return uid_lookup_count, lookup_cap_warned


@traced
async def collect_change_report(
    api: ApiPort,
    cache: _ReportCachePort,
    scopes: Sequence[ReportScope | dict[str, Any]],
    *,
    options: RenderOptions | None = None,
    max_uid_lookups: int = MAX_UID_LOOKUPS,
    now_fn: Callable[[], datetime] = utc_now,
    refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None,
) -> ChangeReport:
    """Collect read-only session change evidence across `SessionScope` and `RangeScope` definitions."""
    if not scopes:
        raise ChangeReportInputError("collect_change_report requires at least one SessionScope or RangeScope.")

    validated_scopes: list[ReportScope] = []
    for raw_s in scopes:
        if isinstance(raw_s, (SessionScope, RangeScope)):
            validated_scopes.append(raw_s)
        elif isinstance(raw_s, dict):
            if "session_uids" in raw_s:
                validated_scopes.append(SessionScope.model_validate(raw_s))
            else:
                validated_scopes.append(RangeScope.model_validate(raw_s))
        else:
            raise ChangeReportInputError(f"Unsupported scope type: {type(raw_s).__name__}")

    span_attrs(scope_count=len(validated_scopes), max_uid_lookups=max_uid_lookups)

    warnings: list[ReportWarning] = []
    raw_responses: list[RawResponse] = []
    scope_sids = _collect_scope_known_sids(validated_scopes)
    target_sessions, session_order = await _discover_target_sessions(
        api,
        validated_scopes,
        warnings,
        raw_responses,
        known_sids=scope_sids,
    )

    uid_lookup_count = 0
    lookup_cap_warned = False
    global_resolved_uids: dict[tuple[str, str, str], str] = {}
    session_reports: list[SessionChangeReport] = []
    eff_opts = options or RenderOptions()

    for key in session_order:
        mgmt_name, dom_name, s_uid, preloaded_meta, owned = target_sessions[key]
        known_sids = [owned.sid] if owned is not None else []
        eff_sid: str | None = owned.sid if owned is not None else None
        eff_server_ip: str | None = owned.server_ip if (owned is not None and owned.server_ip) else None
        if owned is not None and owned.domain and dom_name and owned.domain.strip().lower() != dom_name.strip().lower():
            warnings.append(
                ReportWarning(
                    code="owned_session_not_used",
                    mgmt_name=mgmt_name,
                    domain=dom_name or None,
                    session_uid=s_uid,
                    message=(
                        f"OwnedSession domain {owned.domain!r} does not match target domain {dom_name!r}; "
                        "falling back to shared read-only session."
                    ),
                )
            )
            eff_sid = None
            eff_server_ip = None

        session_meta: dict[str, Any] | None = preloaded_meta
        if session_meta is None:
            for attempt_sid, attempt_ip in (
                ((eff_sid, eff_server_ip), (None, None)) if eff_sid is not None else ((None, None),)
            ):
                try:
                    s_res = await api.api_call(
                        mgmt_name,
                        "show-session",
                        {"uid": s_uid},
                        domain=dom_name or None,
                        sid=attempt_sid,
                        server_ip=attempt_ip,
                    )
                    if s_res.success and isinstance(s_res.data, dict):
                        session_meta = s_res.data
                        raw_responses.append(
                            RawResponse(
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                session_uid=s_uid,
                                command="show-session",
                                payload={"uid": s_uid},
                                response=sanitize_mapping(s_res.data, known_sids=known_sids),
                            )
                        )
                        break
                    err_txt = redact_sid(
                        s_res.error_message or s_res.error_code or "show-session failed",
                        known_sids=known_sids,
                    )
                    if attempt_sid is not None:
                        warnings.append(
                            ReportWarning(
                                code="owned_session_error",
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                session_uid=s_uid,
                                message=f"OwnedSession failed on show-session for {s_uid} ({err_txt}); retrying read-only.",
                            )
                        )
                        eff_sid = None
                        eff_server_ip = None
                        continue
                    warnings.append(
                        ReportWarning(
                            code="session_fetch_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"Failed to fetch session metadata for {s_uid}: {err_txt}",
                        )
                    )
                    session_meta = {"uid": s_uid}
                except ServerIdentityError:
                    raise
                except Exception as exc:
                    safe_err = redact_sid(str(exc), known_sids=known_sids)
                    if attempt_sid is not None:
                        warnings.append(
                            ReportWarning(
                                code="owned_session_error",
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                session_uid=s_uid,
                                message=f"OwnedSession error on show-session for {s_uid} ({safe_err}); retrying read-only.",
                            )
                        )
                        eff_sid = None
                        eff_server_ip = None
                        continue
                    warnings.append(
                        ReportWarning(
                            code="session_fetch_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"Error fetching session metadata for {s_uid}: {safe_err}",
                        )
                    )
                    session_meta = {"uid": s_uid}
        if session_meta is None:
            session_meta = {"uid": s_uid}
        s_meta_dict: dict[str, Any] = session_meta

        changes_payload: dict[str, Any] = {"to-session": s_uid, "details-level": "full"}
        ops_list: list[dict[str, Any]] = []
        changes_user_name = ""
        for attempt_sid, attempt_ip in (
            ((eff_sid, eff_server_ip), (None, None)) if eff_sid is not None else ((None, None),)
        ):
            try:
                ch_res = await api.api_call(
                    mgmt_name,
                    "show-changes",
                    changes_payload,
                    domain=dom_name or None,
                    sid=attempt_sid,
                    server_ip=attempt_ip,
                    wait_for_task=True,
                )
                if ch_res.success and isinstance(ch_res.data, dict):
                    raw_responses.append(
                        RawResponse(
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            command="show-changes",
                            payload=changes_payload,
                            response=sanitize_mapping(ch_res.data, known_sids=known_sids),
                        )
                    )
                    ops_list = _parse_change_containers(ch_res.data, session_uid=s_uid)
                    changes_user_name = _extract_session_user_from_changes(ch_res.data, session_uid=s_uid)
                    break
                err_txt = redact_sid(
                    ch_res.error_message or ch_res.error_code or "show-changes failed",
                    known_sids=known_sids,
                )
                if attempt_sid is not None:
                    warnings.append(
                        ReportWarning(
                            code="owned_session_error",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"OwnedSession failed on show-changes for {s_uid} ({err_txt}); retrying read-only.",
                        )
                    )
                    eff_sid = None
                    eff_server_ip = None
                    continue
                warnings.append(
                    ReportWarning(
                        code="changes_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Failed to fetch changes for session {s_uid}: {err_txt}",
                    )
                )
            except ServerIdentityError:
                raise
            except Exception as exc:
                safe_err = redact_sid(str(exc), known_sids=known_sids)
                if attempt_sid is not None:
                    warnings.append(
                        ReportWarning(
                            code="owned_session_error",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"OwnedSession error on show-changes for {s_uid} ({safe_err}); retrying read-only.",
                        )
                    )
                    eff_sid = None
                    eff_server_ip = None
                    continue
                warnings.append(
                    ReportWarning(
                        code="changes_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Error fetching changes for session {s_uid}: {safe_err}",
                    )
                )

        session_user_name = str(s_meta_dict.get("user-name") or s_meta_dict.get("user") or changes_user_name or "")
        known_names: dict[str, str] = {}
        bare_uids: set[str] = set()
        rule_changes, object_changes, filtered_sys_cnt = _parse_rule_and_object_changes(
            ops_list,
            known_names,
            bare_uids,
            session_user_name=session_user_name,
            include_system_objects=eff_opts.include_system_objects,
        )
        if filtered_sys_cnt > 0:
            logger.debug(
                "Filtered background 'System' maintenance objects from session change report",
                mgmt_name=mgmt_name,
                domain=dom_name or None,
                session_uid=s_uid,
                filtered_count=filtered_sys_cnt,
            )

        uid_lookup_count, lookup_cap_warned = await _resolve_session_bare_uids(
            api,
            cache,
            mgmt_name=mgmt_name,
            dom_name=dom_name,
            s_uid=s_uid,
            owned=owned,
            known_sids=known_sids,
            bare_uids=bare_uids,
            known_names=known_names,
            global_resolved_uids=global_resolved_uids,
            uid_lookup_count=uid_lookup_count,
            max_uid_lookups=max_uid_lookups,
            lookup_cap_warned=lookup_cap_warned,
            warnings=warnings,
        )

        pub_at = parse_cp_publish_timestamp(s_meta_dict.get("publish-time"))
        last_mod = parse_cp_publish_timestamp(s_meta_dict.get("last-modify-time"))
        session_state = str(s_meta_dict.get("state") or ("published" if pub_at is not None else "open"))
        session_report = SessionChangeReport(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            session_uid=s_uid,
            session_name=str(s_meta_dict.get("name") or s_meta_dict.get("session-name") or ""),
            description=str(s_meta_dict.get("description") or ""),
            user_name=session_user_name,
            state=session_state,
            published_at=pub_at,
            last_modify_time=last_mod,
            locks=int(s_meta_dict.get("locks") or 0),
            changes_count=int(
                s_meta_dict.get("changes")
                or s_meta_dict.get("number-of-published-changes")
                or (len(rule_changes) + len(object_changes))
            ),
            rule_changes=rule_changes,
            object_changes=object_changes,
            resolved_names=dict(known_names),
        )
        _replace_resolved_uids_in_session(session_report, known_names)

        await apply_session_rule_placement(
            session_report,
            api=api,
            cache=cache,
            owned_session=owned,
            warnings=warnings,
            now_fn=now_fn,
            refresh_rulebase_fn=refresh_rulebase_fn,
        )

        session_reports.append(session_report)

    return ChangeReport(
        generated_at=now_fn(),
        title=eff_opts.title,
        header_fields=dict(eff_opts.header_fields),
        sessions=session_reports,
        warnings=warnings,
        raw_responses=raw_responses,
    )


__all__ = [
    "MAX_UID_LOOKUPS",
    "collect_change_report",
    "is_bare_uid",
]
