"""Single-pass execution helpers for `Executor` (`arodonata.cpcrud._executor_pass`)."""

from __future__ import annotations

import asyncio
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime

from arodonata.core.context import (
    AuthContext,
    SessionOverlay,
    UserContext,
    WriteSession,
    get_auth_context,
    get_user_context,
    normalize_domain_key,
    update_overlay_from_command,
    write_session_context,
)
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDDomainPublishedEvent,
    CPCRUDEvent,
    CPCRUDStartedEvent,
    StagedSessionEvent,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.ports import ApiPort
from arodonata.cpcrud._executor_helpers import (
    _extract_published_session_uid,
    _is_domain_head_stale,
    _make_action_result_and_event,
    _record_runtime_failure,
    check_current_domain_head,
    resolve_allowlisted_command,
)
from arodonata.cpcrud._planner_helpers import _extract_group_references, _extract_rule_references
from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    DomainStamp,
    Outcome,
    Plan,
    PlannedAction,
    StagedSessionInfo,
)


def _invalidate_domain(
    api: ApiPort,
    on_domain_invalidated: Callable[[str, str | None], None] | None,
    mgmt_name: str,
    domain_name: str | None,
) -> None:
    if on_domain_invalidated is not None:
        on_domain_invalidated(mgmt_name, domain_name or None)
    elif hasattr(api, "invalidate_domain"):
        api.invalidate_domain(mgmt_name, domain_name or None)


async def _shielded_discard(
    api: ApiPort,
    mgmt_name: str,
    dom_name: str,
    ws: WriteSession,
) -> None:
    """Discard an uncommitted `WriteSession` under `asyncio.shield` and mark it discarded."""
    with suppress(BaseException):
        await asyncio.shield(
            api.api_call(
                mgmt_name,
                "discard",
                {},
                domain=dom_name or None,
                sid=ws.sid,
                server_ip=ws.server_ip,
            )
        )
    ws.discarded = True


async def _register_staged_session(
    api: ApiPort,
    mgmt_name: str,
    dom_name: str,
    dom_key: str,
    ws: WriteSession,
    eff_session_name: str,
    staged_sessions: list[StagedSessionInfo],
    staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo],
) -> tuple[str | None, str]:
    """Query `show-session` if needed and register `StagedSessionInfo` upon opening a staged session."""
    session_uid: str | None = ws.session_uid
    resolved_name = eff_session_name
    if not session_uid:
        try:
            s_info = await api.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=dom_name or None,
                sid=ws.sid,
                server_ip=ws.server_ip,
            )
            if s_info.success and isinstance(s_info.data, dict):
                s_uid_val = s_info.data.get("uid")
                if isinstance(s_uid_val, str) and s_uid_val:
                    session_uid = s_uid_val
                if not resolved_name and isinstance(s_info.data.get("name"), str):
                    resolved_name = str(s_info.data["name"])
        except ServerIdentityError:
            raise
        except Exception:
            pass
    staged_info = StagedSessionInfo(
        mgmt_name=mgmt_name,
        domain_name=dom_name,
        sid=ws.sid,
        server_ip=ws.server_ip,
        session_uid=session_uid,
        session_name=resolved_name,
    )
    staged_sessions.append(staged_info)
    if session_uid:
        st_key = (mgmt_name, dom_key, session_uid)
        staged_registry.pop(st_key, None)
        staged_registry[st_key] = staged_info
        while len(staged_registry) > 256:
            staged_registry.popitem(last=False)
    return session_uid, resolved_name


async def _finalize_domain_session(
    *,
    api: ApiPort,
    on_domain_invalidated: Callable[[str, str | None], None] | None,
    mgmt_name: str,
    dom_name: str,
    dom_label: str,
    ws: WriteSession,
    dom_actions: list[PlannedAction],
    stamp: DomainStamp | None,
    force: bool,
    no_publish: bool,
    keep_session: bool,
    any_write_succeeded: bool,
    session_uid: str | None,
    eff_session_name: str,
    results_by_id: dict[str, ActionResult],
    events: list[CPCRUDEvent],
    published_domains: list[str],
    published_sessions: dict[str, str],
    stale_domains: list[str],
) -> None:
    """Finalize a domain `WriteSession` via staging, discard, pre-publish staleness check, or publish."""
    if no_publish and keep_session:
        events.append(
            StagedSessionEvent(
                mgmt_name=mgmt_name,
                domain=dom_name or None,
                server_ip=ws.server_ip,
                session_uid=session_uid,
                session_name=eff_session_name,
                sid=ws.sid,
                message=f"Staged unpublished session on {dom_label} (session_uid={session_uid}).",
            )
        )
        return

    if no_publish:
        await _shielded_discard(api, mgmt_name, dom_name, ws)
        ws.overlay.clear()
        return

    if not any_write_succeeded:
        return

    if not force and stamp is not None:
        pre_pub_ok, pre_pub_uid, pre_pub_at, pre_pub_err = await check_current_domain_head(api, mgmt_name, dom_name)
        if _is_domain_head_stale(stamp, pre_pub_uid, pre_pub_at, pre_pub_ok):
            stale_domains.append(dom_label)
            stale_msg = (
                f"Plan became stale before publish for {dom_label}: expected session head "
                f"{stamp.last_session_uid!r}, got {pre_pub_uid!r} ({pre_pub_err or 'domain published concurrently'})."
            )
            await _shielded_discard(api, mgmt_name, dom_name, ws)
            ws.overlay.clear()
            for act in dom_actions:
                prev_r = results_by_id.get(act.action_id)
                if prev_r is not None:
                    results_by_id[act.action_id] = prev_r.model_copy(
                        update={
                            "outcome": Outcome.PLAN_STALE,
                            "status": "plan_stale",
                            "success": False,
                            "error": stale_msg,
                            "message": stale_msg,
                        }
                    )
            events.append(
                CPCRUDActionEvent(
                    phase="failed",
                    mgmt_name=mgmt_name,
                    domain=dom_name or None,
                    outcome=Outcome.PLAN_STALE.value,
                    error=stale_msg,
                    message=stale_msg,
                )
            )
            return

    try:
        pub_res = await api.api_call(
            mgmt_name,
            "publish",
            {},
            domain=dom_name or None,
            sid=ws.sid,
            server_ip=ws.server_ip,
            wait_for_task=True,
        )
    except ServerIdentityError:
        raise
    except Exception as exc:
        safe_pub_exc = redact_sid(str(exc), known_sids=[ws.sid])
        pub_res = ApiCallResult(
            success=False,
            status_code=500,
            error_code="publish_failed",
            error_message=safe_pub_exc,
        )
    ws.overlay.clear()
    if pub_res.success:
        ws.published = True
        published_domains.append(dom_label)
        pub_data = pub_res.data if isinstance(pub_res.data, dict) else {}
        pub_uid = _extract_published_session_uid(pub_data) or session_uid or None
        if pub_uid is None:
            head_ok, head_uid, _, _ = await check_current_domain_head(api, mgmt_name, dom_name)
            if head_ok and head_uid:
                pub_uid = head_uid
        if pub_uid:
            published_sessions[dom_label] = pub_uid
        _invalidate_domain(api, on_domain_invalidated, mgmt_name, dom_name)
        events.append(
            CPCRUDDomainPublishedEvent(
                mgmt_name=mgmt_name,
                domain=dom_name or None,
                session_uid=pub_uid,
                message=f"Published changes on {dom_label}.",
            )
        )
        return

    pub_err = redact_sid(
        pub_res.error_message or pub_res.error_code or "publish failed",
        known_sids=[ws.sid],
    )
    await _shielded_discard(api, mgmt_name, dom_name, ws)
    for act in dom_actions:
        prev_r = results_by_id.get(act.action_id)
        if prev_r is not None and prev_r.outcome in (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE):
            results_by_id[act.action_id] = prev_r.model_copy(
                update={
                    "outcome": Outcome.ERROR,
                    "status": "error",
                    "success": False,
                    "error": f"Publish failed: {pub_err}",
                    "message": f"Publish failed: {pub_err}",
                }
            )
    events.append(
        CPCRUDActionEvent(
            phase="failed",
            mgmt_name=mgmt_name,
            domain=dom_name or None,
            outcome=Outcome.ERROR.value,
            error=f"Publish failed: {pub_err}",
            message=f"Publish failed on {dom_label}: {pub_err}",
        )
    )


async def _execute_domain_batch(
    *,
    api: ApiPort,
    on_domain_invalidated: Callable[[str, str | None], None] | None,
    staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo],
    mgmt_name: str,
    dom_name: str,
    dom_actions: list[PlannedAction],
    stamp: DomainStamp | None,
    force: bool,
    no_publish: bool,
    keep_session: bool,
    resolved_auth: AuthContext | None,
    resolved_user: UserContext | None,
    eff_session_name: str,
    eff_session_desc: str | None,
    results_by_id: dict[str, ActionResult],
    events: list[CPCRUDEvent],
    published_domains: list[str],
    published_sessions: dict[str, str],
    staged_sessions: list[StagedSessionInfo],
    stale_domains: list[str],
) -> None:
    """Execute planned actions for a single `(mgmt_name, dom_name)` batch."""
    dom_label = f"{mgmt_name}:{dom_name}"

    if (
        not force
        and dom_actions
        and (any(a.is_write_action for a in dom_actions) or (stamp is not None and stamp.readable))
    ):
        readable, curr_uid, curr_pub_at, head_err = await check_current_domain_head(api, mgmt_name, dom_name)
        if _is_domain_head_stale(stamp, curr_uid, curr_pub_at, readable):
            stale_domains.append(dom_label)
            expected_uid = stamp.last_session_uid if stamp else None
            stale_msg = (
                f"Plan is stale for {dom_label}: expected session head {expected_uid!r}, "
                f"got {curr_uid!r} ({head_err or 'domain published after planning'})."
            )
            for act in dom_actions:
                res_item, ev = _make_action_result_and_event(
                    act,
                    outcome=Outcome.PLAN_STALE,
                    success=False,
                    message=stale_msg,
                    error=stale_msg,
                )
                results_by_id[act.action_id] = res_item
                events.append(ev)
            return

    if not any(a.is_write_action for a in dom_actions):
        for act in dom_actions:
            is_ok = act.outcome in (Outcome.UNCHANGED, Outcome.REUSE, Outcome.SKIPPED)
            res_item, ev = _make_action_result_and_event(
                act,
                outcome=act.outcome,
                success=is_ok,
                message=act.message,
                error=act.error,
            )
            results_by_id[act.action_id] = res_item
            events.append(ev)
        return

    try:
        sid, server_ip = await api.create_dedicated_session(
            mgmt_name,
            dom_name or None,
            auth=resolved_auth,
            session_name=eff_session_name,
            session_description=eff_session_desc,
        )
    except ServerIdentityError:
        raise
    except Exception as exc:
        safe_err = redact_sid(str(exc))
        sess_err_msg = f"Failed to open dedicated write session on {dom_label}: {safe_err}"
        for act in dom_actions:
            res_item, ev = _make_action_result_and_event(
                act,
                outcome=Outcome.ERROR,
                success=False,
                message=sess_err_msg,
                error=sess_err_msg,
            )
            results_by_id[act.action_id] = res_item
            events.append(ev)
        return

    dom_key = normalize_domain_key(dom_name or None)
    ws = WriteSession(
        mgmt_name=mgmt_name,
        domain_name=dom_key,
        sid=sid,
        server_ip=server_ip,
        session_name=eff_session_name,
        auth=resolved_auth,
        user=resolved_user,
        overlay=SessionOverlay(mgmt_name, dom_key),
    )

    runtime_failed_names: set[str] = set()
    runtime_failed_ids: set[str] = set()
    any_write_succeeded = False
    session_uid: str | None = ws.session_uid
    resolved_sess_name = eff_session_name

    if no_publish and keep_session:
        session_uid, resolved_sess_name = await _register_staged_session(
            api,
            mgmt_name,
            dom_name,
            dom_key,
            ws,
            eff_session_name,
            staged_sessions,
            staged_registry,
        )

    try:
        with write_session_context(ws):
            for act in dom_actions:
                if not act.is_write_action:
                    is_ok = act.outcome in (Outcome.UNCHANGED, Outcome.REUSE, Outcome.SKIPPED)
                    if not is_ok:
                        _record_runtime_failure(act, runtime_failed_names, runtime_failed_ids)
                    res_item, ev = _make_action_result_and_event(
                        act,
                        outcome=act.outcome,
                        success=is_ok,
                        message=act.message,
                        error=act.error,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(ev)
                    continue

                broken_deps = [d for d in act.depends_on if d in runtime_failed_ids or d in runtime_failed_names]
                if act.object_type in ("group", "service-group"):
                    grp_refs = _extract_group_references(act.desired_spec)
                    broken_deps.extend(sorted(r for r in grp_refs if r in runtime_failed_names))
                elif act.object_type.endswith("-rule"):
                    rule_refs = _extract_rule_references(act.desired_spec)
                    broken_deps.extend(sorted(r for r in rule_refs if r in runtime_failed_names))

                if broken_deps:
                    dep_err = f"Skipped due to failed dependency at runtime: {', '.join(dict.fromkeys(broken_deps))}"
                    _record_runtime_failure(act, runtime_failed_names, runtime_failed_ids)
                    res_item, ev = _make_action_result_and_event(
                        act,
                        outcome=Outcome.SKIPPED_DEPENDENCY,
                        success=False,
                        message=dep_err,
                        error=dep_err,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(ev)
                    continue

                cmd = resolve_allowlisted_command(act)
                events.append(
                    CPCRUDActionEvent(
                        phase="action_started",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        action_id=act.action_id,
                        operation=act.operation,
                        object_type=act.object_type,
                        object_name=act.name,
                        outcome=act.outcome.value,
                        message=f"Executing {cmd} for {act.name!r}.",
                    )
                )
                try:
                    call_res = await api.api_call(
                        mgmt_name,
                        cmd,
                        dict(act.payload),
                        domain=dom_name or None,
                        sid=ws.sid,
                        server_ip=ws.server_ip,
                    )
                except ServerIdentityError:
                    raise
                except Exception as exc:
                    safe_err = redact_sid(str(exc), known_sids=[ws.sid])
                    _record_runtime_failure(act, runtime_failed_names, runtime_failed_ids)
                    res_item, ev = _make_action_result_and_event(
                        act,
                        outcome=Outcome.ERROR,
                        success=False,
                        command=cmd,
                        message=safe_err,
                        error=safe_err,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(ev)
                    continue

                if not call_res.success:
                    raw_err = call_res.error_message or call_res.error_code or f"HTTP {call_res.status_code}"
                    safe_err = redact_sid(raw_err, known_sids=[ws.sid])
                    _record_runtime_failure(act, runtime_failed_names, runtime_failed_ids)
                    res_item, ev = _make_action_result_and_event(
                        act,
                        outcome=Outcome.ERROR,
                        success=False,
                        command=cmd,
                        message=safe_err,
                        error=safe_err,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(ev)
                    continue

                update_overlay_from_command(ws.overlay, cmd, act.payload, call_res)
                any_write_succeeded = True
                resp_dict = call_res.data if isinstance(call_res.data, dict) else {}
                returned_uid = str(resp_dict.get("uid") or act.target_uid or "") or None
                res_item, ev = _make_action_result_and_event(
                    act,
                    outcome=act.outcome,
                    success=True,
                    command=cmd,
                    target_uid=returned_uid,
                    response_data=resp_dict,
                    message=act.message,
                )
                results_by_id[act.action_id] = res_item
                events.append(ev)

            await _finalize_domain_session(
                api=api,
                on_domain_invalidated=on_domain_invalidated,
                mgmt_name=mgmt_name,
                dom_name=dom_name,
                dom_label=dom_label,
                ws=ws,
                dom_actions=dom_actions,
                stamp=stamp,
                force=force,
                no_publish=no_publish,
                keep_session=keep_session,
                any_write_succeeded=any_write_succeeded,
                session_uid=session_uid,
                eff_session_name=resolved_sess_name,
                results_by_id=results_by_id,
                events=events,
                published_domains=published_domains,
                published_sessions=published_sessions,
                stale_domains=stale_domains,
            )
    except BaseException:
        if not (no_publish and keep_session) and not ws.published and not ws.discarded:
            await _shielded_discard(api, mgmt_name, dom_name, ws)
        raise
    finally:
        if not (no_publish and keep_session):
            ws.overlay.clear()
            if not ws.published and not ws.discarded:
                await _shielded_discard(api, mgmt_name, dom_name, ws)
            with suppress(BaseException):
                await asyncio.shield(api.logout_sid(mgmt_name, ws.sid, server_ip=ws.server_ip))


async def execute_single_pass(
    *,
    api: ApiPort,
    now_fn: Callable[[], datetime],
    on_domain_invalidated: Callable[[str, str | None], None] | None,
    staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo],
    plan: Plan,
    force: bool = False,
    no_publish: bool = False,
    keep_session: bool = False,
    auth: AuthContext | None = None,
    user: UserContext | None = None,
    session_name: str | None = None,
    session_description: str | None = None,
) -> tuple[list[CPCRUDEvent], ApplyReport]:
    """Execute one pass of `plan`, collecting both `CPCRUDEvent` items and the pass `ApplyReport`."""
    started_at = now_fn()
    events: list[CPCRUDEvent] = [
        CPCRUDStartedEvent(
            message=f"Starting CPCRUD apply across {len(plan.actions)} planned action(s).",
            details={
                "total_actions": len(plan.actions),
                "write_actions": len(plan.write_actions),
                "force": force,
                "no_publish": no_publish,
                "keep_session": keep_session,
            },
        )
    ]
    results_by_id: dict[str, ActionResult] = {}
    published_domains: list[str] = []
    published_sessions: dict[str, str] = {}
    staged_sessions: list[StagedSessionInfo] = []
    stale_domains: list[str] = []

    domain_groups: dict[tuple[str, str], list[PlannedAction]] = defaultdict(list)
    domain_order: list[tuple[str, str]] = []
    for act in plan.actions:
        if act.is_write_action:
            resolve_allowlisted_command(act)
        key = (act.mgmt_name, act.domain_name)
        if key not in domain_groups:
            domain_order.append(key)
        domain_groups[key].append(act)

    resolved_auth = auth or get_auth_context()
    resolved_user = user or get_user_context()
    eff_session_name = (
        session_name
        or (resolved_user.session_name if resolved_user else None)
        or ("arodonata-cpcrud-staged" if (no_publish and keep_session) else "arodonata-cpcrud")
    )
    eff_session_desc = session_description or (resolved_user.session_description if resolved_user else None)

    for mgmt_name, dom_name in domain_order:
        await _execute_domain_batch(
            api=api,
            on_domain_invalidated=on_domain_invalidated,
            staged_registry=staged_registry,
            mgmt_name=mgmt_name,
            dom_name=dom_name,
            dom_actions=domain_groups[(mgmt_name, dom_name)],
            stamp=plan.domain_stamps.get(f"{mgmt_name}:{dom_name}"),
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            resolved_auth=resolved_auth,
            resolved_user=resolved_user,
            eff_session_name=eff_session_name,
            eff_session_desc=eff_session_desc,
            results_by_id=results_by_id,
            events=events,
            published_domains=published_domains,
            published_sessions=published_sessions,
            staged_sessions=staged_sessions,
            stale_domains=stale_domains,
        )

    ordered_results = [results_by_id[a.action_id] for a in plan.actions if a.action_id in results_by_id]
    report = ApplyReport(
        started_at=started_at,
        completed_at=now_fn(),
        results=ordered_results,
        published_domains=published_domains,
        published_sessions=published_sessions,
        staged_sessions=staged_sessions,
        stale_domains=stale_domains,
    )
    return events, report
