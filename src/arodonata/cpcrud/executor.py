"""Dedicated-session CPCRUD executor (`src/arodonata/cpcrud/executor.py`).

Implements `Executor`:
- Paired `await apply(plan, ...) -> ApplyReport` and `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`.
- Verifies each target domain's current `show-last-published-session` against the `DomainStamp`
  recorded in `Plan` when `force=False`; if drifted or unreadable, marks all actions in that
  domain as `Outcome.PLAN_STALE` and performs zero writes in that domain.
- Executes planned write actions inside an isolated `WriteSession` per `(mgmt_name, domain_name)`,
  updating `SessionOverlay` as each action succeeds.
- Supports `no_publish=True, keep_session=True` staging mode, leaving the dedicated session open,
  recording `StagedSessionInfo` in `ApplyReport.staged_sessions`, and emitting `StagedSessionEvent`.
- Calls `invalidate_domain(mgmt_name, domain_name)` after publish and supports `retry_remaining > 0`
  passes that re-run failed/remaining actions and fold their `ApplyReport` into the cumulative report.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict, defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from datetime import datetime
from typing import Any

from arodonata.adapters.checkpoint.client import _update_overlay_from_command
from arodonata.adapters.checkpoint.sessions import normalize_domain_key
from arodonata.core.context import (
    AuthContext,
    SessionOverlay,
    UserContext,
    WriteSession,
    get_auth_context,
    get_user_context,
    write_session_context,
)
from arodonata.core.errors import ServerIdentityError, ValidationError, redact_sid
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDCompletedEvent,
    CPCRUDDomainPublishedEvent,
    CPCRUDEvent,
    CPCRUDStartedEvent,
    StagedSessionEvent,
)
from arodonata.core.models.common import ApiCallResult, to_naive_utc, utc_now
from arodonata.core.ports import ApiPort
from arodonata.core.services.sync_coordinator import parse_cp_publish_timestamp
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    DomainStamp,
    Outcome,
    Plan,
    PlannedAction,
    StagedSessionInfo,
)
from arodonata.cpcrud.planner import _extract_group_references, _extract_rule_references
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES

EXECUTABLE_RULE_TYPES: frozenset[str] = frozenset(
    {
        "access-rule",
        "nat-rule",
        "https-rule",
        "threat-rule",
    }
)

ALLOWED_COMMAND_MAP: dict[tuple[str, Outcome], str] = {
    **{(t, Outcome.CREATE): f"add-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
    **{(t, Outcome.UPDATE): f"set-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
    **{(t, Outcome.DELETE): f"delete-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
}


def resolve_allowlisted_command(action: PlannedAction) -> str:
    """Derive the canonical Web API write command for `action` from the strict `(object_type, outcome)` allowlist."""
    expected = ALLOWED_COMMAND_MAP.get((action.object_type, action.outcome))
    if expected is None:
        raise ValidationError(
            f"Unsupported CPCRUD action pair ({action.object_type!r}, {action.outcome.value!r}) for action {action.action_id!r}."
        )
    if action.command and action.command != expected:
        raise ValidationError(
            f"PlannedAction.command {action.command!r} disagrees with allowlisted command {expected!r} "
            f"for ({action.object_type!r}, {action.outcome.value!r})."
        )
    return expected


def _is_domain_head_stale(
    stamp: DomainStamp | None,
    current_uid: str | None,
    current_published_at: datetime | None,
    head_readable: bool,
) -> bool:
    """Return `True` if a domain's current published head cannot be read or drifted since `stamp`."""
    if not head_readable or stamp is None or not stamp.readable:
        return True
    if stamp.last_session_uid is not None:
        if current_uid != stamp.last_session_uid:
            return True
    elif current_uid is not None:
        return True

    if stamp.last_published_at is not None:
        return to_naive_utc(current_published_at) != to_naive_utc(stamp.last_published_at)
    return current_published_at is not None


class Executor:
    """Executes `Plan` actions in an isolated `WriteSession` per `(mgmt_name, domain_name)`."""

    def __init__(
        self,
        *,
        api: ApiPort,
        on_domain_invalidated: Callable[[str, str | None], None] | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._api = api
        self._on_domain_invalidated = on_domain_invalidated
        self._now = now_fn
        self._last_report: ApplyReport | None = None
        self._last_staged_publish_result: ApiCallResult | None = None
        self._staged_sessions: OrderedDict[tuple[str, str, str], StagedSessionInfo] = OrderedDict()

    @property
    def last_report(self) -> ApplyReport | None:
        """Return the `ApplyReport` produced by the most recent `stream_apply` or `apply` run."""
        return self._last_report

    def _invalidate_domain(self, mgmt_name: str, domain_name: str | None) -> None:
        if self._on_domain_invalidated is not None:
            self._on_domain_invalidated(mgmt_name, domain_name or None)
        elif hasattr(self._api, "invalidate_domain"):
            self._api.invalidate_domain(mgmt_name, domain_name or None)

    async def _check_current_domain_head(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> tuple[bool, str | None, datetime | None, str | None]:
        """Read `show-last-published-session` and return `(readable, uid, published_at, error)`."""
        try:
            res = await self._api.api_call(
                mgmt_name,
                "show-last-published-session",
                {},
                domain=domain_name or None,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            return False, None, None, str(exc)

        if not res.success:
            return (
                False,
                None,
                None,
                res.error_message or res.error_code or f"HTTP {res.status_code}",
            )

        data = res.data if isinstance(res.data, dict) else {}
        uid_raw = data.get("uid")
        uid_str = str(uid_raw).strip() if isinstance(uid_raw, str) and uid_raw.strip() else None
        pub_at = parse_cp_publish_timestamp(data.get("publish-time") or data.get("last-modify-time"))
        return True, uid_str, pub_at, None

    async def _stream_single_pass(
        self,
        plan: Plan,
        *,
        force: bool = False,
        no_publish: bool = False,
        keep_session: bool = False,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[list[CPCRUDEvent], ApplyReport]:
        """Execute one pass of `plan`, collecting both `CPCRUDEvent` items and the pass `ApplyReport`."""
        started_at = self._now()
        events: list[CPCRUDEvent] = []
        results_by_id: dict[str, ActionResult] = {}
        published_domains: list[str] = []
        published_sessions: dict[str, str] = {}
        staged_sessions: list[StagedSessionInfo] = []
        stale_domains: list[str] = []

        events.append(
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
        )

        # Group actions by (mgmt_name, domain_name) in order of first appearance
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
            dom_actions = domain_groups[(mgmt_name, dom_name)]
            dom_label = f"{mgmt_name}:{dom_name}"
            stamp = plan.domain_stamps.get(dom_label)

            # 1. Verify domain head has not drifted since plan() when force=False
            # Checked whenever a domain has actions and a stamp was recorded (or failed to be recorded)
            if (
                not force
                and dom_actions
                and (any(a.is_write_action for a in dom_actions) or (stamp is not None and stamp.readable))
            ):
                readable, curr_uid, curr_pub_at, head_err = await self._check_current_domain_head(mgmt_name, dom_name)
                if _is_domain_head_stale(stamp, curr_uid, curr_pub_at, readable):
                    stale_domains.append(dom_label)
                    expected_uid = stamp.last_session_uid if stamp else None
                    stale_msg = (
                        f"Plan is stale for {dom_label}: expected session head {expected_uid!r}, "
                        f"got {curr_uid!r} ({head_err or 'domain published after planning'})."
                    )
                    for act in dom_actions:
                        res_item = ActionResult(
                            action_id=act.action_id,
                            mgmt_name=mgmt_name,
                            domain_name=dom_name,
                            operation=act.operation,
                            object_type=act.object_type,
                            name=act.name,
                            resolved_name=act.resolved_name,
                            target_uid=act.target_uid,
                            planned_outcome=act.outcome,
                            outcome=Outcome.PLAN_STALE,
                            status="plan_stale",
                            success=False,
                            command=act.command,
                            prior_state=act.prior_state,
                            message=stale_msg,
                            error=stale_msg,
                        )
                        results_by_id[act.action_id] = res_item
                        events.append(
                            CPCRUDActionEvent(
                                phase="action_failed",
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                action_id=act.action_id,
                                operation=act.operation,
                                object_type=act.object_type,
                                object_name=act.name,
                                outcome=Outcome.PLAN_STALE.value,
                                error=stale_msg,
                                message=stale_msg,
                            )
                        )
                    continue

            # 2. If domain has zero write actions (all UNCHANGED / REUSE / ERROR / SKIPPED_DEPENDENCY),
            # emit results directly without opening a WriteSession (unless keep_session staging was requested with writes).
            has_writes = any(a.is_write_action for a in dom_actions)
            if not has_writes:
                for act in dom_actions:
                    is_ok = act.outcome in (Outcome.UNCHANGED, Outcome.REUSE, Outcome.SKIPPED)
                    res_item = ActionResult(
                        action_id=act.action_id,
                        mgmt_name=mgmt_name,
                        domain_name=dom_name,
                        operation=act.operation,
                        object_type=act.object_type,
                        name=act.name,
                        resolved_name=act.resolved_name,
                        target_uid=act.target_uid,
                        planned_outcome=act.outcome,
                        outcome=act.outcome,
                        status=act.outcome.value,
                        success=is_ok,
                        command=act.command,
                        prior_state=act.prior_state,
                        message=act.message,
                        error=act.error,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(
                        CPCRUDActionEvent(
                            phase="action_completed" if is_ok else "action_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            action_id=act.action_id,
                            operation=act.operation,
                            object_type=act.object_type,
                            object_name=act.name,
                            outcome=act.outcome.value,
                            error=act.error,
                            message=act.message,
                        )
                    )
                continue

            # 3. Open an isolated dedicated WriteSession for this (mgmt_name, domain_name)
            try:
                sid, server_ip = await self._api.create_dedicated_session(
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
                    res_item = ActionResult(
                        action_id=act.action_id,
                        mgmt_name=mgmt_name,
                        domain_name=dom_name,
                        operation=act.operation,
                        object_type=act.object_type,
                        name=act.name,
                        resolved_name=act.resolved_name,
                        target_uid=act.target_uid,
                        planned_outcome=act.outcome,
                        outcome=Outcome.ERROR,
                        status="error",
                        success=False,
                        command=act.command,
                        prior_state=act.prior_state,
                        message=sess_err_msg,
                        error=sess_err_msg,
                    )
                    results_by_id[act.action_id] = res_item
                    events.append(
                        CPCRUDActionEvent(
                            phase="action_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            action_id=act.action_id,
                            operation=act.operation,
                            object_type=act.object_type,
                            object_name=act.name,
                            outcome=Outcome.ERROR.value,
                            error=sess_err_msg,
                            message=sess_err_msg,
                        )
                    )
                continue

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
            staged_info: StagedSessionInfo | None = None

            if no_publish and keep_session:
                if not session_uid:
                    with suppress(Exception):
                        s_info = await self._api.api_call(
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
                            if not eff_session_name and isinstance(s_info.data.get("name"), str):
                                eff_session_name = str(s_info.data["name"])
                staged_info = StagedSessionInfo(
                    mgmt_name=mgmt_name,
                    domain_name=dom_name,
                    sid=ws.sid,
                    server_ip=ws.server_ip,
                    session_uid=session_uid,
                    session_name=eff_session_name,
                )
                staged_sessions.append(staged_info)
                if session_uid:
                    st_key = (mgmt_name, dom_key, session_uid)
                    self._staged_sessions.pop(st_key, None)
                    self._staged_sessions[st_key] = staged_info
                    while len(self._staged_sessions) > 256:
                        self._staged_sessions.popitem(last=False)

            try:
                with write_session_context(ws):
                    for act in dom_actions:
                        # Non-write actions (UNCHANGED, REUSE, ERROR, SKIPPED_DEPENDENCY from planning)
                        if not act.is_write_action:
                            is_ok = act.outcome in (Outcome.UNCHANGED, Outcome.REUSE, Outcome.SKIPPED)
                            if not is_ok:
                                if act.requested_name:
                                    runtime_failed_names.add(act.requested_name)
                                if act.name:
                                    runtime_failed_names.add(act.name)
                                runtime_failed_ids.add(act.action_id)
                            res_item = ActionResult(
                                action_id=act.action_id,
                                mgmt_name=mgmt_name,
                                domain_name=dom_name,
                                operation=act.operation,
                                object_type=act.object_type,
                                name=act.name,
                                resolved_name=act.resolved_name,
                                target_uid=act.target_uid,
                                planned_outcome=act.outcome,
                                outcome=act.outcome,
                                status=act.outcome.value,
                                success=is_ok,
                                command=act.command,
                                prior_state=act.prior_state,
                                message=act.message,
                                error=act.error,
                            )
                            results_by_id[act.action_id] = res_item
                            events.append(
                                CPCRUDActionEvent(
                                    phase="action_completed" if is_ok else "action_failed",
                                    mgmt_name=mgmt_name,
                                    domain=dom_name or None,
                                    action_id=act.action_id,
                                    operation=act.operation,
                                    object_type=act.object_type,
                                    object_name=act.name,
                                    outcome=act.outcome.value,
                                    error=act.error,
                                    message=act.message,
                                )
                            )
                            continue

                        # Check if a runtime failure on an earlier action breaks this action's dependencies
                        broken_runtime_deps = [
                            d for d in act.depends_on if d in runtime_failed_ids or d in runtime_failed_names
                        ]
                        if act.object_type in ("group", "service-group"):
                            grp_refs = _extract_group_references(act.desired_spec)
                            broken_runtime_deps.extend(sorted(r for r in grp_refs if r in runtime_failed_names))
                        elif act.object_type.endswith("-rule"):
                            rule_refs = _extract_rule_references(act.desired_spec)
                            broken_runtime_deps.extend(sorted(r for r in rule_refs if r in runtime_failed_names))

                        if broken_runtime_deps:
                            dep_err = f"Skipped due to failed dependency at runtime: {', '.join(dict.fromkeys(broken_runtime_deps))}"
                            if act.requested_name:
                                runtime_failed_names.add(act.requested_name)
                            if act.name:
                                runtime_failed_names.add(act.name)
                            runtime_failed_ids.add(act.action_id)
                            res_item = ActionResult(
                                action_id=act.action_id,
                                mgmt_name=mgmt_name,
                                domain_name=dom_name,
                                operation=act.operation,
                                object_type=act.object_type,
                                name=act.name,
                                resolved_name=act.resolved_name,
                                target_uid=act.target_uid,
                                planned_outcome=act.outcome,
                                outcome=Outcome.SKIPPED_DEPENDENCY,
                                status="skipped_dependency",
                                success=False,
                                command=act.command,
                                prior_state=act.prior_state,
                                message=dep_err,
                                error=dep_err,
                            )
                            results_by_id[act.action_id] = res_item
                            events.append(
                                CPCRUDActionEvent(
                                    phase="action_failed",
                                    mgmt_name=mgmt_name,
                                    domain=dom_name or None,
                                    action_id=act.action_id,
                                    operation=act.operation,
                                    object_type=act.object_type,
                                    object_name=act.name,
                                    outcome=Outcome.SKIPPED_DEPENDENCY.value,
                                    error=dep_err,
                                    message=dep_err,
                                )
                            )
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
                            call_res = await self._api.api_call(
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
                            if act.requested_name:
                                runtime_failed_names.add(act.requested_name)
                            if act.name:
                                runtime_failed_names.add(act.name)
                            runtime_failed_ids.add(act.action_id)
                            res_item = ActionResult(
                                action_id=act.action_id,
                                mgmt_name=mgmt_name,
                                domain_name=dom_name,
                                operation=act.operation,
                                object_type=act.object_type,
                                name=act.name,
                                resolved_name=act.resolved_name,
                                target_uid=act.target_uid,
                                planned_outcome=act.outcome,
                                outcome=Outcome.ERROR,
                                status="error",
                                success=False,
                                command=cmd,
                                prior_state=act.prior_state,
                                message=safe_err,
                                error=safe_err,
                            )
                            results_by_id[act.action_id] = res_item
                            events.append(
                                CPCRUDActionEvent(
                                    phase="action_failed",
                                    mgmt_name=mgmt_name,
                                    domain=dom_name or None,
                                    action_id=act.action_id,
                                    operation=act.operation,
                                    object_type=act.object_type,
                                    object_name=act.name,
                                    outcome=Outcome.ERROR.value,
                                    error=safe_err,
                                    message=safe_err,
                                )
                            )
                            continue

                        if not call_res.success:
                            raw_err = call_res.error_message or call_res.error_code or f"HTTP {call_res.status_code}"
                            safe_err = redact_sid(raw_err, known_sids=[ws.sid])
                            if act.requested_name:
                                runtime_failed_names.add(act.requested_name)
                            if act.name:
                                runtime_failed_names.add(act.name)
                            runtime_failed_ids.add(act.action_id)
                            res_item = ActionResult(
                                action_id=act.action_id,
                                mgmt_name=mgmt_name,
                                domain_name=dom_name,
                                operation=act.operation,
                                object_type=act.object_type,
                                name=act.name,
                                resolved_name=act.resolved_name,
                                target_uid=act.target_uid,
                                planned_outcome=act.outcome,
                                outcome=Outcome.ERROR,
                                status="error",
                                success=False,
                                command=cmd,
                                prior_state=act.prior_state,
                                message=safe_err,
                                error=safe_err,
                            )
                            results_by_id[act.action_id] = res_item
                            events.append(
                                CPCRUDActionEvent(
                                    phase="action_failed",
                                    mgmt_name=mgmt_name,
                                    domain=dom_name or None,
                                    action_id=act.action_id,
                                    operation=act.operation,
                                    object_type=act.object_type,
                                    object_name=act.name,
                                    outcome=Outcome.ERROR.value,
                                    error=safe_err,
                                    message=safe_err,
                                )
                            )
                            continue

                        # Update SessionOverlay as each action succeeds
                        _update_overlay_from_command(ws.overlay, cmd, act.payload, call_res)
                        any_write_succeeded = True
                        resp_dict = call_res.data if isinstance(call_res.data, dict) else {}
                        returned_uid = str(resp_dict.get("uid") or act.target_uid or "") or None

                        res_item = ActionResult(
                            action_id=act.action_id,
                            mgmt_name=mgmt_name,
                            domain_name=dom_name,
                            operation=act.operation,
                            object_type=act.object_type,
                            name=act.name,
                            resolved_name=act.resolved_name,
                            target_uid=returned_uid,
                            planned_outcome=act.outcome,
                            outcome=act.outcome,
                            status=act.outcome.value,
                            success=True,
                            command=cmd,
                            response_data=resp_dict,
                            prior_state=act.prior_state,
                            message=act.message,
                        )
                        results_by_id[act.action_id] = res_item
                        events.append(
                            CPCRUDActionEvent(
                                phase="action_completed",
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                action_id=act.action_id,
                                operation=act.operation,
                                object_type=act.object_type,
                                object_name=act.name,
                                outcome=act.outcome.value,
                                message=act.message,
                            )
                        )

                    # 4. Handle session finalization: keep_session staging vs publish vs discard
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
                    elif no_publish:
                        with suppress(Exception):
                            await asyncio.shield(
                                self._api.api_call(
                                    mgmt_name,
                                    "discard",
                                    {},
                                    domain=dom_name or None,
                                    sid=ws.sid,
                                    server_ip=ws.server_ip,
                                )
                            )
                        ws.discarded = True
                        ws.overlay.clear()
                    elif any_write_succeeded:
                        # Re-verify domain head immediately prior to publish when force=False
                        if not force and stamp is not None:
                            pre_pub_ok, pre_pub_uid, pre_pub_at, pre_pub_err = await self._check_current_domain_head(
                                mgmt_name, dom_name
                            )
                            if _is_domain_head_stale(stamp, pre_pub_uid, pre_pub_at, pre_pub_ok):
                                stale_domains.append(dom_label)
                                expected_uid = stamp.last_session_uid if stamp else None
                                stale_msg = (
                                    f"Plan became stale before publish for {dom_label}: expected session head "
                                    f"{expected_uid!r}, got {pre_pub_uid!r} ({pre_pub_err or 'domain published concurrently'})."
                                )
                                with suppress(Exception):
                                    await asyncio.shield(
                                        self._api.api_call(
                                            mgmt_name,
                                            "discard",
                                            {},
                                            domain=dom_name or None,
                                            sid=ws.sid,
                                            server_ip=ws.server_ip,
                                        )
                                    )
                                ws.discarded = True
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
                                continue

                        # Query session UID if needed before or from publish
                        try:
                            pub_res = await self._api.api_call(
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
                            pub_uid = str(pub_data.get("uid") or session_uid or "") or None
                            if pub_uid:
                                published_sessions[dom_label] = pub_uid
                            self._invalidate_domain(mgmt_name, dom_name)
                            events.append(
                                CPCRUDDomainPublishedEvent(
                                    mgmt_name=mgmt_name,
                                    domain=dom_name or None,
                                    session_uid=pub_uid,
                                    message=f"Published changes on {dom_label}.",
                                )
                            )
                        else:
                            pub_err = redact_sid(
                                pub_res.error_message or pub_res.error_code or "publish failed",
                                known_sids=[ws.sid],
                            )
                            with suppress(Exception):
                                await asyncio.shield(
                                    self._api.api_call(
                                        mgmt_name,
                                        "discard",
                                        {},
                                        domain=dom_name or None,
                                        sid=ws.sid,
                                        server_ip=ws.server_ip,
                                    )
                                )
                            ws.discarded = True
                            # Mark write actions in this domain as failed due to publish error
                            for act in dom_actions:
                                prev_r = results_by_id.get(act.action_id)
                                if prev_r is not None and prev_r.outcome in (
                                    Outcome.CREATE,
                                    Outcome.UPDATE,
                                    Outcome.DELETE,
                                ):
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
            except BaseException:
                if not (no_publish and keep_session) and not ws.published and not ws.discarded:
                    with suppress(BaseException):
                        await asyncio.shield(
                            self._api.api_call(
                                mgmt_name,
                                "discard",
                                {},
                                domain=dom_name or None,
                                sid=ws.sid,
                                server_ip=ws.server_ip,
                            )
                        )
                    ws.discarded = True
                raise
            finally:
                # Only keep session open when both no_publish=True and keep_session=True
                if not (no_publish and keep_session):
                    ws.overlay.clear()
                    if not ws.published and not ws.discarded:
                        with suppress(BaseException):
                            await asyncio.shield(
                                self._api.api_call(
                                    mgmt_name,
                                    "discard",
                                    {},
                                    domain=dom_name or None,
                                    sid=ws.sid,
                                    server_ip=ws.server_ip,
                                )
                            )
                        ws.discarded = True
                    with suppress(BaseException):
                        await asyncio.shield(self._api.logout_sid(mgmt_name, ws.sid, server_ip=ws.server_ip))

        ordered_results = [results_by_id[a.action_id] for a in plan.actions if a.action_id in results_by_id]
        completed_at = self._now()
        report = ApplyReport(
            started_at=started_at,
            completed_at=completed_at,
            results=ordered_results,
            published_domains=published_domains,
            published_sessions=published_sessions,
            staged_sessions=staged_sessions,
            stale_domains=stale_domains,
        )
        return events, report

    async def stream_apply(
        self,
        plan: Plan,
        *,
        force: bool = False,
        no_publish: bool = False,
        keep_session: bool = False,
        retry_remaining: int = 0,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Execute `plan` in a dedicated `WriteSession` per domain and yield `CPCRUDEvent` updates."""
        events, cumulative_report = await self._stream_single_pass(
            plan,
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
        )
        for ev in events:
            yield ev

        # Handle retry_remaining > 0 for failed/remaining write actions (when not PLAN_STALE)
        max_retries = max(0, int(retry_remaining))
        retry_pass = 0
        current_stamps = dict(plan.domain_stamps)
        last_pass_published_sessions = dict(cumulative_report.published_sessions)

        while retry_pass < max_retries and not cumulative_report.stale_domains:
            failed_ids = {
                r.action_id
                for r in cumulative_report.results
                if not r.success and r.planned_outcome in (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE)
            }
            if not failed_ids:
                break

            # Advance domain_stamps ONLY for domains that THIS executor itself published in the previous pass
            for dom_label, own_pub_uid in last_pass_published_sessions.items():
                if dom_label in current_stamps:
                    m_part, _, d_part = dom_label.partition(":")
                    r_ok, r_uid, r_pub_at, _ = await self._check_current_domain_head(m_part, d_part)
                    if r_ok and r_uid == own_pub_uid:
                        current_stamps[dom_label] = current_stamps[dom_label].model_copy(
                            update={
                                "last_session_uid": r_uid,
                                "last_published_at": r_pub_at,
                            }
                        )

            retry_pass += 1
            remaining_actions = [a for a in plan.actions if a.action_id in failed_ids]
            retry_plan = Plan(
                created_at=self._now(),
                domain_stamps=dict(current_stamps),
                actions=remaining_actions,
                name_resolutions=plan.name_resolutions,
                template=plan.template,
            )

            # Retry passes honor the caller's force flag (never forcing force=True automatically)
            r_events, r_report = await self._stream_single_pass(
                retry_plan,
                force=force,
                no_publish=no_publish,
                keep_session=keep_session,
                auth=auth,
                user=user,
                session_name=session_name,
                session_description=session_description,
            )
            for ev in r_events:
                if not isinstance(ev, (CPCRUDStartedEvent, CPCRUDCompletedEvent)):
                    yield ev

            last_pass_published_sessions = dict(r_report.published_sessions)
            _fold_retry_report(cumulative_report, r_report)

        succeeded_cnt = sum(1 for r in cumulative_report.results if r.success)
        failed_cnt = cumulative_report.failed_count
        skipped_cnt = sum(
            1 for r in cumulative_report.results if r.outcome in (Outcome.SKIPPED, Outcome.SKIPPED_DEPENDENCY)
        )

        self._last_report = cumulative_report
        yield CPCRUDCompletedEvent(
            phase="completed" if failed_cnt == 0 else "failed",
            succeeded_count=succeeded_cnt,
            failed_count=failed_cnt,
            skipped_count=skipped_cnt,
            message=(f"Completed CPCRUD apply: {succeeded_cnt} succeeded, {failed_cnt} failed, {skipped_cnt} skipped."),
            details={
                "published_domains": list(cumulative_report.published_domains),
                "stale_domains": list(cumulative_report.stale_domains),
                "retry_passes": cumulative_report.retry_passes,
            },
        )

    @traced
    async def apply(
        self,
        plan: Plan,
        *,
        force: bool = False,
        no_publish: bool = False,
        keep_session: bool = False,
        retry_remaining: int = 0,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> ApplyReport:
        """Execute `plan` and return the final `ApplyReport`."""
        span_attrs(
            action_count=len(plan.actions),
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            retry_remaining=retry_remaining,
        )
        async for _ in self.stream_apply(
            plan,
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            retry_remaining=retry_remaining,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
        ):
            pass
        assert self._last_report is not None
        return self._last_report

    async def _adopt_staged_session(
        self,
        mgmt_name: str,
        domain: str | None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
    ) -> tuple[str | None, str | None, ApiCallResult]:
        """Adopt ownership of `session_uid` via direct SID reuse or verified `take-over-session` (with fallback to `switch-session`)."""
        resolved_auth = auth or get_auth_context()
        dom_key = normalize_domain_key(domain)
        staged_entry = self._staged_sessions.get((mgmt_name, dom_key, session_uid))

        candidate_sid = sid or (staged_entry.sid if staged_entry is not None else None)
        candidate_ip = server_ip or (staged_entry.server_ip if staged_entry is not None else None)

        # 1. If we already have the active SID for session_uid, verify via `show-session {}` and reuse directly
        if candidate_sid:
            try:
                verify_res = await self._api.api_call(
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
                        return candidate_sid, candidate_ip, verify_res
            except ServerIdentityError:
                raise
            except Exception:
                pass

        # 2. Open a fresh dedicated session to inspect provenance and adopt session_uid
        try:
            fresh_sid, fresh_ip = await self._api.create_dedicated_session(
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

        # 3. Inspect target session metadata via `show-session {"uid": session_uid}` before takeover
        try:
            info_res = await self._api.api_call(
                mgmt_name,
                "show-session",
                {"uid": session_uid},
                domain=domain or None,
                sid=fresh_sid,
                server_ip=fresh_ip,
            )
        except ServerIdentityError:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            raise
        except Exception as exc:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            safe_err = redact_sid(str(exc), known_sids=known_sids)
            return (
                None,
                None,
                ApiCallResult(
                    success=False,
                    status_code=500,
                    error_message=f"Failed to inspect staged session {session_uid}: {safe_err}",
                    error_code="session_inspect_failed",
                ),
            )

        if not info_res.success or not isinstance(info_res.data, dict):
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            safe_err = redact_sid(
                info_res.error_message or info_res.error_code or f"Unable to inspect session {session_uid}",
                known_sids=known_sids,
            )
            return (
                None,
                None,
                info_res.model_copy(update={"error_message": safe_err}),
            )

        s_data = info_res.data
        s_state = str(s_data.get("state") or "").strip().lower()
        has_pub = bool(s_data.get("publish-time"))
        if s_state in ("published", "discarded") or has_pub:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
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

        s_name = str(s_data.get("name") or s_data.get("session-name") or "").strip().lower()
        s_app = str(s_data.get("application") or "").strip().lower()
        is_arodonata_session = staged_entry is not None or s_name.startswith("arodonata") or s_app == "arodonata"
        if not is_arodonata_session:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            return (
                None,
                None,
                ApiCallResult(
                    success=False,
                    status_code=403,
                    error_code="foreign_session_refused",
                    error_message=(
                        f"Refusing to adopt foreign or non-Arodonata session {session_uid} "
                        f"(name={s_name!r}, application={s_app!r})."
                    ),
                ),
            )

        # 4. Perform non-disruptive take-over-session (or force_disconnect if explicitly requested),
        #    falling back to switch-session for disconnected sessions of the same administrator.
        takeover_payload: dict[str, Any] = {"uid": session_uid}
        if force_disconnect:
            takeover_payload["disconnect-active-session"] = True
        switch_payload: dict[str, Any] = {"uid": session_uid}

        try:
            take_res = await self._api.api_call(
                mgmt_name,
                "take-over-session",
                takeover_payload,
                domain=domain or None,
                sid=fresh_sid,
                server_ip=fresh_ip,
            )
            if not take_res.success:
                sw_res = await self._api.api_call(
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
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            raise
        except Exception as exc:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
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
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, fresh_sid, server_ip=fresh_ip)
            safe_err = redact_sid(
                take_res.error_message or take_res.error_code or "take-over-session failed",
                known_sids=known_sids,
            )
            return (
                None,
                None,
                take_res.model_copy(update={"error_message": safe_err}),
            )

        return fresh_sid, fresh_ip, take_res

    async def stream_publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate domain cache."""
        dom_label = f"{mgmt_name}:{domain}" if domain else mgmt_name
        dom_key = normalize_domain_key(domain)
        yield CPCRUDStartedEvent(
            mgmt_name=mgmt_name,
            domain=domain or None,
            message=f"Publishing staged session {session_uid} on {dom_label}...",
            details={"session_uid": session_uid},
        )

        active_sid, active_ip, take_res = await self._adopt_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
            force_disconnect=force_disconnect,
        )
        if not take_res.success or active_sid is None:
            err_msg = take_res.error_message or take_res.error_code or "take-over-session failed"
            self._last_staged_publish_result = take_res
            yield CPCRUDActionEvent(
                phase="failed",
                mgmt_name=mgmt_name,
                domain=domain or None,
                outcome=Outcome.ERROR.value,
                error=err_msg,
                message=f"Failed to adopt staged session {session_uid} on {dom_label}: {err_msg}",
            )
            yield CPCRUDCompletedEvent(
                phase="failed",
                mgmt_name=mgmt_name,
                domain=domain or None,
                succeeded_count=0,
                failed_count=1,
                skipped_count=0,
                error=err_msg,
                message=f"Failed to publish staged session {session_uid} on {dom_label}: {err_msg}",
            )
            return

        known_sids = [s for s in (sid, active_sid) if s]
        try:
            pub_res = await self._api.api_call(
                mgmt_name,
                "publish",
                {},
                domain=domain or None,
                sid=active_sid,
                server_ip=active_ip,
                wait_for_task=True,
                timeout=timeout,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            safe_err = redact_sid(str(exc), known_sids=known_sids)
            pub_res = ApiCallResult(
                success=False,
                status_code=500,
                error_message=safe_err,
                error_code="publish_failed",
            )
        finally:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, active_sid, server_ip=active_ip)
            if sid and sid != active_sid:
                with suppress(Exception):
                    await self._api.logout_sid(mgmt_name, sid, server_ip=server_ip)

        if pub_res.success:
            self._staged_sessions.pop((mgmt_name, dom_key, session_uid), None)
            self._invalidate_domain(mgmt_name, domain)
            self._last_staged_publish_result = pub_res
            yield CPCRUDDomainPublishedEvent(
                mgmt_name=mgmt_name,
                domain=domain or None,
                session_uid=session_uid,
                message=f"Published staged session {session_uid} on {dom_label}.",
            )
            yield CPCRUDCompletedEvent(
                phase="completed",
                mgmt_name=mgmt_name,
                domain=domain or None,
                succeeded_count=1,
                failed_count=0,
                skipped_count=0,
                message=f"Published staged session {session_uid} on {dom_label}.",
                details={"published_domains": [dom_label], "session_uid": session_uid},
            )
        else:
            safe_err = redact_sid(
                pub_res.error_message or pub_res.error_code or "publish failed",
                known_sids=known_sids,
            )
            pub_res = pub_res.model_copy(update={"error_message": safe_err})
            self._last_staged_publish_result = pub_res
            yield CPCRUDActionEvent(
                phase="failed",
                mgmt_name=mgmt_name,
                domain=domain or None,
                outcome=Outcome.ERROR.value,
                error=safe_err,
                message=f"Publish failed for staged session {session_uid} on {dom_label}: {safe_err}",
            )
            yield CPCRUDCompletedEvent(
                phase="failed",
                mgmt_name=mgmt_name,
                domain=domain or None,
                succeeded_count=0,
                failed_count=1,
                skipped_count=0,
                error=safe_err,
                message=f"Publish failed for staged session {session_uid} on {dom_label}: {safe_err}",
            )

    @traced
    async def publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, publish it, log out, and invalidate the domain cache."""
        span_attrs(mgmt_name=mgmt_name, domain=domain, session_uid=session_uid)
        async for _ in self.stream_publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
            force_disconnect=force_disconnect,
        ):
            pass
        assert self._last_staged_publish_result is not None
        return self._last_staged_publish_result

    @traced
    async def discard_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, discard all uncommitted changes in the session, and log out."""
        span_attrs(mgmt_name=mgmt_name, domain=domain, session_uid=session_uid)
        dom_key = normalize_domain_key(domain)
        active_sid, active_ip, take_res = await self._adopt_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
            force_disconnect=force_disconnect,
        )
        if not take_res.success or active_sid is None:
            return take_res

        known_sids = [s for s in (sid, active_sid) if s]
        try:
            disc_res = await self._api.api_call(
                mgmt_name,
                "discard",
                {},
                domain=domain or None,
                sid=active_sid,
                server_ip=active_ip,
            )
            if not disc_res.success:
                safe_err = redact_sid(
                    disc_res.error_message or disc_res.error_code or "discard failed",
                    known_sids=known_sids,
                )
                return disc_res.model_copy(update={"error_message": safe_err})
            self._staged_sessions.pop((mgmt_name, dom_key, session_uid), None)
            return disc_res
        except ServerIdentityError:
            raise
        except Exception as exc:
            safe_err = redact_sid(str(exc), known_sids=known_sids)
            return ApiCallResult(
                success=False,
                status_code=500,
                error_message=safe_err,
                error_code="discard_failed",
            )
        finally:
            with suppress(Exception):
                await self._api.logout_sid(mgmt_name, active_sid, server_ip=active_ip)
            if sid and sid != active_sid:
                with suppress(Exception):
                    await self._api.logout_sid(mgmt_name, sid, server_ip=server_ip)


def _fold_retry_report(cumulative: ApplyReport, retry_rep: ApplyReport) -> None:
    """Fold a retry pass's `ApplyReport` into the cumulative `ApplyReport`."""
    cumulative.retry_passes += 1
    cumulative.retry_reports.append(retry_rep)
    cumulative.completed_at = retry_rep.completed_at

    retry_by_id = {r.action_id: r for r in retry_rep.results}
    cumulative.results = [retry_by_id.get(r.action_id, r) for r in cumulative.results]

    for dom in retry_rep.published_domains:
        if dom not in cumulative.published_domains:
            cumulative.published_domains.append(dom)
    for s_dom in retry_rep.stale_domains:
        if s_dom not in cumulative.stale_domains:
            cumulative.stale_domains.append(s_dom)
    cumulative.published_sessions.update(retry_rep.published_sessions)
    cumulative.staged_sessions.extend(retry_rep.staged_sessions)


__all__ = [
    "ALLOWED_COMMAND_MAP",
    "Executor",
    "resolve_allowlisted_command",
]
