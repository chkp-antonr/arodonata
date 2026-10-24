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

from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from datetime import datetime

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
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDCompletedEvent,
    CPCRUDDomainPublishedEvent,
    CPCRUDEvent,
    CPCRUDStartedEvent,
    StagedSessionEvent,
)
from arodonata.core.models.common import utc_now
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


def _is_domain_head_stale(
    stamp: DomainStamp | None,
    current_uid: str | None,
    current_published_at: datetime | None,
    head_readable: bool,
) -> bool:
    """Return `True` if a domain's current published head cannot be read or drifted since `stamp`."""
    if not head_readable or stamp is None or not stamp.readable:
        return True
    if stamp.last_session_uid is not None and current_uid != stamp.last_session_uid:
        return True
    return bool(stamp.last_published_at is not None and current_published_at != stamp.last_published_at)


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
            key = (act.mgmt_name, act.domain_name)
            if key not in domain_groups:
                domain_order.append(key)
            domain_groups[key].append(act)

        resolved_auth = auth or get_auth_context()
        resolved_user = user or get_user_context()
        eff_session_name = session_name or (resolved_user.session_name if resolved_user else None)
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
                                message=f"Executing {act.command} for {act.name!r}.",
                            )
                        )

                        cmd = act.command or f"add-{act.object_type}"
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
                        # Query show-session to obtain session_uid if not already populated
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
                            await self._api.api_call(
                                mgmt_name,
                                "discard",
                                {},
                                domain=dom_name or None,
                                sid=ws.sid,
                                server_ip=ws.server_ip,
                            )
                        ws.discarded = True
                        ws.overlay.clear()
                    elif any_write_succeeded:
                        # Query session UID if needed before or from publish
                        pub_res = await self._api.api_call(
                            mgmt_name,
                            "publish",
                            {},
                            domain=dom_name or None,
                            sid=ws.sid,
                            server_ip=ws.server_ip,
                            wait_for_task=True,
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
                                await self._api.api_call(
                                    mgmt_name,
                                    "discard",
                                    {},
                                    domain=dom_name or None,
                                    sid=ws.sid,
                                    server_ip=ws.server_ip,
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
            finally:
                # Only keep session open when both no_publish=True and keep_session=True
                if not (no_publish and keep_session):
                    ws.overlay.clear()
                    with suppress(Exception):
                        await self._api.logout_sid(mgmt_name, ws.sid, server_ip=ws.server_ip)

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
        while retry_pass < max_retries and not cumulative_report.stale_domains:
            failed_ids = {
                r.action_id
                for r in cumulative_report.results
                if not r.success and r.planned_outcome in (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE)
            }
            if not failed_ids:
                break

            retry_pass += 1
            remaining_actions = [a for a in plan.actions if a.action_id in failed_ids]
            retry_plan = Plan(
                created_at=self._now(),
                domain_stamps=plan.domain_stamps,
                actions=remaining_actions,
                name_resolutions=plan.name_resolutions,
                template=plan.template,
            )

            # Retry passes run with force=True because an earlier pass may have published other domains
            # or refreshed domain stamps, and fold their ApplyReport into cumulative_report
            r_events, r_report = await self._stream_single_pass(
                retry_plan,
                force=True,
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
    cumulative.published_sessions.update(retry_rep.published_sessions)
    cumulative.staged_sessions.extend(retry_rep.staged_sessions)


__all__ = [
    "Executor",
]
