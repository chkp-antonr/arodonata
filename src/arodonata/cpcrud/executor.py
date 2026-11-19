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

from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from datetime import datetime

from arodonata.core.context import AuthContext, UserContext, normalize_domain_key
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDCompletedEvent,
    CPCRUDDomainPublishedEvent,
    CPCRUDEvent,
    CPCRUDStartedEvent,
)
from arodonata.core.models.common import ApiCallResult, utc_now
from arodonata.core.ports import ApiPort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud._executor_helpers import (
    ALLOWED_COMMAND_MAP,
    EXECUTABLE_RULE_TYPES,
    _extract_published_session_uid,
    _fold_retry_report,
    _is_domain_head_stale,
    check_current_domain_head,
    resolve_allowlisted_command,
)
from arodonata.cpcrud._executor_pass import execute_single_pass
from arodonata.cpcrud._executor_staged import adopt_staged_session
from arodonata.cpcrud.models import ApplyReport, Outcome, Plan, StagedSessionInfo


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
        return await check_current_domain_head(self._api, mgmt_name, domain_name)

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
        return await execute_single_pass(
            api=self._api,
            now_fn=self._now,
            on_domain_invalidated=self._on_domain_invalidated,
            staged_registry=self._staged_sessions,
            plan=plan,
            check_domain_head=self._check_current_domain_head,
            invalidate_domain=self._invalidate_domain,
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
        )

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
            message=f"Completed CPCRUD apply: {succeeded_cnt} succeeded, {failed_cnt} failed, {skipped_cnt} skipped.",
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
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> tuple[str | None, str | None, ApiCallResult]:
        """Adopt ownership of `session_uid` via direct SID reuse or verified `take-over-session`."""
        return await adopt_staged_session(
            api=self._api,
            staged_registry=self._staged_sessions,
            mgmt_name=mgmt_name,
            domain=domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        )

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
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
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
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
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
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
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
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        ):
            pass
        assert self._last_staged_publish_result is not None
        return self._last_staged_publish_result

    def notify_sid_logged_out(self, mgmt_name: str, sid: str) -> None:
        """Clear `_sid` on any tracked staged session whose `sid` was explicitly logged out."""
        if not sid:
            return
        for entry in self._staged_sessions.values():
            if entry.sid == sid and (not mgmt_name or entry.mgmt_name == mgmt_name):
                entry.clear_sid()

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
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
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
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
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


__all__ = [
    "ALLOWED_COMMAND_MAP",
    "EXECUTABLE_RULE_TYPES",
    "Executor",
    "_extract_published_session_uid",
    "_fold_retry_report",
    "_is_domain_head_stale",
    "resolve_allowlisted_command",
]
