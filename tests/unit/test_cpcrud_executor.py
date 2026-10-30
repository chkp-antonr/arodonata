"""Unit tests for CPCRUD `Executor` (`src/arodonata/cpcrud/executor.py`)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pytest

from arodonata.core.context import get_write_session
from arodonata.core.errors import ValidationError
from arodonata.core.events import (
    CPCRUDActionEvent,
    CPCRUDCompletedEvent,
    CPCRUDDomainPublishedEvent,
    CPCRUDStartedEvent,
    StagedSessionEvent,
)
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.models import DomainStamp, Outcome, Plan, PlannedAction


class ExecutorFakeApi:
    """Configurable `ApiPort` double for `Executor` tests."""

    def __init__(self) -> None:
        self.published_uid: str = "pub-head-1"
        self.published_iso: str = "2026-10-24T08:00:00Z"
        self.head_readable: bool = True
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None, str | None]] = []
        self.logged_out_sids: list[str] = []
        self.overlay_snapshots: list[list[str]] = []
        self.flaky_command_failures_remaining: dict[str, int] = {}

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        self.calls.append((mgmt_name, command, payload, domain, sid))

        # Capture current WriteSession overlay keys while inside write_session_context
        ws = get_write_session()
        if ws is not None:
            hosts_in_overlay = [o.name for o in ws.overlay.apply_to_objects([])]
            self.overlay_snapshots.append(hosts_in_overlay)

        if command == "show-last-published-session":
            if not self.head_readable:
                return ApiCallResult(success=False, status_code=503, error_message="Head unreadable")
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )

        if command == "show-session":
            target_uid = (payload or {}).get("uid") or "staged-sess-uid-777"
            return ApiCallResult(
                success=True,
                data={
                    "uid": target_uid,
                    "name": "arodonata-cpcrud-staged",
                    "application": "arodonata",
                    "state": "open",
                },
            )

        remaining = self.flaky_command_failures_remaining.get(command, 0)
        if remaining > 0:
            self.flaky_command_failures_remaining[command] = remaining - 1
            return ApiCallResult(
                success=False,
                status_code=500,
                error_code="generic_err",
                error_message=f"Transient error on {command} (sid={sid})",
            )

        if command.startswith(("add-", "set-")) and payload:
            _, _, obj_type = command.partition("-")
            name = str(payload.get("name") or "unnamed")
            uid = str(payload.get("uid") or f"uid-{obj_type}-{name}")
            return ApiCallResult(success=True, data={**payload, "uid": uid, "name": name, "type": obj_type})

        if command == "publish":
            return ApiCallResult(success=True, data={"uid": "new-pub-sess-200"})

        return ApiCallResult(success=True, data={"message": "OK"})

    async def api_query(self, *args: Any, **kwargs: Any) -> ApiQueryResult:
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        **kwargs: Any,
    ) -> tuple[str, str]:
        return "secret-ws-sid-999", "10.1.0.1"

    async def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> bool:
        self.logged_out_sids.append(sid)
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


def _make_sample_plan(*, session_uid: str = "pub-head-1") -> Plan:
    pub_at = datetime(2026, 10, 24, 8, 0, 0)
    stamp = DomainStamp(
        mgmt_name="mds1",
        domain_name="Corp",
        last_session_uid=session_uid,
        last_published_at=pub_at,
        readable=True,
    )
    return Plan(
        domain_stamps={stamp.key: stamp},
        actions=[
            PlannedAction(
                action_id="act-1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="web-01",
                requested_name="web-01",
                resolved_name="web-01",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "web-01", "ipv4-address": "10.10.1.1"},
                desired_spec={"type": "host", "name": "web-01", "ipv4-address": "10.10.1.1"},
            ),
            PlannedAction(
                action_id="act-2",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="group",
                name="grp-web",
                requested_name="grp-web",
                resolved_name="grp-web",
                outcome=Outcome.CREATE,
                command="add-group",
                payload={"name": "grp-web", "members": ["web-01"]},
                desired_spec={"type": "group", "name": "grp-web", "members": ["web-01"]},
            ),
        ],
    )


@pytest.mark.asyncio
async def test_executor_aborts_stale_plan_with_zero_writes_when_force_is_false() -> None:
    """`Executor` marks all domain actions `Outcome.PLAN_STALE` and performs zero writes when the domain's `show-last-published-session` drifted or is unreadable."""
    api = ExecutorFakeApi()
    invalidated: list[tuple[str, str | None]] = []
    executor = Executor(api=api, on_domain_invalidated=lambda m, d: invalidated.append((m, d)))

    plan = _make_sample_plan(session_uid="pub-head-1")
    # Simulate another operator publishing a new session on Corp after plan() was created
    api.published_uid = "pub-head-2-drifted"

    report = await executor.apply(plan, force=False)
    assert report.has_failures is True
    assert report.stale_domains == ["mds1:Corp"]
    assert all(r.outcome == Outcome.PLAN_STALE for r in report.results)
    assert all(r.status == "plan_stale" for r in report.results)
    # Zero write commands or session openings
    assert [c[1] for c in api.calls] == ["show-last-published-session"]
    assert invalidated == []


@pytest.mark.asyncio
async def test_executor_apply_updates_overlay_publishes_and_invalidates_domain() -> None:
    """`Executor` executes write actions inside a `WriteSession`, updates `SessionOverlay` after each command, publishes, and invalidates the domain."""
    api = ExecutorFakeApi()
    invalidated: list[tuple[str, str | None]] = []
    executor = Executor(api=api, on_domain_invalidated=lambda m, d: invalidated.append((m, d)))

    plan = _make_sample_plan(session_uid="pub-head-1")
    events = [ev async for ev in executor.stream_apply(plan)]

    report = executor.last_report
    assert report is not None
    assert report.has_failures is False
    assert report.published_domains == ["mds1:Corp"]
    assert report.published_sessions == {"mds1:Corp": "new-pub-sess-200"}
    assert invalidated == [("mds1", "Corp")]
    assert "secret-ws-sid-999" in api.logged_out_sids

    # When `add-group` (second command inside WriteSession) ran, `web-01` from `add-host` was already in `ws.overlay`!
    assert any("web-01" in snap for snap in api.overlay_snapshots)

    # Verify event stream lifecycle
    assert isinstance(events[0], CPCRUDStartedEvent)
    assert any(isinstance(e, CPCRUDDomainPublishedEvent) for e in events)
    assert isinstance(events[-1], CPCRUDCompletedEvent)


@pytest.mark.asyncio
async def test_executor_keep_session_staging_mode_and_sid_redaction() -> None:
    """With `no_publish=True, keep_session=True`, `Executor` leaves the session open, emits `StagedSessionEvent`, and redacts `sid` in `StagedSessionInfo` `repr()`."""
    api = ExecutorFakeApi()
    executor = Executor(api=api)
    plan = _make_sample_plan(session_uid="pub-head-1")

    events = [ev async for ev in executor.stream_apply(plan, no_publish=True, keep_session=True)]
    report = executor.last_report
    assert report is not None
    assert report.published_domains == []
    assert len(report.staged_sessions) == 1

    staged = report.staged_sessions[0]
    assert staged.mgmt_name == "mds1"
    assert staged.domain_name == "Corp"
    assert staged.session_uid == "staged-sess-uid-777"
    assert staged.sid == "secret-ws-sid-999"
    # Security hygiene: SID must never appear in repr(), str(), or model_dump()
    assert "secret-ws-sid-999" not in repr(staged)
    assert "secret-ws-sid-999" not in str(staged)
    assert "secret-ws-sid-999" not in str(staged.model_dump())

    # Session was kept open (not logged out and not published/discarded)
    assert api.logged_out_sids == []
    assert not any(c[1] in ("publish", "discard") for c in api.calls)

    staged_events = [e for e in events if isinstance(e, StagedSessionEvent)]
    assert len(staged_events) == 1
    assert staged_events[0].session_uid == "staged-sess-uid-777"
    assert "secret-ws-sid-999" not in repr(staged_events[0])


@pytest.mark.asyncio
async def test_executor_retry_remaining_folds_retry_pass_into_cumulative_report() -> None:
    """`retry_remaining > 0` re-runs failed/skipped-dependency write actions and folds the retry results into the cumulative `ApplyReport`."""
    api = ExecutorFakeApi()
    # Fail `add-host` on pass 1; this causes `add-host` to fail with ERROR and `add-group` to be skipped with SKIPPED_DEPENDENCY.
    # On retry pass 1, `add-host` and `add-group` both succeed!
    api.flaky_command_failures_remaining["add-host"] = 1

    executor = Executor(api=api)
    plan = _make_sample_plan(session_uid="pub-head-1")

    events = [ev async for ev in executor.stream_apply(plan, retry_remaining=1)]
    report = executor.last_report
    assert report is not None

    # After the retry pass, both actions succeeded and the domain was published
    assert report.has_failures is False
    assert [r.outcome for r in report.results] == [Outcome.CREATE, Outcome.CREATE]
    assert all(r.success for r in report.results)
    assert report.published_domains == ["mds1:Corp"]

    # Ensure SID from transient error message was redacted in events
    failed_events = [e for e in events if isinstance(e, CPCRUDActionEvent) and e.phase == "action_failed"]
    assert len(failed_events) >= 1
    for fe in failed_events:
        assert "secret-ws-sid-999" not in (fe.error or "")


@pytest.mark.asyncio
async def test_staged_session_takeover_publish_discard_expired_sid_fallback_and_failure() -> None:
    """Verify `publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session`:
    - Inspect session provenance via `show-session {"uid": session_uid}` before takeover.
    - Omit `"disconnect-active-session"` by default (`force_disconnect=False`).
    - Reuse active `sid` directly when `show-session {}` confirms ownership of `session_uid`.
    - Fall back to a fresh session when `sid` expired, and fall back to `switch-session` when `take-over-session` fails.
    - Refuse foreign/SmartConsole or already published/discarded sessions (`C1`, `W6`).
    - Report both `take-over-session` and `switch-session` errors when both fail (`I6`).
    """
    api = ExecutorFakeApi()
    invalidated: list[tuple[str, str | None]] = []
    executor = Executor(api=api, on_domain_invalidated=lambda m, d: invalidated.append((m, d)))

    # 1. Staged session takeover + publish (without passing sid -> opens fresh session, inspects show-session, takes over non-disruptively)
    pub_events = [
        ev
        async for ev in executor.stream_publish_staged_session(
            "mds1",
            "Corp",
            session_uid="staged-sess-uid-777",
        )
    ]
    assert isinstance(pub_events[0], CPCRUDStartedEvent)
    assert any(isinstance(e, CPCRUDDomainPublishedEvent) and e.session_uid == "staged-sess-uid-777" for e in pub_events)
    assert isinstance(pub_events[-1], CPCRUDCompletedEvent) and pub_events[-1].phase == "completed"
    assert invalidated == [("mds1", "Corp")]
    assert (
        "mds1",
        "show-session",
        {"uid": "staged-sess-uid-777"},
        "Corp",
        "secret-ws-sid-999",
    ) in api.calls
    assert (
        "mds1",
        "take-over-session",
        {"uid": "staged-sess-uid-777"},
        "Corp",
        "secret-ws-sid-999",
    ) in api.calls
    assert ("mds1", "publish", {}, "Corp", "secret-ws-sid-999") in api.calls
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 1b. Direct SID reuse when active `sid` still owns `session_uid` (no take-over-session needed!)
    api.calls.clear()
    api.logged_out_sids.clear()
    invalidated.clear()
    reuse_res = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-777",
        sid="active-staged-sid-555",
        server_ip="10.1.0.1",
    )
    assert reuse_res.success is True
    assert invalidated == [("mds1", "Corp")]
    assert [c[1] for c in api.calls] == ["show-session", "publish"]
    assert "active-staged-sid-555" in api.logged_out_sids

    # 2. Fallback to fresh session when the supplied staged `sid` expired (`show-session {}` fails on expired sid)
    api.calls.clear()
    api.logged_out_sids.clear()
    invalidated.clear()
    api.flaky_command_failures_remaining["show-session"] = 1

    pub_res = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-888",
        sid="expired-staged-sid-111",
        server_ip="10.1.0.1",
    )
    assert pub_res.success is True
    assert invalidated == [("mds1", "Corp")]
    show_sids = [c[4] for c in api.calls if c[1] == "show-session"]
    assert show_sids == ["expired-staged-sid-111", "secret-ws-sid-999"]
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 2b. Fallback to switch-session on fresh session when take-over-session is rejected
    api.calls.clear()
    api.logged_out_sids.clear()
    invalidated.clear()
    api.flaky_command_failures_remaining["take-over-session"] = 1

    pub_sw_res = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-889",
    )
    assert pub_sw_res.success is True
    assert invalidated == [("mds1", "Corp")]
    assert [c[1] for c in api.calls] == ["show-session", "take-over-session", "switch-session", "publish"]
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 2c. Both take-over-session and switch-session fail -> combined error message (I6) and fresh_sid logged out
    api.calls.clear()
    api.logged_out_sids.clear()
    api.flaky_command_failures_remaining["take-over-session"] = 1
    api.flaky_command_failures_remaining["switch-session"] = 1
    both_fail_res = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-both-fail",
    )
    assert both_fail_res.success is False
    assert "take-over-session failed" in (both_fail_res.error_message or "")
    assert "switch-session fallback failed" in (both_fail_res.error_message or "")
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 3. Staged session takeover + discard (with force_disconnect=True explicitly)
    api.calls.clear()
    api.logged_out_sids.clear()
    disc_res = await executor.discard_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-999",
        force_disconnect=True,
    )
    assert disc_res.success is True
    assert [c[1] for c in api.calls] == ["show-session", "take-over-session", "discard"]
    assert api.calls[1][2] == {"uid": "staged-sess-uid-999", "disconnect-active-session": True}
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 4. Failure containment and SID redaction when publish task fails
    api.calls.clear()
    api.logged_out_sids.clear()
    invalidated.clear()
    api.flaky_command_failures_remaining["publish"] = 1

    fail_res = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="staged-sess-uid-fail",
    )
    assert fail_res.success is False
    assert "secret-ws-sid-999" not in (fail_res.error_message or "")
    assert invalidated == []
    assert "secret-ws-sid-999" in api.logged_out_sids

    # 5. C1 & W6: Foreign SmartConsole session and already-published session are refused before take-over-session!
    orig_call = api.api_call

    async def provenance_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "show-session":
            t_uid = (payload or {}).get("uid")
            if t_uid == "foreign-smartconsole-uid":
                return ApiCallResult(
                    success=True,
                    data={"uid": t_uid, "name": "Admin-Edit", "application": "SmartConsole", "state": "open"},
                )
            if t_uid == "already-published-uid":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": t_uid,
                        "name": "arodonata-cpcrud-staged",
                        "application": "arodonata",
                        "state": "published",
                        "publish-time": {"iso-8601": "2026-10-30T10:00:00Z"},
                    },
                )
        return await orig_call(mgmt_name, command, payload, **kwargs)

    api.api_call = provenance_api_call  # type: ignore[method-assign]
    api.calls.clear()
    api.logged_out_sids.clear()
    foreign_res = await executor.discard_staged_session("mds1", "Corp", session_uid="foreign-smartconsole-uid")
    assert foreign_res.success is False
    assert foreign_res.error_code == "foreign_session_refused"
    assert not any(c[1] in ("take-over-session", "switch-session", "discard") for c in api.calls)
    assert "secret-ws-sid-999" in api.logged_out_sids

    api.calls.clear()
    api.logged_out_sids.clear()
    pub_already_res = await executor.publish_staged_session("mds1", "Corp", session_uid="already-published-uid")
    assert pub_already_res.success is False
    assert pub_already_res.error_code == "session_not_open"
    assert not any(c[1] in ("take-over-session", "switch-session", "publish") for c in api.calls)
    assert "secret-ws-sid-999" in api.logged_out_sids


@pytest.mark.asyncio
async def test_executor_command_allowlist_and_forged_command_rejection() -> None:
    """Adversarial test for C1 & C2: Executor rejects forged PlannedAction.command or unlisted (object_type, outcome) before opening a session."""
    api = ExecutorFakeApi()
    executor = Executor(api=api)

    forged_plan = _make_sample_plan(session_uid="pub-head-1")
    forged_plan.actions[0].command = "run-script"

    with pytest.raises(ValidationError, match="disagrees with allowlisted command"):
        await executor.apply(forged_plan)
    assert api.calls == []

    unlisted_plan = _make_sample_plan(session_uid="pub-head-1")
    unlisted_plan.actions[0].object_type = "administrator"
    unlisted_plan.actions[0].command = "add-administrator"

    with pytest.raises(ValidationError, match="Unsupported CPCRUD action pair"):
        await executor.apply(unlisted_plan)
    assert api.calls == []


@pytest.mark.asyncio
async def test_executor_cancellation_publish_exception_prepublish_stale_and_none_head_drift() -> None:
    """Adversarial test for W8, W10, W11, W12:
    - W8: CancelledError during execution shields discard before logout_sid.
    - W10: Exception raised by publish triggers discard and marks actions ERROR without crashing apply().
    - W11: StagedSessionInfo is recorded immediately upon session creation when keep_session=True.
    - W12: Domain head drift detected when stamp.last_session_uid is None, pre-publish head check, and retry_remaining with force=False.
    """
    # 1. W8: CancelledError inside action execution shields discard before logout_sid
    api_cancel = ExecutorFakeApi()
    orig_call = api_cancel.api_call

    async def cancelling_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "add-group":
            raise asyncio.CancelledError("Simulated task cancellation mid-domain")
        return await orig_call(mgmt_name, command, payload, **kwargs)

    api_cancel.api_call = cancelling_api_call  # type: ignore[method-assign]
    exec_cancel = Executor(api=api_cancel)
    with pytest.raises(asyncio.CancelledError):
        await exec_cancel.apply(_make_sample_plan())
    cmds_after_cancel = [c[1] for c in api_cancel.calls]
    assert "discard" in cmds_after_cancel
    assert "secret-ws-sid-999" in api_cancel.logged_out_sids

    # 2. W10: Transport/task exception during publish triggers discard and records Outcome.ERROR
    api_pub_exc = ExecutorFakeApi()
    orig_pub_call = api_pub_exc.api_call

    async def publish_raising_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "publish":
            raise RuntimeError("Publish task timed out with token secret-ws-sid-999")
        return await orig_pub_call(mgmt_name, command, payload, **kwargs)

    api_pub_exc.api_call = publish_raising_api_call  # type: ignore[method-assign]
    exec_pub_exc = Executor(api=api_pub_exc)
    rep_pub_exc = await exec_pub_exc.apply(_make_sample_plan())
    assert rep_pub_exc.has_failures is True
    assert all(r.outcome == Outcome.ERROR for r in rep_pub_exc.results)
    assert all("secret-ws-sid-999" not in (r.error or "") for r in rep_pub_exc.results)
    assert any(c[1] == "discard" for c in api_pub_exc.calls)
    assert "secret-ws-sid-999" in api_pub_exc.logged_out_sids

    # 3. W11: keep_session=True records StagedSessionInfo immediately even if an action fails
    api_staged = ExecutorFakeApi()
    api_staged.flaky_command_failures_remaining["add-host"] = 1
    exec_staged = Executor(api=api_staged)
    rep_staged = await exec_staged.apply(_make_sample_plan(), no_publish=True, keep_session=True)
    assert len(rep_staged.staged_sessions) == 1
    assert rep_staged.staged_sessions[0].session_uid == "staged-sess-uid-777"

    # 4. W12: Stamp with last_session_uid=None detects drift when domain now has a published session
    api_none_head = ExecutorFakeApi()
    exec_none_head = Executor(api=api_none_head)
    none_stamp = DomainStamp(
        mgmt_name="mds1",
        domain_name="Corp",
        last_session_uid=None,
        last_published_at=None,
        readable=True,
    )
    none_plan = _make_sample_plan()
    none_plan.domain_stamps = {none_stamp.key: none_stamp}
    rep_none = await exec_none_head.apply(none_plan, force=False)
    assert rep_none.stale_domains == ["mds1:Corp"]
    assert all(r.outcome == Outcome.PLAN_STALE for r in rep_none.results)

    # 5. W12: Pre-publish head drift check discards session and marks actions PLAN_STALE
    api_prepub = ExecutorFakeApi()
    orig_prepub_call = api_prepub.api_call

    async def drifting_mid_run_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        res = await orig_prepub_call(mgmt_name, command, payload, **kwargs)
        if command == "add-group":
            # Another operator publishes right before our publish!
            api_prepub.published_uid = "concurrent-external-pub-999"
        return res

    api_prepub.api_call = drifting_mid_run_api_call  # type: ignore[method-assign]
    exec_prepub = Executor(api=api_prepub)
    rep_prepub = await exec_prepub.apply(_make_sample_plan(), force=False)
    assert rep_prepub.stale_domains == ["mds1:Corp"]
    assert all(r.outcome == Outcome.PLAN_STALE for r in rep_prepub.results)
    assert any(c[1] == "discard" for c in api_prepub.calls)
    assert not any(c[1] == "publish" for c in api_prepub.calls)

    # 6. W12: retry_remaining does NOT force=True when another operator publishes between retry passes
    api_retry_drift = ExecutorFakeApi()
    orig_retry_call = api_retry_drift.api_call

    async def retry_drifting_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "add-host" and api_retry_drift.published_uid == "pub-head-1":
            # Pass 1 fails add-host, and an external operator publishes before Pass 2 starts
            api_retry_drift.published_uid = "external-drift-between-retries"
            return ApiCallResult(success=False, status_code=500, error_message="Transient failure")
        return await orig_retry_call(mgmt_name, command, payload, **kwargs)

    api_retry_drift.api_call = retry_drifting_api_call  # type: ignore[method-assign]
    exec_retry_drift = Executor(api=api_retry_drift)
    rep_retry_drift = await exec_retry_drift.apply(_make_sample_plan(), force=False, retry_remaining=1)
    assert "mds1:Corp" in rep_retry_drift.stale_domains
    assert all(r.outcome == Outcome.PLAN_STALE for r in rep_retry_drift.results)
