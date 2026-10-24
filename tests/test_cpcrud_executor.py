"""Unit tests for CPCRUD `Executor` (`src/arodonata/cpcrud/executor.py`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from arodonata.core.context import get_write_session
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
            return ApiCallResult(
                success=True,
                data={"uid": "staged-sess-uid-777", "name": "Staged-Change"},
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
    pub_at = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)
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
