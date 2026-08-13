# tests/unit/cpcrud/test_executor.py
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import ApiCallResult
from arodonata.cpcrud.executor import Executor, classify_api_error, fold_reports
from arodonata.cpcrud.models import ActionResult, ApplyReport, DomainStamp, ObjectState, Outcome, Plan, PlannedAction


class FakeRefreshCoordinator:
    def __init__(self):
        self.invalidated = []

    def invalidate(self, mgmt_name, domain):
        self.invalidated.append((mgmt_name, domain))


class FakeClient:
    def __init__(self):
        self.calls = []
        self._session_counter = 0
        self._refresh_coordinator = FakeRefreshCoordinator()
        self.refresh_calls = []

    async def create_dedicated_session(self, mgmt_name, domain="", session_name=None, session_description=None):
        self._session_counter += 1
        return (f"sid-{self._session_counter}", "1.1.1.1")

    async def api_call_with_sid(self, mgmt_name, sid, server_ip, command, payload=None, wait_for_task=True, timeout=-1):
        self.calls.append((command, payload))
        if command == "publish":
            return ApiCallResult(success=True, data={"tasks": [{"task-id": "task-1"}]}, message="OK")
        if command.startswith("add-"):
            return ApiCallResult(success=True, data={"uid": "new-uid", "name": payload.get("name", "x")}, message="OK")
        return ApiCallResult(success=True, data={}, message="OK")

    async def logout_sid(self, sid, server_ip, mgmt_name=""):
        return True

    async def refresh_objects(self, **kwargs):
        self.refresh_calls.append(kwargs)
        return
        yield  # pragma: no cover - makes this an async generator, like the real client method


@pytest.mark.asyncio
async def test_execute_creates_and_publishes():
    client = FakeClient()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-AFTER"
    exe = Executor(client, reader)
    plan = Plan(
        actions=[
            PlannedAction(
                id="act-0001",
                operation="add",
                type="host",
                outcome=Outcome.CREATE,
                mgmt_name="m1",
                domain_name="General",
                resolved_name="h1",
                command="add-host",
                payload={"name": "h1", "ip-address": "10.0.0.1"},
            )
        ]
    )
    report = await exe.execute(plan)
    assert report.results[0].action_id == "act-0001"
    assert report.results[0].outcome == Outcome.CREATE
    assert report.results[0].uid == "new-uid"
    assert report.results[0].type == "host"
    assert report.results[0].name == "h1"
    assert report.results[0].mgmt_name == "m1"
    assert report.results[0].domain_name == "General"
    assert ("add-host", {"name": "h1", "ip-address": "10.0.0.1"}) in client.calls
    assert any(c[0] == "publish" for c in client.calls)
    assert report.summary["create"] == 1
    assert report.published_domains == [
        DomainStamp(mgmt_name="m1", domain_name="General", last_publish_session="sess-AFTER")
    ]
    assert client._refresh_coordinator.invalidated == [("m1", "General")]


@pytest.mark.asyncio
async def test_dry_run_makes_no_calls():
    client = FakeClient()
    exe = Executor(client, AsyncMock())
    plan = Plan(
        actions=[
            PlannedAction(
                id="act-0001",
                operation="add",
                type="host",
                outcome=Outcome.CREATE,
                mgmt_name="m1",
                domain_name="General",
                resolved_name="h1",
                command="add-host",
                payload={"name": "h1"},
            )
        ]
    )
    await exe.execute(plan, dry_run=True)
    assert client.calls == []


@pytest.mark.asyncio
async def test_skip_makes_no_api_call():
    client = FakeClient()
    exe = Executor(client, AsyncMock())
    plan = Plan(
        actions=[
            PlannedAction(
                id="act-0001",
                operation="add",
                type="host",
                outcome=Outcome.UNCHANGED,
                mgmt_name="m1",
                domain_name="General",
                resolved_name="h1",
                resolved_uid="u1",
            )
        ]
    )
    await exe.execute(plan)
    assert all(c[0] not in ("add-host", "set-host") for c in client.calls)


def _action(
    aid, *, otype="host", op="add", outcome=Outcome.CREATE, command="add-host", payload=None, depends_on=(), uid=None
):
    return PlannedAction(
        id=aid,
        operation=op,
        type=otype,
        mgmt_name="m",
        domain_name="d",
        outcome=outcome,
        command=command,
        payload=payload or {"name": aid},
        depends_on=list(depends_on),
        resolved_name=aid,
        resolved_uid=uid,
    )


@pytest.mark.asyncio
async def test_failed_dependency_cascades_to_skip():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    client.api_call_with_sid.return_value = SimpleNamespace(success=False, data=None, message="boom", code="err")
    reader = AsyncMock()
    plan = Plan(
        actions=[
            _action("act-0001", otype="network-group", command="add-group"),
            _action("act-0002", depends_on=["act-0001"]),
            _action("act-0003", depends_on=["act-0002"]),  # transitive
        ],
        stamps=[],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    outcomes = {r.action_id: r.outcome for r in report.results}
    assert outcomes["act-0001"] == Outcome.ERROR
    assert outcomes["act-0002"] == Outcome.SKIPPED_DEPENDENCY
    assert outcomes["act-0003"] == Outcome.SKIPPED_DEPENDENCY
    assert client.api_call_with_sid.await_count <= 2  # add-group (+ possibly no publish); dependents never called


@pytest.mark.asyncio
async def test_delete_gated_by_where_used():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    reader = AsyncMock()
    reader.where_used.return_value = 3
    plan = Plan(
        actions=[
            _action(
                "act-0001", op="delete", outcome=Outcome.DELETE, command="delete-host", payload={"uid": "u1"}, uid="u1"
            ),
        ],
        stamps=[],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    assert report.results[0].outcome == Outcome.ERROR
    assert "3 direct reference" in report.results[0].message
    delete_calls = [c for c in client.api_call_with_sid.await_args_list if c.args[3] == "delete-host"]
    assert delete_calls == []


def _plan_with_stamp(stamp_uid):
    return Plan(
        actions=[_action("act-0001")],
        stamps=[DomainStamp(mgmt_name="m", domain_name="d", last_publish_session=stamp_uid)],
        template_hash="h",
    )


async def test_stale_domain_blocks_all_writes():
    client = AsyncMock()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-NEW"
    report = await Executor(client, reader).execute(_plan_with_stamp("sess-OLD"))
    assert report.results[0].outcome == Outcome.PLAN_STALE
    client.create_dedicated_session.assert_not_awaited()


async def test_force_overrides_staleness():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    client.api_call_with_sid.return_value = SimpleNamespace(success=True, data={"uid": "u1"}, message="", code="")
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-NEW"
    reader.where_used.return_value = 0
    report = await Executor(client, reader).execute(_plan_with_stamp("sess-OLD"), force=True)
    assert report.results[0].outcome == Outcome.CREATE


async def test_unknown_stamp_does_not_block():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    client.api_call_with_sid.return_value = SimpleNamespace(success=True, data={"uid": "u1"}, message="", code="")
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-ANY"
    reader.where_used.return_value = 0
    report = await Executor(client, reader).execute(_plan_with_stamp(""))
    assert report.results[0].outcome == Outcome.CREATE


@pytest.mark.parametrize(
    ("message", "code", "expected"),
    [
        ("Object is locked by another session", "generic_error", "locked"),
        ("ok", "err_object_locked", "locked"),
        ("More than one object named 'h1' exists", "generic_error", "exists"),
        ("Object 'h1' already exists", "", "exists"),
        ("Requested object [h1] not found", "generic_err_object_not_found", "missing"),
        ("some other failure", "err_validation_failed", None),
    ],
)
def test_classify_api_error(message, code, expected):
    assert classify_api_error(message, code) == expected


async def test_locked_object_yields_locked_outcome_with_session_info():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")

    async def api_with_sid(mgmt, sid, server_ip, command, payload=None, wait_for_task=True):
        if command == "set-host":
            return SimpleNamespace(success=False, data=None, message="Object is locked by other session", code="")
        if command == "show-sessions":
            return SimpleNamespace(
                success=True,
                message="",
                code="",
                data={
                    "objects": [
                        {"uid": "other-sess", "user-name": "bob", "application": "SmartConsole", "locks": 2},
                    ]
                },
            )
        return SimpleNamespace(success=True, data={}, message="", code="")

    client.api_call_with_sid.side_effect = api_with_sid
    reader = AsyncMock()
    plan = Plan(
        actions=[
            _action(
                "act-0001", op="update", outcome=Outcome.UPDATE, command="set-host", payload={"uid": "u1"}, uid="u1"
            )
        ],
        stamps=[],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    res = report.results[0]
    assert res.outcome == Outcome.LOCKED
    assert res.locking_session and res.locking_session["user-name"] == "bob"


async def test_create_drift_reuses_existing_object():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    client.api_call_with_sid.return_value = SimpleNamespace(
        success=False, data=None, message="Object 'h1' already exists", code=""
    )
    reader = AsyncMock()
    reader.get_by_name.return_value = ObjectState(uid="u-live", name="act-0001", type="host", raw={})
    plan = Plan(actions=[_action("act-0001")], stamps=[], template_hash="h")
    report = await Executor(client, reader).execute(plan)
    assert report.results[0].outcome == Outcome.DRIFTED
    assert report.results[0].uid == "u-live"


async def test_delete_drift_counts_as_success():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    client.api_call_with_sid.return_value = SimpleNamespace(
        success=False, data=None, message="Requested object not found", code=""
    )
    reader = AsyncMock()
    reader.where_used.return_value = 0
    plan = Plan(
        actions=[
            _action(
                "act-0001", op="delete", outcome=Outcome.DELETE, command="delete-host", payload={"uid": "u1"}, uid="u1"
            )
        ],
        stamps=[],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    assert report.results[0].outcome == Outcome.DRIFTED
    assert "already" in report.results[0].message


async def test_remaining_plan_contains_only_failures_with_fresh_stamp():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")

    async def api_with_sid(mgmt, sid, server_ip, command, payload=None, wait_for_task=True):
        if command == "add-host" and payload.get("name") == "bad":
            return SimpleNamespace(success=False, data=None, message="Object is locked by other session", code="")
        if command == "show-sessions":
            return SimpleNamespace(success=True, data={"objects": []}, message="", code="")
        return SimpleNamespace(success=True, data={"uid": "u-ok"}, message="", code="")

    client.api_call_with_sid.side_effect = api_with_sid
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-AFTER"
    plan = Plan(
        actions=[
            _action("act-0001", payload={"name": "good"}),
            _action("act-0002", payload={"name": "bad"}),
        ],
        stamps=[DomainStamp(mgmt_name="m", domain_name="d", last_publish_session="")],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    assert report.summary == {"create": 1, "locked": 1}
    assert report.published_domains == [DomainStamp(mgmt_name="m", domain_name="d", last_publish_session="sess-AFTER")]
    assert report.remaining is not None
    assert [a.id for a in report.remaining.actions] == ["act-0002"]
    assert report.remaining.stamps == [DomainStamp(mgmt_name="m", domain_name="d", last_publish_session="sess-AFTER")]
    assert report.remaining.template_hash == "h"
    client._refresh_coordinator.invalidate.assert_called_once_with("m", "d")


async def test_stale_domain_actions_excluded_from_remaining():
    client = AsyncMock()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-NEW"
    report = await Executor(client, reader).execute(_plan_with_stamp("sess-OLD"))
    assert report.results[0].outcome == Outcome.PLAN_STALE
    assert report.remaining is None  # stale domains require re-plan, not retry


async def test_refresh_force_calls_refresh_objects():
    client = FakeClient()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-AFTER"
    plan = Plan(actions=[_action("act-0001")], stamps=[], template_hash="h")
    await Executor(client, reader).execute(plan, refresh="force")
    assert client.refresh_calls == [{"mgmt_names": ["m"], "domain_names": ["d"], "mode": "force"}]
    assert client._refresh_coordinator.invalidated == [("m", "d")]


async def test_refresh_default_only_invalidates():
    client = FakeClient()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-AFTER"
    plan = Plan(actions=[_action("act-0001")], stamps=[], template_hash="h")
    await Executor(client, reader).execute(plan)
    assert client.refresh_calls == []
    assert client._refresh_coordinator.invalidated == [("m", "d")]


async def test_no_effective_changes_skips_publish():
    client = AsyncMock()
    client.create_dedicated_session.return_value = ("sid", "ip")
    reader = AsyncMock()
    plan = Plan(
        actions=[_action("act-0001", outcome=Outcome.UNCHANGED, command=None, payload=None)],
        stamps=[],
        template_hash="h",
    )
    report = await Executor(client, reader).execute(plan)
    publish_calls = [c for c in client.api_call_with_sid.await_args_list if c.args[3] == "publish"]
    assert publish_calls == []
    assert report.published_domains == []
    assert report.remaining is None


def test_fold_reports_last_result_wins_and_summary_recomputed():
    first = ApplyReport(
        results=[
            ActionResult(action_id="act-0001", outcome=Outcome.CREATE),
            ActionResult(action_id="act-0002", outcome=Outcome.LOCKED),
        ],
        published_domains=[DomainStamp(mgmt_name="m", domain_name="d", last_publish_session="s1")],
        remaining=Plan(
            actions=[PlannedAction(id="act-0002", operation="add", type="host", mgmt_name="m", domain_name="d")]
        ),
        summary={"create": 1, "locked": 1},
    )
    second = ApplyReport(
        results=[ActionResult(action_id="act-0002", outcome=Outcome.CREATE)],
        published_domains=[DomainStamp(mgmt_name="m", domain_name="d", last_publish_session="s2")],
        remaining=None,
        summary={"create": 1},
    )
    folded = fold_reports(first, second)
    assert [r.action_id for r in folded.results] == ["act-0001", "act-0002"]
    assert folded.results[1].outcome == Outcome.CREATE
    assert folded.summary == {"create": 2}
    assert folded.remaining is None
    assert len(folded.published_domains) == 2
