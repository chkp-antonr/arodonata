from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import ApiCallResult, SSEEventType
from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.models import Outcome, Plan, PlannedAction
from arodonata.cpcrud.service import CPCRUDService


class FakeClient:
    def __init__(self):
        self.calls = []
        self.domains = []
        self._session_counter = 0
        self.invalidated = []
        self.logouts = []
        self.settings = None

    def invalidate_domain(self, mgmt_name, domain_name):
        self.invalidated.append((mgmt_name, domain_name))

    async def create_dedicated_session(self, mgmt_name, domain="", session_name=None, session_description=None):
        self._session_counter += 1
        return (f"sid-{self._session_counter}", "1.1.1.1")

    async def api_call_with_sid(
        self, mgmt_name, sid, server_ip, command, payload=None, wait_for_task=True, timeout=-1, *, domain=None
    ):
        self.calls.append((command, payload))
        self.domains.append(domain)
        if command == "show-session":
            return ApiCallResult(success=True, data={"uid": "sess-uid-123", "name": "test-session"}, message="OK")
        if command == "publish":
            return ApiCallResult(success=True, data={"tasks": [{"task-id": "task-1"}]}, message="OK")
        if command.startswith("add-"):
            return ApiCallResult(success=True, data={"uid": "new-uid", "name": payload.get("name", "x")}, message="OK")
        return ApiCallResult(success=True, data={}, message="OK")

    async def logout_sid(self, sid, server_ip, mgmt_name=""):
        self.logouts.append((sid, server_ip, mgmt_name))
        return True


@pytest.mark.asyncio
async def test_executor_keep_session_true_does_not_logout():
    client = FakeClient()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-INITIAL"
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

    reports = []
    async for item in exe.stream(plan, no_publish=True, keep_session=True, session_name="my-staged-sess"):
        if hasattr(item, "staged_sessions"):
            reports.append(item)

    assert len(reports) == 1
    report = reports[0]
    assert "m1:General" in report.staged_sessions
    sess = report.staged_sessions["m1:General"]
    assert sess["sid"] == "sid-1"
    assert sess["server_ip"] == "1.1.1.1"
    assert sess["session_uid"] == "sess-uid-123"
    assert sess["session_name"] == "my-staged-sess"
    # Crucially: logout_sid was NOT called because keep_session=True
    assert client.logouts == []


@pytest.mark.asyncio
async def test_executor_keep_session_false_logs_out():
    client = FakeClient()
    reader = AsyncMock()
    reader.get_last_publish_session.return_value = "sess-INITIAL"
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

    reports = []
    async for item in exe.stream(plan, no_publish=True, keep_session=False):
        if hasattr(item, "staged_sessions"):
            reports.append(item)

    assert len(reports) == 1
    # logout_sid was called because keep_session=False
    assert client.logouts == [("sid-1", "1.1.1.1", "m1")]


@pytest.mark.asyncio
async def test_cpcud_service_apply_emits_staged_session_status():
    client = FakeClient()
    service = CPCRUDService(client)
    service._new_reader = lambda: AsyncMock()
    exe = Executor(client, AsyncMock())
    service._new_executor = lambda r: exe

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

    events = []
    async for event in service.apply(plan, no_publish=True, keep_session=True, session_name="staged-1"):
        events.append(event)

    log_events = [e for e in events if getattr(e, "event_type", None) == SSEEventType.LOG]
    assert len(log_events) >= 1
    staged_ev = next(e for e in log_events if isinstance(getattr(e, "data", None), dict) and e.data.get("type") == "staged_session")
    assert staged_ev.data["sid"] == "sid-1"
    assert staged_ev.data["session_uid"] == "sess-uid-123"
    assert client.logouts == []
