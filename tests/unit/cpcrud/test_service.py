# tests/unit/cpcrud/test_service.py
import types
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import SSEEvent, SSEEventType
from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.service import CPCRUDService
from tests.unit.cpcrud.test_executor import FakeClient
from tests.unit.cpcrud.test_resolver import FakeReader


def _fake_client():
    c = FakeClient()
    c.settings = types.SimpleNamespace()
    return c


@pytest.mark.asyncio
async def test_apply_dry_run_returns_plan_no_writes(monkeypatch):
    client = _fake_client()
    service = CPCRUDService(client)
    # inject a fake reader so plan() does not hit the API
    service._reader = FakeReader()
    service._planner._reader = service._reader
    template = {
        "management_servers": [
            {
                "mgmt_name": "m1",
                "domains": [
                    {
                        "name": "General",
                        "operations": [{"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}}],
                    }
                ],
            }
        ]
    }
    report = [i async for i in service.apply(template, dry_run=True)][-1]
    assert client.calls == []
    assert report.summary.get("create", 0) == 1


def test_validate_returns_errors_for_bad_template():
    service = CPCRUDService(_fake_client())
    assert not service.validate(
        {"management_servers": []}
    )  # empty management_servers is schema-valid (array may be empty)
    # assert a clearly-bad doc fails:
    bad = {"management_servers": [{"domains": []}]}  # mgmt_name required
    assert service.validate(bad)


async def test_apply_streams_events_then_report(monkeypatch):
    service = CPCRUDService(AsyncMock())

    async def fake_stream(plan, **kwargs):
        yield ActionResult(action_id="act-0001", outcome=Outcome.CREATE, uid="u1")
        yield ApplyReport(
            results=[ActionResult(action_id="act-0001", outcome=Outcome.CREATE, uid="u1")],
            published_domains=[],
            remaining=None,
            summary={"create": 1},
        )

    monkeypatch.setattr(service._executor, "stream", fake_stream)

    async def fake_plan(template, **kwargs):
        return Plan(
            actions=[
                PlannedAction(
                    id="act-0001", operation="add", type="host", mgmt_name="m", domain_name="d", resolved_name="h1"
                )
            ],
            stamps=[],
            template_hash="h",
        )

    monkeypatch.setattr(service, "plan", fake_plan)

    items = [item async for item in service.apply({"management_servers": []})]
    assert isinstance(items[-1], ApplyReport)
    events = [i for i in items[:-1] if isinstance(i, SSEEvent)]
    assert any(e.event_type == SSEEventType.RESULT for e in events)
    result_event = next(e for e in events if e.event_type == SSEEventType.RESULT)
    assert result_event.data["outcome"] == "create"
    assert result_event.mgmt_name == "m" and result_event.domain == "d"


async def test_apply_accepts_prebuilt_plan(monkeypatch):
    service = CPCRUDService(AsyncMock())
    seen = {}

    async def fake_stream(plan, **kwargs):
        seen["plan"] = plan
        yield ApplyReport(results=[], published_domains=[], remaining=None, summary={})

    monkeypatch.setattr(service._executor, "stream", fake_stream)
    prebuilt = Plan(actions=[], stamps=[], template_hash="prebuilt")
    [item async for item in service.apply(prebuilt, force=True)]
    assert seen["plan"].template_hash == "prebuilt"


TEMPLATE = {"management_servers": []}


@pytest.fixture
def service_with_flaky_executor(monkeypatch):
    service = CPCRUDService(AsyncMock())
    call_count = {"n": 0}

    initial_plan = Plan(
        actions=[
            PlannedAction(
                id="act-0001", operation="add", type="host", mgmt_name="m", domain_name="d", resolved_name="h1"
            )
        ],
        stamps=[],
        template_hash="h",
    )
    remaining_plan = Plan(
        actions=[
            PlannedAction(
                id="act-0001", operation="add", type="host", mgmt_name="m", domain_name="d", resolved_name="h1"
            )
        ],
        stamps=[],
        template_hash="h",
    )

    async def fake_stream(plan, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            result = ActionResult(action_id="act-0001", outcome=Outcome.LOCKED)
            yield result
            yield ApplyReport(results=[result], published_domains=[], remaining=remaining_plan, summary={"locked": 1})
        else:
            result = ActionResult(action_id="act-0001", outcome=Outcome.CREATE, uid="u1")
            yield result
            yield ApplyReport(results=[result], published_domains=[], remaining=None, summary={"create": 1})

    monkeypatch.setattr(service._executor, "stream", fake_stream)

    async def fake_plan(template, **kwargs):
        return initial_plan

    monkeypatch.setattr(service, "plan", fake_plan)
    return service


@pytest.mark.asyncio
async def test_apply_retries_remaining_once(service_with_flaky_executor):
    events = [e async for e in service_with_flaky_executor.apply(TEMPLATE, retry_remaining=1)]
    report = events[-1]
    assert isinstance(report, ApplyReport)
    assert report.summary.get("locked") is None or report.summary == {"create": 1}
    assert report.remaining is None
    retry_events = [e for e in events if isinstance(e, SSEEvent) and e.data and e.data.get("attempt") == 1]
    assert retry_events, "retry pass events must carry attempt=1"


@pytest.mark.asyncio
async def test_apply_default_no_retry(service_with_flaky_executor):
    events = [e async for e in service_with_flaky_executor.apply(TEMPLATE)]
    report = events[-1]
    assert report.remaining is not None  # unchanged 1.2.0 behavior
