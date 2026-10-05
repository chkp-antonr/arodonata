# tests/unit/cpcrud/test_service.py
import types
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import SSEEvent, SSEEventType
from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.resolver import StateReadError
from arodonata.cpcrud.service import CPCRUDService
from arodonata.cpcrud.statereader import LiveStateReader
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


class _FailingIpReader(FakeReader):
    """find_by_ip fails for one address, as a failed or inconsistent show-objects listing does."""

    async def find_by_ip(self, *, type, ip_value, mgmt, domain):
        if "10.0.0.1" in ip_value.values():
            raise StateReadError("show-objects failed: paging_inconsistent: listing changed while paging")
        return await super().find_by_ip(type=type, ip_value=ip_value, mgmt=mgmt, domain=domain)


def _service_with_reader(reader):
    client = _fake_client()
    service = CPCRUDService(client)
    service._reader = reader
    service._planner._reader = reader
    service._executor._reader = reader
    return client, service


def _template(*ops):
    return {"management_servers": [{"mgmt_name": "m1", "domains": [{"name": "General", "operations": list(ops)}]}]}


@pytest.mark.asyncio
async def test_failed_ip_lookup_stops_the_create_not_the_other_objects():
    """Backlog #37: a failed lookup must not read as "no object with this IP" and create a duplicate."""
    client, service = _service_with_reader(_FailingIpReader())
    template = _template(
        {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
        {"type": "host", "data": {"name": "h2", "ip-address": "10.0.0.2"}},
    )

    report = [i async for i in service.apply(template)][-1]

    added = [payload["name"] for command, payload in client.calls if command == "add-host"]
    assert added == ["h2"]
    by_name = {r.name: r for r in report.results}
    assert by_name["h1"].outcome == Outcome.ERROR
    assert "lookup failed" in by_name["h1"].message and "paging_inconsistent" in by_name["h1"].message
    assert by_name["h2"].outcome == Outcome.CREATE


@pytest.mark.asyncio
async def test_failed_ip_lookup_in_a_rule_reference_creates_neither_the_host_nor_the_rule():
    client, service = _service_with_reader(_FailingIpReader())
    template = _template(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {
                "name": "r1",
                "source": ["10.0.0.1"],
                "destination": ["any"],
                "service": ["any"],
                "action": "accept",
            },
        }
    )

    report = [i async for i in service.apply(template)][-1]

    assert [command for command, _ in client.calls if command.startswith("add-")] == []
    assert [r.outcome for r in report.results] == [Outcome.ERROR]
    assert report.published_domains == []


class _HeadClient(FakeClient):
    """Executor fake client that also answers the head reads, recording every one that stores the stamp."""

    def __init__(self):
        super().__init__()
        self.settings = types.SimpleNamespace()
        self.head_reads = 0
        self.stamp_writes = 0

    async def fetch_last_published_session(self, mgmt_name, domain_name):
        self.head_reads += 1
        return types.SimpleNamespace(uid="sess-head")

    async def refresh_last_published_session(self, mgmt_name, domain_name):
        self.stamp_writes += 1
        return types.SimpleNamespace(uid="sess-head")


@pytest.mark.asyncio
async def test_plan_and_publish_never_store_the_object_cache_stamp():
    """Backlog #39: cpcrud reads the head to stamp its plan and its publish; storing it marked the object cache fresh
    without refreshing it, so cpcrud's own changes (and a publish before the plan) never reached the cache."""
    client = _HeadClient()
    service = CPCRUDService(client)
    live = LiveStateReader(client)

    class Reader(FakeReader):
        async def get_last_publish_session(self, *, mgmt, domain):
            return await live.get_last_publish_session(mgmt=mgmt, domain=domain)

    reader = Reader()
    service._reader = reader
    service._planner._reader = reader
    service._executor._reader = reader

    report = [
        i async for i in service.apply(_template({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.9"}}))
    ][-1]

    assert [c for c, _ in client.calls if c in ("add-host", "publish")] == ["add-host", "publish"]
    assert report.published_domains and report.published_domains[0].last_publish_session == "sess-head"
    assert client.head_reads == 3  # plan stamp, PLAN_STALE check, publish stamp
    assert client.stamp_writes == 0
