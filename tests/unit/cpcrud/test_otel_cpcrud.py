"""OTEL span tests for CPCRUDService.apply (async-generator span) and executor actions."""

import types
from unittest.mock import AsyncMock

import pytest

from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.models import ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.service import CPCRUDService
from tests.unit.cpcrud.test_executor import FakeClient
from tests.unit.cpcrud.test_resolver import FakeReader

HOST_TEMPLATE = {
    "management_servers": [
        {
            "mgmt_name": "m1",
            "domains": [
                {
                    "name": "General",
                    "operations": [{"type": "host", "data": {"name": "otel-h1", "ip-address": "10.9.9.9"}}],
                }
            ],
        }
    ]
}


@pytest.fixture
def cpcrud_service():
    client = FakeClient()
    client.settings = types.SimpleNamespace()
    service = CPCRUDService(client)
    service._reader = FakeReader()  # plan() must not hit the API
    service._planner._reader = service._reader
    return service


async def test_apply_dry_run_emits_span_covering_stream(otel_spans, cpcrud_service):
    plan = await cpcrud_service.plan(HOST_TEMPLATE)
    events = [item async for item in cpcrud_service.apply(plan, dry_run=True)]
    assert isinstance(events[-1], ApplyReport)
    spans = {s.name: s for s in otel_spans.get_finished_spans()}
    apply_span = next(s for n, s in spans.items() if n.endswith(".apply"))
    assert apply_span.attributes["arodonata.template_hash"] == plan.template_hash[:12]
    assert apply_span.attributes["arodonata.dry_run"] is True
    plan_span = next(s for n, s in spans.items() if n.endswith(".plan"))
    assert plan_span is not None


async def test_apply_works_without_provider(cpcrud_service):
    # NOTE: does not genuinely prove the no-provider case in-process (see
    # test_traced_code_runs_correctly_with_no_provider_configured in
    # tests/unit/api/test_otel_client_surface.py for the real subprocess
    # coverage). Still validates correct return values regardless.
    plan = await cpcrud_service.plan(HOST_TEMPLATE)
    events = [item async for item in cpcrud_service.apply(plan, dry_run=True)]
    assert isinstance(events[-1], ApplyReport)


async def test_execute_action_span_uses_nested_action_attribute_names(otel_spans):
    """Executor._execute_action must namespace type/name/operation/outcome
    under action.* for consistency with lock.*/cleanup.* elsewhere, while
    mgmt_name/domain stay flat (genuinely common cross-cutting keys)."""
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
    await exe.execute(plan)

    span = next(s for s in otel_spans.get_finished_spans() if s.name.endswith("_execute_action"))
    assert span.attributes["arodonata.mgmt_name"] == "m1"
    assert span.attributes["arodonata.domain"] == "General"
    assert span.attributes["arodonata.action.type"] == "host"
    assert span.attributes["arodonata.action.name"] == "h1"
    assert span.attributes["arodonata.action.operation"] == "add"
    assert span.attributes["arodonata.action.outcome"] == Outcome.CREATE.value
    for old_key in ("arodonata.type", "arodonata.name", "arodonata.operation", "arodonata.outcome"):
        assert old_key not in span.attributes
