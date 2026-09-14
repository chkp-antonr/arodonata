"""OTEL span tests for TaskWaiter (one span per wait, so a slow revert is a span, not a gap)."""

from __future__ import annotations

import pytest

from arodonata.asdk.task_waiter import TaskWaiter
from arodonata.core.exceptions import TaskTimeoutError


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def _response(status, progress=100, task_id="01ab"):
    return {
        "success": True,
        "data": {"tasks": [{"task-id": task_id, "status": status, "progress-percentage": progress}]},
        "message": "",
        "code": "200",
    }


async def test_wait_records_span_with_task_attributes(otel_spans):
    clock = FakeClock()
    queue = [_response("in progress", 10), _response("succeeded")]

    async def show_task(payload):
        return queue.pop(0)

    await TaskWaiter(sleep=clock.sleep, clock=clock).wait(show_task, ["01ab"], timeout=900)

    spans = otel_spans.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name.endswith("TaskWaiter.wait")
    assert span.attributes["arodonata.task_ids"] == "01ab"
    assert span.attributes["arodonata.task_count"] == 1
    assert span.attributes["arodonata.task_final_status"] == "succeeded"
    assert span.attributes["arodonata.task_polls"] == 2
    assert span.attributes["arodonata.task_duration_ms"] == 2000  # one 2 s backoff sleep


async def test_wait_records_unsuccessful_final_status_without_error_status(otel_spans):
    """Task failure is data, so the span ends normally; the status attribute carries it."""
    clock = FakeClock()

    async def show_task(payload):
        return _response("failed")

    await TaskWaiter(sleep=clock.sleep, clock=clock).wait(show_task, ["01ab"], timeout=900)

    span = otel_spans.get_finished_spans()[0]
    assert span.attributes["arodonata.task_final_status"] == "failed"
    assert span.status.is_ok or span.status.status_code.name == "UNSET"


async def test_wait_records_timeout_on_the_span(otel_spans):
    clock = FakeClock()

    async def show_task(payload):
        return _response("in progress", 40)

    with pytest.raises(TaskTimeoutError):
        await TaskWaiter(sleep=clock.sleep, clock=clock).wait(show_task, ["01ab"], timeout=5)

    span = otel_spans.get_finished_spans()[0]
    assert span.attributes["arodonata.task_final_status"] == "timeout"
    assert span.attributes["arodonata.task_duration_ms"] == 5000
    assert span.status.status_code.name == "ERROR"
