"""Unit tests for `TaskWaiter` (`src/arodonata/adapters/checkpoint/task_waiter.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from arodonata.adapters.checkpoint.task_waiter import TaskWaiter, extract_task_ids
from arodonata.core.errors import (
    ApiTimeoutError,
    CertificateMismatchError,
    TaskPollError,
    TaskTimeoutError,
)
from arodonata.core.models.common import ApiCallResult


class FakeClockAndSleep:
    def __init__(self, initial: float = 0.0) -> None:
        self.now = initial
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.now += duration


async def test_successful_task_completion_returns_final_show_task_response() -> None:
    """Scenario: Successful task completion returns final show-task response."""
    clock = FakeClockAndSleep()
    waiter = TaskWaiter(
        task_timeout=120.0,
        initial_delay=2.0,
        max_delay=10.0,
        backoff_factor=2.0,
        monotonic_fn=clock.monotonic,
        sleep_fn=clock.sleep,
    )

    responses = [
        ApiCallResult(
            success=True,
            data={"tasks": [{"task-id": "t-1", "status": "in progress", "progress-percentage": 30}]},
        ),
        ApiCallResult(
            success=True,
            data={"tasks": [{"task-id": "t-1", "status": "in progress", "progress-percentage": 80}]},
        ),
        ApiCallResult(
            success=True,
            data={
                "tasks": [
                    {
                        "task-id": "t-1",
                        "task-name": "Publish session",
                        "status": "succeeded",
                        "progress-percentage": 100,
                    }
                ]
            },
        ),
    ]
    idx = 0

    async def poll_fn(_payload: dict[str, Any]) -> ApiCallResult:
        nonlocal idx
        res = responses[idx]
        idx += 1
        return res

    task_ids = extract_task_ids({"task-id": "t-1"})
    assert task_ids == ["t-1"]

    final = await waiter.wait_for_tasks(task_ids, poll_fn)
    assert final.success is True
    assert final.task_id == "t-1"
    assert final.data["tasks"][0]["status"] == "succeeded"
    assert clock.sleeps == [2.0, 4.0, 8.0]


async def test_failed_or_partially_succeeded_task_returns_success_false_without_raising() -> None:
    """Scenario: Failed or partially succeeded task returns success=False without raising."""
    clock = FakeClockAndSleep()
    waiter = TaskWaiter(monotonic_fn=clock.monotonic, sleep_fn=clock.sleep)

    for terminal_status in ("failed", "partially succeeded"):

        async def poll_fn(
            _payload: dict[str, Any],
            _status: str = terminal_status,
        ) -> ApiCallResult:
            return ApiCallResult(
                success=True,
                data={
                    "tasks": [
                        {
                            "task-id": "t-fail",
                            "task-name": "Install Policy",
                            "status": _status,
                            "progress-percentage": 100,
                            "task-details": [{"statusDescription": "Gateway unreachable"}],
                        }
                    ]
                },
            )

        res = await waiter.wait_for_tasks("t-fail", poll_fn)
        assert res.success is False
        assert res.data["tasks"][0]["status"] == terminal_status
        assert res.error_message is not None
        assert "Gateway unreachable" in res.error_message


async def test_tolerance_of_transient_poll_failures_and_limits() -> None:
    """Scenario: Tolerance of transient poll failures (< 5 succeeds, 5 raises TaskPollError, timeout raises TaskTimeoutError)."""
    # 1. 4 consecutive transient errors followed by success -> succeeds!
    clock1 = FakeClockAndSleep()
    waiter1 = TaskWaiter(
        task_timeout=300.0,
        monotonic_fn=clock1.monotonic,
        sleep_fn=clock1.sleep,
    )
    attempts = 0

    async def poll_recover(_payload: dict[str, Any]) -> ApiCallResult:
        nonlocal attempts
        attempts += 1
        if attempts <= 4:
            raise ApiTimeoutError("Transient read timeout", phase="read")
        return ApiCallResult(
            success=True,
            data={"tasks": [{"task-id": "t-rec", "status": "succeeded", "progress-percentage": 100}]},
        )

    res = await waiter1.wait_for_tasks("t-rec", poll_recover)
    assert res.success is True
    assert attempts == 5

    # 2. 5 consecutive transient errors -> raises TaskPollError
    clock2 = FakeClockAndSleep()
    waiter2 = TaskWaiter(
        task_timeout=300.0,
        monotonic_fn=clock2.monotonic,
        sleep_fn=clock2.sleep,
    )

    async def poll_always_fails(_payload: dict[str, Any]) -> ApiCallResult:
        return ApiCallResult(success=False, status_code=503, error_message="Service unavailable")

    with pytest.raises(TaskPollError, match="5 consecutive"):
        await waiter2.wait_for_tasks("t-err", poll_always_fails)

    # 3. Expiration of task_timeout -> raises TaskTimeoutError (subclass of TimeoutError)
    clock3 = FakeClockAndSleep()
    waiter3 = TaskWaiter(
        task_timeout=15.0,
        initial_delay=2.0,
        max_delay=10.0,
        monotonic_fn=clock3.monotonic,
        sleep_fn=clock3.sleep,
    )

    async def poll_forever(_payload: dict[str, Any]) -> ApiCallResult:
        return ApiCallResult(
            success=True,
            data={"tasks": [{"task-id": "t-slow", "status": "in progress", "progress-percentage": 10}]},
        )

    with pytest.raises(TaskTimeoutError) as timeout_exc:
        await waiter3.wait_for_tasks("t-slow", poll_forever)
    assert isinstance(timeout_exc.value, TimeoutError)

    # 4. ServerIdentityError is NEVER retried
    identity_calls = 0

    async def poll_identity_error(_payload: dict[str, Any]) -> ApiCallResult:
        nonlocal identity_calls
        identity_calls += 1
        raise CertificateMismatchError("Certificate mismatch. No request was sent.")

    with pytest.raises(CertificateMismatchError):
        await waiter3.wait_for_tasks("t-id", poll_identity_error)
    assert identity_calls == 1
