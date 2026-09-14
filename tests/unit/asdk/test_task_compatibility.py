"""The self-managed task-polling contract, pinned case by case.

Every row of the compatibility table in
`docs/_AI_/2609/260913-self-managed-task-polling-design.md` gets a test here,
end-to-end through `ApiTransport.api_call` with a fake cpapi client. A future
change to task classification must fail one of these rather than an application
that consumes this library.

| Situation                | Contract                                              |
|--------------------------|-------------------------------------------------------|
| Task succeeds            | success=True, data = final show-task result           |
| Task `failed`            | success=False, same data, NO exception                |
| Task `partially succeeded` | success=False, NO exception                         |
| Wait exceeds `timeout`   | raises TaskTimeoutError, caught by `except TimeoutError` |
| `wait_for_task=False`    | returns the task-id response, untouched               |
| Non-task command         | returns immediately, untouched                        |
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from arodonata.asdk.task_waiter import TaskWaiter
from arodonata.asdk.transport import ApiTransport
from arodonata.core.exceptions import TaskPollError, TaskTimeoutError


def _sdk_response(*, success=True, data=None, status_code="200"):
    """Minimal fake mirroring the cpapi APIResponse attrs the transport reads."""
    return SimpleNamespace(success=success, data={} if data is None else data, message="", status_code=status_code)


def _task(task_id="01ab", status="succeeded", progress=100):
    return {"task-id": task_id, "status": status, "progress-percentage": progress}


def _tasks_response(*tasks):
    return _sdk_response(data={"tasks": list(tasks)})


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def _transport(responses):
    """ApiTransport whose cpapi client returns `responses` in order (last repeats).

    `transport.calls` records `(command, payload, wait_for_task)` per cpapi call.
    """
    calls: list[tuple[str, dict, bool]] = []
    queue = list(responses)

    @asynccontextmanager
    async def _client(self, server_ip, port=None, sid=None):
        client = MagicMock()
        client.sid = sid

        def api_call(command, payload=None, sid_=None, wait_for_task=True, timeout=-1):
            calls.append((command, payload or {}, wait_for_task))
            return queue.pop(0) if len(queue) > 1 else queue[0]

        client.api_call = MagicMock(side_effect=api_call)
        yield client

    clock = FakeClock()
    transport = ApiTransport(task_waiter=TaskWaiter(sleep=clock.sleep, clock=clock))
    transport._client = _client.__get__(transport, ApiTransport)  # type: ignore[method-assign]
    transport.calls = calls  # type: ignore[attr-defined]
    transport.clock = clock  # type: ignore[attr-defined]
    return transport


def _commands(transport):
    return [c[0] for c in transport.calls]


# --------------------------------------------------------------------------
# Rows: non-task command, wait_for_task=False, failed initial call
# --------------------------------------------------------------------------


async def test_non_task_response_is_returned_untouched_and_never_polls():
    transport = _transport([_sdk_response(data={"uid": "u1"})])

    result = await transport.api_call("10.0.0.1", "sid-1", "show-hosts")

    assert result == {"success": True, "data": {"uid": "u1"}, "message": "", "code": "200"}
    assert _commands(transport) == ["show-hosts"]


async def test_wait_for_task_false_returns_the_task_id_response_unwaited():
    transport = _transport([_sdk_response(data={"task-id": "01ab"})])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", wait_for_task=False)

    assert result["data"] == {"task-id": "01ab"}
    assert _commands(transport) == ["publish"]


async def test_failed_initial_call_is_not_waited_on():
    """cpapi's own guard: `res.success` must be true before it looks for a task-id."""
    transport = _transport([_sdk_response(success=False, data={"code": "err_x", "message": "nope", "task-id": "x"})])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=900)

    assert result["success"] is False
    assert result["code"] == "err_x"
    assert _commands(transport) == ["publish"]


async def test_cpapi_is_never_asked_to_wait_for_a_task():
    """cpapi's blocking poll loop must never run again, whatever the caller asks for."""
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task())])

    await transport.api_call("10.0.0.1", "sid-1", "publish", wait_for_task=True, timeout=30)

    assert [c[2] for c in transport.calls] == [False, False]


# --------------------------------------------------------------------------
# Rows: task succeeds / fails / partially succeeds / unknown status
# --------------------------------------------------------------------------


async def test_task_success_returns_the_final_show_task_result():
    transport = _transport(
        [
            _sdk_response(data={"task-id": "01ab"}),
            _tasks_response(_task("01ab", "in progress", 30)),
            _tasks_response(_task("01ab", "succeeded")),
        ]
    )

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=900)

    assert result["success"] is True
    assert result["data"] == {"tasks": [_task("01ab", "succeeded")]}
    assert result["code"] == "200"  # the show-task HTTP status, as cpapi's path produced
    assert _commands(transport) == ["publish", "show-task", "show-task"]
    assert transport.calls[1][1] == {"task-id": "01ab", "details-level": "full"}


@pytest.mark.parametrize("status", ["failed", "partially succeeded"])
async def test_task_failure_yields_success_false_and_raises_nothing(status):
    """Hard requirement: `if not result.success` must keep working, unchanged."""
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", status))])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=900)

    assert result["success"] is False
    assert result["data"] == {"tasks": [_task("01ab", status)]}
    assert result["code"] == "200"


async def test_unknown_status_is_not_treated_as_success():
    """Allowlist: cpapi's denylist would have let `sideways` through as a success."""
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", "sideways"))])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=900)

    assert result["success"] is False


async def test_one_failed_task_among_several_fails_the_whole_response():
    transport = _transport(
        [
            _sdk_response(data={"task-id": ["01ab", "02cd"]}),
            _tasks_response(_task("01ab", "succeeded"), _task("02cd", "failed")),
        ]
    )

    result = await transport.api_call("10.0.0.1", "sid-1", "install-policy", timeout=900)

    assert result["success"] is False


async def test_a_failed_publish_task_reaches_a_consumer_as_success_false():
    """cpcrud/executor.py and MMP both branch on `if not res.success` -- never on an exception.

    The assertion that matters most here is the one that is implicit: nothing raised.
    """
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", "failed"))])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=900)

    assert result["success"] is False
    assert result["data"]["tasks"][0]["status"] == "failed"


# --------------------------------------------------------------------------
# Rows: the `tasks` list shape (open question - both shapes covered)
# --------------------------------------------------------------------------


async def test_tasks_list_of_dicts_waits_on_every_id():
    transport = _transport(
        [
            _sdk_response(data={"tasks": [{"task-id": "01ab"}, {"task-id": "02cd"}]}),
            _tasks_response(_task("01ab", "succeeded"), _task("02cd", "succeeded")),
        ]
    )

    result = await transport.api_call("10.0.0.1", "sid-1", "install-policy", timeout=900)

    assert result["success"] is True
    assert transport.calls[1][1] == {"task-id": ["01ab", "02cd"], "details-level": "full"}


async def test_tasks_list_of_bare_ids_waits_on_every_id():
    transport = _transport(
        [
            _sdk_response(data={"tasks": ["01ab", "02cd"]}),
            _tasks_response(_task("01ab", "succeeded"), _task("02cd", "succeeded")),
        ]
    )

    await transport.api_call("10.0.0.1", "sid-1", "run-script", timeout=900)

    assert transport.calls[1][1] == {"task-id": ["01ab", "02cd"], "details-level": "full"}


# --------------------------------------------------------------------------
# Rows: recursion guard, timeout, poll exhaustion
# --------------------------------------------------------------------------


async def test_show_task_never_waits_on_itself():
    transport = _transport([_tasks_response(_task("01ab", "in progress", 5))])

    result = await transport.api_call("10.0.0.1", "sid-1", "show-task", payload={"task-id": "01ab"})

    assert _commands(transport) == ["show-task"]
    assert result["success"] is True


async def test_wait_exceeding_the_budget_raises_task_timeout_error_with_detail():
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", "in progress", 40))])

    with pytest.raises(TaskTimeoutError) as excinfo:
        await transport.api_call("10.0.0.1", "sid-1", "revert-to-revision", timeout=30)

    message = str(excinfo.value)
    assert "task 01ab 'in progress' at 40%" in message
    assert "revert-to-revision on 10.0.0.1" in message
    assert excinfo.value.task_ids == ["01ab"]


async def test_task_timeout_is_caught_by_an_existing_except_timeout_error_handler():
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", "in progress", 40))])

    with pytest.raises(TimeoutError):
        await transport.api_call("10.0.0.1", "sid-1", "revert-to-revision", timeout=30)


async def test_timeout_budget_covers_the_whole_operation_not_just_the_poll():
    """`timeout` keeps its meaning: initial call + polling. REVERT_TIMEOUT_SECONDS stays correct."""
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), _tasks_response(_task("01ab", "in progress", 1))])

    with pytest.raises(TaskTimeoutError) as excinfo:
        await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=25)

    # 2 + 4 + 8 + 10 = 24 s of backoff, then a 1 s clipped sleep to the 25 s deadline.
    assert transport.clock.now == pytest.approx(25.0, abs=0.5)
    assert "after 25s" in str(excinfo.value)


async def test_non_positive_timeout_waits_without_a_deadline():
    in_progress = _tasks_response(_task("01ab", "in progress", 1))
    transport = _transport([_sdk_response(data={"task-id": "01ab"}), *([in_progress] * 30), _tasks_response(_task())])

    result = await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=-1)

    assert result["success"] is True
    assert transport.clock.now > 120


async def test_exhausted_show_task_failures_raise_task_poll_error():
    transport = _transport(
        [_sdk_response(data={"task-id": "01ab"}), _sdk_response(success=False, data={"message": "reset"})]
    )

    with pytest.raises(TaskPollError) as excinfo:
        await transport.api_call("10.0.0.1", "sid-1", "publish", timeout=-1)

    assert excinfo.value.task_ids == ["01ab"]
    assert _commands(transport) == ["publish"] + ["show-task"] * 6


# --------------------------------------------------------------------------
# Concurrency: polls must not re-enter the rate limiter or the client path
# --------------------------------------------------------------------------


class CountingLimiter:
    """Stands in for RateLimiter, counting slot acquisitions."""

    def __init__(self) -> None:
        self.acquisitions = 0

    @asynccontextmanager
    async def acquire(self, server_ip, timeout=None):
        self.acquisitions += 1
        yield


async def test_a_task_wrapped_call_acquires_the_rate_limiter_exactly_once():
    """The slot is held for the whole task by design (Anton, 2026-09-13).

    Polls go straight to the transport, so they never touch RateLimiter.acquire --
    no reentrancy question, no deadlock risk, and a revert deliberately occupies
    one of the three slots for its full duration as a throttle. If a future change
    routes polls through the client path instead, this is the test to argue with.
    """
    from unittest.mock import AsyncMock

    from arodonata.asdk.client import AMgmtClient

    transport = _transport(
        [
            _sdk_response(data={"task-id": "01ab"}),
            _tasks_response(_task("01ab", "in progress", 10)),
            _tasks_response(_task("01ab", "in progress", 60)),
            _tasks_response(_task("01ab", "succeeded")),
        ]
    )
    limiter = CountingLimiter()
    registry = MagicMock()
    registry.get_server.return_value = SimpleNamespace(port=None)
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "10.0.0.1")
    login_coordinator._credential_username = None

    client = AMgmtClient(registry, transport, limiter, login_coordinator)  # type: ignore[arg-type]
    result = await client.api_call("mgmt1", "publish", timeout=900)
    await client.close()

    assert result["success"] is True
    assert _commands(transport) == ["publish", "show-task", "show-task", "show-task"]
    assert limiter.acquisitions == 1
    login_coordinator.login.assert_awaited_once()  # no re-login per poll either


# --------------------------------------------------------------------------
# Construction: existing call sites are untouched
# --------------------------------------------------------------------------


def test_transport_builds_its_own_waiter_when_none_is_given():
    transport = ApiTransport()
    assert isinstance(transport._task_waiter, TaskWaiter)
