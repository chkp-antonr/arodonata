"""Unit tests for TaskWaiter: response parsing, poll loop, backoff, tolerance, timeout.

Lab-free throughout: `show_task` is a plain async callable, and the waiter takes an
injected `sleep`/`clock` pair so a "ten-minute revert" runs in milliseconds.
"""

from __future__ import annotations

import pytest

from arodonata.asdk.task_waiter import TaskStatus, TaskWaiter, extract_task_ids, parse_task_statuses
from arodonata.core.exceptions import TaskPollError, TaskTimeoutError


def _show_task_response(*tasks, success=True):
    return {"success": success, "data": {"tasks": list(tasks)}, "message": "", "code": "200"}


def _task(task_id="01ab", status="succeeded", progress=100):
    entry = {"task-id": task_id, "status": status}
    if progress is not None:
        entry["progress-percentage"] = progress
    return entry


# --------------------------------------------------------------------------
# extract_task_ids - every response shape Check Point is known or believed to use
# --------------------------------------------------------------------------


def test_extract_task_ids_single_task_id_string():
    assert extract_task_ids({"task-id": "01ab"}) == ["01ab"]


def test_extract_task_ids_task_id_as_list():
    assert extract_task_ids({"task-id": ["01ab", "02cd"]}) == ["01ab", "02cd"]


def test_extract_task_ids_tasks_list_of_dicts():
    """The shape cpapi's __wait_for_tasks handles; assumed for install-policy/run-script."""
    data = {"tasks": [{"task-id": "01ab"}, {"task-id": "02cd"}]}
    assert extract_task_ids(data) == ["01ab", "02cd"]


def test_extract_task_ids_tasks_list_of_bare_strings():
    """Defensive: a `tasks` list of plain ids, unverified against the lab."""
    assert extract_task_ids({"tasks": ["01ab", "02cd"]}) == ["01ab", "02cd"]


def test_extract_task_ids_deduplicates_preserving_order():
    data = {"task-id": "01ab", "tasks": [{"task-id": "01ab"}, {"task-id": "02cd"}]}
    assert extract_task_ids(data) == ["01ab", "02cd"]


@pytest.mark.parametrize(
    "data",
    [None, {}, {"uid": "u1"}, "a string", {"tasks": [None, 5]}, {"task-id": ""}, {"tasks": "01ab"}],
)
def test_extract_task_ids_returns_empty_for_non_task_responses(data):
    assert extract_task_ids(data) == []


# --------------------------------------------------------------------------
# parse_task_statuses - status normalization and the progress open question
# --------------------------------------------------------------------------


def test_parse_task_statuses_reads_id_status_and_progress():
    statuses = parse_task_statuses(_show_task_response(_task("01ab", "in progress", 40)))
    assert statuses == [
        TaskStatus(
            task_id="01ab",
            status="in progress",
            progress=40,
            raw={"task-id": "01ab", "status": "in progress", "progress-percentage": 40},
        )
    ]


def test_parse_task_statuses_tolerates_missing_progress_percentage():
    """Open question: progress may not be populated on this CP version. None is fine."""
    statuses = parse_task_statuses(_show_task_response(_task("01ab", "in progress", None)))
    assert statuses[0].progress is None


@pytest.mark.parametrize("value", [None, "", "n/a", True, {"pct": 40}])
def test_parse_task_statuses_tolerates_unparseable_progress(value):
    response = _show_task_response({"task-id": "01ab", "status": "in progress", "progress-percentage": value})
    assert parse_task_statuses(response)[0].progress is None


def test_parse_task_statuses_normalizes_status_case_and_whitespace():
    """`In Progress ` must not read as a terminal status just because CP changed casing."""
    response = _show_task_response({"task-id": "01ab", "status": " In Progress "})
    status = parse_task_statuses(response)[0]
    assert status.status == "in progress"
    assert status.is_terminal is False


@pytest.mark.parametrize(
    ("status", "terminal", "success"),
    [
        ("succeeded", True, True),
        ("failed", True, False),
        ("partially succeeded", True, False),
        ("in progress", False, False),
        # Allowlist, not cpapi's denylist: an unrecognized status ends the wait
        # (it is not "in progress") but is never read as a success.
        ("something new", True, False),
    ],
)
def test_task_status_terminal_and_success_classification(status, terminal, success):
    entry = TaskStatus(task_id="01ab", status=status, progress=None, raw={})
    assert entry.is_terminal is terminal
    assert entry.is_success is success


def test_task_status_describe_renders_unknown_progress():
    assert TaskStatus("01ab", "in progress", None, {}).describe() == "task 01ab 'in progress' at unknown%"
    assert TaskStatus("01ab", "in progress", 40, {}).describe() == "task 01ab 'in progress' at 40%"


@pytest.mark.parametrize("response", [{}, {"data": None}, {"data": {}}, {"data": {"tasks": "nope"}}])
def test_parse_task_statuses_returns_empty_for_malformed_responses(response):
    assert parse_task_statuses(response) == []


def test_parse_task_statuses_skips_non_dict_entries():
    response = _show_task_response(None, "junk", _task("01ab"))
    assert [s.task_id for s in parse_task_statuses(response)] == ["01ab"]


# --------------------------------------------------------------------------
# TaskWaiter.wait() - fixtures
# --------------------------------------------------------------------------


class FakeClock:
    """Monotonic clock advanced only by the fake sleep, so tests are instant."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _waiter(clock, **kwargs):
    return TaskWaiter(sleep=clock.sleep, clock=clock, **kwargs)


def _scripted(*responses):
    """A show_task callable returning each response in turn (last one repeats), recording payloads."""
    calls: list[dict] = []
    queue = list(responses)

    async def show_task(payload):
        calls.append(payload)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    show_task.calls = calls  # type: ignore[attr-defined]
    return show_task


_POLL_FAILURE = {"success": False, "data": None, "message": "connection reset", "code": "err"}


# --------------------------------------------------------------------------
# wait() - completion
# --------------------------------------------------------------------------


async def test_wait_returns_immediately_when_first_poll_is_terminal():
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab", "succeeded", 100)))

    statuses = await _waiter(clock).wait(show_task, ["01ab"], timeout=900)

    assert [s.status for s in statuses] == ["succeeded"]
    assert len(show_task.calls) == 1
    assert clock.slept == []  # no sleep before a task that is already done


async def test_wait_polls_until_the_task_leaves_in_progress():
    clock = FakeClock()
    show_task = _scripted(
        _show_task_response(_task("01ab", "in progress", 10)),
        _show_task_response(_task("01ab", "in progress", 55)),
        _show_task_response(_task("01ab", "succeeded", 100)),
    )

    statuses = await _waiter(clock).wait(show_task, ["01ab"], timeout=900)

    assert len(show_task.calls) == 3
    assert statuses[0].status == "succeeded"
    assert statuses[0].progress == 100


async def test_wait_sends_details_level_full_and_a_single_id_as_a_scalar():
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab")))

    await _waiter(clock).wait(show_task, ["01ab"], timeout=900)

    assert show_task.calls[0] == {"task-id": "01ab", "details-level": "full"}


async def test_wait_sends_several_ids_as_a_list():
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab"), _task("02cd")))

    await _waiter(clock).wait(show_task, ["01ab", "02cd"], timeout=900)

    assert show_task.calls[0] == {"task-id": ["01ab", "02cd"], "details-level": "full"}


async def test_wait_keeps_polling_until_the_slowest_of_several_tasks_finishes():
    clock = FakeClock()
    show_task = _scripted(
        _show_task_response(_task("01ab", "succeeded"), _task("02cd", "in progress", 20)),
        _show_task_response(_task("01ab", "succeeded"), _task("02cd", "in progress", 80)),
        _show_task_response(_task("01ab", "succeeded"), _task("02cd", "failed")),
    )

    statuses = await _waiter(clock).wait(show_task, ["01ab", "02cd"], timeout=900)

    assert [s.status for s in statuses] == ["succeeded", "failed"]
    assert len(show_task.calls) == 3


@pytest.mark.parametrize("status", ["failed", "partially succeeded", "something new"])
async def test_wait_does_not_raise_when_a_task_ends_unsuccessfully(status):
    """Hard requirement: task failure is data, never an exception."""
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab", status, 100)))

    statuses = await _waiter(clock).wait(show_task, ["01ab"], timeout=900)

    assert statuses[0].status == status
    assert statuses[0].is_success is False


async def test_wait_with_no_task_ids_returns_empty_without_polling():
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab")))

    assert await _waiter(clock).wait(show_task, [], timeout=900) == []
    assert show_task.calls == []


# --------------------------------------------------------------------------
# wait() - backoff schedule
# --------------------------------------------------------------------------


async def test_wait_backs_off_geometrically_and_caps_at_poll_max():
    clock = FakeClock()
    in_progress = _show_task_response(_task("01ab", "in progress", 1))
    done = _show_task_response(_task("01ab", "succeeded", 100))
    show_task = _scripted(*([in_progress] * 6), done)

    await _waiter(clock, poll_initial=2.0, poll_max=10.0).wait(show_task, ["01ab"], timeout=900)

    assert clock.slept == [2.0, 4.0, 8.0, 10.0, 10.0, 10.0]


async def test_wait_never_sleeps_past_the_deadline():
    """The last sleep is clipped to what is left, so a timeout fires on time, not a poll late."""
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab", "in progress", 40)))

    with pytest.raises(TaskTimeoutError):
        await _waiter(clock, poll_initial=2.0, poll_max=10.0).wait(show_task, ["01ab"], timeout=9)

    assert clock.slept == [2.0, 4.0, 3.0]
    assert clock.now == 9.0


# --------------------------------------------------------------------------
# wait() - timeout
# --------------------------------------------------------------------------


async def test_wait_raises_task_timeout_error_carrying_id_status_and_progress():
    """The 2026-09-13 b3 failure, made legible: a bare TimeoutError told us nothing."""
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab", "in progress", 40)))

    with pytest.raises(TaskTimeoutError) as excinfo:
        await _waiter(clock).wait(show_task, ["01ab"], timeout=30, context="revert-to-revision on Domain4")

    message = str(excinfo.value)
    assert "task 01ab 'in progress' at 40%" in message
    assert "after 30s" in message
    assert "(revert-to-revision on Domain4)" in message
    assert excinfo.value.task_ids == ["01ab"]
    assert excinfo.value.statuses[0].status == "in progress"


async def test_wait_timeout_is_caught_by_a_bare_except_timeout_error():
    """The compatibility guarantee, pinned at the waiter level."""
    clock = FakeClock()
    show_task = _scripted(_show_task_response(_task("01ab", "in progress", 40)))

    with pytest.raises(TimeoutError):
        await _waiter(clock).wait(show_task, ["01ab"], timeout=30)


async def test_wait_timeout_message_is_legible_when_no_status_was_ever_observed():
    clock = FakeClock()
    show_task = _scripted(_POLL_FAILURE)

    with pytest.raises(TaskTimeoutError) as excinfo:
        await _waiter(clock).wait(show_task, ["01ab"], timeout=5)

    assert "01ab" in str(excinfo.value)
    assert "no status observed" in str(excinfo.value)
    assert excinfo.value.statuses == []


async def test_wait_with_non_positive_timeout_polls_without_a_deadline():
    clock = FakeClock()
    in_progress = _show_task_response(_task("01ab", "in progress", 1))
    show_task = _scripted(*([in_progress] * 20), _show_task_response(_task("01ab", "succeeded", 100)))

    statuses = await _waiter(clock).wait(show_task, ["01ab"], timeout=-1)

    assert statuses[0].status == "succeeded"
    assert clock.now > 30  # would have timed out long ago under any positive budget


async def test_wait_bounds_a_hung_poll_by_the_remaining_budget():
    """A show-task that never answers cannot outlive the wait: asyncio.wait_for guards it."""
    import asyncio

    async def show_task(payload):
        await asyncio.sleep(3600)  # real loop time - would hang without the guard
        return _show_task_response(_task("01ab"))

    with pytest.raises(TaskTimeoutError) as excinfo:
        await TaskWaiter().wait(show_task, ["01ab"], timeout=0.05)

    assert "no status observed" in str(excinfo.value)


# --------------------------------------------------------------------------
# wait() - poll-failure tolerance
# --------------------------------------------------------------------------


async def test_wait_survives_poll_failures_under_the_tolerance():
    clock = FakeClock()
    show_task = _scripted(*([_POLL_FAILURE] * 5), _show_task_response(_task("01ab", "succeeded", 100)))

    statuses = await _waiter(clock, poll_failure_tolerance=5).wait(show_task, ["01ab"], timeout=-1)

    assert statuses[0].status == "succeeded"
    assert len(show_task.calls) == 6


async def test_wait_raises_task_poll_error_once_failures_exceed_the_tolerance():
    clock = FakeClock()
    show_task = _scripted(_POLL_FAILURE)

    with pytest.raises(TaskPollError) as excinfo:
        await _waiter(clock, poll_failure_tolerance=5).wait(show_task, ["01ab"], timeout=-1)

    assert len(show_task.calls) == 6  # five tolerated, the sixth gives up - cpapi's arithmetic
    assert excinfo.value.task_ids == ["01ab"]
    assert "connection reset" in str(excinfo.value)


async def test_wait_resets_the_failure_counter_after_a_successful_poll():
    clock = FakeClock()
    in_progress = _show_task_response(_task("01ab", "in progress", 50))
    show_task = _scripted(
        *([_POLL_FAILURE] * 5),
        in_progress,
        *([_POLL_FAILURE] * 5),
        _show_task_response(_task("01ab", "succeeded", 100)),
    )

    statuses = await _waiter(clock, poll_failure_tolerance=5).wait(show_task, ["01ab"], timeout=-1)

    assert statuses[0].status == "succeeded"
    assert len(show_task.calls) == 12


async def test_wait_treats_a_raising_show_task_as_a_poll_failure():
    clock = FakeClock()
    calls = {"n": 0}

    async def show_task(payload):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise ConnectionError("socket died")
        return _show_task_response(_task("01ab", "succeeded", 100))

    statuses = await _waiter(clock, poll_failure_tolerance=5).wait(show_task, ["01ab"], timeout=-1)

    assert statuses[0].status == "succeeded"


async def test_wait_treats_a_response_without_task_entries_as_a_poll_failure():
    clock = FakeClock()
    empty = {"success": True, "data": {}, "message": "", "code": "200"}
    show_task = _scripted(empty, empty, _show_task_response(_task("01ab", "succeeded", 100)))

    statuses = await _waiter(clock).wait(show_task, ["01ab"], timeout=-1)

    assert statuses[0].status == "succeeded"


async def test_wait_backs_off_between_failed_polls_too():
    clock = FakeClock()
    show_task = _scripted(_POLL_FAILURE, _POLL_FAILURE, _show_task_response(_task("01ab", "succeeded", 100)))

    await _waiter(clock, poll_initial=2.0, poll_max=10.0).wait(show_task, ["01ab"], timeout=-1)

    assert clock.slept == [2.0, 4.0]
