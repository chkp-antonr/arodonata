"""Self-managed polling of Check Point long-running tasks.

Check Point answers `publish`, `revert-to-revision`, `install-policy` and
`run-script` with a `task-id` instead of a result. cpapi can wait for such a task
itself (`api_call(..., wait_for_task=True)`), but it does so in a blocking loop
inside one thread: its `show-task` calls bypass this library's transport entirely
-- no rate limiting, no OTel span, no log line -- and a timeout surfaces as a bare
`TimeoutError` carrying no task-id, status or progress. A ten-minute revert was
therefore ~300 invisible API calls followed, at worst, by an empty exception
(seen 2026-09-13: `API CALL TIMEOUT: revert-to-revision (timeout=120s)` and no
way to tell whether the revert had started, was half-done, or had hung).

`TaskWaiter` takes that wait over. It is stateless and owned by `ApiTransport`,
which constructs it once with the policy knobs and hands `wait()` a `show_task`
callable already bound to the live server/session of the call being waited on --
so this module stays free of any client, session or transport type and is
testable with a plain async lambda (the same shape `cpcrud/nat_sentinels.py` uses).

It does NOT raise on task failure. A `failed` or `partially succeeded` task is
data, returned to the caller, which renders it exactly as cpapi's
`check_tasks_status` did: `success=False` on the response, no exception. That is a
hard backward-compatibility requirement -- applications branch on
`if not result.success`, and turning that into an exception would break them.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from arlogi.otel.decorator import traced

from ..config.constants import (
    DEFAULT_TASK_POLL_FAILURE_TOLERANCE,
    DEFAULT_TASK_POLL_INITIAL_SECONDS,
    DEFAULT_TASK_POLL_MAX_SECONDS,
)
from ..core.exceptions import TaskPollError, TaskTimeoutError
from ..logger import lazy_logger
from ..telemetry import span_attrs

log = lazy_logger("arodonata.asdk.task_waiter")

# Deliberately re-declared instead of imported from `transport`, which imports this
# module: the dependency runs one way only.
TaskResponse = dict[str, Any]
ShowTask = Callable[[dict[str, Any]], Awaitable[TaskResponse]]
Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]

IN_PROGRESS = "in progress"
SUCCEEDED = "succeeded"


@dataclass(frozen=True)
class TaskStatus:
    """One task's last observed state, as read from a `show-task` entry."""

    task_id: str
    status: str
    progress: int | None
    raw: dict[str, Any]

    @property
    def is_terminal(self) -> bool:
        """True once the task has left `in progress` -- successfully or not.

        Matches cpapi's completion rule exactly (`status != "in progress"`), so an
        unrecognized status ends the wait rather than polling forever.
        """
        return self.status != IN_PROGRESS

    @property
    def is_success(self) -> bool:
        """True only for an explicit `succeeded`.

        An allowlist where cpapi's `check_tasks_status` is a denylist: cpapi flips
        success off only for `failed` / `partially succeeded` / `in progress` and
        lets anything unfamiliar through as a success. An unknown status is far
        more likely to be a new failure mode than a new way of succeeding, so it
        is not a success here.
        """
        return self.status == SUCCEEDED

    def describe(self) -> str:
        """`task <id> '<status>' at <progress>%`, for logs and the timeout message."""
        progress = "unknown" if self.progress is None else str(self.progress)
        return f"task {self.task_id} {self.status!r} at {progress}%"


def extract_task_ids(data: Any) -> list[str]:
    """Pull task ids out of a command response's `data`, tolerating every known shape.

    Publish and revert-to-revision return `{"task-id": "<id>"}` in this repo's
    observed traffic. install-policy and run-script are believed to return a
    `tasks` list (cpapi has a separate `__wait_for_tasks` path for it) but this has
    not been verified against the lab, so both list-of-dicts and list-of-strings
    are accepted, as is a `task-id` that is itself a list. Order-preserving and
    de-duplicated; [] for anything that carries no task.
    """
    if not isinstance(data, dict):
        return []

    raw_id = data.get("task-id")
    candidates: list[Any] = raw_id if isinstance(raw_id, list) else [raw_id]
    entries = data.get("tasks")
    if isinstance(entries, list):
        candidates = [*candidates, *entries]

    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        task_id = _task_id_of(candidate)
        if task_id and task_id not in seen:
            seen.add(task_id)
            unique.append(task_id)
    return unique


def _task_id_of(entry: Any) -> str | None:
    """A task id from either a bare id string or a `{"task-id": ...}` object."""
    if isinstance(entry, dict):
        entry = entry.get("task-id")
    return entry if isinstance(entry, str) and entry else None


def _parse_progress(entry: dict[str, Any]) -> int | None:
    """Read `progress-percentage`, or None when the server does not report one.

    Whether this CP version populates the field at all is an open question; nothing
    branches on it, so None only costs detail in a log line.
    """
    value = entry.get("progress-percentage")
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_task_statuses(response: TaskResponse) -> list[TaskStatus]:
    """Read the `tasks` entries out of a `show-task` response; [] if malformed."""
    data = response.get("data")
    entries = data.get("tasks") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []

    statuses: list[TaskStatus] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        statuses.append(
            TaskStatus(
                task_id=str(entry.get("task-id", "")),
                status=str(entry.get("status", "")).strip().lower(),
                progress=_parse_progress(entry),
                raw=entry,
            )
        )
    return statuses


class TaskWaiter:
    """Polls `show-task` until every task is terminal, with backoff and a budget.

    Stateless: one instance is constructed by `ApiTransport` and reused for every
    call, so the policy knobs live in one place and nothing per-call is retained.
    `sleep` and `clock` are injectable only so the unit tests can run a ten-minute
    wait instantly; production never passes them.
    """

    def __init__(
        self,
        *,
        poll_initial: float = DEFAULT_TASK_POLL_INITIAL_SECONDS,
        poll_max: float = DEFAULT_TASK_POLL_MAX_SECONDS,
        poll_failure_tolerance: int = DEFAULT_TASK_POLL_FAILURE_TOLERANCE,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
    ) -> None:
        self._poll_initial = poll_initial
        self._poll_max = poll_max
        self._poll_failure_tolerance = poll_failure_tolerance
        self._sleep = sleep
        self._clock = clock

    @traced
    async def wait(
        self,
        show_task: ShowTask,
        task_ids: list[str],
        *,
        timeout: float,
        context: str = "",
    ) -> list[TaskStatus]:
        """Poll until every task in `task_ids` is terminal; return their statuses.

        Args:
            show_task: Async callable taking a `show-task` payload and returning
                the response dict. Supplied by the transport as a closure already
                bound to the live server_ip/sid/port of the call being waited on.
            task_ids: Task ids to wait on.
            timeout: Total budget in seconds for the remaining wait. <= 0 means no
                deadline, matching `api_call(timeout=-1)`.
            context: Free text for logs and the timeout message, e.g.
                "revert-to-revision on 10.0.0.1".

        Returns:
            The final `TaskStatus` for each task, successful or not. Task failure
            is never raised -- see the module docstring.

        Raises:
            TaskTimeoutError: The budget expired. Subclasses `TimeoutError`.
            TaskPollError: `show-task` failed more times in a row than tolerated.
        """
        if not task_ids:
            return []

        started = self._clock()
        deadline = started + timeout if timeout > 0 else None
        payload = {"task-id": task_ids if len(task_ids) > 1 else task_ids[0], "details-level": "full"}
        suffix = f" ({context})" if context else ""
        span_attrs(task_ids=",".join(task_ids), task_count=len(task_ids))
        log().debug(f"TASK WAIT: {len(task_ids)} task(s) {', '.join(task_ids)}{suffix}")

        delay = self._poll_initial
        polls = 0
        failures = 0
        last: list[TaskStatus] = []

        while True:
            remaining = None if deadline is None else deadline - self._clock()
            if remaining is not None and remaining <= 0:
                raise self._timeout_error(task_ids, last, started, polls, suffix)

            polls += 1
            try:
                statuses, failure = await self._poll(show_task, payload, remaining)
            except TimeoutError as exc:
                # The budget, not the task, ran out: a poll is never given more
                # time than the wait has left, so a hung show-task cannot outlive it.
                raise self._timeout_error(task_ids, last, started, polls, suffix) from exc

            if failure is not None:
                failures += 1
                log().warning(
                    f"TASK POLL FAILED ({failures}/{self._poll_failure_tolerance} tolerated): "
                    f"{', '.join(task_ids)}{suffix} - {failure}"
                )
                if failures > self._poll_failure_tolerance:
                    raise TaskPollError(
                        f"show-task failed {failures} times in a row for {', '.join(task_ids)}{suffix} "
                        f"- last error: {failure}",
                        task_ids=task_ids,
                    )
            else:
                failures = 0
                last = statuses
                elapsed = self._clock() - started
                for status in statuses:
                    log().trace(f"TASK POLL: {status.describe()} after {elapsed:.0f}s{suffix}")
                if all(status.is_terminal for status in statuses):
                    return self._finish(statuses, started, polls, suffix)

            await self._sleep(delay if remaining is None else min(delay, max(remaining, 0.0)))
            delay = min(delay * 2, self._poll_max)

    async def _poll(
        self, show_task: ShowTask, payload: dict[str, Any], remaining: float | None
    ) -> tuple[list[TaskStatus], str | None]:
        """One `show-task` round trip: (statuses, None) or ([], why_it_failed).

        Only a `TimeoutError` escapes -- and only from the budget guard, never from
        `show_task` itself, which is wrapped so that a dropped connection or an
        unsuccessful response counts as one tolerated poll failure.
        """
        try:
            if remaining is None:
                response = await show_task(payload)
            else:
                response = await asyncio.wait_for(show_task(payload), timeout=remaining)
        except TimeoutError:
            raise
        except Exception as exc:  # noqa: BLE001 - a dropped poll says nothing about the task
            return [], f"{type(exc).__name__}: {exc}"

        if not response.get("success", False):
            return [], str(response.get("message") or response.get("code") or "unsuccessful show-task")

        statuses = parse_task_statuses(response)
        if not statuses:
            return [], "show-task returned no task entries"
        return statuses, None

    def _finish(self, statuses: list[TaskStatus], started: float, polls: int, suffix: str) -> list[TaskStatus]:
        elapsed = self._clock() - started
        final = ", ".join(status.describe() for status in statuses)
        span_attrs(
            task_final_status=",".join(status.status for status in statuses),
            task_polls=polls,
            task_duration_ms=int(elapsed * 1000),
        )
        if all(status.is_success for status in statuses):
            log().info(f"TASK COMPLETE: {final} after {elapsed:.0f}s in {polls} poll(s){suffix}")
        else:
            log().error(f"TASK UNSUCCESSFUL: {final} after {elapsed:.0f}s in {polls} poll(s){suffix}")
        return statuses

    def _timeout_error(
        self, task_ids: list[str], last: list[TaskStatus], started: float, polls: int, suffix: str
    ) -> TaskTimeoutError:
        elapsed = self._clock() - started
        detail = (
            ", ".join(status.describe() for status in last)
            if last
            else f"task(s) {', '.join(task_ids)} - no status observed"
        )
        message = f"{detail} after {elapsed:.0f}s{suffix}"
        span_attrs(task_final_status="timeout", task_polls=polls, task_duration_ms=int(elapsed * 1000))
        log().error(f"TASK WAIT TIMEOUT: {message}")
        return TaskTimeoutError(message, task_ids=task_ids, statuses=last)


__all__ = [
    "IN_PROGRESS",
    "SUCCEEDED",
    "Clock",
    "ShowTask",
    "Sleep",
    "TaskResponse",
    "TaskStatus",
    "TaskWaiter",
    "extract_task_ids",
    "parse_task_statuses",
]
