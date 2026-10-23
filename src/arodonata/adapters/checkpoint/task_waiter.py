"""Self-managed asynchronous Check Point server task polling (`TaskWaiter`).

Polls `show-task` with exponential backoff (`2s` up to `10s`) within `task_timeout`,
tolerates up to 5 consecutive transient poll errors, and returns `ApiCallResult(success=True)`
only when every task reaches a status in the explicit success allowlist (`succeeded`).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

from arodonata.core.errors import (
    ApiTimeoutError,
    ServerIdentityError,
    TaskPollError,
    TaskTimeoutError,
    TransportError,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.telemetry import span_attrs, traced

TASK_SUCCESS_STATUSES: frozenset[str] = frozenset({"succeeded"})
TASK_FAILURE_STATUSES: frozenset[str] = frozenset(
    {
        "failed",
        "partially succeeded",
        "aborted",
    }
)
TASK_IN_PROGRESS_STATUSES: frozenset[str] = frozenset(
    {
        "in progress",
        "pending",
        "initializing",
        "queued",
    }
)

DEFAULT_INITIAL_DELAY: float = 2.0
DEFAULT_MAX_DELAY: float = 10.0
DEFAULT_BACKOFF_FACTOR: float = 1.5
MAX_CONSECUTIVE_POLL_ERRORS: int = 5


def extract_task_ids(data: dict[str, Any]) -> list[str]:
    """Extract all `task-id` strings from a Check Point API response dictionary."""
    if not isinstance(data, dict):
        return []
    task_ids: list[str] = []
    direct_id = data.get("task-id")
    if isinstance(direct_id, str) and direct_id.strip():
        task_ids.append(direct_id.strip())

    tasks_list = data.get("tasks")
    if isinstance(tasks_list, list):
        for entry in tasks_list:
            if isinstance(entry, dict):
                tid = entry.get("task-id")
                if isinstance(tid, str) and tid.strip() and tid.strip() not in task_ids:
                    task_ids.append(tid.strip())
            elif isinstance(entry, str) and entry.strip() and entry.strip() not in task_ids:
                task_ids.append(entry.strip())
    return task_ids


def _extract_task_error_summary(tasks: list[dict[str, Any]]) -> str:
    """Build a concise human-readable error message from failed/partial `show-task` entries."""
    messages: list[str] = []
    for task in tasks:
        task_name = str(task.get("task-name") or task.get("task-id") or "task")
        status = str(task.get("status") or "unknown")
        details = task.get("task-details")
        detail_msgs: list[str] = []
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    msg = (
                        item.get("statusDescription")
                        or item.get("fault-message")
                        or item.get("error-message")
                        or item.get("message")
                    )
                    if isinstance(msg, str) and msg.strip():
                        detail_msgs.append(msg.strip())
        comments = task.get("comments")
        if isinstance(comments, str) and comments.strip() and not detail_msgs:
            detail_msgs.append(comments.strip())
        if detail_msgs:
            messages.append(f"{task_name} ({status}): {'; '.join(detail_msgs)}")
        else:
            messages.append(f"{task_name} finished with status {status!r}")
    return "; ".join(messages) if messages else "Server task did not succeed."


PollCallable = Callable[[dict[str, Any]], Awaitable[ApiCallResult]]


class TaskWaiter:
    """Polls Check Point `show-task` until all tasks reach a terminal state."""

    def __init__(
        self,
        *,
        task_timeout: float = 900.0,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        max_consecutive_errors: int = MAX_CONSECUTIVE_POLL_ERRORS,
        monotonic_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._task_timeout = float(task_timeout)
        self._initial_delay = float(initial_delay)
        self._max_delay = float(max_delay)
        self._backoff_factor = float(backoff_factor)
        self._max_consecutive_errors = int(max_consecutive_errors)
        self._monotonic = monotonic_fn
        self._sleep = sleep_fn

    @property
    def task_timeout(self) -> float:
        """Default task timeout budget in seconds."""
        return self._task_timeout

    @traced
    async def wait_for_tasks(
        self,
        task_ids: list[str] | str,
        poll_fn: PollCallable,
        *,
        timeout: float | None = None,
        initial_result: ApiCallResult | None = None,
    ) -> ApiCallResult:
        """Poll `show-task` via `poll_fn` until all `task_ids` complete.

        Args:
            task_ids: One or more Check Point `task-id` strings.
            poll_fn: Async callable executing `show-task` with the given payload.
            timeout: Optional override for `task_timeout`.
            initial_result: Optional initial `ApiCallResult` that returned the task IDs.
        """
        ids = [task_ids] if isinstance(task_ids, str) else list(task_ids)
        ids = [t.strip() for t in ids if t and t.strip()]
        if not ids:
            return initial_result or ApiCallResult(success=True, data={})

        budget = float(timeout) if timeout is not None else self._task_timeout
        deadline = self._monotonic() + budget
        delay = self._initial_delay
        consecutive_errors = 0
        polls = 0
        primary_task_id = ids[0]

        span_attrs(task_ids=ids, task_timeout=budget)

        while True:
            now = self._monotonic()
            remaining = deadline - now
            if remaining <= 0:
                raise TaskTimeoutError(
                    f"Server task(s) {ids} did not complete within task_timeout={budget}s (polls={polls})."
                )

            sleep_duration = min(delay, remaining)
            if sleep_duration > 0:
                await self._sleep(sleep_duration)

            if self._monotonic() >= deadline:
                raise TaskTimeoutError(
                    f"Server task(s) {ids} did not complete within task_timeout={budget}s (polls={polls})."
                )

            polls += 1
            poll_payload: dict[str, Any] = {
                "task-id": ids[0] if len(ids) == 1 else ids,
                "details-level": "full",
            }

            try:
                poll_res = await poll_fn(poll_payload)
            except ServerIdentityError:
                # Never retry TLS identity errors
                raise
            except (ApiTimeoutError, TransportError, OSError) as exc:
                consecutive_errors += 1
                if consecutive_errors >= self._max_consecutive_errors:
                    raise TaskPollError(
                        f"Task polling for {ids} failed after {consecutive_errors} consecutive transport errors: {exc}"
                    ) from exc
                delay = min(self._max_delay, delay * self._backoff_factor)
                continue

            if not poll_res.success:
                consecutive_errors += 1
                if consecutive_errors >= self._max_consecutive_errors:
                    raise TaskPollError(
                        f"Task polling for {ids} failed after {consecutive_errors} consecutive poll failures: "
                        f"{poll_res.error_message or f'HTTP {poll_res.status_code}'}"
                    )
                delay = min(self._max_delay, delay * self._backoff_factor)
                continue

            tasks_raw = poll_res.data.get("tasks")
            if not isinstance(tasks_raw, list) or not tasks_raw:
                consecutive_errors += 1
                if consecutive_errors >= self._max_consecutive_errors:
                    raise TaskPollError(
                        f"Task polling for {ids} returned empty or malformed 'tasks' payload "
                        f"{consecutive_errors} consecutive times."
                    )
                delay = min(self._max_delay, delay * self._backoff_factor)
                continue

            # Valid show-task response resets consecutive error counter
            consecutive_errors = 0

            task_dicts = [t for t in tasks_raw if isinstance(t, dict)]
            statuses = [str(t.get("status") or "").strip().lower() for t in task_dicts]

            # Check if any task is still in progress
            still_running = False
            for task_obj, st in zip(task_dicts, statuses):
                progress = task_obj.get("progress-percentage")
                if st in TASK_IN_PROGRESS_STATUSES or (
                    st not in TASK_SUCCESS_STATUSES
                    and st not in TASK_FAILURE_STATUSES
                    and isinstance(progress, int | float)
                    and progress < 100
                ):
                    still_running = True
                    break

            if still_running or len(task_dicts) < len(ids):
                delay = min(self._max_delay, delay * self._backoff_factor)
                continue

            # All tasks have reached a terminal state.
            # Requirement: success=True ONLY when every task's status is in TASK_SUCCESS_STATUSES ('succeeded')
            all_succeeded = bool(statuses) and all(st in TASK_SUCCESS_STATUSES for st in statuses)
            if all_succeeded:
                span_attrs(task_polls=polls, task_status="succeeded")
                return ApiCallResult(
                    success=True,
                    status_code=poll_res.status_code,
                    data=poll_res.data,
                    task_id=primary_task_id,
                )

            error_summary = _extract_task_error_summary(task_dicts)
            failed_status = next((st for st in statuses if st not in TASK_SUCCESS_STATUSES), "failed")
            span_attrs(task_polls=polls, task_status=failed_status)
            return ApiCallResult(
                success=False,
                status_code=poll_res.status_code,
                data=poll_res.data,
                error_message=error_summary,
                error_code=f"task_{failed_status.replace(' ', '_')}",
                task_id=primary_task_id,
            )


__all__ = [
    "DEFAULT_BACKOFF_FACTOR",
    "DEFAULT_INITIAL_DELAY",
    "DEFAULT_MAX_DELAY",
    "MAX_CONSECUTIVE_POLL_ERRORS",
    "TASK_FAILURE_STATUSES",
    "TASK_IN_PROGRESS_STATUSES",
    "TASK_SUCCESS_STATUSES",
    "TaskWaiter",
    "extract_task_ids",
]
