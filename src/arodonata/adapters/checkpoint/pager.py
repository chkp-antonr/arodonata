"""Continuity-verified Check Point object listing pagination (`pager.py`).

Pages object listings in chunks (default 300, max 500), acquiring and releasing
a `RateLimiter` slot per page, recovering displaced objects across page boundaries
via a single `±10` window re-read on duplicate UID, and restarting once on
`total` or `from`/`to` discontinuity before failing with `code="paging_inconsistent"`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.telemetry import span_attrs, traced

DEFAULT_PAGE_LIMIT: int = 300
MAX_PAGE_LIMIT: int = 500
BOUNDARY_WINDOW_RADIUS: int = 10

# Commands whose paginated responses are returned inside polled `show-task` payloads (`tasks[].task-details[]`)
TASK_QUERY_COMMANDS: frozenset[str] = frozenset(
    {
        "show-unused-objects",
        "where-used",
        "show-changes",
        "show-Gateways-and-servers-task",
    }
)

# Common collection keys used by Check Point `show-*` listing commands
_COLLECTION_KEYS: tuple[str, ...] = (
    "objects",
    "access-layers",
    "nat-rules",
    "https-layers",
    "threat-layers",
    "packages",
    "domains",
    "sessions",
    "gateways-and-servers",
    "tasks",
    "changes",
    "used-directly",
    "used-indirectly",
)

PageCaller = Callable[[dict[str, Any]], Awaitable[ApiCallResult]]


def _unpack_task_details_page(data: dict[str, Any]) -> dict[str, Any]:
    """Unpack the inner pagination dictionary from `tasks[].task-details[]` if present."""
    tasks = data.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        return data

    first_task = tasks[0]
    if not isinstance(first_task, dict):
        return data

    details = first_task.get("task-details")
    if isinstance(details, list) and details:
        first_detail = details[0]
        if isinstance(first_detail, dict):
            # If the detail itself has `objects` or `total` or `changes`, use it
            if any(k in first_detail for k in ("objects", "total", "from", "to", "changes")):
                return first_detail
            response_sub = first_detail.get("response")
            if isinstance(response_sub, dict):
                return response_sub
    return data


def _extract_page_items(page_data: dict[str, Any], collection_key: str | None = None) -> list[dict[str, Any]]:
    """Extract the list of object dictionaries from a Check Point page payload."""
    if collection_key and isinstance(page_data.get(collection_key), list):
        return [item for item in page_data[collection_key] if isinstance(item, dict)]

    for key in _COLLECTION_KEYS:
        val = page_data.get(key)
        if isinstance(val, list):
            return [item for item in val if isinstance(item, dict)]

    # Fallback: find any list value when `total` is present
    if "total" in page_data:
        for key, val in page_data.items():
            if key not in ("errors", "warnings", "blocking-errors") and isinstance(val, list):
                return [item for item in val if isinstance(item, dict)]
    return []


def _get_item_identity(item: dict[str, Any], fallback_idx: int) -> str:
    """Return the unique identifier (`uid`, `id`, or `name`) for deduplication across pages."""
    uid = item.get("uid")
    if isinstance(uid, str) and uid:
        return uid
    item_id = item.get("id")
    if isinstance(item_id, str) and item_id:
        return item_id
    name = item.get("name")
    if isinstance(name, str) and name:
        obj_type = str(item.get("type") or "")
        return f"{obj_type}:{name}"
    return f"__idx_{fallback_idx}"


class _DiscontinuityError(Exception):
    """Internal signal that a pagination pass violated `from`/`to`/`total` continuity."""


@traced
async def paginate_objects(
    command: str,
    page_caller: PageCaller,
    *,
    details_level: str = "standard",
    payload: dict[str, Any] | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    collection_key: str | None = None,
) -> ApiQueryResult:
    """Execute a continuity-verified paginated Check Point query (`api_query`).

    Acquires and releases a `RateLimiter` slot per page (via `page_caller`), recovers
    boundary-swapped duplicate UIDs via a single `±10` window re-read, and restarts
    the listing at most once on `from`/`to`/`total` discontinuity before returning
    `ApiQueryResult(success=False, code="paging_inconsistent")`.
    """
    clean_cmd = command.strip().lstrip("/")
    effective_limit = max(1, min(int(limit), MAX_PAGE_LIMIT))
    base_payload: dict[str, Any] = dict(payload) if payload else {}
    initial_offset = int(base_payload.get("offset", 0))
    if "details-level" not in base_payload and details_level:
        base_payload["details-level"] = details_level

    is_task_query = clean_cmd in TASK_QUERY_COMMANDS
    span_attrs(cp_command=clean_cmd, page_limit=effective_limit, is_task_query=is_task_query)

    last_inconsistency_reason = "Pagination continuity check failed."

    for attempt in range(2):
        try:
            return await _run_single_pagination_pass(
                command=clean_cmd,
                page_caller=page_caller,
                base_payload=base_payload,
                initial_offset=initial_offset,
                limit=effective_limit,
                is_task_query=is_task_query,
                collection_key=collection_key,
            )
        except _DiscontinuityError as exc:
            last_inconsistency_reason = str(exc)
            if attempt == 0:
                continue

    return ApiQueryResult(
        success=False,
        objects=[],
        total=0,
        error_message=last_inconsistency_reason,
        code="paging_inconsistent",
    )


async def _run_single_pagination_pass(
    *,
    command: str,
    page_caller: PageCaller,
    base_payload: dict[str, Any],
    initial_offset: int,
    limit: int,
    is_task_query: bool,
    collection_key: str | None,
) -> ApiQueryResult:
    offset = initial_offset
    expected_total: int | None = None
    collected: list[dict[str, Any]] = []
    seen_uids: set[str] = set()

    while True:
        req_payload = dict(base_payload)
        req_payload["limit"] = limit
        req_payload["offset"] = offset

        call_res = await page_caller(req_payload)
        if not call_res.success:
            return ApiQueryResult(
                success=False,
                objects=[],
                total=expected_total or 0,
                error_message=call_res.error_message or f"{command} failed at offset {offset}",
                code=call_res.error_code or f"http_{call_res.status_code}",
            )

        page_data = (
            _unpack_task_details_page(call_res.data) if (is_task_query or "tasks" in call_res.data) else call_res.data
        )
        items = _extract_page_items(page_data, collection_key=collection_key)

        raw_total = page_data.get("total")
        raw_from = page_data.get("from")
        raw_to = page_data.get("to")

        # If server response is not paginated (no `total` field), return items directly
        if raw_total is None:
            return ApiQueryResult(
                success=True,
                objects=items,
                total=len(items),
            )

        page_total = int(raw_total)
        if expected_total is None:
            expected_total = page_total
        elif page_total != expected_total:
            raise _DiscontinuityError(
                f"Total object count changed mid-listing for {command!r}: "
                f"expected {expected_total}, got {page_total} at offset {offset}."
            )

        if page_total == 0 or (offset == initial_offset and not items and page_total == 0):
            return ApiQueryResult(success=True, objects=[], total=0)

        if not items:
            raise _DiscontinuityError(
                f"Pagination stalled for {command!r} at offset {offset}: "
                f"received 0 items while total={expected_total} (collected={len(collected)})."
            )

        expected_from = offset + 1
        expected_to = offset + len(items)
        if raw_from is not None and int(raw_from) != expected_from:
            raise _DiscontinuityError(
                f"Pagination 'from' discontinuity for {command!r} at offset {offset}: "
                f"expected from={expected_from}, got from={raw_from}."
            )
        if raw_to is not None and int(raw_to) != expected_to:
            raise _DiscontinuityError(
                f"Pagination 'to' discontinuity for {command!r} at offset {offset}: "
                f"expected to={expected_to}, got to={raw_to}."
            )

        boundary_duplicates_detected = False
        for idx, item in enumerate(items):
            uid = _get_item_identity(item, offset + idx)
            if uid in seen_uids:
                boundary_duplicates_detected = True
                continue
            seen_uids.add(uid)
            collected.append(item)

        # If a duplicate UID occurred on this page (boundary swap of equal-named objects),
        # re-read a small window (up to 10 objects on each side of the boundary) in a single request.
        if boundary_duplicates_detected and offset > initial_offset:
            win_offset = max(initial_offset, offset - BOUNDARY_WINDOW_RADIUS)
            win_limit = BOUNDARY_WINDOW_RADIUS * 2
            win_payload = dict(base_payload)
            win_payload["offset"] = win_offset
            win_payload["limit"] = win_limit

            win_res = await page_caller(win_payload)
            if not win_res.success:
                return ApiQueryResult(
                    success=False,
                    objects=[],
                    total=expected_total,
                    error_message=win_res.error_message or f"{command} boundary window recovery failed",
                    code=win_res.error_code or f"http_{win_res.status_code}",
                )
            win_data = (
                _unpack_task_details_page(win_res.data) if (is_task_query or "tasks" in win_res.data) else win_res.data
            )
            win_total = win_data.get("total")
            if win_total is not None and int(win_total) != expected_total:
                raise _DiscontinuityError(
                    f"Total count changed during boundary recovery for {command!r}: "
                    f"expected {expected_total}, got {win_total}."
                )
            win_items = _extract_page_items(win_data, collection_key=collection_key)
            for idx, w_item in enumerate(win_items):
                w_uid = _get_item_identity(w_item, win_offset + idx)
                if w_uid not in seen_uids:
                    seen_uids.add(w_uid)
                    collected.append(w_item)

        effective_to = int(raw_to) if raw_to is not None else expected_to
        if effective_to <= offset:
            raise _DiscontinuityError(
                f"Pagination failed to advance for {command!r}: offset={offset}, to={effective_to}."
            )

        offset = effective_to
        if offset >= expected_total:
            break

    expected_distinct_count = max(0, expected_total - initial_offset)
    if len(collected) != expected_distinct_count:
        raise _DiscontinuityError(
            f"Final distinct object count mismatch for {command!r}: "
            f"collected {len(collected)} distinct objects, expected {expected_distinct_count} (total={expected_total})."
        )

    return ApiQueryResult(
        success=True,
        objects=collected,
        total=expected_total,
    )


__all__ = [
    "BOUNDARY_WINDOW_RADIUS",
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "TASK_QUERY_COMMANDS",
    "paginate_objects",
]
