"""Own paging for listing commands (spec D3): one call per page, so a caller holds a RateLimiter slot per page.

cpapi's api_query fetched every page inside one call and checked nothing across pages. Here every page is checked
against the previous one; a publish between pages shifts offsets (an insert before the cursor repeats the boundary
object, a delete skips one and lowers `total`), so a failed check restarts the listing once from the caller's
offset, and a second failure fails the query instead of returning duplicates or gaps.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..logger import lazy_logger
from .transport import RawApiResponse

log = lazy_logger("arodonata.asdk.pager")

PageFetcher = Callable[[int, int], Awaitable[RawApiResponse]]
"""Reads one page: `(offset, limit) -> that page's response`."""

PAGING_INCONSISTENT_CODE = "paging_inconsistent"


class _Shifted(Exception):
    """A page does not continue the previous one: the listing changed under the cursor."""


async def fetch_all_pages(
    fetch_page: PageFetcher,
    *,
    command: str,
    container_key: str,
    offset: int,
    page_size: int,
) -> RawApiResponse:
    """Page `command` from `offset` to the end, `page_size` objects per call.

    Returns cpapi's api_query shape: on success `data` is the list of objects. An unsuccessful first page, or a first
    page without a `container_key` list or a `total` (or with `total` 0), is returned as is, as cpapi does. An
    unsuccessful later page fails the query with that page's code. Exceptions from `fetch_page` propagate untouched:
    nothing here retries a timeout or an identity error.
    """
    try:
        return await _read(fetch_page, command, container_key, offset, page_size)
    except _Shifted as first:
        log().info(f"{command}: listing changed while paging ({first}); restarting from offset {offset}")
    try:
        return await _read(fetch_page, command, container_key, offset, page_size)
    except _Shifted as second:
        message = f"{command}: listing changed while paging twice from offset {offset}: {second}"
        log().warning(message)
        return {"success": False, "data": None, "message": message, "code": PAGING_INCONSISTENT_CODE}


async def _read(
    fetch_page: PageFetcher, command: str, container_key: str, offset: int, page_size: int
) -> RawApiResponse:
    response = await fetch_page(offset, page_size)
    if not response.get("success"):
        return response
    data = response.get("data")
    if (
        not isinstance(data, dict)
        or not isinstance(data.get(container_key), list)
        or not isinstance(data.get("total"), int)
        or data["total"] == 0
    ):
        return response

    total: int = data["total"]
    objects: list[Any] = []
    seen: set[str] = set()
    prev_to = offset
    page_offset = offset
    page: Any = data
    while True:
        prev_to = _check_page(page, container_key, page_offset, prev_to, total, seen)
        objects.extend(page[container_key])
        if prev_to >= total:
            return {"success": True, "data": objects, "message": "", "code": ""}
        page_offset = prev_to
        response = await fetch_page(page_offset, page_size)
        if not response.get("success"):
            return {
                **response,
                "success": False,
                "message": f"{command} page at offset {page_offset}: {response.get('message', '')}",
            }
        page = response.get("data")


def _check_page(page: Any, container_key: str, offset: int, prev_to: int, total: int, seen: set[str]) -> int:
    """Raise _Shifted unless `page` continues right after `prev_to`; record its uids in `seen`; return its `to`."""
    if not isinstance(page, dict) or not isinstance(page.get(container_key), list):
        raise _Shifted(f"page at offset {offset} has no {container_key} list")
    items: list[Any] = page[container_key]
    if page.get("total") != total:
        raise _Shifted(f"page at offset {offset}: total changed from {total} to {page.get('total')}")
    if not items:
        raise _Shifted(f"page at offset {offset} is empty before total {total}")
    page_to = page.get("to")
    if not isinstance(page_to, int) or page_to <= prev_to:
        raise _Shifted(f"page at offset {offset} did not advance (to={page_to}, previous to={prev_to})")
    page_from = page.get("from")
    if isinstance(page_from, int) and page_from != prev_to + 1:
        raise _Shifted(f"page at offset {offset} starts at {page_from}, expected {prev_to + 1}")
    for item in items:
        uid = item.get("uid") if isinstance(item, dict) else None
        if isinstance(uid, str):
            if uid in seen:
                raise _Shifted(f"page at offset {offset} repeats an object seen on an earlier page")
            seen.add(uid)
    return page_to
