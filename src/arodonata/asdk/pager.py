"""Own paging for listing commands (spec D3): one call per page, so a caller holds a RateLimiter slot per page.

cpapi's api_query fetched every page inside one call and checked nothing across pages. Here every page is checked
against the previous one. An object can come twice for two reasons: Check Point swapped two objects with equal names
at a page boundary between requests, which hides the other one, so the repeat is dropped and the few objects just
before the page are read again to recover it (spec D3a); or a publish between pages shifted offsets (an insert or a
delete before the cursor), which a changed `total` or a final count other than `total` catches. A failed check restarts
the listing once from the caller's offset, and a second failure fails the query instead of returning duplicates or
gaps.
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

# Check Point sorts listings by name, and objects with equal names come back in either order from one request to
# the next (spec D3a). Equal names exist in Check Point's own data: Domain4's show-objects has two
# application-site-category objects named "Email" in APPI Data at positions 3949 and 3950,
#   uid 00fa9e44-405b-0f65-e053-08241dc22da2 (category-id 40000130) and
#   uid 00fa9e44-416f-0f65-e053-08241dc22da2 (category-id 52000130).
# With pages of 50, page one (offset 3900) ends at 3949 and page two (offset 3950) starts at 3950. The first request
# put ...405b at 3949; the second swapped the two and put ...405b at 3950 as well. So ...405b came twice and ...416f
# never: it sat at 3949 in the second request's order, a position no page asked for. Dropping the repeat is not
# enough to get it back, so the few objects just before the page are read again.
_TIE_WINDOW = 10


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

    Returns cpapi's api_query shape: on success `data` is the list of objects. A first page that is unsuccessful, not a
    dict or without a `container_key` list is returned as is; one with the list but no paging (no `total`, `total` 0 or
    an empty list) comes back with `data` replaced by that list, as cpapi does. An unsuccessful later page (or window
    re-read) fails the query with that page's code. A repeated uid on a later page is dropped and the `_TIE_WINDOW`
    objects before that page are re-read to recover the object an equal-name swap hid; the listing must end with
    `total - offset` distinct objects, or it is restarted once. Exceptions from `fetch_page` propagate untouched:
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
    if not isinstance(data, dict) or not isinstance(data.get(container_key), list):
        return response
    if not isinstance(data.get("total"), int) or data["total"] == 0 or not data[container_key]:
        return {**response, "data": data[container_key]}

    total: int = data["total"]
    objects: list[Any] = []
    seen: set[str] = set()
    prev_to = offset
    page_offset = offset
    page: Any = data
    while True:
        prev_to = _check_page(page, container_key, page_offset, prev_to, total)
        new, repeated = _split_new(page[container_key], seen)
        if repeated and page_offset > offset:
            recovered = await _reread_window(fetch_page, command, container_key, offset, page_offset, total, seen)
            if isinstance(recovered, dict):
                return recovered
            objects.extend(recovered)
        objects.extend(new)
        if prev_to >= total:
            if len(objects) != total - offset:
                raise _Shifted(f"listed {len(objects)} distinct objects, expected {total - offset}")
            return {"success": True, "data": objects, "message": "", "code": ""}
        page_offset = prev_to
        response = await fetch_page(page_offset, page_size)
        if not response.get("success"):
            return _failed_page(command, page_offset, response)
        page = response.get("data")


def _failed_page(command: str, page_offset: int, response: RawApiResponse) -> RawApiResponse:
    return {
        **response,
        "success": False,
        "message": f"{command} page at offset {page_offset}: {response.get('message', '')}",
    }


def _check_page(page: Any, container_key: str, offset: int, prev_to: int, total: int) -> int:
    """Raise _Shifted unless `page` continues right after `prev_to`; return its `to`."""
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
    return page_to


def _split_new(items: list[Any], seen: set[str]) -> tuple[list[Any], list[Any]]:
    """Split `items` into (new items in order, repeated items), adding the new items' uids to `seen`.

    An item whose `str` uid is already in `seen` is repeated; items without a uid are always new.
    """
    new: list[Any] = []
    repeated: list[Any] = []
    for item in items:
        uid = item.get("uid") if isinstance(item, dict) else None
        if isinstance(uid, str):
            if uid in seen:
                repeated.append(item)
                continue
            seen.add(uid)
        new.append(item)
    return new, repeated


async def _reread_window(
    fetch_page: PageFetcher,
    command: str,
    container_key: str,
    offset: int,
    page_offset: int,
    total: int,
    seen: set[str],
) -> list[Any] | RawApiResponse:
    """Re-read the objects just before `page_offset` and return those whose uid is not in `seen` (spec D3a).

    An unsuccessful read is returned as the failed query (a dict); a read that is not a listing page or has another
    `total` raises _Shifted.
    """
    w_offset = max(offset, page_offset - _TIE_WINDOW)
    limit = page_offset - w_offset
    log().debug(
        f"{command}: equal names swapped at the page boundary at offset {page_offset}; re-read {limit} objects before it"
    )
    response = await fetch_page(w_offset, limit)
    if not response.get("success"):
        return _failed_page(command, w_offset, response)
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(data.get(container_key), list):
        raise _Shifted(f"window at offset {w_offset} has no {container_key} list")
    if data.get("total") != total:
        raise _Shifted(f"window at offset {w_offset}: total changed from {total} to {data.get('total')}")
    # Only objects with a uid can be told apart from what is already listed; one without a uid in the window was
    # listed already (it is counted, never deduplicated), so it is not added again.
    with_uid = [item for item in data[container_key] if isinstance(item, dict) and isinstance(item.get("uid"), str)]
    recovered, _ = _split_new(with_uid, seen)
    return recovered
