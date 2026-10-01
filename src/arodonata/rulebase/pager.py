"""Page a ``show-*-rulebase`` command to completion, or fail: never a partial layer.

The pager assumes ``offset`` counts rules and continues from the previous page's ``to``. It checks that
assumption on every page (``from`` must be the previous ``to + 1``), so a server that pages differently makes it
raise instead of silently skipping or duplicating rules.
"""

from __future__ import annotations

from typing import Any

RULEBASE_PAGE_SIZE = 100


class RulebaseFetchError(Exception):
    """A rulebase page failed, or CP paged the layer in a way the pager cannot trust."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}" if code else message)
        self.code = code
        self.message = message


def _is_section(item: Any) -> bool:
    return isinstance(item, dict) and str(item.get("type", "")).endswith("-section")


def _merge_sections(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """One section that CP split across a page boundary: children concatenated, ``from`` = min, ``to`` = max."""
    merged = {**left, "rulebase": [*left.get("rulebase", []), *right.get("rulebase", [])]}
    starts = [n for n in (left.get("from"), right.get("from")) if isinstance(n, int)]
    ends = [n for n in (left.get("to"), right.get("to")) if isinstance(n, int)]
    if starts:
        merged["from"] = min(starts)
    if ends:
        merged["to"] = max(ends)
    return merged


def _count_rules(items: Any) -> int:
    """Rule items in a page's ``rulebase``, looking through sections (recursively)."""
    if not isinstance(items, list):
        return 0
    return sum(_count_rules(i.get("rulebase")) if _is_section(i) else 1 for i in items)


def _page_bounds(page: dict[str, Any], command: str, offset: int, prev_to: int) -> tuple[int, int, int] | None:
    """Validate a page's from/to/total bounds, or return None for an empty layer.

    Returns:
        (from, to, total) if valid; None if this is an empty layer (total 0, no rules, no prior rules). An empty
        layer may still hold empty sections, which the caller keeps.

    Raises:
        RulebaseFetchError: Page is invalid (missing/non-int bounds, total 0 with rules or after rules, etc).
    """
    total = page.get("total")
    page_from, page_to = page.get("from"), page.get("to")

    if total == 0:
        if prev_to:
            raise RulebaseFetchError("", f"{command} reported total 0 after {prev_to} rules")
        rule_count = _count_rules(page.get("rulebase", []))
        if rule_count:
            raise RulebaseFetchError("", f"{command} reported total 0 with {rule_count} items at offset {offset}")
        return None

    # Validate bounds exist and are ints
    if not isinstance(page_from, int) or not isinstance(page_to, int) or not isinstance(total, int):
        raise RulebaseFetchError("", f"{command} page at offset {offset} has no from/to/total")

    # Bounds sanity
    if page_to <= prev_to:
        raise RulebaseFetchError("", f"{command} did not advance at offset {offset} (to={page_to})")
    if page_from != prev_to + 1:
        raise RulebaseFetchError(
            "", f"{command} page at offset {offset} starts at rule {page_from}, expected {prev_to + 1}"
        )

    return page_from, page_to, total


async def fetch_full_rulebase(
    client: Any,
    mgmt_name: str,
    domain: str,
    command: str,
    payload: dict[str, Any],
    *,
    page_size: int = RULEBASE_PAGE_SIZE,
) -> dict[str, Any]:
    """Every page of one layer, merged into one response.

    Args:
        client: Anything with ``api_call(mgmt_name=, domain=, command=, payload=)`` returning an
            ``ApiCallResult``-like object (``success``, ``data``, ``code``, ``message``).
        mgmt_name: Management server name.
        domain: Domain name ('' for the system domain).
        command: ``show-access-rulebase``, ``show-nat-rulebase``, ``show-https-rulebase`` or ``show-threat-rulebase``.
        payload: uid/name/package, details-level, use-object-dictionary and any live-only parameters; ``limit`` and
            ``offset`` are set by the pager.
        page_size: Rules per page.

    Returns:
        The first page's top-level keys (including its ``from``, ``to``, and ``total``), with ``rulebase`` holding
        every item (a section split across pages merged by uid) and ``objects-dictionary`` merged by uid.

    Raises:
        RulebaseFetchError: A page failed, was not a dict, did not advance, or did not start right after the
            previous one. Exceptions raised by ``client.api_call`` itself propagate unchanged.
    """
    first: dict[str, Any] | None = None
    items: list[Any] = []
    dictionary: dict[str, dict[str, Any]] = {}
    offset = 0
    prev_to = 0
    while True:
        result = await client.api_call(
            mgmt_name=mgmt_name,
            domain=domain,
            command=command,
            payload={**payload, "limit": page_size, "offset": offset},
        )
        if not result.success:
            raise RulebaseFetchError(result.code or "", result.message or f"{command} failed at offset {offset}")
        page = result.data
        if not isinstance(page, dict):
            raise RulebaseFetchError("", f"{command} returned a non-dict page at offset {offset}")
        if first is None:
            first = page

        bounds = _page_bounds(page, command, offset, prev_to)
        for obj in page.get("objects-dictionary", []):
            if isinstance(obj, dict) and "uid" in obj:
                dictionary.setdefault(str(obj["uid"]), obj)
        if bounds is None:
            # Empty layer: total 0, no rules (empty sections are kept), no prior rules
            items.extend(page.get("rulebase", []))
            break

        page_from, page_to, total = bounds
        page_items = list(page.get("rulebase", []))
        if (
            items
            and page_items
            and _is_section(items[-1])
            and _is_section(page_items[0])
            and items[-1].get("uid") == page_items[0].get("uid")
        ):
            items[-1] = _merge_sections(items[-1], page_items.pop(0))
        items.extend(page_items)
        prev_to = page_to
        if page_to >= total:
            break
        offset = page_to
    return {**(first or {}), "rulebase": items, "objects-dictionary": list(dictionary.values())}


__all__ = ["RULEBASE_PAGE_SIZE", "RulebaseFetchError", "fetch_full_rulebase"]
