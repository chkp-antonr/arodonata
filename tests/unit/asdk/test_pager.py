"""Unit tests for asdk/pager.py: own paging, page continuity checks and one restart (spec D3)."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from arodonata.asdk.pager import PAGING_INCONSISTENT_CODE, fetch_all_pages
from arodonata.core.exceptions import ApiTimeoutError


def _page(start: int, count: int, total: int, *, key: str = "objects", uid_base: int | None = None) -> dict[str, Any]:
    """One successful listing page holding objects start..start+count-1 (from/to are 1-based, like Check Point)."""
    base = start if uid_base is None else uid_base
    items = [{"uid": f"u{base + i}", "name": f"n{base + i}"} for i in range(count)]
    data: dict[str, Any] = {key: items, "total": total}
    if count:
        data["from"] = start + 1
        data["to"] = start + count
    return {"success": True, "data": data, "message": "", "code": ""}


class Script:
    """A fetch_page that returns scripted responses in order and records (offset, limit) of every call."""

    def __init__(self, *responses: dict[str, Any] | BaseException) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[int, int]] = []

    async def __call__(self, offset: int, limit: int) -> dict[str, Any]:
        self.calls.append((offset, limit))
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


async def _run(script: Script, *, offset: int = 0, page_size: int = 3, key: str = "objects") -> dict[str, Any]:
    return await fetch_all_pages(script, command="show-hosts", container_key=key, offset=offset, page_size=page_size)


async def test_pages_are_joined_in_order_and_each_page_starts_at_the_previous_to():
    script = Script(_page(0, 3, 7), _page(3, 3, 7), _page(6, 1, 7))

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == [f"u{i}" for i in range(7)]
    assert script.calls == [(0, 3), (3, 3), (6, 3)]


async def test_a_listing_that_fits_one_page_is_one_call():
    script = Script(_page(0, 2, 2))

    result = await _run(script)

    assert [o["uid"] for o in result["data"]] == ["u0", "u1"]
    assert script.calls == [(0, 3)]


async def test_an_empty_listing_returns_an_empty_list():
    empty = _page(0, 0, 0)
    script = Script(empty)

    result = await _run(script)

    assert result["success"] is True
    assert result["data"] == []
    assert script.calls == [(0, 3)]


async def test_a_first_page_without_the_container_list_is_returned_as_is():
    page = {"success": True, "data": {"access-layers": [{"uid": "a"}], "total": 1, "from": 1, "to": 1}}
    script = Script(page)

    result = await _run(script)

    assert result == page


async def test_an_unsuccessful_first_page_is_returned_as_is():
    failed = {
        "success": False,
        "data": {"code": "generic_err_object_not_found"},
        "message": "nope",
        "code": "generic_err_object_not_found",
    }
    script = Script(failed)

    assert await _run(script) == failed


async def test_an_unsuccessful_later_page_fails_the_query_with_its_offset_and_code():
    script = Script(_page(0, 3, 7), {"success": False, "data": None, "message": "busy", "code": "generic_error"})

    result = await _run(script)

    assert result["success"] is False
    assert result["code"] == "generic_error"
    assert result["message"] == "show-hosts page at offset 3: busy"
    assert len(script.calls) == 2  # no extra retry


async def test_the_callers_offset_is_the_start():
    script = Script(_page(10, 3, 14), _page(13, 1, 14))

    result = await _run(script, offset=10)

    assert [o["uid"] for o in result["data"]] == ["u10", "u11", "u12", "u13"]
    assert script.calls == [(10, 3), (13, 3)]


async def test_a_repeat_with_nothing_to_recover_restarts_the_listing_once():
    # An object inserted before the cursor and one deleted after it between pages: total stays, the boundary object
    # comes again on page 2, the window re-reads only objects already listed, and the final count is one short.
    shifted = _page(3, 3, 7, uid_base=2)
    script = Script(
        _page(0, 3, 7), shifted, _page(0, 3, 7), _page(6, 1, 7), _page(0, 3, 7), _page(3, 3, 7), _page(6, 1, 7)
    )

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == [f"u{i}" for i in range(7)]
    assert script.calls == [(0, 3), (3, 3), (0, 3), (6, 3), (0, 3), (3, 3), (6, 3)]  # the restart begins at offset 0


def _explicit(uids: list[str], *, start: int, total: int) -> dict[str, Any]:
    """A successful page holding `uids` in that order, from start + 1 to start + len(uids)."""
    items = [{"uid": uid, "name": "Email" if uid in ("A", "B") else uid} for uid in uids]
    data = {"objects": items, "total": total, "from": start + 1, "to": start + len(uids)}
    return {"success": True, "data": data, "message": "", "code": ""}


async def test_equal_names_swapped_at_a_boundary_are_recovered_without_a_restart():
    # A and B share a name; the second request put B before A, so page 2 repeats A and B sat where no page asked.
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = _explicit(["u0", "u1", "B"], start=0, total=6)
    script = Script(page1, page2, window)

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == ["u0", "u1", "A", "B", "u4", "u5"]
    assert script.calls == [(0, 3), (3, 3), (0, 3)]


async def test_the_window_is_the_ten_objects_just_before_the_page():
    page1 = _page(0, 15, 20)
    page2 = _explicit(["u14", "u16", "u17", "u18", "u19"], start=15, total=20)
    window = _explicit([f"u{i}" for i in range(5, 14)] + ["u15"], start=5, total=20)
    script = Script(page1, page2, window)

    result = await _run(script, page_size=15)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == [f"u{i}" for i in range(20)]
    assert script.calls == [(0, 15), (15, 15), (5, 10)]


async def test_with_a_callers_offset_the_window_still_reads_the_ten_objects_before_the_page():
    # Caller offset 10, page two at 21: the window (11..20) starts after the caller's offset, so it is read.
    page1 = _page(10, 11, 24)
    page2 = _explicit(["u20", "u22", "u23"], start=21, total=24)
    window = _explicit([f"u{i}" for i in range(11, 20)] + ["u21"], start=11, total=24)
    script = Script(page1, page2, window)

    result = await _run(script, offset=10, page_size=11)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == [f"u{i}" for i in range(10, 24)]
    assert script.calls == [(10, 11), (21, 11), (11, 10)]


async def test_a_window_that_would_start_exactly_at_the_callers_offset_is_not_read():
    # Caller offset 10, page two at 20: the window would be 10..19, and a tie between 9 (never read) and 10 could
    # bring in the object at 9. So nothing is re-read: the count is one short and the listing restarts.
    page1 = _page(10, 10, 23)
    page2 = _explicit(["u19", "u21", "u22"], start=20, total=23)
    script = Script(page1, page2, page1, _page(20, 3, 23))

    result = await _run(script, offset=10, page_size=10)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == [f"u{i}" for i in range(10, 23)]
    assert script.calls == [(10, 10), (20, 10), (10, 10), (20, 10)]  # no window call, then the restart


async def test_a_window_that_would_reach_before_the_callers_offset_is_not_read():
    # Clamped to the caller's offset, the window would hold G from before that offset in place of the hidden B and
    # "recover" G, a success with the wrong set. So nothing is re-read: the count is one short and the listing restarts.
    page1 = _explicit(["H", "u11", "A"], start=10, total=16)
    page2 = _explicit(["A", "u14", "u15"], start=13, total=16)
    clean2 = _explicit(["B", "u14", "u15"], start=13, total=16)
    script = Script(page1, page2, page1, clean2)

    result = await _run(script, offset=10)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == ["H", "u11", "A", "B", "u14", "u15"]
    assert script.calls == [(10, 3), (13, 3), (10, 3), (13, 3)]  # no window call, then the restart


async def test_a_window_that_swaps_back_is_caught_by_the_count_and_restarts():
    # The window request puts A before B again, so B stays hidden and the window brings back only objects already
    # listed: the final count is one short.
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = _explicit(["u0", "u1", "A"], start=0, total=6)
    clean2 = _explicit(["B", "u4", "u5"], start=3, total=6)
    script = Script(page1, page2, window, page1, clean2)

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == ["u0", "u1", "A", "B", "u4", "u5"]
    assert script.calls == [(0, 3), (3, 3), (0, 3), (0, 3), (3, 3)]


async def test_a_swap_that_hides_an_object_twice_fails_as_paging_inconsistent():
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    script = Script(page1, page2, page1, page1, page2, page1)

    result = await _run(script)

    assert result["success"] is False
    assert result["code"] == PAGING_INCONSISTENT_CODE
    assert "show-hosts" in result["message"]
    assert "listed 5 distinct objects, expected 6" in result["message"]
    assert len(script.calls) == 6


async def test_a_repeat_on_the_first_page_reads_no_window_and_restarts():
    doubled = {"success": True, "data": {"objects": [{"uid": "u0"}, {"uid": "u0"}], "total": 2, "from": 1, "to": 2}}
    script = Script(doubled, _page(0, 2, 2))

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == ["u0", "u1"]
    assert script.calls == [(0, 3), (0, 3)]


async def test_a_failed_window_read_fails_the_query_with_its_offset_and_code():
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    failed = {"success": False, "data": None, "message": "busy", "code": "generic_error"}
    script = Script(page1, page2, failed)

    result = await _run(script)

    assert result["success"] is False
    assert result["code"] == "generic_error"
    assert result["message"] == "show-hosts page at offset 0: busy"
    assert len(script.calls) == 3  # no extra retry


async def test_a_window_with_a_changed_total_restarts():
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = _explicit(["u0", "u1", "B"], start=0, total=7)
    clean2 = _explicit(["B", "u4", "u5"], start=3, total=6)
    script = Script(page1, page2, window, page1, clean2)

    result = await _run(script)

    assert result["success"] is True
    assert [o["uid"] for o in result["data"]] == ["u0", "u1", "A", "B", "u4", "u5"]
    assert script.calls == [(0, 3), (3, 3), (0, 3), (0, 3), (3, 3)]


@pytest.mark.parametrize("window_data", [[{"uid": "B"}], {"total": 6}])
async def test_a_window_without_the_container_list_restarts(window_data):
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = {"success": True, "data": window_data, "message": "", "code": ""}
    clean2 = _explicit(["B", "u4", "u5"], start=3, total=6)
    script = Script(page1, page2, window, page1, clean2)

    result = await _run(script)

    assert result["success"] is True
    assert script.calls == [(0, 3), (3, 3), (0, 3), (0, 3), (3, 3)]


async def test_the_window_recovers_only_objects_with_a_uid_not_listed_yet():
    # An object without a uid in the window cannot be told apart from the one already listed; it is not added again.
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page1["data"]["objects"][0] = {"name": "x"}
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = _explicit(["u0", "u1", "B"], start=0, total=6)
    window["data"]["objects"][0] = {"name": "x"}
    script = Script(page1, page2, window)

    result = await _run(script)

    assert result["success"] is True
    assert [o.get("uid", o.get("name")) for o in result["data"]] == ["x", "u1", "A", "B", "u4", "u5"]
    assert script.calls == [(0, 3), (3, 3), (0, 3)]


async def test_a_swap_is_logged_at_debug_without_names_or_uids(caplog):
    page1 = _explicit(["u0", "u1", "A"], start=0, total=6)
    page2 = _explicit(["A", "u4", "u5"], start=3, total=6)
    window = _explicit(["u0", "u1", "B"], start=0, total=6)
    script = Script(page1, page2, window)

    with caplog.at_level(logging.DEBUG, logger="arodonata.asdk.pager"):
        await _run(script)

    swap = [r for r in caplog.records if "equal names swapped" in r.getMessage()]
    assert [r.levelno for r in swap] == [logging.DEBUG]
    assert swap[0].getMessage() == (
        "show-hosts: equal names swapped at the page boundary at offset 3; re-read 3 objects before it"
    )


async def test_a_restart_begins_at_the_callers_offset():
    script = Script(_page(10, 3, 14), _page(13, 1, 15), _page(10, 3, 14), _page(13, 1, 14))

    result = await _run(script, offset=10)

    assert result["success"] is True
    assert script.calls == [(10, 3), (13, 3), (10, 3), (13, 3)]


async def test_a_changed_total_restarts_the_listing():
    # An object deleted before the cursor: total drops and one object would be skipped.
    script = Script(_page(0, 3, 7), _page(3, 3, 6), _page(0, 3, 6), _page(3, 3, 6))

    result = await _run(script)

    assert result["success"] is True
    assert len(result["data"]) == 6


async def test_a_page_that_does_not_start_after_the_previous_to_restarts():
    gap = _page(4, 3, 7)  # from=5, expected 4
    script = Script(_page(0, 3, 7), gap, _page(0, 3, 7), _page(3, 3, 7), _page(6, 1, 7))

    assert (await _run(script))["success"] is True


async def test_an_empty_page_before_total_restarts():
    script = Script(_page(0, 3, 7), _page(3, 0, 7), _page(0, 3, 7), _page(3, 3, 7), _page(6, 1, 7))

    assert (await _run(script))["success"] is True


async def test_a_page_whose_to_does_not_advance_restarts():
    stuck = {"success": True, "data": {"objects": [{"uid": "x"}], "total": 7, "to": 3}}
    script = Script(_page(0, 3, 7), stuck, _page(0, 3, 7), _page(3, 3, 7), _page(6, 1, 7))

    assert (await _run(script))["success"] is True


async def test_a_shift_on_the_restart_too_fails_as_paging_inconsistent():
    script = Script(_page(0, 3, 7), _page(3, 3, 6), _page(0, 3, 6), _page(3, 3, 5))

    result = await _run(script)

    assert result["success"] is False
    assert result["code"] == PAGING_INCONSISTENT_CODE
    assert "show-hosts" in result["message"]
    assert "offset 3" in result["message"]
    assert "total" in result["message"]
    assert len(script.calls) == 4


@pytest.mark.parametrize(
    "error",
    [
        ApiTimeoutError("read timed out", phase="read", host="h", port=443, timeout=125, command="show-hosts"),
        ConnectionError("x"),
    ],
)
async def test_an_exception_from_a_page_propagates_without_a_retry(error):
    script = Script(_page(0, 3, 7), error)

    with pytest.raises(type(error)):
        await _run(script)
    assert len(script.calls) == 2


async def test_objects_without_uid_are_not_checked_for_duplicates():
    page1 = {"success": True, "data": {"objects": [{"name": "a"}, {"name": "a"}], "total": 3, "from": 1, "to": 2}}
    page2 = {"success": True, "data": {"objects": [{"name": "a"}], "total": 3, "from": 3, "to": 3}}
    script = Script(page1, page2)

    result = await _run(script, page_size=2)

    assert result["success"] is True
    assert len(result["data"]) == 3


async def test_a_first_page_with_no_objects_returns_an_empty_list():
    page = {"success": True, "data": {"objects": [], "total": 7}}
    script = Script(page)

    result = await _run(script, offset=10)

    assert result["success"] is True
    assert result["data"] == []
    assert len(script.calls) == 1


async def test_a_first_page_with_items_but_no_total_returns_them_as_a_list_in_one_call():
    page = {"success": True, "data": {"objects": [{"uid": "a"}, {"uid": "b"}]}}
    script = Script(page)

    result = await _run(script)

    assert result["success"] is True
    assert result["data"] == [{"uid": "a"}, {"uid": "b"}]
    assert len(script.calls) == 1


async def test_a_later_page_that_is_not_a_dict_restarts_once_then_fails():
    bad = {"success": True, "data": [{"uid": "x"}]}
    script = Script(_page(0, 3, 7), bad, _page(0, 3, 7), bad)

    result = await _run(script)

    assert result["success"] is False
    assert result["code"] == PAGING_INCONSISTENT_CODE
    assert len(script.calls) == 4
