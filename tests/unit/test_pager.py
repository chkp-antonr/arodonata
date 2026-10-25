"""Unit tests for `paginate_objects` (`src/arodonata/adapters/checkpoint/pager.py`)."""

from __future__ import annotations

from typing import Any

from arodonata.adapters.checkpoint.pager import TASK_QUERY_COMMANDS, paginate_objects
from arodonata.core.models.common import ApiCallResult


async def test_boundary_swap_duplicate_uid_recovery() -> None:
    """Scenario: Boundary swap duplicate UID recovery via ±10 window re-read without restarting full listing."""
    # Suppose 30 objects total, page size = 15.
    # On page 1 (offset=0, limit=15): returns uids 0..14 (uid-14 is at index 14).
    # Before page 2 (offset=15, limit=15): Check Point swaps uid-14 and uid-15 across the boundary!
    # So page 2 (offset=15, limit=15) returns [uid-14, uid-16, uid-17, ..., uid-29] (uid-15 was displaced to index 14!).
    # The pager detects duplicate uid-14, drops it, and re-reads window offset=5, limit=20 (covering indices 5..24),
    # which now includes uid-15 at index 14!
    all_items_after_swap = [{"uid": f"uid-{i}", "name": f"obj-{i}"} for i in range(30)]
    # Swap index 14 and 15 in the post-page-1 state
    all_items_after_swap[14], all_items_after_swap[15] = all_items_after_swap[15], all_items_after_swap[14]

    calls: list[tuple[int, int]] = []

    async def page_caller(payload: dict[str, Any]) -> ApiCallResult:
        offset = int(payload["offset"])
        limit = int(payload["limit"])
        calls.append((offset, limit))

        if len(calls) == 1:
            # First page before swap
            initial_items = [{"uid": f"uid-{i}", "name": f"obj-{i}"} for i in range(15)]
            return ApiCallResult(
                success=True,
                data={"objects": initial_items, "from": 1, "to": 15, "total": 30},
            )

        slice_items = all_items_after_swap[offset : offset + limit]
        return ApiCallResult(
            success=True,
            data={
                "objects": slice_items,
                "from": offset + 1,
                "to": offset + len(slice_items),
                "total": 30,
            },
        )

    res = await paginate_objects("show-hosts", page_caller, limit=15)
    assert res.success is True
    assert res.total == 30
    assert len(res.objects) == 30
    returned_uids = {obj["uid"] for obj in res.objects}
    assert returned_uids == {f"uid-{i}" for i in range(30)}
    # Calls should be: page 1 (0, 15), page 2 (15, 15), window recovery (5, 20) — no full restart!
    assert calls == [(0, 15), (15, 15), (5, 20)]


async def test_total_count_change_or_continuity_break_triggers_single_restart() -> None:
    """Scenario: Total count change or continuity break triggers single restart, and second failure returns paging_inconsistent."""
    # Case A: First pass has a total count change on page 2, second pass succeeds cleanly.
    pass_num = 0
    calls_a: list[int] = []

    async def caller_recovers_on_restart(payload: dict[str, Any]) -> ApiCallResult:
        nonlocal pass_num
        offset = int(payload["offset"])
        calls_a.append(offset)
        if offset == 0:
            pass_num += 1
            return ApiCallResult(
                success=True,
                data={
                    "objects": [{"uid": "u1"}, {"uid": "u2"}],
                    "from": 1,
                    "to": 2,
                    "total": 4,
                },
            )
        if pass_num == 1:
            # Total changed mid-listing from 4 to 5!
            return ApiCallResult(
                success=True,
                data={
                    "objects": [{"uid": "u3"}, {"uid": "u4"}],
                    "from": 3,
                    "to": 4,
                    "total": 5,
                },
            )
        return ApiCallResult(
            success=True,
            data={
                "objects": [{"uid": "u3"}, {"uid": "u4"}],
                "from": 3,
                "to": 4,
                "total": 4,
            },
        )

    res_a = await paginate_objects("show-hosts", caller_recovers_on_restart, limit=2)
    assert res_a.success is True
    assert len(res_a.objects) == 4
    assert calls_a == [0, 2, 0, 2]

    # Case B: Both passes fail continuity -> returns success=False, code="paging_inconsistent"
    calls_b: list[int] = []

    async def caller_always_inconsistent(payload: dict[str, Any]) -> ApiCallResult:
        offset = int(payload["offset"])
        calls_b.append(offset)
        if offset == 0:
            return ApiCallResult(
                success=True,
                data={"objects": [{"uid": "u1"}, {"uid": "u2"}], "from": 1, "to": 2, "total": 4},
            )
        # Broken `from` continuity (from=4 instead of 3)
        return ApiCallResult(
            success=True,
            data={"objects": [{"uid": "u3"}, {"uid": "u4"}], "from": 4, "to": 4, "total": 4},
        )

    res_b = await paginate_objects("show-hosts", caller_always_inconsistent, limit=2)
    assert res_b.success is False
    assert res_b.code == "paging_inconsistent"
    assert calls_b == [0, 2, 0, 2]


async def test_task_based_query_commands_paged_through_task_waiter() -> None:
    """Scenario: Task-based query commands paged through TaskWaiter (`tasks[].task-details[]`)."""
    assert "show-unused-objects" in TASK_QUERY_COMMANDS

    async def task_page_caller(payload: dict[str, Any]) -> ApiCallResult:
        offset = int(payload["offset"])
        if offset == 0:
            return ApiCallResult(
                success=True,
                data={
                    "tasks": [
                        {
                            "task-id": "t-page-1",
                            "status": "succeeded",
                            "task-details": [
                                {
                                    "objects": [{"uid": "unused-1"}, {"uid": "unused-2"}],
                                    "from": 1,
                                    "to": 2,
                                    "total": 3,
                                }
                            ],
                        }
                    ]
                },
            )
        return ApiCallResult(
            success=True,
            data={
                "tasks": [
                    {
                        "task-id": "t-page-2",
                        "status": "succeeded",
                        "task-details": [
                            {
                                "objects": [{"uid": "unused-3"}],
                                "from": 3,
                                "to": 3,
                                "total": 3,
                            }
                        ],
                    }
                ]
            },
        )

    res = await paginate_objects("show-unused-objects", task_page_caller, limit=2)
    assert res.success is True
    assert res.total == 3
    assert [o["uid"] for o in res.objects] == ["unused-1", "unused-2", "unused-3"]
