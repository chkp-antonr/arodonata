"""drain_background_tasks: let a client's background work finish before cancelling it.

Clients spawn short background tasks (a keepalive sweep after every API call,
the startup session cleanup). close() used to cancel them outright. A sweep
cancelled while it held a pooled SQLite connection made SQLAlchemy log
"Exception during reset or similar" with a CancelledError traceback on every
test teardown that raced one (int-1, 2026-09-28). A short grace period lets
the sweep return its connection normally; only work still running after it is
cancelled.
"""

from __future__ import annotations

import asyncio

from arodonata.utils.background_tasks import drain_background_tasks


async def test_a_task_that_finishes_within_the_grace_period_is_not_cancelled():
    finished = asyncio.Event()

    async def short_sweep():
        await asyncio.sleep(0.05)
        finished.set()

    task = asyncio.create_task(short_sweep())

    await drain_background_tasks({task}, grace=2.0)

    assert finished.is_set()
    assert not task.cancelled()


async def test_a_task_still_running_after_the_grace_period_is_cancelled():
    async def never_ends():
        await asyncio.sleep(100)

    task = asyncio.create_task(never_ends())
    loop = asyncio.get_running_loop()
    started = loop.time()

    await drain_background_tasks({task}, grace=0.05)

    assert task.cancelled()
    assert loop.time() - started < 1.0  # bounded by the grace, not by the task


async def test_zero_grace_cancels_at_once():
    async def never_ends():
        await asyncio.sleep(100)

    task = asyncio.create_task(never_ends())

    await drain_background_tasks({task}, grace=0)

    assert task.cancelled()


async def test_a_failing_task_does_not_propagate_out_of_close():
    """Background work is best effort: its exception must not break close()."""

    async def boom():
        raise RuntimeError("sweep failed")

    task = asyncio.create_task(boom())

    await drain_background_tasks({task}, grace=1.0)

    assert task.done()


async def test_no_tasks_is_a_no_op():
    await drain_background_tasks(set(), grace=5.0)
