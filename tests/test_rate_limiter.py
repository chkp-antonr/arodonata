"""Unit tests for `RateLimiter` and `LoginGate` (`src/arodonata/adapters/checkpoint/rate_limiter.py`)."""

from __future__ import annotations

import asyncio

import pytest

from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.storage import DatabaseManager, SqlLockAdapter
from arodonata.core.errors import RateLimitTimeoutError


async def test_fair_waiter_wakeup_on_slot_release_and_timeout() -> None:
    """Scenario: Fair waiter wakeup on slot release in FIFO arrival order, and timeout when exhausted."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    lock_adapter = SqlLockAdapter(db)

    limiter = RateLimiter(
        concurrent_limit=2,
        slot_timeout=5.0,
        lock_port=lock_adapter,
    )

    wakeup_order: list[str] = []
    hold_slot_1 = asyncio.Event()
    hold_slot_2 = asyncio.Event()
    started_1 = asyncio.Event()
    started_2 = asyncio.Event()

    async def holder(name: str, started: asyncio.Event, release_ev: asyncio.Event) -> None:
        async with limiter.slot("10.0.0.1"):
            wakeup_order.append(name)
            started.set()
            await release_ev.wait()

    t1 = asyncio.create_task(holder("h1", started_1, hold_slot_1))
    t2 = asyncio.create_task(holder("h2", started_2, hold_slot_2))
    await started_1.wait()
    await started_2.wait()

    # Now both slots for 10.0.0.1 are occupied. Queue 3 waiters in exact FIFO order: w1, w2, w3.
    async def waiter(name: str) -> None:
        async with limiter.slot("10.0.0.1"):
            wakeup_order.append(name)
            await asyncio.sleep(0.005)

    w1 = asyncio.create_task(waiter("w1"))
    await asyncio.sleep(0.01)
    w2 = asyncio.create_task(waiter("w2"))
    await asyncio.sleep(0.01)
    w3 = asyncio.create_task(waiter("w3"))
    await asyncio.sleep(0.01)

    # Release slot 1 -> wakes w1, then w2, then w3 in strict FIFO order
    hold_slot_1.set()
    hold_slot_2.set()
    await asyncio.gather(t1, t2, w1, w2, w3)

    assert wakeup_order == ["h1", "h2", "w1", "w2", "w3"]

    # Test timeout when all slots remain occupied beyond rate_limit_slot_timeout
    block_forever = asyncio.Event()
    s1 = asyncio.Event()
    s2 = asyncio.Event()
    b1 = asyncio.create_task(holder("b1", s1, block_forever))
    b2 = asyncio.create_task(holder("b2", s2, block_forever))
    await s1.wait()
    await s2.wait()

    with pytest.raises(RateLimitTimeoutError) as exc_info:
        async with limiter.slot("10.0.0.1", timeout=0.05):
            pass
    assert isinstance(exc_info.value, TimeoutError)

    block_forever.set()
    await asyncio.gather(b1, b2)
    await db.close()


async def test_coalesced_background_keepalive_sweeps() -> None:
    """Scenario: Coalesced background keepalive sweeps so at most one sweep runs at a time."""
    limiter = RateLimiter(concurrent_limit=2)
    sweep_executions = 0
    sweep_gate = asyncio.Event()

    async def keepalive_sweep() -> int:
        nonlocal sweep_executions
        sweep_executions += 1
        await sweep_gate.wait()
        return sweep_executions

    t1 = asyncio.create_task(limiter.run_coalesced_keepalive("mds1", keepalive_sweep))
    await asyncio.sleep(0.01)
    t2 = asyncio.create_task(limiter.run_coalesced_keepalive("mds1", keepalive_sweep))
    t3 = asyncio.create_task(limiter.run_coalesced_keepalive("mds1", keepalive_sweep))
    await asyncio.sleep(0.01)

    sweep_gate.set()
    results = await asyncio.gather(t1, t2, t3)
    assert results == [1, 1, 1]
    assert sweep_executions == 1

    # Subsequent sweep after completion executes a new run
    res_next = await limiter.run_coalesced_keepalive("mds1", keepalive_sweep)
    assert res_next == 2
    assert sweep_executions == 2


async def test_login_gate_serializes_concurrent_logins_per_mds_member() -> None:
    """Verify LoginGate serializes concurrent logins per active_mds_ip."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    gate = LoginGate(lock_port=SqlLockAdapter(db))

    active_in_gate = 0
    max_concurrent_in_gate = 0

    async def do_login() -> None:
        nonlocal active_in_gate, max_concurrent_in_gate
        async with gate.acquire("10.0.0.1"):
            active_in_gate += 1
            max_concurrent_in_gate = max(max_concurrent_in_gate, active_in_gate)
            await asyncio.sleep(0.015)
            active_in_gate -= 1

    await asyncio.gather(do_login(), do_login(), do_login())
    assert max_concurrent_in_gate == 1
    await db.close()
