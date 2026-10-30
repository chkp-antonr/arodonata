"""Per-MDS-member concurrency semaphore (`RateLimiter`) and login serialization (`LoginGate`).

Enforces `concurrent_limit` per MDS member (`active_mds_ip`) using database-backed
slot locks (`LockPort`) and strict FIFO in-process waiter queues, coalesces
overlapping background keepalive sweeps, and serializes logins per `active_mds_ip`.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from typing import Any, TypeVar

from arodonata.core.errors import AuthenticationError, RateLimitTimeoutError
from arodonata.core.ports import LockPort
from arodonata.core.telemetry import span_attrs, traced

T = TypeVar("T")


class _MdsSlotQueue:
    """In-process FIFO waiter queue and available local slot pool for a single `active_mds_ip`."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.available_slots: deque[int] = deque(range(limit))
        self.waiters: deque[asyncio.Future[int]] = deque()


class RateLimiter:
    """Caps in-flight API requests per MDS member (`active_mds_ip`) to `concurrent_limit`.

    Uses both in-process strict FIFO waiter queues and optional database-backed
    slot locks (`LockPort`) so multiple coroutines wake in exact arrival order
    and cross-process workers coordinate over `distributed_locks`.
    """

    def __init__(
        self,
        *,
        concurrent_limit: int = 4,
        slot_timeout: float = 90.0,
        lock_port: LockPort | None = None,
        slot_lock_ttl: float = 180.0,
        monotonic_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._concurrent_limit = max(1, min(int(concurrent_limit), 20))
        self._slot_timeout = float(slot_timeout)
        self._lock_port = lock_port
        self._slot_lock_ttl = float(slot_lock_ttl)
        self._monotonic = monotonic_fn
        self._sleep = sleep_fn
        self._worker_prefix = f"rl-{uuid.uuid4().hex[:8]}"

        self._queues: dict[str, _MdsSlotQueue] = {}
        self._inflight_keepalives: dict[str, asyncio.Task[Any]] = {}

    @property
    def concurrent_limit(self) -> int:
        """Maximum concurrent requests per MDS member."""
        return self._concurrent_limit

    @property
    def slot_timeout(self) -> float:
        """Default timeout in seconds when waiting for a free slot."""
        return self._slot_timeout

    def _get_queue(self, mds_ip: str) -> _MdsSlotQueue:
        q = self._queues.get(mds_ip)
        if q is None:
            q = _MdsSlotQueue(self._concurrent_limit)
            self._queues[mds_ip] = q
        return q

    async def _acquire_local_fifo_slot(self, mds_ip: str, deadline: float, timeout_budget: float) -> int:
        """Acquire a local slot index `(0..concurrent_limit-1)` in strict FIFO arrival order."""
        q = self._get_queue(mds_ip)
        if q.available_slots and not q.waiters:
            return q.available_slots.popleft()

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[int] = loop.create_future()
        q.waiters.append(fut)

        remaining = deadline - self._monotonic()
        if remaining <= 0:
            if fut in q.waiters:
                q.waiters.remove(fut)
            if fut.done() and not fut.cancelled():
                self._release_local_fifo_slot(mds_ip, fut.result())
            raise RateLimitTimeoutError(
                f"Timed out after {timeout_budget}s waiting for a RateLimiter slot on MDS member {mds_ip!r}."
            )

        try:
            return await asyncio.wait_for(fut, timeout=remaining)
        except TimeoutError as exc:
            if fut in q.waiters:
                q.waiters.remove(fut)
            elif fut.done() and not fut.cancelled():
                # Slot was handed to `fut` right as timeout fired; pass it to the next waiter
                self._release_local_fifo_slot(mds_ip, fut.result())
            raise RateLimitTimeoutError(
                f"Timed out after {timeout_budget}s waiting for a RateLimiter slot on MDS member {mds_ip!r}."
            ) from exc
        except asyncio.CancelledError:
            if fut in q.waiters:
                q.waiters.remove(fut)
            elif fut.done() and not fut.cancelled():
                self._release_local_fifo_slot(mds_ip, fut.result())
            raise

    def _release_local_fifo_slot(self, mds_ip: str, slot_idx: int) -> None:
        """Release `slot_idx` and wake the oldest waiting coroutine in arrival order."""
        q = self._get_queue(mds_ip)
        while q.waiters:
            waiter = q.waiters.popleft()
            if not waiter.done():
                waiter.set_result(slot_idx)
                return
        q.available_slots.append(slot_idx)

    async def _acquire_db_slot(
        self,
        mds_ip: str,
        preferred_slot: int,
        deadline: float,
        timeout_budget: float,
    ) -> tuple[str, str]:
        """Acquire a database-backed slot lock for `mds_ip` when `self._lock_port` is configured."""
        assert self._lock_port is not None
        owner_id = f"{self._worker_prefix}:{uuid.uuid4().hex[:8]}"

        # Try preferred slot first, then scan other slots if another process holds it
        candidate_indices = [preferred_slot] + [i for i in range(self._concurrent_limit) if i != preferred_slot]
        while True:
            for idx in candidate_indices:
                lock_key = f"rate_slot:{mds_ip}:{idx}"
                acquired = await self._lock_port.acquire(
                    lock_key,
                    ttl_seconds=self._slot_lock_ttl,
                    owner_id=owner_id,
                    wait_timeout=0.0,
                )
                if acquired:
                    return lock_key, owner_id

            if self._monotonic() >= deadline:
                raise RateLimitTimeoutError(
                    f"Timed out after {timeout_budget}s waiting for database RateLimiter slot on MDS member {mds_ip!r}."
                )
            await self._sleep(min(0.02, max(0.001, deadline - self._monotonic())))

    @asynccontextmanager
    async def slot(
        self,
        mds_ip: str,
        *,
        timeout: float | None = None,
    ) -> AsyncIterator[int]:
        """Acquire a concurrency slot for `mds_ip` in FIFO order and release on exit."""
        target_ip = (mds_ip or "default").strip()
        budget = float(timeout) if timeout is not None else self._slot_timeout
        deadline = self._monotonic() + budget
        span_attrs(mds_ip=target_ip, concurrent_limit=self._concurrent_limit)

        local_slot = await self._acquire_local_fifo_slot(target_ip, deadline, budget)
        db_lock_info: tuple[str, str] | None = None
        try:
            if self._lock_port is not None:
                db_lock_info = await self._acquire_db_slot(target_ip, local_slot, deadline, budget)
            yield local_slot
        finally:
            try:
                if db_lock_info is not None and self._lock_port is not None:
                    lock_key, owner_id = db_lock_info
                    with suppress(Exception):
                        await asyncio.shield(self._lock_port.release(lock_key, owner_id=owner_id))
            finally:
                self._release_local_fifo_slot(target_ip, local_slot)

    @traced
    async def run_coalesced_keepalive(
        self,
        sweep_key: str,
        sweep_factory: Callable[[], Awaitable[T]],
    ) -> T:
        """Coalesce overlapping background keepalive sweeps for `sweep_key`.

        If a keepalive sweep is already running for `sweep_key`, concurrent callers
        await the active task via `asyncio.shield` (`I7`) instead of scheduling duplicate
        sweeps or cancelling the shared task when a single waiter is cancelled.
        """
        existing = self._inflight_keepalives.get(sweep_key)
        if existing is not None and not existing.done():
            span_attrs(keepalive_coalesced=True, sweep_key=sweep_key)
            res: T = await asyncio.shield(existing)
            return res

        span_attrs(keepalive_coalesced=False, sweep_key=sweep_key)

        async def _runner() -> T:
            try:
                return await sweep_factory()
            finally:
                if self._inflight_keepalives.get(sweep_key) is task:
                    self._inflight_keepalives.pop(sweep_key, None)

        task: asyncio.Task[T] = asyncio.create_task(_runner())
        self._inflight_keepalives[sweep_key] = task
        return await asyncio.shield(task)


class LoginGate:
    """Serializes and rate-limits logins per MDS member (`active_mds_ip`) so concurrent domain logins
    against the same MDS member do not trigger Check Point's 3 logins/minute rate limit (`C7`, `W4`, `W5`).
    """

    def __init__(
        self,
        *,
        lock_port: LockPort | None = None,
        gate_lock_ttl: float = 180.0,
        min_login_interval: float = 0.0,
        monotonic_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._lock_port = lock_port
        self._gate_lock_ttl = float(gate_lock_ttl)
        self._min_login_interval = max(0.0, float(min_login_interval))
        self._monotonic = monotonic_fn
        self._sleep = sleep_fn
        self._local_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._next_allowed_at: dict[str, float] = defaultdict(float)
        self._owner_prefix = f"lg-{uuid.uuid4().hex[:8]}"

    def record_cooldown(self, mds_ip: str, cooldown_seconds: float) -> None:
        """Record a shared throttle or backoff cooldown window for `mds_ip` (`W4`)."""
        target_ip = (mds_ip or "default").strip()
        candidate = self._monotonic() + max(0.0, float(cooldown_seconds))
        if candidate > self._next_allowed_at[target_ip]:
            self._next_allowed_at[target_ip] = candidate

    @asynccontextmanager
    async def acquire(
        self,
        mds_ip: str,
        *,
        wait_timeout: float = 900.0,
    ) -> AsyncIterator[str]:
        """Serialize login execution for `mds_ip` across in-process coroutines and distributed workers."""
        target_ip = (mds_ip or "default").strip()
        budget = max(0.01, float(wait_timeout))
        deadline = self._monotonic() + budget
        local_lock = self._local_locks[target_ip]

        try:
            async with asyncio.timeout(budget):
                await local_lock.acquire()
        except TimeoutError as exc:
            raise AuthenticationError(
                f"Timed out after {budget}s waiting for local LoginGate on MDS member {target_ip!r}."
            ) from exc

        try:
            remaining = max(0.01, deadline - self._monotonic())
            if self._lock_port is None:
                cooldown_wait = self._next_allowed_at[target_ip] - self._monotonic()
                if cooldown_wait > 0:
                    if self._monotonic() + cooldown_wait > deadline:
                        raise AuthenticationError(
                            f"LoginGate cooldown ({cooldown_wait:.1f}s) on MDS member {target_ip!r} "
                            f"exceeds remaining wait_timeout ({remaining:.1f}s)."
                        )
                    await self._sleep(cooldown_wait)
                if self._min_login_interval > 0:
                    self._next_allowed_at[target_ip] = max(
                        self._next_allowed_at[target_ip],
                        self._monotonic() + self._min_login_interval,
                    )
                yield target_ip
                return

            lock_key = f"login_gate:{target_ip}"
            async with self._lock_port.lock(
                lock_key,
                ttl_seconds=self._gate_lock_ttl,
                owner_id=f"{self._owner_prefix}:{uuid.uuid4().hex[:8]}",
                wait_timeout=remaining,
            ):
                cooldown_wait = self._next_allowed_at[target_ip] - self._monotonic()
                if cooldown_wait > 0:
                    if self._monotonic() + cooldown_wait > deadline:
                        raise AuthenticationError(
                            f"LoginGate cooldown ({cooldown_wait:.1f}s) on MDS member {target_ip!r} "
                            f"exceeds remaining wait_timeout."
                        )
                    await self._sleep(cooldown_wait)
                if self._min_login_interval > 0:
                    self._next_allowed_at[target_ip] = max(
                        self._next_allowed_at[target_ip],
                        self._monotonic() + self._min_login_interval,
                    )
                yield target_ip
        finally:
            local_lock.release()


__all__ = [
    "LoginGate",
    "RateLimiter",
]
