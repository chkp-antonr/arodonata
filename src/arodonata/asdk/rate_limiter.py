"""Rate limiter for per-MDS member concurrent API request limiting.

Manages distributed locks to limit concurrent operations per MDS member,
preventing overload of management servers across multiple workers.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import itertools
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from contextvars import ContextVar

from arlogi.otel.decorator import traced

from ..cache.lock_manager import DatabaseLockManager, LockAcquisitionError, LockContext, LockOwnershipError
from ..config.constants import DEFAULT_CONCURRENT_LIMIT, DEFAULT_RATE_LIMIT_SLOT_TIMEOUT
from ..logger import lazy_logger
from ..telemetry import span_attrs

log = lazy_logger("arodonata.asdk.rate_limiter")

_caller_id_var: ContextVar[int | None] = ContextVar("_caller_id_var", default=None)
_caller_id_counter = itertools.count(1)


class RateLimiter:
    """Per-MDS member distributed lock for concurrent API operation limiting.

    Uses SQL-database-backed distributed locks (any SQLAlchemy-supported
    dialect) to enforce concurrent operation limits across multiple
    workers/processes.

    Lock keys use a slot-based approach: ratelimit:{host}:slot_{n}
    where host is the MDS member hosting the target (LoginCoordinator.mds_host)
    and n is determined by hashing the operation ID to distribute load.
    A held slot's row is renewed every third of its TTL until release, so a
    request that outlasts the TTL (a publish task, a long single call) keeps it.

    Waiters for one host are served in arrival order within this process: a caller that finds others
    waiting queues behind them, only the longest waiter sweeps the slots, and a release wakes it at
    once. A caller that releases after a page and asks again (asdk/pager.py) therefore lets the waiter
    in first. Slots freed by other processes are found by the longest waiter's polling sweep.

    Example:
        limiter = RateLimiter(concurrent_limit=4)
        async with limiter.acquire("192.168.1.10"):
            # Make API call - limited to 4 concurrent per member across all workers
            pass
    """

    def __init__(
        self,
        concurrent_limit: int = DEFAULT_CONCURRENT_LIMIT,
        lock_manager: DatabaseLockManager | None = None,
        slot_timeout: int = DEFAULT_RATE_LIMIT_SLOT_TIMEOUT,
        slot_renew_interval: float | None = None,
    ) -> None:
        """Initialize rate limiter.

        Args:
            concurrent_limit: Maximum concurrent operations per MDS member.
            lock_manager: Optional DatabaseLockManager instance.
            slot_timeout: Default seconds acquire() waits for a free slot before
                giving up (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT for why this must
                comfortably exceed a single login retry-with-backoff sequence).
            slot_renew_interval: Seconds between renewals of a held slot's lock row.
                Defaults to a third of the row's TTL (DEFAULT_TTL_RATE_LIMIT, so 100 s);
                must be positive.
        """
        self._concurrent_limit = concurrent_limit
        self._lock_manager = lock_manager
        self._slot_timeout = slot_timeout
        if slot_renew_interval is not None and slot_renew_interval <= 0:
            raise ValueError(f"slot_renew_interval must be positive, got {slot_renew_interval}")
        self._slot_renew_interval_override = slot_renew_interval
        self._in_process_locks: dict[str, asyncio.Lock] = {}  # For in-process synchronization
        self._reentrancy_count: dict[str, int] = {}  # Track reentrant locks per task, keyed by held slot
        self._task_slot: dict[str, str] = {}  # (server_ip, task) -> lock_key of the slot actually held
        self._waiters: dict[str, deque[asyncio.Event]] = {}  # host -> callers waiting for a slot, oldest first
        self._lock_init_lock = asyncio.Lock()  # Protection for lock manager initialization
        self._closed = False
        log().debug(f"RateLimiter initialized with limit={concurrent_limit}, slot_timeout={slot_timeout}")

    async def close(self) -> None:
        """Clean up resources."""
        if not self._closed:
            self._closed = True
            if self._lock_manager:
                await self._lock_manager.close()
            self._in_process_locks.clear()
            self._reentrancy_count.clear()
            self._task_slot.clear()
            self._waiters.clear()
            log().debug("RateLimiter closed")

    async def _get_lock_manager(self) -> DatabaseLockManager:
        """Get or create lock manager instance.

        Uses the global lock manager if available to reuse database connections.

        Returns:
            DatabaseLockManager instance.
        """
        if self._lock_manager is None:
            async with self._lock_init_lock:
                if self._lock_manager is None:
                    from arodonata.cache import _get_global_lock_manager

                    self._lock_manager = await _get_global_lock_manager()
                    await self._lock_manager.initialize()

        assert self._lock_manager is not None
        return self._lock_manager

    def _slot_renew_interval(self, ttl: int) -> float:
        """Seconds between renewals of a held slot's distributed row: a third of its TTL unless overridden."""
        if self._slot_renew_interval_override is not None:
            return self._slot_renew_interval_override
        return ttl / 3

    def _get_slot_number(self, server_ip: str) -> int:
        """Get slot number for server IP using consistent hash.

        Args:
            server_ip: Server IP address.

        Returns:
            Slot number (0 to concurrent_limit - 1).
        """
        # Use hash of server_ip + current task/coroutine ID for distribution
        # This ensures different operations get different slots
        task_id = self._current_task_id()

        hash_input = f"{server_ip}:{task_id}".encode()
        hash_value = int(hashlib.sha256(hash_input).hexdigest(), 16)
        return hash_value % self._concurrent_limit

    @staticmethod
    def _current_task_id() -> int:
        """Identity of the running task (unique per context outside a task), for reentrancy bookkeeping."""
        try:
            current_task = asyncio.current_task()
            if current_task is not None:
                return id(current_task)
        except RuntimeError:
            pass

        caller_id = _caller_id_var.get()
        if caller_id is None:
            caller_id = next(_caller_id_counter)
            _caller_id_var.set(caller_id)
        return caller_id

    async def _try_take_slot(
        self, lock_manager: DatabaseLockManager, lock_key: str, ttl: int
    ) -> tuple[asyncio.Lock, LockContext] | None:
        """Take `lock_key` if it is free right now; never wait.

        In-process gate first (cheap, no DB round-trip), then the distributed
        row. Returns (in_process_lock, lock) on success — the caller releases
        both — or None when the slot is busy at either level.
        """
        in_process = self._in_process_locks.setdefault(lock_key, asyncio.Lock())
        if in_process.locked():
            return None
        await in_process.acquire()  # unlocked -> returns without suspending

        lock = await lock_manager.try_acquire_lock(lock_key, ttl)
        if lock is None:
            in_process.release()
            return None
        return in_process, lock

    async def _sweep(
        self, lock_manager: DatabaseLockManager, server_ip: str, base_slot: int, ttl: int
    ) -> tuple[int, str, asyncio.Lock, LockContext] | None:
        """One pass over the host's slots, starting at the hashed one: the first free slot, or None if all are busy."""
        for offset in range(self._concurrent_limit):
            slot = (base_slot + offset) % self._concurrent_limit
            lock_key = f"ratelimit:{server_ip}:slot_{slot}"
            taken = await self._try_take_slot(lock_manager, lock_key, ttl)
            if taken is not None:
                return slot, lock_key, taken[0], taken[1]
        return None

    def _wake_head(self, server_ip: str) -> None:
        """Tell the longest waiter for `server_ip` to sweep now."""
        queue = self._waiters.get(server_ip)
        if queue:
            queue[0].set()

    async def _take_in_turn(
        self,
        lock_manager: DatabaseLockManager,
        server_ip: str,
        base_slot: int,
        ttl: int,
        timeout: int,
    ) -> tuple[int, str, asyncio.Lock, LockContext]:
        """Take a slot in arrival order, or raise LockAcquisitionError after `timeout` seconds.

        Nobody waiting: sweep at once. Otherwise queue at the tail; only the head sweeps. The head
        re-sweeps when a release in this process wakes it, or after its backoff (0.1 s doubling to
        2 s) for slots other processes free; everyone behind it waits to become head. Leaving the
        queue for any reason (slot taken, timeout, cancellation) wakes the next head, which may find
        another free slot.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        if not self._waiters.get(server_ip):
            taken = await self._sweep(lock_manager, server_ip, base_slot, ttl)
            if taken is not None:
                span_attrs(attempts=0)
                return taken
        # No await between looking the queue up and joining it: an emptied queue is dropped from
        # _waiters in the finally below, and joining a dropped one would never be woken.
        queue = self._waiters.setdefault(server_ip, deque())
        me = asyncio.Event()
        queue.append(me)
        attempt = 0
        try:
            while True:
                is_head = queue[0] is me
                me.clear()  # before the sweep: a release during the sweep must not be lost
                if is_head:
                    taken = await self._sweep(lock_manager, server_ip, base_slot, ttl)
                    if taken is not None:
                        span_attrs(attempts=attempt)
                        return taken
                remaining = deadline - loop.time()
                if remaining <= 0:
                    span_attrs(attempts=attempt)
                    raise LockAcquisitionError(f"ratelimit:{server_ip}:slot_*", timeout)
                if is_head:
                    wait = min(2**attempt * 0.1, 2.0, remaining)
                    attempt += 1
                    log().trace(
                        f"RateLimiter all {self._concurrent_limit} slots busy for {server_ip}; first in line, retry in {wait:.1f}s"
                    )
                else:
                    wait = remaining
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(me.wait(), wait)
        finally:
            was_head = bool(queue) and queue[0] is me
            with contextlib.suppress(ValueError):
                queue.remove(me)
            if was_head and queue:
                queue[0].set()
            if not queue and self._waiters.get(server_ip) is queue:
                del self._waiters[server_ip]

    async def _keep_slot(self, lock_manager: DatabaseLockManager, lock_key: str, owner_id: str, ttl: int) -> None:
        """Renew the held slot's distributed row every `_slot_renew_interval(ttl)` until cancelled at release.

        A failed renewal cannot stop the request already in flight. A row that is gone or owned by
        someone else cannot be won back by renewing, so that is reported once and renewal stops; any
        other error (a busy database, a dropped connection) is logged and the next interval retries.
        No upper bound on the hold: a request that hangs keeps its slot in every process until it
        ends (cpapi has no socket timeout of its own).
        """
        interval = self._slot_renew_interval(ttl)
        while True:
            await asyncio.sleep(interval)
            try:
                if not await lock_manager.renew_lock(lock_key, owner_id, ttl):
                    log().warning(f"RateLimiter slot {lock_key} lapsed while held; another process may take it")
                    return
            except LockOwnershipError:
                log().warning(f"RateLimiter slot {lock_key} was taken by another owner while held")
                return
            except Exception as exc:  # noqa: BLE001 - renewal is best effort; the request continues
                log().warning(f"RateLimiter could not renew slot {lock_key}: {type(exc).__name__}")
                log().debug(f"RateLimiter renewal error for {lock_key}", exc_info=True)

    def _drop_reentrancy(self, reentrancy_key: str, task_key: str) -> None:
        """Undo one level of reentrancy bookkeeping; forget the task's slot at zero."""
        if reentrancy_key in self._reentrancy_count:
            self._reentrancy_count[reentrancy_key] -= 1
            if self._reentrancy_count[reentrancy_key] <= 0:
                del self._reentrancy_count[reentrancy_key]
        self._task_slot.pop(task_key, None)

    @asynccontextmanager
    @traced
    async def acquire(self, server_ip: str, timeout: int | None = None) -> AsyncGenerator[None]:
        """Acquire lock for server operations (reentrant per task).

        Args:
            server_ip: The slot key — the MDS member hosting the target (LoginCoordinator.mds_host).
            timeout: Maximum time to wait for lock acquisition in seconds.
                Defaults to the slot_timeout this RateLimiter was constructed
                with (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT).

        Yields:
            None when lock is acquired.

        Raises:
            LockAcquisitionError: If lock cannot be acquired within timeout.
        """
        if timeout is None:
            timeout = self._slot_timeout
        span_attrs(server_ip=server_ip)

        task_id = self._current_task_id()

        # Reentrant: this task already holds a slot for this server. Follow the
        # slot it actually holds, which may differ from its hashed slot.
        task_key = f"{server_ip}:{task_id}"
        held_key = self._task_slot.get(task_key)
        if held_key is not None and self._reentrancy_count.get(f"{held_key}:{task_id}", 0) > 0:
            reentrancy_key = f"{held_key}:{task_id}"
            self._reentrancy_count[reentrancy_key] += 1
            span_attrs(reentrant=True, slot=held_key.rsplit("_", 1)[-1])
            log().trace(
                f"RateLimiter REENTRANT for {server_ip} ({held_key}, count={self._reentrancy_count[reentrancy_key]})"
            )
            try:
                yield
            finally:
                self._reentrancy_count[reentrancy_key] -= 1
                if self._reentrancy_count[reentrancy_key] == 0:
                    del self._reentrancy_count[reentrancy_key]
                log().trace(
                    f"RateLimiter RELEASED (reentrant) for {server_ip} (count={self._reentrancy_count.get(reentrancy_key, 0)})"
                )
            return

        # The limiter is a semaphore over `concurrent_limit` slots, not a set of
        # pinned locks: start at the hashed slot (spreads load), but take ANY free
        # slot. Pinning to one slot starved callers for the full timeout while other
        # slots sat idle (seen as 90 s login stalls behind keepalives). Waiters are
        # served in arrival order (_take_in_turn), so a caller that releases after a
        # page and asks again does not overtake one that is already waiting.
        lock_manager = await self._get_lock_manager()
        ttl = lock_manager.DEFAULT_TTL_RATE_LIMIT
        base_slot = self._get_slot_number(server_ip)
        log().trace(f"RateLimiter WAITING for {server_ip} (preferred slot={base_slot})")
        slot, lock_key, in_process, lock = await self._take_in_turn(lock_manager, server_ip, base_slot, ttl, timeout)

        reentrancy_key = f"{lock_key}:{task_id}"
        self._reentrancy_count[reentrancy_key] = 1
        self._task_slot[task_key] = lock_key
        span_attrs(slot=slot)
        log().trace(f"RateLimiter ACQUIRED for {server_ip} (slot={slot})")
        # A request can hold the slot longer than the row's TTL (a publish task, a long
        # single call); keep the row alive so no other process takes the slot.
        renewer = asyncio.create_task(self._keep_slot(lock_manager, lock_key, lock.owner_id, ttl))
        try:
            yield
        finally:
            renewer.cancel()
            # Every step below runs even if this task is cancelled while it waits:
            # a skipped release would leave the slot taken for the life of the process.
            try:
                await asyncio.wait({renewer})
            finally:
                self._drop_reentrancy(reentrancy_key, task_key)
                try:
                    await lock_manager.release_lock(lock_key, lock.owner_id)
                finally:
                    in_process.release()
                    self._wake_head(server_ip)
            log().trace(f"RateLimiter RELEASED for {server_ip} (slot={slot})")


__all__ = ["RateLimiter"]
