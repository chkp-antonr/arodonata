"""Rate limiter for per-server concurrent API request limiting.

Manages distributed locks to limit concurrent operations per server IP,
preventing overload of management servers across multiple workers.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from contextvars import ContextVar

from arlogi.otel.decorator import traced

from ..cache.lock_manager import DatabaseLockManager, LockAcquisitionError, LockContext
from ..config.constants import DEFAULT_RATE_LIMIT_SLOT_TIMEOUT
from ..logger import lazy_logger
from ..telemetry import span_attrs

log = lazy_logger("arodonata.asdk.rate_limiter")

_caller_id_var: ContextVar[int | None] = ContextVar("_caller_id_var", default=None)
_caller_id_counter = itertools.count(1)


class RateLimiter:
    """Per-server distributed lock for concurrent API operation limiting.

    Uses SQL-database-backed distributed locks (any SQLAlchemy-supported
    dialect) to enforce concurrent operation limits across multiple
    workers/processes.

    Lock keys use a slot-based approach: ratelimit:{server_ip}:slot_{n}
    where n is determined by hashing the operation ID to distribute load.

    Example:
        limiter = RateLimiter(concurrent_limit=3)
        async with limiter.acquire("192.168.1.10"):
            # Make API call - limited to 3 concurrent per server across all workers
            pass
    """

    def __init__(
        self,
        concurrent_limit: int = 3,
        lock_manager: DatabaseLockManager | None = None,
        slot_timeout: int = DEFAULT_RATE_LIMIT_SLOT_TIMEOUT,
    ) -> None:
        """Initialize rate limiter.

        Args:
            concurrent_limit: Maximum concurrent operations per server.
            lock_manager: Optional DatabaseLockManager instance.
            slot_timeout: Default seconds acquire() waits for a free slot before
                giving up (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT for why this must
                comfortably exceed a single login retry-with-backoff sequence).
        """
        self._concurrent_limit = concurrent_limit
        self._lock_manager = lock_manager
        self._slot_timeout = slot_timeout
        self._in_process_locks: dict[str, asyncio.Lock] = {}  # For in-process synchronization
        self._reentrancy_count: dict[str, int] = {}  # Track reentrant locks per task, keyed by held slot
        self._task_slot: dict[str, str] = {}  # (server_ip, task) -> lock_key of the slot actually held
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
            server_ip: Server IP address.
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
        # slot. A caller only waits when every slot is busy, and only up to
        # `timeout`. Pinning to one slot starved callers for the full timeout
        # while other slots sat idle (seen as 90 s login stalls behind keepalives).
        lock_manager = await self._get_lock_manager()
        ttl = lock_manager.DEFAULT_TTL_RATE_LIMIT
        base_slot = self._get_slot_number(server_ip)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        attempt = 0
        log().trace(f"RateLimiter WAITING for {server_ip} (preferred slot={base_slot})")

        while True:
            for offset in range(self._concurrent_limit):
                slot = (base_slot + offset) % self._concurrent_limit
                lock_key = f"ratelimit:{server_ip}:slot_{slot}"

                taken = await self._try_take_slot(lock_manager, lock_key, ttl)
                if taken is None:
                    continue
                in_process, lock = taken

                reentrancy_key = f"{lock_key}:{task_id}"
                self._reentrancy_count[reentrancy_key] = 1
                self._task_slot[task_key] = lock_key
                span_attrs(slot=slot, attempts=attempt)
                log().trace(f"RateLimiter ACQUIRED for {server_ip} (slot={slot})")
                try:
                    yield
                finally:
                    self._drop_reentrancy(reentrancy_key, task_key)
                    try:
                        await lock_manager.release_lock(lock_key, lock.owner_id)
                    finally:
                        in_process.release()
                    log().trace(f"RateLimiter RELEASED for {server_ip} (slot={slot})")
                return

            # Every slot busy: give up at the deadline, otherwise back off and re-sweep.
            if loop.time() >= deadline:
                span_attrs(attempts=attempt)
                raise LockAcquisitionError(f"ratelimit:{server_ip}:slot_*", timeout)
            backoff = min(2**attempt * 0.1, 2.0)
            attempt += 1
            log().trace(f"RateLimiter all {self._concurrent_limit} slots busy for {server_ip}; retry in {backoff}s")
            await asyncio.sleep(min(backoff, max(deadline - loop.time(), 0)))


__all__ = ["RateLimiter"]
