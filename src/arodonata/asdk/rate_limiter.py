"""Rate limiter for per-server concurrent API request limiting.

Manages distributed locks to limit concurrent operations per server IP,
preventing overload of management servers across multiple workers.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from arlogi.otel.decorator import traced

from ..cache.lock_manager import DatabaseLockManager
from ..logger import lazy_logger
from ..telemetry import span_attrs

log = lazy_logger("arodonata.asdk.rate_limiter")


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

    def __init__(self, concurrent_limit: int = 3, lock_manager: DatabaseLockManager | None = None) -> None:
        """Initialize rate limiter.

        Args:
            concurrent_limit: Maximum concurrent operations per server.
            lock_manager: Optional DatabaseLockManager instance.
        """
        self._concurrent_limit = concurrent_limit
        self._lock_manager = lock_manager
        self._in_process_locks: dict[str, asyncio.Lock] = {}  # For in-process synchronization
        self._reentrancy_count: dict[str, int] = {}  # Track reentrant locks per task
        self._lock_init_lock = asyncio.Lock()  # Protection for lock manager initialization
        self._closed = False
        log().debug(f"RateLimiter initialized with limit={concurrent_limit}")

    async def close(self) -> None:
        """Clean up resources."""
        if not self._closed:
            self._closed = True
            if self._lock_manager:
                await self._lock_manager.close()
            self._in_process_locks.clear()
            self._reentrancy_count.clear()
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
        try:
            current_task = asyncio.current_task()
            task_id = id(current_task) if current_task else 0
        except RuntimeError:
            task_id = 0

        hash_input = f"{server_ip}:{task_id}".encode()
        hash_value = int(hashlib.sha256(hash_input).hexdigest(), 16)
        return hash_value % self._concurrent_limit

    @asynccontextmanager
    @traced
    async def acquire(self, server_ip: str, timeout: int = 30) -> AsyncGenerator[None]:
        """Acquire lock for server operations (reentrant per task).

        Args:
            server_ip: Server IP address.
            timeout: Maximum time to wait for lock acquisition in seconds.

        Yields:
            None when lock is acquired.

        Raises:
            LockAcquisitionError: If lock cannot be acquired within timeout.
        """
        slot = self._get_slot_number(server_ip)
        lock_key = f"ratelimit:{server_ip}:slot_{slot}"
        span_attrs(server_ip=server_ip, slot=slot)

        # Get current task ID for reentrancy tracking
        try:
            current_task = asyncio.current_task()
            task_id = id(current_task) if current_task else 0
        except RuntimeError:
            task_id = 0

        reentrancy_key = f"{lock_key}:{task_id}"

        # Check if this task already holds the lock (reentrant)
        if self._reentrancy_count.get(reentrancy_key, 0) > 0:
            # Already held by this task - just increment counter
            self._reentrancy_count[reentrancy_key] += 1
            span_attrs(reentrant=True)
            log().trace(
                f"RateLimiter REENTRANT for {server_ip} (slot={slot}, count={self._reentrancy_count[reentrancy_key]})"
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

        # In-process lock for optimization
        if lock_key not in self._in_process_locks:
            self._in_process_locks[lock_key] = asyncio.Lock()

        async with self._in_process_locks[lock_key]:
            lock_manager = await self._get_lock_manager()

            log().trace(f"RateLimiter WAITING for {server_ip} (slot={slot})")

            # Acquire distributed lock
            async with lock_manager.acquire(
                lock_key,
                timeout=timeout,
                ttl=lock_manager.DEFAULT_TTL_RATE_LIMIT,
            ):
                try:
                    # Initialize reentrancy counter inside try to ensure cleanup
                    self._reentrancy_count[reentrancy_key] = 1
                    log().trace(f"RateLimiter ACQUIRED for {server_ip} (slot={slot})")
                    yield
                finally:
                    # Defensive skip if it was never set (though unlikely)
                    if reentrancy_key in self._reentrancy_count:
                        self._reentrancy_count[reentrancy_key] -= 1
                        if self._reentrancy_count[reentrancy_key] <= 0:
                            del self._reentrancy_count[reentrancy_key]
                    log().trace(f"RateLimiter RELEASED for {server_ip}")


__all__ = ["RateLimiter"]
