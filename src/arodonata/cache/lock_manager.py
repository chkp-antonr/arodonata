"""Database-backed distributed lock manager for cross-process coordination.

This module provides SQL-database-backed distributed locking (works with any
SQLAlchemy-supported dialect, e.g. SQLite or PostgreSQL) to coordinate
operations across multiple gunicorn workers, CLI sessions, or service instances.

Lock acquisition uses INSERT with retry logic and exponential backoff.
Locks automatically expire based on TTL to prevent deadlocks.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import socket
from collections import defaultdict
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import TYPE_CHECKING, Any

from arlogi.otel.decorator import traced
from sqlalchemy import and_, delete, select, update

from ..logger import lazy_logger
from ..telemetry import span_attrs
from .database import DatabaseManager
from .models import DistributedLock

if TYPE_CHECKING:
    pass

# Context variable to track current lock for renewal in decorated functions
_current_lock_context: ContextVar[LockContext | None] = ContextVar("_current_lock_context", default=None)

log = lazy_logger("arodonata.cache.lock_manager")


class LockAcquisitionError(Exception):
    """Raised when lock acquisition fails due to timeout."""

    def __init__(self, lock_key: str, timeout: int) -> None:
        """Initialize lock acquisition error.

        Args:
            lock_key: The lock key that could not be acquired.
            timeout: The timeout period in seconds.
        """
        self.lock_key = lock_key
        self.timeout = timeout
        super().__init__(f"Failed to acquire lock '{lock_key}' within {timeout} seconds")


class LockOwnershipError(Exception):
    """Raised when lock operation fails due to ownership mismatch."""

    def __init__(self, lock_key: str, owner_id: str) -> None:
        """Initialize lock ownership error.

        Args:
            lock_key: The lock key with ownership issue.
            owner_id: The owner ID that doesn't match.
        """
        self.lock_key = lock_key
        self.owner_id = owner_id
        super().__init__(f"Lock '{lock_key}' is not owned by '{owner_id}'")


def generate_owner_id() -> str:
    """Generate unique owner ID for this process/worker.

    Returns:
        Owner ID string in format 'hostname:pid:worker_id'.

    Example:
        'web-server-1:12345:worker-2'
    """
    hostname = socket.gethostname()
    pid = os.getpid()

    # Try to get worker ID from environment (gunicorn, uvicorn, etc.)
    worker_id = os.environ.get("WORKER_ID", os.environ.get("GUNICORN_WORKER_ID", "main"))

    return f"{hostname}:{pid}:{worker_id}"


def _build_acquire_stmt(
    dialect_name: str,
    lock_key: str,
    owner_id: str,
    now: datetime,
    expires_at: datetime,
) -> Any:
    """Build the dialect-specific INSERT ... ON CONFLICT DO UPDATE upsert.

    Inserts a fresh lock row, or - on a primary-key conflict - takes over the
    existing row only if it has already expired (`WHERE expires_at < now`).
    Extracted as a standalone helper (rather than inlined in `_try_acquire`)
    so it can be exercised directly by dialect-compile tests without a live
    database connection.

    Args:
        dialect_name: SQLAlchemy dialect name (`engine.dialect.name`), e.g.
            "postgresql" or "sqlite".
        lock_key: Lock key (primary key of the row).
        owner_id: Owner ID attempting to acquire.
        now: Current naive UTC timestamp.
        expires_at: New expiration timestamp to write on success.

    Returns:
        An `Insert` construct with `.on_conflict_do_update(...)` applied,
        ready to `session.execute(...)`.

    Raises:
        NotImplementedError: If `dialect_name` is neither "postgresql" nor
            "sqlite".
    """
    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    elif dialect_name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as dialect_insert  # type: ignore[assignment]
    else:
        raise NotImplementedError(f"Unsupported dialect for lock manager: {dialect_name}")

    table = DistributedLock.__table__  # type: ignore[attr-defined]
    return (
        dialect_insert(table)
        .values(
            lock_key=lock_key,
            owner_id=owner_id,
            acquired_at=now,
            expires_at=expires_at,
            metadata=None,
        )
        .on_conflict_do_update(
            index_elements=[table.c.lock_key],
            set_={
                "owner_id": owner_id,
                "acquired_at": now,
                "expires_at": expires_at,
                "metadata": None,
            },
            where=(table.c.expires_at < now),
        )
    )


class LockContext:
    """Context for an acquired lock, supporting renewal.

    This class is returned by the acquire() context manager and provides
    methods for lock renewal and metadata access.
    """

    def __init__(
        self,
        lock_key: str,
        owner_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        ttl: int,
        manager: DatabaseLockManager,
    ) -> None:
        """Initialize lock context.

        Args:
            lock_key: The lock key.
            owner_id: The owner ID.
            acquired_at: When the lock was acquired.
            expires_at: When the lock expires.
            ttl: The lock TTL in seconds.
            manager: The DatabaseLockManager instance.
        """
        self.lock_key = lock_key
        self.owner_id = owner_id
        self.acquired_at = acquired_at
        self.expires_at = expires_at
        self.ttl = ttl
        self._manager = manager

    async def renew(self, ttl: int | None = None) -> bool:
        """Renew the lock with a new TTL.

        Args:
            ttl: New TTL in seconds. If None, uses original TTL.

        Returns:
            True if renewed successfully, False if lock lost/expired.

        Raises:
            LockOwnershipError: If lock is not owned by current owner.
        """
        return await self._manager.renew_lock(self.lock_key, self.owner_id, ttl or self.ttl)

    async def renew_if_needed(self, threshold: float = 0.5) -> bool:
        """Renew lock only if more than threshold of TTL has elapsed.

        Args:
            threshold: Fraction of TTL that must elapse before renewal (default 0.5 = 50%).

        Returns:
            True if renewed, False if renewal not needed yet or failed.

        Raises:
            LockOwnershipError: If lock is not owned by current owner.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        elapsed = (now - self.acquired_at).total_seconds()
        ttl_seconds = self.ttl

        # Only renew if more than threshold of TTL has elapsed
        if elapsed > (ttl_seconds * threshold):
            return await self.renew()

        return False

    def __repr__(self) -> str:
        """String representation."""
        return f"LockContext(key='{self.lock_key}', owner='{self.owner_id}', expires_at={self.expires_at})"


class DatabaseLockManager:
    """SQL-database-backed distributed lock manager.

    Provides distributed locking across multiple processes using the
    consumer's configured SQL database (any SQLAlchemy-supported dialect,
    e.g. SQLite or PostgreSQL) as the coordination backend. Locks
    automatically expire to prevent deadlocks.

    Example:
        manager = DatabaseLockManager()
        await manager.initialize()

        # Context manager usage
        async with await manager.acquire("my_lock", timeout=30, ttl=60) as lock:
            # Critical section
            pass

        # Manual usage
        lock = await manager.acquire_lock("my_lock", timeout=30, ttl=60)
        try:
            # Critical section
            pass
        finally:
            await manager.release_lock("my_lock", lock.owner_id)
    """

    # Default TTL values for different lock types
    DEFAULT_TTL_LOGIN = 90  # 90 seconds for login (with throttling/retries)
    DEFAULT_TTL_RATE_LIMIT = 300  # 5 minutes for rate limiting
    DEFAULT_TTL_ASSET_REFRESH = 300  # 5 minutes for asset refresh (with renewal)

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize lock manager.

        Args:
            db_manager: DatabaseManager instance.
        """
        self._db_manager = db_manager
        self._owner_id = generate_owner_id()
        # Per-lock-key in-process locks (optimization to avoid redundant DB
        # round-trips when this process races itself on the SAME key) - must
        # be keyed by lock_key, not a single shared lock, or acquiring one
        # key blocks every other key in this process for the full
        # retry-until-timeout loop below.
        self._in_process_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        log().debug(f"DatabaseLockManager initialized with owner_id='{self._owner_id}'")

    async def initialize(self) -> None:
        """Initialize database connection.

        This method is idempotent - calling it multiple times is safe.
        """
        await self._db_manager.initialize()

    async def close(self) -> None:
        """Close database connection."""
        # No-op here as DatabaseManager is shared and managed elsewhere,
        # but kept for API consistency if we ever need local cleanup.
        pass

    @asynccontextmanager
    async def acquire(
        self,
        lock_key: str,
        timeout: int = 30,
        ttl: int | None = None,
    ) -> AsyncGenerator[LockContext]:
        """Acquire lock as async context manager.

        Args:
            lock_key: Unique lock identifier.
            timeout: Maximum time to wait for lock acquisition in seconds.
            ttl: Lock time-to-live in seconds. If None, uses default (300s).

        Yields:
            LockContext: Lock context with renewal methods.

        Raises:
            LockAcquisitionError: If lock cannot be acquired within timeout.
        """
        if ttl is None:
            ttl = self.DEFAULT_TTL_ASSET_REFRESH

        log().trace(f"Acquiring lock '{lock_key}' (timeout={timeout}s, ttl={ttl}s)")
        lock = await self.acquire_lock(lock_key, timeout, ttl)
        log().trace(f"Lock acquired '{lock_key}' (owner={lock.owner_id})")
        try:
            yield lock
        finally:
            await self.release_lock(lock_key, lock.owner_id)
            log().trace(f"Lock released '{lock_key}'")

    @traced
    async def acquire_lock(
        self,
        lock_key: str,
        timeout: int = 30,
        ttl: int = 300,
    ) -> LockContext:
        """Acquire a lock with retry logic and exponential backoff.

        Args:
            lock_key: Unique lock identifier.
            timeout: Maximum time to wait for lock acquisition in seconds.
            ttl: Lock time-to-live in seconds.

        Returns:
            LockContext with lock details.

        Raises:
            LockAcquisitionError: If lock cannot be acquired within timeout.
        """
        # In-process lock first (optimization), scoped to this lock_key only
        # so contention on one key never blocks acquisition of another.
        async with self._in_process_locks[lock_key]:
            now_ts = datetime.now(UTC).replace(tzinfo=None).timestamp()
            deadline = now_ts + timeout
            attempt = 0
            max_backoff = 2.0  # Maximum backoff in seconds

            span_attrs(
                **{
                    "lock.key": lock_key,
                    "lock.timeout": timeout,
                    "lock.ttl": ttl,
                    "lock.owner_id": self._owner_id,
                }
            )

            while True:
                now = datetime.now(UTC).replace(tzinfo=None)

                # Check timeout
                if now.timestamp() >= deadline:
                    span_attrs(
                        **{
                            "lock.attempts": attempt,
                            "lock.wait_seconds": round(now.timestamp() - now_ts, 3),
                        }
                    )
                    raise LockAcquisitionError(lock_key, timeout)

                # Try to acquire lock (atomic upsert: inserts, or steals an
                # expired row; None means a live owner holds it)
                lock = await self._try_acquire(lock_key, ttl)
                if lock is not None:
                    log().trace(f"Acquired lock '{lock_key}' (owner='{self._owner_id}', ttl={ttl}s)")
                    span_attrs(
                        **{
                            "lock.attempts": attempt,
                            "lock.wait_seconds": round(datetime.now(UTC).replace(tzinfo=None).timestamp() - now_ts, 3),
                        }
                    )
                    return lock

                log().trace(f"Lock '{lock_key}' held by another owner (attempt {attempt + 1})")

                # Calculate backoff time (exponential)
                backoff = min(2**attempt * 0.1, max_backoff)  # Start at 0.1s
                attempt += 1

                # Sleep before retry
                log().trace(f"Retry {attempt} for lock '{lock_key}' after {backoff}s backoff")
                await asyncio.sleep(backoff)

    async def _try_acquire(self, lock_key: str, ttl: int) -> LockContext | None:
        """Attempt to acquire the lock with one atomic upsert.

        INSERT the lock row; on conflict, take over the row only if it has
        expired. Returns None when the lock is held by a live owner.

        Args:
            lock_key: Lock key.
            ttl: Time-to-live in seconds.

        Returns:
            LockContext if acquired (fresh insert or stolen expired row),
            None if a live owner currently holds the lock.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        expires_at = now + timedelta(seconds=ttl)
        dialect = self._db_manager.engine.dialect.name
        stmt = _build_acquire_stmt(dialect, lock_key, self._owner_id, now, expires_at)

        async with self._db_manager.session() as session:
            result = await session.execute(stmt)
            rowcount = getattr(result, "rowcount", 0)
            if rowcount is None:
                rowcount = 0

            if rowcount < 0:
                # Some DBAPI drivers report -1 ("unknown row count") for
                # RETURNING-less DML instead of a real count. Do NOT treat
                # that as failure - a false "held by someone else" here would
                # make every retry fail the upsert's `WHERE expires_at < now`
                # against the row we ourselves just wrote, deadlocking this
                # owner out until the TTL expires. Verify directly instead.
                verify_stmt = select(DistributedLock).where(
                    and_(
                        DistributedLock.lock_key == lock_key,  # type: ignore
                        DistributedLock.owner_id == self._owner_id,  # type: ignore
                        DistributedLock.expires_at == expires_at,  # type: ignore
                    )
                )
                won = (await session.execute(verify_stmt)).scalar_one_or_none() is not None
                await session.commit()
                if not won:
                    return None
            else:
                await session.commit()
                if rowcount < 1:
                    return None

        return LockContext(
            lock_key=lock_key,
            owner_id=self._owner_id,
            acquired_at=now,
            expires_at=expires_at,
            ttl=ttl,
            manager=self,
        )

    @traced
    async def release_lock(self, lock_key: str, owner_id: str) -> None:
        """Release a lock with one conditional DELETE.

        Idempotent when the lock is already gone. Raises LockOwnershipError
        when the lock exists but belongs to another owner (rare path — only
        then is a second query issued).
        """
        span_attrs(**{"lock.key": lock_key, "lock.owner_id": owner_id})
        async with self._db_manager.session() as session:
            delete_stmt = delete(DistributedLock).where(
                and_(
                    DistributedLock.lock_key == lock_key,  # type: ignore
                    DistributedLock.owner_id == owner_id,  # type: ignore
                )
            )
            result = await session.execute(delete_stmt)
            await session.commit()
            if (getattr(result, "rowcount", 0) or 0) >= 1:
                log().trace(f"Released lock '{lock_key}' (owner='{owner_id}')")
                return

            # Rare path: nothing *confirmed* deleted — could be already
            # released, owned by another owner, or a driver reporting
            # rowcount=-1 ("unknown") on a DELETE that actually succeeded
            # (mirrors the quirk `_try_acquire` hardens against). Verify via
            # SELECT before concluding failure.
            stmt = select(DistributedLock).where(DistributedLock.lock_key == lock_key)  # type: ignore
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing is None:
                log().debug(f"Lock '{lock_key}' not found (already released or expired)")
                return
            if existing.owner_id != owner_id:
                raise LockOwnershipError(lock_key, owner_id)

            # We own it — rowcount was merely ambiguous, not a real failure.
            # Re-run the conditional delete to guarantee the row is gone.
            await session.execute(delete_stmt)
            await session.commit()
            log().trace(f"Released lock '{lock_key}' (owner='{owner_id}')")

    async def is_lock_held(self, lock_key: str, owner_id: str) -> bool:
        """Check if a lock is currently held by a specific owner.

        Args:
            lock_key: Lock key to check.
            owner_id: Owner ID to check.

        Returns:
            True if the lock exists and is held by the owner and not expired.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        async with self._db_manager.session() as session:
            stmt = select(DistributedLock).where(
                and_(
                    DistributedLock.lock_key == lock_key,  # type: ignore
                    DistributedLock.owner_id == owner_id,  # type: ignore
                    DistributedLock.expires_at > now,  # type: ignore
                )
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

    @traced
    async def renew_lock(
        self,
        lock_key: str,
        owner_id: str,
        ttl: int | None = None,
    ) -> bool:
        """Renew a lock with one conditional UPDATE.

        Returns False when the lock is gone; raises LockOwnershipError when
        it exists under another owner (rare path — only then a second query).
        """
        span_attrs(**{"lock.key": lock_key, "lock.owner_id": owner_id})
        if ttl is None:
            ttl = self.DEFAULT_TTL_ASSET_REFRESH

        now = datetime.now(UTC).replace(tzinfo=None)
        new_expires_at = now + timedelta(seconds=ttl)

        async with self._db_manager.session() as session:
            update_stmt = (
                update(DistributedLock)
                .where(
                    and_(
                        DistributedLock.lock_key == lock_key,  # type: ignore
                        DistributedLock.owner_id == owner_id,  # type: ignore
                    )
                )
                .values(expires_at=new_expires_at)
            )
            result = await session.execute(update_stmt)
            await session.commit()
            if (getattr(result, "rowcount", 0) or 0) >= 1:
                log().debug(f"Renewed lock '{lock_key}' (owner='{owner_id}', ttl={ttl}s)")
                return True

            # Rare path: nothing *confirmed* updated — could be gone, owned
            # by another owner, or a driver reporting rowcount=-1
            # ("unknown") on an UPDATE that actually succeeded (mirrors the
            # quirk `_try_acquire` hardens against). Verify via SELECT before
            # concluding failure.
            stmt = select(DistributedLock).where(DistributedLock.lock_key == lock_key)  # type: ignore
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing is None:
                log().warning(f"Cannot renew lock '{lock_key}' - not found (expired or released)")
                return False
            if existing.owner_id != owner_id:
                raise LockOwnershipError(lock_key, owner_id)

            # We own it — the UPDATE's WHERE (lock_key AND owner_id) already
            # matched this row, so the write applied even though rowcount
            # didn't confirm it. Rowcount was merely ambiguous.
            log().debug(f"Renewed lock '{lock_key}' (owner='{owner_id}', ttl={ttl}s)")
            return True


def get_current_lock_context() -> LockContext | None:
    """Get the current lock context from context variable.

    Returns:
        Current LockContext if in a decorated function, None otherwise.

    Example:
        @distributed_lock("my_key")
        async def my_function():
            ctx = get_current_lock_context()
            if ctx:
                await ctx.renew_if_needed()
    """
    return _current_lock_context.get(None)


# Global lock manager instance (lazy initialized)
_global_lock_manager: DatabaseLockManager | None = None
_global_lock_manager_lock = asyncio.Lock()


async def _get_global_lock_manager(db_manager: DatabaseManager | None = None) -> DatabaseLockManager:
    """Get or create global lock manager instance.

    Args:
        db_manager: DatabaseManager to use if creating a new instance.
                   Required if the global instance doesn't exist yet.

    Returns:
        Global DatabaseLockManager instance.

    Raises:
        RuntimeError: If db_manager not provided and instance doesn't exist.
    """
    global _global_lock_manager
    if _global_lock_manager is None:
        async with _global_lock_manager_lock:
            if _global_lock_manager is None:
                if db_manager is None:
                    raise RuntimeError("DatabaseLockManager must be initialized before use")
                _global_lock_manager = DatabaseLockManager(db_manager=db_manager)
    if _global_lock_manager is None:
        raise RuntimeError("Failed to initialize DatabaseLockManager")

    return _global_lock_manager


def set_global_lock_manager(lock_manager: DatabaseLockManager | None) -> None:
    """Set the global lock manager instance.

    This allows sharing a DatabaseLockManager across the application,
    for example, using the same DatabaseManager as the ArodonataClient.

    Args:
        lock_manager: The lock manager to use as the global instance, or None to reset.

    Example:
        # In your application setup
        db_manager = DatabaseManager()
        lock_manager = DatabaseLockManager(db_manager)
        set_global_lock_manager(lock_manager)

        # Now all @distributed_lock decorated functions will use this instance

        # To reset (useful in tests):
        set_global_lock_manager(None)
    """
    global _global_lock_manager
    _global_lock_manager = lock_manager


def distributed_lock(  # noqa: C901
    lock_key_template: str,
    timeout: int = 30,
    ttl: int | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for async function-level distributed locking.

    The lock_key_template can contain parameter placeholders in {braces}.
    For example, "asset_refresh:{mgmt_names}" will substitute the mgmt_names
    parameter value.

    Args:
        lock_key_template: Lock key template, can use {param} placeholders.
        timeout: Maximum time to wait for lock acquisition in seconds.
        ttl: Lock time-to-live in seconds. If None, uses default (300s).

    Returns:
        Decorator function.

    Example:
        @distributed_lock("asset_refresh:{mgmt_names}", timeout=300, ttl=300)
        async def build_refresh_assets_cache(self, mgmt_names: str, domains: str):
            # Function is automatically locked
            # Can access lock context for manual renewal:
            ctx = get_current_lock_context()
            if ctx:
                await ctx.renew_if_needed()
    """

    def _format_lock_key(func: Callable[..., Any], args: Any, kwargs: Any) -> str:
        """Format lock key from template using function parameters."""
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()
        try:
            return lock_key_template.format(**bound_args.arguments)
        except KeyError as e:
            raise ValueError(
                f"Lock key template '{lock_key_template}' references "
                f"parameter '{e.args[0]}' which doesn't exist in function signature"
            ) from None

    async def _acquire_lock(
        func: Callable[..., Any], args: Any, kwargs: Any
    ) -> tuple[DatabaseLockManager, str, LockContext]:
        """Acquire distributed lock for the function call."""
        lock_key = _format_lock_key(func, args, kwargs)
        manager = await _get_global_lock_manager()
        await manager.initialize()
        lock_ttl = ttl if ttl is not None else manager.DEFAULT_TTL_ASSET_REFRESH
        lock = await manager.acquire_lock(lock_key, timeout, lock_ttl)
        return manager, lock_key, lock

    async def _release_lock_safely(manager: DatabaseLockManager, lock_key: str, owner_id: str) -> None:
        """Release a lock, logging (instead of raising) if release fails.

        A failure here must not mask whatever the caller itself raised or
        returned, but it also must not be silently discarded — log it so a
        stuck lock (which will block this key until its TTL expires) is
        diagnosable.
        """
        try:
            await manager.release_lock(lock_key, owner_id)
        except Exception as e:
            log().warning(f"Failed to release lock '{lock_key}' during cleanup: {e}")

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Acquire lock
            manager, lock_key, lock = await _acquire_lock(func, args, kwargs)

            # Set lock context for access in decorated function
            token = _current_lock_context.set(lock)

            try:
                return await func(*args, **kwargs)
            finally:
                _current_lock_context.reset(token)

                # Release lock. Unlike async_generator_wrapper below, this is
                # NOT wrapped in _release_lock_safely: a plain function call
                # has no generator lifecycle to protect, so a release failure
                # here should propagate to the caller rather than be swallowed.
                await manager.release_lock(lock_key, lock.owner_id)

        @wraps(func)
        async def async_generator_wrapper(*args: Any, **kwargs: Any) -> AsyncGenerator[Any]:
            """Wrapper for async generator functions with distributed locking.

            The lock is held for the entire duration of the generator's lifecycle,
            from creation until exhaustion or close.
            """
            # Acquire lock
            manager, lock_key, lock = await _acquire_lock(func, args, kwargs)

            # Set lock context for access in decorated function
            token = _current_lock_context.set(lock)

            try:
                # Create the generator and yield from it
                async for item in func(*args, **kwargs):
                    yield item
            except (KeyboardInterrupt, asyncio.CancelledError):
                # Propagate cancellation signals but ensure cleanup runs
                raise
            finally:
                # Clear lock context
                _current_lock_context.reset(token)

                # Release lock. Unlike wrapper above, a failure here is
                # logged rather than raised (see _release_lock_safely) — the
                # generator's own result must not be masked by a cleanup error.
                await _release_lock_safely(manager, lock_key, lock.owner_id)

        # Check if function is an async generator
        if inspect.isasyncgenfunction(func):
            return async_generator_wrapper
        else:
            return wrapper

    return decorator


__all__ = [
    "DatabaseLockManager",
    "LockContext",
    "LockAcquisitionError",
    "LockOwnershipError",
    "generate_owner_id",
    "get_current_lock_context",
    "distributed_lock",
]
