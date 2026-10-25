"""Database-backed distributed lock adapter (`SqlLockAdapter` / `DatabaseLockManager`)."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from arodonata.adapters.storage.database import DatabaseManager
from arodonata.adapters.storage.tables import DistributedLockRecord, _ensure_utc
from arodonata.core.errors import LockAcquisitionError
from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.telemetry import span_attrs, traced

_MAX_TRANSIENT_RETRIES = 3


def _is_transient_db_error(exc: BaseException) -> bool:
    """Return `True` if `exc` is a transient database lock/serialization/deadlock error (`I6`)."""
    if isinstance(exc, IntegrityError):
        return False
    if not isinstance(exc, (OperationalError, DBAPIError)):
        return False
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "database is locked",
            "database table is locked",
            "deadlock",
            "could not serialize",
            "serialization failure",
            "lock timeout",
        )
    )


class SqlLockAdapter:
    """Coordinates cross-process locks via the `arodonata_distributed_locks` table with DB-time expiration."""

    def __init__(
        self,
        db: DatabaseManager,
        *,
        default_owner_id: str | None = None,
        db_now_fn: Callable[[AsyncSession], Any] | None = None,
    ) -> None:
        self._db = db
        self._default_owner_id = default_owner_id or f"worker-{uuid.uuid4().hex[:12]}"
        self._db_now_fn = db_now_fn

    @property
    def default_owner_id(self) -> str:
        """Default lock owner identifier for this adapter instance."""
        return self._default_owner_id

    async def _get_db_utc_now(self, session: AsyncSession) -> datetime:
        """Fetch the database server's current UTC timestamp as naive UTC (`W16`)."""
        if self._db_now_fn is not None:
            custom_val = await self._db_now_fn(session)
            return to_naive_utc(custom_val) or utc_now()

        dialect = self._db.engine.dialect.name
        if dialect == "postgresql":
            raw = (await session.execute(text("SELECT timezone('UTC', clock_timestamp())"))).scalar_one()
            if isinstance(raw, datetime):
                return to_naive_utc(raw) or utc_now()
        elif dialect == "sqlite":
            raw_str = (await session.execute(text("SELECT strftime('%Y-%m-%dT%H:%M:%f', 'now')"))).scalar_one()
            if isinstance(raw_str, str):
                return datetime.fromisoformat(raw_str)
        return utc_now()

    async def _try_acquire_once(
        self,
        lock_key: str,
        *,
        ttl_seconds: float,
        owner_id: str,
    ) -> bool:
        """Attempt a single atomic lock acquisition or expired-lock reclamation (`W16`, `I6`)."""
        for attempt in range(_MAX_TRANSIENT_RETRIES):
            async with self._db.session() as session:
                try:
                    now = await self._get_db_utc_now(session)
                    expires_at = now + timedelta(seconds=max(0.1, float(ttl_seconds)))

                    # 1. Reclaim expired lock ONLY (active locks must be extended via renew(), not re-acquired)
                    await session.execute(
                        delete(DistributedLockRecord).where(
                            DistributedLockRecord.lock_key == lock_key,  # type: ignore[arg-type]
                            DistributedLockRecord.expires_at <= now,  # type: ignore[arg-type]
                        )
                    )

                    # 2. Check if an active lock still exists
                    existing_stmt = select(DistributedLockRecord).where(
                        DistributedLockRecord.lock_key == lock_key  # type: ignore[arg-type]
                    )
                    existing_row = (await session.execute(existing_stmt)).scalar_one_or_none()
                    if existing_row is not None:
                        row_expires = _ensure_utc(existing_row.expires_at)
                        if row_expires is not None and row_expires <= now:
                            await session.delete(existing_row)
                        else:
                            await session.rollback()
                            return False

                    # 3. Insert the new lock row
                    record = DistributedLockRecord(
                        lock_key=lock_key,
                        owner_id=owner_id,
                        acquired_at=now,
                        expires_at=expires_at,
                    )
                    session.add(record)
                    await session.commit()
                    return True
                except IntegrityError:
                    await session.rollback()
                    return False
                except (OperationalError, DBAPIError) as exc:
                    await session.rollback()
                    if _is_transient_db_error(exc) and attempt + 1 < _MAX_TRANSIENT_RETRIES:
                        await asyncio.sleep(0.02 * (attempt + 1))
                        continue
                    return False
        return False

    @traced
    async def acquire(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
        wait_timeout: float | None = None,
        poll_interval: float = 0.05,
    ) -> bool:
        """Acquire `lock_key`, reclaiming expired rows and optionally waiting up to `wait_timeout`."""
        resolved_owner = owner_id or self._default_owner_id
        span_attrs(lock_key=lock_key, lock_owner=resolved_owner, ttl_seconds=ttl_seconds)

        deadline = (time.monotonic() + wait_timeout) if (wait_timeout is not None and wait_timeout > 0) else None
        while True:
            acquired = await self._try_acquire_once(
                lock_key,
                ttl_seconds=ttl_seconds,
                owner_id=resolved_owner,
            )
            if acquired:
                span_attrs(lock_acquired=True)
                return True
            if deadline is None or time.monotonic() >= deadline:
                span_attrs(lock_acquired=False)
                return False
            remaining = max(0.001, deadline - time.monotonic())
            await asyncio.sleep(min(poll_interval, remaining))

    @traced
    async def renew(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
    ) -> bool:
        """Extend `expires_at` for an active (unexpired) lock held by `owner_id` (`W13`, `W16`, `I6`)."""
        resolved_owner = owner_id or self._default_owner_id
        span_attrs(lock_key=lock_key, lock_owner=resolved_owner, ttl_seconds=ttl_seconds)

        for attempt in range(_MAX_TRANSIENT_RETRIES):
            async with self._db.session() as session:
                try:
                    now = await self._get_db_utc_now(session)
                    expires_at = now + timedelta(seconds=max(0.1, float(ttl_seconds)))
                    stmt = (
                        update(DistributedLockRecord)
                        .where(
                            DistributedLockRecord.lock_key == lock_key,  # type: ignore[arg-type]
                            DistributedLockRecord.owner_id == resolved_owner,  # type: ignore[arg-type]
                            DistributedLockRecord.expires_at > now,  # type: ignore[arg-type]
                        )
                        .values(expires_at=expires_at)
                    )
                    result = await session.execute(stmt)
                    await session.commit()
                    renewed = bool(result.rowcount and result.rowcount > 0)  # type: ignore[attr-defined]
                    span_attrs(lock_renewed=renewed)
                    return renewed
                except (OperationalError, DBAPIError) as exc:
                    await session.rollback()
                    if _is_transient_db_error(exc) and attempt + 1 < _MAX_TRANSIENT_RETRIES:
                        await asyncio.sleep(0.02 * (attempt + 1))
                        continue
                    return False
        return False

    @traced
    async def release(
        self,
        lock_key: str,
        *,
        owner_id: str | None = None,
    ) -> bool:
        """Release `lock_key` ONLY when owned by `owner_id` (defaults to `default_owner_id`) (`I6`)."""
        resolved_owner = owner_id if owner_id is not None else self._default_owner_id
        if not resolved_owner:
            return False
        span_attrs(lock_key=lock_key, lock_owner=resolved_owner)
        for attempt in range(_MAX_TRANSIENT_RETRIES):
            async with self._db.session() as session:
                try:
                    stmt = delete(DistributedLockRecord).where(
                        DistributedLockRecord.lock_key == lock_key,  # type: ignore[arg-type]
                        DistributedLockRecord.owner_id == resolved_owner,  # type: ignore[arg-type]
                    )
                    result = await session.execute(stmt)
                    await session.commit()
                    released = bool(result.rowcount and result.rowcount > 0)  # type: ignore[attr-defined]
                    span_attrs(lock_released=released)
                    return released
                except (OperationalError, DBAPIError) as exc:
                    await session.rollback()
                    if _is_transient_db_error(exc) and attempt + 1 < _MAX_TRANSIENT_RETRIES:
                        await asyncio.sleep(0.02 * (attempt + 1))
                        continue
                    return False
        return False

    @asynccontextmanager
    async def lock(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
        wait_timeout: float | None = None,
        poll_interval: float = 0.05,
    ) -> AsyncIterator[str]:
        """Async context manager acquiring `lock_key` on entry and releasing on exit."""
        resolved_owner = owner_id or f"{self._default_owner_id}:{uuid.uuid4().hex[:8]}"
        acquired = await self.acquire(
            lock_key,
            ttl_seconds=ttl_seconds,
            owner_id=resolved_owner,
            wait_timeout=wait_timeout,
            poll_interval=poll_interval,
        )
        if not acquired:
            raise LockAcquisitionError(f"Could not acquire distributed lock {lock_key!r} (owner={resolved_owner!r}).")
        try:
            yield resolved_owner
        finally:
            await asyncio.shield(self.release(lock_key, owner_id=resolved_owner))


DatabaseLockManager = SqlLockAdapter
