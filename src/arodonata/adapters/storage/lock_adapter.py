"""Database-backed distributed lock adapter (`SqlLockAdapter` / `DatabaseLockManager`)."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError

from arodonata.adapters.storage.database import DatabaseManager
from arodonata.adapters.storage.tables import DistributedLockRecord, _ensure_utc
from arodonata.core.errors import LockAcquisitionError
from arodonata.core.models.common import utc_now
from arodonata.core.telemetry import span_attrs, traced


class SqlLockAdapter:
    """Coordinates cross-process locks via the `distributed_locks` table with expiration reclamation."""

    def __init__(
        self,
        db: DatabaseManager,
        *,
        default_owner_id: str | None = None,
    ) -> None:
        self._db = db
        self._default_owner_id = default_owner_id or f"worker-{uuid.uuid4().hex[:12]}"

    @property
    def default_owner_id(self) -> str:
        """Default lock owner identifier for this adapter instance."""
        return self._default_owner_id

    async def _try_acquire_once(
        self,
        lock_key: str,
        *,
        ttl_seconds: float,
        owner_id: str,
    ) -> bool:
        """Attempt a single atomic lock acquisition or expired-lock reclamation."""
        now = utc_now()
        expires_at = now + timedelta(seconds=max(0.1, float(ttl_seconds)))

        async with self._db.session() as session:
            try:
                # 1. Reclaim expired lock or refresh existing lock held by the same owner_id
                await session.execute(
                    delete(DistributedLockRecord).where(
                        DistributedLockRecord.lock_key == lock_key,  # type: ignore[arg-type]
                        or_(
                            DistributedLockRecord.expires_at <= now,  # type: ignore[arg-type]
                            DistributedLockRecord.owner_id == owner_id,  # type: ignore[arg-type]
                        ),
                    )
                )

                # 2. Check if an active lock held by another owner still exists
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
    async def release(
        self,
        lock_key: str,
        *,
        owner_id: str | None = None,
    ) -> bool:
        """Release `lock_key` if owned by `owner_id` (or unconditionally when `owner_id` is None)."""
        span_attrs(lock_key=lock_key, lock_owner=owner_id)
        async with self._db.session() as session:
            stmt = delete(DistributedLockRecord).where(
                DistributedLockRecord.lock_key == lock_key  # type: ignore[arg-type]
            )
            if owner_id is not None:
                stmt = stmt.where(DistributedLockRecord.owner_id == owner_id)  # type: ignore[arg-type]
            result = await session.execute(stmt)
            await session.commit()
            released = bool(result.rowcount and result.rowcount > 0)  # type: ignore[attr-defined]
            span_attrs(lock_released=released)
            return released

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
            await self.release(lock_key, owner_id=resolved_owner)


DatabaseLockManager = SqlLockAdapter
