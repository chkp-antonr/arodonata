"""Shared session execution and batched SQLite/PostgreSQL dialect helpers for `SqlCacheAdapter`."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from sqlalchemy import Table, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel

from arodonata.adapters.storage.cache.mappers import _sync_state_to_row
from arodonata.adapters.storage.database import DatabaseManager
from arodonata.adapters.storage.tables import DomainSyncStateRecord
from arodonata.core.models.domains import DomainSyncState

_BATCH_ROWS = 500


class SqlCacheBase:
    """Shared base class holding `DatabaseManager` and batched SQL Core helpers."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    @property
    def db(self) -> DatabaseManager:
        """Return the underlying `DatabaseManager`."""
        return self._db

    async def _insert_rows_batched[T](
        self,
        session: AsyncSession,
        model_cls: type[SQLModel],
        items: Sequence[T],
        mapper: Callable[[T], dict[str, Any]],
    ) -> None:
        """Execute Core multi-row `INSERT` in `_BATCH_ROWS` chunks without ORM identity-map bloat."""
        if not items:
            return
        table: Table = model_cls.__table__  # type: ignore[attr-defined]
        total = len(items)
        for start in range(0, total, _BATCH_ROWS):
            batch = [mapper(item) for item in items[start : start + _BATCH_ROWS]]
            await session.execute(insert(table), batch)

    async def _dialect_upsert(
        self,
        session: AsyncSession,
        model_cls: type[SQLModel],
        values_list: Sequence[dict[str, Any]],
    ) -> None:
        """Execute a batched dialect-aware `INSERT ... ON CONFLICT DO UPDATE` upsert (`W21`)."""
        if not values_list:
            return
        table: Table = model_cls.__table__  # type: ignore[attr-defined]
        pk_cols = [c.name for c in table.primary_key.columns]
        non_pk_cols = [c.name for c in table.columns if c.name not in pk_cols]
        dialect_name = self._db.engine.dialect.name
        insert_fn = pg_insert if dialect_name == "postgresql" else sqlite_insert

        # Deduplicate by primary key preserving the last occurrence so PostgreSQL multi-row
        # ON CONFLICT DO UPDATE never attempts to update the same target row twice in one statement.
        deduped_map: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row_vals in values_list:
            pk_key = tuple(row_vals.get(col_name) for col_name in pk_cols)
            deduped_map[pk_key] = row_vals
        deduped_rows = list(deduped_map.values())

        for start in range(0, len(deduped_rows), _BATCH_ROWS):
            batch = deduped_rows[start : start + _BATCH_ROWS]
            stmt: Any = insert_fn(table).values(batch)
            update_map = {col_name: getattr(stmt.excluded, col_name) for col_name in non_pk_cols}
            await session.execute(stmt.on_conflict_do_update(index_elements=pk_cols, set_=update_map))

    async def _upsert_sync_states_in_session(
        self,
        session: AsyncSession,
        states: Sequence[DomainSyncState],
    ) -> None:
        """Upsert one or more `DomainSyncState` rows inside an active `session` (`W19`, `W21`)."""
        if not states:
            return
        rows = [_sync_state_to_row(state) for state in states]
        await self._dialect_upsert(session, DomainSyncStateRecord, rows)
