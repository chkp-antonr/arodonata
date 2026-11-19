"""Domain metadata, SID cache, and sync-state operations for `SqlCacheAdapter`."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlmodel import col

from arodonata.adapters.storage.cache._base import SqlCacheBase
from arodonata.adapters.storage.cache.mappers import (
    _domain_to_row,
    _record_to_domain,
    _record_to_sid_entry,
    _record_to_sync_state,
    _sid_entry_to_row,
)
from arodonata.adapters.storage.tables import DomainRecord, DomainSyncStateRecord, SIDCacheRecord
from arodonata.core.models.common import SyncScope
from arodonata.core.models.domains import DomainInfo, DomainSyncState, SIDCacheEntry
from arodonata.core.telemetry import span_attrs, traced


class ControlCacheMixin(SqlCacheBase):
    """Implements `DomainCachePort`, `SidCachePort`, and `SyncStatePort` over SQL storage."""

    @traced
    async def get_domains(
        self,
        mgmt_name: str | None = None,
        *,
        include_global: bool = False,
    ) -> list[DomainInfo]:
        """Return cached domains, excluding Global domains unless `include_global=True`."""
        span_attrs(mgmt_name=mgmt_name, include_global=include_global)
        async with self._db.session() as session:
            stmt = select(DomainRecord)
            if mgmt_name is not None:
                stmt = stmt.where(DomainRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if not include_global:
                stmt = stmt.where(
                    DomainRecord.is_global == False,  # type: ignore[arg-type]  # noqa: E712
                    DomainRecord.name != "Global",  # type: ignore[arg-type]
                )
            stmt = stmt.order_by(DomainRecord.mgmt_name, DomainRecord.name)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_domain(r) for r in rows]

    @traced
    async def get_domain(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainInfo | None:
        """Return a single cached domain by `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            stmt = select(DomainRecord).where(
                DomainRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                DomainRecord.name == domain_name,  # type: ignore[arg-type]
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            return _record_to_domain(row) if row is not None else None

    @traced
    async def upsert_domains(self, domains: Sequence[DomainInfo]) -> None:
        """Insert or update domain rows in `arodonata_domains`."""
        if not domains:
            return
        span_attrs(count=len(domains))
        rows = [_domain_to_row(dom) for dom in domains]
        async with self._db.session() as session:
            await self._dialect_upsert(session, DomainRecord, rows)
            await session.commit()

    @traced
    async def get_sid(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        auth_identity: str | None = None,
    ) -> SIDCacheEntry | None:
        """Fetch a cached shared read-only session entry for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            if auth_identity is not None:
                key = f"{mgmt_name}:{domain_name}:{auth_identity}"
                rec = await session.get(SIDCacheRecord, key)
                if rec is not None and rec.auth_identity == auth_identity:
                    return _record_to_sid_entry(rec)
                return None
            key = f"{mgmt_name}:{domain_name}"
            rec = await session.get(SIDCacheRecord, key)
            if rec is not None:
                return _record_to_sid_entry(rec)
            stmt = (
                select(SIDCacheRecord)
                .where(
                    SIDCacheRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    SIDCacheRecord.domain_name == domain_name,  # type: ignore[arg-type]
                )
                .order_by(col(SIDCacheRecord.last_used_at).desc())
            )
            row = (await session.execute(stmt)).scalars().first()
            return _record_to_sid_entry(row) if row is not None else None

    @traced
    async def upsert_sid(self, entry: SIDCacheEntry) -> None:
        """Insert or update a shared read-only session entry in `arodonata_sid_cache`."""
        span_attrs(mgmt_name=entry.mgmt_name, domain=entry.domain_name, server_ip=entry.server_ip)
        row = _sid_entry_to_row(entry)
        async with self._db.session() as session:
            await self._dialect_upsert(session, SIDCacheRecord, [row])
            await session.commit()

    @traced
    async def evict_sid(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        auth_identity: str | None = None,
    ) -> bool:
        """Remove the cached SID for `(mgmt_name, domain_name)` immediately."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            if auth_identity is not None:
                key = f"{mgmt_name}:{domain_name}:{auth_identity}"
                result = await session.execute(
                    delete(SIDCacheRecord).where(SIDCacheRecord.id == key)  # type: ignore[arg-type]
                )
            else:
                result = await session.execute(
                    delete(SIDCacheRecord).where(
                        SIDCacheRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        SIDCacheRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    )
                )
            await session.commit()
            return bool(result.rowcount and result.rowcount > 0)  # type: ignore[attr-defined]

    @traced
    async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]:
        """List cached shared read-only SIDs, optionally filtered by `mgmt_name`."""
        span_attrs(mgmt_name=mgmt_name)
        async with self._db.session() as session:
            stmt = select(SIDCacheRecord)
            if mgmt_name is not None:
                stmt = stmt.where(SIDCacheRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_sid_entry(r) for r in rows]

    @traced
    async def get_sync_state(
        self,
        mgmt_name: str,
        domain_name: str,
        scope: SyncScope,
        item_type: str = "*",
    ) -> DomainSyncState | None:
        """Fetch synchronization state for `(mgmt_name, domain_name, scope, item_type)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, scope=scope, item_type=item_type)
        row_id = DomainSyncState.make_id(mgmt_name, domain_name, scope, item_type)
        async with self._db.session() as session:
            rec = await session.get(DomainSyncStateRecord, row_id)
            return _record_to_sync_state(rec) if rec is not None else None

    @traced
    async def list_sync_states(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> list[DomainSyncState]:
        """List synchronization states matching optional filters."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, scope=scope)
        async with self._db.session() as session:
            stmt = select(DomainSyncStateRecord)
            if mgmt_name is not None:
                stmt = stmt.where(DomainSyncStateRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(DomainSyncStateRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if scope is not None:
                stmt = stmt.where(DomainSyncStateRecord.scope == scope)  # type: ignore[arg-type]
            stmt = stmt.order_by(DomainSyncStateRecord.id)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_sync_state(r) for r in rows]

    @traced
    async def upsert_sync_state(self, state: DomainSyncState) -> None:
        """Insert or update a `DomainSyncState` row in `arodonata_domain_sync_state`."""
        span_attrs(
            mgmt_name=state.mgmt_name,
            domain=state.domain_name,
            scope=state.scope,
            item_type=state.item_type,
            status=state.status,
        )
        async with self._db.session() as session:
            await self._upsert_sync_states_in_session(session, [state])
            await session.commit()
