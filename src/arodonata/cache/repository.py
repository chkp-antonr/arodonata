"""Centralized cache repository - ALL database operations go through here.

Other modules MUST NOT access PostgreSQL directly.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select, update
from sqlmodel import SQLModel

from ..config import GLOBAL_DOMAIN_NAME
from ..logger import lazy_logger
from ..rulebase.model import DomainRulebaseSnapshot
from .database import DatabaseManager
from .models import (
    RULEBASE_MODELS,
    Asset,
    CPObject,
    Domain,
    LastPublishedSession,
    PolicyPackageLayer,
    RulebaseLayer,
    RulebaseSection,
    RulebaseSyncState,
    SIDCache,
)
from .rulebase_rows import snapshot_from_rows

log = lazy_logger("arodonata.cache.repository")

_RULEBASE_MODELS = RULEBASE_MODELS


def _sid_key(mgmt_name: str, domain: str, username: str | None = None) -> str:
    """Build the SID cache primary key.

    Api-key mode:    'mgmt_name:domain'
    Credential mode: 'mgmt_name:domain:username'  — one row per (mgmt, domain, user)
    """
    if username:
        return f"{mgmt_name}:{domain}:{username}"
    return f"{mgmt_name}:{domain}"


class CacheRepository:
    """High-level cache operations for all modules.

    This is the ONLY class that performs database operations.
    All other modules must use this repository for data access.

    Example:
        from sqlalchemy.ext.asyncio import create_async_engine

        # Main app creates engine from its own config
        engine = create_async_engine("postgresql+asyncpg://...")
        db_manager = DatabaseManager(engine)

        cache = CacheRepository(db_manager)
        await cache.initialize()

        # Session operations
        await cache.set_sid("mgmt1", "domain1", "sid123", "192.168.1.1")
        sid = await cache.get_sid("mgmt1", "domain1")

        # Asset operations
        assets = await cache.get_assets(mgmt_names=["mgmt1"])
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize cache repository with database manager.

        Args:
            db_manager: DatabaseManager instance for database access.
        """
        self._db = db_manager
        self._swap_lock = asyncio.Lock()  # see replace_domain_objects
        # Process-local write-through cache of SID records (detached copies).
        # DB stays the persistent store: a new process falls back to it on
        # first read, which is how a fresh run reuses the previous run's SIDs.
        self._sid_memory: dict[str, SIDCache] = {}

    @staticmethod
    def _detached_sid_copy(record: SIDCache) -> SIDCache:
        """Plain copy that is never bound to a session."""
        return SIDCache(
            mgmt_dmn_key=record.mgmt_dmn_key,
            sid=record.sid,
            uid=record.uid,
            server_ip=record.server_ip,
            created_at=record.created_at,
            last_keepalive=record.last_keepalive,
            metadata_=record.metadata_,
        )

    def _memory_get(self, key: str, max_age_seconds: int | None) -> SIDCache | None:
        """Return the fresh memory copy for key, evicting it if aged out."""
        record = self._sid_memory.get(key)
        if record is None:
            return None
        if max_age_seconds and max_age_seconds > 0:
            created = record.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            if created < datetime.now(UTC) - timedelta(seconds=max_age_seconds):
                del self._sid_memory[key]
                log().trace(f"Memory cache EXPIRED: {key}")
                return None
        log().trace(f"Memory cache HIT: {key}")
        return record

    # ==================== SID Operations ====================

    async def get_sid(
        self,
        mgmt_name: str,
        domain: str,
        max_age_seconds: int | None = None,
        session: Any | None = None,
        username: str | None = None,
    ) -> SIDCache | None:
        """Retrieve cached session ID.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            max_age_seconds: If set, check expiration and delete if expired.
            session: Optional database session.
            username: CP username (credential mode). Scopes the cache to this user.

        Returns:
            SIDCache record or None if not found/expired.
        """
        key = _sid_key(mgmt_name, domain, username)

        memory_hit = self._memory_get(key, max_age_seconds)
        if memory_hit is not None:
            return memory_hit

        stmt = select(SIDCache).where(SIDCache.mgmt_dmn_key == key)  # type: ignore

        if session:
            record = await self._get_sid_internal(session, stmt, key, max_age_seconds)
        else:
            async with self._db.session() as session:
                record = await self._get_sid_internal(session, stmt, key, max_age_seconds)

        if record is not None:
            self._sid_memory[key] = self._detached_sid_copy(record)
        return record

    async def _get_sid_internal(
        self,
        session: Any,
        stmt: Any,
        key: str,
        max_age_seconds: int | None,
    ) -> SIDCache | None:
        """Internal helper for SID retrieval with optional expiration check."""
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            log().trace(f"Cache MISS: {key}")
            return None

        # Interpret naive datetime from DB as UTC
        created = record.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)

        # Check expiration
        if max_age_seconds and max_age_seconds > 0:
            cutoff = datetime.now(UTC) - timedelta(seconds=max_age_seconds)

            if created < cutoff:
                log().debug(f"Cache EXPIRED: {key}")
                await session.execute(
                    delete(SIDCache).where(SIDCache.mgmt_dmn_key == key)  # type: ignore
                )
                await session.commit()
                return None

        log().trace(f"Cache HIT: {key}")
        from typing import cast

        return cast(SIDCache, record)

    async def set_sid(
        self,
        mgmt_name: str,
        domain: str,
        sid: str,
        server_ip: str,
        uid: str | None = None,
        session: Any | None = None,
        username: str | None = None,
    ) -> None:
        """Store or update session ID in cache.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            sid: Session identifier.
            server_ip: Management server IP address.
            uid: Optional CP session UID from login response.
            session: Optional database session.
            username: CP username (credential mode). Scopes the cache to this user.
        """
        key = _sid_key(mgmt_name, domain, username)
        now = datetime.now(UTC).replace(tzinfo=None)

        if session:
            await self._set_sid_internal(session, key, sid, server_ip, uid, now)
        else:
            async with self._db.session() as session:
                await self._set_sid_internal(session, key, sid, server_ip, uid, now)

        self._sid_memory[key] = SIDCache(
            mgmt_dmn_key=key,
            sid=sid,
            server_ip=server_ip,
            uid=uid,
            created_at=now,
            last_keepalive=now,
            # Explicit for parity with _detached_sid_copy: a freshly-set SID
            # has no metadata yet (matches current behavior).
            metadata_=None,
        )

    async def _set_sid_internal(
        self,
        session: Any,
        key: str,
        sid: str,
        server_ip: str,
        uid: str | None,
        now: datetime,
    ) -> None:
        """Internal helper for setting SID."""
        # Check if exists
        stmt = select(SIDCache).where(SIDCache.mgmt_dmn_key == key)  # type: ignore
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.sid = sid
            existing.server_ip = server_ip
            existing.uid = uid
            existing.created_at = now
            existing.last_keepalive = now
            log().trace(f"Cache UPDATE: {key}")
        else:
            new_record = SIDCache(
                mgmt_dmn_key=key,
                sid=sid,
                server_ip=server_ip,
                uid=uid,
                created_at=now,
                last_keepalive=now,
            )
            session.add(new_record)
            log().trace(f"Cache INSERT: {key}")

    async def delete_sid(
        self,
        mgmt_name: str,
        domain: str,
        username: str | None = None,
    ) -> None:
        """Delete specific session from cache.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            username: CP username (credential mode). Scopes the delete to this user.
        """
        key = _sid_key(mgmt_name, domain, username)
        async with self._db.session() as session:
            await session.execute(
                delete(SIDCache).where(SIDCache.mgmt_dmn_key == key)  # type: ignore
            )
            log().debug(f"Cache DELETE: {key}")
        self._sid_memory.pop(key, None)

    async def clear_sessions(self, older_than_seconds: int | None = None) -> int:
        """Clear session entries from cache.

        Args:
            older_than_seconds: If set, only delete entries older than this.
                               If None, delete all entries.

        Returns:
            Number of entries deleted.
        """
        async with self._db.session() as session:
            if older_than_seconds:
                cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
                stmt = delete(SIDCache).where(SIDCache.created_at < cutoff)  # type: ignore
            else:
                stmt = delete(SIDCache)

            result = await session.execute(stmt)
            count = getattr(result, "rowcount", 0) or 0
            log().info(f"Cleared {count} session entries")
        self._sid_memory.clear()
        return count

    async def list_all_sids(self) -> list[SIDCache]:
        """List all session IDs in cache.

        Returns:
            List of SIDCache records.
        """
        async with self._db.session() as session:
            stmt = select(SIDCache)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def update_keepalive(
        self,
        mgmt_name: str,
        domain: str,
        username: str | None = None,
    ) -> None:
        """Update last_keepalive timestamp for a cached session.

        Does nothing if no record exists for the given key.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            username: CP username (credential mode). Scopes the update to this user.
        """
        key = _sid_key(mgmt_name, domain, username)
        now = datetime.now(UTC).replace(tzinfo=None)
        async with self._db.session() as session:
            stmt = (
                update(SIDCache)
                .where(SIDCache.mgmt_dmn_key == key)  # type: ignore
                .values(last_keepalive=now)
            )
            result = await session.execute(stmt)
            if (getattr(result, "rowcount", 0) or 0) >= 1:
                log().trace(f"Keepalive updated: {key}")
            else:
                log().trace(f"Keepalive skipped (no record): {key}")
        cached = self._sid_memory.get(key)
        if cached is not None:
            cached.last_keepalive = now

    async def list_stale_keepalives(self, threshold_seconds: int = 600) -> list[SIDCache]:
        """Return all SID cache entries with a stale or missing keepalive.

        Args:
            threshold_seconds: Age in seconds after which keepalive is considered stale.

        Returns:
            List of SIDCache records needing a keepalive ping.
        """
        cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=threshold_seconds)
        async with self._db.session() as session:
            stmt = select(SIDCache).where(  # type: ignore
                or_(
                    SIDCache.last_keepalive.is_(None),  # type: ignore
                    SIDCache.last_keepalive < cutoff,  # type: ignore
                )
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_by_sid(self, sid: str) -> SIDCache | None:
        """Retrieve cached session by session ID.

        Args:
            sid: Session identifier.

        Returns:
            SIDCache record or None if not found.
        """
        async with self._db.session() as session:
            stmt = select(SIDCache).where(SIDCache.sid == sid)  # type: ignore[arg-type]
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_by_uid(self, uid: str) -> SIDCache | None:
        """Retrieve cached session by user ID.

        Args:
            uid: User identifier.

        Returns:
            SIDCache record or None if not found.
        """
        async with self._db.session() as session:
            stmt = select(SIDCache).where(SIDCache.uid == uid)  # type: ignore[arg-type]
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_uid_by_sid(self, sid: str) -> str | None:
        """Get user ID by session ID.

        Args:
            sid: Session identifier.

        Returns:
            User ID or None if not found.
        """
        record = await self.get_by_sid(sid)
        return record.uid if record else None

    async def get_sid_by_uid(self, uid: str) -> str | None:
        """Get session ID by user ID.

        Args:
            uid: User identifier.

        Returns:
            Session ID or None if not found.
        """
        record = await self.get_by_uid(uid)
        return record.sid if record else None

    # ==================== Asset Operations ====================

    async def get_assets(
        self,
        asset_ids: list[str] | None = None,
        asset_types: list[str] | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[Asset]:
        """Retrieve assets with optional filters.

        Args:
            asset_ids: Filter by specific asset IDs.
            asset_types: Filter by asset types.
            mgmt_names: Filter by management server names.
            domain_names: Filter by domain names.

        Returns:
            List of matching Asset records.
        """
        async with self._db.session() as session:
            stmt = select(Asset)

            if asset_ids:
                stmt = stmt.where(Asset.asset_id.in_(asset_ids))  # type: ignore[attr-defined]
            if asset_types:
                stmt = stmt.where(Asset.asset_type.in_(asset_types))  # type: ignore[attr-defined]
            if mgmt_names:
                stmt = stmt.where(Asset.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(Asset.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def upsert_asset(self, asset: Asset, session: Any | None = None) -> None:
        """Insert or update a single asset.

        Args:
            asset: Asset record to upsert.
            session: Optional database session.
        """
        if session:
            await session.merge(asset)
        else:
            async with self._db.session() as session:
                await session.merge(asset)

    async def upsert_assets(self, assets: list[Asset], session: Any | None = None) -> int:
        """Bulk insert or update assets using merge in a single transaction.

        Args:
            assets: List of Asset records to upsert.
            session: Optional database session.

        Returns:
            Number of assets processed.
        """
        if not assets:
            return 0

        # Ensure parent_asset_id is None if empty string to satisfy FK
        for asset in assets:
            if asset.parent_asset_id == "":
                asset.parent_asset_id = None

        if session:
            for asset in assets:
                await session.merge(asset)
            return len(assets)

        async with self._db.session() as session:
            for asset in assets:
                await session.merge(asset)
            await session.commit()
            log().debug(f"Upserted {len(assets)} assets")
            return len(assets)

    async def delete_assets(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> int:
        """Delete assets with optional filters.

        Args:
            mgmt_names: Delete only for these management servers.
            domain_names: Delete only for these domains.

        Returns:
            Number of assets deleted.
        """
        async with self._db.session() as session:
            stmt = delete(Asset)

            if mgmt_names:
                stmt = stmt.where(Asset.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(Asset.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            count = getattr(result, "rowcount", 0) or 0
            log().debug(f"Deleted {count} assets")
            return count

    async def restore_asset_local_fields(self, snapshot: dict[str, dict[str, str]]) -> int:
        """Restore locally-owned path/ip_address/ssh_ip fields onto refreshed assets.

        A raw refresh (delete_assets + upsert_assets from live management-API
        data) has no notion of these fields and always writes them blank.
        Callers that need them preserved across a refresh call get_assets()
        beforehand to build `snapshot`, then call this after the refresh
        completes. Only fills in fields that came back empty - never
        overwrites a value the refresh legitimately set.

        Args:
            snapshot: Mapping of asset_id to its pre-refresh path/ip_address/
                ssh_ip, as produced by get_assets().

        Returns:
            Number of assets whose fields were restored.
        """
        if not snapshot:
            return 0

        restored_count = 0

        async with self._db.session() as session:
            for asset_id, fields in snapshot.items():
                stmt = select(Asset).where(Asset.asset_id == asset_id)  # type: ignore[arg-type]
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()

                if not asset:
                    continue

                changed = False
                if not asset.path and fields.get("path"):
                    asset.path = fields["path"]
                    changed = True
                if not asset.ip_address and fields.get("ip_address"):
                    asset.ip_address = fields["ip_address"]
                    changed = True
                if not asset.ssh_ip and fields.get("ssh_ip"):
                    asset.ssh_ip = fields["ssh_ip"]
                    changed = True

                if changed:
                    session.add(asset)
                    restored_count += 1

            if restored_count:
                await session.commit()

        return restored_count

    # ==================== Domain Operations ====================

    async def get_domain(self, mdm_dmn: str) -> Domain | None:
        """Get domain by composite key.

        Args:
            mdm_dmn: Composite key 'active_mds:domain'.

        Returns:
            Domain record or None.
        """
        async with self._db.session() as session:
            stmt = select(Domain).where(Domain.mdm_dmn == mdm_dmn)  # type: ignore
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_domains(
        self,
        mgmt_name: str | None = None,
        mgmt_names: list[str] | None = None,
        include_global: bool = False,
    ) -> list[Domain]:
        """Get all domains, optionally filtered by management server.

        Args:
            mgmt_name: Optional single management server filter (deprecated, use mgmt_names).
            mgmt_names: Optional list of management server names to filter.
            include_global: When False (default), the "Global" domain
                row is excluded so existing callers see today's behavior.

        Returns:
            List of Domain records.
        """
        async with self._db.session() as session:
            stmt = select(Domain)
            # Support both mgmt_name (singular) and mgmt_names (plural) for compatibility
            if mgmt_names:
                stmt = stmt.where(Domain.mgmt_name.in_(mgmt_names))  # type: ignore
            elif mgmt_name:
                stmt = stmt.where(Domain.mgmt_name == mgmt_name)  # type: ignore
            if not include_global:
                stmt = stmt.where(Domain.domain_name != GLOBAL_DOMAIN_NAME)  # type: ignore
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def upsert_domain(self, domain: Domain) -> None:
        """Insert or update domain record.

        Args:
            domain: Domain record to upsert.
        """
        async with self._db.session() as session:
            await session.merge(domain)
            await session.commit()

    async def initialize(self) -> None:
        """Initialize cache repository database connections."""
        await self._db.initialize()

    async def close(self) -> None:
        """Close cache repository connections.

        Note: Does not dispose the engine - main app is responsible for that.
        """
        log().debug("CacheRepository closed")

    # ==================== CPObject Operations ====================

    async def upsert_objects(self, objects: list[CPObject], session: Any | None = None) -> int:
        """Bulk insert or update CPObject records.

        Uses merge for upsert - updates existing records or creates new ones.

        Args:
            objects: List of CPObject records to upsert.
            session: Optional database session.

        Returns:
            Number of objects processed.
        """
        if not objects:
            return 0

        if session:
            for obj in objects:
                await session.merge(obj)
            return len(objects)

        async with self._db.session() as session:
            for obj in objects:
                await session.merge(obj)
            await session.commit()
            log().debug(f"Upserted {len(objects)} objects")
            return len(objects)

    async def get_objects_by_ip(
        self,
        ip_address: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve objects by IP address.

        Searches ipv4_address, ipv4_address_first, and ipv4_address_last fields.

        Args:
            ip_address: IP address to search for.
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.

        Returns:
            List of matching CPObject records.
        """
        from sqlalchemy import or_

        async with self._db.session() as session:
            stmt = select(CPObject).where(
                or_(
                    CPObject.ipv4_address == ip_address,  # type: ignore[arg-type]
                    CPObject.ipv4_address_first == ip_address,  # type: ignore[arg-type]
                    CPObject.ipv4_address_last == ip_address,  # type: ignore[arg-type]
                )
            )

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_objects_by_subnet(
        self,
        subnet: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve objects by subnet CIDR.

        Args:
            subnet: Subnet CIDR (e.g., "192.168.1.0/24").
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.

        Returns:
            List of matching CPObject records.
        """
        async with self._db.session() as session:
            stmt = select(CPObject).where(CPObject.subnet4 == subnet)  # type: ignore[arg-type]

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_objects_in_ip_range(
        self,
        start_ip: str,
        end_ip: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve address-range objects that contain the specified IP range.

        Args:
            start_ip: Start IP address of range.
            end_ip: End IP address of range.
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.

        Returns:
            List of matching CPObject records.
        """
        async with self._db.session() as session:
            stmt = select(CPObject).where(
                CPObject.type == "address-range",  # type: ignore[arg-type]
                CPObject.ipv4_address_first == start_ip,  # type: ignore[arg-type]
                CPObject.ipv4_address_last == end_ip,  # type: ignore[arg-type]
            )

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_objects_by_name(
        self,
        name: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        search_comments: bool = True,
    ) -> list[CPObject]:
        """Retrieve objects by name or comments with optional wildcards.

        Args:
            name: Object name to search for (supports * and ?).
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.
            search_comments: Whether to include comments in matching.

        Returns:
            List of matching CPObject records.
        """
        async with self._db.session() as session:
            if "*" in name or "?" in name:
                pattern = name.replace("*", "%").replace("?", "_")
            else:
                pattern = f"%{name}%" if search_comments else name

            if search_comments:
                stmt = select(CPObject).where(
                    or_(
                        CPObject.name.ilike(pattern),  # type: ignore[attr-defined]
                        CPObject.comments.ilike(pattern),  # type: ignore[attr-defined]
                    )
                )
            elif "*" in name or "?" in name:
                stmt = select(CPObject).where(CPObject.name.like(pattern))  # type: ignore[attr-defined]
            else:
                stmt = select(CPObject).where(CPObject.name == name)  # type: ignore[arg-type]

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_objects_by_uids(
        self,
        uids: list[str],
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve objects by a list of UIDs.

        Args:
            uids: List of object UIDs.
            mgmt_names: Optional management filter.
            domain_names: Optional domain filter.

        Returns:
            List of matching CPObject records.
        """
        if not uids:
            return []

        async with self._db.session() as session:
            stmt = select(CPObject).where(CPObject.uid.in_(uids))  # type: ignore[attr-defined]

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            res_list = list(result.scalars().all())
            return res_list

    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
    ) -> CPObject | None:
        """Retrieve object by UID.

        Args:
            uid: Object UID to search for.
            mgmt_name: Optional management server name.
            domain_name: Optional domain name.

        Returns:
            CPObject record or None if not found.
        """
        async with self._db.session() as session:
            stmt = select(CPObject).where(CPObject.uid == uid)  # type: ignore[arg-type]

            if mgmt_name:
                stmt = stmt.where(CPObject.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name:
                stmt = stmt.where(CPObject.domain_name == domain_name)  # type: ignore[arg-type]

            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_objects(
        self,
        object_type: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[CPObject]:
        """Retrieve objects from cache with flexible filtering.

        Args:
            object_type: Optional object type filter (host, network, group, etc.).
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.
            filters: Optional additional filters as key-value pairs (supports wildcards in string values).

        Returns:
            List of matching CPObject records.
        """
        async with self._db.session() as session:
            stmt = select(CPObject)

            # Apply object type filter
            if object_type:
                stmt = stmt.where(CPObject.type == object_type)  # type: ignore[arg-type]

            # Apply management server filter
            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]

            # Apply domain filter
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            # Apply additional filters
            if filters:
                for key, value in filters.items():
                    if hasattr(CPObject, key):
                        col = getattr(CPObject, key)
                        if isinstance(value, str) and ("*" in value or "?" in value):
                            pattern = value.replace("*", "%").replace("?", "_")
                            stmt = stmt.where(col.like(pattern))
                        else:
                            stmt = stmt.where(col == value)
                    else:
                        from arodonata.logger import get_logger

                        get_logger("arodonata.cache.repository").warning(f"Filter key '{key}' not found in CPObject")

            result = await session.execute(stmt)
            res_list = list(result.scalars().all())
            return res_list

    async def get_objects_last_update(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> datetime | None:
        """Most recent ``update_time`` among cached objects in scope, or ``None`` when the scope is empty."""
        async with self._db.session() as session:
            stmt: Any = select(func.max(CPObject.update_time))
            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]
            result = await session.execute(stmt)
            value = result.scalar_one_or_none()
            return value if isinstance(value, datetime) else None

    async def get_rulebase_last_update(
        self,
        rulebase_type: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> datetime | None:
        """Most recent ``update_time`` among cached rules of one rulebase type in scope, or ``None`` when empty.

        Args:
            rulebase_type: One of ``"access"``, ``"nat"``, ``"https"``, ``"threat"``.
            mgmt_names: Optional management server names to filter.
            domain_names: Optional domain names to filter.

        Raises:
            ValueError: If ``rulebase_type`` is not one of the supported types.
        """
        model = _RULEBASE_MODELS.get(rulebase_type)
        if model is None:
            raise ValueError(f"unknown rulebase_type '{rulebase_type}'; expected one of: {', '.join(_RULEBASE_MODELS)}")
        async with self._db.session() as session:
            stmt: Any = select(func.max(model.update_time))  # type: ignore[attr-defined]
            if mgmt_names:
                stmt = stmt.where(model.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(model.domain_name.in_(domain_names))  # type: ignore[attr-defined]
            result = await session.execute(stmt)
            value = result.scalar_one_or_none()
            return value if isinstance(value, datetime) else None

    async def get_objects_by_type(
        self,
        object_type: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve objects by type.

        Args:
            object_type: Object type (host, network, group, etc.).
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.

        Returns:
            List of matching CPObject records.
        """
        async with self._db.session() as session:
            stmt = select(CPObject).where(CPObject.type == object_type)  # type: ignore[arg-type]

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_objects_by_members(
        self,
        member_uid: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
    ) -> list[CPObject]:
        """Retrieve groups that contain the specified member UID.

        Searches for groups where the members field contains the member UID.
        Members are stored as comma-separated quoted strings like '"uid1","uid2","uid3"'.

        Args:
            member_uid: Member UID to search for.
            mgmt_names: Optional list of management servers to filter by.
            domain_names: Optional list of domains to filter by.

        Returns:
            List of group CPObject records containing the member.
        """
        from sqlalchemy import desc, text

        # Search for the UID in the members field
        # Pattern matches quoted UID within comma-separated list: %"<uid>"%
        search_pattern = f'%"{member_uid}"%'

        async with self._db.session() as session:
            stmt = select(CPObject).where(text("members LIKE :search_pattern")).where(CPObject.type == "group")  # type: ignore[arg-type]

            if mgmt_names:
                stmt = stmt.where(CPObject.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]
            if domain_names:
                stmt = stmt.where(CPObject.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            # Order by update time to get most recently updated groups first
            stmt = stmt.order_by(desc(CPObject.update_time))  # type: ignore[arg-type]

            result = await session.execute(stmt, params={"search_pattern": search_pattern})
            return list(result.scalars().all())

    async def delete_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> int:
        """Delete all objects for a management server and domain.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            Number of records deleted.
        """
        async with self._db.session() as session:
            stmt = delete(CPObject).where(
                CPObject.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                CPObject.domain_name == domain_name,  # type: ignore[arg-type]
            )
            result = await session.execute(stmt)
            await session.commit()
            count = getattr(result, "rowcount", 0) or 0
            log().debug(f"Deleted {count} objects for {mgmt_name}/{domain_name}")
            return count

    async def replace_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        objects: list[CPObject],
    ) -> tuple[int, int]:
        """Atomically replace all objects for a domain.

        Delete + bulk insert run in ONE transaction, so concurrent readers
        never observe an empty/partial domain and a failure rolls back to
        the previous cache contents. Input is deduped by primary key (the
        API occasionally returns duplicate uids within a page set). Swaps of
        one repository run one at a time (see the lock).

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            objects: Full replacement set for the domain.

        Returns:
            (deleted_count, inserted_count).
        """
        deduped = list({obj.id: obj for obj in objects}.values())
        # One swap at a time per repository. Domains refresh concurrently, and on SQLite a second writer
        # waits only SQLite's busy timeout (5 s by default) for the first to commit before failing with
        # "database is locked"; a large domain's swap can take longer. Swaps are short next to the fetch
        # that precedes them, so serializing them costs nothing measurable, on any dialect.
        async with self._swap_lock, self._db.session() as session:
            stmt = delete(CPObject).where(
                CPObject.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                CPObject.domain_name == domain_name,  # type: ignore[arg-type]
            )
            result = await session.execute(stmt)
            deleted = getattr(result, "rowcount", 0) or 0
            session.add_all(deduped)
            await session.commit()
            log().debug(f"Replaced objects for {mgmt_name}/{domain_name}: -{deleted} +{len(deduped)}")
            return deleted, len(deduped)

    async def delete_object(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> int:
        """Delete a single object by UID within a management server/domain.

        Args:
            uid: Object UID.
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            Number of records deleted (0 if not present).
        """
        async with self._db.session() as session:
            stmt = delete(CPObject).where(
                CPObject.uid == uid,  # type: ignore[arg-type]
                CPObject.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                CPObject.domain_name == domain_name,  # type: ignore[arg-type]
            )
            result = await session.execute(stmt)
            await session.commit()
            count = getattr(result, "rowcount", 0) or 0
            log().debug(f"Deleted object {uid} for {mgmt_name}/{domain_name} (count={count})")
            return count

    # ==================== LastPublishedSession Operations ====================

    async def get_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> LastPublishedSession | None:
        """Retrieve last published session for a domain.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            LastPublishedSession record or None.
        """
        key = f"{mgmt_name}:{domain_name}"
        async with self._db.session() as session:
            stmt = select(LastPublishedSession).where(LastPublishedSession.id == key)  # type: ignore
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def upsert_last_published_session(
        self,
        record: LastPublishedSession,
    ) -> None:
        """Insert or update last published session record.

        Args:
            record: LastPublishedSession record to upsert.
        """
        async with self._db.session() as session:
            await session.merge(record)
            await session.commit()
            log().debug(f"Upserted last published session for {record.id}")

    # ==================== Rulebase Operations ====================

    async def get_rulebase(
        self,
        model_class: type,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[Any]:
        """Query rulebase rules from cache with optional filters.

        Args:
            model_class: Rulebase model class (RulebaseAccess, RulebaseNAT, etc.).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            filters: Optional additional filters (e.g., layer_name, enabled).

        Returns:
            List of rulebase records.
        """
        async with self._db.session() as session:
            stmt: Any = select(model_class)

            # Apply management server filter
            if mgmt_names:
                stmt = stmt.where(model_class.mgmt_name.in_(mgmt_names))  # type: ignore[attr-defined]

            # Apply domain filter
            if domain_names:
                stmt = stmt.where(model_class.domain_name.in_(domain_names))  # type: ignore[attr-defined]

            # Apply additional filters
            if filters:
                for key, value in filters.items():
                    if hasattr(model_class, key):
                        stmt = stmt.where(getattr(model_class, key) == value)

            # Legacy getters return rules only; place-holders exist for numbering (rulebase cache v2)
            if hasattr(model_class, "kind"):
                stmt = stmt.where(model_class.kind == "rule")  # type: ignore[attr-defined]

            # Layer first, then in-layer position, so rules of different layers never interleave
            if hasattr(model_class, "rule_number"):
                order = [model_class.layer_name]  # type: ignore[attr-defined]
                if hasattr(model_class, "layer_uid"):  # same-named layers (Global and domain) stay apart
                    order.append(model_class.layer_uid)  # type: ignore[attr-defined]
                stmt = stmt.order_by(*order, model_class.rule_number)  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def upsert_rulebase(
        self,
        rule: Any,
        session: Any | None = None,
    ) -> None:
        """Insert or update a single rulebase rule.

        Args:
            rule: Rulebase model instance to upsert.
            session: Optional database session.
        """
        if session:
            await session.merge(rule)
        else:
            async with self._db.session() as session:
                await session.merge(rule)
                await session.commit()

    async def upsert_rulebases(
        self,
        rules: list[Any],
        session: Any | None = None,
    ) -> int:
        """Bulk insert or update rulebase rules.

        Args:
            rules: List of rulebase model instances to upsert.
            session: Optional database session.

        Returns:
            Number of rules processed.
        """
        if not rules:
            return 0

        if session:
            for rule in rules:
                await session.merge(rule)
            return len(rules)
        else:
            async with self._db.session() as session:
                for rule in rules:
                    await session.merge(rule)
                await session.commit()
                return len(rules)

    async def delete_rulebase(
        self,
        model_class: type,
        mgmt_name: str,
        domain_name: str,
        layer_name: str | None = None,
    ) -> int:
        """Delete rules from cache for a specific domain.

        Args:
            model_class: Rulebase model class.
            mgmt_name: Management server name.
            domain_name: Domain name.
            layer_name: Optional layer name filter.

        Returns:
            Number of rules deleted.
        """
        async with self._db.session() as session:
            stmt = delete(model_class).where(
                model_class.mgmt_name == mgmt_name,  # type: ignore[attr-defined]
                model_class.domain_name == domain_name,  # type: ignore[attr-defined]
            )
            if layer_name:
                stmt = stmt.where(model_class.layer_name == layer_name)  # type: ignore[attr-defined]

            result = await session.execute(stmt)
            await session.commit()
            # Get rowcount from result - type: ignore for mypy compatibility
            # The Result object does have rowcount but mypy doesn't recognize it
            if hasattr(result, "rowcount"):
                return result.rowcount  # type: ignore[attr-defined]
            return 0

    _SNAPSHOT_TABLES: tuple[type[SQLModel], ...] = (RulebaseLayer, RulebaseSection, PolicyPackageLayer)

    async def replace_domain_rulebases(
        self,
        mgmt_name: str,
        domain_name: str,
        rows: Sequence[SQLModel],
        state: RulebaseSyncState,
    ) -> int:
        """Atomically replace a domain's whole rulebase snapshot and its sync state.

        One session and commit: deletes the domain's rows from the four rule tables, ``rulebase_layer``,
        ``rulebase_section`` and ``rulebase_package_layer`` (this also purges pre-v2 rule rows, whatever their id),
        inserts ``rows`` (deduped by primary key) and merges ``state``. A failure rolls back to the previous snapshot
        and state.

        Returns:
            Number of rule rows inserted (all four types, place-holders included).
        """
        deduped = list({row.id: row for row in rows}.values())  # type: ignore[attr-defined]
        rule_models = tuple(_RULEBASE_MODELS.values())
        async with self._db.session() as session:
            for model in (*rule_models, *self._SNAPSHOT_TABLES):
                await session.execute(
                    delete(model).where(
                        model.mgmt_name == mgmt_name,  # type: ignore[attr-defined]
                        model.domain_name == domain_name,  # type: ignore[attr-defined]
                    )
                )
            session.add_all(deduped)
            await session.merge(state)
            await session.commit()
        inserted = sum(1 for row in deduped if isinstance(row, rule_models))
        log().debug(f"Replaced rulebase snapshot for {mgmt_name}/{domain_name}: {inserted} rule rows")
        return inserted

    async def get_rulebase_sync_state(self, mgmt_name: str, domain_name: str) -> RulebaseSyncState | None:
        """The domain's rulebase sync state, or None before its first rulebase refresh."""
        async with self._db.session() as session:
            return await session.get(RulebaseSyncState, f"{mgmt_name}:{domain_name}")

    async def mark_rulebase_sync_failed(self, mgmt_name: str, domain_name: str, error: str) -> None:
        """Record a failed refresh: status 'failed' and ``last_error``; ``session_uid`` and ``format_version`` stay."""
        async with self._db.session() as session:
            key = f"{mgmt_name}:{domain_name}"
            state = await session.get(RulebaseSyncState, key) or RulebaseSyncState(
                id=key, mgmt_name=mgmt_name, domain_name=domain_name
            )
            state.status = "failed"
            state.last_error = error
            state.update_time = datetime.now(UTC).replace(tzinfo=None)
            await session.merge(state)
            await session.commit()

    async def find_rulebase_layers(self, mgmt_name: str, layer: str, rulebase_type: str) -> list[tuple[str, str]]:
        """``(domain_name, layer_uid)`` of every cached layer of that type whose uid or name is ``layer``."""
        async with self._db.session() as session:
            stmt = (
                select(RulebaseLayer.domain_name, RulebaseLayer.layer_uid)  # type: ignore[call-overload]
                .where(
                    RulebaseLayer.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    RulebaseLayer.rulebase_type == rulebase_type,  # type: ignore[arg-type]
                    or_(RulebaseLayer.layer_uid == layer, RulebaseLayer.layer_name == layer),  # type: ignore[arg-type]
                )
                .distinct()
            )
            return sorted((str(d), str(u)) for d, u in (await session.execute(stmt)).all())

    async def find_rulebase_packages(self, mgmt_name: str, package: str) -> list[tuple[str, str]]:
        """``(domain_name, package_uid)`` of every cached package whose name or uid is ``package``."""
        async with self._db.session() as session:
            stmt = (
                select(PolicyPackageLayer.domain_name, PolicyPackageLayer.package_uid)  # type: ignore[call-overload]
                .where(
                    PolicyPackageLayer.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    or_(PolicyPackageLayer.package_name == package, PolicyPackageLayer.package_uid == package),  # type: ignore[arg-type]
                )
                .distinct()
            )
            return sorted((str(d), str(u)) for d, u in (await session.execute(stmt)).all())

    async def load_domain_rulebase_snapshot(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot | None:
        """The domain's cached rulebase snapshot (canonical order), or None when it has no sync state."""
        async with self._db.session() as session:
            state = await session.get(RulebaseSyncState, f"{mgmt_name}:{domain_name}")
            if state is None:
                return None

            async def rows(model: type[SQLModel]) -> list[Any]:
                stmt = select(model).where(
                    model.mgmt_name == mgmt_name,  # type: ignore[attr-defined]
                    model.domain_name == domain_name,  # type: ignore[attr-defined]
                )
                return list((await session.execute(stmt)).scalars().all())

            rule_rows: list[Any] = []
            for model in _RULEBASE_MODELS.values():
                rule_rows += await rows(model)
            return snapshot_from_rows(
                state, await rows(RulebaseLayer), await rows(RulebaseSection), rule_rows, await rows(PolicyPackageLayer)
            )


__all__ = ["CacheRepository"]
