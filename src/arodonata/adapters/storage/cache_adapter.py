"""SQL cache adapter (`SqlCacheAdapter`) implementing `CachePort` over SQLite and PostgreSQL."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlmodel import col

from arodonata.adapters.storage.database import DatabaseManager
from arodonata.adapters.storage.tables import (
    AccessRuleRecord,
    AssetRecord,
    CPObjectRecord,
    CPServiceRecord,
    DomainRecord,
    DomainSyncStateRecord,
    HttpsRuleRecord,
    NatRuleRecord,
    RulebaseLayerRecord,
    RulebasePackageLayerRecord,
    RulebaseSectionRecord,
    SIDCacheRecord,
    ThreatRuleRecord,
    _ensure_utc,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import SyncScope, SyncStatus, utc_now
from arodonata.core.models.domains import DomainInfo, DomainSyncState, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.core.telemetry import span_attrs, traced


def _record_to_domain(rec: DomainRecord) -> DomainInfo:
    return DomainInfo(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        uid=rec.uid,
        name=rec.name,
        domain_type=rec.domain_type,
        active_ip=rec.active_ip,
        active_mds_ip=rec.active_mds_ip,
        standby_ips=list(rec.standby_ips or []),
        servers=list(rec.servers or []),
        is_global=bool(rec.is_global),
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _record_to_sid_entry(rec: SIDCacheRecord) -> SIDCacheEntry:
    return SIDCacheEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        sid=rec.sid,
        server_ip=rec.server_ip,
        session_uid=rec.session_uid,
        created_at=_ensure_utc(rec.created_at) or utc_now(),
        last_used_at=_ensure_utc(rec.last_used_at) or utc_now(),
        expires_at=_ensure_utc(rec.expires_at),
    )


def _record_to_sync_state(rec: DomainSyncStateRecord) -> DomainSyncState:
    return DomainSyncState(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        scope=rec.scope,  # type: ignore[arg-type]
        item_type=rec.item_type,
        last_published_at=_ensure_utc(rec.last_published_at),
        last_session_uid=rec.last_session_uid,
        synced_at=_ensure_utc(rec.synced_at),
        status=rec.status,  # type: ignore[arg-type]
        object_count=rec.object_count,
        last_error=rec.last_error,
    )


def _record_to_cp_object(rec: CPObjectRecord) -> CPObject:
    return CPObject(
        id=rec.id,
        uid=rec.uid,
        name=rec.name,
        type=rec.type,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        original_domain=rec.original_domain,
        ipv4_address=rec.ipv4_address,
        ipv6_address=rec.ipv6_address,
        subnet4=rec.subnet4,
        mask_length4=rec.mask_length4,
        subnet_mask=rec.subnet_mask,
        ipv4_address_first=rec.ipv4_address_first,
        ipv4_address_last=rec.ipv4_address_last,
        fqdn=rec.fqdn,
        is_sub_domain=rec.is_sub_domain,
        members=list(rec.members or []),
        comments=rec.comments,
        color=rec.color,
        tags=list(rec.tags or []),
        nat_settings=dict(rec.nat_settings or {}),
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _cp_object_to_record(obj: CPObject) -> CPObjectRecord:
    return CPObjectRecord(
        id=obj.id or f"{obj.mgmt_name}:{obj.domain_name}:{obj.uid}",
        uid=obj.uid,
        name=obj.name,
        type=obj.type,
        mgmt_name=obj.mgmt_name,
        domain_name=obj.domain_name,
        original_domain=obj.original_domain or obj.domain_name,
        ipv4_address=obj.ipv4_address,
        ipv6_address=obj.ipv6_address,
        subnet4=obj.subnet4,
        mask_length4=obj.mask_length4,
        subnet_mask=obj.subnet_mask,
        ipv4_address_first=obj.ipv4_address_first,
        ipv4_address_last=obj.ipv4_address_last,
        fqdn=obj.fqdn,
        is_sub_domain=obj.is_sub_domain,
        members=list(obj.members),
        comments=obj.comments,
        color=obj.color,
        tags=list(obj.tags),
        nat_settings=dict(obj.nat_settings),
        raw_data=dict(obj.raw_data),
        updated_at=obj.updated_at,
    )


def _record_to_cp_service(rec: CPServiceRecord) -> CPService:
    return CPService(
        id=rec.id,
        uid=rec.uid,
        name=rec.name,
        type=rec.type,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        original_domain=rec.original_domain,
        port=rec.port,
        protocol=rec.protocol,
        icmp_type=rec.icmp_type,
        icmp_code=rec.icmp_code,
        members=list(rec.members or []),
        session_timeout=rec.session_timeout,
        match_for_any=rec.match_for_any,
        comments=rec.comments,
        color=rec.color,
        tags=list(rec.tags or []),
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _cp_service_to_record(svc: CPService) -> CPServiceRecord:
    return CPServiceRecord(
        id=svc.id or f"{svc.mgmt_name}:{svc.domain_name}:{svc.uid}",
        uid=svc.uid,
        name=svc.name,
        type=svc.type,
        mgmt_name=svc.mgmt_name,
        domain_name=svc.domain_name,
        original_domain=svc.original_domain or svc.domain_name,
        port=svc.port,
        protocol=svc.protocol,
        icmp_type=svc.icmp_type,
        icmp_code=svc.icmp_code,
        members=list(svc.members),
        session_timeout=svc.session_timeout,
        match_for_any=svc.match_for_any,
        comments=svc.comments,
        color=svc.color,
        tags=list(svc.tags),
        raw_data=dict(svc.raw_data),
        updated_at=svc.updated_at,
    )


def _record_to_asset(rec: AssetRecord) -> Asset:
    return Asset(
        id=rec.id,
        uid=rec.uid,
        name=rec.name,
        type=rec.type,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        ipv4_address=rec.ipv4_address,
        ipv6_address=rec.ipv6_address,
        version=rec.version,
        os_name=rec.os_name,
        hardware=rec.hardware,
        sic_status=rec.sic_status,
        parent_uid=rec.parent_uid,
        parent_name=rec.parent_name,
        member_uids=list(rec.member_uids or []),
        virtual_system_uids=list(rec.virtual_system_uids or []),
        interfaces=list(rec.interfaces or []),
        network_security_blades=dict(rec.network_security_blades or {}),
        comments=rec.comments,
        color=rec.color,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _asset_to_record(asset: Asset) -> AssetRecord:
    return AssetRecord(
        id=asset.id or f"{asset.mgmt_name}:{asset.domain_name}:{asset.uid}",
        uid=asset.uid,
        name=asset.name,
        type=asset.type,
        mgmt_name=asset.mgmt_name,
        domain_name=asset.domain_name,
        ipv4_address=asset.ipv4_address,
        ipv6_address=asset.ipv6_address,
        version=asset.version,
        os_name=asset.os_name,
        hardware=asset.hardware,
        sic_status=asset.sic_status,
        parent_uid=asset.parent_uid,
        parent_name=asset.parent_name,
        member_uids=list(asset.member_uids),
        virtual_system_uids=list(asset.virtual_system_uids),
        interfaces=list(asset.interfaces),
        network_security_blades=dict(asset.network_security_blades),
        comments=asset.comments,
        color=asset.color,
        raw_data=dict(asset.raw_data),
        updated_at=asset.updated_at,
    )


class SqlCacheAdapter:
    """SQLAlchemy/SQLModel cache adapter implementing `CachePort`."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    @property
    def db(self) -> DatabaseManager:
        """Return the underlying `DatabaseManager`."""
        return self._db

    # ------------------------------------------------------------------
    # Domains (`domains`)
    # ------------------------------------------------------------------

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
        """Insert or update domain rows in `domains`."""
        if not domains:
            return
        span_attrs(count=len(domains))
        async with self._db.session() as session:
            for dom in domains:
                rec = DomainRecord(
                    id=dom.id or f"{dom.mgmt_name}:{dom.name}",
                    mgmt_name=dom.mgmt_name,
                    uid=dom.uid,
                    name=dom.name,
                    domain_type=dom.domain_type,
                    active_ip=dom.active_ip,
                    active_mds_ip=dom.active_mds_ip,
                    standby_ips=list(dom.standby_ips),
                    servers=list(dom.servers),
                    is_global=dom.is_global or dom.name == "Global",
                    raw_data=dict(dom.raw_data),
                    updated_at=dom.updated_at,
                )
                await session.merge(rec)
            await session.commit()

    # ------------------------------------------------------------------
    # Shared Read-Only Session Cache (`sid_cache`)
    # ------------------------------------------------------------------

    @traced
    async def get_sid(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> SIDCacheEntry | None:
        """Fetch a cached shared read-only session entry for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        key = f"{mgmt_name}:{domain_name}"
        async with self._db.session() as session:
            rec = await session.get(SIDCacheRecord, key)
            return _record_to_sid_entry(rec) if rec is not None else None

    @traced
    async def upsert_sid(self, entry: SIDCacheEntry) -> None:
        """Insert or update a shared read-only session entry in `sid_cache`."""
        span_attrs(mgmt_name=entry.mgmt_name, domain=entry.domain_name, server_ip=entry.server_ip)
        async with self._db.session() as session:
            rec = SIDCacheRecord(
                id=entry.id or f"{entry.mgmt_name}:{entry.domain_name}",
                mgmt_name=entry.mgmt_name,
                domain_name=entry.domain_name,
                sid=entry.sid,
                server_ip=entry.server_ip,
                session_uid=entry.session_uid,
                created_at=entry.created_at,
                last_used_at=entry.last_used_at,
                expires_at=entry.expires_at,
            )
            await session.merge(rec)
            await session.commit()

    @traced
    async def evict_sid(self, mgmt_name: str, domain_name: str) -> bool:
        """Remove the cached SID for `(mgmt_name, domain_name)` immediately."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        key = f"{mgmt_name}:{domain_name}"
        async with self._db.session() as session:
            result = await session.execute(
                delete(SIDCacheRecord).where(SIDCacheRecord.id == key)  # type: ignore[arg-type]
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

    # ------------------------------------------------------------------
    # Unified Domain Sync State (`domain_sync_state`)
    # ------------------------------------------------------------------

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
        """Insert or update a `DomainSyncState` row in `domain_sync_state`."""
        span_attrs(
            mgmt_name=state.mgmt_name,
            domain=state.domain_name,
            scope=state.scope,
            item_type=state.item_type,
            status=state.status,
        )
        async with self._db.session() as session:
            rec = DomainSyncStateRecord(
                id=state.id
                or DomainSyncState.make_id(state.mgmt_name, state.domain_name, state.scope, state.item_type),
                mgmt_name=state.mgmt_name,
                domain_name=state.domain_name,
                scope=state.scope,
                item_type=state.item_type,
                last_published_at=state.last_published_at,
                last_session_uid=state.last_session_uid,
                synced_at=state.synced_at,
                status=state.status,
                object_count=state.object_count,
                last_error=state.last_error,
            )
            await session.merge(rec)
            await session.commit()

    # ------------------------------------------------------------------
    # Network Objects (`arodonata_objects`)
    # ------------------------------------------------------------------

    @traced
    async def get_objects(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPObject]:
        """Query cached network objects from `arodonata_objects`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=list(types) if types else None)
        async with self._db.session() as session:
            stmt = select(CPObjectRecord)
            if mgmt_name is not None:
                stmt = stmt.where(CPObjectRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(CPObjectRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if types is not None:
                if not types:
                    return []
                stmt = stmt.where(CPObjectRecord.type.in_(list(types)))  # type: ignore[attr-defined]
            if names is not None:
                if not names:
                    return []
                stmt = stmt.where(CPObjectRecord.name.in_(list(names)))  # type: ignore[attr-defined]
            if uids is not None:
                if not uids:
                    return []
                stmt = stmt.where(CPObjectRecord.uid.in_(list(uids)))  # type: ignore[attr-defined]
            stmt = stmt.order_by(CPObjectRecord.name, CPObjectRecord.uid)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_cp_object(r) for r in rows]

    @traced
    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        uid: str,
    ) -> CPObject | None:
        """Fetch a single cached `CPObject` by `(mgmt_name, domain_name, uid)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, uid=uid)
        key = f"{mgmt_name}:{domain_name}:{uid}"
        async with self._db.session() as session:
            rec = await session.get(CPObjectRecord, key)
            return _record_to_cp_object(rec) if rec is not None else None

    @traced
    async def replace_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        objects: Sequence[CPObject],
        *,
        types: Sequence[str],
    ) -> int:
        """Atomically replace objects of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        type_list = list(types)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=type_list, count=len(objects))
        if not type_list:
            return 0
        type_set = set(type_list)
        filtered_objects = [o for o in objects if o.type in type_set]

        async with self._db.session() as session:
            await session.execute(
                delete(CPObjectRecord).where(
                    CPObjectRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPObjectRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPObjectRecord.type.in_(type_list),  # type: ignore[attr-defined]
                )
            )
            for obj in filtered_objects:
                session.add(_cp_object_to_record(obj))
            await session.commit()
        return len(filtered_objects)

    @traced
    async def upsert_objects(self, objects: Sequence[CPObject]) -> int:
        """Insert or update `CPObject` rows in `arodonata_objects`."""
        if not objects:
            return 0
        span_attrs(count=len(objects))
        async with self._db.session() as session:
            for obj in objects:
                await session.merge(_cp_object_to_record(obj))
            await session.commit()
        return len(objects)

    @traced
    async def delete_objects_by_uids(
        self,
        mgmt_name: str,
        domain_name: str,
        uids: Sequence[str],
    ) -> int:
        """Delete `CPObject` rows matching `uids` in `(mgmt_name, domain_name)`."""
        uid_list = list(uids)
        if not uid_list:
            return 0
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, count=len(uid_list))
        async with self._db.session() as session:
            result = await session.execute(
                delete(CPObjectRecord).where(
                    CPObjectRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPObjectRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPObjectRecord.uid.in_(uid_list),  # type: ignore[attr-defined]
                )
            )
            await session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Service Objects (`arodonata_services`)
    # ------------------------------------------------------------------

    @traced
    async def get_services(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPService]:
        """Query cached service objects from `arodonata_services`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=list(types) if types else None)
        async with self._db.session() as session:
            stmt = select(CPServiceRecord)
            if mgmt_name is not None:
                stmt = stmt.where(CPServiceRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(CPServiceRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if types is not None:
                if not types:
                    return []
                stmt = stmt.where(CPServiceRecord.type.in_(list(types)))  # type: ignore[attr-defined]
            if names is not None:
                if not names:
                    return []
                stmt = stmt.where(CPServiceRecord.name.in_(list(names)))  # type: ignore[attr-defined]
            if uids is not None:
                if not uids:
                    return []
                stmt = stmt.where(CPServiceRecord.uid.in_(list(uids)))  # type: ignore[attr-defined]
            stmt = stmt.order_by(CPServiceRecord.name, CPServiceRecord.uid)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_cp_service(r) for r in rows]

    @traced
    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        uid: str,
    ) -> CPService | None:
        """Fetch a single cached `CPService` by `(mgmt_name, domain_name, uid)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, uid=uid)
        key = f"{mgmt_name}:{domain_name}:{uid}"
        async with self._db.session() as session:
            rec = await session.get(CPServiceRecord, key)
            return _record_to_cp_service(rec) if rec is not None else None

    @traced
    async def replace_domain_services(
        self,
        mgmt_name: str,
        domain_name: str,
        services: Sequence[CPService],
        *,
        types: Sequence[str],
    ) -> int:
        """Atomically replace services of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        type_list = list(types)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=type_list, count=len(services))
        if not type_list:
            return 0
        type_set = set(type_list)
        filtered_services = [s for s in services if s.type in type_set]

        async with self._db.session() as session:
            await session.execute(
                delete(CPServiceRecord).where(
                    CPServiceRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPServiceRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPServiceRecord.type.in_(type_list),  # type: ignore[attr-defined]
                )
            )
            for svc in filtered_services:
                session.add(_cp_service_to_record(svc))
            await session.commit()
        return len(filtered_services)

    @traced
    async def upsert_services(self, services: Sequence[CPService]) -> int:
        """Insert or update `CPService` rows in `arodonata_services`."""
        if not services:
            return 0
        span_attrs(count=len(services))
        async with self._db.session() as session:
            for svc in services:
                await session.merge(_cp_service_to_record(svc))
            await session.commit()
        return len(services)

    @traced
    async def delete_services_by_uids(
        self,
        mgmt_name: str,
        domain_name: str,
        uids: Sequence[str],
    ) -> int:
        """Delete `CPService` rows matching `uids` in `(mgmt_name, domain_name)`."""
        uid_list = list(uids)
        if not uid_list:
            return 0
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, count=len(uid_list))
        async with self._db.session() as session:
            result = await session.execute(
                delete(CPServiceRecord).where(
                    CPServiceRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPServiceRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPServiceRecord.uid.in_(uid_list),  # type: ignore[attr-defined]
                )
            )
            await session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Assets (`assets`)
    # ------------------------------------------------------------------

    @traced
    async def get_assets(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
    ) -> list[Asset]:
        """Query cached gateway/cluster/VSX/server assets from `assets`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=list(types) if types else None)
        async with self._db.session() as session:
            stmt = select(AssetRecord)
            if mgmt_name is not None:
                stmt = stmt.where(AssetRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(AssetRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if types is not None:
                if not types:
                    return []
                stmt = stmt.where(AssetRecord.type.in_(list(types)))  # type: ignore[attr-defined]
            stmt = stmt.order_by(AssetRecord.name, AssetRecord.uid)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_asset(r) for r in rows]

    @traced
    async def replace_domain_assets(
        self,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
    ) -> int:
        """Atomically replace all cached assets for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, count=len(assets))
        async with self._db.session() as session:
            await session.execute(
                delete(AssetRecord).where(
                    AssetRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    AssetRecord.domain_name == domain_name,  # type: ignore[arg-type]
                )
            )
            for asset in assets:
                session.add(_asset_to_record(asset))
            await session.commit()
        return len(assets)

    # ------------------------------------------------------------------
    # Rulebase Snapshot (`rulebase_*`)
    # ------------------------------------------------------------------

    @traced
    async def replace_domain_rulebase(self, snapshot: DomainRulebaseSnapshot) -> None:
        """Atomically replace all `rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`."""
        mgmt = snapshot.mgmt_name
        dom = snapshot.domain_name
        span_attrs(
            mgmt_name=mgmt,
            domain=dom,
            layers=len(snapshot.layers),
            access_rules=len(snapshot.access_rules),
            nat_rules=len(snapshot.nat_rules),
        )

        async with self._db.session() as session:
            for model_cls in (
                RulebasePackageLayerRecord,
                RulebaseLayerRecord,
                RulebaseSectionRecord,
                AccessRuleRecord,
                NatRuleRecord,
                HttpsRuleRecord,
                ThreatRuleRecord,
            ):
                await session.execute(
                    delete(model_cls).where(
                        model_cls.mgmt_name == mgmt,  # type: ignore[arg-type]
                        model_cls.domain_name == dom,  # type: ignore[arg-type]
                    )
                )

            for pkg_layer in snapshot.package_layers:
                session.add(
                    RulebasePackageLayerRecord(
                        id=pkg_layer.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        package_uid=pkg_layer.package_uid,
                        package_name=pkg_layer.package_name,
                        rulebase_type=pkg_layer.rulebase_type,
                        layer_uid=pkg_layer.layer_uid,
                        layer_name=pkg_layer.layer_name,
                        position=pkg_layer.position,
                        raw_data=dict(pkg_layer.raw_data),
                        updated_at=pkg_layer.updated_at,
                    )
                )

            for layer in snapshot.layers:
                session.add(
                    RulebaseLayerRecord(
                        id=layer.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        uid=layer.uid,
                        name=layer.name,
                        rulebase_type=layer.rulebase_type,
                        parent_layer_uid=layer.parent_layer_uid,
                        parent_rule_uid=layer.parent_rule_uid,
                        is_global=layer.is_global,
                        shared=layer.shared,
                        implicit_cleanup_action=layer.implicit_cleanup_action,
                        raw_data=dict(layer.raw_data),
                        updated_at=layer.updated_at,
                    )
                )

            for sec in snapshot.sections:
                session.add(
                    RulebaseSectionRecord(
                        id=sec.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        layer_uid=sec.layer_uid,
                        layer_name=sec.layer_name,
                        rulebase_type=sec.rulebase_type,
                        uid=sec.uid,
                        name=sec.name,
                        position=sec.position,
                        from_rule=sec.from_rule,
                        to_rule=sec.to_rule,
                        rule_uids=list(sec.rule_uids),
                        raw_data=dict(sec.raw_data),
                        updated_at=sec.updated_at,
                    )
                )

            for rule in snapshot.access_rules:
                session.add(
                    AccessRuleRecord(
                        id=rule.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        layer_uid=rule.layer_uid,
                        layer_name=rule.layer_name,
                        section_uid=rule.section_uid,
                        section_name=rule.section_name,
                        uid=rule.uid,
                        name=rule.name,
                        rule_type=rule.rule_type,
                        position=rule.position,
                        rule_number=rule.rule_number,
                        enabled=rule.enabled,
                        action=rule.action,
                        inline_layer_uid=rule.inline_layer_uid,
                        inline_layer_name=rule.inline_layer_name,
                        placeholder_domain_layer_uid=rule.placeholder_domain_layer_uid,
                        source=list(rule.source),
                        destination=list(rule.destination),
                        service=list(rule.service),
                        source_negate=rule.source_negate,
                        destination_negate=rule.destination_negate,
                        service_negate=rule.service_negate,
                        track=rule.track,
                        install_on=list(rule.install_on),
                        comments=rule.comments,
                        raw_data=dict(rule.raw_data),
                        updated_at=rule.updated_at,
                    )
                )

            for nat_rule in snapshot.nat_rules:
                session.add(
                    NatRuleRecord(
                        id=nat_rule.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        package_uid=nat_rule.package_uid,
                        package_name=nat_rule.package_name,
                        section_uid=nat_rule.section_uid,
                        section_name=nat_rule.section_name,
                        uid=nat_rule.uid,
                        name=nat_rule.name,
                        rule_type=nat_rule.rule_type,
                        position=nat_rule.position,
                        rule_number=nat_rule.rule_number,
                        enabled=nat_rule.enabled,
                        method=nat_rule.method,
                        auto_generated=nat_rule.auto_generated,
                        original_source=nat_rule.original_source,
                        original_destination=nat_rule.original_destination,
                        original_service=nat_rule.original_service,
                        translated_source=nat_rule.translated_source,
                        translated_destination=nat_rule.translated_destination,
                        translated_service=nat_rule.translated_service,
                        install_on=list(nat_rule.install_on),
                        comments=nat_rule.comments,
                        raw_data=dict(nat_rule.raw_data),
                        updated_at=nat_rule.updated_at,
                    )
                )

            for https_rule in snapshot.https_rules:
                session.add(
                    HttpsRuleRecord(
                        id=https_rule.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        layer_uid=https_rule.layer_uid,
                        layer_name=https_rule.layer_name,
                        section_uid=https_rule.section_uid,
                        section_name=https_rule.section_name,
                        uid=https_rule.uid,
                        name=https_rule.name,
                        rule_type=https_rule.rule_type,
                        position=https_rule.position,
                        rule_number=https_rule.rule_number,
                        enabled=https_rule.enabled,
                        action=https_rule.action,
                        inline_layer_uid=https_rule.inline_layer_uid,
                        source=list(https_rule.source),
                        destination=list(https_rule.destination),
                        service=list(https_rule.service),
                        site_category=list(https_rule.site_category),
                        certificate=https_rule.certificate,
                        track=https_rule.track,
                        install_on=list(https_rule.install_on),
                        comments=https_rule.comments,
                        raw_data=dict(https_rule.raw_data),
                        updated_at=https_rule.updated_at,
                    )
                )

            for threat_rule in snapshot.threat_rules:
                session.add(
                    ThreatRuleRecord(
                        id=threat_rule.id,
                        mgmt_name=mgmt,
                        domain_name=dom,
                        layer_uid=threat_rule.layer_uid,
                        layer_name=threat_rule.layer_name,
                        section_uid=threat_rule.section_uid,
                        section_name=threat_rule.section_name,
                        uid=threat_rule.uid,
                        name=threat_rule.name,
                        rule_type=threat_rule.rule_type,
                        position=threat_rule.position,
                        rule_number=threat_rule.rule_number,
                        enabled=threat_rule.enabled,
                        action=threat_rule.action,
                        protected_scope=list(threat_rule.protected_scope),
                        source=list(threat_rule.source),
                        destination=list(threat_rule.destination),
                        service=list(threat_rule.service),
                        track=threat_rule.track,
                        install_on=list(threat_rule.install_on),
                        comments=threat_rule.comments,
                        raw_data=dict(threat_rule.raw_data),
                        updated_at=threat_rule.updated_at,
                    )
                )

            await session.commit()

    @traced
    async def get_domain_rulebase(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            pkg_rows = (
                (
                    await session.execute(
                        select(RulebasePackageLayerRecord)
                        .where(
                            RulebasePackageLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebasePackageLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(
                            col(RulebasePackageLayerRecord.package_name),
                            col(RulebasePackageLayerRecord.position),
                        )
                    )
                )
                .scalars()
                .all()
            )
            layer_rows = (
                (
                    await session.execute(
                        select(RulebaseLayerRecord)
                        .where(
                            RulebaseLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebaseLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(RulebaseLayerRecord.name))
                    )
                )
                .scalars()
                .all()
            )
            sec_rows = (
                (
                    await session.execute(
                        select(RulebaseSectionRecord)
                        .where(
                            RulebaseSectionRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebaseSectionRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(
                            col(RulebaseSectionRecord.layer_uid),
                            col(RulebaseSectionRecord.position),
                        )
                    )
                )
                .scalars()
                .all()
            )
            access_rows = (
                (
                    await session.execute(
                        select(AccessRuleRecord)
                        .where(
                            AccessRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            AccessRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(AccessRuleRecord.layer_uid), col(AccessRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            nat_rows = (
                (
                    await session.execute(
                        select(NatRuleRecord)
                        .where(
                            NatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            NatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(NatRuleRecord.package_uid), col(NatRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            https_rows = (
                (
                    await session.execute(
                        select(HttpsRuleRecord)
                        .where(
                            HttpsRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            HttpsRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(HttpsRuleRecord.layer_uid), col(HttpsRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            threat_rows = (
                (
                    await session.execute(
                        select(ThreatRuleRecord)
                        .where(
                            ThreatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            ThreatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(ThreatRuleRecord.layer_uid), col(ThreatRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )

        return DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            package_layers=[
                RulebasePackageLayerEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    package_uid=r.package_uid,
                    package_name=r.package_name,
                    rulebase_type=r.rulebase_type,  # type: ignore[arg-type]
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    position=r.position,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in pkg_rows
            ],
            layers=[
                RulebaseLayerEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    uid=r.uid,
                    name=r.name,
                    rulebase_type=r.rulebase_type,  # type: ignore[arg-type]
                    parent_layer_uid=r.parent_layer_uid,
                    parent_rule_uid=r.parent_rule_uid,
                    is_global=r.is_global,
                    shared=r.shared,
                    implicit_cleanup_action=r.implicit_cleanup_action,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in layer_rows
            ],
            sections=[
                RulebaseSectionEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    rulebase_type=r.rulebase_type,  # type: ignore[arg-type]
                    uid=r.uid,
                    name=r.name,
                    position=r.position,
                    from_rule=r.from_rule,
                    to_rule=r.to_rule,
                    rule_uids=list(r.rule_uids or []),
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in sec_rows
            ],
            access_rules=[
                AccessRuleEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    section_uid=r.section_uid,
                    section_name=r.section_name,
                    uid=r.uid,
                    name=r.name,
                    rule_type=r.rule_type,
                    position=r.position,
                    rule_number=r.rule_number,
                    enabled=r.enabled,
                    action=r.action,
                    inline_layer_uid=r.inline_layer_uid,
                    inline_layer_name=r.inline_layer_name,
                    placeholder_domain_layer_uid=r.placeholder_domain_layer_uid,
                    source=list(r.source or []),
                    destination=list(r.destination or []),
                    service=list(r.service or []),
                    source_negate=r.source_negate,
                    destination_negate=r.destination_negate,
                    service_negate=r.service_negate,
                    track=r.track,
                    install_on=list(r.install_on or []),
                    comments=r.comments,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in access_rows
            ],
            nat_rules=[
                NatRuleEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    package_uid=r.package_uid,
                    package_name=r.package_name,
                    section_uid=r.section_uid,
                    section_name=r.section_name,
                    uid=r.uid,
                    name=r.name,
                    rule_type=r.rule_type,
                    position=r.position,
                    rule_number=r.rule_number,
                    enabled=r.enabled,
                    method=r.method,
                    auto_generated=r.auto_generated,
                    original_source=r.original_source,
                    original_destination=r.original_destination,
                    original_service=r.original_service,
                    translated_source=r.translated_source,
                    translated_destination=r.translated_destination,
                    translated_service=r.translated_service,
                    install_on=list(r.install_on or []),
                    comments=r.comments,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in nat_rows
            ],
            https_rules=[
                HttpsRuleEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    section_uid=r.section_uid,
                    section_name=r.section_name,
                    uid=r.uid,
                    name=r.name,
                    rule_type=r.rule_type,
                    position=r.position,
                    rule_number=r.rule_number,
                    enabled=r.enabled,
                    action=r.action,
                    inline_layer_uid=r.inline_layer_uid,
                    source=list(r.source or []),
                    destination=list(r.destination or []),
                    service=list(r.service or []),
                    site_category=list(r.site_category or []),
                    certificate=r.certificate,
                    track=r.track,
                    install_on=list(r.install_on or []),
                    comments=r.comments,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in https_rows
            ],
            threat_rules=[
                ThreatRuleEntry(
                    id=r.id,
                    mgmt_name=r.mgmt_name,
                    domain_name=r.domain_name,
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    section_uid=r.section_uid,
                    section_name=r.section_name,
                    uid=r.uid,
                    name=r.name,
                    rule_type=r.rule_type,
                    position=r.position,
                    rule_number=r.rule_number,
                    enabled=r.enabled,
                    action=r.action,
                    protected_scope=list(r.protected_scope or []),
                    source=list(r.source or []),
                    destination=list(r.destination or []),
                    service=list(r.service or []),
                    track=r.track,
                    install_on=list(r.install_on or []),
                    comments=r.comments,
                    raw_data=dict(r.raw_data or {}),
                    updated_at=_ensure_utc(r.updated_at) or utc_now(),
                )
                for r in threat_rows
            ],
        )


__all__ = ["SqlCacheAdapter", "SyncStatus", "RulebaseType"]
