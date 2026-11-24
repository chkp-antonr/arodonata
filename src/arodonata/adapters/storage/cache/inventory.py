"""Objects, services, and gateway/VSX asset CRUD operations for `SqlCacheAdapter`."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select
from sqlmodel import col

from arodonata.adapters.storage.cache._base import SqlCacheBase
from arodonata.adapters.storage.cache.mappers import (
    _asset_to_row,
    _cp_object_to_row,
    _cp_service_to_row,
    _record_to_asset,
    _record_to_cp_object,
    _record_to_cp_service,
)
from arodonata.adapters.storage.tables import AssetRecord, CPObjectRecord, CPServiceRecord
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import expand_asset_types
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.telemetry import span_attrs, traced


class InventoryCacheMixin(SqlCacheBase):
    """Implements `ObjectCachePort`, `ServiceCachePort`, and `AssetCachePort` over SQL storage."""

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
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace objects of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        type_list = list(types)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=type_list, count=len(objects))
        if not type_list:
            return 0
        type_set = set(type_list)
        deduped_objects: dict[str, CPObject] = {
            (o.id or f"{o.mgmt_name}:{o.domain_name}:{o.uid}"): o for o in objects if o.type in type_set
        }
        unique_objects = list(deduped_objects.values())
        del deduped_objects

        async with self._db.session() as session:
            await session.execute(
                delete(CPObjectRecord).where(
                    CPObjectRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPObjectRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPObjectRecord.type.in_(type_list),  # type: ignore[attr-defined]
                )
            )
            await self._insert_rows_batched(session, CPObjectRecord, unique_objects, _cp_object_to_row)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(unique_objects)

    @traced
    async def upsert_objects(
        self,
        objects: Sequence[CPObject],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `CPObject` rows in `arodonata_objects`."""
        if not objects and not sync_states:
            return 0
        span_attrs(count=len(objects))
        rows = [_cp_object_to_row(obj) for obj in objects]
        async with self._db.session() as session:
            await self._dialect_upsert(session, CPObjectRecord, rows)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
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

    @traced
    async def apply_object_diff(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        deleted_uids: Sequence[str] = (),
        objects: Sequence[CPObject] = (),
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically delete `deleted_uids`, upsert `objects`, and update `sync_states` in one transaction."""
        del_list = list(deleted_uids)
        rows = [_cp_object_to_row(obj) for obj in objects]
        if not del_list and not rows and not sync_states:
            return 0
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, deleted=len(del_list), upserted=len(rows))
        async with self._db.session() as session:
            if del_list:
                await session.execute(
                    delete(CPObjectRecord).where(
                        CPObjectRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        CPObjectRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        CPObjectRecord.uid.in_(del_list),  # type: ignore[attr-defined]
                    )
                )
            if rows:
                await self._dialect_upsert(session, CPObjectRecord, rows)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(rows) + len(del_list)

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
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace services of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        type_list = list(types)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=type_list, count=len(services))
        if not type_list:
            return 0
        type_set = set(type_list)
        deduped_services: dict[str, CPService] = {
            (s.id or f"{s.mgmt_name}:{s.domain_name}:{s.uid}"): s for s in services if s.type in type_set
        }
        unique_services = list(deduped_services.values())
        del deduped_services

        async with self._db.session() as session:
            await session.execute(
                delete(CPServiceRecord).where(
                    CPServiceRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    CPServiceRecord.domain_name == domain_name,  # type: ignore[arg-type]
                    CPServiceRecord.type.in_(type_list),  # type: ignore[attr-defined]
                )
            )
            await self._insert_rows_batched(session, CPServiceRecord, unique_services, _cp_service_to_row)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(unique_services)

    @traced
    async def upsert_services(
        self,
        services: Sequence[CPService],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `CPService` rows in `arodonata_services`."""
        if not services and not sync_states:
            return 0
        span_attrs(count=len(services))
        rows = [_cp_service_to_row(svc) for svc in services]
        async with self._db.session() as session:
            await self._dialect_upsert(session, CPServiceRecord, rows)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
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

    @traced
    async def apply_service_diff(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        deleted_uids: Sequence[str] = (),
        services: Sequence[CPService] = (),
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically delete `deleted_uids`, upsert `services`, and update `sync_states` in one transaction."""
        del_list = list(deleted_uids)
        rows = [_cp_service_to_row(svc) for svc in services]
        if not del_list and not rows and not sync_states:
            return 0
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, deleted=len(del_list), upserted=len(rows))
        async with self._db.session() as session:
            if del_list:
                await session.execute(
                    delete(CPServiceRecord).where(
                        CPServiceRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        CPServiceRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        CPServiceRecord.uid.in_(del_list),  # type: ignore[attr-defined]
                    )
                )
            if rows:
                await self._dialect_upsert(session, CPServiceRecord, rows)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(rows) + len(del_list)

    @traced
    async def get_assets(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
    ) -> list[Asset]:
        """Query cached gateway/cluster/VSX/server assets from `arodonata_assets`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, types=list(types) if types else None)
        async with self._db.session() as session:
            stmt = select(AssetRecord)
            if mgmt_name is not None:
                stmt = stmt.where(AssetRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(AssetRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if types is not None:
                expanded_types = expand_asset_types(types)
                if not expanded_types:
                    return []
                lowered_types = [t.lower() for t in expanded_types]
                stmt = stmt.where(func.lower(col(AssetRecord.type)).in_(lowered_types))
            stmt = stmt.order_by(AssetRecord.name, AssetRecord.uid)
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_asset(r) for r in rows]

    @traced
    async def replace_domain_assets(
        self,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace all cached assets for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, count=len(assets))
        deduped_assets: dict[str, Asset] = {(a.id or f"{a.mgmt_name}:{a.domain_name}:{a.uid}"): a for a in assets}
        unique_assets = list(deduped_assets.values())
        del deduped_assets

        async with self._db.session() as session:
            await session.execute(
                delete(AssetRecord).where(
                    AssetRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    AssetRecord.domain_name == domain_name,  # type: ignore[arg-type]
                )
            )
            await self._insert_rows_batched(session, AssetRecord, unique_assets, _asset_to_row)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(unique_assets)

    @traced
    async def upsert_assets(
        self,
        assets: Sequence[Asset],
    ) -> int:
        """Insert or update `Asset` rows in `arodonata_assets`."""
        if not assets:
            return 0
        span_attrs(count=len(assets))
        rows = [_asset_to_row(asset) for asset in assets]
        async with self._db.session() as session:
            await self._dialect_upsert(session, AssetRecord, rows)
            await session.commit()
        return len(assets)
