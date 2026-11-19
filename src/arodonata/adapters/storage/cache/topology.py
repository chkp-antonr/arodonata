"""Gateway interface topology and administrator annotation operations for `SqlCacheAdapter`."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlmodel import col

from arodonata.adapters.storage.cache._base import SqlCacheBase
from arodonata.adapters.storage.cache.mappers import (
    _record_to_topology_annotation,
    _record_to_topology_entry,
    _topology_annotation_to_row,
    _topology_entry_to_row,
)
from arodonata.adapters.storage.tables import GatewayTopologyRecord, TopologyAnnotationRecord
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.topology import GatewayTopologyEntry, TopologyAnnotation
from arodonata.core.telemetry import span_attrs, traced


class TopologyCacheMixin(SqlCacheBase):
    """Implements `TopologyCachePort` over SQL storage."""

    @traced
    async def get_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        gateway_uids: Sequence[str] | None = None,
        gateway_names: Sequence[str] | None = None,
        topology_zone: str | None = None,
        source_types: Sequence[str] | None = None,
    ) -> list[GatewayTopologyEntry]:
        """Query cached gateway interface topology intervals from `arodonata_gateway_topology`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, topology_zone=topology_zone)
        async with self._db.session() as session:
            stmt = select(GatewayTopologyRecord)
            if mgmt_name is not None:
                stmt = stmt.where(GatewayTopologyRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(GatewayTopologyRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if gateway_uids is not None:
                if not gateway_uids:
                    return []
                stmt = stmt.where(GatewayTopologyRecord.gateway_uid.in_(list(gateway_uids)))  # type: ignore[attr-defined]
            if gateway_names is not None:
                if not gateway_names:
                    return []
                stmt = stmt.where(GatewayTopologyRecord.gateway_name.in_(list(gateway_names)))  # type: ignore[attr-defined]
            if topology_zone is not None:
                stmt = stmt.where(GatewayTopologyRecord.topology_zone == topology_zone)  # type: ignore[arg-type]
            if source_types is not None:
                if not source_types:
                    return []
                stmt = stmt.where(GatewayTopologyRecord.source_type.in_(list(source_types)))  # type: ignore[attr-defined]
            stmt = stmt.order_by(
                col(GatewayTopologyRecord.mgmt_name),
                col(GatewayTopologyRecord.domain_name),
                col(GatewayTopologyRecord.gateway_name),
                col(GatewayTopologyRecord.interface_name),
                col(GatewayTopologyRecord.ip_first_int),
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_topology_entry(r) for r in rows]

    @traced
    async def replace_domain_topology(
        self,
        mgmt_name: str,
        domain_name: str,
        entries: Sequence[GatewayTopologyEntry],
        *,
        gateway_uids: Sequence[str] | None = None,
        source_types: Sequence[str] | None = None,
        active_gateway_uids: Sequence[str] | None = None,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace cached gateway topology entries for `(mgmt_name, domain_name)` (optionally scoped by `gateway_uids` and `source_types`)."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, count=len(entries))
        # Deduplicate entries by primary key `id` to prevent duplicate PK errors within the same domain batch.
        deduped: dict[str, GatewayTopologyEntry] = {entry.id: entry for entry in entries}

        async with self._db.session() as session:
            del_stmt = delete(GatewayTopologyRecord).where(
                GatewayTopologyRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                GatewayTopologyRecord.domain_name == domain_name,  # type: ignore[arg-type]
            )
            if gateway_uids is not None:
                if gateway_uids:
                    del_stmt = del_stmt.where(GatewayTopologyRecord.gateway_uid.in_(list(gateway_uids)))  # type: ignore[attr-defined]
                else:
                    if sync_states:
                        await self._upsert_sync_states_in_session(session, sync_states)
                        await session.commit()
                    return 0
            if source_types is not None:
                if source_types:
                    del_stmt = del_stmt.where(GatewayTopologyRecord.source_type.in_(list(source_types)))  # type: ignore[attr-defined]
                else:
                    if sync_states:
                        await self._upsert_sync_states_in_session(session, sync_states)
                        await session.commit()
                    return 0

            await session.execute(del_stmt)

            # On a full domain refresh (`gateway_uids is None`) scoped by `source_types` (e.g. `STATIC_TOPOLOGY_SOURCES`),
            # also prune orphan rows (such as `LIVE_ROUTE_SOURCES`) for gateways that no longer exist in the domain.
            if gateway_uids is None and source_types is not None:
                valid_gw_uids = (
                    list(active_gateway_uids)
                    if active_gateway_uids is not None
                    else sorted({e.gateway_uid for e in deduped.values()})
                )
                if valid_gw_uids:
                    await session.execute(
                        delete(GatewayTopologyRecord).where(
                            GatewayTopologyRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            GatewayTopologyRecord.domain_name == domain_name,  # type: ignore[arg-type]
                            GatewayTopologyRecord.gateway_uid.notin_(valid_gw_uids),  # type: ignore[attr-defined]
                        )
                    )
                else:
                    await session.execute(
                        delete(GatewayTopologyRecord).where(
                            GatewayTopologyRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            GatewayTopologyRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                    )

            deduped_entries = list(deduped.values())
            await self._insert_rows_batched(session, GatewayTopologyRecord, deduped_entries, _topology_entry_to_row)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(deduped)

    @traced
    async def upsert_gateway_topology(
        self,
        entries: Sequence[GatewayTopologyEntry],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `GatewayTopologyEntry` rows in `arodonata_gateway_topology`."""
        if not entries and not sync_states:
            return 0
        span_attrs(count=len(entries))
        rows = [_topology_entry_to_row(entry) for entry in entries]
        async with self._db.session() as session:
            await self._dialect_upsert(session, GatewayTopologyRecord, rows)
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(entries)

    @traced
    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        gateway_uids: Sequence[str] | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Query persistent administrator topology annotations from `arodonata_topology_annotations`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            stmt = select(TopologyAnnotationRecord)
            if mgmt_name is not None:
                stmt = stmt.where(TopologyAnnotationRecord.mgmt_name == mgmt_name)  # type: ignore[arg-type]
            if domain_name is not None:
                stmt = stmt.where(TopologyAnnotationRecord.domain_name == domain_name)  # type: ignore[arg-type]
            if gateway_uids is not None:
                if not gateway_uids:
                    return []
                stmt = stmt.where(TopologyAnnotationRecord.gateway_uid.in_(list(gateway_uids)))  # type: ignore[attr-defined]
            if interface_name is not None:
                stmt = stmt.where(TopologyAnnotationRecord.interface_name == interface_name)  # type: ignore[arg-type]
            stmt = stmt.order_by(
                col(TopologyAnnotationRecord.mgmt_name),
                col(TopologyAnnotationRecord.domain_name),
                col(TopologyAnnotationRecord.gateway_uid),
                col(TopologyAnnotationRecord.interface_name),
                col(TopologyAnnotationRecord.cidr_or_range),
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_record_to_topology_annotation(r) for r in rows]

    @traced
    async def upsert_topology_annotations(
        self,
        annotations: Sequence[TopologyAnnotation],
    ) -> int:
        """Insert or update `TopologyAnnotation` rows in `arodonata_topology_annotations`."""
        if not annotations:
            return 0
        span_attrs(count=len(annotations))
        rows = [_topology_annotation_to_row(ann) for ann in annotations]
        async with self._db.session() as session:
            await self._dialect_upsert(session, TopologyAnnotationRecord, rows)
            await session.commit()
        return len(annotations)

    @traced
    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str],
    ) -> int:
        """Delete `TopologyAnnotation` rows matching `annotation_ids`."""
        clean_ids = [i.strip() for i in annotation_ids if i and i.strip()]
        if not clean_ids:
            return 0
        span_attrs(count=len(clean_ids))
        async with self._db.session() as session:
            res = await session.execute(
                delete(TopologyAnnotationRecord).where(
                    TopologyAnnotationRecord.id.in_(clean_ids)  # type: ignore[attr-defined]
                )
            )
            await session.commit()
            return int(getattr(res, "rowcount", 0) or 0)
