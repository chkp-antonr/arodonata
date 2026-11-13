"""SQL cache adapter (`SqlCacheAdapter`) implementing `CachePort` over SQLite and PostgreSQL."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from sqlalchemy import Table, delete, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, col

from arodonata.adapters.storage.database import DatabaseManager
from arodonata.adapters.storage.tables import (
    AccessRuleRecord,
    AssetRecord,
    CPObjectRecord,
    CPServiceRecord,
    DomainRecord,
    DomainSyncStateRecord,
    GatewayTopologyRecord,
    HttpsRuleRecord,
    NatRuleRecord,
    RulebaseLayerRecord,
    RulebasePackageLayerRecord,
    RulebaseSectionRecord,
    SIDCacheRecord,
    ThreatRuleRecord,
    TopologyAnnotationRecord,
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
from arodonata.core.models.topology import GatewayTopologyEntry, TopologyAnnotation
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
    now = utc_now()
    created_at = _ensure_utc(rec.created_at) or now
    last_used_at = _ensure_utc(rec.last_used_at) or now
    expires_at = _ensure_utc(rec.expires_at)
    # SQLite stores naive UTC datetimes in some drivers; normalize to UTC
    return SIDCacheEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        sid=rec.sid,
        server_ip=rec.server_ip,
        session_uid=rec.session_uid,
        auth_identity=rec.auth_identity,
        created_at=created_at,
        last_used_at=last_used_at,
        expires_at=expires_at,
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
    raw = dict(rec.raw_data or {})
    raw_url_list = raw.get("url-list") if "url-list" in raw else raw.get("url_list")
    url_list = [str(u) for u in raw_url_list if str(u)] if isinstance(raw_url_list, list) else []
    raw_regex = (
        raw.get("urls-defined-as-regular-expression")
        if "urls-defined-as-regular-expression" in raw
        else raw.get("urls_defined_as_regular_expression")
    )
    return CPObject(
        id=rec.id,
        object_id=rec.object_id or f"{rec.mgmt_name}:{rec.domain_name}:{rec.name}",
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
        primary_category=raw.get("primary-category") or raw.get("primary_category"),
        url_list=url_list,
        urls_defined_as_regular_expression=bool(raw_regex) if raw_regex is not None else None,
        description=str(raw.get("description") or ""),
        members=list(rec.members or []),
        comments=rec.comments,
        color=rec.color,
        tags=list(rec.tags or []),
        nat_settings=dict(rec.nat_settings or {}),
        raw_data=raw,
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _cp_object_to_row(obj: CPObject) -> dict[str, Any]:
    return {
        "id": obj.id or f"{obj.mgmt_name}:{obj.domain_name}:{obj.uid}",
        "object_id": obj.object_id or f"{obj.mgmt_name}:{obj.domain_name}:{obj.name}",
        "uid": obj.uid,
        "name": obj.name,
        "type": obj.type,
        "mgmt_name": obj.mgmt_name,
        "domain_name": obj.domain_name,
        "original_domain": obj.original_domain or obj.domain_name,
        "ipv4_address": obj.ipv4_address,
        "ipv6_address": obj.ipv6_address,
        "subnet4": obj.subnet4,
        "mask_length4": obj.mask_length4,
        "subnet_mask": obj.subnet_mask,
        "ipv4_address_first": obj.ipv4_address_first,
        "ipv4_address_last": obj.ipv4_address_last,
        "fqdn": obj.fqdn,
        "is_sub_domain": obj.is_sub_domain,
        "members": list(obj.members),
        "comments": obj.comments,
        "color": obj.color,
        "tags": list(obj.tags),
        "nat_settings": dict(obj.nat_settings),
        "raw_data": dict(obj.raw_data),
        "updated_at": _ensure_utc(obj.updated_at) or utc_now(),
    }


def _cp_object_to_record(obj: CPObject) -> CPObjectRecord:
    return CPObjectRecord(**_cp_object_to_row(obj))


def _record_to_cp_service(rec: CPServiceRecord) -> CPService:
    return CPService(
        id=rec.id,
        service_id=rec.service_id or f"{rec.mgmt_name}:{rec.domain_name}:{rec.name}",
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


def _cp_service_to_row(svc: CPService) -> dict[str, Any]:
    return {
        "id": svc.id or f"{svc.mgmt_name}:{svc.domain_name}:{svc.uid}",
        "service_id": svc.service_id or f"{svc.mgmt_name}:{svc.domain_name}:{svc.name}",
        "uid": svc.uid,
        "name": svc.name,
        "type": svc.type,
        "mgmt_name": svc.mgmt_name,
        "domain_name": svc.domain_name,
        "original_domain": svc.original_domain or svc.domain_name,
        "port": svc.port,
        "protocol": svc.protocol,
        "icmp_type": svc.icmp_type,
        "icmp_code": svc.icmp_code,
        "members": list(svc.members),
        "session_timeout": svc.session_timeout,
        "match_for_any": svc.match_for_any,
        "comments": svc.comments,
        "color": svc.color,
        "tags": list(svc.tags),
        "raw_data": dict(svc.raw_data),
        "updated_at": _ensure_utc(svc.updated_at) or utc_now(),
    }


def _cp_service_to_record(svc: CPService) -> CPServiceRecord:
    return CPServiceRecord(**_cp_service_to_row(svc))


def _record_to_asset(rec: AssetRecord) -> Asset:
    return Asset(
        id=rec.id,
        asset_id=rec.asset_id or f"{rec.mgmt_name}:{rec.domain_name}:{rec.name}",
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
        parent_id=rec.parent_id,
        parent_asset_id=rec.parent_asset_id,
        member_uids=list(rec.member_uids or []),
        member_asset_ids=list(rec.member_asset_ids or []),
        virtual_system_uids=list(rec.virtual_system_uids or []),
        virtual_system_asset_ids=list(rec.virtual_system_asset_ids or []),
        interfaces=list(rec.interfaces or []),
        network_security_blades=dict(rec.network_security_blades or {}),
        comments=rec.comments,
        color=rec.color,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _asset_to_row(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id or f"{asset.mgmt_name}:{asset.domain_name}:{asset.uid}",
        "asset_id": asset.asset_id or f"{asset.mgmt_name}:{asset.domain_name}:{asset.name}",
        "uid": asset.uid,
        "name": asset.name,
        "type": asset.type,
        "mgmt_name": asset.mgmt_name,
        "domain_name": asset.domain_name,
        "ipv4_address": asset.ipv4_address,
        "ipv6_address": asset.ipv6_address,
        "version": asset.version,
        "os_name": asset.os_name,
        "hardware": asset.hardware,
        "sic_status": asset.sic_status,
        "parent_uid": asset.parent_uid,
        "parent_name": asset.parent_name,
        "parent_id": asset.parent_id,
        "parent_asset_id": asset.parent_asset_id,
        "member_uids": list(asset.member_uids),
        "member_asset_ids": list(asset.member_asset_ids),
        "virtual_system_uids": list(asset.virtual_system_uids),
        "virtual_system_asset_ids": list(asset.virtual_system_asset_ids),
        "interfaces": list(asset.interfaces),
        "network_security_blades": dict(asset.network_security_blades),
        "comments": asset.comments,
        "color": asset.color,
        "raw_data": dict(asset.raw_data),
        "updated_at": _ensure_utc(asset.updated_at) or utc_now(),
    }


def _asset_to_record(asset: Asset) -> AssetRecord:
    return AssetRecord(**_asset_to_row(asset))


def _record_to_topology_entry(rec: GatewayTopologyRecord) -> GatewayTopologyEntry:
    return GatewayTopologyEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        gateway_id=rec.gateway_id,
        gateway_asset_id=rec.gateway_asset_id,
        gateway_uid=rec.gateway_uid,
        gateway_name=rec.gateway_name,
        gateway_type=rec.gateway_type,
        interface_name=rec.interface_name,
        interface_ipv4=rec.interface_ipv4,
        interface_mask_length=rec.interface_mask_length,
        topology_zone=rec.topology_zone,  # type: ignore[arg-type]
        leads_to_dmz=bool(rec.leads_to_dmz),
        anti_spoofing_mode=(rec.anti_spoofing_mode or "unknown"),  # type: ignore[arg-type]
        source_type=rec.source_type,  # type: ignore[arg-type]
        source_ref=rec.source_ref,
        cidr_or_range=rec.cidr_or_range,
        ip_first_int=int(rec.ip_first_int),
        ip_last_int=int(rec.ip_last_int),
        prefix_len=int(rec.prefix_len),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _topology_entry_to_row(entry: GatewayTopologyEntry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "mgmt_name": entry.mgmt_name,
        "domain_name": entry.domain_name,
        "gateway_id": entry.gateway_id,
        "gateway_asset_id": entry.gateway_asset_id,
        "gateway_uid": entry.gateway_uid,
        "gateway_name": entry.gateway_name,
        "gateway_type": entry.gateway_type,
        "interface_name": entry.interface_name,
        "interface_ipv4": entry.interface_ipv4,
        "interface_mask_length": entry.interface_mask_length,
        "topology_zone": entry.topology_zone,
        "leads_to_dmz": entry.leads_to_dmz,
        "anti_spoofing_mode": entry.anti_spoofing_mode,
        "source_type": entry.source_type,
        "source_ref": entry.source_ref,
        "cidr_or_range": entry.cidr_or_range,
        "ip_first_int": int(entry.ip_first_int),
        "ip_last_int": int(entry.ip_last_int),
        "prefix_len": int(entry.prefix_len),
        "updated_at": _ensure_utc(entry.updated_at) or utc_now(),
    }


def _topology_entry_to_record(entry: GatewayTopologyEntry) -> GatewayTopologyRecord:
    return GatewayTopologyRecord(**_topology_entry_to_row(entry))


def _record_to_topology_annotation(rec: TopologyAnnotationRecord) -> TopologyAnnotation:
    return TopologyAnnotation(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        gateway_uid=rec.gateway_uid,
        gateway_name=rec.gateway_name,
        interface_name=rec.interface_name,
        cidr_or_range=rec.cidr_or_range,
        trust_static_topology=rec.trust_static_topology,
        disposition=rec.disposition,  # type: ignore[arg-type]
        topology_zone=rec.topology_zone,  # type: ignore[arg-type]
        zone=rec.zone,
        site=rec.site,
        comment=rec.comment,
        custom_metadata=dict(rec.custom_metadata or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _topology_annotation_to_row(ann: TopologyAnnotation) -> dict[str, Any]:
    return {
        "id": ann.id,
        "mgmt_name": ann.mgmt_name,
        "domain_name": ann.domain_name,
        "gateway_uid": ann.gateway_uid,
        "gateway_name": ann.gateway_name,
        "interface_name": ann.interface_name,
        "cidr_or_range": ann.cidr_or_range,
        "trust_static_topology": ann.trust_static_topology,
        "disposition": ann.disposition,
        "topology_zone": ann.topology_zone,
        "zone": ann.zone,
        "site": ann.site,
        "comment": ann.comment,
        "custom_metadata": dict(ann.custom_metadata),
        "updated_at": _ensure_utc(ann.updated_at) or utc_now(),
    }


def _topology_annotation_to_record(ann: TopologyAnnotation) -> TopologyAnnotationRecord:
    return TopologyAnnotationRecord(**_topology_annotation_to_row(ann))


def _package_layer_to_row(pkg_layer: RulebasePackageLayerEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": pkg_layer.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "package_uid": pkg_layer.package_uid,
        "package_name": pkg_layer.package_name,
        "rulebase_type": pkg_layer.rulebase_type,
        "layer_uid": pkg_layer.layer_uid,
        "layer_name": pkg_layer.layer_name,
        "position": pkg_layer.position,
        "raw_data": dict(pkg_layer.raw_data),
        "updated_at": _ensure_utc(pkg_layer.updated_at) or utc_now(),
    }


def _rulebase_layer_to_row(layer: RulebaseLayerEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": layer.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "uid": layer.uid,
        "name": layer.name,
        "rulebase_type": layer.rulebase_type,
        "parent_layer_uid": layer.parent_layer_uid,
        "parent_rule_uid": layer.parent_rule_uid,
        "is_global": layer.is_global,
        "shared": layer.shared,
        "implicit_cleanup_action": layer.implicit_cleanup_action,
        "raw_data": dict(layer.raw_data),
        "updated_at": _ensure_utc(layer.updated_at) or utc_now(),
    }


def _rulebase_section_to_row(sec: RulebaseSectionEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": sec.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": sec.layer_uid,
        "layer_name": sec.layer_name,
        "rulebase_type": sec.rulebase_type,
        "uid": sec.uid,
        "name": sec.name,
        "position": sec.position,
        "from_rule": sec.from_rule,
        "to_rule": sec.to_rule,
        "rule_uids": list(sec.rule_uids),
        "raw_data": dict(sec.raw_data),
        "updated_at": _ensure_utc(sec.updated_at) or utc_now(),
    }


def _access_rule_to_row(rule: AccessRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": rule.layer_uid,
        "layer_name": rule.layer_name,
        "section_uid": rule.section_uid,
        "section_name": rule.section_name,
        "uid": rule.uid,
        "name": rule.name,
        "rule_type": rule.rule_type,
        "position": rule.position,
        "rule_number": rule.rule_number,
        "enabled": rule.enabled,
        "action": rule.action,
        "inline_layer_uid": rule.inline_layer_uid,
        "inline_layer_name": rule.inline_layer_name,
        "placeholder_domain_layer_uid": rule.placeholder_domain_layer_uid,
        "source": list(rule.source),
        "destination": list(rule.destination),
        "service": list(rule.service),
        "source_negate": rule.source_negate,
        "destination_negate": rule.destination_negate,
        "service_negate": rule.service_negate,
        "track": rule.track,
        "install_on": list(rule.install_on),
        "comments": rule.comments,
        "raw_data": dict(rule.raw_data),
        "updated_at": _ensure_utc(rule.updated_at) or utc_now(),
    }


def _nat_rule_to_row(nat_rule: NatRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": nat_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "package_uid": nat_rule.package_uid,
        "package_name": nat_rule.package_name,
        "section_uid": nat_rule.section_uid,
        "section_name": nat_rule.section_name,
        "uid": nat_rule.uid,
        "name": nat_rule.name,
        "rule_type": nat_rule.rule_type,
        "position": nat_rule.position,
        "rule_number": nat_rule.rule_number,
        "enabled": nat_rule.enabled,
        "method": nat_rule.method,
        "auto_generated": nat_rule.auto_generated,
        "original_source": nat_rule.original_source,
        "original_destination": nat_rule.original_destination,
        "original_service": nat_rule.original_service,
        "translated_source": nat_rule.translated_source,
        "translated_destination": nat_rule.translated_destination,
        "translated_service": nat_rule.translated_service,
        "install_on": list(nat_rule.install_on),
        "comments": nat_rule.comments,
        "raw_data": dict(nat_rule.raw_data),
        "updated_at": _ensure_utc(nat_rule.updated_at) or utc_now(),
    }


def _https_rule_to_row(https_rule: HttpsRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": https_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": https_rule.layer_uid,
        "layer_name": https_rule.layer_name,
        "section_uid": https_rule.section_uid,
        "section_name": https_rule.section_name,
        "uid": https_rule.uid,
        "name": https_rule.name,
        "rule_type": https_rule.rule_type,
        "position": https_rule.position,
        "rule_number": https_rule.rule_number,
        "enabled": https_rule.enabled,
        "action": https_rule.action,
        "inline_layer_uid": https_rule.inline_layer_uid,
        "source": list(https_rule.source),
        "destination": list(https_rule.destination),
        "service": list(https_rule.service),
        "site_category": list(https_rule.site_category),
        "certificate": https_rule.certificate,
        "track": https_rule.track,
        "install_on": list(https_rule.install_on),
        "comments": https_rule.comments,
        "raw_data": dict(https_rule.raw_data),
        "updated_at": _ensure_utc(https_rule.updated_at) or utc_now(),
    }


def _threat_rule_to_row(threat_rule: ThreatRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": threat_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": threat_rule.layer_uid,
        "layer_name": threat_rule.layer_name,
        "section_uid": threat_rule.section_uid,
        "section_name": threat_rule.section_name,
        "uid": threat_rule.uid,
        "name": threat_rule.name,
        "rule_type": threat_rule.rule_type,
        "position": threat_rule.position,
        "rule_number": threat_rule.rule_number,
        "enabled": threat_rule.enabled,
        "action": threat_rule.action,
        "protected_scope": list(threat_rule.protected_scope),
        "source": list(threat_rule.source),
        "destination": list(threat_rule.destination),
        "service": list(threat_rule.service),
        "track": threat_rule.track,
        "install_on": list(threat_rule.install_on),
        "comments": threat_rule.comments,
        "raw_data": dict(threat_rule.raw_data),
        "updated_at": _ensure_utc(threat_rule.updated_at) or utc_now(),
    }


_BATCH_ROWS = 500


class SqlCacheAdapter:
    """SQLAlchemy/SQLModel cache adapter implementing `CachePort`."""

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

        # Deduplicate by primary key preserving the last occurrence so PostgreSQL multi-row
        # ON CONFLICT DO UPDATE never attempts to update the same target row twice in one statement.
        deduped_map: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row_vals in values_list:
            pk_key = tuple(row_vals.get(col_name) for col_name in pk_cols)
            deduped_map[pk_key] = row_vals
        deduped_rows = list(deduped_map.values())

        for start in range(0, len(deduped_rows), _BATCH_ROWS):
            batch = deduped_rows[start : start + _BATCH_ROWS]
            if dialect_name == "postgresql":
                pg_stmt = pg_insert(table).values(batch)
                update_map = {col_name: getattr(pg_stmt.excluded, col_name) for col_name in non_pk_cols}
                await session.execute(pg_stmt.on_conflict_do_update(index_elements=pk_cols, set_=update_map))
            else:
                sq_stmt = sqlite_insert(table).values(batch)
                update_map = {col_name: getattr(sq_stmt.excluded, col_name) for col_name in non_pk_cols}
                await session.execute(sq_stmt.on_conflict_do_update(index_elements=pk_cols, set_=update_map))

    async def _upsert_sync_states_in_session(
        self,
        session: AsyncSession,
        states: Sequence[DomainSyncState],
    ) -> None:
        """Upsert one or more `DomainSyncState` rows inside an active `session` (`W19`, `W21`)."""
        if not states:
            return
        rows = [
            {
                "id": state.id
                or DomainSyncState.make_id(state.mgmt_name, state.domain_name, state.scope, state.item_type),
                "mgmt_name": state.mgmt_name,
                "domain_name": state.domain_name,
                "scope": state.scope,
                "item_type": state.item_type,
                "last_published_at": _ensure_utc(state.last_published_at),
                "last_session_uid": state.last_session_uid,
                "synced_at": _ensure_utc(state.synced_at),
                "status": state.status,
                "object_count": state.object_count,
                "last_error": state.last_error,
            }
            for state in states
        ]
        await self._dialect_upsert(session, DomainSyncStateRecord, rows)

    # ------------------------------------------------------------------
    # Domains (`arodonata_domains`)
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
        """Insert or update domain rows in `arodonata_domains`."""
        if not domains:
            return
        span_attrs(count=len(domains))
        rows = [
            {
                "id": dom.id or f"{dom.mgmt_name}:{dom.name}",
                "mgmt_name": dom.mgmt_name,
                "uid": dom.uid,
                "name": dom.name,
                "domain_type": dom.domain_type,
                "active_ip": dom.active_ip,
                "active_mds_ip": dom.active_mds_ip,
                "standby_ips": list(dom.standby_ips),
                "servers": list(dom.servers),
                "is_global": dom.is_global or dom.name == "Global",
                "raw_data": dict(dom.raw_data),
                "updated_at": _ensure_utc(dom.updated_at) or utc_now(),
            }
            for dom in domains
        ]
        async with self._db.session() as session:
            await self._dialect_upsert(session, DomainRecord, rows)
            await session.commit()

    # ------------------------------------------------------------------
    # Shared Read-Only Session Cache (`arodonata_sid_cache`)
    # ------------------------------------------------------------------

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
        row_id = entry.id or (
            f"{entry.mgmt_name}:{entry.domain_name}:{entry.auth_identity}"
            if entry.auth_identity
            else f"{entry.mgmt_name}:{entry.domain_name}"
        )
        row = {
            "id": row_id,
            "mgmt_name": entry.mgmt_name,
            "domain_name": entry.domain_name,
            "sid": entry.sid,
            "server_ip": entry.server_ip,
            "session_uid": entry.session_uid,
            "auth_identity": entry.auth_identity,
            "created_at": _ensure_utc(entry.created_at) or utc_now(),
            "last_used_at": _ensure_utc(entry.last_used_at) or utc_now(),
            "expires_at": _ensure_utc(entry.expires_at),
        }
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

    # ------------------------------------------------------------------
    # Unified Domain Sync State (`arodonata_domain_sync_state`)
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

    # ------------------------------------------------------------------
    # Assets (`arodonata_assets`)
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Gateway Interface Topology (`arodonata_gateway_topology`)
    # ------------------------------------------------------------------

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
        # Deduplicate entries by primary key `id` to prevent duplicate PK errors within the same domain batch
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

    # ------------------------------------------------------------------
    # Rulebase Snapshot (`arodonata_rulebase_*`)
    # ------------------------------------------------------------------

    @traced
    async def replace_domain_rulebase(
        self,
        snapshot: DomainRulebaseSnapshot,
        *,
        sync_state: DomainSyncState | None = None,
    ) -> None:
        """Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`."""
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

            dedup_pkg = list({pkg_layer.id: pkg_layer for pkg_layer in snapshot.package_layers}.values())
            await self._insert_rows_batched(
                session,
                RulebasePackageLayerRecord,
                dedup_pkg,
                lambda pkg_layer: _package_layer_to_row(pkg_layer, mgmt, dom),
            )
            del dedup_pkg

            dedup_layers = list({layer.id: layer for layer in snapshot.layers}.values())
            await self._insert_rows_batched(
                session,
                RulebaseLayerRecord,
                dedup_layers,
                lambda layer: _rulebase_layer_to_row(layer, mgmt, dom),
            )
            del dedup_layers

            dedup_secs = list({sec.id: sec for sec in snapshot.sections}.values())
            await self._insert_rows_batched(
                session,
                RulebaseSectionRecord,
                dedup_secs,
                lambda sec: _rulebase_section_to_row(sec, mgmt, dom),
            )
            del dedup_secs

            dedup_access = list({r.id: r for r in snapshot.access_rules}.values())
            await self._insert_rows_batched(
                session,
                AccessRuleRecord,
                dedup_access,
                lambda rule: _access_rule_to_row(rule, mgmt, dom),
            )
            del dedup_access

            dedup_nat = list({r.id: r for r in snapshot.nat_rules}.values())
            await self._insert_rows_batched(
                session,
                NatRuleRecord,
                dedup_nat,
                lambda nat_rule: _nat_rule_to_row(nat_rule, mgmt, dom),
            )
            del dedup_nat

            dedup_https = list({r.id: r for r in snapshot.https_rules}.values())
            await self._insert_rows_batched(
                session,
                HttpsRuleRecord,
                dedup_https,
                lambda https_rule: _https_rule_to_row(https_rule, mgmt, dom),
            )
            del dedup_https

            dedup_threat = list({r.id: r for r in snapshot.threat_rules}.values())
            await self._insert_rows_batched(
                session,
                ThreatRuleRecord,
                dedup_threat,
                lambda threat_rule: _threat_rule_to_row(threat_rule, mgmt, dom),
            )
            del dedup_threat

            if sync_state is not None:
                await self._upsert_sync_states_in_session(session, [sync_state])
            await session.commit()

    @traced
    async def replace_domain_package_catalog(
        self,
        mgmt_name: str,
        domain_name: str,
        package_layers: Sequence[RulebasePackageLayerEntry],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace `arodonata_rulebase_package_layer` rows for `(mgmt_name, domain_name)` without touching layer, section, or rule tables."""
        dedup_pkg = list({pkg_layer.id: pkg_layer for pkg_layer in package_layers}.values())
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, package_layers=len(dedup_pkg))
        async with self._db.session() as session:
            await session.execute(
                delete(RulebasePackageLayerRecord).where(
                    RulebasePackageLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    RulebasePackageLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                )
            )
            await self._insert_rows_batched(
                session,
                RulebasePackageLayerRecord,
                dedup_pkg,
                lambda pkg_layer: _package_layer_to_row(pkg_layer, mgmt_name, domain_name),
            )
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(dedup_pkg)

    @traced
    async def upsert_domain_rulebase_layers(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        layers: Sequence[RulebaseLayerEntry] = (),
        sections: Sequence[RulebaseSectionEntry] = (),
        access_rules: Sequence[AccessRuleEntry] = (),
        nat_rules: Sequence[NatRuleEntry] = (),
        https_rules: Sequence[HttpsRuleEntry] = (),
        threat_rules: Sequence[ThreatRuleEntry] = (),
        package_layers: Sequence[RulebasePackageLayerEntry] = (),
        replaced_layer_uids: Sequence[str] = (),
        replaced_nat_package_uids: Sequence[str] = (),
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace rulebase layers, sections, and rules strictly for `replaced_layer_uids` (and NAT packages) in `(mgmt_name, domain_name)`."""
        nat_from_layers = {
            u.removeprefix("nat:") for u in replaced_layer_uids if u.startswith("nat:") and u.removeprefix("nat:")
        }
        target_nat_pkg_uids = sorted(
            {u for u in replaced_nat_package_uids if u}
            | nat_from_layers
            | {nr.package_uid for nr in nat_rules if nr.package_uid}
        )
        nat_section_layer_uids = {f"nat:{u}" for u in target_nat_pkg_uids}
        target_layer_uids = sorted(
            {u for u in replaced_layer_uids if u}
            | {layer.uid for layer in layers if layer.uid}
            | {sec.layer_uid for sec in sections if sec.layer_uid}
            | nat_section_layer_uids
        )

        dedup_layers = list({layer.id: layer for layer in layers}.values())
        dedup_secs = list({sec.id: sec for sec in sections}.values())
        dedup_access = list({r.id: r for r in access_rules}.values())
        dedup_nat = list({r.id: r for r in nat_rules}.values())
        dedup_https = list({r.id: r for r in https_rules}.values())
        dedup_threat = list({r.id: r for r in threat_rules}.values())

        span_attrs(
            mgmt_name=mgmt_name,
            domain=domain_name,
            replaced_layers=len(target_layer_uids),
            replaced_nat_packages=len(target_nat_pkg_uids),
            access_rules=len(dedup_access),
            nat_rules=len(dedup_nat),
        )

        async with self._db.session() as session:
            if package_layers:
                pkg_rows = [_package_layer_to_row(pl, mgmt_name, domain_name) for pl in package_layers]
                await self._dialect_upsert(session, RulebasePackageLayerRecord, pkg_rows)

            for start in range(0, len(target_layer_uids), _BATCH_ROWS):
                chunk = target_layer_uids[start : start + _BATCH_ROWS]
                await session.execute(
                    delete(RulebaseLayerRecord).where(
                        RulebaseLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        RulebaseLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        col(RulebaseLayerRecord.uid).in_(chunk),
                    )
                )
                for layer_scoped_cls in (
                    RulebaseSectionRecord,
                    AccessRuleRecord,
                    HttpsRuleRecord,
                    ThreatRuleRecord,
                ):
                    await session.execute(
                        delete(layer_scoped_cls).where(
                            layer_scoped_cls.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            layer_scoped_cls.domain_name == domain_name,  # type: ignore[arg-type]
                            col(layer_scoped_cls.layer_uid).in_(chunk),
                        )
                    )

            for start in range(0, len(target_nat_pkg_uids), _BATCH_ROWS):
                nat_chunk = target_nat_pkg_uids[start : start + _BATCH_ROWS]
                await session.execute(
                    delete(NatRuleRecord).where(
                        NatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        NatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        col(NatRuleRecord.package_uid).in_(nat_chunk),
                    )
                )

            await self._insert_rows_batched(
                session,
                RulebaseLayerRecord,
                dedup_layers,
                lambda layer: _rulebase_layer_to_row(layer, mgmt_name, domain_name),
            )
            await self._insert_rows_batched(
                session,
                RulebaseSectionRecord,
                dedup_secs,
                lambda sec: _rulebase_section_to_row(sec, mgmt_name, domain_name),
            )
            await self._insert_rows_batched(
                session,
                AccessRuleRecord,
                dedup_access,
                lambda rule: _access_rule_to_row(rule, mgmt_name, domain_name),
            )
            await self._insert_rows_batched(
                session,
                NatRuleRecord,
                dedup_nat,
                lambda nat_rule: _nat_rule_to_row(nat_rule, mgmt_name, domain_name),
            )
            await self._insert_rows_batched(
                session,
                HttpsRuleRecord,
                dedup_https,
                lambda https_rule: _https_rule_to_row(https_rule, mgmt_name, domain_name),
            )
            await self._insert_rows_batched(
                session,
                ThreatRuleRecord,
                dedup_threat,
                lambda threat_rule: _threat_rule_to_row(threat_rule, mgmt_name, domain_name),
            )

            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()

        return len(dedup_access) + len(dedup_nat) + len(dedup_https) + len(dedup_threat)

    @traced
    async def get_domain_rulebase_packages(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load only `package_layers` and distinct NAT package stubs for `(mgmt_name, domain_name)` without loading rule tables."""
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
            nat_pkg_rows = (
                await session.execute(
                    select(
                        col(NatRuleRecord.package_uid),
                        col(NatRuleRecord.package_name),
                        func.max(col(NatRuleRecord.updated_at)),
                    )
                    .where(
                        col(NatRuleRecord.mgmt_name) == mgmt_name,
                        col(NatRuleRecord.domain_name) == domain_name,
                    )
                    .group_by(col(NatRuleRecord.package_uid), col(NatRuleRecord.package_name))
                )
            ).all()

        package_layers = [
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
        ]
        nat_pkg_uids_in_layers = {pl.package_uid for pl in package_layers if pl.rulebase_type == "nat"}
        nat_stubs = [
            NatRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                package_uid=str(p_uid),
                package_name=str(p_name),
                uid=f"pkg-stub:{p_uid}",
                position=1,
                updated_at=_ensure_utc(max_ts) or utc_now(),
            )
            for p_uid, p_name, max_ts in nat_pkg_rows
            if p_uid and str(p_uid) not in nat_pkg_uids_in_layers
        ]
        return DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            package_layers=package_layers,
            nat_rules=nat_stubs,
        )

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
