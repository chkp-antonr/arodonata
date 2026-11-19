"""Record <-> domain model and row-dict converters for control, inventory, and topology tables."""

from __future__ import annotations

from typing import Any

from arodonata.adapters.storage.tables import (
    AssetRecord,
    CPObjectRecord,
    CPServiceRecord,
    DomainRecord,
    DomainSyncStateRecord,
    GatewayTopologyRecord,
    SIDCacheRecord,
    TopologyAnnotationRecord,
    _ensure_utc,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import utc_now
from arodonata.core.models.domains import DomainInfo, DomainSyncState, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.models.topology import GatewayTopologyEntry, TopologyAnnotation


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


def _domain_to_row(dom: DomainInfo) -> dict[str, Any]:
    return {
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


def _record_to_sid_entry(rec: SIDCacheRecord) -> SIDCacheEntry:
    now = utc_now()
    # SQLite stores naive UTC datetimes in some drivers; normalize to UTC.
    return SIDCacheEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        sid=rec.sid,
        server_ip=rec.server_ip,
        session_uid=rec.session_uid,
        auth_identity=rec.auth_identity,
        created_at=_ensure_utc(rec.created_at) or now,
        last_used_at=_ensure_utc(rec.last_used_at) or now,
        expires_at=_ensure_utc(rec.expires_at),
    )


def _sid_entry_to_row(entry: SIDCacheEntry) -> dict[str, Any]:
    row_id = entry.id or (
        f"{entry.mgmt_name}:{entry.domain_name}:{entry.auth_identity}"
        if entry.auth_identity
        else f"{entry.mgmt_name}:{entry.domain_name}"
    )
    return {
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


def _sync_state_to_row(state: DomainSyncState) -> dict[str, Any]:
    return {
        "id": state.id or DomainSyncState.make_id(state.mgmt_name, state.domain_name, state.scope, state.item_type),
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
