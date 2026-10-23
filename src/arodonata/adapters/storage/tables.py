"""SQLModel table definitions for Arodonata v2 persistence (`SQLite` and `PostgreSQL`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime
from sqlmodel import Field, SQLModel

from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.core.models.common import utc_now


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime loaded from SQLite/PostgreSQL to timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class SchemaVersionRecord(SQLModel, table=True):
    """Tracks applied SQLModel metadata SHA-256 hashes to skip redundant migration checks."""

    __tablename__ = "arodonata_schema_version"

    schema_hash: str = Field(primary_key=True)
    applied_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class DistributedLockRecord(SQLModel, table=True):
    """Cross-process distributed lock row with expiration timestamp."""

    __tablename__ = "distributed_locks"

    lock_key: str = Field(primary_key=True)
    owner_id: str = Field(index=True)
    acquired_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )


class DomainRecord(SQLModel, table=True):
    """Cached Check Point domain metadata in `domains`."""

    __tablename__ = "domains"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    domain_type: str = Field(default="domain")
    active_ip: str | None = Field(default=None)
    active_mds_ip: str | None = Field(default=None, index=True)
    standby_ips: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    servers: list[dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    is_global: bool = Field(default=False, index=True)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class SIDCacheRecord(SQLModel, table=True):
    """Persistent shared read-only session cache row in `sid_cache`.

    Strictly omits `sid` from `__repr__` and `__str__`.
    """

    __tablename__ = "sid_cache"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    sid: str = Field(repr=False)
    server_ip: str
    session_uid: str | None = Field(default=None)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_used_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    def __repr__(self) -> str:
        return (
            f"SIDCacheRecord(id={self.id!r}, mgmt_name={self.mgmt_name!r}, "
            f"domain_name={self.domain_name!r}, server_ip={self.server_ip!r}, "
            f"sid={REDACTED_PLACEHOLDER!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class DomainSyncStateRecord(SQLModel, table=True):
    """Unified per-`(mgmt_name, domain_name, scope, item_type)` synchronization state."""

    __tablename__ = "domain_sync_state"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    scope: str = Field(index=True)
    item_type: str = Field(default="*", index=True)
    last_published_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    last_session_uid: str | None = Field(default=None)
    synced_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    status: str = Field(default="idle")
    object_count: int = Field(default=0)
    last_error: str | None = Field(default=None)


class CPObjectRecord(SQLModel, table=True):
    """Cached network object row in `arodonata_objects`."""

    __tablename__ = "arodonata_objects"

    id: str = Field(primary_key=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    original_domain: str | None = Field(default=None, index=True)
    ipv4_address: str | None = Field(default=None, index=True)
    ipv6_address: str | None = Field(default=None)
    subnet4: str | None = Field(default=None, index=True)
    mask_length4: int | None = Field(default=None)
    subnet_mask: str | None = Field(default=None)
    ipv4_address_first: str | None = Field(default=None)
    ipv4_address_last: str | None = Field(default=None)
    fqdn: str | None = Field(default=None, index=True)
    is_sub_domain: bool | None = Field(default=None)
    members: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    nat_settings: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class CPServiceRecord(SQLModel, table=True):
    """Cached service object row in `arodonata_services`."""

    __tablename__ = "arodonata_services"

    id: str = Field(primary_key=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    original_domain: str | None = Field(default=None, index=True)
    port: str | None = Field(default=None, index=True)
    protocol: str | None = Field(default=None, index=True)
    icmp_type: int | None = Field(default=None)
    icmp_code: int | None = Field(default=None)
    members: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    session_timeout: int | None = Field(default=None)
    match_for_any: bool | None = Field(default=None)
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AssetRecord(SQLModel, table=True):
    """Cached gateway, cluster, cluster member, VSX, or management server asset row in `assets`."""

    __tablename__ = "assets"

    id: str = Field(primary_key=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    ipv4_address: str | None = Field(default=None, index=True)
    ipv6_address: str | None = Field(default=None)
    version: str | None = Field(default=None)
    os_name: str | None = Field(default=None)
    hardware: str | None = Field(default=None)
    sic_status: str | None = Field(default=None)
    parent_uid: str | None = Field(default=None, index=True)
    parent_name: str | None = Field(default=None)
    member_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    virtual_system_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    interfaces: list[dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    network_security_blades: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RulebasePackageLayerRecord(SQLModel, table=True):
    """Cached policy package to ordered layer/NAT linkage in `rulebase_package_layer`."""

    __tablename__ = "rulebase_package_layer"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    package_uid: str = Field(index=True)
    package_name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    position: int = Field(default=0)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RulebaseLayerRecord(SQLModel, table=True):
    """Cached rulebase layer row in `rulebase_layer`."""

    __tablename__ = "rulebase_layer"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    parent_layer_uid: str | None = Field(default=None, index=True)
    parent_rule_uid: str | None = Field(default=None, index=True)
    is_global: bool = Field(default=False)
    shared: bool = Field(default=False)
    implicit_cleanup_action: str | None = Field(default=None)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RulebaseSectionRecord(SQLModel, table=True):
    """Cached rulebase section header row in `rulebase_section`."""

    __tablename__ = "rulebase_section"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    position: int = Field(default=0)
    from_rule: int | None = Field(default=None)
    to_rule: int | None = Field(default=None)
    rule_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AccessRuleRecord(SQLModel, table=True):
    """Cached access-control rule row in `rulebase_access`."""

    __tablename__ = "rulebase_access"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="access-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    inline_layer_uid: str | None = Field(default=None)
    inline_layer_name: str | None = Field(default=None)
    placeholder_domain_layer_uid: str | None = Field(default=None)
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    source_negate: bool = Field(default=False)
    destination_negate: bool = Field(default=False)
    service_negate: bool = Field(default=False)
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class NatRuleRecord(SQLModel, table=True):
    """Cached NAT rule row in `rulebase_nat`."""

    __tablename__ = "rulebase_nat"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    package_uid: str = Field(index=True)
    package_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="nat-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    method: str | None = Field(default=None)
    auto_generated: bool = Field(default=False)
    original_source: str | None = Field(default=None)
    original_destination: str | None = Field(default=None)
    original_service: str | None = Field(default=None)
    translated_source: str | None = Field(default=None)
    translated_destination: str | None = Field(default=None)
    translated_service: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class HttpsRuleRecord(SQLModel, table=True):
    """Cached HTTPS inspection rule row in `rulebase_https`."""

    __tablename__ = "rulebase_https"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="https-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    inline_layer_uid: str | None = Field(default=None)
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    site_category: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    certificate: str | None = Field(default=None)
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class ThreatRuleRecord(SQLModel, table=True):
    """Cached Threat Prevention rule row in `rulebase_threat`."""

    __tablename__ = "rulebase_threat"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="threat-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    protected_scope: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
