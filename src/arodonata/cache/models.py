"""SQLModel table definitions for PostgreSQL cache.

Supports JSONB columns for complex data types with binary keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Column
from sqlmodel import JSON, Field, SQLModel


@dataclass(frozen=True)
class ServerList:
    """Value object for comma-separated server lists.

    Provides type-safe handling of standby server lists.

    Example:
        servers = ServerList.from_csv("server1,server2,server3")
        assert servers.servers == ["server1", "server2", "server3"]
        assert servers.to_csv() == "server1,server2,server3"

        empty = ServerList.from_csv("")
        assert empty.servers == []
        assert empty.to_csv() == ""
    """

    servers: list[str]

    @classmethod
    def from_csv(cls, csv: str) -> ServerList:
        """Create ServerList from comma-separated string.

        Args:
            csv: Comma-separated string (empty string returns empty list).

        Returns:
            ServerList instance.
        """
        if not csv:
            return cls([])
        return cls([s.strip() for s in csv.split(",") if s.strip()])

    def to_csv(self) -> str:
        """Convert to comma-separated string.

        Returns:
            Comma-separated string (empty string if no servers).
        """
        return ",".join(self.servers)

    def __bool__(self) -> bool:
        """Return True if there are servers."""
        return bool(self.servers)


class SIDCache(SQLModel, table=True):
    """Cached Check Point API session identifiers."""

    __tablename__ = "sid_cache"

    mgmt_dmn_key: str = Field(
        primary_key=True,
        max_length=255,
        description="Composite key: 'mgmt_name:domain' (api-key mode) or 'mgmt_name:domain:username' (credential mode)",
    )
    sid: str = Field(max_length=255, description="Session identifier")
    uid: str | None = Field(default=None, max_length=255, index=True, description="User identifier")
    server_ip: str = Field(max_length=45, description="Management server IP")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        description="Cache entry timestamp",
    )
    last_keepalive: datetime | None = Field(
        default=None,
        description="Last keepalive sent for this session (naive UTC)",
    )
    # JSONB column for additional metadata if needed
    metadata_: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("metadata", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        uid_str = f", uid='{self.uid[:8]}...'" if self.uid else ""
        return f"SIDCache(key='{self.mgmt_dmn_key}', sid='{self.sid[:8]}...'{uid_str}, server_ip='{self.server_ip}')"


class Asset(SQLModel, table=True):
    """Cached gateway and server assets from Check Point."""

    __tablename__ = "assets"

    asset_id: str = Field(
        primary_key=True,
        max_length=255,
        description="Composite key: 'mgmt_name:domain:name'",
    )
    name: str = Field(max_length=255, index=True)
    asset_type: str = Field(max_length=100, index=True)
    asset_hardware: str = Field(default="", max_length=100, index=True)
    asset_uid: str = Field(max_length=255)
    domain_name: str = Field(default="", max_length=255)
    domain_uid: str = Field(default="", max_length=255)
    mgmt_name: str = Field(max_length=100, index=True)
    parent_asset_id: str | None = Field(
        default=None,
        max_length=255,
        foreign_key="assets.asset_id",
        index=True,
    )
    path: str = Field(default="", max_length=1000)
    ip_address: str = Field(default="", max_length=45)
    ssh_ip: str = Field(default="", max_length=45)
    comments: str = Field(default="", max_length=2000, description="Asset comments from API")
    # Tags applied to this asset (list of {name, color} dicts)
    tags: list[dict[str, Any]] | None = Field(
        default=None,
        sa_column=Column("tags", JSON, nullable=True),
    )
    # Device type classification fields (calculated from blades + inventory data)
    deployed_as: str | None = Field(
        default=None,
        max_length=20,
        description="Device deployment: virtual or physical",
    )
    device_type: str | None = Field(
        default=None,
        max_length=50,
        description="Specific device type (e.g., CLM, MDS, ClusterMember)",
    )
    device_category: str | None = Field(
        default=None,
        max_length=50,
        description="Broader functional category (e.g., Domain_CLM, Physical_FW)",
    )
    # Location enrichment fields (populated by build_inventory LocationEnricher)
    region: str | None = Field(default=None, max_length=100, index=True)
    country_code: str | None = Field(default=None, max_length=10, index=True)
    country_name: str | None = Field(default=None, max_length=100)
    city_code: str | None = Field(default=None, max_length=10, index=True)
    # JSONB for raw API response data with binary keys support
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"Asset(id='{self.asset_id}', name='{self.name}', type='{self.asset_type}')"


class Domain(SQLModel, table=True):
    """Cached domain information with MDS server mappings."""

    __tablename__ = "domains"

    mdm_dmn: str = Field(
        primary_key=True,
        description="'active_mds:domain' or 'sms:'",
    )
    domain_name: str = Field(index=True)
    domain_uid: str = Field(default="", max_length=255)
    active_mds: str
    active_ip: str
    active_server: str
    standby_mdss: str = Field(default="")  # Comma-separated - use ServerList for type safety
    standby_ips: str = Field(default="")
    standby_servers: str = Field(default="")
    mgmt_name: str
    is_mdm: bool = Field(default=False)

    def __repr__(self) -> str:
        """String representation."""
        return f"Domain(name='{self.domain_name}', uid='{self.domain_uid}', mds='{self.active_mds}')"

    @classmethod
    def build(
        cls,
        *,
        mgmt_name: str,
        domain_name: str,
        domain_uid: str = "",
        active_ip: str,
        active_server: str = "",
        standby_mdss: str = "",
        standby_ips: str = "",
        standby_servers: str = "",
        is_mdm: bool = False,
    ) -> Domain:
        """Factory method to create Domain objects with proper defaults.

        Eliminates duplication in domain creation across the codebase.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            domain_uid: Domain UID (default: "").
            active_ip: Active server IP address.
            active_server: Active server name (default: mgmt_name).
            standby_mdss: Comma-separated MDS standby servers.
            standby_ips: Comma-separated standby IPs.
            standby_servers: Comma-separated standby server names.
            is_mdm: Multi-Domain Management status.

        Returns:
            Configured Domain instance.

        Example:
            domain = Domain.build(
                mgmt_name="mgmt1",
                domain_name="dmn1",
                domain_uid="123abc",
                active_ip="192.168.1.10"
            )
        """
        if not active_server:
            active_server = mgmt_name

        return cls(
            mdm_dmn=f"{mgmt_name}:{domain_name}",
            domain_name=domain_name,
            domain_uid=domain_uid,
            active_mds=mgmt_name,
            active_ip=active_ip,
            active_server=active_server,
            standby_mdss=standby_mdss,
            standby_ips=standby_ips,
            standby_servers=standby_servers,
            mgmt_name=mgmt_name,
            is_mdm=is_mdm,
        )


class DistributedLock(SQLModel, table=True):
    """Distributed lock record for cross-process coordination."""

    __tablename__ = "distributed_locks"

    lock_key: str = Field(
        primary_key=True,
        max_length=255,
        description="Unique lock identifier",
    )
    owner_id: str = Field(
        max_length=255,
        description="Process/worker holding the lock (format: hostname:pid:worker_id)",
    )
    acquired_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        description="Lock acquisition timestamp",
    )
    expires_at: datetime = Field(
        description="Lock expiration timestamp for safety",
    )
    # JSONB column for optional metadata (debugging info, operation context)
    metadata_: dict[str, Any] | None = Field(
        default=None,
        # sa_column=Column("metadata", JSONB, nullable=True),
        sa_column=Column("metadata", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"DistributedLock(key='{self.lock_key}', owner='{self.owner_id}', expires_at={self.expires_at})"


class SchemaVersion(SQLModel, table=True):
    """Row-per-applied-hash record of confirmed-applied model schema hashes.

    DatabaseManager.initialize() skips the per-table migration scan when a
    row for the currently registered metadata hash already exists. The hash
    itself (rather than a synthetic single row id) is the primary key so that
    multiple processes sharing one DB but registering different model sets
    (e.g. different DISABLED_PLUGINS) each get their own row instead of
    thrashing: with a single mutable row, each process's init would mismatch
    the other's stored hash, pay the full scan every time, and overwrite the
    other's hash.
    """

    __tablename__ = "arodonata_schema_version"

    schema_hash: str = Field(primary_key=True, max_length=64, description="SHA-256 of the applied model metadata")
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        description="When this schema hash was last confirmed applied (naive UTC)",
    )


class CPObject(SQLModel, table=True):
    """Cached Check Point network object with extracted fields and raw data.

    Stores relevant fields from Check Point API responses with automatic field
    filtering for fast queries, plus raw JSONB for complete object access.
    """

    __tablename__ = "arodonata_objects"

    # Compound primary key
    id: str = Field(
        primary_key=True,
        max_length=384,
        description="Composite key: 'mgmt_name:domain_name:uid'",
    )

    # Identifying fields (indexed)
    uid: str = Field(index=True, max_length=64, description="Check Point object UID")
    name: str = Field(index=True, max_length=255, description="Object name")
    type: str = Field(
        index=True,
        max_length=64,
        description="Object type (host, network, group, etc.)",
    )
    mgmt_name: str = Field(index=True, max_length=64, description="Management server name")
    domain_name: str = Field(index=True, max_length=255, default="", description="Domain name")
    original_domain: str = Field(default="", max_length=255, description="Original domain")

    # IP address fields (indexed for fast lookups)
    ipv4_address: str = Field(default="", max_length=45, index=True, description="IPv4 address")
    subnet4: str = Field(default="", max_length=43, description="Subnet network (CIDR)")
    subnet_mask: str = Field(default="", max_length=18, description="Subnet mask")
    ipv4_address_first: str = Field(default="", max_length=45, description="First IP in address range")
    ipv4_address_last: str = Field(default="", max_length=45, description="Last IP in address range")

    # Group membership (comma-separated UIDs)
    members: str = Field(default="", description="Comma-separated member UIDs")

    # Other commonly-searched fields
    color: str = Field(default="", max_length=32)
    comments: str = Field(default="")
    tags: str = Field(default="", description="Comma-separated tags")

    # NAT settings as JSON (changed from string to dict)
    nat_settings: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("nat_settings", JSON, nullable=True),
        description="NAT settings as JSON",
    )

    # Network interfaces as JSON list
    interfaces: list[dict[str, Any]] | None = Field(
        default=None,
        sa_column=Column("interfaces", JSON, nullable=True),
        description="Network interfaces as JSON list",
    )

    # Additional frequently queried fields
    version: str = Field(default="", max_length=16, description="Object version")
    cluster_uid: str = Field(default="", max_length=64, description="Cluster UID if member")
    original_domain_uid: str = Field(default="", max_length=64, description="Original domain UID")

    # Timestamps (all naive UTC) - use UTC pattern consistent with existing models
    creation_time: datetime | None = Field(default=None)
    last_modify_time: datetime | None = Field(default=None)
    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
        description="Last cache update",
    )

    # Full raw API response (JSON) - using JSON (not JSONB) for consistency
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
        description="Complete API response as JSON",
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"CPObject(id='{self.id}', name='{self.name}', type='{self.type}')"


class LastPublishedSession(SQLModel, table=True):
    """Last published session for smart refresh detection.

    Tracks the last published session time per domain to determine if cache
    refresh is needed during "check" mode.
    """

    __tablename__ = "last_published_sessions"

    # Compound key: mgmt_name:domain_name
    id: str = Field(primary_key=True, max_length=319)
    mgmt_name: str = Field(index=True, max_length=64)
    domain_name: str = Field(index=True, max_length=255)

    published_time: datetime = Field(
        default_factory=lambda: datetime(1970, 1, 1).replace(tzinfo=None),
        description="Session publish timestamp (naive UTC)",
    )

    uid: str = Field(default="", max_length=64)
    name: str = Field(default="", max_length=255)
    ip_address: str = Field(default="", max_length=45)
    comments: str = Field(default="")
    creator: str = Field(default="", max_length=255)
    description: str = Field(default="")

    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"LastPublishedSession(id='{self.id}', time={self.published_time})"


class RulebaseAccess(SQLModel, table=True):
    """Cached access control rules from Network layer."""

    __tablename__ = "rulebase_access"

    id: str = Field(
        primary_key=True,
        max_length=512,
        description="Composite key: 'mgmt_name:domain_name:layer_name:uid'",
    )
    uid: str = Field(index=True, max_length=64)
    rule_number: int = Field(index=True, description="Rule position in layer")
    name: str = Field(max_length=255)
    enabled: bool = Field(index=True)
    layer_name: str = Field(index=True, max_length=255)
    mgmt_name: str = Field(index=True, max_length=64)
    domain_name: str = Field(index=True, max_length=255, default="")
    sources: str = Field(default="", description="Comma-separated source UIDs")
    destinations: str = Field(default="", description="Comma-separated destination UIDs")
    services: str = Field(default="", description="Comma-separated service UIDs")
    action: str = Field(default="accept", max_length=32)
    track: str = Field(default="", max_length=32)
    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
    )
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"RulebaseAccess(id='{self.id}', name='{self.name}', layer='{self.layer_name}')"


class RulebaseNAT(SQLModel, table=True):
    """Cached NAT rules from NAT layer."""

    __tablename__ = "rulebase_nat"

    id: str = Field(
        primary_key=True,
        max_length=512,
        description="Composite key: 'mgmt_name:domain_name:layer_name:uid'",
    )
    uid: str = Field(index=True, max_length=64)
    rule_number: int = Field(index=True)
    name: str = Field(max_length=255)
    enabled: bool = Field(index=True)
    layer_name: str = Field(index=True, max_length=255)
    mgmt_name: str = Field(index=True, max_length=64)
    domain_name: str = Field(index=True, max_length=255, default="")
    original_source: str = Field(default="", max_length=255)
    original_destination: str = Field(default="", max_length=255)
    original_service: str = Field(default="", max_length=255)
    translated_source: str = Field(default="", max_length=255)
    translated_destination: str = Field(default="", max_length=255)
    translated_service: str = Field(default="", max_length=255)
    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
    )
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"RulebaseNAT(id='{self.id}', name='{self.name}', layer='{self.layer_name}')"


class RulebaseHTTPS(SQLModel, table=True):
    """Cached HTTPS inspection rules from CVD layer."""

    __tablename__ = "rulebase_https"

    id: str = Field(
        primary_key=True,
        max_length=512,
        description="Composite key: 'mgmt_name:domain_name:layer_name:uid'",
    )
    uid: str = Field(index=True, max_length=64)
    rule_number: int = Field(index=True)
    name: str = Field(max_length=255)
    enabled: bool = Field(index=True)
    layer_name: str = Field(index=True, max_length=255)
    mgmt_name: str = Field(index=True, max_length=64)
    domain_name: str = Field(index=True, max_length=255, default="")
    sources: str = Field(default="", description="Comma-separated source UIDs")
    destinations: str = Field(default="", description="Comma-separated destination UIDs")
    track: str = Field(default="", max_length=32)
    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
    )
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"RulebaseHTTPS(id='{self.id}', name='{self.name}', layer='{self.layer_name}')"


class RulebaseThreat(SQLModel, table=True):
    """Cached threat prevention rules from Threat layer."""

    __tablename__ = "rulebase_threat"

    id: str = Field(
        primary_key=True,
        max_length=512,
        description="Composite key: 'mgmt_name:domain_name:layer_name:uid'",
    )
    uid: str = Field(index=True, max_length=64)
    rule_number: int = Field(index=True)
    name: str = Field(max_length=255)
    enabled: bool = Field(index=True)
    layer_name: str = Field(index=True, max_length=255)
    mgmt_name: str = Field(index=True, max_length=64)
    domain_name: str = Field(index=True, max_length=255, default="")
    track: str = Field(default="", max_length=32)
    protections: str = Field(default="", description="Comma-separated protection names")
    update_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        index=True,
    )
    raw_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("raw_data", JSON, nullable=True),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"RulebaseThreat(id='{self.id}', name='{self.name}', layer='{self.layer_name}')"


__all__ = [
    "SIDCache",
    "Asset",
    "Domain",
    "DistributedLock",
    "SchemaVersion",
    "ServerList",
    "CPObject",
    "LastPublishedSession",
    "RulebaseAccess",
    "RulebaseNAT",
    "RulebaseHTTPS",
    "RulebaseThreat",
]
