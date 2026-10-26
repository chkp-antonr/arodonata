"""Common domain types, constants, and API result models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, overload

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import redact_sid, sanitize_mapping

CacheMode = Literal["cache", "smart", "smart-fast", "force"]
SyncScope = Literal["domains", "objects", "services", "assets", "rulebase"]
SyncStatus = Literal["idle", "syncing", "ok", "failed"]

DEFAULT_OBJECT_TYPES: tuple[str, ...] = (
    "host",
    "network",
    "address-range",
    "group",
    "dns-domain",
)

DEFAULT_SERVICE_TYPES: tuple[str, ...] = (
    "service-tcp",
    "service-udp",
    "service-icmp",
    "service-group",
)

OBJECT_TYPE_ALIASES: dict[str, str] = {
    "range": "address-range",
    "ip-range": "address-range",
    "address_range": "address-range",
    "dns": "dns-domain",
    "fqdn": "dns-domain",
    "dns_domain": "dns-domain",
    "dynamic": "dynamic-object",
    "dynamic_object": "dynamic-object",
    "zone": "security-zone",
    "security_zone": "security-zone",
}

SERVICE_TYPE_ALIASES: dict[str, str] = {
    "tcp": "service-tcp",
    "udp": "service-udp",
    "icmp": "service-icmp",
    "icmp6": "service-icmp6",
    "icmpv6": "service-icmp6",
    "sctp": "service-sctp",
    "other": "service-other",
    "dce-rpc": "service-dce-rpc",
    "rpc": "service-rpc",
    "gtp": "service-gtp",
    "citrix-tcp": "service-citrix-tcp",
    "compound-tcp": "service-compound-tcp",
    "svc-group": "service-group",
    "service_group": "service-group",
}

ASSET_TYPE_ALIASES: dict[str, str] = {
    "gateway": "simple-gateway",
    "simple_gateway": "simple-gateway",
    "cluster": "simple-cluster",
    "simple_cluster": "simple-cluster",
    "member": "cluster-member",
    "cluster_member": "cluster-member",
    "vsx": "vsx-gateway",
    "vsx_gateway": "vsx-gateway",
    "vsx_cluster": "vsx-cluster",
    "vs": "virtual-system",
    "virtual_system": "virtual-system",
    "server": "checkpoint-host",
    "mgmt": "checkpoint-host",
    "host-ckp": "checkpoint-host",
    "checkpoint_host": "checkpoint-host",
    "interoperable": "interoperable-device",
    "interoperable_device": "interoperable-device",
}

CANONICAL_ASSET_TYPES: frozenset[str] = frozenset(
    {
        "simple-gateway",
        "simple-cluster",
        "cluster-member",
        "vsx-gateway",
        "vsx-cluster",
        "vsx-cluster-member",
        "virtual-system",
        "vs-netobj",
        "checkpoint-host",
        "interoperable-device",
        "CpmiGatewayPlain",
        "CpmiGatewayCluster",
        "CpmiClusterMember",
        "CpmiVsxNetobj",
        "CpmiVsxClusterNetobj",
        "CpmiVsxClusterMember",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
        "CpmiHostCkp",
    }
)


def normalize_object_type(item_type: str) -> str:
    """Normalize a network object type alias (e.g. `'range'` -> `'address-range'`)."""
    clean = item_type.strip().lower()
    return OBJECT_TYPE_ALIASES.get(clean, clean)


def normalize_service_type(item_type: str) -> str:
    """Normalize a service type alias (e.g. `'tcp'` -> `'service-tcp'`, `'group'` -> `'service-group'`)."""
    clean = item_type.strip().lower()
    if clean == "group":
        return "service-group"
    return SERVICE_TYPE_ALIASES.get(clean, clean)


def normalize_asset_type(item_type: str) -> str:
    """Normalize an asset type alias (e.g. `'gateway'` -> `'simple-gateway'`, `'cluster'` -> `'simple-cluster'`)."""
    clean = item_type.strip().lower()
    return ASSET_TYPE_ALIASES.get(clean, clean)


def normalize_any_type(item_type: str) -> str:
    """Normalize an object, service, or asset type alias across all scopes."""
    clean = item_type.strip().lower()
    if clean in OBJECT_TYPE_ALIASES:
        return OBJECT_TYPE_ALIASES[clean]
    if clean in SERVICE_TYPE_ALIASES:
        return SERVICE_TYPE_ALIASES[clean]
    if clean in ASSET_TYPE_ALIASES:
        return ASSET_TYPE_ALIASES[clean]
    return clean


def utc_now() -> datetime:
    """Return current naive UTC datetime (tzinfo=None)."""
    return datetime.now(UTC).replace(tzinfo=None)


@overload
def to_naive_utc(dt: datetime) -> datetime: ...
@overload
def to_naive_utc(dt: None) -> None: ...


def to_naive_utc(dt: datetime | None) -> datetime | None:
    """Convert any datetime to naive UTC (tzinfo=None).

    Aware datetimes are converted to UTC and stripped of tzinfo;
    naive datetimes are assumed to already be in UTC and returned as-is.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


class ApiCallResult(BaseModel):
    """Typed result of a single Check Point Management API call."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    status_code: int = 200
    data: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    error_code: str | None = None
    task_id: str | None = None

    def __repr__(self) -> str:
        safe_data = sanitize_mapping(self.data) if isinstance(self.data, dict) else self.data
        safe_err = redact_sid(self.error_message) if self.error_message else None
        return (
            f"ApiCallResult(success={self.success!r}, status_code={self.status_code!r}, "
            f"data={safe_data!r}, error_message={safe_err!r}, "
            f"error_code={self.error_code!r}, task_id={self.task_id!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class ApiQueryResult(BaseModel):
    """Typed result of a paginated Check Point Management API query."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    objects: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    error_message: str | None = None
    code: str | None = None
