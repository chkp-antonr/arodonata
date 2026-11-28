"""Common domain types, constants, and API result models."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal, NamedTuple, overload

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import redact_sid, sanitize_mapping

CacheMode = Literal["cache", "smart", "smart-fast", "force"]
SyncScope = Literal["domains", "objects", "services", "assets", "rulebase", "topology"]
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
    "app-site": "application-site",
    "application_site": "application-site",
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
    "vsx_cluster_member": "vsx-cluster-member",
    "vs": "virtual-system",
    "virtual_system": "virtual-system",
    "vs_netobj": "vs-netobj",
    "server": "checkpoint-host",
    "mgmt": "checkpoint-host",
    "host-ckp": "checkpoint-host",
    "checkpoint_host": "checkpoint-host",
    "cpmimds": "mds",
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
        "mds",
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
        "CpmiMds",
    }
)

_CANONICAL_ASSET_BY_LOWER: dict[str, str] = {t.lower(): t for t in CANONICAL_ASSET_TYPES}

_ASSET_EQUIVALENT_GROUPS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        ("gateway", "simple-gateway", "simple_gateway", "cpmigatewayplain"),
        ("simple-gateway", "CpmiGatewayPlain"),
    ),
    (
        ("cluster", "simple-cluster", "simple_cluster", "cpmigatewaycluster"),
        ("simple-cluster", "CpmiGatewayCluster"),
    ),
    (
        ("member", "cluster-member", "cluster_member", "cpmiclustermember"),
        ("cluster-member", "vsx-cluster-member", "CpmiClusterMember", "CpmiVsxClusterMember"),
    ),
    (
        ("vsx-cluster-member", "vsx_cluster_member", "cpmivsxclustermember"),
        ("vsx-cluster-member", "CpmiVsxClusterMember"),
    ),
    (
        ("vsx", "vsx-gateway", "vsx_gateway", "cpmivsxnetobj"),
        ("vsx-gateway", "vsx-cluster", "CpmiVsxNetobj", "CpmiVsxClusterNetobj"),
    ),
    (
        ("vsx-cluster", "vsx_cluster", "cpmivsxclusternetobj"),
        ("vsx-cluster", "CpmiVsxClusterNetobj"),
    ),
    (
        (
            "vs",
            "virtual-system",
            "virtual_system",
            "vs-netobj",
            "vs_netobj",
            "cpmivsnetobj",
            "cpmivsclusternetobj",
        ),
        ("virtual-system", "vs-netobj", "CpmiVsNetobj", "CpmiVsClusterNetobj"),
    ),
    (
        ("server", "mgmt", "host-ckp", "checkpoint-host", "checkpoint_host", "cpmihostckp"),
        ("checkpoint-host", "CpmiHostCkp"),
    ),
    (
        ("mds", "cpmimds"),
        ("mds", "CpmiMds"),
    ),
    (
        ("interoperable", "interoperable-device", "interoperable_device"),
        ("interoperable-device",),
    ),
)

ASSET_TYPE_EQUIVALENTS: dict[str, tuple[str, ...]] = {
    alias: targets for aliases, targets in _ASSET_EQUIVALENT_GROUPS for alias in aliases
}

QUERY_GROUP_BY_ALIASES: dict[str, str] = {
    "domain": "domain_name",
    "mgmt": "mgmt_name",
    "server": "mgmt_name",
    "management": "mgmt_name",
    "object_type": "type",
    "asset_type": "type",
    "service_type": "type",
    "orig_domain": "original_domain",
    "role": "asset_role",
    "platform": "platform_family",
}


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


def expand_asset_type(item_type: str) -> tuple[str, ...]:
    """Expand an asset type or alias to all equivalent REST and Check Point `Cpmi*` classes."""
    clean = item_type.strip()
    if not clean:
        return ()
    low = clean.lower()
    if low in ASSET_TYPE_EQUIVALENTS:
        return ASSET_TYPE_EQUIVALENTS[low]
    if low in _CANONICAL_ASSET_BY_LOWER:
        return (_CANONICAL_ASSET_BY_LOWER[low],)
    return (clean,)


def expand_asset_types(types: Sequence[str]) -> list[str]:
    """Expand asset types/aliases into deduplicated REST and Check Point `Cpmi*` classes."""
    expanded: list[str] = []
    seen_lower: set[str] = set()
    for raw_type in types:
        for candidate in expand_asset_type(str(raw_type or "")):
            low = candidate.lower()
            if low not in seen_lower:
                seen_lower.add(low)
                expanded.append(candidate)
    return expanded


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


_GATEWAY_FAMILY_EXTRA_TYPES: tuple[str, ...] = (
    "simple-gateway",
    "simple-cluster",
    "vsx-gateway",
    "vsx-cluster",
    "virtual-system",
    "CpmiGatewayPlain",
    "CpmiGatewayCluster",
    "CpmiVsxNetobj",
    "CpmiVsxClusterNetobj",
    "CpmiVsNetobj",
    "CpmiVsClusterNetobj",
)


class PartitionedEntityTypes(NamedTuple):
    """Result of partitioning raw entity type filters into object, service, and asset scopes."""

    object_types: list[str]
    service_types: list[str]
    asset_types: list[str]
    is_explicit_empty: bool


def partition_entity_types(
    types: Sequence[str] | None,
    *,
    expand_gateway_family: bool = False,
    group_as_service: bool = False,
) -> PartitionedEntityTypes:
    """Partition raw `types` filters into deduplicated `(object_types, service_types, asset_types, is_explicit_empty)`.

    When `types` is `None`, returns empty lists and `is_explicit_empty=False`.
    When `types` is non-`None` but contains no non-blank entries, returns `is_explicit_empty=True`.
    """
    if types is None:
        return PartitionedEntityTypes([], [], [], False)

    non_blank = [str(raw_t).strip() for raw_t in types if str(raw_t or "").strip()]
    if not non_blank:
        return PartitionedEntityTypes([], [], [], True)

    object_types: list[str] = []
    service_types: list[str] = []
    asset_types: list[str] = []
    seen_obj: set[str] = set()
    seen_svc: set[str] = set()
    seen_asset_lower: set[str] = set()

    for raw_t in non_blank:
        if group_as_service and raw_t.lower() == "group":
            if "service-group" not in seen_svc:
                seen_svc.add("service-group")
                service_types.append("service-group")
            continue

        any_t = normalize_any_type(raw_t)
        if any_t.lower() in _CANONICAL_ASSET_BY_LOWER:
            for cand in expand_asset_type(raw_t):
                low = cand.lower()
                if low not in seen_asset_lower:
                    seen_asset_lower.add(low)
                    asset_types.append(cand)
            if expand_gateway_family and raw_t.lower() == "gateway":
                for cand in _GATEWAY_FAMILY_EXTRA_TYPES:
                    low = cand.lower()
                    if low not in seen_asset_lower:
                        seen_asset_lower.add(low)
                        asset_types.append(cand)
        elif any_t.startswith("service-"):
            svc_t = normalize_service_type(raw_t)
            if svc_t and svc_t not in seen_svc:
                seen_svc.add(svc_t)
                service_types.append(svc_t)
        else:
            obj_t = normalize_object_type(raw_t)
            if obj_t and obj_t not in seen_obj:
                seen_obj.add(obj_t)
                object_types.append(obj_t)

    return PartitionedEntityTypes(object_types, service_types, asset_types, False)


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


def _parse_posix_timestamp(value: int | float) -> datetime:
    ts = float(value)
    if ts > 1e11:  # Milliseconds epoch
        ts = ts / 1000.0
    return datetime.fromtimestamp(ts, tz=UTC).replace(tzinfo=None)


def _parse_iso_datetime(iso_str: str) -> datetime | None:
    normalized = iso_str
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    # Handle "+0300" -> "+03:00"
    if len(normalized) >= 5 and normalized[-5] in ("+", "-") and ":" not in normalized[-5:]:
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    try:
        dt = datetime.fromisoformat(normalized)
        return to_naive_utc(dt)
    except ValueError:
        return None


def parse_cp_publish_timestamp(raw_time: Any) -> datetime | None:
    """Parse Check Point `publish-time` or `last-modify-time` dict/string/int into a naive UTC `datetime`."""
    if raw_time is None:
        return None
    if isinstance(raw_time, datetime):
        return to_naive_utc(raw_time)
    if isinstance(raw_time, dict):
        iso_str = raw_time.get("iso-8601") or raw_time.get("iso_8601")
        if isinstance(iso_str, str) and iso_str.strip():
            parsed = _parse_iso_datetime(iso_str.strip())
            if parsed is not None:
                return parsed
        posix_val = raw_time.get("posix")
        if isinstance(posix_val, (int, float)):
            return _parse_posix_timestamp(posix_val)
    if isinstance(raw_time, (int, float)):
        return _parse_posix_timestamp(raw_time)
    if isinstance(raw_time, str) and raw_time.strip():
        return _parse_iso_datetime(raw_time.strip())
    return None


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

    def __repr__(self) -> str:
        safe_objects = [sanitize_mapping(obj) if isinstance(obj, dict) else obj for obj in self.objects]
        safe_err = redact_sid(self.error_message) if self.error_message else None
        return (
            f"ApiQueryResult(success={self.success!r}, objects={safe_objects!r}, "
            f"total={self.total!r}, error_message={safe_err!r}, code={self.code!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()
