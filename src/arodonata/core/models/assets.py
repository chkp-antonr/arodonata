"""Gateway, cluster, VSX, and management server asset models (`Asset`) and vendor-neutral classification."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.primitives import format_composite_id

AssetRole = Literal[
    "gateway",
    "cluster",
    "cluster_member",
    "vsx_gateway",
    "vsx_cluster",
    "vsx_cluster_member",
    "virtual_system",
    "management_server",
    "mds",
    "log_server",
    "interoperable_device",
    "unknown",
]

AssetPlatform = Literal[
    "gaia",
    "gaia_embedded",
    "maestro",
    "cloudguard",
    "open_server",
    "unknown",
]

POLICY_TARGET_ROLES: frozenset[str] = frozenset({"gateway", "cluster", "virtual_system"})

EXECUTION_TARGET_ROLES: frozenset[str] = frozenset(
    {
        "gateway",
        "cluster_member",
        "vsx_gateway",
        "vsx_cluster_member",
        "management_server",
        "mds",
        "log_server",
    }
)

_SMB_TOKEN_RE = re.compile(r"\bsmb\b")
_MAESTRO_TOKEN_RE = re.compile(r"\b(?:mho|smo|sgm)(?:[-_]?\d+)?\b")
_CLOUD_TOKEN_RE = re.compile(r"\b(?:aws|azure|gcp|vmss)\b")

_VENDOR_PLATFORM_KEYS: tuple[str, ...] = (
    "os-name",
    "os_name",
    "hardware",
    "appliance",
    "appliance-type",
    "appliance_type",
    "platform",
    "platform-type",
    "platform_type",
    "model",
    "deployment-type",
    "deployment_type",
    "cloud-provider",
    "cloud_provider",
)
_VENDOR_MAPPING_SUBKEYS: tuple[str, ...] = ("name", "type", "model", "vendor", "family", "platform")
_MGMT_POLICY_BLADE_KEYS: tuple[str, ...] = (
    "network-policy-management",
    "secondary",
    "primary",
    "smart-event-server",
    "smart-event-correlation",
)


def _extract_blades(source: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    for key in keys:
        val = source.get(key)
        if isinstance(val, Mapping):
            return val
    return {}


def _has_vsx_parent_hint(parent_type: str | None, raw: Mapping[str, Any]) -> bool:
    if parent_type:
        pt = parent_type.strip()
        if pt in {"vsx-cluster", "CpmiVsxClusterNetobj", "vsx-gateway", "CpmiVsxNetobj"} or "vsx" in pt.lower():
            return True
    if raw.get("vsx-cluster") or raw.get("vsx_cluster") or raw.get("vsx-gateway") or raw.get("vsx_gateway"):
        return True
    for key in ("cluster", "parent-cluster", "parent_cluster", "parent"):
        val = raw.get(key)
        if isinstance(val, Mapping):
            type_hint = f"{val.get('type') or ''} {val.get('class-name') or ''}".lower()
            if "vsx" in type_hint:
                return True
    return False


def _classify_host_ckp_blades(mgmt_blades: Mapping[str, Any]) -> AssetRole:
    if mgmt_blades.get("multi-domain-server") is True:
        return "mds"
    if any(mgmt_blades.get(k) is True for k in _MGMT_POLICY_BLADE_KEYS):
        return "management_server"
    if mgmt_blades.get("logging-and-status") is True:
        return "log_server"
    return "management_server"


def classify_asset_role(asset: Asset | Mapping[str, Any], *, parent_type: str | None = None) -> AssetRole:
    """Classify an `Asset` or raw Check Point payload into a normalized `AssetRole`."""
    if isinstance(asset, Asset):
        a_type = asset.type.strip()
        raw: Mapping[str, Any] = asset.raw_data
        net_blades: Mapping[str, Any] = asset.network_security_blades or _extract_blades(
            raw, "network-security-blades", "network_security_blades"
        )
        mgmt_blades: Mapping[str, Any] = asset.management_blades or _extract_blades(
            raw, "management-blades", "management_blades"
        )
    else:
        a_type = str(asset.get("type") or asset.get("class-name") or "").strip()
        raw = asset
        net_blades = _extract_blades(raw, "network-security-blades", "network_security_blades")
        mgmt_blades = _extract_blades(raw, "management-blades", "management_blades")

    if a_type == "interoperable-device":
        return "interoperable_device"
    if a_type in {"virtual-system", "vs-netobj", "CpmiVsNetobj", "CpmiVsClusterNetobj"}:
        return "virtual_system"
    if a_type in {"vsx-cluster-member", "CpmiVsxClusterMember"}:
        return "vsx_cluster_member"
    if a_type in {"cluster-member", "CpmiClusterMember"}:
        return "vsx_cluster_member" if _has_vsx_parent_hint(parent_type, raw) else "cluster_member"
    if a_type in {"vsx-cluster", "CpmiVsxClusterNetobj"}:
        return "vsx_cluster"
    if a_type in {"vsx-gateway", "CpmiVsxNetobj"}:
        return "vsx_gateway"
    if a_type in {"simple-cluster", "cluster", "CpmiGatewayCluster"}:
        return "cluster"
    if a_type in {"mds", "CpmiMds"}:
        return "mds"
    if a_type in {"checkpoint-host", "CpmiHostCkp"}:
        if a_type == "CpmiHostCkp" and net_blades.get("firewall") is True:
            return "gateway"
        return _classify_host_ckp_blades(mgmt_blades)
    if a_type in {"simple-gateway", "gateway", "CpmiGatewayPlain"}:
        return "gateway"

    lower_type = a_type.lower()
    if "interoperable" in lower_type:
        return "interoperable_device"
    if "member" in lower_type:
        return (
            "vsx_cluster_member"
            if ("vsx" in lower_type or _has_vsx_parent_hint(parent_type, raw))
            else "cluster_member"
        )
    if "vsx" in lower_type:
        return "vsx_cluster" if "cluster" in lower_type else "vsx_gateway"
    if "checkpoint-host" in lower_type or "hostckp" in lower_type:
        return _classify_host_ckp_blades(mgmt_blades)
    if "virtual-system" in lower_type:
        return "virtual_system"
    if "cluster" in lower_type:
        return "cluster"
    if "gateway" in lower_type:
        return "gateway"
    if "mds" in lower_type or mgmt_blades.get("multi-domain-server") is True:
        return "mds"
    if "log-server" in lower_type or "log_server" in lower_type:
        return "log_server"
    return "unknown"


def classify_asset_platform(asset: Asset | Mapping[str, Any]) -> AssetPlatform:
    """Classify an `Asset` or raw Check Point payload into a normalized `AssetPlatform` from vendor fields only."""
    parts: list[str] = []

    def _add_val(val: Any) -> None:
        if isinstance(val, str):
            stripped = val.strip()
            if stripped:
                parts.append(stripped)
        elif isinstance(val, Mapping):
            for subkey in _VENDOR_MAPPING_SUBKEYS:
                subval = val.get(subkey)
                if isinstance(subval, str):
                    stripped = subval.strip()
                    if stripped:
                        parts.append(stripped)

    if isinstance(asset, Asset):
        _add_val(asset.os_name)
        _add_val(asset.hardware)
        raw: Mapping[str, Any] = asset.raw_data
    else:
        raw = asset

    for key in _VENDOR_PLATFORM_KEYS:
        if key in raw:
            _add_val(raw.get(key))

    combined = " ".join(parts).lower()
    if not combined:
        return "unknown"

    if (
        "gaia embedded" in combined
        or "embedded gaia" in combined
        or "quantum spark" in combined
        or _SMB_TOKEN_RE.search(combined)
    ):
        return "gaia_embedded"
    if (
        "maestro" in combined
        or "scalable platform" in combined
        or "orchestrator" in combined
        or _MAESTRO_TOKEN_RE.search(combined)
    ):
        return "maestro"
    if (
        "cloudguard" in combined
        or "ve-series" in combined
        or "virtual edition" in combined
        or _CLOUD_TOKEN_RE.search(combined)
    ):
        return "cloudguard"
    if "open server" in combined or "open-server" in combined or "openserver" in combined:
        return "open_server"
    if "gaia" in combined:
        return "gaia"
    return "unknown"


def classify_asset(asset: Asset, *, parent_type: str | None = None) -> Asset:
    """Recompute vendor-neutral role, platform, and target flags on an `Asset`, returning an updated copy if needed."""
    role = classify_asset_role(asset, parent_type=parent_type)
    platform = classify_asset_platform(asset)
    is_policy = role in POLICY_TARGET_ROLES
    is_exec = role in EXECUTION_TARGET_ROLES
    if (
        asset.asset_role == role
        and asset.platform_family == platform
        and asset.is_policy_target == is_policy
        and asset.is_execution_target == is_exec
    ):
        return asset
    return asset.model_copy(
        update={
            "asset_role": role,
            "platform_family": platform,
            "is_policy_target": is_policy,
            "is_execution_target": is_exec,
        }
    )


class Asset(BaseModel):
    """Canonical Check Point gateway, cluster, cluster member, VSX, or server asset model."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
    asset_id: str = ""
    uid: str
    name: str
    type: str
    mgmt_name: str
    domain_name: str
    ipv4_address: str | None = Field(default=None, validation_alias=AliasChoices("ipv4_address", "ipv4-address"))
    ipv6_address: str | None = Field(default=None, validation_alias=AliasChoices("ipv6_address", "ipv6-address"))
    version: str | None = None
    os_name: str | None = Field(default=None, validation_alias=AliasChoices("os_name", "os-name"))
    hardware: str | None = None
    sic_status: str | None = Field(default=None, validation_alias=AliasChoices("sic_status", "sic-status"))
    parent_uid: str | None = None
    parent_name: str | None = None
    parent_id: str | None = None
    parent_asset_id: str | None = None
    member_uids: list[str] = Field(default_factory=list)
    member_asset_ids: list[str] = Field(default_factory=list)
    virtual_system_uids: list[str] = Field(default_factory=list)
    virtual_system_asset_ids: list[str] = Field(default_factory=list)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)
    network_security_blades: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("network_security_blades", "network-security-blades"),
    )
    management_blades: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("management_blades", "management-blades"),
    )
    asset_role: AssetRole = "unknown"
    platform_family: AssetPlatform = "unknown"
    is_policy_target: bool = False
    is_execution_target: bool = False
    comments: str = ""
    color: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.uid)
        if not self.asset_id:
            self.asset_id = format_composite_id(self.mgmt_name, self.domain_name, self.name)
        if self.parent_uid and not self.parent_id:
            self.parent_id = format_composite_id(self.mgmt_name, self.domain_name, self.parent_uid)
        if self.parent_name and not self.parent_asset_id:
            self.parent_asset_id = format_composite_id(self.mgmt_name, self.domain_name, self.parent_name)
        if "management_blades" not in self.model_fields_set and not self.management_blades:
            raw_mgmt_blades = self.raw_data.get("management-blades") or self.raw_data.get("management_blades")
            if isinstance(raw_mgmt_blades, Mapping):
                self.management_blades = dict(raw_mgmt_blades)
        if "asset_role" not in self.model_fields_set:
            self.asset_role = classify_asset_role(self)
        if "platform_family" not in self.model_fields_set:
            self.platform_family = classify_asset_platform(self)
        if "is_policy_target" not in self.model_fields_set:
            self.is_policy_target = self.asset_role in POLICY_TARGET_ROLES
        if "is_execution_target" not in self.model_fields_set:
            self.is_execution_target = self.asset_role in EXECUTION_TARGET_ROLES
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()

    @classmethod
    def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> Asset:
        """Construct an `Asset` from a raw Check Point gateway/server dictionary."""
        uid = str(data.get("uid") or "")
        name = str(data.get("name") or "")
        asset_type = str(data.get("type") or "gateway")
        interfaces_raw = data.get("interfaces")
        interfaces: list[dict[str, Any]] = []
        if isinstance(interfaces_raw, list):
            interfaces = [item for item in interfaces_raw if isinstance(item, dict)]
        elif isinstance(interfaces_raw, dict):
            objs = interfaces_raw.get("objects")
            if isinstance(objs, list):
                interfaces = [item for item in objs if isinstance(item, dict)]

        raw_net_blades = data.get("network-security-blades") or data.get("network_security_blades")
        net_blades = dict(raw_net_blades) if isinstance(raw_net_blades, Mapping) else {}
        raw_mgmt_blades = data.get("management-blades") or data.get("management_blades")
        mgmt_blades = dict(raw_mgmt_blades) if isinstance(raw_mgmt_blades, Mapping) else {}

        return cls(
            id=format_composite_id(mgmt_name, domain_name, uid),
            asset_id=format_composite_id(mgmt_name, domain_name, name),
            uid=uid,
            name=name,
            type=asset_type,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            ipv4_address=data.get("ipv4-address") or data.get("ipv4_address"),
            ipv6_address=data.get("ipv6-address") or data.get("ipv6_address"),
            version=data.get("version"),
            os_name=data.get("os-name") or data.get("os_name"),
            hardware=data.get("hardware"),
            sic_status=data.get("sic-status") or data.get("sic_status"),
            parent_uid=data.get("parent_uid"),
            parent_name=data.get("parent_name"),
            parent_id=data.get("parent_id"),
            parent_asset_id=data.get("parent_asset_id"),
            member_uids=list(data.get("member_uids") or []),
            member_asset_ids=list(data.get("member_asset_ids") or []),
            virtual_system_uids=list(data.get("virtual_system_uids") or []),
            virtual_system_asset_ids=list(data.get("virtual_system_asset_ids") or []),
            interfaces=interfaces,
            network_security_blades=net_blades,
            management_blades=mgmt_blades,
            comments=str(data.get("comments") or ""),
            color=data.get("color"),
            raw_data=dict(data),
        )
