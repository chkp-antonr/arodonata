"""Gateway, cluster, VSX, and management server asset models (`Asset`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now


class Asset(BaseModel):
    """Canonical Check Point gateway, cluster, cluster member, VSX, or server asset model."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
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
    member_uids: list[str] = Field(default_factory=list)
    virtual_system_uids: list[str] = Field(default_factory=list)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)
    network_security_blades: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("network_security_blades", "network-security-blades"),
    )
    comments: str = ""
    color: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.uid}"
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

        return cls(
            id=f"{mgmt_name}:{domain_name}:{uid}",
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
            member_uids=list(data.get("member_uids") or []),
            virtual_system_uids=list(data.get("virtual_system_uids") or []),
            interfaces=interfaces,
            network_security_blades=data.get("network-security-blades") or data.get("network_security_blades") or {},
            comments=str(data.get("comments") or ""),
            color=data.get("color"),
            raw_data=dict(data),
        )
