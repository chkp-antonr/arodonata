"""Service object domain models (`CPService`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.models.objects import _extract_member_uids, _extract_original_domain, _extract_tag_names


class CPService(BaseModel):
    """Canonical service object model stored in `arodonata_services`."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
    uid: str
    name: str
    type: str
    mgmt_name: str
    domain_name: str
    original_domain: str | None = None
    port: str | None = None
    protocol: str | None = None
    icmp_type: int | None = Field(default=None, validation_alias=AliasChoices("icmp_type", "icmp-type"))
    icmp_code: int | None = Field(default=None, validation_alias=AliasChoices("icmp_code", "icmp-code"))
    members: list[str] = Field(default_factory=list)
    session_timeout: int | None = Field(
        default=None, validation_alias=AliasChoices("session_timeout", "session-timeout")
    )
    match_for_any: bool | None = Field(default=None, validation_alias=AliasChoices("match_for_any", "match-for-any"))
    comments: str = ""
    color: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.uid}"
        if self.original_domain is None:
            self.original_domain = self.domain_name
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()

    @classmethod
    def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPService:
        """Construct a `CPService` from a raw Check Point Web API service dictionary."""
        uid = str(data.get("uid") or "")
        name = str(data.get("name") or "")
        svc_type = str(data.get("type") or "service-other")
        port_raw = data.get("port")
        protocol_raw = data.get("protocol") or data.get("ip-protocol")

        return cls(
            id=f"{mgmt_name}:{domain_name}:{uid}",
            uid=uid,
            name=name,
            type=svc_type,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            original_domain=_extract_original_domain(data, domain_name),
            port=str(port_raw) if port_raw is not None else None,
            protocol=str(protocol_raw) if protocol_raw is not None else None,
            icmp_type=data.get("icmp-type") if "icmp-type" in data else data.get("icmp_type"),
            icmp_code=data.get("icmp-code") if "icmp-code" in data else data.get("icmp_code"),
            members=_extract_member_uids(data.get("members")),
            session_timeout=data.get("session-timeout") if "session-timeout" in data else data.get("session_timeout"),
            match_for_any=data.get("match-for-any") if "match-for-any" in data else data.get("match_for_any"),
            comments=str(data.get("comments") or ""),
            color=data.get("color"),
            tags=_extract_tag_names(data.get("tags")),
            raw_data=dict(data),
        )
