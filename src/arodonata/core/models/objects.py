"""Network object domain models (`CPObject`) and search result structures."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now


def _extract_member_uids(raw_members: Any) -> list[str]:
    """Normalize Check Point group `members` list (UID strings or object dicts) into UID strings."""
    if not isinstance(raw_members, list):
        return []
    uids: list[str] = []
    for item in raw_members:
        if isinstance(item, str) and item:
            uids.append(item)
        elif isinstance(item, dict):
            uid = item.get("uid")
            if isinstance(uid, str) and uid:
                uids.append(uid)
    return uids


def _extract_tag_names(raw_tags: Any) -> list[str]:
    """Normalize Check Point `tags` list into tag name strings."""
    if not isinstance(raw_tags, list):
        return []
    names: list[str] = []
    for item in raw_tags:
        if isinstance(item, str) and item:
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("uid")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _extract_original_domain(data: dict[str, Any], fallback_domain: str) -> str:
    """Resolve the owning domain name from Check Point `domain` sub-object."""
    domain_obj = data.get("domain")
    if isinstance(domain_obj, dict):
        name = domain_obj.get("name")
        if isinstance(name, str) and name:
            return name
    return fallback_domain


class CPObject(BaseModel):
    """Canonical network object model stored in `arodonata_objects`."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
    uid: str
    name: str
    type: str
    mgmt_name: str
    domain_name: str
    original_domain: str | None = None
    ipv4_address: str | None = Field(default=None, validation_alias=AliasChoices("ipv4_address", "ipv4-address"))
    ipv6_address: str | None = Field(default=None, validation_alias=AliasChoices("ipv6_address", "ipv6-address"))
    subnet4: str | None = None
    mask_length4: int | None = Field(default=None, validation_alias=AliasChoices("mask_length4", "mask-length4"))
    subnet_mask: str | None = Field(default=None, validation_alias=AliasChoices("subnet_mask", "subnet-mask"))
    ipv4_address_first: str | None = Field(
        default=None, validation_alias=AliasChoices("ipv4_address_first", "ipv4-address-first")
    )
    ipv4_address_last: str | None = Field(
        default=None, validation_alias=AliasChoices("ipv4_address_last", "ipv4-address-last")
    )
    fqdn: str | None = None
    is_sub_domain: bool | None = Field(default=None, validation_alias=AliasChoices("is_sub_domain", "is-sub-domain"))
    members: list[str] = Field(default_factory=list)
    comments: str = ""
    color: str | None = None
    tags: list[str] = Field(default_factory=list)
    nat_settings: dict[str, Any] = Field(
        default_factory=dict, validation_alias=AliasChoices("nat_settings", "nat-settings")
    )
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.uid}"
        if self.original_domain is None:
            self.original_domain = self.domain_name
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()

    @classmethod
    def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPObject:
        """Construct a `CPObject` from a raw Check Point Web API object dictionary."""
        uid = str(data.get("uid") or "")
        name = str(data.get("name") or "")
        obj_type = str(data.get("type") or "unknown")
        fqdn = data.get("fqdn")
        if fqdn is None and obj_type == "dns-domain" and name.startswith("."):
            fqdn = name.lstrip(".")

        return cls(
            id=f"{mgmt_name}:{domain_name}:{uid}",
            uid=uid,
            name=name,
            type=obj_type,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            original_domain=_extract_original_domain(data, domain_name),
            ipv4_address=data.get("ipv4-address") or data.get("ipv4_address"),
            ipv6_address=data.get("ipv6-address") or data.get("ipv6_address"),
            subnet4=data.get("subnet4"),
            mask_length4=data.get("mask-length4") or data.get("mask_length4"),
            subnet_mask=data.get("subnet-mask") or data.get("subnet_mask"),
            ipv4_address_first=data.get("ipv4-address-first") or data.get("ipv4_address_first"),
            ipv4_address_last=data.get("ipv4-address-last") or data.get("ipv4_address_last"),
            fqdn=fqdn,
            is_sub_domain=data.get("is-sub-domain") if "is-sub-domain" in data else data.get("is_sub_domain"),
            members=_extract_member_uids(data.get("members")),
            comments=str(data.get("comments") or ""),
            color=data.get("color"),
            tags=_extract_tag_names(data.get("tags")),
            nat_settings=data.get("nat-settings") or data.get("nat_settings") or {},
            raw_data=dict(data),
        )


class GroupMembershipNode(BaseModel):
    """Represents a group that directly or transitively contains a matched object."""

    model_config = ConfigDict(extra="ignore")

    uid: str
    name: str
    mgmt_name: str
    domain_name: str
    depth: int = 1
    parent_uids: list[str] = Field(default_factory=list)


class SearchResult(BaseModel):
    """Result of `search_objects` with direct object matches and containing group hierarchies."""

    model_config = ConfigDict(extra="ignore")

    query: str
    matches: list[CPObject] = Field(default_factory=list)
    memberships: dict[str, list[GroupMembershipNode]] = Field(default_factory=dict)
