"""Rulebase snapshot domain models for packages, layers, sections, and rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.primitives import format_composite_id

RulebaseType = Literal["access", "nat", "https", "threat"]


class RulebasePackageLayerEntry(BaseModel):
    """Links a policy package to an ordered layer or NAT policy in `rulebase_package_layer`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    package_uid: str
    package_name: str
    rulebase_type: RulebaseType
    layer_uid: str
    layer_name: str
    position: int = 0
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(
                self.mgmt_name,
                self.domain_name,
                self.package_uid,
                self.rulebase_type,
                self.layer_uid,
                self.position,
            )
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class RulebaseLayerEntry(BaseModel):
    """Cached rulebase layer metadata in `rulebase_layer`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    uid: str
    name: str
    rulebase_type: RulebaseType
    parent_layer_uid: str | None = None
    parent_rule_uid: str | None = None
    is_global: bool = False
    shared: bool = False
    implicit_cleanup_action: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.rulebase_type, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class RulebaseSectionEntry(BaseModel):
    """Cached rulebase section header in `rulebase_section`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    rulebase_type: RulebaseType
    uid: str
    name: str
    position: int = 0
    from_rule: int | None = None
    to_rule: int | None = None
    rule_uids: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.layer_uid, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class AccessRuleEntry(BaseModel):
    """Cached access-control rule or placeholder in `rulebase_access`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    section_uid: str | None = None
    section_name: str | None = None
    uid: str
    name: str = ""
    rule_type: str = "access-rule"
    position: int = 0
    rule_number: str | None = None
    enabled: bool = True
    action: str | None = None
    inline_layer_uid: str | None = None
    inline_layer_name: str | None = None
    placeholder_domain_layer_uid: str | None = None
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    source_negate: bool = False
    destination_negate: bool = False
    service_negate: bool = False
    track: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.layer_uid, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class NatRuleEntry(BaseModel):
    """Cached NAT rule in `rulebase_nat`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    package_uid: str
    package_name: str
    section_uid: str | None = None
    section_name: str | None = None
    uid: str
    name: str = ""
    rule_type: str = "nat-rule"
    position: int = 0
    rule_number: str | None = None
    enabled: bool = True
    method: str | None = None
    auto_generated: bool = False
    original_source: str | None = None
    original_destination: str | None = None
    original_service: str | None = None
    translated_source: str | None = None
    translated_destination: str | None = None
    translated_service: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.package_uid, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class HttpsRuleEntry(BaseModel):
    """Cached HTTPS inspection rule in `rulebase_https`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    section_uid: str | None = None
    section_name: str | None = None
    uid: str
    name: str = ""
    rule_type: str = "https-rule"
    position: int = 0
    rule_number: str | None = None
    enabled: bool = True
    action: str | None = None
    inline_layer_uid: str | None = None
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    site_category: list[str] = Field(default_factory=list)
    certificate: str | None = None
    track: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.layer_uid, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class ThreatRuleEntry(BaseModel):
    """Cached Threat Prevention rule in `rulebase_threat`."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    section_uid: str | None = None
    section_name: str | None = None
    uid: str
    name: str = ""
    rule_type: str = "threat-rule"
    position: int = 0
    rule_number: str | None = None
    enabled: bool = True
    action: str | None = None
    protected_scope: list[str] = Field(default_factory=list)
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    track: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.domain_name, self.layer_uid, self.uid)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class DomainRulebaseSnapshot(BaseModel):
    """Complete rulebase snapshot for a single `(mgmt_name, domain_name)` replaced atomically."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    package_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
    layers: list[RulebaseLayerEntry] = Field(default_factory=list)
    sections: list[RulebaseSectionEntry] = Field(default_factory=list)
    access_rules: list[AccessRuleEntry] = Field(default_factory=list)
    nat_rules: list[NatRuleEntry] = Field(default_factory=list)
    https_rules: list[HttpsRuleEntry] = Field(default_factory=list)
    threat_rules: list[ThreatRuleEntry] = Field(default_factory=list)


class PolicyPackageInfo(BaseModel):
    """Summary of a cached policy package and its attached ordered layers / NAT policy."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    uid: str
    name: str
    has_nat_policy: bool = False
    access_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
    https_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
    threat_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


def extract_policy_packages(snapshot: DomainRulebaseSnapshot) -> list[PolicyPackageInfo]:
    """Build `PolicyPackageInfo` models from `snapshot.package_layers`."""
    pkgs_by_uid: dict[str, PolicyPackageInfo] = {}
    ordered_uids: list[str] = []

    sorted_entries = sorted(
        snapshot.package_layers,
        key=lambda e: (e.package_name, e.package_uid, e.rulebase_type, e.position),
    )

    for entry in sorted_entries:
        if entry.package_uid not in pkgs_by_uid:
            pkgs_by_uid[entry.package_uid] = PolicyPackageInfo(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                uid=entry.package_uid,
                name=entry.package_name,
                raw_data=dict(entry.raw_data),
                updated_at=entry.updated_at,
            )
            ordered_uids.append(entry.package_uid)

        pkg = pkgs_by_uid[entry.package_uid]
        if entry.rulebase_type == "nat":
            pkg.has_nat_policy = True
        elif entry.rulebase_type == "access":
            pkg.access_layers.append(entry)
        elif entry.rulebase_type == "https":
            pkg.https_layers.append(entry)
        elif entry.rulebase_type == "threat":
            pkg.threat_layers.append(entry)

    # Also detect packages that have NAT rules even if package_layers had no explicit nat entry
    for nr in snapshot.nat_rules:
        if nr.package_uid not in pkgs_by_uid:
            pkgs_by_uid[nr.package_uid] = PolicyPackageInfo(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                uid=nr.package_uid,
                name=nr.package_name,
                has_nat_policy=True,
                updated_at=nr.updated_at,
            )
            ordered_uids.append(nr.package_uid)
        else:
            pkgs_by_uid[nr.package_uid].has_nat_policy = True

    return [pkgs_by_uid[u] for u in ordered_uids]


__all__ = [
    "AccessRuleEntry",
    "DomainRulebaseSnapshot",
    "HttpsRuleEntry",
    "NatRuleEntry",
    "PolicyPackageInfo",
    "RulebaseLayerEntry",
    "RulebasePackageLayerEntry",
    "RulebaseSectionEntry",
    "RulebaseType",
    "ThreatRuleEntry",
    "extract_policy_packages",
]
