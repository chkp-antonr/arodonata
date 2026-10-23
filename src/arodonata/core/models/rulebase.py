"""Rulebase snapshot domain models for packages, layers, sections, and rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.models.common import utc_now

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
            self.id = (
                f"{self.mgmt_name}:{self.domain_name}:{self.package_uid}:"
                f"{self.rulebase_type}:{self.layer_uid}:{self.position}"
            )


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.rulebase_type}:{self.uid}"


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.layer_uid}:{self.uid}"


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.layer_uid}:{self.uid}"


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.package_uid}:{self.uid}"


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.layer_uid}:{self.uid}"


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
            self.id = f"{self.mgmt_name}:{self.domain_name}:{self.layer_uid}:{self.uid}"


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
