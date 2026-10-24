"""Typed domain models for rulebase introspection, SmartConsole numbering, and local filtering."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.models.common import SyncStatus, utc_now
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    RulebaseType,
    ThreatRuleEntry,
)

RuleFormat = Literal["markdown", "model_friendly", "raw"]


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


class NumberedRule(BaseModel):
    """A rule or placeholder carrying its dynamically computed SmartConsole hierarchical number."""

    model_config = ConfigDict(extra="ignore")

    uid: str
    name: str = ""
    rule_number: str
    position: int = 0
    rule_type: str = "access-rule"
    rulebase_type: RulebaseType = "access"
    enabled: bool = True
    layer_uid: str = ""
    layer_name: str = ""
    package_uid: str | None = None
    package_name: str | None = None
    section_uid: str | None = None
    section_name: str | None = None
    parent_rule_uid: str | None = None
    action: str | None = None
    method: str | None = None
    inline_layer_uid: str | None = None
    inline_layer_name: str | None = None
    placeholder_domain_layer_uid: str | None = None
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    source_negate: bool = False
    destination_negate: bool = False
    service_negate: bool = False
    original_source: str | None = None
    original_destination: str | None = None
    original_service: str | None = None
    translated_source: str | None = None
    translated_destination: str | None = None
    translated_service: str | None = None
    site_category: list[str] = Field(default_factory=list)
    certificate: str | None = None
    protected_scope: list[str] = Field(default_factory=list)
    track: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    children: list[NumberedRule] = Field(default_factory=list)
    nested_sections: list[NumberedSection] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_access_entry(
        cls,
        entry: AccessRuleEntry,
        *,
        rule_number: str,
        package_uid: str | None = None,
        package_name: str | None = None,
        parent_rule_uid: str | None = None,
        children: list[NumberedRule] | None = None,
        nested_sections: list[NumberedSection] | None = None,
    ) -> NumberedRule:
        """Construct a `NumberedRule` from an `AccessRuleEntry`."""
        return cls(
            uid=entry.uid,
            name=entry.name,
            rule_number=rule_number,
            position=entry.position,
            rule_type=entry.rule_type,
            rulebase_type="access",
            enabled=entry.enabled,
            layer_uid=entry.layer_uid,
            layer_name=entry.layer_name,
            package_uid=package_uid,
            package_name=package_name,
            section_uid=entry.section_uid,
            section_name=entry.section_name,
            parent_rule_uid=parent_rule_uid,
            action=entry.action,
            inline_layer_uid=entry.inline_layer_uid,
            inline_layer_name=entry.inline_layer_name,
            placeholder_domain_layer_uid=entry.placeholder_domain_layer_uid,
            source=list(entry.source),
            destination=list(entry.destination),
            service=list(entry.service),
            source_negate=entry.source_negate,
            destination_negate=entry.destination_negate,
            service_negate=entry.service_negate,
            track=entry.track,
            install_on=list(entry.install_on),
            comments=entry.comments,
            children=list(children or []),
            nested_sections=list(nested_sections or []),
            raw_data=dict(entry.raw_data),
        )

    @classmethod
    def from_nat_entry(
        cls,
        entry: NatRuleEntry,
        *,
        rule_number: str,
    ) -> NumberedRule:
        """Construct a `NumberedRule` from a `NatRuleEntry`."""
        return cls(
            uid=entry.uid,
            name=entry.name,
            rule_number=rule_number,
            position=entry.position,
            rule_type=entry.rule_type,
            rulebase_type="nat",
            enabled=entry.enabled,
            layer_uid=entry.package_uid,
            layer_name=entry.package_name,
            package_uid=entry.package_uid,
            package_name=entry.package_name,
            section_uid=entry.section_uid,
            section_name=entry.section_name,
            method=entry.method,
            original_source=entry.original_source,
            original_destination=entry.original_destination,
            original_service=entry.original_service,
            translated_source=entry.translated_source,
            translated_destination=entry.translated_destination,
            translated_service=entry.translated_service,
            install_on=list(entry.install_on),
            comments=entry.comments,
            raw_data=dict(entry.raw_data),
        )

    @classmethod
    def from_https_entry(
        cls,
        entry: HttpsRuleEntry,
        *,
        rule_number: str,
        package_uid: str | None = None,
        package_name: str | None = None,
        parent_rule_uid: str | None = None,
        children: list[NumberedRule] | None = None,
        nested_sections: list[NumberedSection] | None = None,
    ) -> NumberedRule:
        """Construct a `NumberedRule` from an `HttpsRuleEntry`."""
        return cls(
            uid=entry.uid,
            name=entry.name,
            rule_number=rule_number,
            position=entry.position,
            rule_type=entry.rule_type,
            rulebase_type="https",
            enabled=entry.enabled,
            layer_uid=entry.layer_uid,
            layer_name=entry.layer_name,
            package_uid=package_uid,
            package_name=package_name,
            section_uid=entry.section_uid,
            section_name=entry.section_name,
            parent_rule_uid=parent_rule_uid,
            action=entry.action,
            inline_layer_uid=entry.inline_layer_uid,
            source=list(entry.source),
            destination=list(entry.destination),
            service=list(entry.service),
            site_category=list(entry.site_category),
            certificate=entry.certificate,
            track=entry.track,
            install_on=list(entry.install_on),
            comments=entry.comments,
            children=list(children or []),
            nested_sections=list(nested_sections or []),
            raw_data=dict(entry.raw_data),
        )

    @classmethod
    def from_threat_entry(
        cls,
        entry: ThreatRuleEntry,
        *,
        rule_number: str,
        package_uid: str | None = None,
        package_name: str | None = None,
        parent_rule_uid: str | None = None,
    ) -> NumberedRule:
        """Construct a `NumberedRule` from a `ThreatRuleEntry`."""
        return cls(
            uid=entry.uid,
            name=entry.name,
            rule_number=rule_number,
            position=entry.position,
            rule_type=entry.rule_type,
            rulebase_type="threat",
            enabled=entry.enabled,
            layer_uid=entry.layer_uid,
            layer_name=entry.layer_name,
            package_uid=package_uid,
            package_name=package_name,
            section_uid=entry.section_uid,
            section_name=entry.section_name,
            parent_rule_uid=parent_rule_uid,
            action=entry.action,
            protected_scope=list(entry.protected_scope),
            source=list(entry.source),
            destination=list(entry.destination),
            service=list(entry.service),
            track=entry.track,
            install_on=list(entry.install_on),
            comments=entry.comments,
            raw_data=dict(entry.raw_data),
        )


class NumberedSection(BaseModel):
    """A rulebase section header with SmartConsole range display (`1-3`, `2.1-2.2`, or `No Rules`)."""

    model_config = ConfigDict(extra="ignore")

    uid: str
    name: str
    position: int = 0
    layer_uid: str = ""
    layer_name: str = ""
    rulebase_type: RulebaseType = "access"
    range_label: str = "No Rules"
    from_rule: str | None = None
    to_rule: str | None = None
    rules: list[NumberedRule] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_section_entry(
        cls,
        sec: RulebaseSectionEntry,
        rules: list[NumberedRule],
    ) -> NumberedSection:
        """Construct a `NumberedSection` with computed SmartConsole `range_label`."""
        if not rules:
            range_label = "No Rules"
            from_num: str | None = None
            to_num: str | None = None
        else:
            from_num = rules[0].rule_number
            to_num = rules[-1].rule_number
            range_label = from_num if from_num == to_num else f"{from_num}-{to_num}"
        return cls(
            uid=sec.uid,
            name=sec.name,
            position=sec.position,
            layer_uid=sec.layer_uid,
            layer_name=sec.layer_name,
            rulebase_type=sec.rulebase_type,
            range_label=range_label,
            from_rule=from_num,
            to_rule=to_num,
            rules=list(rules),
            raw_data=dict(sec.raw_data),
        )


class NumberedLayerRulebase(BaseModel):
    """Numbered rulebase for a single ordered or standalone layer (with inline/placeholder expansions)."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    rulebase_type: RulebaseType
    package_uid: str | None = None
    package_name: str | None = None
    prefix: str = ""
    is_global: bool = False
    implicit_cleanup_action: str | None = None
    sections: list[NumberedSection] = Field(default_factory=list)
    rules: list[NumberedRule] = Field(default_factory=list)
    flat_rules: list[NumberedRule] = Field(default_factory=list)
    snapshot_session_uid: str | None = None
    snapshot_published_at: datetime | None = None
    sync_status: SyncStatus = "idle"
    layer_metadata: RulebaseLayerEntry | None = None


class PackageRulebase(BaseModel):
    """SmartConsole-numbered rulebase for a policy package across its ordered layers or NAT policy."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    package_uid: str
    package_name: str
    rulebase_type: RulebaseType = "access"
    layers: list[NumberedLayerRulebase] = Field(default_factory=list)
    sections: list[NumberedSection] = Field(default_factory=list)
    rules: list[NumberedRule] = Field(default_factory=list)
    flat_rules: list[NumberedRule] = Field(default_factory=list)
    snapshot_session_uid: str | None = None
    snapshot_published_at: datetime | None = None
    sync_status: SyncStatus = "idle"


class RuleLocation(BaseModel):
    """A single SmartConsole position of a rule within a package and/or layer."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    rule_uid: str
    rule_name: str = ""
    rule_number: str
    position: int = 0
    rulebase_type: RulebaseType = "access"
    package_uid: str | None = None
    package_name: str | None = None
    layer_uid: str
    layer_name: str
    section_uid: str | None = None
    section_name: str | None = None
    section_range: str | None = None
    parent_rule_uid: str | None = None
    context: Literal["package", "layer"] = "package"


class LayerPrefixLocation(BaseModel):
    """Numbering prefix (`""`, `"2."`, `"2.2."`) of a layer in a package or standalone context."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    layer_uid: str
    layer_name: str
    rulebase_type: RulebaseType = "access"
    prefix: str = ""
    package_uid: str | None = None
    package_name: str | None = None
    parent_layer_uid: str | None = None
    parent_rule_uid: str | None = None
    context: Literal["package", "layer"] = "package"


class RuleLocations(BaseModel):
    """Result of `locate_rules(...)` across all packages and layers of a domain."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    rule_locations: dict[str, list[RuleLocation]] = Field(default_factory=dict)
    layer_prefixes: dict[str, list[LayerPrefixLocation]] = Field(default_factory=dict)
    snapshot_session_uid: str | None = None
    snapshot_published_at: datetime | None = None
    sync_status: SyncStatus = "idle"


class FilteredRulebaseResult(BaseModel):
    """Result of evaluating a filter locally against a cached rulebase snapshot."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    target_name: str
    target_uid: str
    rulebase_type: RulebaseType
    query: str = ""
    format: RuleFormat = "model_friendly"
    total_rules: int = 0
    matched_count: int = 0
    rules: list[NumberedRule] = Field(default_factory=list)
    rendered_text: str = ""
    raw_items: list[dict[str, Any]] = Field(default_factory=list)
    source: Literal["cache", "live"] = "cache"
    cache_age_seconds: float | None = None
    snapshot_session_uid: str | None = None
    snapshot_published_at: datetime | None = None


NumberedRule.model_rebuild()
NumberedSection.model_rebuild()

__all__ = [
    "FilteredRulebaseResult",
    "LayerPrefixLocation",
    "NumberedLayerRulebase",
    "NumberedRule",
    "NumberedSection",
    "PackageRulebase",
    "PolicyPackageInfo",
    "RuleFormat",
    "RuleLocation",
    "RuleLocations",
]
