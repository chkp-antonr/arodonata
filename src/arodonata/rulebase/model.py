"""Parsed rulebase structures shared by the cache, the numbering and the change report (pure: no DB or API imports).

Numbers here are Check Point's in-layer ``rule-number``s; hierarchical SmartConsole numbers are computed by
``arodonata.rulebase.numbering`` and never stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

RulebaseType = Literal["access", "nat", "https", "threat"]
ItemKind = Literal["rule", "place-holder"]

RULEBASE_CACHE_FORMAT = 2
RULEBASE_TYPES: tuple[RulebaseType, ...] = ("access", "nat", "https", "threat")
RULEBASE_COMMANDS: dict[RulebaseType, str] = {
    "access": "show-access-rulebase",
    "nat": "show-nat-rulebase",
    "https": "show-https-rulebase",
    "threat": "show-threat-rulebase",
}
RULE_ITEM_TYPES: dict[RulebaseType, str] = {
    "access": "access-rule",
    "nat": "nat-rule",
    "https": "https-rule",
    "threat": "threat-rule",
}
PLACEHOLDER_TYPE = "place-holder"


@dataclass(frozen=True)
class SectionItem:
    uid: str
    name: str
    from_number: int | None  # in-layer; None for an empty section
    to_number: int | None
    rules_before: int  # rules (and place-holders) preceding the section in the layer walk
    seq: int  # 0-based order among the layer's sections (tie-break for empty sections)
    raw: dict[str, Any]  # the section without its nested 'rulebase'


@dataclass(frozen=True)
class RuleItem:
    uid: str
    name: str
    kind: ItemKind
    rule_number: int  # in-layer 'rule-number'
    enabled: bool
    section_uid: str | None
    inline_layer_uid: str | None  # 'inline-layer' uid string (a dict is tolerated: its 'uid')
    domain_type: str  # the rule's 'domain.domain-type'
    auto_generated: bool  # NAT only; False elsewhere
    raw: dict[str, Any]


@dataclass(frozen=True)
class LayerSnapshot:
    rulebase_type: RulebaseType
    layer_uid: str
    layer_name: str  # NAT: the package name
    layer_domain_type: str  # from the package or listing entry; '' for layers reached only as inline layers
    total: int
    sections: tuple[SectionItem, ...]  # walk order (seq)
    items: tuple[RuleItem, ...]  # ordered by rule_number
    objects_dictionary: tuple[dict[str, str], ...]  # trimmed {uid, name, type}


@dataclass(frozen=True)
class OrderedLayer:
    rulebase_type: RulebaseType
    position: int  # order within package and type, 0-based (HTTPS: inbound 0, outbound 1)
    slot: str  # '' | 'inbound' | 'outbound'
    layer_uid: str
    layer_name: str
    layer_domain_type: str  # 'domain' | 'global domain' | ''
    placeholder_uid: str | None = None  # global layer with a linked place-holder only
    parent_rule_uid: str | None = None  # rule shown in place of the place-holder for this package
    parent_rule_name: str | None = None
    domain_layer_uid: str | None = None  # domain layer nested under the place-holder


@dataclass(frozen=True)
class PackageLayout:
    package_uid: str
    package_name: str
    layers: tuple[OrderedLayer, ...]  # sorted by (rulebase_type, position)


@dataclass(frozen=True)
class DomainRulebaseSnapshot:
    """One domain's rulebases. Canonical order: layers by (rulebase_type, layer_uid), packages by package_name."""

    mgmt_name: str
    domain_name: str
    session_uid: str | None
    session_published_time: datetime | None
    refreshed_at: datetime | None
    packages: tuple[PackageLayout, ...]
    layers: tuple[LayerSnapshot, ...]


@dataclass(frozen=True)
class DomainRefreshResult:
    mgmt_name: str
    domain_name: str
    status: Literal["ok", "unversioned", "fresh", "failed"]
    session_uid: str | None
    counts: dict[str, int]  # rules per rulebase type
    error: str | None
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class ParentRule:
    """The rule CP shows in place of a global place-holder when the global layer is read with ``package``."""

    uid: str
    name: str
    domain_layer_uid: str
