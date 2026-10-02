"""Rulebase reading helpers shared by the cache and live paths (pure: no DB or API imports)."""

from .model import (
    PLACEHOLDER_TYPE,
    RULE_ITEM_TYPES,
    RULEBASE_CACHE_FORMAT,
    RULEBASE_COMMANDS,
    RULEBASE_TYPES,
    DomainRefreshResult,
    DomainRulebaseSnapshot,
    ItemKind,
    LayerSnapshot,
    OrderedLayer,
    PackageLayout,
    ParentRule,
    RulebaseType,
    RuleItem,
    SectionItem,
)
from .numbering import NumberedEntry, number_layer, number_package, section_range
from .pager import RULEBASE_PAGE_SIZE, UNSUPPORTED_CODES, RulebaseFetchError, fetch_full_rulebase
from .parse import find_parent_rule, link_placeholder, objects_map, parse_layer_response, parse_packages

__all__ = [
    "PLACEHOLDER_TYPE",
    "RULEBASE_CACHE_FORMAT",
    "RULEBASE_COMMANDS",
    "RULEBASE_PAGE_SIZE",
    "RULEBASE_TYPES",
    "RULE_ITEM_TYPES",
    "UNSUPPORTED_CODES",
    "DomainRefreshResult",
    "DomainRulebaseSnapshot",
    "ItemKind",
    "LayerSnapshot",
    "NumberedEntry",
    "OrderedLayer",
    "PackageLayout",
    "ParentRule",
    "RuleItem",
    "RulebaseFetchError",
    "RulebaseType",
    "SectionItem",
    "fetch_full_rulebase",
    "find_parent_rule",
    "link_placeholder",
    "number_layer",
    "number_package",
    "objects_map",
    "parse_layer_response",
    "parse_packages",
    "section_range",
]
