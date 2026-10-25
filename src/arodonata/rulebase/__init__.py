"""Rulebase introspection, snapshot caching, SmartConsole numbering, and local filtering (`arodonata.rulebase`)."""

from arodonata.rulebase.filter import (
    filter_numbered_rulebase,
    format_rules_markdown,
    format_rules_model_friendly,
    rule_matches_filter,
    rule_to_cpcrud_operation,
)
from arodonata.rulebase.models import (
    FilteredRulebaseResult,
    LayerPrefixLocation,
    NumberedLayerRulebase,
    NumberedRule,
    NumberedSection,
    PackageRulebase,
    PolicyPackageInfo,
    RuleFormat,
    RuleLocation,
    RuleLocations,
)
from arodonata.rulebase.numbering import (
    extract_policy_packages,
    locate_rules_in_snapshot,
    number_layer_rulebase,
    number_package_rulebase,
)
from arodonata.rulebase.pager import (
    MAX_RULEBASE_PAGE_LIMIT,
    RULEBASE_TYPE_TO_COMMAND,
    PagedRulebaseResult,
    fetch_paged_rulebase,
    parse_access_rule_entry,
    parse_https_rule_entry,
    parse_nat_rule_entry,
    parse_threat_rule_entry,
)
from arodonata.rulebase.refresh import (
    RulebaseRefreshService,
    collect_domain_rulebase_snapshot,
)
from arodonata.rulebase.source import CachedRulebaseSource

__all__ = [
    "CachedRulebaseSource",
    "FilteredRulebaseResult",
    "LayerPrefixLocation",
    "MAX_RULEBASE_PAGE_LIMIT",
    "NumberedLayerRulebase",
    "NumberedRule",
    "NumberedSection",
    "PackageRulebase",
    "PagedRulebaseResult",
    "PolicyPackageInfo",
    "RULEBASE_TYPE_TO_COMMAND",
    "RuleFormat",
    "RuleLocation",
    "RuleLocations",
    "RulebaseRefreshService",
    "collect_domain_rulebase_snapshot",
    "extract_policy_packages",
    "fetch_paged_rulebase",
    "filter_numbered_rulebase",
    "format_rules_markdown",
    "format_rules_model_friendly",
    "locate_rules_in_snapshot",
    "number_layer_rulebase",
    "number_package_rulebase",
    "parse_access_rule_entry",
    "parse_https_rule_entry",
    "parse_nat_rule_entry",
    "parse_threat_rule_entry",
    "rule_matches_filter",
    "rule_to_cpcrud_operation",
]
