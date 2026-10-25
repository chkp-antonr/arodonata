# Rulebase Introspection, Caching, and Numbering Specification Delta

## ADDED Requirements

### Requirement: Local Rulebase Filtering and CPCRUD Rule Export

`filter_rulebase()` and `rule_to_cpcrud_operation()` SHALL evaluate search/filter queries locally against cached rulebases (`PackageRulebase` or `NumberedLayerRulebase`) with transitive object/service group expansion and convert matched access, NAT, HTTPS, and threat-prevention rules into schema-valid `cpcrud` operation dictionaries (`format="cpcrud"`).

#### Scenario: Convert matched access and NAT rules into valid CPCRUD operations

- **WHEN** `rule_to_cpcrud_operation(rule)` or `filter_rulebase(..., format="cpcrud")` is called on a cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, or `ThreatRuleEntry`
- **THEN** it SHALL return an operation dictionary (`operation`, `type`, `layer` or `package`, `key`, `data`) that passes `CPCRUDService.validate()` and normalizes Check Point NAT `"Original"` / `"Any"` sentinel UIDs
