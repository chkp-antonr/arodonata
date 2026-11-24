# Spec Delta

## MODIFIED Requirements

### Requirement: Targeted Single-Package Rulebase Synchronization

**ID**: REQ-RULE-003\
**Intent**: Avoid downloading unrelated policy packages and rulebases when inspecting one target package.\
**Non-goals**: Cross-package full-domain `locate_rules` indexing (`REQ-RULE-001`, `REQ-RULE-004`).

When `get_package_rulebase` or `refresh_package_rulebase` runs with `cache_mode != "cache"` without a fresh `item_type="*"` snapshot, it SHALL evaluate slice-scoped invalidation (`scope="rulebase"`, `item_type="package:<rulebase_type>:<package_uid>"`, `synced_at`), honor `cache_ttl` once synced, and sync only the target package catalog and reachable layers.

#### Scenario: SCN-RULE-003-1 — Cold-cache access rulebase read for one package skips NAT, HTTPS, Threat, and sibling packages

- **GIVEN** a domain containing multiple policy packages, NAT policies, HTTPS layers, threat layers, and standalone layers
- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package="Branch_Pkg", rulebase_type="access", cache_mode="smart")` runs
- **THEN** the system SHALL fetch only package metadata, the ordered access layers of `"Branch_Pkg"`, any Global placeholder expansion in `"Branch_Pkg"` context, and referenced inline access sub-layers
- **AND** it SHALL persist those layers and record `item_type="package:access:<package_uid>"` without stamping `item_type="*"`
- **AND** it SHALL return SmartConsole-numbered sections and rules identical to a full domain snapshot

#### Scenario: SCN-RULE-003-2 — Locate rules still requires or triggers full domain rulebase snapshot

- **GIVEN** a domain where only a targeted `item_type="package:access:<package_uid>"` slice is cached
- **WHEN** `locate_rules(mgmt_name, domain_name, ...)` or `refresh_rulebases(...)` runs
- **THEN** the system SHALL treat `item_type="*"` as unsynced until a full domain rulebase snapshot completes so cross-package rule location never omits sibling packages

#### Scenario: SCN-RULE-003-3 — Single-package rulebase refresh honors cache_ttl once domain invalidation is satisfied

- **GIVEN** a domain previously marked invalidated via `invalidate_domain(mgmt_name, domain)` followed by a completed `refresh_package_rulebase(..., package="Branch_Pkg", rulebase_type="access")`
- **WHEN** a subsequent `refresh_package_rulebase` runs within `cache_ttl` in `"smart"` or `"smart-fast"` mode for that same package slice
- **THEN** invalidation checking SHALL compare the target `(scope="rulebase", item_type="package:access:<package_uid>")` `synced_at` timestamp instead of treating domain invalidation as permanent
- **AND** the refresh SHALL honor `cache_ttl` and skip remote rulebase probes until `cache_ttl` expires or a newer invalidation occurs
