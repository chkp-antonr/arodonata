# Spec Delta: Rulebase Introspection, Caching, and Numbering

## ADDED Requirements

### Requirement: Lightweight Policy Package Catalog Synchronization

The rulebase service SHALL synchronize and return policy package metadata (`get_policy_packages`, `refresh_policy_packages`) using a package-only synchronization slice (`scope="rulebase"`, `item_type="packages"`) when the full domain rulebase snapshot (`item_type="*"`) is not yet fresh, querying `show-packages` without downloading NAT, HTTPS, threat-prevention, or access rulebases.

#### Scenario: Cold-cache get_policy_packages queries show-packages without fetching rulebases

- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs on a domain whose `scope="rulebase"` cache has neither a fresh `"*"` snapshot nor a fresh `"packages"` slice
- **THEN** the system SHALL verify the shared session is clean under the domain lock, fetch `show-packages`, atomically replace the domain's package-catalog metadata and update `item_type="packages"` sync state without marking `item_type="*"` as synced, and perform zero `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase` calls

#### Scenario: Fresh full rulebase snapshot satisfies get_policy_packages from cache

- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs on a domain whose full `scope="rulebase"`, `item_type="*"` snapshot already matches the domain's published session head
- **THEN** the system SHALL return the cached `PolicyPackageInfo` list without issuing `show-packages` again

### Requirement: Targeted Single-Package Rulebase Synchronization

When `get_package_rulebase` (or `refresh_package_rulebase`) runs with `cache_mode != "cache"` on a domain lacking a fresh full `item_type="*"` snapshot, the system SHALL synchronize only the target package's catalog entry and the layers reachable for the requested `(package, rulebase_type)` slice (`item_type="package:<rulebase_type>:<package_uid>"`), skipping unrelated packages, standalone unused layers, and other rulebase types.

#### Scenario: Cold-cache access rulebase read for one package skips NAT, HTTPS, Threat, and sibling packages

- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package="Branch_Pkg", rulebase_type="access", cache_mode="smart")` runs in a domain containing multiple policy packages, NAT policies, HTTPS layers, threat layers, and standalone layers
- **THEN** the system SHALL fetch only package metadata, the ordered access layers of `"Branch_Pkg"`, any Global placeholder access expansion in `"Branch_Pkg"` context, and any inline access sub-layers referenced by rules in `"Branch_Pkg"`, persist those layers and record `item_type="package:access:<package_uid>"` without stamping `item_type="*"`, and return SmartConsole-numbered sections and rules identical to a full domain snapshot

#### Scenario: Locate rules still requires or triggers full domain rulebase snapshot

- **WHEN** `locate_rules(mgmt_name, domain_name, ...)` or `refresh_rulebases(...)` runs after a targeted single-package sync populated `item_type="package:access:<package_uid>"`
- **THEN** the system SHALL treat `item_type="*"` as unsynced until a full domain rulebase snapshot completes, ensuring cross-package rule location never omits unsynced sibling packages
