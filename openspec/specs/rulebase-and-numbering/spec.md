# Rulebase Introspection, Caching, and Numbering Specification

## Purpose

Defines multi-domain rulebase snapshot caching (`RulebaseRefreshService`, `DomainSyncCoordinator`), rulebase pagination (`rulebase/pager.py`), SmartConsole-accurate hierarchical rule numbering (`rulebase/numbering.py`, `CachedRulebaseSource`), and package/layer introspection APIs (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`).

## Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's rulebase snapshot (`arodonata_rulebase_*` tables) and `arodonata_domain_sync_state` (`scope="rulebase"`) in a single atomic database transaction protected by a per-domain distributed lock with periodic heartbeat renewal, tracking freshness against the domain's last published session UID and preserving `last_published_at=None` for never-published domains.

#### Scenario: Refusal to refresh when shared session is dirty

- **WHEN** `refresh_rulebases` runs for a domain whose shared API session currently holds unpublished changes or object locks (`number-of-published-changes` / `locks` non-zero) or where `show-session` fails
- **THEN** the refresh for that domain SHALL refuse to proceed (failing closed on `show-session` error), preserve any existing cached rulebase snapshot, and mark `arodonata_domain_sync_state.status = "failed"` (`scope="rulebase"`) with SID-redacted `last_error`

#### Scenario: Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **WHEN** `refresh_rulebases` reads a clean domain
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, every access/HTTPS/threat layer reachable from packages, layer listings, or inline-layer rule references, and for any global layer containing a domain `place-holder`, query the global layer with `package` context to resolve the parent rule and nested domain layer, replacing the domain's snapshot rows across `arodonata_rulebase_*` AND updating `arodonata_domain_sync_state` inside a single atomic database transaction under a renewed domain lock

#### Scenario: Rulebase pager merges split sections across page boundaries

- **WHEN** `rulebase/pager.py` pages `show-*-rulebase` in chunks of up to 100 rules and Check Point repeats a `rulebase-section` header across two consecutive pages
- **THEN** the pager SHALL merge the split section into a single section entry containing all of its rules in order and recover empty trailing sections

### Requirement: SmartConsole-Identical Hierarchical Rule Numbering

`arodonata.rulebase.numbering` and `CachedRulebaseSource` SHALL compute hierarchical rule and section numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, or `No Rules`) dynamically from the domain's cached rulebase snapshot so that numbers match SmartConsole display both in package context (`get_package_rulebase`) and standalone layer context (`get_layer_rulebase`).

#### Scenario: Package rulebase numbering expands global placeholders and inline layers

- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type="access")` is called for a package that includes a Global layer with a `place-holder` and rules calling inline layers
- **THEN** the returned `PackageRulebase` SHALL number top-level rules sequentially (`1`, `2`, ...), expand the domain layer under the global placeholder's parent rule with dotted numbers (`2.1`, `2.2`, ...), and expand inline layers beneath their calling rule (`2.2.1`, ...)

#### Scenario: Locate rules across all packages and layers of a domain

- **WHEN** `locate_rules(mgmt_name, domain_name, rule_uids=[...], layer_uids=[...])` is called
- **THEN** it SHALL return `RuleLocations` mapping each rule UID to all of its SmartConsole positions across packages/layers and each layer UID to its numbering prefixes (`""`, `"2."`, `"2.2."`), along with `snapshot_session_uid`, `snapshot_published_at`, and sync status

#### Scenario: Automatic domain resolution and ambiguity error for domainless calls

- **WHEN** `get_package_rulebase` or `get_layer_rulebase` is called with `domain_name=None` or `""`
- **THEN** the client SHALL resolve the unique cached domain containing that package or layer (or the single cached domain on an SMS); if multiple cached domains contain a matching name/UID, it SHALL raise `AmbiguousLayerName` listing all `(domain, uid)` candidates

### Requirement: Local Rulebase Filtering and CPCRUD Rule Export

`filter_rulebase()` and `rule_to_cpcrud_operation()` SHALL evaluate search/filter queries locally against cached rulebases (`PackageRulebase` or `NumberedLayerRulebase`) with transitive object/service group expansion and convert matched access, NAT, HTTPS, and threat-prevention rules into schema-valid `cpcrud` operation dictionaries (`format="cpcrud"`).

#### Scenario: Convert matched access and NAT rules into valid CPCRUD operations

- **WHEN** `rule_to_cpcrud_operation(rule)` or `filter_rulebase(..., format="cpcrud")` is called on a cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, or `ThreatRuleEntry`
- **THEN** it SHALL return an operation dictionary (`operation`, `type`, `layer` or `package`, `key`, `data`) that passes `CPCRUDService.validate()` and normalizes Check Point NAT `"Original"` / `"Any"` sentinel UIDs
