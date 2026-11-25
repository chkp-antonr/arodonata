# Rulebase Introspection, Caching, and Numbering Specification

## Purpose

Defines multi-domain rulebase snapshot caching (`RulebaseRefreshService`, `DomainSyncCoordinator`), continuity-verified rulebase pagination (`fetch_paged_rulebase`), SmartConsole-accurate hierarchical rule numbering (`CachedRulebaseSource`, `number_package_rulebase`, `number_layer_rulebase`), and package/layer introspection APIs (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`, `filter_rulebase`).

## Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

**ID**: REQ-RULE-001\
**Intent**: Keep cached domain rulebases internally consistent and protected against dirty-session reads or partial writes.\
**Non-goals**: Lightweight package-only or single-package synchronization slices (`REQ-RULE-002`, `REQ-RULE-003`).

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's `arodonata_rulebase_*` snapshot and `arodonata_domain_sync_state` (`scope="rulebase"`) in one atomic transaction under a per-domain distributed lock with heartbeat renewal, tracking freshness via the last published session UID and preserving `last_published_at=None` for never-published domains.

#### Scenario: SCN-RULE-001-1 — Refusal to refresh when shared session is dirty

- **GIVEN** a domain whose shared API session holds unpublished changes or locks (`number-of-published-changes` / `locks` non-zero) or where `show-session` fails
- **WHEN** `refresh_rulebases` runs for that domain
- **THEN** the refresh SHALL refuse to proceed (failing closed on `show-session` error) and preserve any existing cached rulebase snapshot
- **AND** `arodonata_domain_sync_state.status` (`scope="rulebase"`) SHALL be recorded as `"failed"` with `sid`-redacted `last_error`

#### Scenario: SCN-RULE-001-2 — Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **GIVEN** a clean domain session under a renewed per-domain distributed lock
- **WHEN** `refresh_rulebases` fetches the domain's rulebases
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, and every access, HTTPS, and threat layer reachable from packages, layer listings, or inline-layer references
- **AND** for any global layer containing a domain `place-holder`, it SHALL query the global layer with `package` context to resolve the parent rule and nested domain layer
- **AND** it SHALL replace the domain's rows across `arodonata_rulebase_*` and update `arodonata_domain_sync_state` in a single atomic transaction

#### Scenario: SCN-RULE-001-3 — Rulebase pager merges split sections across page boundaries

- **GIVEN** Check Point `show-*-rulebase` pagination in chunks of up to 100 rules where a `rulebase-section` header repeats across consecutive pages
- **WHEN** `fetch_paged_rulebase()` fetches the rulebase
- **THEN** it SHALL merge the split section into a single section entry containing all of its rules in order
- **AND** it SHALL recover empty trailing sections

### Requirement: Lightweight Policy Package Catalog Synchronization

**ID**: REQ-RULE-002\
**Intent**: Allow fast listing of policy packages without downloading full domain rulebases.\
**Non-goals**: Synchronizing rulebase layers or rules (`REQ-RULE-001`, `REQ-RULE-003`).

The rulebase service SHALL synchronize and return policy package metadata (`get_policy_packages`, `refresh_policy_packages`) using a package-only synchronization slice (`scope="rulebase"`, `item_type="packages"`) when the full domain rulebase snapshot (`item_type="*"`) is not yet fresh, querying `show-packages` without downloading NAT, HTTPS, threat-prevention, or access rulebases.

#### Scenario: SCN-RULE-002-1 — Cold-cache get_policy_packages queries show-packages without fetching rulebases

- **GIVEN** a domain whose `scope="rulebase"` cache has neither a fresh `"*"` snapshot nor a fresh `"packages"` slice
- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs
- **THEN** the system SHALL verify the shared session is clean under the domain lock and fetch `show-packages`
- **AND** it SHALL atomically replace package-catalog metadata and update `item_type="packages"` sync state without stamping `item_type="*"`
- **AND** it SHALL execute zero `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase` calls

#### Scenario: SCN-RULE-002-2 — Fresh full rulebase snapshot satisfies get_policy_packages from cache

- **GIVEN** a domain whose full `scope="rulebase"`, `item_type="*"` snapshot already matches the domain's published session head
- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs
- **THEN** the system SHALL return the cached `PolicyPackageInfo` list without issuing `show-packages` again

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

### Requirement: SmartConsole-Identical Hierarchical Rule Numbering

**ID**: REQ-RULE-004\
**Intent**: Produce SmartConsole-exact rule numbers and cross-package positions from cached snapshots.\
**Non-goals**: Fetching rulebases from Check Point (`REQ-RULE-001`..`REQ-RULE-003`) or filtering rules (`REQ-RULE-005`).

`arodonata.rulebase` (`CachedRulebaseSource`, `number_package_rulebase`, `number_layer_rulebase`) SHALL compute hierarchical rule and section numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, or `No Rules`) dynamically from the domain's cached rulebase snapshot so that numbers match SmartConsole display both in package context (`get_package_rulebase`) and standalone layer context (`get_layer_rulebase`).

#### Scenario: SCN-RULE-004-1 — Package rulebase numbering expands global placeholders and inline layers

- **GIVEN** a policy package whose rulebase includes a Global layer with a `place-holder` and rules calling inline layers
- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type="access")` is called
- **THEN** the returned `PackageRulebase` SHALL number top-level rules sequentially (`1`, `2`, ...)
- **AND** it SHALL expand the domain layer under the global placeholder's parent rule with dotted numbers (`2.1`, `2.2`, ...)
- **AND** it SHALL expand inline layers beneath their calling rule (`2.2.1`, ...)

#### Scenario: SCN-RULE-004-2 — Locate rules across all packages and layers of a domain

- **WHEN** `locate_rules(mgmt_name, domain_name, rule_uids=[...], layer_uids=[...])` is called
- **THEN** it SHALL return `RuleLocations` mapping each rule UID to all of its SmartConsole positions across packages and layers
- **AND** it SHALL map each layer UID to its numbering prefixes (`""`, `"2."`, `"2.2."`) along with `snapshot_session_uid`, `snapshot_published_at`, and sync status

#### Scenario: SCN-RULE-004-3 — Automatic domain resolution and ambiguity error for domainless calls

- **WHEN** `get_package_rulebase` or `get_layer_rulebase` is called with `domain_name=None` or `""`
- **THEN** the client SHALL resolve the unique cached domain containing that package or layer (or the sole cached domain on an SMS)
- **AND** if multiple cached domains contain a matching name or UID, it SHALL raise `AmbiguousLayerName` listing all `(domain, uid)` candidates

### Requirement: Local Rulebase Filtering and CPCRUD Rule Export

**ID**: REQ-RULE-005\
**Intent**: Search cached rulebases offline with transitive group expansion and export matched rules directly into CPCRUD templates.\
**Non-goals**: Planning or applying CPCRUD rule mutations against Check Point (`REQ-CPCRUD-008`, `REQ-CPCRUD-009`).

`filter_rulebase()` and `rule_to_cpcrud_operation()` SHALL evaluate search/filter queries locally against cached rulebases (`PackageRulebase` or `NumberedLayerRulebase`) with transitive object/service group expansion and convert matched access, NAT, HTTPS, and threat-prevention rules into schema-valid `cpcrud` operation dictionaries (`output_format="cpcrud"`).

#### Scenario: SCN-RULE-005-1 — Convert matched access and NAT rules into valid CPCRUD operations

- **WHEN** `rule_to_cpcrud_operation(rule)` or `filter_rulebase(..., output_format="cpcrud")` is called on a cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, or `ThreatRuleEntry`
- **THEN** it SHALL return a flat operation dictionary (`operation`, `type`, `layer` or `package`, `uid`, `name`, `source`/`destination`/`service` or NAT `original-*`/`translated-*` keys) compatible with `CPCRUDService.validate({"operations": [...]})`
- **AND** it SHALL normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs

### Requirement: Public Rulebase Numbering and Formatting Helper Exports

**ID**: REQ-RULE-006\
**Intent**: Export pure rulebase filtering, SmartConsole formatting, policy-package extraction, and standalone snapshot helpers cleanly under `arodonata.rulebase`.\
**Non-goals**: Coordinator-synchronized database persistence (`REQ-RULE-002`, `REQ-RULE-003`).

`arodonata.rulebase` SHALL export `filter_numbered_rulebase`, `format_rules_markdown`, `format_rules_model_friendly`, `extract_policy_packages`, and `collect_domain_rulebase_snapshot` alongside model and numbering primitives so downstream tools and custom adapters can format and inspect snapshots offline.

#### Scenario: SCN-RULE-006-1 — Public rulebase formatting and package extraction helpers work standalone on snapshot objects

- **WHEN** callers invoke `extract_policy_packages()`, `filter_numbered_rulebase()`, `format_rules_markdown()`, `format_rules_model_friendly()`, or `collect_domain_rulebase_snapshot()` from `arodonata.rulebase`
- **THEN** `extract_policy_packages` SHALL extract `PolicyPackageInfo` entries from a domain snapshot
- **AND** `filter_numbered_rulebase`, `format_rules_markdown`, and `format_rules_model_friendly` SHALL render filtered rules deterministically offline

### Requirement: Complete Layer Pagination, Advancing Zero-Rule Pages, and Prefix Continuity

**ID**: REQ-RULE-007\
**Intent**: Prevent silent rulebase snapshot truncation from unpaginated layer listings, zero-rule advancing pages, or missing post-fetch completeness checks.\
**Non-goals**: Base SmartConsole hierarchical numbering (`REQ-RULE-004`) or local filtering (`REQ-RULE-005`).

Rulebase synchronization SHALL paginate `show-access-layers`, `show-https-layers`, and `show-threat-layers` via `api_query`, continue rulebase paging across zero-rule advancing pages (`to > offset`), fail closed if collected rule count is less than `total_reported` before committing `status="ok"`, unify synthetic fallback UIDs, and record layer prefixes for empty or name-keyed layers.

#### Scenario: SCN-RULE-007-1 — Paginated layer discovery and zero-rule advancing pages never truncate snapshots

- **GIVEN** a domain with more than 50 standalone layers OR a rulebase page where `data["to"] > offset` returns zero rules (e.g., empty sections) before `total_reported`
- **WHEN** `refresh_rulebases()` or `fetch_paged_rulebase()` executes
- **THEN** layer discovery SHALL paginate all layers via `api_query` and rulebase paging SHALL continue across zero-rule advancing pages without the `' blade'` typo or diverging fallback UIDs
- **AND** if upstream pagination stops short of `total_reported`, rulebase refresh SHALL raise an error and record `status="failed"` rather than committing a truncated snapshot as `"ok"`

#### Scenario: SCN-RULE-007-2 — Empty inline/placeholder layers and layer-name lookups preserve prefix locations

- **GIVEN** an inline layer or Global-placeholder-embedded domain layer with zero child rules, OR a `show-changes` entry keyed by layer name instead of UID
- **WHEN** SmartConsole rulebase numbering and placement resolve layer prefixes
- **THEN** `LayerPrefixLocation` entries SHALL still be recorded for empty inline/placeholder layers and indexed under requested layer-name keys

### Requirement: Precomputed Group and Pattern Index for Rulebase Filtering

**ID**: REQ-RULE-008\
**Intent**: Eliminate quadratic `O(R * T * (|O| + |S|))` group-graph rebuilding and IP/CIDR re-parsing on the event loop during local rulebase filtering.\
**Non-goals**: Remote Check Point server-side rulebase search or SmartConsole rule numbering rules (`REQ-RULE-004`).

`filter_numbered_rulebase` SHALL precompute query IP/CIDR tokens, object and service `reverse_parents` membership graphs, and per-token matching identifier sets once per invocation and reuse them across all evaluated rules while preserving identical match results for both `filter_numbered_rulebase` and direct `rule_matches_filter` callers.

#### Scenario: SCN-RULE-008-1 — Precomputed rulebase filter index preserves exact match parity in linear group-graph time

- **GIVEN** a numbered rulebase with nested object/service groups and IP/CIDR or name filter tokens
- **WHEN** `filter_numbered_rulebase()` evaluates all rules alongside direct `rule_matches_filter()` calls on individual rules
- **THEN** `filter_numbered_rulebase()` SHALL build the object and service membership graphs at most once rather than per rule
- **AND** matched rule UIDs and ordering SHALL match direct `rule_matches_filter()` evaluation identically across nested group, IP, CIDR, range, and wildcard tokens
