# Spec Delta

## MODIFIED Requirements

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `SqlCacheAdapter` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in `arodonata_assets` concurrently across domains via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) with UID primary keys (`id`) and indexed composite identifiers (`asset_id`).

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`max(1, concurrent_limit - 1)`), persist rows in `arodonata_assets` (avoiding collision with host application `assets` tables), emit typed `SyncProgressEvent` items (convertible to `SSEEvent` via `adapters.sse`) tagged with `mgmt_name` and `domain`, link cluster members and VSX virtual systems to their parent asset UIDs and composite IDs (`parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`), and update `domain_sync_state` (`scope="assets"`, `item_type="*"`)

#### Scenario: Cross-domain VSX gateway and Virtual System topology reconciliation

- **WHEN** a VSX gateway (`vsx_gateway` or `vsx_cluster`) is cached in one domain (e.g., `"VSX"`) and its Virtual System (`virtual_system`) is cached in another domain (e.g., `"Domain4"`) on the same management server (`mgmt_name`)
- **THEN** asset relationship reconciliation SHALL populate the Virtual System's `parent_uid`, `parent_name`, `parent_id` (`"mds:VSX:<vsx-uid>"`), and `parent_asset_id` (`"mds:VSX:<vsx-name>"`), and populate the parent VSX asset's `virtual_system_uids` and `virtual_system_asset_ids` (`["mds:Domain4:<vs-name>"]`)

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4, CIDR, address range, wildcard, UID, composite ID, or name), support `exact_match: bool = False`, query cached objects with active `WriteSession` `contextvars` overlays across target servers/domains, and resolve parent group memberships up to `max_depth` (default 2) into `SearchResult` with dual UID and composite group links.

#### Scenario: Search resolves direct matches and containing groups with human-readable composite IDs

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects, with each `GroupMembershipNode` populated with `id`, `object_id`, `parent_uids`, and `parent_object_ids`

#### Scenario: Exact-match name search avoids partial substring matches

- **WHEN** `await client.search_objects(".example.com", exact_match=True)` is called on a domain containing `.example.com` and `sub.example.com`
- **THEN** it SHALL return only `.example.com` (and its parent groups) without matching `sub.example.com`, while wildcard terms (`*.example.com`) continue to match via anchored `fnmatchcase`

## ADDED Requirements

### Requirement: Cluster and Cross-Domain VSX Parent-Child Topology Enrichment

`ClusterRelationshipManager` and `VSXRelationshipManager` SHALL enrich cached `arodonata_assets` rows with bidirectional parent-child topology attributes (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`), including cross-domain VSX parent/child links on the same management server.

#### Scenario: Cluster members and VSX virtual systems link bidirectionally to parent containers

- **WHEN** asset refresh reconciles cluster members and VSX virtual systems on `mgmt_name`
- **THEN** each child member or virtual system SHALL reference its parent's UID and composite `asset_id`, and each parent cluster or VSX container SHALL list all child UIDs and composite `asset_id`s across domains on `mgmt_name`

### Requirement: Exclusive Coordinator-Synchronized Rulebase Cache Writes

Shared `arodonata_rulebase_*` cache tables SHALL be written exclusively under `DomainSyncCoordinator` per-domain distributed locks after `verify_session_clean` succeeds and within an atomic transaction that updates `arodonata_domain_sync_state` (`scope="rulebase"`, `item_type="*"`); read-only consumers (including `arodonata.reports`) SHALL NEVER invoke `CachePort.replace_domain_rulebase` directly out-of-band.

#### Scenario: Concurrent report generation cannot overwrite a newer stamped rulebase snapshot

- **WHEN** `refresh_rulebases` updates `arodonata_rulebase_*` and `arodonata_domain_sync_state` while a concurrent `collect_change_report` call numbers rule changes
- **THEN** `collect_change_report` SHALL NOT perform unlocked `replace_domain_rulebase` writes that could replace the newer cached rulebase under a fresh `DomainSyncState` stamp

### Requirement: Cross-Domain Group Member Resolution with Ambiguity Detection

`SearchService.get_group_members()` SHALL reject empty or whitespace-only `group_name_or_uid` inputs with `ValidationError`, and when `domain` is `None` (and not encoded in a `mgmt:domain:name` composite ID) SHALL resolve the target container across cached domains including `"Global"` using `cache_mode="cache"`, raising `AmbiguousObjectError` if matching containers exist in more than one domain.

#### Scenario: Cross-domain group member lookup detects multi-domain name collision without whole-MDS sync

- **WHEN** `SearchService.get_group_members(mgmt_name, None, "SharedGroup")` runs against a cache where `"SharedGroup"` exists in two distinct domains
- **THEN** it SHALL execute zero remote domain refreshes (`cache_mode="cache"`) and raise `AmbiguousObjectError` enumerating the matching domains and composite identifiers
