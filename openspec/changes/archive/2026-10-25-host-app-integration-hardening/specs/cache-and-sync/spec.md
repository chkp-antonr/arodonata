# Cache, Synchronization, and Search Specification Delta

## MODIFIED Requirements

### Requirement: Schema Hash Auto-Migration and Multi-Backend Persistence

`DatabaseManager.initialize()` SHALL support both PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`, with a 30s busy timeout by default), store all database timestamps as **naive UTC** (`DateTime(timezone=False)`, `tzinfo=None`), compute a deterministic SHA-256 hash (`compute_schema_hash`) scoped strictly to Arodonata's managed table set (`ARODONATA_TABLE_NAMES`) to skip redundant per-table schema migration checks when the hash is already recorded in `arodonata_schema_version`, wrap additive DDL alterations in savepoints (`begin_nested()`), and automatically drop and recreate any Arodonata cache table whose existing primary key or required columns are incompatible with the current model.

#### Scenario: Unchanged schema hash skips table inspection

- **WHEN** `DatabaseManager.initialize()` runs and a row with the current `schema_hash` already exists in `arodonata_schema_version`
- **THEN** the database manager SHALL skip per-table column/index migration inspection and mark the database initialized immediately

#### Scenario: Schema evolution applies missing columns and records new hash

- **WHEN** the Arodonata SQLModel metadata changes (producing a new `schema_hash` not in `arodonata_schema_version`) on a database shared with host application tables in `SQLModel.metadata`
- **THEN** `DatabaseManager.initialize()` SHALL inspect only tables in `ARODONATA_TABLE_NAMES`, create any new Arodonata tables with naive UTC timestamp columns, add any missing columns/indexes safely inside per-statement savepoints (tolerating concurrent duplicate-column/index errors from sibling workers), and insert the new `schema_hash` row into `arodonata_schema_version`

#### Scenario: Legacy v1 cache table with incompatible primary key is dropped and recreated

- **WHEN** `DatabaseManager.initialize()` encounters an existing Arodonata table (such as legacy v1 `domains` with primary key `mdm_dmn` or `sid_cache` with primary key `mgmt_dmn_key`) whose primary key columns or `NOT NULL` columns do not match the v2 model
- **THEN** `DatabaseManager.initialize()` SHALL drop and recreate that Arodonata table with the v2 schema rather than failing on `ALTER TABLE`

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `SqlCacheAdapter` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in the `arodonata_assets` table across domains concurrently via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) and enrich parent-child relationships via `ClusterRelationshipManager` and `VSXRelationshipManager`.

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`max(1, concurrent_limit - 1)`), persist rows in `arodonata_assets` (avoiding collision with host application `assets` tables), emit typed `SyncProgressEvent` items (convertible to `SSEEvent` via `adapters.sse`) tagged with `mgmt_name` and `domain`, link cluster members and VSX virtual systems to their parent asset IDs, and update `domain_sync_state` (`scope="assets"`, `item_type="*"`)

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4 address, CIDR subnet, address range, wildcard pattern, UID, or object name), support `exact_match: bool = False` for case-insensitive exact name/FQDN matching, query cached objects (including any active `WriteSession` overlay in `contextvars`) across target servers and domains, and traverse parent group memberships up to `max_depth` (default 2), returning a typed `SearchResult`.

#### Scenario: Search resolves direct matches and containing groups

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects

#### Scenario: Exact-match name search avoids partial substring matches

- **WHEN** `await client.search_objects(".example.com", exact_match=True)` is called on a domain containing `.example.com` and `sub.example.com`
- **THEN** it SHALL return only `.example.com` (and its parent groups) without matching `sub.example.com`, while wildcard terms (`*.example.com`) continue to match via anchored `fnmatchcase`
