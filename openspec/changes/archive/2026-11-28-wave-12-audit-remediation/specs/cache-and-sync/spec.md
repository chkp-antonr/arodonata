# Spec Delta

## ADDED Requirements

### Requirement: Hardened SQLite Paths, Race-Free VSX Reconciliation, and Unified Search Filtering

**ID**: REQ-CACHE-021\
**Intent**: Prevent SQLite permission bypasses, cross-domain VSX upsert races, stale cold-failure timestamps, discovery secret leaks, and search filter inconsistencies.\
**Non-goals**: Changing SQLite/PostgreSQL schema table columns or `Asset` classification taxonomy (`REQ-CACHE-019`).

Database initialization MUST validate regular-file/symlink safety and `0o600` permissions even on concurrent creation or injected SQLite engines. Cross-domain VSX reconciliation MUST update only VSX-linking columns on existing rows, cold failures MUST preserve `synced_at=None`, discovery logs and `ApiQueryResult.__repr__` MUST scrub secrets, and search MUST handle `ip_subnet` on `Asset` and `types=[]`.

#### Scenario: SCN-CACHE-021-1 — SQLite hardening, cold failure synced_at, invalidation watermark, and discovery redaction

- **GIVEN** concurrent SQLite file initialization or an injected file-backed SQLite engine, a failed cold domain sync, a mid-flight domain-list invalidation, or a failing `show-domains` response
- **WHEN** `DatabaseManager` initializes, sync/discovery failures record state, or `DomainListRefreshTracker.mark_refreshed()` completes
- **THEN** SQLite paths SHALL verify non-symlink regular files with `0o600` mode, cold failed slices SHALL retain `synced_at=None`, and mid-flight invalidations SHALL remain preserved
- **AND** domain discovery warnings and `ApiQueryResult.__repr__` SHALL redact SIDs and secrets

#### Scenario: SCN-CACHE-021-2 — Race-free partial VSX reconciliation and strict member exclusions

- **GIVEN** concurrent per-domain `refresh_assets()` runs alongside cross-domain VSX reconciliation, or mixed cluster/VSX payloads containing Virtual Systems and VSX cluster members
- **WHEN** `reconcile_cross_domain()` persists VSX links or `ClusterRelationshipManager.enrich()` links hierarchy relationships
- **THEN** cross-domain reconciliation SHALL update only VSX-linking columns conditionally on existing rows without overwriting concurrent domain refreshes or resurrecting deleted assets
- **AND** Virtual Systems SHALL be excluded from cluster member lists and VSX members excluded from VSX parent candidates per `SCN-CACHE-019-5`

#### Scenario: SCN-CACHE-021-3 — Asset ip_subnet matching, empty types=[] short-circuit, and shared type partitioning

- **GIVEN** cached `Asset` rows with primary or interface IPs queried with `ip_subnet`, or a `search_objects()` / `query_objects()` call with `types=[]`
- **WHEN** `SearchService` partitions entity types and evaluates queries
- **THEN** `query_objects(ip_subnet=...)` SHALL evaluate CIDR/range containment against `Asset` primary and interface IPv4 addresses
- **AND** explicit `types=[]` SHALL return zero matches without refreshing or querying default types via one unified type-partitioning helper
