# Spec Delta

## ADDED Requirements

### Requirement: Single-Flight Coalescing Freshness Integrity and Hardened SQLite Cache Permissions

**ID**: REQ-CACHE-020\
**Intent**: Prevent stale or offline single-flight operations from suppressing concurrent smart refreshes and ensure existing SQLite cache files reject symlinks and enforce owner-only permissions.\
**Non-goals**: Base domain sync lock heartbeats (`REQ-CACHE-004`) or schema hash auto-migration (`REQ-CACHE-001`).

`DomainSyncCoordinator` SHALL prevent `mode="cache"`, looser-TTL skips, and mid-flight-invalidated flights from suppressing concurrent `mode="smart"` waiters or mislabeling fresh slices as `"failed"`, and `DatabaseManager` SHALL reject SQLite symlinks and tighten pre-existing SQLite cache files to `0o600`.

#### Scenario: SCN-CACHE-020-1 — Single-flight coalescing preserves mid-flight invalidations, mode="cache" isolation, and fresh sibling slices

- **GIVEN** concurrent `DomainSyncCoordinator.stream_ensure()` callers across `mode="cache"`, `mode="smart"` with differing `cache_ttl` values, or mid-flight `invalidate_domain()` calls
- **WHEN** a `mode="cache"` or TTL-skipped leader completes, an invalidation arrives mid-flight, or one stale item type fails while sibling item types already passed
- **THEN** waiters requiring server verification or observing newer invalidations SHALL NOT skip syncing, and sibling `fresh_types` SHALL retain `status="ok"`

#### Scenario: SCN-CACHE-020-2 — DatabaseManager rejects SQLite symlinks and enforces 0o600 on pre-existing cache files

- **GIVEN** a pre-existing SQLite cache path that is a symlink (including a dangling symlink) or an owner-owned regular file with `0644` permissions
- **WHEN** `DatabaseManager.initialize()` opens the SQLite engine
- **THEN** symlinks and non-regular files SHALL fail closed before SQLite opens them, and pre-existing regular files with group/other permission bits SHALL be tightened to `0o600`
