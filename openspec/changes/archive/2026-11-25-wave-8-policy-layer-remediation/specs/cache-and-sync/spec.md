# Spec Delta

## ADDED Requirements

### Requirement: Lock-Serialized Per-Management Cross-Domain VSX Reconciliation

**ID**: REQ-CACHE-017\
**Intent**: Prevent unlocked cross-domain VSX asset overwrites, unintended writes during `cache` mode, and bare-UID collisions across multiple management servers.\
**Non-goals**: Single-domain asset synchronization (`REQ-CACHE-008`) or cluster enrichment (`REQ-CACHE-009`).

`AssetRefreshService` SHALL skip cross-domain VSX reconciliation when `mode == "cache"` or no domains were written, partition asset lookups by `(mgmt_name, uid)` to avoid cross-management UID collisions, and serialize cross-domain VSX updates under a per-management distributed lock.

#### Scenario: SCN-CACHE-017-1 — Cross-domain VSX reconciliation skips cache mode and serializes per management server

- **GIVEN** multi-management cached assets with overlapping UIDs across `mgmt_name`s or concurrent `refresh_assets()` calls
- **WHEN** `get_assets(cache_mode="cache")` or `refresh_assets()` executes
- **THEN** `mode == "cache"` (and no-op refreshes) SHALL perform zero cross-domain asset writes
- **AND** active refreshes SHALL key assets by `(mgmt_name, uid)` and serialize cross-domain VSX updates under a per-management distributed lock
