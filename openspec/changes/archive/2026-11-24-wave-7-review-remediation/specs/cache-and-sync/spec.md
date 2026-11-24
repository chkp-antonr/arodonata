# Spec Delta

## ADDED Requirements

### Requirement: In-Flight Sync Probe Invalidation Preservation

**ID**: REQ-CACHE-015\
**Intent**: Prevent concurrent publish or explicit domain invalidations from being lost when an in-flight smart staleness probe or sync completes.\
**Non-goals**: Multi-scope wildcard invalidation storage semantics (`REQ-CACHE-004`).

Domain and wildcard invalidations recorded via `invalidate_domain()` while a staleness probe or slice refresh is in flight SHALL survive probe or sync completion so pre-invalidation cache states are never marked fresh for remaining `cache_ttl` windows.

#### Scenario: SCN-CACHE-015-1 — Domain invalidation during in-flight smart probe survives probe completion

- **GIVEN** a domain cache whose synced head matches the initial `show-last-published-session` probe response
- **WHEN** `WriteSession` publish or `invalidate_domain(mgmt_name, domain)` executes after the staleness probe started (under advancing or frozen clocks) and the earlier probe later receives the pre-publish response
- **THEN** probe completion SHALL NOT stamp `synced_at` or record an invalidation sequence ahead of the in-flight invalidation
- **AND** subsequent `"smart"` or `"smart-fast"` reads within `cache_ttl` SHALL still treat the domain slice as invalidated
