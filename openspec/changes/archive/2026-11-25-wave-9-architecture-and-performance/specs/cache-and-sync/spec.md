# Spec Delta

## ADDED Requirements

### Requirement: Unified Typed Cache Sync Pipeline, Modular Search Package, and Shared VSX Linking

**ID**: REQ-CACHE-018\
**Intent**: Eliminate behavioral drift between duplicated object/service sync pipelines and improve modularity across `SearchService` and `VSXRelationshipManager` while preserving full backward compatibility.\
**Non-goals**: Cache SQL schema layout (`REQ-CACHE-001`) or cross-domain VSX distributed locking (`REQ-CACHE-017`).

`ObjectService` and `ServiceCacheService` SHALL share a unified typed sync/overlay pipeline, `SearchService` SHALL delegate through `arodonata.core.services.search` with full `search_service` import and `@traced` compatibility, and `AssetRefreshService` SHALL share cluster and VSX linking helpers.

#### Scenario: SCN-CACHE-018-1 — Unified typed cache sync and overlay pipeline keeps object and service parity

- **GIVEN** concurrent or sequential incremental (`smart-fast`), full (`force`), and `WriteSession`-overlay reads on `ObjectService` and `ServiceCacheService`
- **WHEN** `refresh_objects()`, `refresh_services()`, `get_objects()`, or `get_services()` executes
- **THEN** both services SHALL share identical incremental fallback, sync-progress emission, and `WriteSession` overlay semantics without type-normalization drift

#### Scenario: SCN-CACHE-018-2 — Decomposed search package and shared asset linking preserve public APIs and telemetry

- **GIVEN** imports from `arodonata.core.services.search_service` and VSX/cluster assets spanning single-domain and cross-domain enrichment
- **WHEN** callers invoke `SearchService` methods, `classify_search_term()`, `VSXRelationshipManager.enrich()`, and `reconcile_cross_domain()`
- **THEN** all exported symbols, `@traced` span names/qualnames, and hexagonal AST layer boundaries SHALL remain preserved
- **AND** cluster, local VSX, and cross-domain VSX parent-child links and slot metadata SHALL reconcile consistently without duplicated link loops
