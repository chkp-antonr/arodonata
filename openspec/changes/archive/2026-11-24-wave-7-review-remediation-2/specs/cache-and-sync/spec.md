# Spec Delta

## ADDED Requirements

### Requirement: Start-Epoch Slice Timestamping and Mid-Sync Invalidation Preservation

**ID**: REQ-CACHE-016\
**Intent**: Prevent domain or wildcard invalidations arriving while a slice refresh is executing from being masked by post-sync completion timestamps.\
**Non-goals**: Fresh-slice staleness probe invalidation preservation (`REQ-CACHE-015`) or multi-scope invalidation storage (`REQ-CACHE-004`).

When `ArodonataClient` synchronizes cached domain slices (`objects`, `services`, `assets`, `rulebase`, or `topology`), persisted `DomainSyncState.synced_at` timestamps SHALL record the pre-probe synchronization start time rather than completion time, and any `WriteSession` publish or `invalidate_domain()` call occurring during probe, lock acquisition, or slice execution SHALL preserve invalidation on subsequent `"smart"` and `"smart-fast"` reads.

#### Scenario: SCN-CACHE-016-1 — Mid-handler domain invalidation survives slice sync completion under advancing and frozen clocks

- **GIVEN** an in-flight `ArodonataClient` domain slice synchronization (`refresh_objects`, `refresh_services`, `refresh_assets`, `refresh_rulebases`, `refresh_package_rulebase`, or `refresh_topology`) whose staleness probe started at `T0`
- **WHEN** `WriteSession` publish or `invalidate_domain(mgmt_name, domain)` runs at `T1` while slice fetching or lock acquisition is still in progress (`T0 <= T1 <= T2` under advancing or frozen clocks) and the slice completes at `T2`
- **THEN** persisted `DomainSyncState.synced_at` SHALL reflect `T0` rather than `T2` and sequence watermarks SHALL NOT advance past the `T1` invalidation
- **AND** a subsequent `"smart"` or `"smart-fast"` read within `cache_ttl` SHALL treat the domain slice as invalidated instead of skipping server re-verification
