# Spec Delta

## ADDED Requirements

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
