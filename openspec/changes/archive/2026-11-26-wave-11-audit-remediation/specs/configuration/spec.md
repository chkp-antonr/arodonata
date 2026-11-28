# Spec Delta

## MODIFIED Requirements

### Requirement: Operational Timeout, Cache TTL, and Sync Tuning Configuration

**ID**: REQ-CONFIG-009\
**Intent**: Expose typed, validated settings fields for multi-server API versions, ports, session TTLs, login throttling, cache windows, SQLite busy timeouts, pagination caps, CPCRUD schema path overrides, and topology confidence weights.\
**Non-goals**: Core required `mgmt_names`/`mgmt_servers` parsing (`REQ-CONFIG-001`) or timeout calculation rules (`REQ-CONFIG-004`).

`ArodonataSettings` SHALL expose and validate `api_versions`, `api_version`, `mgmt_port` (`1..65535`), `max_response_bytes` (`>= 1024`, default `67108864`), `max_query_pages` (`>= 1`, default `5000`), `max_query_objects` (`>= 1`, default `1000000`), `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights` with safe defaults and per-server resolution.

#### Scenario: SCN-CONFIG-009-1 — Operational and per-server version settings resolve with validated defaults and overrides

- **WHEN** `ArodonataSettings` is constructed with defaults or overrides (including `mgmt_port <= 0` / `> 65535`, `max_response_bytes < 1024`, `api_versions`, `api_version`, `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights`)
- **THEN** all fields SHALL enforce their Pydantic numeric bounds (`mgmt_port` within `1..65535`, `max_response_bytes >= 1024`) and per-server `api_versions` resolution SHALL fall back to `api_version` when a server entry is omitted

#### Scenario: SCN-CONFIG-009-2 — Pagination page and object caps bound api_query and rulebase paging

- **WHEN** `AMgmtClient.api_query()` exceeds `max_query_pages` or `max_query_objects`, OR `fetch_paged_rulebase()` exceeds `MAX_RULEBASE_OBJECTS`
- **THEN** `api_query()` SHALL return `ApiQueryResult(success=False, code="paging_limit_exceeded")` before unbounded accumulation, and rulebase paging SHALL stop cleanly at the configured object cap
