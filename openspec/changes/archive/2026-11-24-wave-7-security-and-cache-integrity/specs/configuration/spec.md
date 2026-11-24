# Spec Delta

## MODIFIED Requirements

### Requirement: Operational Timeout, Cache TTL, and Sync Tuning Configuration

**ID**: REQ-CONFIG-009\
**Intent**: Expose typed, validated settings fields for multi-server API versions, ports, session TTLs, login throttling, cache windows, SQLite busy timeouts, CPCRUD schema path overrides, and topology confidence weights.\
**Non-goals**: Core required `mgmt_names`/`mgmt_servers` parsing (`REQ-CONFIG-001`) or timeout calculation rules (`REQ-CONFIG-004`).

`ArodonataSettings` SHALL expose and validate `api_versions`, `api_version`, `mgmt_port` (`1..65535`), `max_response_bytes` (`>= 1024`, default `67108864`), `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights`.

#### Scenario: SCN-CONFIG-009-1 — Operational and per-server version settings resolve with validated defaults and overrides

- **WHEN** `ArodonataSettings` is constructed with defaults or overrides (including `mgmt_port <= 0` / `> 65535`, `max_response_bytes < 1024`, `api_versions`, `api_version`, `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights`)
- **THEN** all fields SHALL enforce their Pydantic numeric bounds (`mgmt_port` within `1..65535`, `max_response_bytes >= 1024`) and per-server `api_versions` resolution SHALL fall back to `api_version` when a server entry is omitted
