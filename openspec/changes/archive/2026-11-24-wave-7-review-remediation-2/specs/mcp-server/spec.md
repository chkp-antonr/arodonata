# Spec Delta

## ADDED Requirements

### Requirement: Bounded Multi-Domain Fan-Out Quota Charging and Slot Rollback

**ID**: REQ-MCP-014\
**Intent**: Allow a single full-MDS `cache_control` refresh per idle window at default rate limits while rejecting oversize explicit fan-out calls cleanly without leaking quota slots.\
**Non-goals**: Base per-caller sliding-window rate-limit enforcement (`REQ-MCP-012`) or offline domain pre-validation (`REQ-MCP-013`).

When `live_tool_rate_limit_per_minute > 0`, implicit all-domain `cache_control(action="refresh")` (`domain=None`, `domains=None`) SHALL cap single-call live cost at `live_tool_rate_limit_per_minute` on an empty live bucket, while explicit `cache_control(domains=...)` or `change_report(scopes=...)` requests exceeding `live_tool_rate_limit_per_minute` SHALL fail upfront with `error_code="rate_limit_exceeded"`, zero consumed quota slots, and batching guidance.

#### Scenario: SCN-MCP-014-1 — Implicit all-domain cache_control refresh succeeds once per idle window when domain count exceeds live_tool_rate_limit_per_minute

- **GIVEN** a management server with more cached domains (e.g., `40`) than `live_tool_rate_limit_per_minute` (e.g., `30`) and an empty caller `live` quota bucket
- **WHEN** the caller invokes `cache_control(action="refresh", scope="objects")` with `domain=None` and `domains=None`
- **THEN** single-call live quota consumption SHALL cap at `live_tool_rate_limit_per_minute` so the refresh executes once on the idle bucket
- **AND** any second live tool call within the same 60-second window SHALL be rejected with `error_code="rate_limit_exceeded"`

#### Scenario: SCN-MCP-014-2 — Explicit multi-domain or multi-scope fan-out exceeding per-minute live limit rejects upfront without leaking general or live slots

- **GIVEN** `live_tool_rate_limit_per_minute` set to `L > 0`
- **WHEN** a caller invokes `cache_control(action="refresh", domains=[...])` or `change_report(scopes=[...])` with explicit fan-out count `C > L` (or a multi-unit fan-out exceeding remaining live slots)
- **THEN** the server SHALL reject the call with `is_error=True`, `error_code="rate_limit_exceeded"`, and actionable guidance to pass batches of `<= L` items when `C > L` (with `retry_after_seconds=0.0` rather than a misleading retry timer)
- **AND** neither `general` nor `live` quota slots SHALL remain consumed by the rejected invocation

### Requirement: Stalest-Scope Cache Age Reporting Across Multi-Scope Queries

**ID**: REQ-MCP-015\
**Intent**: Prevent multi-scope MCP queries from understating data staleness when combined scopes were synchronized at different times.\
**Non-goals**: Single-scope `list_*` envelope pagination (`REQ-MCP-002`).

When `query_objects` or `search_objects` evaluates cached entities across multiple cache scopes (`objects`, `services`, `assets`), the returned `cache_age_seconds` envelope field SHALL report the maximum (`max`) age across all touched scopes that have a persisted `synced_at` timestamp (or `null` when none are synchronized).

#### Scenario: SCN-MCP-015-1 — Multi-scope query_objects and search_objects report maximum cache_age_seconds across touched scopes

- **GIVEN** `objects` synchronized `7200` seconds ago and `services` (or `assets`) synchronized `120` seconds ago on the same domain
- **WHEN** `query_objects(types=["host", "service-tcp"], cache_mode="cache")` or `search_objects(query="gw", types=["host", "gateway"], cache_mode="cache")` executes
- **THEN** the response envelope `cache_age_seconds` SHALL reflect the stalest touched scope (`>= 7200` seconds) rather than only the first or last scope evaluated
