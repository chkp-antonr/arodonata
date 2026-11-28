# Spec Delta

## ADDED Requirements

### Requirement: Bounded MCP Report Scopes, Atomic Multi-Domain Staging, and Live Asset Filtering

**ID**: REQ-MCP-018\
**Intent**: Close MCP quota-amplification, caller-supplied session injection, multi-domain staged session leaks, and silent filter drops on live asset queries.\
**Non-goals**: Changing MCP bearer authentication middleware or HMAC plan token signing (`REQ-MCP-009`).

MCP `change_report` MUST cap total `session_uids`, charge live quota proportionally, and strip caller-supplied `owned_sessions` entries. Multi-domain `cpcrud_apply` staging MUST verify or roll back capacity atomically without self-evicting sibling domains or leaking unstored sessions, and `list_assets(..., cache_mode="live")` MUST honor `types`, `roles`, `platforms`, `parent`, and `filter`.

#### Scenario: SCN-MCP-018-1 — Bounded session_uids quota and sanitized change_report scopes

- **GIVEN** an MCP `change_report` request specifying many `session_uids` or caller-supplied `owned_sessions` entries in `scopes`
- **WHEN** MCP validates arguments, charges live quota, and builds `SessionScope` inputs
- **THEN** `change_report` SHALL reject requests exceeding the `session_uids` cap and charge live quota proportionally to requested session/scope fan-out
- **AND** untrusted caller-supplied `owned_sessions` (`sid`/`server_ip`) SHALL be stripped before `collect_change_report()` runs

#### Scenario: SCN-MCP-018-2 — Atomic multi-domain cpcrud_apply staging and live list_assets filtering

- **GIVEN** a multi-domain `cpcrud_apply(no_publish=True, keep_session=True)` hitting `staged_session_store` capacity limits, or a `list_assets(..., cache_mode="live")` call with `types`, `roles`, `platforms`, `parent`, or `filter`
- **WHEN** MCP registers staged sessions or executes `list_assets` in `live` mode
- **THEN** `cpcrud_apply` SHALL pre-check or atomically roll back all staged sessions in the batch using shielded eviction without self-evicting sibling domains
- **AND** `list_assets(..., cache_mode="live")` SHALL filter live hydrated assets locally by all supplied filter arguments
