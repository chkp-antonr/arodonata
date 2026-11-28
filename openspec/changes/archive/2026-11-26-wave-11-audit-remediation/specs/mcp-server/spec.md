# Spec Delta

## ADDED Requirements

### Requirement: Accurate Tool Naming Hints, Multi-Domain Cold Upgrade, Asset Classification MCP Filters, and Peer-Safe Staged Registry

**ID**: REQ-MCP-017\
**Intent**: Keep MCP error hints accurate to consolidated tool names, evaluate multi-domain `domains` cold-cache upgrades reliably, expose asset role/platform filtering on MCP tools alongside shared list helpers, and prevent third-caller staged session exhaustion of peer callers.\
**Non-goals**: Initial MCP quota enforcement (`REQ-MCP-016`) or HMAC plan verification (`REQ-MCP-009`).

MCP error hints SHALL reference `list_domains` rather than `show_domains`, `_upgrade_uninitialized_cache_mode()` SHALL evaluate multi-domain `domains` scopes, `list_assets`/`query_objects` SHALL expose role/platform classification filters alongside shared typed-list execution, and `staged_session_store` SHALL protect single-session peers.

#### Scenario: SCN-MCP-017-1 — Accurate list_domains guidance, multi-domain cold-cache upgrade, asset role/platform MCP filters, and owner-fair staged session capacity

- **GIVEN** empty cached domain errors, a multi-domain `domains` list containing an uncached domain under `cache_mode="cache"`, `list_objects`/`list_services`/`list_assets`/`query_objects` classification queries, or a saturated `staged_session_store`
- **WHEN** `format_invalid_credentials_failure()`, `_upgrade_uninitialized_cache_mode()`, object/asset tools, or `_store_staged_session()` executes
- **THEN** credential errors SHALL instruct callers to run `list_domains`, `_upgrade_uninitialized_cache_mode()` SHALL upgrade when any requested domain is cold, `list_assets` and `query_objects` SHALL filter by `roles`/`platforms` (and target flags on `query_objects`), and `_store_staged_session()` SHALL evict greedy multi-slot owners first or discard and fail cleanly rather than evicting single-session peers
