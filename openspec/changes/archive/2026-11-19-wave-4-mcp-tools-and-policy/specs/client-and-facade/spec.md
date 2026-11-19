# Spec Delta

## MODIFIED Requirements

### Requirement: Hexagonal Layer Boundaries, Segregated Cache Ports, and Shared Core Primitives

**ID**: REQ-CLIENT-018\
**Intent**: Enforce strict hexagonal import isolation, Interface Segregation on `CachePort`, and DRY core primitives and Check Point sentinel definitions.\
**Non-goals**: Behavioral changes to Management API pagination or cache schema migrations.

Hexagonal layers (`core`, `adapters`, `cpcrud`, `rulebase`, `reports`, `mcp`) SHALL obey AST-verified import boundaries, `CachePort` SHALL compose eight `@runtime_checkable` ISP sub-protocols matched to service consumers alongside `RulebaseRefreshPort`, and `arodonata.core.primitives` / `arodonata.core.models.sentinels` SHALL provide shared primitives and Check Point sentinel UIDs with backward-compatible re-exports.

#### Scenario: SCN-CLIENT-018-1 — Hexagonal layer import boundaries are enforced via AST across core, adapters, cpcrud, rulebase, reports, and mcp

- **WHEN** an AST boundary scan inspects every import statement (including relative, lazy, and `TYPE_CHECKING` imports) in `core`, `adapters`, `cpcrud`, `rulebase`, `reports`, and `mcp`
- **THEN** `core` SHALL have zero imports from `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.rulebase`, `arodonata.testing`, `cpapi`, `aiohttp`, `sqlalchemy`, `sqlmodel`, `asyncpg`, or `aiosqlite`
- **AND** `adapters` SHALL not import `arodonata.client`, `arodonata.mcp`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.rulebase`, or `arodonata.testing`
- **AND** `cpcrud` SHALL not import `arodonata.adapters` or `arodonata.client`, `rulebase` SHALL not import `arodonata.cpcrud`, `arodonata.adapters`, or `arodonata.client`, `reports` SHALL not import `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, or `arodonata.testing`, and `mcp` SHALL not import `arodonata.adapters` or `arodonata.testing`
