# Spec Delta: Integration Testing and Examples

## MODIFIED Requirements

### Requirement: Progressive Runnable SDK Examples Catalog

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding, ensuring that embedded MCP examples enforce host or bearer authentication when write tools (`cpcrud=True` or `live_compat=True`) are enabled.

#### Scenario: Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** the catalog SHALL include runnable scripts for basic domain/object/service queries (`01`), search and structured queries (`02`), gateway/cluster/VSX relationships (`03`), streaming cache refresh (`04`), rulebase queries and numbering (`05`), session lifecycle (`06`), `auth_context`/`user_context` and `SessionOverlay` read-your-own-writes (`07`), CPCRUD idempotent apply (`08`) and compensating inverse (`09`), change report evidence (`10`), OpenTelemetry tracing with module gating (`11`), and FastAPI MCP embedding (`12`, configured with explicit bearer/host authentication middleware protecting write-capable MCP routes), with all mutating examples wrapped in `guarded_session` so target lab domains are automatically restored on exit
