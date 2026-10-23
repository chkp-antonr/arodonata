# Tasks: Revise Arodonata v2 Architecture & Specifications

## 1. Specification & Architecture Revision

- [x] 1.1 Audit all 9 v1 capability specs and document clean-slate v2 hexagonal architecture in `proposal.md` and `design.md`
- [x] 1.2 Author delta specifications for `configuration`, `transport-and-tls`, `sessions-and-mdm`, `cache-and-sync`, `rulebase-and-numbering`, `client-and-facade`, `cpcrud`, and `mcp-server` and verify `openspec validate --strict` passes
- [x] 1.3 Synchronize delta specifications into `openspec/specs/` and verify `openspec validate --specs --strict` passes
- [x] 1.4 Split `pyproject.toml` dependencies into base (`aiohttp`, `aiosqlite`, `sqlalchemy`, `sqlmodel`, `pydantic`, `jsonschema`, `pyyaml`, `arlogi`, `opentelemetry-api`) and optional extras (`postgres`, `mcp`, `all`) and verify quality gates pass
