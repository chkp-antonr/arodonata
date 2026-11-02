# Tasks: Bundled Multi-Version Check Point API Reference Engine & Unified MCP Tool

## 1. Bundled Index & Offline API Reference Engine (`src/arodonata/api_reference/`)

- [x] 1.1 Copy `~/Code/2026/CP_API/dist/cp_api_index.json.gz` into `src/arodonata/api_reference/data/cp_api_index.json.gz` (with `__init__.py` so Hatchling includes it in wheels) and implement `src/arodonata/api_reference/models.py` and `src/arodonata/api_reference/engine.py` (`ApiReferenceEngine`, `get_api_reference`, `normalize_api_version`, `search_api_commands`, `describe_api_command`, `validate_api_payload`).
- [x] 1.2 Add unit tests in `tests/unit/test_api_reference.py` verifying lazy loading, two-step search/describe across versions (`v1.9` vs `v2.2`), batch command describe (`list[str]`), and offline payload validation (`validate_payload` for missing required fields, `field_alternatives`, enum `valid_values`, and version-specific fields), and verify `uv run pytest tests/unit/test_api_reference.py` passes.

## 2. `ArodonataClient` Facade & Package Exports

- [x] 2.1 Expose `api_reference`, `search_api_commands`, `describe_api_command`, and `validate_api_payload` on `ArodonataClient` (`src/arodonata/client.py`) with automatic target `version` resolution from `mgmt_name` settings (`api_version`), and export top-level symbols in `src/arodonata/__init__.py`.
- [x] 2.2 Add unit tests in `tests/unit/test_api_reference.py` verifying `ArodonataClient` automatic `api_version` inference per `mgmt_name` and fallback to `"v2.2"`, and verify `uv run pytest tests/unit/test_api_reference.py` passes.

## 3. Unified `api_reference` MCP Tool (`src/arodonata/mcp/`)

- [x] 3.1 Register the unified `api_reference(action="search" | "describe" | "validate", ...)` tool in `src/arodonata/mcp/tools.py` and update MCP prompt guidance in `src/arodonata/mcp/prompts.py`.
- [x] 3.2 Add MCP unit tests in `tests/unit/test_mcp_server.py` (or `tests/unit/test_api_reference.py`) covering `api_reference` tool calls (`action="search"`, `action="describe"` single and batch, `action="validate"`, and `mgmt_name` version inference), and verify `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` pass.

## Workflow follow-up

- Run `/openspec-archive-change` and `/archive-task` once implementation and verification are complete.
