# Proposal: Bundled Multi-Version Check Point API Reference Engine & Unified MCP Tool

## Why

Downstream applications (such as MMP), AI agents, and `arodonata` users frequently need to discover the exact Check Point Management or Gaia API command for a task, inspect its request parameters and nested object schemas for a specific Check Point API version (`v1.9` through `v2.2`), or validate a JSON payload before sending a live `api_call`. Loading raw multi-megabyte API documentation into an LLM context window is prohibitively expensive, while querying external documentation servers requires network access and lacks version-aware filtering matched to the connected Management Server's `api_version`.

## What Changes

- **Bundle Compact Multi-Version API Schema Index (`cp_api_index.json.gz`)**:
  - Package the normalized, deduplicated multi-version schema bundle (~395 KB gzip, produced by `~/Code/2026/CP_API` from official Check Point `v1.9`, `v2`, `v2.1`, `v2.2` dynamic datasets and Gaia `v2.0.1` Postman collections) inside `src/arodonata/api_reference/data/cp_api_index.json.gz`.
- **Add Offline Two-Step API Reference Engine (`arodonata.api_reference`)**:
  - Provide a lazy, thread-safe in-memory query and validation service (`ApiReferenceEngine` / `get_api_reference()`) supporting:
    1. **Step 1 — `search_commands`**: Fast keyword, category, `crud_type` (`add`, `set`, `show`, `delete`, `action`), `api_family` (`management`, `gaia`), and `version` search returning lightweight command summaries (~300–500 bytes).
    2. **Step 2 — `describe_command`**: Detailed command schema lookup (accepting a single command name or a list of command names) dynamically filtering top-level fields, mutually exclusive `field_alternatives`, and recursive `nested_objects` / `enums` to the caller's target API version (`v1.9`, `v2`, `v2.1`, `v2.2`), plus official request/CLI examples.
    3. **Step 3 — `validate_payload`**: Offline pre-flight validation of a request payload dict against a command's version-specific schema (checking unknown fields, fields unsupported in the target API version, missing `required` fields, mutually exclusive `field_alternatives`, primitive/list/object types, and enum `valid_values`).
- **Expose Facade Helpers on `ArodonataClient` and Top-Level Package**:
  - Expose `client.api_reference` and convenience methods `client.search_api_commands(...)`, `client.describe_api_command(...)`, and `client.validate_api_payload(...)` on `ArodonataClient`, automatically resolving the default `version` from the configured management server's `api_version` when `mgmt_name` is provided (or defaulting to the single configured server).
- **Add Consolidated `api_reference` MCP Tool**:
  - Register a single progressive-disclosure MCP tool `api_reference(action="search" | "describe" | "validate", ...)` on `arodonata-mcp` so MCP clients and agents can perform two-step command discovery, inspect version-specific nested schemas, and pre-validate `api_call` payloads offline.

## Capabilities

### New Capabilities

- `api-reference`: Bundled multi-version Check Point API schema index (`cp_api_index.json.gz`), lazy in-memory `ApiReferenceEngine`, two-step command discovery (`search_commands`, `describe_command` with dynamic version filtering), and offline request payload validation (`validate_payload`).

### Modified Capabilities

- `client-and-facade`: Expose `api_reference` property and `search_api_commands`, `describe_api_command`, and `validate_api_payload` methods on `ArodonataClient` (with automatic `api_version` inference from configured `mgmt_name`) and top-level `arodonata` exports.
- `mcp-server`: Expose the unified `api_reference(action="search" | "describe" | "validate")` tool in `arodonata.mcp`.

## Impact

- **New Package**: `src/arodonata/api_reference/` (`__init__.py`, `engine.py`, `models.py`, `data/cp_api_index.json.gz`).
- **Updated Files**: `src/arodonata/client.py`, `src/arodonata/__init__.py`, `src/arodonata/mcp/tools.py`, `src/arodonata/mcp/prompts.py`, `pyproject.toml` (package data inclusion if needed).
- **Dependencies**: Zero new external dependencies (uses Python stdlib `gzip`, `json`, `importlib.resources` and existing `pydantic`).
