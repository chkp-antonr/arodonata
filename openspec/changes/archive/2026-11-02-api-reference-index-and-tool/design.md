# Design: Bundled Multi-Version Check Point API Reference Engine & Unified MCP Tool

## Context

See `proposal.md` for motivation and scope. `~/Code/2026/CP_API` now compiles Check Point's official `v1.9`, `v2`, `v2.1`, and `v2.2` dynamic documentation datasets (`apis.json`, `content.json`, `examples.json`, `changes.json`) plus Gaia `v2.0.1` and Management `v2.1` Postman collections into a single normalized, deduplicated gzip bundle (`dist/cp_api_index.json.gz`, ~395 KB compressed, containing 1,161 commands, 724 shared nested objects, and 430 shared enums).

`arodonata` needs to embed this bundle so both Python SDK consumers (e.g., MMP) and MCP agents can perform fast, offline, version-aware two-step API introspection (`search` -> `describe`) and pre-flight payload validation (`validate`) without loading multi-megabyte schemas into LLM contexts or making network calls.

## Goals / Non-Goals

**Goals:**

- Embed `cp_api_index.json.gz` (~395 KB) inside `src/arodonata/api_reference/data/cp_api_index.json.gz` and load it lazily on first use.
- Provide a clean, synchronous (in-memory) `ApiReferenceEngine` in `arodonata.api_reference` usable both standalone (`from arodonata import search_api_commands, describe_api_command, validate_api_payload`) and via `ArodonataClient`.
- Automatically infer the target Check Point API `version` from `ArodonataClient` management server settings (`MgmtServerConfig.api_version`) when `mgmt_name` is provided or a single management server is configured.
- Expose a single consolidated MCP tool `api_reference(action="search" | "describe" | "validate", ...)` in `arodonata.mcp.tools`.

**Non-Goals:**

- Re-implementing the raw HTML/JSON compiler inside `arodonata` (`~/Code/2026/CP_API` remains the upstream compiler that produces `cp_api_index.json.gz`).
- Making live network requests to `sc1.checkpoint.com` from `arodonata` at runtime.

## Decisions

### 1. Package Layout & Lazy Singleton Loading (`src/arodonata/api_reference/`)

```text
src/arodonata/api_reference/
├── __init__.py
├── data/
│   └── cp_api_index.json.gz   # ~395 KB bundled multi-version schema index
├── models.py                  # Typed Pydantic v2 / TypedDict response models
└── engine.py                  # ApiReferenceEngine (search, describe, validate)
```

- **Why bundle `.json.gz` inside `src/arodonata/api_reference/data/`?**
  At 395 KB, `cp_api_index.json.gz` adds negligible wheel size while guaranteeing zero external file path dependencies when `arodonata` is installed in downstream virtualenvs or containers. Decompressing 395 KB in memory takes ~15 ms and occurs lazily on the first call to `get_api_reference()`.
- **Custom Path Override**: `ApiReferenceEngine.from_path(path)` allows loading a custom or newly generated `cp_api_index.json` / `.json.gz` without reinstalling the package.

### 2. Version Normalization & Management Server Inference

Check Point API versions appear in multiple formats across configurations (`"1.9"`, `"v1.9"`, `"1.9.1"`, `"2"`, `"2.0"`, `"v2.0.1"`, `"2.1"`, `"v2.2"`).

- `normalize_api_version(version)` maps:
  - `"1.9"`, `"v1.9"`, `"1.9.1"`, `"v1.9.1"` → `"v1.9"`
  - `"2"`, `"v2"`, `"2.0"`, `"v2.0"`, `"2.0.1"`, `"v2.0.1"` → `"v2"`
  - `"2.1"`, `"v2.1"` → `"v2.1"`
  - `"2.2"`, `"v2.2"` → `"v2.2"`
- When called via `ArodonataClient` or the MCP `api_reference` tool with `version=None`:
  - If `mgmt_name` is provided (or if `client.settings.mgmt_servers` has a single entry), inspect `mgmt_cfg.api_version`. If set, normalize and use it as the target `version`; otherwise default to `"v2.2"` (`meta["latest"]`).

### 3. Offline Payload Validation (`validate_payload`)

To help both LLMs and `cpcrud` / `api_call` callers catch schema mistakes before opening a Check Point session, `engine.validate_payload(command, payload, version=...)` performs fast structural checks against the resolved command schema:

1. **Command existence & version check**: If `command` does not exist in the index, return `valid=False` with top similar command suggestions via `search_commands`. If `command` exists but is not in `supported_versions` for `version`, report the exact versions where it is supported (`added_in` / `supported_versions`).
2. **Unknown or version-mismatched fields**: If a top-level key in `payload` is not in the command's `fields` for `version`, check whether the field exists in another version of the same command (e.g., `"Field 'gateway-owner' is only supported in ['v1.9'], not in target version 'v2.2'"` or `"Field 'xyz' was added in v2.2; target version is v2.0"`) or is completely unknown.
3. **Required fields & `field_alternatives`**:
   - Check unconditionally `required=True` fields that are not part of an alternative group.
   - For each group in `field_alternatives` (e.g., `["uid", "name"]` or `["ip-address", "ipv4-address", "ipv6-address"]`), if none of the alternatives is present and the command requires an identifier/address (or one of the group fields is marked required), report the alternative group clearly.
4. **Type & Enum Value Checks**:
   - Verify field values match at least one declared `ApiFieldType` (`string`, `integer`, `boolean`, `list`, `object`), and when `enum_ref` / `valid_values` is present on a string field (and no non-enum string type is allowed), verify the value is in `valid_values`.

### 4. Consolidated MCP Tool (`api_reference`)

Following the progressive-disclosure pattern established by `query_objects` and `cache_control`:

- Register a single MCP tool `api_reference` in `src/arodonata/mcp/tools.py` (always available, read-only, zero network/DB side effects):
  - `action: Literal["search", "describe", "validate"] = "search"`
  - `query: str | None = None` (for `action="search"`)
  - `command: str | list[str] | None = None` (for `action="describe"` or `"validate"`)
  - `payload: dict[str, Any] | None = None` (for `action="validate"`)
  - `category: str | None = None`
  - `crud_type: Literal["add", "set", "show", "delete", "action"] | None = None`
  - `api_family: Literal["management", "gaia"] | None = None`
  - `version: str | None = None`
  - `mgmt_name: str | None = None`
  - `resolve_nested: bool = True`
  - `include_examples: bool = True`
  - `limit: int = 15`

## Risks / Trade-offs

- **[Risk] Check Point fields with union types (e.g., a field accepting either a `string` name, a `list[str]`, or an `object` with `add`/`remove`)** → **Mitigation**: `validate_payload` checks whether the provided Python value matches *any* of the entries in `field["types"]`, avoiding false-positive rejections on polymorphic Check Point parameters.
- **[Risk] Wheel packaging omitting `.json.gz` data files** → **Mitigation**: Place `cp_api_index.json.gz` inside `src/arodonata/api_reference/data/` (with an `__init__.py` or Hatchling wheel inclusion) and verify loading via `importlib.resources` in unit tests.
