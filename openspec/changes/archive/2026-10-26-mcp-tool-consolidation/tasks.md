# Tasks: Consolidate MCP Tool Surface Around Cache Tables (`mcp-tool-consolidation`)

## 1. Multi-Table `find_object` & `get_group_members` in Core / Client

- [x] 1.1 Update `ArodonataClient.find_object` in `src/arodonata/client.py` to resolve targets across `arodonata_objects` (`CPObject`), `arodonata_services` (`CPService`), and `arodonata_assets` (`Asset`), normalizing short `obj_type` aliases and verifying via unit tests in `tests/unit/test_client.py`
- [x] 1.2 Extend `SearchService.get_group_members` (`src/arodonata/core/services/search_service.py`) and `ArodonataClient.get_group_members` (`src/arodonata/client.py`) to expand `service-group` members from `arodonata_services` and cluster/VSX child assets (`member_uids` / `virtual_system_uids`) from `arodonata_assets` in addition to network groups (`arodonata_objects`), and verify via unit tests in `tests/unit/test_search_service.py`
- [x] 1.3 Extend `SearchService.describe_objects` and `SearchService.query_objects` (`src/arodonata/core/services/search_service.py`) to support `aggregate="describe"` and include `arodonata_assets` type counts/queries when asset types are requested, verifying with unit tests in `tests/unit/test_search_service.py`

## 2. Consolidated MCP Tool Surface (`list_*`, `show_*`, `cache_control`, `cpcrud_staged_session`)

- [x] 2.1 Implement canonical type alias normalization (`normalize_object_type`, `normalize_service_type`, `normalize_asset_type`) and replace the 8 legacy listing tools in `src/arodonata/mcp/tools.py` with `list_domains`, `list_objects(types=...)`, `list_services(types=...)`, and `list_assets(types=..., parent=...)`, verifying envelopes (`from`, `to`, `total`, `source`, `cache_age_seconds`) in `tests/unit/test_mcp_tools.py`
- [x] 2.2 Implement three-tier matching in `show_object` (`src/arodonata/mcp/tools.py`) across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (Tier 1 exact match with full details; Tier 2 strict anchored wildcard `fnmatchcase` without implicit prefix/suffix; Tier 3 substring candidate fallback bounded by `limit=20`, `offset=0` in compact format), removing `find_object` and verifying all 3 tiers in `tests/unit/test_mcp_tools.py`
- [x] 2.3 Replace `show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, and `show_policy_packages` with unified `show_rulebase(rulebase_type="access" | "nat" | "https" | "threat", ...)` in `src/arodonata/mcp/tools.py`, returning the domain's cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers and `implicit_cleanup_action`) when `package`/`layer` is omitted or unmatched, and verifying both catalog discovery and cached/live rulebase execution in `tests/unit/test_mcp_tools.py`
- [x] 2.4 Consolidate `describe_objects` into `query_objects(..., aggregate="list" | "count" | "describe")`, merge `cache_status` and `refresh_cache` into `cache_control(action="status" | "refresh", ...)`, merge `cpcrud_publish_staged` and `cpcrud_discard_staged` into `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)`, remove redundant `live_compat` wrapper tools in favor of `api_call`, update `src/arodonata/mcp/prompts.py`, and verify tool registration count (`13` base tools, `18` with `cpcrud=True`) in `tests/unit/test_mcp_tools.py`

## 3. Integration Tests & Quality Gates

- [x] 3.1 Update live MCP integration tests in `tests/integration/b7/test_mcp_tools.py` to exercise the consolidated tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `query_objects`, `cache_control`, `change_report`, `api_call`) and verify all quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `./pytest.sh`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `openspec validate --specs --no-interactive`) pass

## Workflow follow-up

- Synchronize delta specifications into `openspec/specs/` and archive the `mcp-tool-consolidation` change once implementation and verification are complete.
