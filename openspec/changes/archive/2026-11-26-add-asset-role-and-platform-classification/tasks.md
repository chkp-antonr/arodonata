# Tasks

## 1. Domain Model & Vendor-Neutral Classification

- [x] 1.1 Add `AssetRole`, `AssetPlatform`, `POLICY_TARGET_ROLES`, `EXECUTION_TARGET_ROLES`, `classify_asset_role()`, `classify_asset_platform()`, `classify_asset()`, and `Asset` fields (`management_blades`, `asset_role`, `platform_family`, `is_policy_target`, `is_execution_target`) in `src/arodonata/core/models/assets.py`, re-exporting them via `src/arodonata/core/models/__init__.py` and `src/arodonata/__init__.py`; add unit tests `@pytest.mark.spec("SCN-CACHE-019-1")` and `@pytest.mark.spec("SCN-CACHE-019-2")` in `tests/unit/test_asset_classification.py` verifying role/platform classification and `uv run pytest tests/unit/test_asset_classification.py` passes
- [x] 1.2 Align `is_policy_enforcing_gateway()` in `src/arodonata/core/services/topology/_shared.py` with `classify_asset_role()` / `Asset.is_policy_target` preserving exact `REQ-TOPO-002` parity, and verify existing topology tests (`uv run pytest tests/unit/test_topology_service.py tests/unit/test_asset_classification.py`) pass

## 2. Cluster Member Inheritance & Cache Persistence

- [x] 2.1 Update `ClusterRelationshipManager.enrich()` in `src/arodonata/core/services/_asset_linking.py` to inherit missing `hardware`, `os_name`, and `version` from parent clusters onto linked members (without overwriting non-empty member values) and re-classify member `asset_role` (including `"vsx_cluster_member"`), `platform_family`, `is_policy_target`, and `is_execution_target`; add `@pytest.mark.spec("SCN-CACHE-019-3")` test in `tests/unit/test_asset_classification.py` and verify `uv run pytest tests/unit/test_asset_classification.py tests/unit/test_asset_service.py` passes
- [x] 2.2 Add nullable indexed columns (`management_blades`, `asset_role`, `platform_family`, `is_policy_target`, `is_execution_target`) to `AssetRecord` (`src/arodonata/adapters/storage/tables.py`) and update `_record_to_asset()` / `_asset_to_row()` (`src/arodonata/adapters/storage/cache/mappers.py`) so `DatabaseManager` evolves existing caches in place and legacy `NULL` rows auto-classify on read; update `docs/architecture/database-schema.md` and verify SQLite migration tests pass

## 3. Filtering, Structured Querying & Documentation Sync

- [x] 3.1 Add optional `roles` and `platforms` filter parameters to `AssetRefreshService.get_assets()` (`src/arodonata/core/services/asset_service.py`) and `ArodonataClient.get_gateways()` (`src/arodonata/client/inventory.py`), and add `asset_role`, `platform_family`, `is_policy_target`, `is_execution_target` (plus `"role"`/`"platform"` aliases, `roles`/`platforms` filtering, and `asset_roles`/`asset_platforms` summary counts) in `src/arodonata/core/models/common.py` and `src/arodonata/core/services/search/query.py`; add `@pytest.mark.spec("SCN-CACHE-019-4")` tests in `tests/unit/test_asset_classification.py` and verify `uv run pytest tests/unit/test_asset_classification.py tests/unit/test_search_service.py` passes
- [x] 3.2 Update `docs/troubleshooting/checkpoint-ops-quirks.md` to reflect native `Asset` role/platform classification and cluster-member hardware inheritance, and regenerate `docs-notebooklm/` (`05-sdk-quickref.md`) via `uv run python docs/scripts/build_notebooklm_docs.py` (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py`)

## 4. Branch Audit Remediation

- [x] 4.1 (`DA-003`, `DA-004`) Parse `group_by` via `_parse_and_validate_group_by` in `src/arodonata/mcp/tools/objects.py` (`query_objects`) and pass `group_by_attrs` to `resolve_query_scopes()` so asset grouping routes live quota, cold-cache auto-upgrade, and `cache_age_seconds` to `scope="assets"`; add `@pytest.mark.spec("SCN-CACHE-019-5")` tests in `tests/unit/test_asset_classification.py` and verify `uv run pytest tests/unit/test_asset_classification.py tests/unit/test_mcp_tools.py` passes
- [x] 4.2 (`DA-023`) Add `"mds"` and `"CpmiMds"` to `CANONICAL_ASSET_TYPES`, `_ASSET_EQUIVALENT_GROUPS`, and `ASSET_TYPE_ALIASES` in `src/arodonata/core/models/common.py`; add `@pytest.mark.spec("SCN-CACHE-019-5")` coverage for `query_objects`, `find_object`, `search_objects`, `get_gateways`, and MCP `show_object` and verify `uv run pytest tests/unit/test_asset_classification.py tests/unit/test_search_service.py` passes
- [x] 4.3 (`DA-027`) Exclude `CLUSTER_MEMBER_TYPES`, `VSX_PARENT_TYPES`, and self-links in `VSXRelationshipManager._link_vsx_children_to_parents()` and `reconcile_cross_domain()` in `src/arodonata/core/services/_asset_linking.py`; add `@pytest.mark.spec("SCN-CACHE-019-5")` tests and verify `uv run pytest tests/unit/test_asset_classification.py tests/unit/test_asset_service.py` passes
- [x] 4.4 (`DA-040`) Fix `_compact_field_default()` (`ast.Lambda` unparsing) and remove `[:8]` method slices for `FileReplayApiMock` and `CheckPointReplayHttpServer` in `docs/scripts/build_notebooklm_docs.py`; regenerate `docs-notebooklm/05-sdk-quickref.md` and add `@pytest.mark.spec("SCN-AIBUILD-003-2")` tests in `tests/unit/test_aibuilder_docs_and_packaging.py` verifying valid default syntax and full method coverage (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py`)
- [x] 4.5 (`DA-046`, `DA-049`) Update `README.md` (document `docs-notebooklm/05-sdk-quickref.md`, 13 OpenSpec capabilities, and `01..05.md` rebuild comment) and `AGENTS.md` (add `docs/architecture/`, `docs/scripts/`, `docs-notebooklm/` to the documentation tree); verify `npx markdownlint-cli README.md AGENTS.md` passes

## 5. End-to-End Quality & Traceability Verification

- [x] 5.1 Run full repository quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `uv run mypy src`, `uv run pytest`, `openspec schema validate arodonata`, `openspec validate --changes --strict --no-interactive`, and `uv run python scripts/check_spec_traceability.py`) and verify zero errors

## Workflow follow-up

- (`DA-048`) Sync `cache-and-sync` and `ai-builder` delta specs into `openspec/specs/`, archive `add-asset-role-and-platform-classification`, re-run `uv run python docs/scripts/build_notebooklm_docs.py` so `docs-notebooklm/04-capabilities-db-mcp-and-openspec.md` includes `REQ-CACHE-019`, and create a checkpoint commit on `feat/arodonata-aibuilder`.
- Proceed to the next OpenSpec change on the roadmap: `plugins/arodonata-aibuilder` multi-agent skill bundle and end-to-end English playbooks.
