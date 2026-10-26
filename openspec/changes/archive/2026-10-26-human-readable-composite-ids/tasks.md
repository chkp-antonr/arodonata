# Tasks

## 1. Domain Models and SQL Storage Tables

- [x] 1.1 Add auto-populated `object_id: str` (`"{mgmt_name}:{domain_name}:{name}"`) to `CPObject`, `id` / `object_id` / `parent_object_ids` to `GroupMembershipNode`, `service_id: str` (`"{mgmt_name}:{domain_name}:{name}"`) to `CPService`, and `asset_id: str`, `parent_id: str | None`, `parent_asset_id: str | None`, `member_asset_ids: list[str]`, and `virtual_system_asset_ids: list[str]` to `Asset` in `src/arodonata/core/models/{objects,services,assets}.py`, and verify with unit tests in `tests/unit/test_models.py`.
- [x] 1.2 Add non-unique indexed `object_id` to `CPObjectRecord`, `service_id` to `CPServiceRecord`, and `asset_id`, `parent_id`, `parent_asset_id`, `member_asset_ids`, and `virtual_system_asset_ids` to `AssetRecord` in `src/arodonata/adapters/storage/tables.py`, update record-mapping and upsert logic in `src/arodonata/adapters/storage/cache_adapter.py` (adding `upsert_assets` to `CachePort` and `SqlCacheAdapter` if needed for cross-domain VSX updates), and verify in `tests/unit/test_storage.py` that duplicate-named objects/services (`email` with two distinct UIDs) persist without collision while exposing identical `object_id` / `service_id` values.
- [x] 1.3 Update `docs/architecture/database-schema.md` (ER diagram and table catalog for `arodonata_objects`, `arodonata_services`, and `arodonata_assets`) to document the new columns and verify with `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`.

## 2. Cluster and Cross-Domain VSX Topology Enrichment

- [x] 2.1 Update `ClusterRelationshipManager` and `VSXRelationshipManager` in `src/arodonata/core/services/asset_service.py` to populate `parent_id`, `parent_asset_id`, `member_asset_ids`, and `virtual_system_asset_ids` alongside `parent_uid`, `parent_name`, `member_uids`, and `virtual_system_uids`.
- [x] 2.2 Implement cross-domain VSX-to-Virtual-System relationship reconciliation across cached domains of the same `mgmt_name` in `AssetRefreshService` / `VSXRelationshipManager` so Virtual Systems in tenant domains resolve `parent_id = "{mgmt_name}:{vsx_domain}:{vsx_uid}"` and `parent_asset_id = "{mgmt_name}:{vsx_domain}:{vsx_name}"` and parent VSX containers record `virtual_system_uids` and `virtual_system_asset_ids`, and verify with unit tests in `tests/unit/test_asset_service.py`.

## 3. Search, Query, and Facade Composite Identifier Resolution

- [x] 3.1 Update `SearchService` (`src/arodonata/core/services/search_service.py`) and `ArodonataClient.find_object()` (`src/arodonata/client.py`) to populate `id`, `object_id`, and `parent_object_ids` on `GroupMembershipNode`, match composite identifiers (`object_id`, `service_id`, `asset_id`, `id`) in `search_objects()`, `find_object()`, `get_group_members()`, and `query_objects()`, and list the new fields in `describe_objects()`, verifying with unit tests in `tests/unit/test_search_service.py` and `tests/unit/test_client_facade.py`.
- [x] 3.2 Run full quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, `openspec validate --strict --no-interactive`, and `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`) and verify all checks pass with zero errors.
