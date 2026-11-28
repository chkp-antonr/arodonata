# Proposal

## Why

Downstream Check Point automation scripts, MCP callers, and AI-generated workflows repeatedly re-implement ad-hoc `Asset.type` and `raw_data` checks to distinguish policy-enforcing targets from physical execution targets, separate management/MDS/log servers from gateways, detect Gaia vs. Gaia Embedded vs. Maestro vs. CloudGuard platforms, and recover missing hardware metadata on cluster members. Arodonata should expose a single authoritative, vendor-neutral classification directly on `Asset`, persisted in `arodonata_assets` and searchable through `get_gateways()` and `query_objects()`.

## What Changes

- Extend `Asset` (`src/arodonata/core/models/assets.py`) with `management_blades: dict[str, Any]`, `asset_role: AssetRole`, `platform_family: AssetPlatform`, `is_policy_target: bool`, and `is_execution_target: bool`, along with pure vendor-neutral classification helpers (`classify_asset_role`, `classify_asset_platform`, `classify_asset`, `POLICY_TARGET_ROLES`, `EXECUTION_TARGET_ROLES`) exported via `arodonata.core.models` and `arodonata`.
- Extend `ClusterRelationshipManager.enrich()` (`src/arodonata/core/services/_asset_linking.py`) to inherit missing `hardware`, `os_name`, and `version` from parent clusters onto linked cluster members without overwriting explicit member fields, and re-classify member `asset_role` (promoting VSX cluster members to `"vsx_cluster_member"`) and `platform_family`.
- Add nullable, indexed classification columns (`management_blades`, `asset_role`, `platform_family`, `is_policy_target`, `is_execution_target`) to `AssetRecord` (`arodonata_assets` in `src/arodonata/adapters/storage/tables.py`) and update `_record_to_asset()` / `_asset_to_row()` (`src/arodonata/adapters/storage/cache/mappers.py`) so `DatabaseManager` evolves existing caches in place (`ALTER TABLE ADD COLUMN`) and legacy `NULL` rows auto-classify transparently on read.
- Add optional `roles` and `platforms` filter parameters to `AssetRefreshService.get_assets()` and `ArodonataClient.get_gateways()` (preserving the `AssetCachePort.get_assets()` protocol signature for custom doubles), and expose `asset_role`, `platform_family`, `is_policy_target`, `is_execution_target` (plus `"role"` / `"platform"` aliases and `asset_roles` / `asset_platforms` summary counts) in `SearchService.query_objects()` and `describe_objects()`.
- Align `is_policy_enforcing_gateway()` (`src/arodonata/core/services/topology/_shared.py`) with `Asset.is_policy_target`, update `docs/troubleshooting/checkpoint-ops-quirks.md` and `docs/architecture/database-schema.md`, and regenerate `docs-notebooklm/` (`05-sdk-quickref.md`).
- Remediate branch deep-audit findings (`docs/_audit_/2611261737-deep-audit.json` in `arodonata_v2`):
  - Forward parsed `group_by` attributes from MCP `query_objects` (`src/arodonata/mcp/tools/objects.py`) into `resolve_query_scopes()` so role/platform grouping enforces live quota, cold-cache auto-upgrade, and `cache_age_seconds` against `scope="assets"` (`DA-003`, `DA-004`).
  - Add `"mds"` and `"CpmiMds"` to `CANONICAL_ASSET_TYPES`, `_ASSET_EQUIVALENT_GROUPS`, and `ASSET_TYPE_ALIASES` (`src/arodonata/core/models/common.py`) (`DA-023`).
  - Exclude `CLUSTER_MEMBER_TYPES`, `VSX_PARENT_TYPES`, and self-links in `VSXRelationshipManager._link_vsx_children_to_parents()` and `reconcile_cross_domain()` (`src/arodonata/core/services/_asset_linking.py`) (`DA-027`).
  - Fix `docs/scripts/build_notebooklm_docs.py` (`DA-040`) to unparse `ast.Lambda.body` in `_compact_field_default()` and remove `[:8]` method slicing for `FileReplayApiMock` and `CheckPointReplayHttpServer`, then regenerate `docs-notebooklm/05-sdk-quickref.md`.
  - Sync repository documentation (`README.md` for `05-sdk-quickref.md` and 13 capabilities `DA-046`; `AGENTS.md` docs tree `DA-049`) and regenerate `docs-notebooklm/04-capabilities-db-mcp-and-openspec.md` after spec sync (`DA-048`).

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `cache-and-sync`: Add `REQ-CACHE-019` defining vendor-neutral `Asset` role/platform classification, cluster member metadata inheritance, in-place nullable `arodonata_assets` persistence, role/platform filtering and grouping across `get_assets()`, `get_gateways()`, `query_objects()`, and `describe_objects()`, canonical `"mds"`/`"CpmiMds"` asset routing, VSX member/self-link exclusion, and MCP `query_objects` asset-scope parity.
- `ai-builder`: Extend `REQ-AIBUILD-003` (`SCN-AIBUILD-003-2`) to require syntactically valid default-factory rendering and complete public method coverage for `FileReplayApiMock` and `CheckPointReplayHttpServer`.

## Impact

- **Core Models & Services**: `src/arodonata/core/models/assets.py`, `src/arodonata/core/models/common.py`, `src/arodonata/core/models/__init__.py`, `src/arodonata/__init__.py`, `src/arodonata/core/services/_asset_linking.py`, `src/arodonata/core/services/asset_service.py`, `src/arodonata/core/services/search/query.py`, `src/arodonata/core/services/topology/_shared.py`, `src/arodonata/client/inventory.py`, `src/arodonata/mcp/tools/objects.py`.
- **Storage Persistence**: `src/arodonata/adapters/storage/tables.py` (`AssetRecord`) and `src/arodonata/adapters/storage/cache/mappers.py`.
- **Documentation & Tests**: `docs/scripts/build_notebooklm_docs.py`, `docs/troubleshooting/checkpoint-ops-quirks.md`, `docs/architecture/database-schema.md`, `docs-notebooklm/*`, `README.md`, `AGENTS.md`, `tests/unit/test_asset_classification.py`, and `tests/unit/test_aibuilder_docs_and_packaging.py`.
