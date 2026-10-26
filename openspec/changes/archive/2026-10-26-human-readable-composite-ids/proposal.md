# Proposal

## Why

In Arodonata v2, `arodonata_objects` (`CPObject`), `arodonata_services` (`CPService`), and `arodonata_assets` (`Asset`) standardized on `id = "{mgmt_name}:{domain_name}:{uid}"` as their database primary key so that incremental synchronization (`show-changes`), object renames, and duplicate-named Check Point objects with distinct UIDs (such as built-in application/service entries sharing the name `email`) never collide or overwrite one another. However, dashboards, operator views, logs, and downstream host applications (MMP, FPCR) rely on human-readable composite identifiers formatted as `"{mgmt_name}:{domain_name}:{name}"` (for example, `mds:General:hWebHost`) and human-readable parent/child asset references (`parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`) so engineers immediately understand the management server, domain, and entity name without UID lookups.

## What Changes

- **Human-Readable Composite Identifiers Alongside UID Primary Keys**:
  - Retain `id = "{mgmt_name}:{domain_name}:{uid}"` as the primary key across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` so duplicate-named Check Point objects with distinct UIDs coexist without collision or data loss.
  - Add non-unique indexed `object_id: str` (`"{mgmt_name}:{domain_name}:{name}"`) to `CPObject` (`src/arodonata/core/models/objects.py`) and `CPObjectRecord` (`arodonata_objects` in `src/arodonata/adapters/storage/tables.py`), and add `object_id: str` and `parent_object_ids: list[str]` to `GroupMembershipNode`.
  - Add non-unique indexed `service_id: str` (`"{mgmt_name}:{domain_name}:{name}"`) to `CPService` (`src/arodonata/core/models/services.py`) and `CPServiceRecord` (`arodonata_services` in `src/arodonata/adapters/storage/tables.py`).
  - Add non-unique indexed `asset_id: str` (`"{mgmt_name}:{domain_name}:{name}"`) to `Asset` (`src/arodonata/core/models/assets.py`) and `AssetRecord` (`arodonata_assets` in `src/arodonata/adapters/storage/tables.py`).
- **Dual UID and Human-Readable Parent/Child Asset Topology**:
  - Add indexed `parent_id: str | None` (`"{mgmt_name}:{parent_domain}:{parent_uid}"`) and indexed `parent_asset_id: str | None` (`"{mgmt_name}:{parent_domain}:{parent_name}"`) to `Asset` and `AssetRecord`.
  - Add `member_asset_ids: list[str]` and `virtual_system_asset_ids: list[str]` (JSON list columns on `AssetRecord`) alongside `member_uids` and `virtual_system_uids`.
  - Update `ClusterRelationshipManager` and `VSXRelationshipManager` (including cross-domain VSX parent/child linking across cached domains of the same `mgmt_name`) to populate both UID-based (`parent_uid`, `parent_id`, `member_uids`, `virtual_system_uids`) and human-readable (`parent_name`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`) relationship fields.
- **Search, Structured Query, and Lookup Support**:
  - Update `SearchService` (`search_objects`, `query_objects`, `describe_objects`, `get_group_members`) and `ArodonataClient.find_object()` to accept and return `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id`.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `cache-and-sync`: Persist indexed human-readable composite identifiers (`object_id`, `service_id`, `asset_id`) and dual UID/human-readable parent-child asset relationship fields (`parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`) in `arodonata_objects`, `arodonata_services`, and `arodonata_assets` while preserving `id = "{mgmt_name}:{domain_name}:{uid}"` as primary key, and include `object_id` / `parent_object_ids` in `SearchResult` group membership nodes.
- `client-and-facade`: Resolve `find_object` and `get_group_members` by composite human-readable identifiers (`object_id`, `service_id`, `asset_id`) in addition to raw `name` or `uid`.

## Impact

- **Domain Models (`src/arodonata/core/models/`)**: `CPObject`, `GroupMembershipNode`, `CPService`, and `Asset` auto-compute `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` in `model_post_init` and `from_cp_dict`.
- **SQL Persistence (`src/arodonata/adapters/storage/`)**: `CPObjectRecord`, `CPServiceRecord`, and `AssetRecord` gain new columns and indexes; `DatabaseManager.initialize()` automatically migrates existing `arodonata_*` tables via `compute_schema_hash()`.
- **Services & Client (`src/arodonata/core/services/`, `src/arodonata/client.py`)**: `ClusterRelationshipManager`, `VSXRelationshipManager`, `SearchService`, and `ArodonataClient.find_object()` populate and query the human-readable composite fields.
- **Documentation (`docs/architecture/database-schema.md`)**: ER diagram and table catalog reflect the new columns.
