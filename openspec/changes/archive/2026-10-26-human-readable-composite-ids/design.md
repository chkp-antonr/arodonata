# Design

## Context

See `proposal.md` for motivation. In Arodonata v2, all cached entity tables (`arodonata_objects`, `arodonata_services`, `arodonata_assets`) use `id = "{mgmt_name}:{domain_name}:{uid}"` as their primary key. While UID-keyed primary keys are essential for Check Point `show-changes` incremental upserts, object renames, and duplicate-named built-in objects with distinct UIDs (which also motivate the `±10` boundary window in `pager.py`), downstream dashboards, UI tables, and host applications (MMP, FPCR) need direct access to human-readable composite identifiers (`"{mgmt_name}:{domain_name}:{name}"`) and human-readable parent/child asset links without performing joins or client-side string concatenation.

## Goals / Non-Goals

**Goals:**

- Expose `object_id`, `service_id`, and `asset_id` (`"{mgmt_name}:{domain_name}:{name}"`) as indexed SQL columns and auto-populated Pydantic fields on `CPObject`, `CPService`, and `Asset`.
- Expose both UID-based (`parent_id`, `parent_uid`, `member_uids`, `virtual_system_uids`) and human-readable (`parent_asset_id`, `parent_name`, `member_asset_ids`, `virtual_system_asset_ids`) topology links on `Asset`, including cross-domain VSX-to-Virtual-System relationships on the same `mgmt_name`.
- Expose `id`, `object_id`, and `parent_object_ids` on `GroupMembershipNode` in `SearchResult`.
- Accept composite identifiers (`"{mgmt_name}:{domain_name}:{name}"` and `"{mgmt_name}:{domain_name}:{uid}"`) in `find_object`, `get_group_members`, `search_objects`, and `query_objects`.

**Non-Goals:**

- Changing the primary key (`id`) of `arodonata_objects`, `arodonata_services`, `arodonata_assets`, or `arodonata_rulebase_*` tables away from UID-based composite keys.
- Enforcing a database `UNIQUE` constraint on `object_id` or `service_id` (which would break on duplicate-named Check Point objects).

## Decisions

### 1. Non-Unique Indexed Composite Name Columns (`object_id`, `service_id`, `asset_id`)

- **Choice**: Keep `id = "{mgmt_name}:{domain_name}:{uid}"` as `primary_key=True` and add `object_id` (on `CPObject` / `CPObjectRecord`), `service_id` (on `CPService` / `CPServiceRecord`), and `asset_id` (on `Asset` / `AssetRecord`) as `Field(default="", index=True)` populated with `f"{mgmt_name}:{domain_name}:{name}"` in `model_post_init` and `from_cp_dict`.
- **Rationale**:
  - Check Point databases can contain multiple objects with identical `name` and distinct `uid` values within the same domain (for example, duplicate `email` entries in application/service definitions, or local and `Global` objects sharing a name).
  - Keeping `id` (`mgmt_name:domain_name:uid`) as the primary key ensures `ON CONFLICT (id) DO UPDATE` upserts and `replace_domain_*` operations never overwrite or drop one of the duplicate-named objects, and ensures object renames in `smart-fast` incremental mode update `name` and `object_id` / `service_id` in place.
  - Indexing `object_id`, `service_id`, and `asset_id` (`index=True`, non-unique) provides fast SQL lookups for dashboards and host applications.
- **Alternatives Considered**:
  - *Reverting `id` PK to `mgmt_name:domain_name:name`*: Rejected because duplicate-named Check Point objects would collide on primary key insert, losing UIDs referenced by groups and rules, and object renames during incremental sync would leave orphaned rows under the old name.

### 2. Dual UID and Human-Readable Parent/Child Links on `Asset` (Including Cross-Domain VSX)

- **Choice**:
  - Add `parent_id: str | None = None` (`"{mgmt_name}:{parent_domain}:{parent_uid}"`, indexed) and `parent_asset_id: str | None = None` (`"{mgmt_name}:{parent_domain}:{parent_name}"`, indexed) to `Asset` and `AssetRecord`.
  - Add `member_asset_ids: list[str]` and `virtual_system_asset_ids: list[str]` (stored as JSON arrays on `AssetRecord`) alongside `member_uids` and `virtual_system_uids`.
  - In `ClusterRelationshipManager.enrich()` and `VSXRelationshipManager.enrich()`, populate all four parent fields (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`) on child assets and both UID and `asset_id` lists on parent cluster/VSX assets.
  - In `AssetRefreshService`, after per-domain asset synchronization completes (or using existing cached assets across `mgmt_name`), reconcile cross-domain VSX-to-Virtual-System links across all cached domains of `mgmt_name` so a Virtual System in a tenant domain resolves `parent_id = "{mgmt_name}:{vsx_domain}:{vsx_uid}"` and `parent_asset_id = "{mgmt_name}:{vsx_domain}:{vsx_name}"` pointing to the physical VSX gateway/cluster in its infrastructure domain, and the parent VSX asset's `virtual_system_uids` and `virtual_system_asset_ids` include the child Virtual System.
- **Rationale**: In MDSM deployments with VSX, the physical VSX gateway/cluster typically resides in an infrastructure domain while individual Virtual Systems reside in tenant domains. Including `parent_domain` in `parent_id` and `parent_asset_id` makes cross-domain hierarchy immediately visible in dashboards and SQL queries.

### 3. Composite Identifier Support in `SearchService` and `ArodonataClient`

- **Choice**:
  - Enrich `GroupMembershipNode` with `id: str = ""` (`"{mgmt_name}:{domain_name}:{uid}"`), `object_id: str = ""` (`"{mgmt_name}:{domain_name}:{name}"`), and `parent_object_ids: list[str]`.
  - Update `matches_classified_term()` in `SearchService` so `"name"` and `"wildcard"` terms also match against `obj.object_id` and `obj.id`.
  - Update `ArodonataClient.find_object()` and `SearchService.get_group_members()` so callers can pass a full composite identifier (`"mds:General:hWebHost"`, `"mds:General:Cluster01"`, or `"mds:General:<uid>"`) as `name_or_uid` / `group_name_or_uid` in addition to a bare `name` or `uid`.
  - Update `SearchService.describe_objects()` and `SearchService.query_objects()` to include `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id`.

## Risks / Trade-offs

- **[Risk] Upgrading existing SQLite/PostgreSQL cache databases with new `NOT NULL` columns (`object_id`, `service_id`, `asset_id`, `member_asset_ids`, `virtual_system_asset_ids`)** → **Mitigation**: `DatabaseManager._apply_schema_evolution_sync()` already detects `NOT NULL` column additions on ephemeral `arodonata_*` cache tables via `compute_schema_hash()` and automatically recreates or alters those cache tables safely inside the cross-worker initialization lock (`pg_advisory_xact_lock` / `BEGIN IMMEDIATE`).

## Migration Plan

1. Update Pydantic models in `src/arodonata/core/models/{objects,services,assets}.py` with auto-computed default fields in `model_post_init` and `from_cp_dict`.
2. Update SQLModel table definitions in `src/arodonata/adapters/storage/tables.py` and record-mapping functions in `src/arodonata/adapters/storage/cache_adapter.py`.
3. Update `ClusterRelationshipManager`, `VSXRelationshipManager`, and `AssetRefreshService` in `src/arodonata/core/services/asset_service.py` to populate dual UID and human-readable topology links (including cross-domain VSX reconciliation).
4. Update `SearchService` and `ArodonataClient.find_object()` to populate `GroupMembershipNode` composite fields and match composite identifiers.
5. Update `docs/architecture/database-schema.md` and unit tests.
