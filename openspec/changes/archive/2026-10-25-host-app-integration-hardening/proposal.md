# Proposal

## Why

When `arodonata` v2 is embedded into downstream host applications that share a single PostgreSQL or SQLite database engine (`SQLModel.metadata`), run multiple concurrent worker processes, and build higher-level automation workflows on top of the SDK ("Delegate, Never Duplicate"), several storage, timestamp, and API surface enhancements are needed:

1. **Uniform Naive UTC Database & Model Timestamps**: Distributed environments span administrators and security gateways across multiple timezones. Storing all database timestamps as **naive UTC** (`TIMESTAMP WITHOUT TIME ZONE` / `tzinfo=None`) across the SDK and converting to local time only at the presentation boundary avoids `TypeError: can't compare offset-naive and offset-aware datetimes` in Python and `asyncpg` `DataError` mismatches in PostgreSQL when joining or comparing timestamps with host application tables.
2. **Table Namespace Consistency (`assets` vs `arodonata_assets`)**: Arodonata v2 already namespaces its object and service cache tables as `arodonata_objects` and `arodonata_services`, but leaves `AssetRecord.__tablename__ = "assets"`. Generic table names like `assets` frequently collide with host application CMDB or inventory tables sharing the same database and `SQLModel.metadata`.
3. **Scoped Auto-Migration & Multi-Worker Startup Safety**: `DatabaseManager` currently hashes and inspects all tables in the global `SQLModel.metadata` (including any host application tables registered in the same process), executes `ALTER TABLE ADD COLUMN` without per-statement savepoints (`begin_nested()`), and fails when upgrading a database that still contains legacy Arodonata v1 cache tables (`domains`, `sid_cache`, `rulebase_*`) whose primary keys or `NOT NULL` columns changed in v2.
4. **SDK Workflow Completeness**:
   - **Exact-Match Object Search (`exact_match: bool = False`)**: Callers need case-insensitive exact name/FQDN matching (alongside `*` and `?` wildcard patterns) so searching `.example.com` does not match `sub.example.com`.
   - **Staged Session Finalization (`publish_staged_session` & `discard_staged_session`)**: When `cpcrud.apply(..., no_publish=True, keep_session=True)` leaves a write session staged for human review or deferred approval, Check Point Management API rejects publishing or discarding that session from a subsequent connection unless session ownership is adopted first via `take-over-session`.
   - **CPCRUD Rule Export from Cached Rulebases (`rule_to_cpcrud_operation`)**: Downstream automation and Policy-as-Code tools need a built-in helper to convert cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, and `ThreatRuleEntry` models directly into schema-valid `cpcrud` operation dictionaries.

## What Changes

- **Standardize Naive UTC Across All Arodonata Tables and Models**:
  - Change `utc_now()` in `src/arodonata/core/models/common.py` to return naive UTC (`datetime.now(UTC).replace(tzinfo=None)`) and add `to_naive_utc(dt: datetime | None) -> datetime | None` to convert any timezone-aware datetime (e.g. parsed from Check Point API ISO-8601/epoch responses) into naive UTC.
  - Change all `DateTime(timezone=True)` columns in `src/arodonata/adapters/storage/tables.py` to `DateTime(timezone=False)` (naive UTC) and update `_ensure_utc()` to normalize any datetime to naive UTC (`tzinfo=None`).
- **Namespace Arodonata Asset Cache Table (`arodonata_assets`) & Isolate `DatabaseManager` Migrations**:
  - Rename `AssetRecord.__tablename__` from `"assets"` to `"arodonata_assets"` so Arodonata's Check Point gateway/server cache never collides with host application `assets` tables.
  - Scope `compute_schema_hash()` and `DatabaseManager._apply_schema_evolution_sync()` strictly to Arodonata's own registered table set (`ARODONATA_TABLE_NAMES`), ignoring foreign tables that share `SQLModel.metadata`.
  - Detect incompatible legacy v1 cache table schemas (e.g., missing v2 primary key column, orphaned legacy `NOT NULL` columns such as `mdm_dmn` on `domains` or `mgmt_dmn_key` on `sid_cache`, or `TIMESTAMPTZ` vs naive `TIMESTAMP` mismatch) and automatically `DROP` + `CREATE` those ephemeral cache tables during `DatabaseManager.initialize()`.
  - Wrap each `ALTER TABLE ADD COLUMN` and `CREATE INDEX` statement in a nested transaction (`sync_conn.begin_nested()`) that tolerates concurrent `duplicate column` / `already exists` errors across multi-worker startups.
- **Add `exact_match: bool = False` to `SearchService.search_objects` and `ArodonataClient.search_objects`**:
  - Support `exact_match: bool = False` in `matches_classified_term()`, `SearchService.search_objects()`, `ArodonataClient.search_objects()`, and the `search_objects` MCP tool so `kind == "name"` terms perform case-insensitive equality (`c.lower() == needle`) while `kind == "wildcard"` continues to anchor `fnmatchcase(c.lower(), pattern)` across full strings.
- **Add Staged Session Finalization (`publish_staged_session` & `discard_staged_session`)**:
  - Add `publish_staged_session` (`stream_publish_staged_session`) and `discard_staged_session` to `CPCRUDService` and `ArodonataClient`.
  - Automatically adopt ownership of the staged session via `take-over-session` (`uid=session_uid`) when no active `sid` is bound or when publishing from a new connection, execute `publish` (with `TaskWaiter` progress polling and automatic `invalidate_domain`) or `discard`, and clean up the session.
- **Add Native CPCRUD Rule Export (`rule_to_cpcrud_operation` & `RuleFormat="cpcrud"`)**:
  - Add `rule_to_cpcrud_operation()` in `arodonata.rulebase` (and support `format="cpcrud"` in `filter_rulebase`) to convert cached/numbered `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, and `ThreatRuleEntry` models into schema-valid `checkpoint_ops_schema.json` operation dictionaries.

## Capabilities

### New Capabilities
<!-- None; all enhancements extend existing core specifications. -->

### Modified Capabilities

- `cache-and-sync`: Enforce naive UTC (`DateTime(timezone=False)` and `to_naive_utc()`) across all cache tables and domain models, rename asset cache table to `arodonata_assets`, scope `DatabaseManager` schema hashing and savepoint-protected auto-migration to `ARODONATA_TABLE_NAMES` with legacy v1 cache table drop-and-recreate recovery, and add `exact_match: bool = False` to `SearchService.search_objects()`.
- `cpcrud`: Add `publish_staged_session` (`stream_publish_staged_session`) and `discard_staged_session` with `take-over-session` adoption and domain cache invalidation.
- `rulebase-and-numbering`: Add `rule_to_cpcrud_operation()` and `format="cpcrud"` support in local rulebase filtering to export matched rules directly as valid CPCRUD operations.

## Impact

- **`src/arodonata/core/models/common.py` & `src/arodonata/adapters/storage/tables.py`**: Naive UTC `utc_now()`, `to_naive_utc()`, `DateTime(timezone=False)` on all database columns, and `AssetRecord.__tablename__ = "arodonata_assets"`.
- **`src/arodonata/adapters/storage/database.py`**: `ARODONATA_TABLE_NAMES` filtering, incompatible v1 table drop/recreate, and `begin_nested()` savepoints on DDL alterations.
- **`src/arodonata/core/services/search_service.py` & `src/arodonata/client.py`**: `exact_match: bool = False` parameter on `search_objects`.
- **`src/arodonata/cpcrud/service.py`, `src/arodonata/core/events.py`, & `src/arodonata/client.py`**: `publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session`.
- **`src/arodonata/rulebase/filter.py` & `models.py`**: `rule_to_cpcrud_operation` and `RuleFormat` extension.
