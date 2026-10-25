# Design

## Context

`arodonata` v2 is designed to operate both as a standalone Check Point SDK/MCP server and as an embedded engine inside larger async Python applications that pass a shared SQLAlchemy `AsyncEngine` (`ArodonataClient(engine=host_engine)`). Embedding into multi-worker host applications with existing database schemas requires strict table namespace isolation, uniform naive UTC timestamp handling, and complete lifecycle methods for staged sessions, exact-match search, and Policy-as-Code rule export.

## Goals / Non-Goals

**Goals:**

- Standardize all database columns and domain models in `arodonata` v2 on **naive UTC** (`datetime.now(UTC).replace(tzinfo=None)` / `DateTime(timezone=False)`) so timestamps remain uniform and unambiguous across PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`).
- Ensure `DatabaseManager.initialize()` runs safely on a shared database containing host application tables in `SQLModel.metadata` as well as legacy Arodonata v1 cache tables (`domains`, `sid_cache`, `rulebase_*`).
- Eliminate table name collisions on generic `"assets"` tables by naming Arodonata's gateway/server cache table `"arodonata_assets"` (consistent with `"arodonata_objects"` and `"arodonata_services"`).
- Provide first-class SDK methods for exact-match object search (`exact_match=True`), staged session publication/discard via `take-over-session`, and exporting cached rulebase entries into `cpcrud` operation dicts.

**Non-Goals:**

- Introducing host-application business logic or local-timezone presentation formatting into `arodonata` (converting naive UTC to user-facing local timezones belongs at the presentation boundary).

## Decisions

### 1. Uniform Naive UTC (`DateTime(timezone=False)` and `to_naive_utc()`)

- **Decision**:
  1. In `src/arodonata/core/models/common.py`, update `utc_now()` to return `datetime.now(UTC).replace(tzinfo=None)` and add `to_naive_utc(dt: datetime | None) -> datetime | None` (converting aware datetimes via `dt.astimezone(UTC).replace(tzinfo=None)` and leaving naive datetimes as-is).
  2. In `src/arodonata/adapters/storage/tables.py` (and all Check Point timestamp parsers in `services/` and `reports/`), replace `DateTime(timezone=True)` with `DateTime(timezone=False)` and normalize all incoming/loaded timestamps via `to_naive_utc()`.
- **Rationale**: Multi-region deployments have administrators and gateways distributed across many timezones. Storing naive UTC uniformly in every database table prevents `asyncpg` `TIMESTAMP WITHOUT TIME ZONE` vs `TIMESTAMPTZ` errors and Python `TypeError: can't compare offset-naive and offset-aware datetimes`, while allowing callers to convert to local time programmatically when rendering UI or evaluating schedules.

### 2. Rename `AssetRecord.__tablename__` to `"arodonata_assets"`

- **Decision**: Change `AssetRecord.__tablename__` in `src/arodonata/adapters/storage/tables.py` from `"assets"` to `"arodonata_assets"`.
- **Rationale**: In `arodonata` v2, object and service caches are already namespaced as `arodonata_objects` and `arodonata_services`. Naming the gateway/server cache `arodonata_assets` prevents colliding with host application `assets` tables that may reside in the same database.

### 3. Scope `DatabaseManager` to `ARODONATA_TABLE_NAMES` with Legacy v1 Cache Table Recovery and Savepoints

- **Decision**:
  1. Define `ARODONATA_TABLE_NAMES: frozenset[str]` in `src/arodonata/adapters/storage/tables.py` listing only Arodonata's own tables (`arodonata_schema_version`, `distributed_locks`, `domains`, `sid_cache`, `domain_sync_state`, `arodonata_objects`, `arodonata_services`, `arodonata_assets`, `rulebase_package_layer`, `rulebase_layer`, `rulebase_section`, `rulebase_access`, `rulebase_nat`, `rulebase_https`, `rulebase_threat`).
  2. Filter `compute_schema_hash()` and `_apply_schema_evolution_sync()` by `table_name in ARODONATA_TABLE_NAMES` whenever `self._metadata is SQLModel.metadata`.
  3. In `_apply_schema_evolution_sync()`, inspect each existing Arodonata table before running `ALTER TABLE`: if the existing primary key columns do not match the v2 model's primary key columns (e.g., v1 `domains.mdm_dmn` vs v2 `domains.id`, or v1 `sid_cache.mgmt_dmn_key` vs v2 `sid_cache.id`, or v1 `arodonata_schema_version.id` vs v2 `schema_hash`), or if the existing table contains orphaned `NOT NULL` columns removed in v2, drop and recreate that Arodonata cache table inside a savepoint.
  4. Wrap every additive `ALTER TABLE ... ADD COLUMN` and `idx.create()` in `with sync_conn.begin_nested():`, catching duplicate-column / already-exists errors so multi-worker server startups never crash on a TOCTOU race.
- **Rationale**: All Arodonata tables are ephemeral caches or short-lived locks/SIDs that are automatically repopulated from Check Point Management API. Dropping and recreating an incompatible v1 cache table during a v1 -> v2 upgrade is safe and prevents `NotNullViolation` / `ProgrammingError` crashes on existing databases.

### 4. `exact_match: bool = False` in `SearchService.search_objects`

- **Decision**: Add keyword parameter `exact_match: bool = False` to `matches_classified_term()`, `SearchService.search_objects()`, `ArodonataClient.search_objects()`, and MCP `search_objects`. When `exact_match=True` and `term.kind == "name"`, compare `c.lower() == needle` instead of `needle in c.lower()` across `obj.name`, `obj.uid`, `obj.fqdn`, `obj.ipv4_address`, and `obj.subnet4`.
- **Rationale**: Enables callers to search for exact object names or domain objects (e.g. `.example.com` without matching `sub.example.com`) while wildcard queries (`*.example.com`) continue to use anchored `fnmatchcase`.

### 5. Staged Session Finalization via `take-over-session` (`publish_staged_session` & `discard_staged_session`)

- **Decision**: Add `publish_staged_session(mgmt_name, domain, *, session_uid, sid=None, server_ip=None, timeout=None)` (plus streaming `stream_publish_staged_session`) and `discard_staged_session(mgmt_name, domain, *, session_uid, sid=None, server_ip=None)` to `CPCRUDService` and `ArodonataClient`.
  - Check Point Web API `POST /web_api/publish` only commits the session bound to the caller's current `X-chkp-sid` (`Publishing other than current session is not implemented` if `{"uid": session_uid}` is passed from another session), and `discard` fails if session ownership diverged.
  - Both methods therefore open a dedicated session (or use the supplied `sid` if still valid, falling back to a fresh dedicated session on expiration), issue `take-over-session` with `{"uid": session_uid, "take-over-lock": True}` to adopt ownership, and then execute `publish` (`payload={}`) or `discard` (`payload={}`), followed by `logout` and `client.invalidate_domain(mgmt_name, domain)`.
- **Rationale**: Completes the `keep_session=True` staging lifecycle in `CPCRUDService` by encapsulating Check Point's `take-over-session` protocol requirement inside the SDK.

### 6. Native CPCRUD Rule Conversion (`rule_to_cpcrud_operation`)

- **Decision**: Add `rule_to_cpcrud_operation(rule: AccessRuleEntry | NatRuleEntry | HttpsRuleEntry | ThreatRuleEntry | NumberedRule, *, operation: Literal["add", "set", "delete"] = "set", package: str | None = None) -> dict[str, Any]` in `arodonata.rulebase` and support `format="cpcrud"` in `filter_rulebase()`.
- **Rationale**: Bridges Arodonata's read-side rulebase cache with its write-side `cpcrud` engine so callers can query cached rules and immediately emit schema-valid CPCRUD templates.

## Risks / Trade-offs

- **[Risk] Renaming `assets` to `arodonata_assets` affects raw SQL queries in unit tests** -> **Mitigation**: Update any test in `tests/unit/` that references the table name `"assets"` directly; `CachePort` / `ArodonataClient.get_gateways()` callers are unaffected because they use the `Asset` Pydantic model.
- **[Risk] Dropping legacy v1 `sid_cache` on v1->v2 upgrade orphans old read-only SIDs** -> **Mitigation**: `SessionCleaner` already cleans up stale sessions on startup, so dropping the v1 `sid_cache` table once during schema upgrade has zero operational impact.
