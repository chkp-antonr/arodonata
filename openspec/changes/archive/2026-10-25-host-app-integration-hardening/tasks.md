# Tasks

## 1. Uniform Naive UTC Timestamps (`core/models/` & `adapters/storage/tables.py`)

- [x] 1.1 Update `utc_now()` in `src/arodonata/core/models/common.py` to return naive UTC (`datetime.now(UTC).replace(tzinfo=None)`) and add `to_naive_utc(dt: datetime | None) -> datetime | None` helper exported from `arodonata.core.models.common` and top-level `arodonata`.
- [x] 1.2 Replace all `DateTime(timezone=True)` column definitions in `src/arodonata/adapters/storage/tables.py` with `DateTime(timezone=False)`, update `_ensure_utc()` in `tables.py` and timestamp parsers across `core/services/`, `cpcrud/`, `rulebase/`, and `reports/` to normalize all datetimes to naive UTC (`tzinfo=None`), and update unit tests to assert naive UTC datetimes.

## 2. Storage Namespace & Safe Multi-Worker Schema Evolution (`adapters/storage/`)

- [x] 2.1 Rename `AssetRecord.__tablename__` from `"assets"` to `"arodonata_assets"` in `src/arodonata/adapters/storage/tables.py` and export `ARODONATA_TABLE_NAMES: frozenset[str]` containing only Arodonata's managed tables.
- [x] 2.2 Update `compute_schema_hash()` and `DatabaseManager._apply_schema_evolution_sync()` in `src/arodonata/adapters/storage/database.py` to filter by `ARODONATA_TABLE_NAMES`, wrap `ALTER TABLE` / `CREATE INDEX` in `sync_conn.begin_nested()` savepoints tolerating concurrent duplicate-column/index errors, and automatically `DROP` + `CREATE` any Arodonata table whose existing primary key or `NOT NULL` columns are incompatible with the v2 model (including `arodonata_schema_version` v1 -> v2 upgrade).
- [x] 2.3 Add unit tests in `tests/unit/test_storage.py` verifying: (a) `arodonata_assets` table name and naive UTC columns, (b) foreign host tables in `SQLModel.metadata` are ignored by `DatabaseManager`, (c) legacy v1 `domains` (`mdm_dmn` PK) and `sid_cache` (`mgmt_dmn_key` PK) tables are cleanly dropped and recreated on `initialize()`, and (d) duplicate column/index errors inside savepoints do not abort initialization.

## 3. Exact-Match Object Search (`core/services/search_service.py` & `client.py`)

- [x] 3.1 Add `exact_match: bool = False` to `matches_classified_term()`, `SearchService.search_objects()`, `ArodonataClient.search_objects()`, and the `search_objects` MCP tool in `src/arodonata/mcp/tools.py`.
- [x] 3.2 Add unit tests in `tests/unit/test_search_service.py` verifying `exact_match=True` matches `.example.com` without matching `sub.example.com`, while preserving `*` and `?` wildcard matching and parent group traversal.

## 4. Staged Session Finalization (`cpcrud/service.py` & `client.py`)

- [x] 4.1 Implement `publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session` on `CPCRUDService` and expose them on `ArodonataClient`, handling `take-over-session` (`uid=session_uid`), `publish` / `discard`, `TaskWaiter` progress events, session logout, and `invalidate_domain()`.
- [x] 4.2 Add unit tests in `tests/unit/test_cpcrud_executor.py` covering staged session takeover + publish, takeover + discard, fallback to fresh session when the staged `sid` expired, and failure containment when publish task fails.

## 5. Native CPCRUD Rule Export (`rulebase/filter.py` & `rulebase/__init__.py`)

- [x] 5.1 Implement `rule_to_cpcrud_operation()` in `src/arodonata/rulebase/filter.py` (supporting access, NAT with `NAT_ORIGINAL_OBJECT_UID` / `NAT_ANY_OBJECT_UID` normalization, HTTPS, and threat-prevention rules) and extend `RuleFormat` / `filter_rulebase()` to support `format="cpcrud"`.
- [x] 5.2 Export `rule_to_cpcrud_operation` from `arodonata.rulebase` and top-level `arodonata`, and add unit tests in `tests/unit/test_rulebase_numbering.py` verifying that exported rule operations pass `validate_template()`.

## 6. Quality Gates & Spec Validation

- [x] 6.1 Run `./pytest.sh`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, and `openspec validate --strict --no-interactive`.
