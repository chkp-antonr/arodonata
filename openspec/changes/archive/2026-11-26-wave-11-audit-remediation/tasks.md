# Tasks

## 1. Transport, Sessions, Lifecycle & Pagination

- [x] 1.1 Fix `SessionCleaner` `ServerIdentityError` re-raise, `keepalive_sid()` isolation, `target_resolver` eviction guard, and `get_readonly_session()` single-DNS target resolution (`DA-009`, `DA-016`, `DA-024`)
- [x] 1.2 Extend `redact_sid()`, add `shielded_best_effort()`, fix write-session cancellation/discard, discard failed `_mutate_object()`, and enforce `max_query_pages` / `max_query_objects` / `MAX_RULEBASE_OBJECTS` (`DA-012`, `DA-017`, `DA-018`, `DA-031`)

## 2. Assets, Topology & Script Repository

- [x] 2.1 Add `vsx_cluster_member`/`vs_netobj` aliases, harden `_asset_linking.py` exclusion guards, and decompose `reconcile_cross_domain()` (`DA-010`, `DA-039`, `DA-055`)
- [x] 2.2 Isolate topology SQL writes from active `WriteSession`, enforce `verify_session_clean()`, scope CLI targets, match all canonical annotation IDs, preserve `/0` prefixes, and map `RepositoryScriptUnsupportedError` (`DA-004`, `DA-013`, `DA-014`, `DA-026`, `DA-034`, `DA-041`, `DA-056`)

## 3. CPCRUD, Change Reports & MCP Tools

- [x] 3.1 Reject blank/duplicate IDs, unify verb normalization, fix planner virtual rule overlays/collision guards, preserve `ip_protocol=0` & access inline layers, restore empty `description`/`additional-categories`, fix concurrent `Executor.apply()` reports, and enforce owner-fair staged eviction (`DA-005`, `DA-021`, `DA-027`, `DA-028`, `DA-033`, `DA-045`, `DA-047`, `DA-057`)
- [x] 3.2 Add `"range_session_not_found"`, omit server date bounds for `RangeScope(to_session=...)`, extract `_OwnedSessionContext`, fix `list_domains` hints, multi-domain `_upgrade_uninitialized_cache_mode()`, `_run_typed_collection_tool()`, asset role/platform MCP filters, and peer-safe `staged_session_store` (`DA-022`, `DA-029`, `DA-030`, `DA-032`, `DA-040`, `DA-042`, `DA-049`, `DA-054`)

## 4. OpenSpec Sync, Docs Rebuild & Quality Gates

- [x] 4.1 Sync Wave-7 & asset-classification specs (`DA-008`, `DA-052`), add Wave-11 requirements and `@pytest.mark.spec` markers, rebuild `docs-notebooklm/*`, and pass all quality gates
