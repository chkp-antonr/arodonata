# Design

## Context

See `proposal.md` for motivation and scope, `specs/*/spec.md` for the 11 capability delta contracts (`REQ-CONFIG-010`, `REQ-TRANS-008`, `REQ-SESS-016`, `REQ-CACHE-021`, `REQ-TOPO-024`, `REQ-RULE-010`, `REQ-REPORT-010`, `REQ-CPCRUD-019`, `REQ-MCP-018`, `REQ-ITEST-022`, `REQ-AIBUILD-007`), and `docs/_audit_/2611280941-deep-audit.md` for full evidence of all 52 confirmed findings (`DA-001`–`DA-052`) and 7 cross-module attack/failure chains (`CHAIN-01`–`CHAIN-07`).

## Goals / Non-Goals

**Goals:**

- Break all 7 compound cross-module failure/attack chains (`CHAIN-01`–`CHAIN-07`) and close every confirmed `HIGH`, `MEDIUM`, and `LOW` defect across core, adapters, rulebase, reports, CPCRUD, MCP, testing, plugin docs, and governance docs.
- Maintain strict hexagonal port boundaries (`ApiPort`, `LockPort`, `AuthProvider`, `GatewayCliPort`, `RulebaseRefreshPort`, and segregated `CachePort` sub-protocols) and naive UTC SQLModel conventions.
- Leave every new requirement/scenario (`19` scenarios across `11` capabilities) backed by `@pytest.mark.spec("SCN-...")` unit/spec tests with zero baseline drift.

**Non-Goals:**

- Modifying `pyproject.toml` dependency versions or breaking existing public signatures on `ArodonataClient`, `CPCRUDService`, or `FileReplayApiMock`.
- Introducing breaking changes to `arodonata_collect_routes_v1` rendered script bodies or Check Point schema table layouts.

## Decisions

### 1. TLS Pinning, Rate Limiting, Config & Session Hardening (Breaks `CHAIN-02`, `CHAIN-07`)

- **Atomic Multi-Key TOFU & Symmetric Hostname Binding (`DA-004`, `DA-033`)**: Add `TrustStore.record_many(targets, fingerprint, source=..., persist=...)` in `src/arodonata/adapters/checkpoint/tls.py` to validate all `(host, port)` keys against `disk_entries` inside a single `flock` critical section in `_save_atomic()` before writing/replacing `tls_known_hosts.json`. In `TrustPolicy.verify_fingerprint()`, add the symmetric branch binding `(id_host, port)` when `stored_entry` matches `(resolved_ip, port)` and `stored_id_entry is None`.
- **Pinned `SessionCleaner` & Pre-Lock Cooldown Waiting (`DA-024`, `DA-030`, `DA-031`)**: Remove unconditional `evict_sid` calls on `ApiTimeoutError` and non-failover `TransportError` in `AMgmtClient.api_call()`. In `LoginGate.acquire()`, wait out active in-process `_next_allowed_at[target_ip]` cooldown before entering the distributed lock (`gate_lock_ttl >= connect_timeout + max(api_timeout, login_timeout) + 60.0`). In `SessionCleaner.cleanup_server_sessions()`, pass the DNS-pinned IP, port, and `tls_identity_host` to both `show-sessions` and `discard`.
- **Pydantic v2 `@field_serializer` & Recursive Redaction (`DA-009`, `DA-015`, `DA-049`)**: Replace `model_dump()` / `model_dump_json()` masking overrides on `ArodonataSettings` and `ArodonataMCPSettings` with `@field_serializer` methods so enclosing Pydantic models redact secrets automatically. In `update_overlay_from_command()`, recursively strip any mapping key satisfying `is_sensitive_key(k)` across nested dicts/lists and apply `redact_sid()` to string values. In `ScriptRepositoryService`, extract `_map_script_session_errors` `@asynccontextmanager` tracking the active phase (`login`, mutation verb, or `publish`).

### 2. SQLite Hardening, Multi-Domain Sync, VSX Assets & Search (Breaks `CHAIN-05`)

- **SQLite Symlink & `0o600` Enforcement (`DA-014`)**: Extract `_validate_and_harden_sqlite_file(db_file)` in `src/arodonata/adapters/storage/database.py` and invoke it before creation, inside `except FileExistsError:`, and at the start of `DatabaseManager.initialize()` for any non-memory file-backed SQLite engine.
- **Race-Free Partial-Column Cross-Domain VSX Reconciliation (`DA-007`, `DA-035`)**: Replace blind full-row `upsert_assets(modified)` in `AssetRefreshService.reconcile_cross_domain()` with conditional partial-column updates targeting only VSX-linking columns on existing rows inside a transaction (never resurrecting deleted rows or overwriting concurrent per-domain asset columns). Add `_is_excluded_cluster_member` in `ClusterRelationshipManager.enrich()` Pass 1 and exclude `"member"` types in `_build_cross_domain_find_by_ref()` per `SCN-CACHE-019-5`.
- **Discovery Watermarks, Logs, Cold-Failure `synced_at` & Search (`DA-010`, `DA-025`, `DA-026`, `DA-027`, `DA-037`, `DA-041`)**: Pass pre-discovery `target_seq` to `DomainListRefreshTracker.mark_refreshed()`, scrub discovery warnings through `redact_sid()` plus add SID-redacting `ApiQueryResult.__repr__`/`__str__`, preserve `prev.synced_at if prev else None` on failed cold slices, extract `asset_matches_classified_term()` for `ip_subnet` queries, short-circuit `types=[]`, and unify type-scope partitioning in `arodonata.core.models.common.partition_entity_types()`.

### 3. Gateway Topology, Route Parsers & Scoring (Breaks `CHAIN-01`)

- **Read-Only `mode="cache"`, `WriteSession` Isolation & Coalescing (`DA-005`, `DA-016`, `DA-044`)**: Make `_stream_targeted_gateway_refresh()` a read-only no-op on `mode="cache"`, pass `apply_overlay=False` (or skip shared SQL writes under an active `WriteSession`), include resolved `cache_ttl` in `refresh_topology` single-flight `flight_key`, and hydrate only uncached requested domains in `collect_gateway_routes()`.
- **ECMP/`proto routed`, VSX Bundle Errors & Destination Normalization (`DA-008`, `DA-018`, `DA-019`, `DA-051`)**: Track multi-line ECMP headers in `parse_ip_route_show` and `parse_clish_show_route`, upgrade `clish_route` to `bgp_route`/`ospf_route` in `parse_combined_cli_routes_with_status`, check upstream `base_result` failure before `VSX_BUNDLE_END_MARKER` and `matched is None` in `extract_vs_slice_from_bundle()`, add `subnet4`/`mask-length4` support in `_parse_route_destination()` returning `None` for non-default unresolved dicts, and compose `route_scripts.py` from shared private shell-fragment helpers while keeping rendered scripts byte-identical.
- **Exclusion Groups, Scoring & Object Indexing (`DA-028`, `DA-029`, `DA-050`)**: Hydrate `except` in `group-with-exclusion` and subtract excluded intervals in `_expand_cp_object()`; check same-interface covering live routes and pass `ann_by_if_wildcard` in `_score_interface_group()`; unify exact+`.lower()` lookups in `_lookup_indexed_object()` and decompose `_resolve_topology_objects_on_demand()`.

### 4. Rulebase Numbering, Pagination & Change Reports (Breaks `CHAIN-06`)

- **Case-Insensitive Fallback, Placeholder Precedence & Pagination (`DA-012`, `DA-042`, `DA-052`)**: Align exact-first + `.lower()` fallback across `number_package_rulebase`, `_find_layer_entry`, `_ensure_and_load_package_snapshot`, and `_resolve_domain_for_target`; check `placeholder_domain_layer_uid` before `inline_layer_uid` in `_record_layer_prefixes_from_rules`; extract `_RulebasePageAccumulator`, `_build_rulebase_page_payload`, and `_materialize_paged_rulebase` in `rulebase/pager.py`.
- **Markdown Escaping, `OwnedSession` 404 Recovery & Partial-Slice Warming (`DA-020`, `DA-021`, `DA-022`, `DA-038`, `DA-048`)**: Extract `escape_markdown_cell` (backslash-first) and `escape_markdown_code` into `src/arodonata/core/primitives.py` and fix `render_safe_inline_markdown_md` backslash handling; move `is_not_found_error` into `arodonata.core.errors` (or `primitives.py`) so `_resolve_session_bare_uids` retries read-only (`sid=None`) on 404 without disabling `OwnedSession`; trigger `refresh_rulebase_fn` in `apply_session_rule_placement()` when `sync_state is None`; add `"range_session_timestamp_missing"` to `WarningCode`.

### 5. CPCRUD & MCP Multi-Tenant Isolation (Breaks `CHAIN-03`, `CHAIN-04`)

- **Virtual Rule Overlays, `where-used` & `UserContext` Isolation (`DA-001`, `DA-002`, `DA-003`, `DA-017`, `DA-040`)**: Resolve UID overrides in-place before `del_set` name checks and anchor newly created virtual rules before trailing cleanup rules in `HybridStateReader._apply_virtual_rules`; propagate `{add, remove}` cell deltas, `track`, `raw_data`, and NAT/HTTPS/Threat fields in `_apply_update_to_virtual_rule`; fail closed at plan time on unnamed virtual rule updates/deletes; fix `check_where_used` rule extraction, `_deleted_rules`, and active-rename filtering; compute `owner_key` from `AuthContext` + `UserContext` in `_execute_domain_batch` and remove the single-peer fallback in `_select_staged_eviction_key`.
- **MCP Scope/Quota Bounds, Atomic Staging & Live Filtering (`DA-006`, `DA-011`, `DA-034`)**: Cap total unique `session_uids` (`<= 50`) in MCP `change_report`, charge `consume_live_quota_if_needed(cost=max(len(scopes), total_unique_session_uids))`, and construct `SessionScope`/`RangeScope` from a strict allowlist omitting `owned_sessions`. Pre-check/roll back multi-domain `cpcrud_apply` staged capacity atomically without self-evicting batch siblings and shield line-184 eviction discards. Filter `list_assets(..., cache_mode="live")` locally after full `show-gateways-and-servers` pagination.

### 6. Replay Emulator, AI-Builder Plugin Docs & Governance Alignment

- **Replay Emulator Fidelity (`DA-013`, `DA-023`, `DA-032`, `DA-036`, `DA-039`, `DA-043`, `DA-045`)**: Validate `manage_repository_scripts` (`"write"`, `"read"`, `"none"`), preserve constructor RBAC flags on `reset()`, enforce group `is_group`/self-reference/cross-session parent locks, use `DROP_UID` for default track, deduplicate `where-used` column constants from `_emulator_projection`, catch `ValidationError` as JSON HTTP 400 in `CheckPointReplayHttpServer`, and enforce open-session/same-domain/zero-changes/write guards in `handle_verify_or_install_policy()` (aligning `verify-policy` documentation/read-only behavior across `core/primitives.py` and `docs/troubleshooting/checkpoint-api-quirks.md` while keeping `sid=None` stateless test compatibility).
- **Docs & Spec Sync (`DA-032`, `DA-046`, `DA-047`)**: Fix `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md`, update `AGENTS.md` and `openspec/config.yaml` hexagonal port summaries, and complete `add-arodonata-aibuilder-plugin` sync/archive in workflow follow-up.

## Risks / Trade-offs

- **[Risk] Refactoring `route_scripts.py` subtly alters rendered `arodonata-collect-routes-v1` script text** → Mitigation: Assert byte-for-byte identity between old and new `build_route_collection_script()` / `build_route_collection_repository_script()` outputs in unit tests.
- **[Risk] Enforcing `verify-policy` write-session vs. read-only semantics breaks existing MCP or `AMgmtClient` tests** → Mitigation: Explicitly reconcile `core/primitives.py` (`READONLY_EXACT_COMMANDS`) vs. `docs/troubleshooting/checkpoint-api-quirks.md:12` in Task 6.1 and keep stateless `sid=None` replay mock compatibility when `active_ws is None`.
- **[Risk] Active `add-arodonata-aibuilder-plugin` delta spec and `wave-12` `ai-builder` delta spec both target `openspec/specs/ai-builder/spec.md`** → Mitigation: Use disjoint requirement IDs (`REQ-AIBUILD-007` in Wave 12 vs. `001`/`004`/`005`/`006` in `add-arodonata-aibuilder-plugin`) so both validate cleanly side by side and archive independently in either order.
