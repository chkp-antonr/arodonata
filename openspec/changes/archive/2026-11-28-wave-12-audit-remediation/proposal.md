# Proposal

## Why

The `2611280941` full-repository deep audit (`docs/_audit_/2611280941-deep-audit.md`) of `arodonata_v2_aibuilder` (`feat/arodonata-aibuilder`, `87.4%` file coverage, `0` security blind spots) confirmed **52 findings** (`8` high, `30` medium, `14` low) and **7 compound cross-module chains** (`CHAIN-01`–`CHAIN-07`) spanning TLS/sessions, storage/sync/search, gateway topology, rulebases, change reports, CPCRUD, MCP, the replay emulator, AI-builder plugin documentation, and OpenSpec governance docs. Remediating all 52 findings in Wave 12 resolves every confirmed security, concurrency, spec-drift, and high-ROI refactoring issue in one clean, traceable OpenSpec change ready to execute in a fresh session.

## What Changes

1. **Configuration, TLS Pinning, Rate Limiting & Session Safety (`DA-004`, `DA-009`, `DA-015`, `DA-024`, `DA-030`, `DA-031`, `DA-033`, `DA-049`)**:
   - Switch `ArodonataSettings` and `ArodonataMCPSettings` secret masking to Pydantic v2 `@field_serializer` so enclosing-model serialization never leaks plaintext secrets (`DA-009`).
   - Make `TrustStore` multi-key TOFU persistence atomic across all target keys (`DA-004`), bind `(hostname, port)` symmetrically in `TrustPolicy.verify_fingerprint()` even when `(resolved_ip, port)` already exists (`DA-033`), preserve cached read-only SIDs across read timeouts and non-failover connect errors (`DA-024`), wait out `LoginGate` cooldown before acquiring the distributed DB lock (`DA-030`), and preserve DNS-pinned IP plus `tls_identity_host` in `SessionCleaner` (`DA-031`).
   - Recursively strip sensitive keys in `update_overlay_from_command()` (`DA-015`), and extract a shared phase-aware exception-scrubbing context manager in `ScriptRepositoryService` (`DA-049`).
2. **SQLite Hardening, Multi-Domain Sync, VSX Asset Reconciliation & Search (`DA-007`, `DA-010`, `DA-014`, `DA-025`, `DA-026`, `DA-027`, `DA-035`, `DA-037`, `DA-041`)**:
   - Harden `DatabaseManager` SQLite `FileExistsError` TOCTOU and external `AsyncEngine` path/symlink/`0o600` checks (`DA-014`).
   - Replace full-row cross-domain VSX upserts with conditional partial-column updates so concurrent per-domain asset refreshes are never clobbered (`DA-007`), and exclude Virtual Systems from cluster members and VSX members from parent candidates per `SCN-CACHE-019-5` (`DA-035`).
   - Preserve mid-flight domain-list invalidations in `DomainListRefreshTracker.mark_refreshed()` (`DA-025`), scrub domain discovery warning logs and `ApiQueryResult.__repr__` (`DA-026`), preserve `synced_at=None` on cold failed slices (`DA-027`), support CIDR/range and interface-IP `ip_subnet` queries on `Asset` rows (`DA-010`), short-circuit `search_objects(types=[])` (`DA-041`), and unify duplicated type-scope partitioning (`DA-037`).
3. **Gateway Topology, Live CLI Route Parsers, VSX Coalescing & Scoring (`DA-005`, `DA-008`, `DA-016`, `DA-018`, `DA-019`, `DA-028`, `DA-029`, `DA-044`, `DA-050`, `DA-051`)**:
   - Make targeted `refresh_topology(mode="cache")` strictly read-only and isolate `WriteSession` overlays (`DA-005`), key single-flight topology coalescing on effective `cache_ttl` (`DA-044`), and hydrate cold requested domains per domain in `collect_gateway_routes` (`DA-016`).
   - Support multi-line Linux/Gaia ECMP routes and Gaia `proto routed` BGP/OSPF upgrades (`DA-008`), prioritize upstream `run-script` failure checks before missing-VS checks in `extract_vs_slice_from_bundle` (`DA-019`), and prevent `_parse_route_destination` from fabricating `0.0.0.0/0` on non-default/`subnet4`/IPv6 dicts (`DA-018`).
   - Support `group-with-exclusion` `except` clauses (`DA-028`), fix same-interface live-summary scoring and wildcard annotation dispositions (`DA-029`), unify case-insensitive topology object indexing and decompose `_resolve_topology_objects_on_demand` (`DA-050`), and deduplicate bash/awk snippets in `route_scripts.py` (`DA-051`).
4. **Rulebase Numbering, Pagination Decomposition & Change Reports (`DA-012`, `DA-020`, `DA-021`, `DA-022`, `DA-038`, `DA-042`, `DA-048`, `DA-052`)**:
   - Align case-insensitive package/layer fallback across rulebase loading and numbering (`DA-012`), prioritize `placeholder_domain_layer_uid` over `inline_layer_uid` in prefix tracking (`DA-042`), and decompose `fetch_paged_rulebase` (`DA-052`).
   - Fix backslash-prefix escaping and unify Markdown escapers across `reports` and `rulebase/filter.py` (`DA-020`, `DA-038`), fall back cleanly on single `show-object` 404 without disabling healthy `OwnedSession`s (`DA-021`), warm full-domain rulebases when only a partial single-package slice is cached (`DA-022`), and add `"range_session_timestamp_missing"` to `WarningCode` (`DA-048`).
5. **CPCRUD Virtual Overlays, `where-used` & Multi-Tenant Staged Registry (`DA-001`, `DA-002`, `DA-003`, `DA-017`, `DA-040`)**:
   - Preserve renamed rule indices and anchor virtual rules before trailing cleanup rules in `HybridStateReader._apply_virtual_rules` (`DA-001`), preserve `{add, remove}` cell deltas and full rule fields in `_apply_update_to_virtual_rule` (`DA-003`), respect virtually deleted rules and active renamed entities in `check_where_used` (`DA-017`), and fail closed at plan time on unnamed virtual rule updates/deletes (`DA-040`).
   - Derive `Executor._staged_sessions` `owner_key` from `UserContext` as well as `AuthContext` and enforce peer-safe staged session eviction (`DA-002`).
6. **MCP Quota/Scope Hardening, Atomic Multi-Domain Staging & Live Asset Filtering (`DA-006`, `DA-011`, `DA-034`)**:
   - Enforce an explicit `session_uids` cap with proportional live quota charging and strip caller-supplied `owned_sessions` in MCP `change_report` (`DA-006`).
   - Pre-check/roll back multi-domain `cpcrud_apply` staged capacity atomically with shielded eviction (`DA-011`), and apply local `types`/`roles`/`platforms`/`parent`/`filter` filtering in `list_assets(..., cache_mode="live")` (`DA-034`).
7. **Replay Emulator Fidelity, AI-Builder Plugin Docs & Governance Alignment (`DA-013`, `DA-023`, `DA-032`, `DA-036`, `DA-039`, `DA-043`, `DA-045`, `DA-046`, `DA-047`)**:
   - Validate `manage_repository_scripts` and preserve constructor RBAC flags on `FileReplayApiMock.reset()` (`DA-013`, `DA-032`), fix group self-containment and cross-session parent locks (`DA-023`), use `DROP_UID` in default access-rule track (`DA-039`), deduplicate rulebase reference-column constants (`DA-036`), return Check Point JSON 400 on malformed command names in `CheckPointReplayHttpServer` (`DA-043`), and enforce session/domain guards on `verify-policy`/`install-policy` (`DA-045`).
   - Align `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md` (`DA-032`) and `AGENTS.md` / `openspec/config.yaml` (`DA-047`), and track `add-arodonata-aibuilder-plugin` spec sync/archive (`DA-046`).

## Capabilities

### Modified Capabilities

- `configuration`: Add `REQ-CONFIG-010` (`SCN-CONFIG-010-1`).
- `transport-and-tls`: Add `REQ-TRANS-008` (`SCN-TRANS-008-1`, `SCN-TRANS-008-2`).
- `sessions-and-mdm`: Add `REQ-SESS-016` (`SCN-SESS-016-1`).
- `cache-and-sync`: Add `REQ-CACHE-021` (`SCN-CACHE-021-1`, `SCN-CACHE-021-2`, `SCN-CACHE-021-3`).
- `gateway-topology`: Add `REQ-TOPO-024` (`SCN-TOPO-024-1`, `SCN-TOPO-024-2`, `SCN-TOPO-024-3`).
- `rulebase-and-numbering`: Add `REQ-RULE-010` (`SCN-RULE-010-1`).
- `change-reports`: Add `REQ-REPORT-010` (`SCN-REPORT-010-1`, `SCN-REPORT-010-2`).
- `cpcrud`: Add `REQ-CPCRUD-019` (`SCN-CPCRUD-019-1`, `SCN-CPCRUD-019-2`).
- `mcp-server`: Add `REQ-MCP-018` (`SCN-MCP-018-1`, `SCN-MCP-018-2`).
- `integration-testing-and-examples`: Add `REQ-ITEST-022` (`SCN-ITEST-022-1`, `SCN-ITEST-022-2`).
- `ai-builder`: Add `REQ-AIBUILD-007` (`SCN-AIBUILD-007-1`).

## Impact

- **Codebase**: `src/arodonata/{adapters,core,rulebase,reports,cpcrud,mcp,testing}/`, `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md`, `AGENTS.md`, `openspec/config.yaml`, and `docs-notebooklm/*`.
- **Tests & Traceability**: Unit and spec tests carrying `@pytest.mark.spec("SCN-...")` across all 19 new scenarios (`SCN-CONFIG-010-1` through `SCN-AIBUILD-007-1`).
