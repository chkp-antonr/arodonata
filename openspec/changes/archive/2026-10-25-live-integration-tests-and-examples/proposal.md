# Proposal

## Why

Arodonata v2 has completed all 8 core milestones with full unit test coverage against mocks, but lacks a live-environment integration test harness and runnable SDK usage examples. Adding a bucketed integration test suite (`tests/integration/b1..b7`) driven by `./pytest.sh` alongside a progressive `examples/` catalog allows us to validate real Check Point MDSM/SMS behavior (TLS fingerprint verification, login rate-limiting and 70s throttle windows, session overlays, cache synchronization modes, CPCRUD idempotency, rulebase numbering, change reports, and MCP tools) while keeping fast unit tests (`tests/unit/`) as a strict, zero-network gate before every PR.

## What Changes

- **Restructure `tests/` into `tests/unit/` and `tests/integration/`**:
  - Move all existing fast unit test modules from `tests/test_*.py` into `tests/unit/test_*.py`.
  - Configure `pyproject.toml` pytest markers (`integration`, `bucket_1`..`bucket_7`, `cp_mutates`) and default `addopts` (`-m "not integration"`) so bare `pytest` / `./pytest.sh` runs only the fast unit suite required for PRs.
- **Add `./pytest.sh` unified test runner**:
  - `./pytest.sh` (or `./pytest.sh unit`): Runs the fast unit test suite (`tests/unit/`) with coverage.
  - `./pytest.sh int-1` .. `./pytest.sh int-7`: Runs a single live integration bucket as an isolated pytest session with live CLI logging (`--log-cli-level=INFO`), `--tb=short` (to prevent leaking secrets in tracebacks), and `--durations=15`.
  - `./pytest.sh int-full`: Executes all 7 integration buckets sequentially, each in its own pytest session with a configurable `BUCKET_PAUSE_SECONDS` (default 90s) pause between buckets to clear Check Point's per-IP login rate-limit window, continuing on failure and summarizing results at the end.
  - `./pytest.sh <pytest args>`: Passthrough for targeted test execution (e.g. `-k`, specific file paths).
- **Add live integration harness and utilities in `tests/integration/`**:
  - `lab_env.py`: Loads `.env.test`, `.env.secrets`, and `.env.lab.<ARODONATA_LAB>` profile overrides (with `${VAR}` expansion and `ARODONATA_TEST_DOMAINS` filtering).
  - `run_lock.py`: Non-blocking `fcntl.flock` exclusive file lock (`_tmp/integration.lock`) preventing concurrent integration runs from colliding on the shared lab server and SQLite cache.
  - `lab_ready.py`: Pre-session readiness gate probing `show-api-versions` without a session header via v2 `ApiTransport` + `TrustPolicy` so an idle/waking CPM fails fast or warms up without spending login rate-limit allowance.
  - `cp_revision.py` & `restore_baseline.py`: Captures `show-last-published-session` baseline snapshots (`_tmp/cp_baseline/baseline-<UTC>.json`) for `TEST_DOMAIN_A` and `TEST_DOMAIN_B` before any test runs, and automatically reverts drifted domains via `revert-to-revision` (`timeout=900s`) after `cp_mutates` tests.
  - `probe_lab_domains.py`, `probe_login_throttle.py`, `lab_build.py`: Standalone diagnostic and lab-provisioning scripts adapted to Arodonata v2 `ApiTransport`, `TrustPolicy`, and `ArodonataClient`.
  - `conftest.py`: Session-scoped fixtures (`integration_tracing`, `integration_run_lock`, `lab_ready`, `db_engine`, `cp_baseline_snapshot`, `all_domains`) and per-identity client fixtures (`apikey_client`, `admin_client`, `antonr_client`, `eng1_client`..`eng4_client`).
- **Add 7 live integration test buckets (`tests/integration/b1`..`b7`) adapted to Arodonata v2 APIs**:
  - `b1`: Harness smoke, authentication (API key, credentials, dynamic `auth_context`, invalid credentials fast-fail), session lifecycle (SID caching, reuse, server-side expiration recovery, startup cleanup), session naming (`write_session` / `user_context`), concurrent admins & login deduplication, rate limiting, cached reads & search (`get_hosts`, `get_networks`, `search_objects`, `query_objects`), rulebase reads & SmartConsole numbering, and non-mutating change report reads.
  - `b2`: Single-domain object/service cache build (`refresh_objects`, `refresh_services`, `mode="smart"`) and live `client.cpcrud` suite (`plan`, `apply`, idempotency, staleness & `force=True`, `inverse`, conflict policies, services, groups, rules).
  - `b3`: Light mutation cycles (`write_session` with `SessionOverlay` read-your-own-writes, `create_dedicated_session`, publish, `smart-fast` incremental pickup, discard, revert) and login throttle recovery (`70s` window).
  - `b4`: Full cache mode matrix (`cache`, `smart`, `smart-fast`, `force`, fallback triggers when baseline is missing or changes exceed `max_incremental_changes`) and MDM multi-domain isolation (`TEST_DOMAIN_A` vs `TEST_DOMAIN_B`, `Global` domain resolution).
  - `b5`: Multi-domain full rebuilds (`refresh_objects`, `refresh_services`, `refresh_assets` with cluster/VSX relationships, `refresh_rulebases`), large rulebase pagination (>120 rules across sections), rulebase session check-mode refresh, publish/discard/revert multi-user matrix, and live/provisional/published change report session evidence.
  - `b6`: Bounded soak test (`test_soak.py`) running repeated publish -> `smart-fast` -> revert cycles to verify zero SID leakage and baseline stability.
  - `b7`: Live MCP server and tool suite (`test_mcp_server.py`, `test_mcp_tools.py`) testing `arodonata_init`, cached and live object/gateway tools, `search_objects`, `query_objects`, `describe_objects`, `get_cache_status`, cached/live rulebase rendering, `change_report`, and `api_call` write-protection gate.
- **Add environment templates and lab configs**:
  - Add `.env.example` documenting `.env`, `.env.test`, `.env.secrets`, and `.env.lab.<profile>` variables for Arodonata v2.
  - Copy and adapt `.env.test`, `.env.lab.home`, `.env.lib`, and `.env.secrets` from `../arodonata` (ensuring gitignore protection for secret/local env files).
- **Add progressive `examples/` catalog**:
  - `examples/README.md` & `examples/README_CRUD.md`: Setup and narrative guide for all examples.
  - `examples/_session_guard.py` & `examples/crud_example.yaml`: Crash-safe baseline snapshot/revert context manager and sample CPCRUD template.
  - `examples/01_basic_queries.py`: Querying domains, hosts, networks, and services through `ArodonataClient`.
  - `examples/02_search_and_query.py`: Multi-term `search_objects`, structured `query_objects`, `describe_objects`, and `get_group_members`.
  - `examples/03_gateway_relationships.py`: Inspecting gateway, cluster, and VSX topology via `refresh_assets` and `get_gateways`.
  - `examples/04_smart_refresh.py`: Populating and streaming cache progress (`stream_refresh_objects`, `stream_refresh_services`, `stream_refresh_assets`, `get_cache_status`).
  - `examples/05_rulebase_queries.py`: Refreshing rulebases (`stream_refresh_rulebases`), querying `get_access_rules` / `get_nat_rules`, SmartConsole package numbering (`get_package_rulebase`), `locate_rules`, and local `filter_rulebase`.
  - `examples/06_session_basics.py`: Raw and context-managed session lifecycle (`write_session`, `create_dedicated_session`, baseline capture, publish, discard, `revert-to-revision`).
  - `examples/07_context_and_overlay.py`: Arodonata v2 `auth_context`, `user_context`, and `SessionOverlay` read-your-own-writes isolation inside an uncommitted `write_session` before discard/publish.
  - `examples/08_cpcrud_operations.py`: Idempotent Policy-as-Code `client.cpcrud.apply()` with `guarded_session`.
  - `examples/09_cpcrud_inverse.py`: `plan()` -> `apply()` -> `inverse()` -> compensating `apply()` round-trip.
  - `examples/10_change_report_evidence.py`: Generating pending (live SID), provisional, and published change report evidence in HTML, Markdown, and JSON.
  - `examples/11_otel_tracing.py`: Provider-agnostic OpenTelemetry tracing with `arlogi.otel`, module span gating (`ARODONATA_TRACE_MODULES`), and per-span duration summary.
  - `examples/12_mcp_embedded.py`: Embedding Arodonata's ASGI MCP server inside a FastAPI application with custom tools.

## Capabilities

### New Capabilities

- `integration-testing-and-examples`: Live Check Point integration test harness (`tests/integration/b1..b7`), `./pytest.sh` bucketed test runner and PR unit-test gate, lab safety net (exclusive run lock, readiness gate, automatic revision baseline snapshot and revert), and progressive SDK usage examples (`examples/`).

### Modified Capabilities
<!-- No existing core library specification requirements are modified. -->

## Impact

- **Test Layout**: Moves `tests/test_*.py` to `tests/unit/test_*.py` and adds `tests/integration/` (with `b1`..`b7` buckets, `conftest.py`, and lab management scripts).
- **Tooling & Configuration**: Adds `./pytest.sh` at repository root, updates `pyproject.toml` (`pytest` markers, `addopts`, `python-dotenv` dev dependency, `fastapi` dev dependency for the embedded MCP example), updates `.gitignore` for `_tmp/`, `.env.*`, and `tls_known_hosts.json`.
- **Documentation & Examples**: Adds `examples/` directory with 12 runnable scripts, helper modules, and markdown guides (`examples/README.md`, `examples/README_CRUD.md`).
