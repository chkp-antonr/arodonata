# Design

## Context

See `proposal.md` for motivation and scope. Arodonata v1 (`../arodonata/`) established a battle-tested live integration harness against a Check Point MDSM lab (7 buckets `b1..b7`, `pytest.sh`, `lab_env.py`, `run_lock.py`, `lab_ready.py`, `cp_revision.py`, and `examples/`). However, Arodonata v2 introduces a clean hexagonal architecture with significant API and behavioral differences from v1:

- **Native `aiohttp` Transport & Pre-Request TLS Verification**: v2 replaces `cp-mgmt-api-sdk` (`cpapi`) with `arodonata.adapters.checkpoint.transport.ApiTransport` and `TrustPolicy` (`pinned`, `tofu`, `lab-memory`). Note that `TrustPolicy(mode="lab-memory")` checks `ARODONATA_LAB` for truthiness (`1`, `true`, `yes`, `on`), whereas `lab_env.py` uses `ARODONATA_LAB=<profile_name>` (e.g. `home`) to select `.env.lab.<profile>`. In `.env.lab.home`, `ARODONATA_TLS_TRUST=pinned` is used with explicit `ARODONATA_TLS_FINGERPRINTS`.
- **Paired Refresh APIs**: v1's generator-only `refresh_objects()` / `build_refresh_assets_cache()` are replaced in v2 by paired methods on `ArodonataClient`:
  - `await client.refresh_objects(...) -> RefreshOutcome` and `async for ev in client.stream_refresh_objects(...) -> SyncProgressEvent`
  - `await client.refresh_services(...) -> RefreshOutcome` and `async for ev in client.stream_refresh_services(...) -> SyncProgressEvent`
  - `await client.refresh_assets(...) -> RefreshOutcome` and `async for ev in client.stream_refresh_assets(...) -> SyncProgressEvent`
  - `await client.refresh_rulebases(...) -> RefreshOutcome` and `async for ev in client.stream_refresh_rulebases(...) -> SyncProgressEvent`
- **Unified Facade & Context-Bound Sessions**: v1's `arodonata.helpers` (`create_session`, `add_object`, `discard_session`) and `api_call_with_sid` are replaced in v2 by built-in `ArodonataClient` methods:
  - `async with client.write_session(mgmt_name, domain, auth=..., user=..., session_name=..., publish_on_exit=...) as ws:` with `SessionOverlay` read-your-own-writes isolation.
  - `await client.api_call(mgmt_name, command, payload, domain=..., sid=..., server_ip=..., wait_for_task=..., timeout=...)` (accepting `sid` and `server_ip` directly as keyword arguments).
  - `await client.add_object(mgmt_name, obj_type, payload, domain=..., sid=..., server_ip=...)`, `set_object`, `delete_object`, `find_object`, `get_group_members`.
  - `client.auth_context(...)` and `client.user_context(...)` via `contextvars`.
- **Typed Read Models & Cache Port**:
  - `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_objects` return `list[CPObject]` (with `ipv4_address`, `subnet4`, `mask_length4`, `raw_data`).
  - `get_services` returns `list[CPService]`.
  - `get_gateways` returns `list[Asset]` (with `parent_uid`, `asset_type`, `ipv4_address`).
  - `search_objects` returns a structured `SearchResult` (`matches`, `parent_groups`, `total_matches`), complemented by `query_objects`, `describe_objects`, and `get_cache_status`.
- **Startup Cleanup Control**: `await client.initialize(run_startup_cleanup=False)` cleanly disables background startup session cleanup in integration fixtures without mutating private attributes after `__aenter__`.

## Goals / Non-Goals

**Goals:**

- Provide a zero-network, sub-10-second unit test execution path (`./pytest.sh` or `./pytest.sh unit`) that is mandatory before any PR.
- Port all 7 integration buckets (`b1..b7`), harness fixtures, and diagnostic/lab scripts (`lab_env.py`, `run_lock.py`, `lab_ready.py`, `cp_revision.py`, `restore_baseline.py`, `probe_lab_domains.py`, `probe_login_throttle.py`, `lab_build.py`) to native Arodonata v2 APIs without any dependency on `cpapi` or legacy v1 modules.
- Deliver a 12-script `examples/` catalog covering basic reads through advanced v2 features (`auth_context`, `user_context`, `SessionOverlay`, `cpcrud`, `change_reports`, OpenTelemetry span breakdown, and embedded FastAPI MCP).

**Non-Goals:**

- Modifying core library business logic or existing OpenSpec capability specifications (unless a real bug is uncovered during live lab execution, which would be tracked separately).
- Requiring a live Check Point server during standard CI or local unit-test runs.

## Decisions

### 1. Directory Layout & Pytest Marker Auto-Application

- **Decision**: Move all existing `tests/test_*.py` unit tests into `tests/unit/test_*.py` and place all live integration tests under `tests/integration/b1..b7/`. Configure `pyproject.toml` with `addopts = ["-ra", "-v", "--strict-markers", "-m", "not integration"]`.
- **Rationale**: Mirrors the proven `../arodonata/` layout. Any test under `tests/integration/` is automatically marked with `integration` and `bucket_<N>` via `pytest_collection_modifyitems` in `tests/integration/conftest.py`. Developers running `uv run pytest` or `./pytest.sh` never accidentally hit the live lab, and verbose output (`-v`) is shown by default for clear per-test visibility.
- **Alternatives Considered**: Keeping unit tests flat in `tests/` was rejected because separating `tests/unit/` and `tests/integration/` makes test discovery, coverage scoping, and bucket rebalancing (`git mv`) unambiguous.

### 2. Bucketed Execution via `./pytest.sh` with Login-Window Pauses

- **Decision**: `./pytest.sh` supports:
  - `./pytest.sh` or `./pytest.sh unit`: runs `uv run pytest tests/unit`
  - `./pytest.sh int-1` .. `./pytest.sh int-7`: runs a single bucket with `--override-ini=addopts= -ra -v --durations=15 --tb=short -o log_cli=true --log-cli-level=INFO`
  - `./pytest.sh int-full`: runs `b1..b7` as 7 independent `pytest` processes with `BUCKET_PAUSE_SECONDS="${BUCKET_PAUSE_SECONDS:-90}"` between buckets.
- **Rationale**: Each bucket runs as its own process so it acquires `IntegrationRunLock`, snapshots `TEST_DOMAIN_A`/`TEST_DOMAIN_B` baselines before the bucket starts, and reverts any drift at bucket teardown. Pausing 90s between buckets ensures the next bucket's baseline snapshot does not walk into Check Point's 3-logins-per-minute-per-IP lockout window armed by the previous bucket.

### 3. Native v2 Readiness Probe & Diagnostic Scripts (Zero `cpapi`)

- **Decision**: Implement `lab_ready.py`, `probe_lab_domains.py`, `probe_login_throttle.py`, and `lab_build.py` using Arodonata v2's `ApiTransport` and `TrustPolicy` (async `aiohttp` under `asyncio.run`) rather than v1's synchronous `cpapi` (`VerifiedAPIClient`).
- **Rationale**: Arodonata v2 intentionally eliminated `cp-mgmt-api-sdk` (`cpapi`). Using `ApiTransport.execute(host, "show-api-versions", {}, sid=None, timeout=10.0)` in `lab_ready.py` verifies both TLS certificate trust (`TrustPolicy`) and CPM API responsiveness (`res.success` or `res.error_code` present in JSON response, e.g., `generic_err_missing_required_header`) without consuming a login slot.

### 4. Client Fixture Lifecycle in `tests/integration/conftest.py`

- **Decision**: In `tests/integration/conftest.py`, construct `ArodonataClient(settings=..., engine=db_engine)` and enter it via `await client.initialize(run_startup_cleanup=False)` inside an async generator fixture that calls `await client.close(logout=True)` in `finally:`.
- **Rationale**:
  1. Passing an external `db_engine` causes `client.owns_engine` to be `False`, which by default sets `should_logout=False` on `client.close()` so persistent caches keep their SIDs. Explicitly calling `await client.close(logout=True)` on fixture teardown ensures test sessions are cleanly logged out on the Check Point server at the end of each test/fixture scope, preventing `max sessions exceeded` accumulation across a bucket.
  2. `run_startup_cleanup=False` prevents concurrent background `SessionCleaner` tasks from competing for rate-limiter slots during fixture setup; `test_session_lifecycle.py` tests startup cleanup explicitly with `run_startup_cleanup=True`.

### 5. Adapting `.env.*` Configuration Files for v2

- **Decision**: Copy `.env.example`, `.env.test`, `.env.lab.home`, `.env.lib`, and `.env.secrets` from `../arodonata/` into the repository root, keeping `.env`, `.env.test`, `.env.secrets`, `.env.lib`, and `.env.lab.*` in `.gitignore` (while tracking `.env.example`). In `lab_env.py`, bridge `API_MGMT` / `APIKEY` and `ARODONATA_TLS_*` environment variables cleanly into `ArodonataSettings`.
- **Rationale**: Note that in v2 `TrustPolicy.__init__`, `mode == "lab-memory"` checks `ARODONATA_LAB in ("1", "true", "yes", "on")`. When `ARODONATA_LAB=home` is used to select `.env.lab.home` (which uses `ARODONATA_TLS_TRUST=pinned`), `TrustPolicy` works as-is. If a user sets `ARODONATA_TLS_TRUST=lab-memory` alongside `ARODONATA_LAB=home`, `TrustPolicy` should accept any non-empty `ARODONATA_LAB` value (or `lab_env.py` / `TrustPolicy` should treat any non-empty `ARODONATA_LAB` profile name as enabling lab mode). We will ensure `lab_env.py` and `ArodonataSettings` interoperate seamlessly.

### 6. Progressive Examples Architecture (`examples/01..12`)

- **Decision**: Organize `examples/` into 12 numbered, self-contained scripts plus `_session_guard.py` and `crud_example.yaml`:
  - Read-only / Cache warm-up (`01`..`05`): load `.env.lib` + `.env.secrets` (falling back to `.env.test` + `.env.secrets` + `.env.lab.<ARODONATA_LAB>` so they work out-of-the-box in both dev and lab setups).
  - Session & Context workflows (`06_session_basics.py`, `07_context_and_overlay.py`): showcase v2's `write_session`, `auth_context`, `user_context`, and `SessionOverlay` read-your-own-writes before discard/publish.
  - Mutating CPCRUD & Change Report workflows (`08_cpcrud_operations.py`, `09_cpcrud_inverse.py`, `10_change_report_evidence.py`): wrap all Check Point mutations in `async with guarded_session(client, mgmt_name, domains=[...]):` so the lab domain is always restored to its pre-run baseline revision.
  - Observability & Integration (`11_otel_tracing.py`, `12_mcp_embedded.py`): demonstrate `arlogi.otel` span file export + `ARODONATA_TRACE_MODULES` filtering, and mounting `create_asgi_app` inside FastAPI.

## Risks / Trade-offs

- **[Risk] Check Point Login Rate Limiting (3 logins / minute / IP)** → **Mitigation**: `LoginCoordinator` in v2 already gates logins per `active_mds_ip` and waits `login_throttle_window` (`70s`) on throttle responses; `pytest.sh int-full` pauses `90s` between buckets; `conftest.py` paces `SETTLE_SECONDS` (default `3s`) between tests and `2s` between domain baseline snapshots.
- **[Risk] Crashed Mutating Test Leaves Lab Domain Drifted** → **Mitigation**: `cp_baseline_snapshot` writes `_tmp/cp_baseline/baseline-<UTC>.json` before any test runs and reverts drifted domains in teardown; `restore_baseline.py` provides one-command manual recovery if the test process was killed with `SIGKILL`; `examples/_session_guard.py` persists `examples/_tmp/session_guard_state.json` and recovers prior unclean runs on entry before taking a new snapshot.
- **[Risk] Secret Leakage in Test Tracebacks or Logs** → **Mitigation**: `pytest.sh` enforces `--tb=short` by default on all integration runs, and v2's `ArodonataSettings`, `AuthContext`, and `ArodonataError` redact SIDs, passwords, and API keys in `repr()` and exception messages.
