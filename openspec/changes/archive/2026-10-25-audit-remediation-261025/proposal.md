# Proposal

## Why

An independent Principal Security Architect & SDK Compliance Audit (`docs/_audit_/2610250949.md`) uncovered 8 Critical security/correctness defects (`C1`–`C8`), 30 Warnings (`W1`–`W30`), and 18 Architecture/Implementation Improvements (`I1`–`I18`) across transport, sessions, storage schema evolution, distributed locking, secret hygiene, CPCRUD, MCP server, and the integration test harness. Addressing every finding in a single cohesive OpenSpec remediation change is mandatory before Arodonata v2 can be certified for production release or embedded into downstream enterprise platforms.

## What Changes

- **Transport & TLS (`C1`, `C8`, `W1`, `W2`, `W3`, `I9`, `I10`, `I11`, `I12`)**:
  - Enforce strict command name validation (`^[a-z0-9]+(-[a-z0-9]+)*$`) at the central `ApiTransport.execute` choke point (`C1`).
  - Disable HTTP redirects (`allow_redirects=False`) and treat any `3xx` response as a transport error (`W1`).
  - Classify `TransportError` by execution phase (`phase="connect"` vs `phase="post-send"` / `request_sent: bool`) using concrete `aiohttp` exception types rather than string heuristics (`C8`, `I10`), preventing CMA failover retry after request bytes have been transmitted (`C8`).
  - Harden `TrustStore` with cross-process file locking (`fcntl.flock`), atomic read-merge-write, file permission/ownership validation on load, a deterministic user-scoped default path (`~/.config/arodonata/tls_known_hosts.json` or explicit path) instead of CWD-relative, and RFC-compliant IPv6 `[host]:port` parsing (`W3`, `I9`).
  - Remove or strictly gate the unverified `request_sender` test seam so unit tests exercise `FingerprintTCPConnector` against a local TLS server (`W2`), enforce `trust_env=False` and explicitly reject proxy connections (`_create_proxy_connection`) (`I12`), and bound connection pool housekeeping (`WeakKeyDictionary` or transport close cleanup, `show-*`-only pooling, idle socket reaper) (`I11`).

- **Sessions, MDM & Rate Limiting (`C4`, `C7`, `C8`, `W4`, `W5`, `W6`, `W7`, `W9`, `I7`, `I8`)**:
  - **BREAKING (Internal Cache Schema)**: Bind `AuthContext.identity_key` and `sid_cache` rows to a cryptographic HMAC-SHA256 digest of credentials (`username` + `password` or `api_key`, plus `user_id` and `auth_mode`), include `auth_identity` in the `arodonata_sid_cache` primary key (`f"{mgmt_name}:{dom_key}:{auth_identity}"`), and never match `auth_identity=None` (`C4`).
  - Reject mutating commands on the shared read-only `sid_cache` path (requiring an active `WriteSession`, explicit `sid`, or auto-dedicated isolated session for standalone `add_object`/`set_object`/`delete_object`) (`C8`).
  - Eliminate the `LoginGate` failover deadlock by moving `refresh_domain_active_ip()` and backoff sleeps outside `LoginGate.acquire()`, bounding local `asyncio.Lock` acquisition with `asyncio.timeout(wait_timeout)`, adding backoff after login read timeouts (`W4`), and enforcing true inter-login rate-limiting (`min_interval` / shared throttle cooldown per MDS IP) inside `LoginGate` (`C7`, `W5`).
  - Protect `RateLimiter` slot release with `try ... finally` and `asyncio.shield` so DB errors or `CancelledError` never leak local FIFO semaphore slots (`W6`), shield `run_coalesced_keepalive` from waiter cancellation (`I7`), and ensure DB slot/gate TTL exceeds maximum permitted call timeouts (`max(api_timeout, login_timeout) + 60s`) (`I8`).
  - Harden `write_session` cleanup against `CancelledError` (`BaseException`), discard unpublished changes when `publish` returns `success=False`, and retain `_active_dedicated_sids` until `logout_sid` succeeds (`W7`).
  - Restrict `SessionCleaner` to discard only Arodonata-owned sessions (`application == "arodonata"` or `arodonata*` session name prefix) that have `changes == 0` and `locks == 0` (`W9`).

- **Database Storage, Table Namespacing & Sync Coordination (`C5`, `C6`, `W13`–`W21`, `I1`–`I6`, `I14`, `I15`)**:
  - **BREAKING (Database Table Names)**: Prefix ALL Arodonata SQLModel tables with `arodonata_` (`arodonata_distributed_locks`, `arodonata_domains`, `arodonata_sid_cache`, `arodonata_domain_sync_state`, `arodonata_rulebase_access`, `arodonata_rulebase_nat`, `arodonata_rulebase_https`, `arodonata_rulebase_threat`, `arodonata_rulebase_layer`, `arodonata_rulebase_section`, `arodonata_rulebase_package_layer` alongside existing `arodonata_schema_version`, `arodonata_objects`, `arodonata_services`, `arodonata_assets`) (`C5`).
  - Gate legacy v1 table cleanup (`LEGACY_V1_TABLES`) strictly on positive v1 column fingerprints (`mdm_dmn` on `domains`, `mgmt_dmn_key` on `sid_cache`) and never `DROP` or `ALTER` unprefixed host tables (`C5`).
  - Serialize `DatabaseManager.initialize()` across workers using `pg_advisory_xact_lock` on PostgreSQL and `BEGIN IMMEDIATE` on SQLite, re-checking `arodonata_schema_version` and table existence after acquiring the lock (`C6`, `I1`, `I2`).
  - Extend `LockPort` and `SqlLockAdapter` with lock renewal (`renew` / periodic heartbeat task during long syncs), owner-verified `release`, DB-server-side UTC clock comparisons (`func.now()` / SQLite UTC expression), and retry handling for PostgreSQL serialization/deadlock errors (`W13`, `W16`, `I6`).
  - Treat `LockAcquisitionError` in `DomainSyncCoordinator` as a non-destructive `skipped_locked` / contended state (or wait briefly) rather than overwriting `domain_sync_state.status = "failed"` over an active worker (`W14`).
  - Replace `asyncio.gather` with `asyncio.TaskGroup` in `DomainSyncCoordinator` so fatal errors (`ServerIdentityError`) cancel sibling domain tasks deterministically (`W15`).
  - Avoid shared single-connection rollback hazards on in-memory SQLite (`W17`), format `from-date` with explicit UTC `Z` suffix, align `ServiceCacheService` to prefer `from-session` over `from-date` (`W18`), commit snapshot replacement and `domain_sync_state` updates in a single atomic transaction across `RulebaseRefreshService`, `ObjectService`, and `ServiceCacheService` (`W19`), fail closed when `verify_session_clean` (`show-session`) fails (`W20`), and use dialect-aware `ON CONFLICT DO UPDATE` upserts instead of racy `session.merge()` (`W21`).
  - Normalize naive datetime comparisons and injected `now_fn` clocks (`I3`, `I4`), never fabricate `last_published_at = now` when `remote_published_at is None` (`I5`), paginate `show-domains` in `DomainService` (`I14`), and clean up stale docstrings/config (`I15`, `I16`).

- **Secret Hygiene & Telemetry (`W22`–`W25`, `I13`)**:
  - Redact all error strings written to `domain_sync_state.last_error`, `DomainSyncFailedEvent`, and `DomainStamp.error` using `redact_sid(..., known_sids=...)` (`W22`).
  - Redact sensitive fields in `ApiCallResult.__repr__` and strip secret request parameters (`one-time-password`, `shared-secret`, `password`, `api-key`) before merging into `SessionOverlay` (`W23`).
  - Protect secrets in `ArodonataSettings` / `ArodonataMCPSettings` (`SecretStr` or masked serializers) and mask credentials in `database_url` within `__repr__` (`W24`).
  - Make `sanitize_mapping` recurse into nested lists/tuples, pass active `known_sids` into MCP error redaction (`W25`), and sanitize chained `__cause__` / `__context__` exceptions in `@traced` (`I13`).

- **CPCRUD & MCP Server Hardening (`C1`, `C2`, `C3`, `W8`, `W10`–`W12`, `W26`–`W28`, `I17`, `I18`)**:
  - Replace raw client-supplied executable `Plan` deserialization in MCP `cpcrud_apply` with server-side stored plans (`plan_id`) and/or HMAC-SHA256 signed plans; re-derive all execution commands strictly from an allowlist of `(object_type, operation)` pairs; remove `force` and `validate_schema` from the MCP tool surface and cap `retry_remaining` (`<= 3`) (`C2`).
  - Enforce an explicit read-only command allowlist in MCP `api_call` and validate `obj_type` against the canonical object type registry in `show_object`, `HybridStateReader`, and `Planner` (`C1`).
  - Fix `ArodonataMCPSettings` static token parsing so `client_id=secret` splits only when the left-hand side matches `^[A-Za-z_][A-Za-z0-9_-]*$`, enforce minimum token length (`>= 32` chars), never log secret prefixes, hash both sides with SHA-256 before `hmac.compare_digest`, and validate numeric ports on wildcard `Host` headers (`C3`, `I18`).
  - Refuse `auth_mode="jwt"` when `token_verifier is None`, reject or warn on unauthenticated `0.0.0.0` / wildcard host bindings, and secure `examples/12_mcp_embedded.py` (`W26`).
  - Route `ARODONATA_MCP_ALLOW_WRITE_API=true` mutating `api_call` invocations through isolated dedicated sessions (`W27`), bound `timeout` in MCP `api_call`, and add `cpcrud_publish_staged` and `cpcrud_discard_staged` MCP tools (`W28`).
  - Ensure `CPCRUDService` executor discards open sessions on any exception or `CancelledError` (`BaseException`) and wraps `publish` transport failures (`W8`), re-checks domain head before retry passes (`force=False`) and immediately prior to `publish` while rejecting `last_session_uid=None` drift (`W10`, `W11`), requires/accepts `ApplyReport` (or `plan_id`) in `cpcrud_inverse` so only actually applied actions are inverted safely (`W12`), and rejects duplicate template operation `id`s while wrapping `dns-domain` dot-retry errors in `StateLookupError` (`I17`).

- **Integration Testing Harness & Adversarial Unit Suite (`W29`, `W30`)**:
  - Align `pytest.sh`, `tests/integration/conftest.py`, and `tests/integration/_harness/cp_revision.py` with `integration-testing-and-examples` spec (`BUCKET_PAUSE_SECONDS=90`, `-o log_cli=true --log-cli-level=INFO`, exit codes `3`/`4`/`5`, `ARODONATA_TEST_READY_WAIT`, `_tmp/cp_baseline/baseline-<UTC>.json`, `REVERT_TIMEOUT_SECONDS=900`) (`W29`).
  - Add comprehensive adversarial and regression unit tests covering every single `C1`–`C8` and `W1`–`W30` vector (`W30`).

## Capabilities

### New Capabilities

<!-- None: all changes harden and extend existing canonical capabilities. -->

### Modified Capabilities

- `transport-and-tls`: Enforce strict command regex validation (`^[a-z0-9]+(-[a-z0-9]+)*$`), `allow_redirects=False`, phase-aware `TransportError` (`connect` vs `post-send`), file-locked/permission-checked `TrustStore` with RFC IPv6 key parsing, `trust_env=False` proxy rejection, and real TLS connector unit testing.
- `sessions-and-mdm`: Bind `sid_cache` to HMAC credential identity in PK, forbid mutating commands on shared read-only `sid_cache`, eliminate `LoginGate` failover deadlock, enforce true per-MDS login rate-limiting and read-timeout backoff, shield `RateLimiter` slot release, harden `write_session` cancellation/discard, and restrict `SessionCleaner` to Arodonata sessions with 0 changes/locks.
- `client-and-facade`: Enforce dedicated sessions for standalone `add_object`/`set_object`/`delete_object` mutations, redact `ApiCallResult` repr and `SessionOverlay` secret fields, and sanitize chained exceptions in `@traced`.
- `configuration`: Store secrets as `SecretStr` / masked fields, mask `database_url` credentials in `__repr__`, anchor default `tls_known_hosts_path` outside CWD, and harden MCP static token parsing (`^[A-Za-z_][A-Za-z0-9_-]*$` prefix split and minimum secret length).
- `cache-and-sync`: Prefix all Arodonata tables with `arodonata_`, fingerprint-gate legacy v1 drops, serialize `DatabaseManager.initialize()` via advisory/immediate locks with double-check, add distributed lock renewal/heartbeat and DB-clock expiry, handle lock contention without marking active syncs failed, use `asyncio.TaskGroup`, use dialect `ON CONFLICT` upserts, and enforce atomic state writes and `from-session`/`from-date` UTC invariants.
- `rulebase-and-numbering`: Commit rulebase snapshot replacement and `arodonata_domain_sync_state` update in a single atomic transaction with periodic distributed lock renewal.
- `cpcrud`: Re-derive execution commands from an allowlist of `(object_type, operation)`, discard uncommitted sessions on any `BaseException` during `apply`, enforce strict domain head staleness checks across retry passes and pre-publish, reject duplicate template `id`s, and harden `inverse()` with `ApplyReport` filtering and full prior-state restoration.
- `mcp-server`: Enforce read-only command allowlist, eliminate client-forged `Plan` execution via server-stored/HMAC-signed plans without `force`/`validate_schema`, add `cpcrud_publish_staged`/`cpcrud_discard_staged` tools, isolate `ALLOW_WRITE_API` calls in dedicated sessions, forbid `jwt` auth fail-open, and pass `known_sids` into error redaction.
- `integration-testing-and-examples`: Align `pytest.sh`, `conftest.py`, `cp_revision.py`, and `examples/12_mcp_embedded.py` with canonical timeout, logging, exit code (`3`/`4`/`5`), baseline path, and authentication requirements.

## Impact

- **Affected Code**: `src/arodonata/adapters/checkpoint/{transport,tls,sessions,rate_limiter,client}.py`, `src/arodonata/adapters/storage/{tables,database,cache_adapter,lock_adapter}.py`, `src/arodonata/core/{config,context,errors,telemetry}.py`, `src/arodonata/core/models/common.py`, `src/arodonata/core/services/{sync_coordinator,object_service,service_cache,domain_service}.py`, `src/arodonata/rulebase/refresh.py`, `src/arodonata/cpcrud/{models,planner,state_reader,executor,inverse}.py`, `src/arodonata/mcp/{config,security,server,tools,errors}.py`, `src/arodonata/client.py`, `pytest.sh`, `tests/integration/`, `examples/12_mcp_embedded.py`, `tests/unit/`.
- **Database Schema Impact**: All unprefixed Arodonata cache/coordination tables are renamed to `arodonata_*`. Existing v2 cache tables from pre-release deployments will be cleanly created under `arodonata_*`; legacy v1 tables are dropped only when positively fingerprinted.
- **MCP Tool Surface Impact**: `cpcrud_apply` requires a server-issued `plan_id` (or signed plan envelope) and drops `force`; `cpcrud_plan` drops `validate_schema`; new `cpcrud_publish_staged` and `cpcrud_discard_staged` tools are added.
