# Design

## Context

See `proposal.md` for motivation and `docs/_audit_/2610250949.md` for the full Independent Principal Security Architect & Spec Compliance Audit findings (`C1`–`C8`, `W1`–`W30`, `I1`–`I18`). Arodonata v2 adheres strictly to Hexagonal Architecture (Ports & Adapters), database-backed caching (`SQLAlchemy 2.0+` async + `SQLModel` on PostgreSQL and SQLite), naive UTC timestamps (`DateTime(timezone=False)`), and zero-leak secret hygiene. This design specifies the concrete architectural mechanics across all five remediation domains so implementation proceeds deterministically without regressions.

## Goals / Non-Goals

**Goals:**

- Eliminate all 8 Critical findings (`C1`–`C8`), all 30 Warnings (`W1`–`W30`), and all 18 Improvements (`I1`–`I18`) identified in `2610250949.md`.
- Maintain strict Hexagonal Architecture boundaries (`core/`, `rulebase/`, and `reports/` remain 100% free of `aiohttp`, `sqlalchemy`, `sqlmodel`, `asyncpg`, `aiosqlite`, `mcp`, and `arodonata.adapters` imports).
- Guarantee zero destructive impact on host-application tables when sharing a PostgreSQL or SQLite database.
- Back every remediated vulnerability and race condition with deterministic adversarial unit tests (`tests/unit/`).

**Non-Goals:**

- Introducing external migration frameworks (Alembic) or external lock managers (Redis/etcd); Arodonata remains self-contained on PostgreSQL/SQLite.
- Modifying the external Check Point Web API wire protocol.

## Decisions

### 1. Central Command Validation, Redirect Prohibition, and Phase-Typed Transport Errors (`C1`, `C8`, `W1`, `W2`, `W3`, `I9`–`I12`)

- **Command Validation Choke Point (`C1`)**:
  - In `src/arodonata/adapters/checkpoint/transport.py`, `ApiTransport.execute()` validates `clean_cmd` against `_COMMAND_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")` before constructing the URL or acquiring a connection. Any non-matching command (e.g., `show-hosts/../publish`, `show-x/%2e%2e/publish`, uppercase, whitespace, slashes, query strings) immediately raises `ValidationError`.
  - Secondary object-type interpolations in `src/arodonata/mcp/tools.py` (`show_object`), `src/arodonata/cpcrud/state_reader.py`, and `src/arodonata/cpcrud/planner.py` validate `obj_type` against a canonical frozen set of Check Point object types (`VALID_CP_OBJECT_TYPES`) before formatting `f"show-{obj_type}"` or `f"add-{obj_type}"`.
- **Disable HTTP Redirects (`W1`)**:
  - Pass `allow_redirects=False` to `session.post(...)` in `ApiTransport._send_request`. Any HTTP `3xx` status (`301`, `302`, `303`, `307`, `308`) is rejected immediately as a `TransportError` (`phase="post-send"`, `request_sent=True`) before any redirect target is contacted or learned by TOFU.
- **Explicit Transport Error Phase (`C8`, `I10`)**:
  - Extend `TransportError` (`src/arodonata/core/errors.py`) with `phase: Literal["connect", "post-send", "read"] = "post-send"` and `request_sent: bool = True`.
  - In `ApiTransport._send_request`, classify exceptions using concrete `aiohttp` types rather than `"connect" in str(exc).lower()`:
    - `aiohttp.ClientConnectorError`, `aiohttp.ClientConnectorCertificateError`, `aiohttp.ClientConnectorSSLError`, `aiohttp.ServerConnectionError` during connector acquisition, and `asyncio.TimeoutError` caught during connection establishment set `phase="connect"` and `request_sent=False`.
    - `aiohttp.ServerTimeoutError` (read timeout), `aiohttp.ServerDisconnectedError`, `ConnectionResetError`, `BrokenPipeError`, and post-connect `aiohttp.ClientOSError` set `phase="post-send"` (or `phase="read"` for `ApiTimeoutError`) with `request_sent=True`.
  - In `AMgmtClient.api_call` (`src/arodonata/adapters/checkpoint/client.py`), CMA failover re-resolution (`refresh_domain_active_ip()` followed by `_execute_once` retry) is permitted **only** when `exc.phase == "connect"` (`not exc.request_sent`) **and** the command is a read-only command (`is_readonly_command(command)`). Post-send errors never trigger failover retry.
- **TrustStore Hardening & IPv6 Normalization (`W3`, `I9`)**:
  - Anchor the default `tls_known_hosts_path` in `ArodonataSettings` (`src/arodonata/core/config.py`) to `Path.home() / ".config" / "arodonata" / "tls_known_hosts.json"` (expanding `~`), ensuring working directory changes never reset TOFU state.
  - Normalize `host:port` keys via a shared helper `format_host_port(host: str, port: int) -> str` and `parse_host_port(key: str, default_port: int = 443) -> tuple[str, int]` supporting bracketed IPv6 (`[2001:db8::1]:443`) and bare IPv6 literals (`2001:db8::1`) via `ipaddress.ip_address`.
  - In `TrustStore` (`src/arodonata/adapters/checkpoint/tls.py`), guard TOFU updates with an exclusive file lock (`fcntl.flock` on a sibling `.lock` file), re-read and merge on-disk JSON before writing atomically via temporary file + `os.chmod(tmp, 0o600)` + `os.replace`, and verify on load that the file is owned by `os.geteuid()` and has no group/world write bits (`st_mode & 0o022 == 0`).
- **Connector Security & Pool Housekeeping (`W2`, `I11`, `I12`)**:
  - Configure `aiohttp.ClientSession(..., trust_env=False)` and override `FingerprintTCPConnector._create_proxy_connection` to raise `TransportError("HTTP proxy connections are not supported with TLS fingerprint verification")`.
  - Require `peer_cert_getter` whenever `request_sender` is injected in `ApiTransport`, and add real loopback TLS (`ssl.SSLContext` + `aiohttp.web`) unit tests exercising `FingerprintTCPConnector` directly.
  - Track verified protocols in `FingerprintTCPConnector` using `weakref.WeakKeyDictionary` (or explicit cleanup in `ResponseHandler.close()`), pool connections strictly when `is_show_command(command)` is true, and reap expired idle sockets deterministically.

### 2. Table Namespacing, Fingerprinted v1 Migration, and Serialized Initialization (`C5`, `C6`, `I1`, `I2`)

- **Universal `arodonata_` Table Prefix (`C5`)**:
  - Rename all remaining unprefixed SQLModel `__tablename__` definitions in `src/arodonata/adapters/storage/tables.py`:
    - `distributed_locks` -> `arodonata_distributed_locks`
    - `domains` -> `arodonata_domains`
    - `sid_cache` -> `arodonata_sid_cache`
    - `domain_sync_state` -> `arodonata_domain_sync_state`
    - `rulebase_access` -> `arodonata_rulebase_access`
    - `rulebase_nat` -> `arodonata_rulebase_nat`
    - `rulebase_https` -> `arodonata_rulebase_https`
    - `rulebase_threat` -> `arodonata_rulebase_threat`
    - `rulebase_layer` -> `arodonata_rulebase_layer`
    - `rulebase_section` -> `arodonata_rulebase_section`
    - `rulebase_package_layer` -> `arodonata_rulebase_package_layer`
  - Every table in `ARODONATA_TABLE_NAMES` now begins with `arodonata_`.
- **Positive Fingerprint Gate for Legacy v1 Tables (`C5`)**:
  - Define `LEGACY_V1_TABLE_FINGERPRINTS: dict[str, set[str]] = {"domains": {"mdm_dmn"}, "sid_cache": {"mgmt_dmn_key"}}`.
  - During `DatabaseManager.initialize()`, an unprefixed table in `LEGACY_V1_TABLE_FINGERPRINTS` is dropped **only** if inspection confirms the table contains all required v1 fingerprint columns (`mdm_dmn` or `mgmt_dmn_key`). Any host table named `domains`, `sid_cache`, `distributed_locks`, etc. without the v1 fingerprint is completely untouched (never dropped, never altered).
- **Cross-Worker Migration Serialization & Double-Checked Existence (`C6`, `I1`, `I2`)**:
  - In `DatabaseManager.initialize()` (`src/arodonata/adapters/storage/database.py`):
    - On PostgreSQL, acquire a transaction-level advisory lock at the start of the migration transaction: `SELECT pg_advisory_xact_lock(7281940251839201)`.
    - On SQLite, begin the migration transaction with `EXEC SQL "BEGIN IMMEDIATE"` (coupled with an in-process `asyncio.Lock` per `DatabaseManager`).
    - Inside the lock, re-inspect the live database schema (`conn.run_sync(...)` with a fresh SQLAlchemy inspector), verify both `arodonata_schema_version` hash match **and** that every table in `ARODONATA_TABLE_NAMES` exists in `existing_tables` (`I2`).
    - Extend `_is_table_schema_incompatible` to also detect column type changes and newly required `NOT NULL` columns (`I1`) on `arodonata_*` cache tables so incompatible `arodonata_*` tables are cleanly recreated under the exclusive migration lock rather than adding `NULL` columns that violate model invariants.

### 3. Cryptographic SID Identity, Mutation Isolation, LoginGate & Cleanup Safety (`C4`, `C7`, `C8`, `W4`–`W9`, `I7`, `I8`)

- **HMAC-Bound `auth_identity` and `arodonata_sid_cache` Primary Key (`C4`)**:
  - In `src/arodonata/core/context.py` and `src/arodonata/adapters/checkpoint/sessions.py`, compute `auth_identity` using HMAC-SHA256 keyed by a secret salt (derived from `settings` or SHA-256 of the configured credential set so multi-worker processes sharing the same config derive the same deterministic identity, with a per-process CSPRNG key fallback for pure dynamic credentials) over the canonical credential tuple:
    - Credential mode / `AuthContext(username, password)`: `hmac_sha256(key, f"cred:{user_id or ''}:{username}:{password}")`.
    - API-key mode / `AuthContext(api_key)`: `hmac_sha256(key, f"apikey:{user_id or ''}:{api_key}")`.
  - Never return a static shared string (`"api_key_principal"`) or match `auth_identity is None`.
  - Change `SIDCacheRecord` (`arodonata_sid_cache`) primary key to `f"{mgmt_name}:{dom_key}:{auth_identity}"` so distinct tenants/principals on the same domain coexist in `arodonata_sid_cache` without overwriting or reusing each other's SIDs.
- **Strict Read-Only Enforcement on Cached SIDs (`C8`)**:
  - Define a canonical predicate `is_readonly_command(cmd: str) -> bool` (matching `show-*` and `where-used` / read-only diagnostic commands).
  - In `AMgmtClient.api_call`, if `sid is None` and no active `WriteSession` is bound in `contextvars`, reject any command where `not is_readonly_command(command)` by raising `SessionStateError("Mutating command requires a dedicated write_session or explicit sid")`.
  - In `ArodonataClient.add_object`, `set_object`, and `delete_object` (`src/arodonata/client.py`), if no active `WriteSession` is present in `contextvars` and no explicit `sid` was passed, automatically execute the operation inside `async with self.write_session(mgmt_name, domain):` so standalone helper calls always use an isolated dedicated session and publish/discard cleanly.
- **Deadlock-Free, Rate-Limiting `LoginGate` (`C7`, `W4`, `W5`)**:
  - In `LoginGate` (`src/arodonata/adapters/checkpoint/rate_limiter.py`):
    - Bound local `asyncio.Lock` acquisition with `async with asyncio.timeout(wait_timeout):`.
    - Track per-MDS login timestamps (`_last_login_at: dict[str, float]`) and shared throttle/cooldown deadlines (`_cooldown_until: dict[str, float]`) inside the gate, enforcing a minimum spacing between login attempts on the same MDS IP and honoring `record_throttle(mds_ip, duration)` across all queued coroutines (`W5`).
  - In `LoginCoordinator._perform_gated_login` (`src/arodonata/adapters/checkpoint/sessions.py`):
    - Hold `self._login_gate.acquire(mds_ip)` **only** around the single transport `login` call and rate-limit spacing check.
    - Release `LoginGate` **before** calling `refresh_domain_active_ip()` on failover/transport error and **before** any retry/throttle `asyncio.sleep(...)`, eliminating the self-deadlock when `refresh_domain_active_ip()` logs into the System domain on the same `mds_ip` (`C7`).
    - Apply exponential backoff when a login attempt fails with `ApiTimeoutError(phase="read")` (`W4`).
- **Cancellation-Safe Slot Release, WriteSession & SessionCleaner (`W6`, `W7`, `W9`, `I7`, `I8`)**:
  - In `RateLimiter.slot()` (`rate_limiter.py`), wrap DB lock release in `try: await asyncio.shield(self._lock_port.release(...)) finally: self._release_local_fifo_slot(...)` so `CancelledError` or DB errors never leak local FIFO slots (`W6`).
  - Set DB slot and login gate lock TTL to `max(180, max(api_timeout, login_timeout) + 60)` seconds (`I8`), and wrap the shared task in `run_coalesced_keepalive` with `await asyncio.shield(shared_task)` (`I7`).
  - In `AMgmtClient.write_session` (`adapters/checkpoint/client.py`) and `LoginCoordinator.logout_sid` (`sessions.py`):
    - Catch `BaseException` (including `asyncio.CancelledError`), shield `discard` and `logout_sid` via `asyncio.shield`, issue `discard` before `logout_sid` whenever `publish` returns `success=False`, and remove `sid` from `_active_dedicated_sids` only after `logout` completes (`W7`).
  - In `SessionCleaner` (`sessions.py`), inspect session metadata from `show-sessions` (`application`, `name`, `changes`, `locks`) and issue `discard` **only** when the session belongs to Arodonata (`application == "arodonata"` or `session_name.startswith("arodonata")`) **and** `changes == 0` **and** `locks == 0` (`W9`).

### 4. Distributed Lock Renewal, Atomic Sync Transactions & Secret Hygiene (`W13`–`W25`, `I3`–`I6`, `I13`–`I16`)

- **Distributed Lock Heartbeat & Server-Clock Expiry (`W13`, `W16`, `I6`)**:
  - Add `async def renew(self, lock_key: str, owner_id: str, ttl_seconds: int) -> bool` to `LockPort` and `SqlLockAdapter` (`src/arodonata/adapters/storage/lock_adapter.py`).
  - Use database-evaluated UTC time (`func.timezone('utc', func.now())` on PostgreSQL; `func.datetime('now')` on SQLite) for `expires_at` comparisons so host clock skew cannot steal valid locks (`W16`).
  - Require matching `owner_id` on `release()` and `renew()`, prevent silent re-acquisition without explicit renewal, and catch/retry PostgreSQL serialization/deadlock (`DBAPIError`) exceptions (`I6`).
  - In `DomainSyncCoordinator`, run a background heartbeat task that renews the per-domain lock every `ttl_seconds / 3` while the domain refresh is executing (`W13`).
- **Contention Handling & `asyncio.TaskGroup` (`W14`, `W15`)**:
  - When `DomainSyncCoordinator` catches `LockAcquisitionError` (another worker holds the domain lock), wait briefly or record the domain as skipped due to active peer sync without overwriting `arodonata_domain_sync_state.status = "failed"` and without emitting `DomainSyncFailedEvent` (`W14`).
  - Replace `asyncio.gather` with `asyncio.TaskGroup` in `DomainSyncCoordinator` so any unhandled fatal exception (such as `ServerIdentityError`) immediately cancels and awaits all sibling domain tasks (`W15`).
- **SQLite Concurrency, Atomic Sync Commits & Dialect Upserts (`W17`–`W21`, `I3`–`I5`, `I14`)**:
  - Use a shared-cache URI (`file:arodonata_mem_<id>?mode=memory&cache=shared`, `uri=True`) or serialized session write lock for default in-memory SQLite engines so concurrent coroutine rollbacks do not corrupt sibling transactions (`W17`).
  - Format `from-date` with explicit `Z` (`dt.strftime("%Y-%m-%dT%H:%M:%SZ")`) and update `ServiceCacheService` to prefer `from-session` (`last_session_uid`) over `from-date` (`W18`).
  - Commit data replacement and `arodonata_domain_sync_state` updates inside the **same** database session transaction in `RulebaseRefreshService`, `ObjectService`, and `ServiceCacheService` (`W19`).
  - Fail closed in `verify_session_clean` if `show-session` fails (`W20`).
  - Replace `await session.merge(...)` with `sqlalchemy.dialects.postgresql.insert(...).on_conflict_do_update(...)` and `sqlalchemy.dialects.sqlite.insert(...).on_conflict_do_update(...)` across `SqlCacheAdapter` (`W21`).
  - Compare naive UTC `datetime` objects directly without `.timestamp()` (`I3`), wrap `now_fn()` in `to_naive_utc()` (`I4`), keep `last_published_at = probe.remote_published_at` (`None` when never published) (`I5`), and page `show-domains` via `api_query` in `DomainService` (`I14`).
- **Comprehensive Secret & SID Redaction (`W22`–`W25`, `I13`)**:
  - Pass `redact_sid(str(exc), known_sids=...)` whenever writing `last_error`, `DomainSyncFailedEvent`, or `DomainStamp.error` (`W22`).
  - Implement a custom `ApiCallResult.__repr__` that masks `sid` and secret keys in `data`, and strip sensitive request keys (`password`, `one-time-password`, `shared-secret`, `api-key`, `secret`) in `_update_overlay_from_command` (`W23`).
  - Use custom Pydantic serializers / masked dump behavior on `ArodonataSettings` and `ArodonataMCPSettings` so `model_dump()` and `model_dump_json()` mask secrets by default, and mask `database_url` credentials (`urllib.parse` password replacement) in `ArodonataSettings.__repr__` (`W24`).
  - Recurse into `list`, `tuple`, and `set` values inside `sanitize_mapping`, pass active `known_sids` into MCP error redaction (`W25`), and sanitize `__cause__` and `__context__` chains in `@traced` (`I13`).

### 5. CPCRUD & MCP Hardening and Integration Harness Alignment (`C1`–`C3`, `W8`, `W10`–`W12`, `W26`–`W30`, `I17`, `I18`)

- **Server-Side / HMAC-Signed CPCRUD Plans & Command Allowlisting (`C2`, `W8`, `W10`–`W12`, `I17`)**:
  - In `src/arodonata/cpcrud/executor.py`, never trust `PlannedAction.command` blindly. Derive the Web API command strictly from a canonical `(object_type, operation) -> command` allowlist mapping (`_ALLOWED_CPCRUD_COMMANDS`); if `act.command` is present and differs from the derived allowlisted command, or `(act.object_type, act.operation)` is not in the allowlist, raise `ValidationError`.
  - In `src/arodonata/mcp/tools.py`:
    - Maintain an in-memory bounded LRU registry of generated plans (`_plan_store: dict[str, tuple[Plan, ApplyReport | None]]`) keyed by `plan_id` **and** attach an HMAC-SHA256 signature (`plan_signature`) computed with a server-secret key over the canonical plan JSON.
    - `cpcrud_apply` accepts `plan_id` (or a signed `plan` verified via `hmac.compare_digest` before `Plan.model_validate`), removes the `force` parameter from the MCP tool signature, removes `validate_schema` from `cpcrud_plan`, and caps `retry_remaining` at `3` (`C2`).
    - Add `cpcrud_publish_staged(mgmt_name, domain, session_uid)` and `cpcrud_discard_staged(mgmt_name, domain, session_uid)` MCP tools (`W28`).
    - Require `plan_id` or `report` in `cpcrud_inverse` so only succeeded actions are inverted (`W12`), and update `build_inverse_template` (`src/arodonata/cpcrud/inverse.py`) to refuse delete-by-name for unexecuted `planned:` UIDs and restore all prior fields present in `prior_state`.
  - In `Executor` (`src/arodonata/cpcrud/executor.py`):
    - Record staged sessions in `ApplyReport.staged_sessions` immediately after opening the session when `keep_session=True`, wrap `publish` in try/except, and in `finally` catch `BaseException` and shield `discard` before `logout_sid` whenever changes were not cleanly published or intentionally staged (`W8`).
    - Keep `force=False` on `retry_remaining` passes (`W10`), treat `stamp.last_session_uid is None` vs non-`None` current head as stale, and re-verify the domain head inside the session immediately before calling `publish` (`W11`).
  - In `Planner` and `HybridStateReader`, reject duplicate operation `id`s with `ValidationError` and wrap `dns-domain` leading-dot retry calls in `StateLookupError` (`I17`).
- **MCP Read Allowlist, Dedicated Write Sessions & Fail-Closed Auth (`C1`, `C3`, `W26`–`W28`, `I18`)**:
  - Replace `clean_cmd.startswith("show-")` in MCP `api_call` with an explicit frozen allowlist `MCP_READONLY_COMMANDS` when `ARODONATA_MCP_ALLOW_WRITE_API=false` (`C1`).
  - When `ARODONATA_MCP_ALLOW_WRITE_API=true` and a non-read-only command is passed to MCP `api_call`, execute it inside an isolated dedicated session (`async with client.write_session(...)` or `create_dedicated_session`) and cap `timeout` to `<= settings.task_timeout` (`W27`, `W28`).
  - In `ArodonataMCPSettings` (`src/arodonata/mcp/config.py`), split `entry` on `=` or `:` **only** when matching `^([A-Za-z_][A-Za-z0-9_-]*)[:=](.+)$` where the right-hand secret is at least 32 characters (and for `=`, only when the right-hand side is not pure `=` padding of a raw base64 token); enforce `len(secret) >= 32` across all static tokens; hash both expected and presented tokens with `hashlib.sha256` before `hmac.compare_digest`; and validate numeric ports (`1..65535`) on `host:*` wildcard patterns (`C3`, `I18`).
  - In `create_mcp_server` / `create_asgi_app` (`src/arodonata/mcp/server.py`), raise `ConfigurationError` when `auth_mode="jwt"` and `token_verifier is None`, log a prominent security warning (or reject unless explicitly opted in) when `auth_mode="none"` is bound to `0.0.0.0` or `allowed_hosts=["*"]`, and update `examples/12_mcp_embedded.py` to enforce bearer authentication middleware (`W26`).
- **Integration Harness Alignment (`W29`)**:
  - Update `pytest.sh` (`BUCKET_PAUSE_SECONDS="${BUCKET_PAUSE_SECONDS:-90}"`, add `-o log_cli=true --log-cli-level=INFO` to `INT_OPTS`).
  - Update `tests/integration/conftest.py` to read `ARODONATA_TEST_READY_WAIT`, write baselines to `_tmp/cp_baseline/baseline-<UTC>.json`, and call `pytest.exit(..., returncode=3|4|5)` for lock contention (`3`), readiness timeout (`4`), and baseline snapshot failure (`5`).
  - Update `REVERT_TIMEOUT_SECONDS = 900` in `tests/integration/_harness/cp_revision.py`.

## Risks / Trade-offs

- **[Risk] Renaming database tables to `arodonata_*` invalidates pre-existing local SQLite/PostgreSQL cache tables** -> **Mitigation**: All Arodonata tables are ephemeral caches/locks rebuildable from Check Point Management servers on first sync; `DatabaseManager.initialize()` automatically creates the new `arodonata_*` tables and cleans up fingerprinted legacy v1 tables.
- **[Risk] Raw base64 tokens with internal `=` characters in `ARODONATA_MCP_TOKENS`** -> **Mitigation**: Base64 alphabet uses `A-Z`, `a-z`, `0-9`, `+`, `/`, `-`, `_` with `=` occurring only as 1 or 2 trailing padding characters; requiring `client_id` to match `^[A-Za-z_][A-Za-z0-9_-]*$` AND the secret after `=` to be `>= 32` non-empty characters unambiguously distinguishes `client_id=secret` from `base64secret==`.
- **[Risk] Moving `refresh_domain_active_ip()` outside `LoginGate` allows two coroutines to trigger domain refresh concurrently on failover** -> **Mitigation**: `DomainService` / `LoginCoordinator` already deduplicates or serializes system-domain login via the system domain's own `LoginGate` entry without risking a recursive lock cycle.

## Migration Plan

1. Land transport, TLS, and secret-hygiene primitives first so all higher layers inherit command validation, phase-typed errors, and redaction.
2. Land `arodonata_*` table renames, fingerprinted v1 drop rules, serialized `DatabaseManager.initialize()`, and `SqlLockAdapter` renewal/server-clock updates.
3. Land `LoginCoordinator` HMAC `auth_identity` primary key, `LoginGate` rate-limiting and deadlock elimination, `RateLimiter` shielded cleanup, and `SessionCleaner` ownership guards.
4. Land `DomainSyncCoordinator` (`TaskGroup`, lock renewal, non-destructive lock contention), atomic `RulebaseRefreshService`/`ObjectService`/`ServiceCacheService` transactions, and `ON CONFLICT` upserts.
5. Land CPCRUD command allowlisting, server-stored/signed MCP plans, MCP static token parser fix, fail-closed JWT auth, and `pytest.sh` / `conftest.py` harness alignment, followed by the full adversarial unit test suite.
