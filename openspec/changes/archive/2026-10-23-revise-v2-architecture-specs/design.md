# Design: Arodonata v2 Clean-Slate Hexagonal Architecture

## Context

See `proposal.md` for motivation. Arodonata v2 is being built from a clean slate in `src/arodonata/` targeting Python 3.13+. While the v1 specifications in `openspec/specs/` capture essential Check Point Management API behaviors (certificate fingerprint verification, MDS member login rate-limiting, continuity-verified pagination, SmartConsole rule numbering, idempotent CPCRUD, and auditable change reports), they also carry v1 structural coupling that must be resolved before writing code.

## Goals / Non-Goals

**Goals:**

- Establish a strict Hexagonal (Ports & Adapters) package layout where `core` has zero imports from `aiohttp`, `sqlalchemy`, `sqlmodel`, or `mcp`.
- Replace synchronous `cp-mgmt-api-sdk` (`cpapi`) with a native `asyncio` HTTP transport (`aiohttp`) that verifies TLS SHA-256 certificate fingerprints before sending HTTP request bytes and pools verified connections for read-only calls.
- Provide a zero-boilerplate minimalist entry point (`AMgmtClient` and `ArodonataClient` defaulting `engine=None` to an auto-owned `sqlite+aiosqlite:///:memory:` engine) alongside full PostgreSQL (`arodonata[postgres]`) and MCP (`arodonata[mcp]`) deployments.
- Unify domain synchronization across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` using a single `domain_sync_state` table, per-MDS-member concurrency bounds, and per-domain distributed locks.
- Separate cached network objects (`arodonata_objects`) and services (`arodonata_services`) with selective default type sets so large static Check Point catalogs (such as built-in applications) are never fetched by default.
- Support static, hybrid (shared read-only `api_key` + per-admin write credentials), and dynamic/deferred authentication (cold startup without static credentials) via `contextvars`.
- Provide isolated `WriteSession` context managers (`async with client.write_session(...)`) with an in-memory `SessionOverlay` propagated via `contextvars` so read calls (`get_hosts()`, `get_services()`, etc.) reflect uncommitted creations, updates, and deletions within that session.
- Replace `SSEEvent` generators in core services with a uniform paired API: `await client.<op>(...)` returning a final result model and `async for ev in client.stream_<op>(...)` yielding typed domain progress events.

**Non-Goals:**

- Maintaining backwards-compatible v1 aliases (`PostgresCacheAdapter`, `arodonata.helpers`, `skip`/`check`/`incremental` mode aliases, or implicit `get_domains()` background warm-up).
- Caching all Check Point `generic-object` classes in a general-purpose SQL table (`generic-object` queries remain encapsulated inside high-level topology services such as VSX relationship resolution).

## Decisions

### 1. Package Decomposition & Optional Extras

```text
src/arodonata/
├── core/                  # Pure domain & ports (no transport/ORM/ASGI imports)
│   ├── config.py          # ArodonataSettings, server topology, timeout budgets
│   ├── context.py         # ContextVars for AuthContext, UserContext, and active WriteSession
│   ├── errors.py          # Domain, transport, and auth exception hierarchy
│   ├── events.py          # Typed domain progress events (SyncProgressEvent, CPCRUDEvent)
│   ├── telemetry.py       # @traced, span_attrs, secret/SID redaction
│   ├── models/            # Pydantic v2 domain models (objects, services, assets, sessions)
│   ├── ports/             # Protocols: ApiPort, CachePort, LockPort
│   └── services/          # DomainService, ObjectService, ServiceCacheService, AssetRefreshService, SearchService, DomainSyncCoordinator
├── adapters/
│   ├── checkpoint/        # Native aiohttp transport, TrustPolicy, VerifiedConnectionPool, TaskWaiter, LoginCoordinator, RateLimiter, Pager, AMgmtClient
│   ├── storage/           # DatabaseManager, SqlCacheAdapter, SqlLockAdapter, SQLModel tables
│   └── sse/               # SSEEvent model and converter from core domain events
├── rulebase/              # Rulebase pager, snapshot refresh, SmartConsole numbering, local filter
├── cpcrud/                # Schema validation, Planner, HybridStateReader, Executor, Differ, Inverse
├── reports/               # Auditable ChangeReport collector, placement numbering, HTML/MD/JSON renderers
├── mcp/                   # Optional MCP server (CLI + ASGI app, cached/live/aggregate/cpcrud tools)
└── client.py              # ArodonataClient composition root and unified facade
```

- **Rationale**: Keeps `core` pure and testable with in-memory fakes while allowing applications that only need raw API transport (`AMgmtClient`) to run without warming object caches. Lazy module imports in `src/arodonata/__init__.py` ensure unused modules (`cpcrud`, `reports`, `mcp`) are not loaded into memory unless imported.

### 2. Native `aiohttp` Transport & Pre-Request TLS Verification

- **Choice**: Drop `cp-mgmt-api-sdk` (`cpapi`) and implement `ApiTransport` directly on `aiohttp` targeting `POST https://<host>:<port>/web_api/<command>`.
- **TLS Identity Check**: A custom `aiohttp.TCPConnector` subclass inspects `transport.get_extra_info("ssl_object").getpeercert(binary_form=True)` immediately after the TLS handshake completes and verifies the SHA-256 fingerprint against `TrustPolicy` (`pinned`, `tofu`, `lab-memory`) **before** any HTTP request line, headers (`X-chkp-sid`), or payload bytes are written to the socket.
- **Connection Reuse (`VerifiedConnectionPool`)**: Read-only `show-*` commands reuse verified keep-alive connections for up to 10 seconds idle (staying safely under Check Point CPWS's 15-second idle close and 101-request cap). Mutating commands, logins, logouts, keepalives, publish, and discard always use a fresh connection.
- **No Silent Re-send**: The transport disables `aiohttp` auto-retry after request bytes are written so neither `ReadTimeout` nor `ConnectionResetError` / `BrokenPipeError` can trigger a duplicate write on the management server.

### 3. Unified `DomainSyncCoordinator` & Selective Object/Service Tables

- **Choice**: Replace `last_published_sessions` and `rulebase_sync_state` with a single `domain_sync_state` table keyed by `id = "{mgmt_name}:{domain_name}:{scope}:{item_type}"` where `scope` is `"domains" | "objects" | "services" | "assets" | "rulebase"` and `item_type` is the specific object/service type (e.g., `"host"`, `"network"`, `"dns-domain"`, `"service-tcp"`, `"service-other"`) or `"*"` for whole-domain scopes (`"domains"`, `"assets"`, `"rulebase"`).
- **Timestamps & Revision Check**: Each `domain_sync_state` row stores both `last_published_at` (the Check Point session's `publish-time`), `last_session_uid` (disambiguating multiple publishes within the same minute), and `synced_at` (when the local cache slice was last refreshed/verified, used for `cache_ttl` and MCP `cache_age_seconds`). Staleness checks compare `last_published_at` first and verify `last_session_uid` when timestamps match.
- **Selective Tables & Type-Scoped Replacement**:
  - `arodonata_objects` (`CPObject`) stores network objects; `refresh_objects` defaults to `types=("host", "network", "address-range", "group", "dns-domain")`.
  - `arodonata_services` (`CPService`) stores service objects (`port`, `protocol`, `icmp_type`, `icmp_code`, `members`, `session_timeout`, `match_for_any`, `raw_data`); `refresh_services` defaults to `types=("service-tcp", "service-udp", "service-icmp", "service-group")`.
  - Callers may pass explicit `types=[...]` to sync additional types on demand without bloating default refreshes with tens of thousands of static built-in objects. Database replacements are scoped by `(mgmt_name, domain_name, type IN refreshed_types)` so refreshing a subset of types never deletes other cached types in that domain.
- **Concurrency & Locking**: `DomainSyncCoordinator` groups target domains by `active_mds_ip`, runs up to `max(1, concurrent_limit - 1)` domains concurrently per MDS member (members in parallel), verifies that the shared read session is not dirty (`locks == 0` and `number-of-published-changes == 0`), and acquires a per-domain distributed lock (`sync:{mgmt_name}:{domain_name}:{scope}`) via `SqlLockAdapter` before replacing rows in the database.

### 4. Static, Hybrid, and Dynamic Authentication with `WriteSession` Overlay

- **Choice**:
  - `sid_cache` is strictly for shared read-only sessions. If a `keepalive` returns `success=False`, the SID is evicted from `sid_cache` immediately.
  - `ArodonataClient` can start without static credentials (`auth_mode="dynamic"`), deferring session acquisition until credentials are provided via `with client.auth_context(username=..., password=...):` (`contextvars`) or an injected `AuthProvider`.
  - Mutations always execute inside an isolated `WriteSession` (`async with client.write_session(mgmt_name, domain, auth=...) as ws:`), which binds itself to a `ContextVar`.
  - Every `add-*` / `set-*` / `delete-*` operation executed within the `WriteSession` updates `ws.overlay` (`SessionOverlay`: `upserted` models + `deleted` UID tombstones). Read calls (`client.get_hosts()`, `client.get_services()`, etc.) inside the same `contextvars` context automatically merge `ws.overlay` over the database cache so uncommitted changes are visible immediately to that session and invisible to other concurrent sessions.

### 5. Paired Coroutine and Streaming APIs

- **Choice**: Every multi-step operation (`refresh_objects`, `refresh_services`, `refresh_assets`, `refresh_rulebases`, `cpcrud.apply`) exposes two methods:
  - `await client.refresh_objects(...) -> RefreshOutcome`
  - `async for event in client.stream_refresh_objects(...) -> AsyncIterator[SyncProgressEvent]`
- **Rationale**: Eliminates `SSEEvent` from `core` while giving both simple callers (`await`) and streaming UIs (`async for`) a predictable, ergonomic API.

## Risks / Trade-offs

- **[Risk] Custom `aiohttp` connector TLS inspection across Python 3.13+ event loops** → Mitigation: Extract the post-handshake `ssl_object.getpeercert(binary_form=True)` check into a dedicated helper tested against both real local TLS sockets and fake transports before any request payload is serialized.
- **[Risk] Stale admin credentials in Dynamic Auth mode when an admin changes their password** → Mitigation: On `InvalidCredentialsError`, immediately evict any cached session associated with that user, notify the optional `AuthProvider.on_auth_failed(user)`, and fail fast without burning login retry loops.
- **[Risk] Memory footprint of `SessionOverlay` on massive bulk writes** → Mitigation: `SessionOverlay` stores only the delta (`upserted` and `deleted` objects created/modified within that single `WriteSession`) and is discarded immediately upon `publish` or `discard`.

## Migration Plan

1. Update the 8 modified capability specifications via this OpenSpec change (`revise-v2-architecture-specs`) and sync them into `openspec/specs/`.
2. Update `pyproject.toml` extras (`postgres`, `mcp`, `all`).
3. Implement `src/arodonata/` in layered milestones (`core` & `storage` -> `checkpoint` native transport & sessions -> `sync` & `search` -> `rulebase` & `reports` -> `cpcrud` -> `mcp`).
