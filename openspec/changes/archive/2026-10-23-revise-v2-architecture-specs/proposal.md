# Proposal: Arodonata v2 Clean-Slate Architecture & Specification Revision

## Why

The initial 9 specifications in `openspec/specs/` were extracted directly from Arodonata v1, preserving hard-won Check Point domain invariants alongside v1 architectural debt: synchronous `cpapi` transport wrapped in threads, leaky `SSEEvent` primitives inside core domain services, fragmented synchronization pipelines and state tables (`last_published_sessions` vs `rulebase_sync_state`), double cache adapter layers (`PostgresCacheAdapter` + `CacheRepository`), rigid startup authentication assumptions, and duplicated facade helpers (`arodonata.helpers`). Before implementing `src/arodonata/` for v2, we must revise the specifications to establish clean hexagonal boundaries, native `asyncio` transport, unified domain synchronization, selective object/service caching, and context-propagated write sessions with read-your-own-writes overlays.

## What Changes

- **BREAKING**: Replace synchronous `cp-mgmt-api-sdk` (`cpapi`) with a native `asyncio` HTTP transport (`aiohttp`) featuring pre-request TLS SHA-256 fingerprint verification on the socket, read-only keep-alive connection pooling (`VerifiedConnectionPool`), and strict prohibition of automatic request re-sends on any socket error or timeout.
- **BREAKING**: Restructure package boundaries (`core`, `adapters/checkpoint`, `adapters/storage`, `adapters/sse`, `rulebase`, `cpcrud`, `reports`, `mcp`) and split optional dependencies into `arodonata` (base with `aiosqlite`), `arodonata[postgres]` (`asyncpg`), and `arodonata[mcp]` (`mcp`, `starlette`, `uvicorn`).
- **BREAKING**: Remove `SSEEvent` from core domain services and replace async-generator-only entry points with a uniform paired contract: `await client.<op>(...)` returning a typed final result model, and `async for event in client.stream_<op>(...)` yielding typed domain progress events (with `arodonata.adapters.sse` converting domain events to SSE at the HTTP boundary).
- **BREAKING**: Rename `PostgresCacheAdapter` to `SqlCacheAdapter` and eliminate the redundant `CacheRepository` wrapper layer.
- **BREAKING**: Standardize cache freshness modes to a single canonical set (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`), removing duplicate alias sets (`"skip"`, `"check"`, `"incremental"`).
- **BREAKING**: Consolidate `arodonata.helpers` into `ArodonataClient` and remove the implicit background object-cache warm-up side effect from `get_domains()` in favor of explicit warm-up invocation.
- Unify domain synchronization across scopes (`"domains"`, `"objects"`, `"services"`, `"assets"`, `"rulebase"`) under a single `domain_sync_state` table, a shared MDS-member-bounded concurrent driver (`max(1, concurrent_limit - 1)` per `active_mds_ip`), and per-domain distributed locks during database swaps.
- Introduce a dedicated `arodonata_services` (`CPService`) cache table and `refresh_services(types=...)` / `stream_refresh_services(types=...)` alongside `arodonata_objects` (`CPObject`), defaulting to mutable core types (`("host", "network", "address-range", "group", "dns-domain")` for objects; `("service-tcp", "service-udp", "service-icmp", "service-group")` for services) with explicit opt-in for heavy/static types.
- Support static (`api_key` or `credential`), hybrid (shared read-only `api_key` + per-admin write credentials), and dynamic/deferred authentication (cold startup without static credentials, resolving admin credentials via `contextvars` `AuthContext` or `AuthProvider`).
- Enforce read-only usage on the shared `sid_cache` pool (evicting SIDs immediately on rejected keepalive) and route all mutations through isolated `WriteSession` context managers (`async with client.write_session(...)`) tracked via `contextvars`, providing an in-memory `SessionOverlay` so read methods (`get_hosts()`, `get_services()`, etc.) reflect uncommitted session creations, updates, and deletions prior to publish.
- Consolidate all MCP-specific tooling and LLM ergonomics (`describe_objects`, `query_objects`, `cache_status`, domain pre-validation, local cached rulebase filtering, and model-friendly auth error mapping) into `mcp-server`.

## Capabilities

### New Capabilities

<!-- None: all changes refine and restructure the 9 existing capability domains. -->

### Modified Capabilities

- `configuration`: Support static, hybrid, and deferred/dynamic authentication modes; default `engine=None` to an auto-owned in-memory SQLite engine across all modes; unify `API_KEYS` and `API_KEY_VARS` resolution.
- `transport-and-tls`: Replace `cpapi` with native `aiohttp` transport, add `VerifiedConnectionPool` for read-only `show-*` calls, and prohibit request re-send on `ConnectionResetError` / `BrokenPipeError` as well as read timeouts.
- `sessions-and-mdm`: Enforce read-only shared `sid_cache` (with immediate eviction on failed keepalive), add `AuthContext` / `AuthProvider` support for hybrid and dynamic admin authentication, and specify `contextvars`-bound `WriteSession` with `SessionOverlay` for read-your-own-writes isolation.
- `cache-and-sync`: Replace `PostgresCacheAdapter`/`CacheRepository` with `SqlCacheAdapter`, add `arodonata_services` and `dns-domain` support with selective type syncing, unify `domain_sync_state` and member-bounded locked refresh across objects/services/assets/rulebase, standardize `CacheMode` names, and replace core `SSEEvent` yields with paired coroutine + `stream_*` domain event APIs.
- `rulebase-and-numbering`: Integrate rulebase snapshot refresh with unified `domain_sync_state` (`scope="rulebase"`), per-domain distributed locks, paired `refresh_rulebases` / `stream_refresh_rulebases` methods, and local cache-backed rule filtering.
- `client-and-facade`: Merge `arodonata.helpers` into `ArodonataClient`, remove implicit warm-up from `get_domains()`, wire `contextvars` `WriteSession` overlay into read/write facade methods, and move `SSEEvent` formatting to `adapters/sse`.
- `cpcrud`: Integrate `HybridStateReader` and `Executor` with `arodonata_services` and `WriteSession` overlay, and provide paired `apply()` / `stream_apply()` returning `ApplyReport` and `CPCRUDEvent` items.
- `mcp-server`: Isolate MCP dependencies under `arodonata[mcp]` and add structured `describe_objects` / `query_objects` aggregation, `cache_status`, pre-login domain validation, model-facing `InvalidCredentialsError` diagnostics, and cache-first rulebase filtering.

## Impact

- **Specifications**: Updates 8 of the 9 canonical specs under `openspec/specs/`.
- **Dependencies (`pyproject.toml`)**: Removes `cp-mgmt-api-sdk`; keeps base installation lightweight (`aiohttp`, `aiosqlite`, `sqlalchemy[asyncio]`, `sqlmodel`, `pydantic`, `pydantic-settings`, `jsonschema`, `pyyaml`, `arlogi`, `opentelemetry-api`) and defines optional extras `postgres` (`asyncpg`), `mcp` (`mcp`, `starlette`, `uvicorn`), and `all`.
- **Source Architecture (`src/arodonata/`)**: Establishes the clean v2 package layout (`core/`, `adapters/checkpoint/`, `adapters/storage/`, `adapters/sse/`, `rulebase/`, `cpcrud/`, `reports/`, `mcp/`, `client.py`).
