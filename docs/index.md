# Arodonata

**A high-performance, async-first Python library for Check Point security
management operations with intelligent PostgreSQL caching and automatic
session handling.**

Arodonata wraps the Check Point Management API in an async engine backed by a
database cache layer, so scripts that would otherwise re-authenticate and
re-query thousands of objects on every run instead read from a fast local
cache and only pull incremental changes.

## Where to start

<div class="grid cards" markdown>

- **[Getting Started](getting-started/index.md)**
  Install the library, configure your `.env`, and run your first script.

- **[Core Architecture](architecture/index.md)**
  How the ports-and-adapters layering, caching, and session management fit
  together.

- **[Configuration Guide](configuration/index.md)**
  Every `ArodonataSettings` field, environment variable, and multi-server
  setup pattern.

- **[API Reference](api/)**
  Generated reference for every public class and function in `arodonata`.

- **[CPCRUD Engine](user-guide/cpcrud.md)**
  Declarative Policy-as-Code object and rule management with zero-mutation idempotency.

- **[Examples](examples/index.md)**
  Runnable, narrated scripts covering queries, search, refresh, CPCRUD, and
  production patterns.

</div>

## Why Arodonata?

- **High-concurrency execution** — fully asynchronous via `aiohttp`/`asyncio`.
- **Idempotent CPCRUD Policy-as-Code** — Plan-then-Execute engine with conflict resolution for objects & rules.
- **Zero-config session handling** — transparent authentication, session
  pooling, and auto-recovery on session expiry.
- **Intelligent DB caching** — PostgreSQL + SQLAlchemy, with JSONB storage.
- **Smart refresh (`show-changes`)** — pulls only incremental changes
  instead of rebuilding the cache from scratch.
- **Strict type safety** — Pydantic v2 models throughout.

See the [Changelog](CHANGELOG.md) for recent changes.
