# Ports & Adapters

## Facades

- **[`ArodonataClient`](../api/arodonata/api/client.md)**
  (`src/arodonata/api/client.py`) — the main developer entry point. Wraps
  caching, rate limiting, and session management behind helper methods like
  `get_hosts()`, `get_networks()`, `get_access_rules()`.
- **[`AMgmtClient`](../api/arodonata/asdk/client.md)** (`src/arodonata/asdk/`) —
  the lower-level session-oriented client: login, keepalive, and raw
  `api-query`/`show-*` calls against a single management server.

## Ports

Defined in `src/arodonata/ports/`:

- **[`ApiPort`](../api/arodonata/ports/api_port.md)** — the interface the core
  framework calls to talk to *some* Check Point management API — real or
  mocked.
- **[`CachePort`](../api/arodonata/ports/cache_port.md)** — the interface for
  reading/writing cached objects, independent of the storage engine.

## Adapters

Defined in `src/arodonata/adapters/`:

- **[`asdk_adapter`](../api/arodonata/adapters/api/asdk_adapter.md)**
  (`adapters/api/asdk_adapter.py`) — implements `ApiPort` on top of
  `AMgmtClient`.
- **[`postgres_adapter`](../api/arodonata/adapters/cache/postgres_adapter.md)**
  (`adapters/cache/postgres_adapter.py`) — implements `CachePort` on top of
  SQLAlchemy async sessions against PostgreSQL.

Because `arodonata.core` and `arodonata.api` depend only on the port protocols,
swapping the cache backend or mocking the management API for tests (see
`tests/mock_api/`) never requires touching business logic.
