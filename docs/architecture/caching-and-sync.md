# Caching & Sync

## Why cache at all

Check Point management servers rate-limit and are slow to re-authenticate;
Arodonata avoids repeating full `show-*` queries by storing objects, gateways,
domains, and rulebases in PostgreSQL (`src/arodonata/cache/`) as JSONB-backed
rows via [`CacheRepository`](../api/arodonata/cache/repository.md).

## Populating the cache

- [`ArodonataClient.build_refresh_assets_cache()`](../api/arodonata/api/client.md)
  — full refresh of domains and gateways.
- [`ArodonataClient.refresh_objects()`](../api/arodonata/api/client.md) — refresh
  of hosts, networks, groups, and address ranges.
- [`ArodonataClient.refresh_rulebases()`](../api/arodonata/api/client.md) —
  refresh of access/NAT/HTTPS/threat rulebases.

Each of these is an async generator yielding `SSEEvent` progress updates
(`src/arodonata/api/schemas.py`), so a caller can stream progress to a UI or
log line-by-line instead of blocking until completion.

## Smart refresh (`show-changes`)

Rather than re-pulling every object on every refresh, Arodonata tracks the last
processed session per management server/domain
([`session_tracker.py`](../api/arodonata/core/session_tracker.md)) and uses
Check Point's `show-changes` API to pull only what changed since then
([`change_processor.py`](../api/arodonata/core/change_processor.md)). This is
what the [`RefreshMode`](../api/arodonata/core/protocols.md) enum's incremental
modes select between a full rebuild and an incremental catch-up (`SKIP` uses
the cache as-is with no API calls at all).

## Reading from the cache

Helper methods on `ArodonataClient` (`get_hosts`, `get_networks`, `get_groups`,
`get_domains`, `get_gateways`, `get_access_rules`, ...) always read from the
cache — they never make a live API call. For lower-level, filterable access,
[`CacheRepository`](../api/arodonata/cache/repository.md) exposes
`get_objects()`, `get_objects_by_type()`, `get_objects_by_ip()`, and
`get_rulebase()` directly.
