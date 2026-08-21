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

## Refresh modes

`refresh_objects()` takes a `mode` selecting how much work a refresh does
([`RefreshMode`](../api/arodonata/core/protocols.md)):

- **`skip`** — use the cache as-is, no API calls.
- **`check`** — probe each domain's `show-last-published-session` (session
  *uid* comparison; stored per domain in the `last_published_sessions`
  table) and fully reload only stale domains, via one atomic
  collect-then-swap transaction per domain.
- **`force`** — full atomic reload of every domain, unconditionally.
- **`incremental`** — same staleness probe as `check`, but a stale domain is
  caught up from Check Point's `show-changes` diff
  ([`change_processor.py`](../api/arodonata/core/change_processor.md),
  [`incremental_refresh.py`](../api/arodonata/core/incremental_refresh.md)):
  the diff is used only as a *change list* — every added or modified object
  is re-fetched in full (`show-object`, `details-level: full`) and converted
  by the same converter as a full reload, so its cache row is
  field-identical to what `force` would produce. Deletes are applied
  directly. Any unsafe condition (no baseline, truncated diff, more changes
  than the configurable cap — `ArodonataClient(max_incremental_changes=…)`,
  default 500 — parse anomalies, re-fetch failures) falls back to the atomic
  full reload. Only changes to cached object kinds (hosts, networks, address
  ranges, groups) are applied; a rules-only publish just advances the
  freshness baseline.

The same engine backs the `smart-fast` cache mode used by read helpers.

## Reading from the cache

Helper methods on `ArodonataClient` (`get_hosts`, `get_networks`, `get_groups`,
`get_domains`, `get_gateways`, `get_access_rules`, ...) always read from the
cache — they never make a live API call. For lower-level, filterable access,
[`CacheRepository`](../api/arodonata/cache/repository.md) exposes
`get_objects()`, `get_objects_by_type()`, `get_objects_by_ip()`, and
`get_rulebase()` directly.
