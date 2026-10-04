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

The same engine backs the `smart-fast` cache mode used by read helpers for objects. Rule reads (`get_*_rules`) do not refresh objects: they use the rulebase sync state (see [Rulebase refresh](#rulebase-refresh)) and refresh only explicitly named domains, on the named management servers or, when none is named, on the first configured one (an application that omits the server is assumed to have one).

## Rulebase refresh

`refresh_rulebases` works per domain. It first reads the domain's last published session, refuses to continue while the shared API session holds unpublished changes or locks (`dirty session`, also with `force`), then reads `show-packages`, the NAT policy of every package with `nat-policy`, and every access, HTTPS and threat layer the packages, the layer listings and the rules' inline layers reach, each completely (pages of 100 with `from`/`to` continuity checked; empty trailing sections recovered). For a package whose global layer holds a place-holder, one more read of that global layer with `package` finds the parent rule and the domain layer nested under it. The domain's whole snapshot (rules, layers, sections, package layouts) and its sync state are then replaced in one transaction, so a domain is cached completely or not at all.

The sync state (`rulebase_sync_state`) records which published session the snapshot was built from, separately from the object cache's baseline. `mode='check'` and smart reads compare it with the domain's current last published session (session uid, publish time as fallback) and re-read only when it differs; `force` always re-reads. If the head cannot be read, `check` treats a domain that already has a usable snapshot (sync state `ok`, current format) as fresh and emits a warning; a domain without one is refreshed, and that refresh then fails on the unreadable head (or, with `force`, stores the snapshot unversioned so the next check re-reads it).

Failures keep the previous snapshot and mark the sync state `failed` with the error: a layer or listing error, an unreadable head (except with `force`), invalid credentials, or a dirty session. A command the server does not have (`generic_err_command_not_found`) leaves that rulebase type empty instead. A failed place-holder link is a warning: that package's place-holder is then numbered without the domain layer. Two refreshes of the same domain running at the same moment (for example a `refresh_rulebases` call and a smart read in another worker) can make the later commit fail on PostgreSQL with a duplicate key; that refresh then reports `domain_failed`, the snapshot written by the other one stays, and the next check refreshes normally.

Legacy rule getters (`get_*_rules`) read the same rows; place-holders are excluded. NAT rows keep the package name as `layer_name`. `sources`, `destinations` and `services` are stored as comma-joined names, so a name that itself contains a comma splits when the rule is read back; the exact values stay in `raw_data` with the layer's objects-dictionary.

Hierarchical numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, `2.3`, `No Rules`) are not stored: `arodonata.rulebase.numbering.number_package` computes them from a snapshot (`CacheRepository.load_domain_rulebase_snapshot`), exactly as SmartConsole shows them for a package.

## Request concurrency

The `RateLimiter` caps requests in flight per MDS member (`concurrent_limit`, `ARODONATA_CONCURRENT_LIMIT`, default 4), because Check Point serves every domain of a member from one API server. The cap is keyed like the login gate, on the member hosting the domain (the domain row's `active_mds_ip`, else the configured server IP); the request itself still goes to the domain server. Logins, keepalives, session cleanup, system-domain calls and explicit-SID calls (`api_call_with_sid(..., domain=...)`) take a slot on that member; a call without a domain looks the member up by the server IP. A listing (`api_query`) is paged by arodonata itself, one call per page (`asdk/pager.py`): each page takes a slot and releases it, so short calls get in between the pages of long listings. Waiters for a member are served in arrival order within one client, and a release wakes the longest waiter at once; other processes and other clients find a freed slot by polling. Pages hold 300 objects unless the caller sets `limit` (at most 500). Every page is checked against the previous one (`from`, `to`, `total`, repeated uids); a listing that changes under the cursor is read again once, then reported as failed (`paging_inconsistent`) instead of returning duplicates or gaps. A call that waits for a task (publish, revert) still holds its slot for the whole task. One `ensure` call refreshes at most `concurrent_limit − 1` (at least one) domains at once per member. A full refresh stores the last-published session read before its listing, so a publish during the listing is picked up by the next incremental refresh.

## Reading from the cache

Helper methods on `ArodonataClient` (`get_hosts`, `get_networks`, `get_groups`, `get_gateways`, `get_access_rules`, ...) always read from the cache — they never make a live API call (`get_domains` may re-read the domain list, see below). For lower-level, filterable access, [`CacheRepository`](../api/arodonata/cache/repository.md) exposes `get_objects()`, `get_objects_by_type()`, `get_objects_by_ip()`, and `get_rulebase()` directly.

`get_domains` refreshes only the domain list (one `show-domains` per management server), never the domains' objects: `cache_mode='cache'` reads the table as is, `smart`/`smart-fast` re-read the list when the table is empty or the domain-list TTL (one hour) has passed, and `force` re-reads it now. Without `mgmt_names` it reads every cached server and refreshes the first configured server's list. On first use, when a server's object cache is still empty, `get_domains` returns the list at once and starts loading every domain's objects in the background (once per server per client; `warm_object_cache_on_first_use`, on by default). Smart and smart-fast object reads of a domain being warmed wait for that domain's refresh instead of starting a second one (explicit `refresh_objects` or `search_objects(refresh='force')` calls are not coordinated and can reload the same domain in parallel; each domain is replaced atomically either way).

A scope's domains are refreshed concurrently: at most `concurrent_limit − 1` (at least one) domains at once per MDS member in one `ensure` call, members in parallel (the cap is per call in one process; see Request concurrency), so a multi-domain server warms several times faster than one domain after another. Each domain is still replaced atomically; the swaps of one client run one at a time, and SQLite connections wait up to 30 s for a busy database (instead of SQLite's default 5 s, unless the engine sets its own timeout) so concurrent refreshes and several processes on one file wait instead of failing with `database is locked`. If a domain fails, the others still run to the end and the first exception is then re-raised.

`close()` cancels a running warm-up at once. `ArodonataClient.object_cache_warm_up(mgmt_name)` reports it (`ObjectCacheWarmUp`: `running`, `finished`, `failed` or `cancelled`, with the refreshed and failed domain counts once it ended); MCP `arodonata_init` shows it per server.

The rulebase facade (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`) reads the `rulebase_*` snapshots through `CachedRulebaseSource`, after refreshing the domain session-aware per `cache_mode`. A domain is ready when it has a sync state at the current cache format; a domain whose refreshes only ever failed is not ready, and the not-ready error names the last refresh error. A domain whose last refresh failed is served from its last good snapshot, with `status` and `last_error` set. Numbers reflect the snapshot's published session (`snapshot_session_uid`, published at `snapshot_published_at`), not necessarily an older session a caller is asking about.
