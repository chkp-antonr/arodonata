# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are generated from [Conventional Commits](https://www.conventionalcommits.org/)
via [commitizen](https://commitizen-tools.github.io/commitizen/) — do not
hand-edit released sections, only the `[Unreleased]` section above them.

## v1.10.0 (2026-09-21)

### Feat

- audit hardening, search service, and login rate-limiting resilience (#5)
- pace logins per Multi-Domain Server member (#4)

### Fix

- **cache**: satisfy mypy on the login-gate additions

## v1.9.0 (2026-09-14)

### Feat

- **asdk**: long-running Check Point tasks (`publish`, `revert-to-revision`, `install-policy`, `run-script`) are now polled by the library instead of by cpapi. `ApiTransport.api_call` always calls cpapi with `wait_for_task=False` and runs the `show-task` loop itself through the new `TaskWaiter`, so every poll is logged, OTel-spanned and covered by the rate-limiter slot the enclosing call already holds — previously a ten-minute revert was ~300 API calls this library could not see, rate-limit or trace. The poll interval backs off from 2 s to a 10 s ceiling instead of cpapi's flat 2 s (~70 polls for that revert instead of ~300), five consecutive poll failures are tolerated as cpapi did, and a wait that exceeds its budget raises `TaskTimeoutError` naming the task-id, its last status, its progress and the elapsed time, where cpapi raised a bare `TimeoutError` with no message at all. Backwards compatible by design: `TaskTimeoutError` subclasses `TimeoutError` so existing handlers still catch it; a `failed` or `partially succeeded` task still yields `success=False` on the returned response and still raises nothing; the returned response is still the final `show-task` result with the same `data`, `message` and `code`; and `wait_for_task=False`, non-task commands and `show-task` itself are untouched paths. One deliberate difference from cpapi: a task status that is neither `succeeded` nor a recognized failure now yields `success=False` rather than being reported as a success. New public names `TaskWaiter`, `TaskStatus`, `TaskTimeoutError` and `TaskPollError` are additive; `arodonata.config` gained `DEFAULT_TASK_POLL_INITIAL_SECONDS`, `DEFAULT_TASK_POLL_MAX_SECONDS` and `DEFAULT_TASK_POLL_FAILURE_TOLERANCE`.
- **cache**: `RefreshOutcome.failed_domains` records the `(mgmt, domain)` pairs whose reload failed, so callers can distinguish a domain that was already fresh from one the refresh failed to repair — previously both were simply absent from `refreshed_domains`. Additive and defaults to empty; existing callers are unaffected.

### Fix

- **cache**: an incremental (`smart-fast`) refresh now refuses to apply a diff when the domain's history has not moved forward, and reloads the domain in full instead. A `revert-to-revision` moves a domain's head *backwards* and discards the sessions in between, so the objects it restores were deleted in sessions that no longer exist and the ones it removes were added in sessions that no longer exist — no forward change list can describe that, and applying one leaves objects the revert removed sitting in the cache while ones it restored go missing. Previously the full reload after a revert happened only because Check Point refused the `show-changes` call and every failure became a fallback: the right outcome by luck, dependent on server-side behaviour, and absent entirely from the bulk `mode="incremental"` path, which had no guard of its own. `IncrementalRefresher` now compares the domain's current head against the cached baseline before fetching any diff, via a new read-only `ObjectService.fetch_last_published_session()` (the existing `refresh_last_published_session()` would have advanced the baseline and emptied the diff window). Only a head that is strictly *earlier* than the baseline counts as reverted: Check Point publish-times have minute resolution, so requiring the head to be strictly later made every prompt publish-then-read fall back to a full reload. The residual gap — reverting to a revision published inside the same minute as the baseline — still relies on the `show-changes` failure path, and closing it properly means diffing by `from-session` rather than `from-date`.
- **asdk**: a login that gets no answer no longer hammers the same address. `LoginCoordinator` now classifies a login failure three ways: a *refusal* (the server answered — throttling, or Check Point's `Database revision is in progress` after a revert) keeps its existing retry-with-backoff against the same address, because that is what clears a lockout; a *timeout* is retried for the full budget, because a slow server and a dead one look identical until one of them answers; and an *unreachable* address (refused or unroutable socket, or Check Point's own `Unable to connect to server...`) stops at once. When a login does stop — on conclusive evidence, or after every attempt timed out — the cached SID is dropped, the domain's active server is re-resolved via `show-domains`, and the login is retried there. If the domain has not moved, it fails with an `AuthenticationError` naming the address that went silent, rather than the empty `TimeoutError` it used to be. This closes a gap in failover handling: `FAILOVER_ERROR_CODES` only ever fired on a *response code*, so a domain server that simply stopped answering could never trigger the domain-IP refresh that the cached `active_ip` exists to support. New `ServerUnreachableError` (an `ApiConnectionError`) is exported for callers who want the distinction; login failures still surface as `AuthenticationError`, so existing handlers are unchanged. The marker string is exported as `arodonata.config.SERVER_UNREACHABLE_MESSAGE`, and the wait a throttled login sits out is `ArodonataSettings.login_throttle_window` (`ARODONATA_LOGIN_THROTTLE_WINDOW`, default 70 s) — the limit is server-side configuration rather than a universal constant, and a caller that knows it will not meet a real lockout should not be made to wait one out.
- **asdk**: a login attempt now has its own per-attempt budget, `ArodonataSettings.login_timeout` (`ARODONATA_LOGIN_TIMEOUT`, default `DEFAULT_LOGIN_TIMEOUT` = 120 s), instead of silently inheriting the transport's API default. `LoginCoordinator` never passed a timeout at all, so there was no way to tune a login independently of ordinary API work — a deployment whose servers answer quickly can now lower it without touching `api_timeout`. The default deliberately matches the old inherited value: a domain-server login on a loaded MDS legitimately takes longer than a minute, and a tighter budget fails servers that are merely slow. The transport's `LOGIN ... TIMEOUT` log lines now state the budget they exhausted instead of printing `asyncio.wait_for`'s empty message.
- **cache**: rejected credentials during the domain staleness probe now report the domain as stale and log at `error` level, instead of falling through the generic fail-open handler and reporting it fresh. Unlike a transient probe error, a bad password or API key recurs on every tick and the nightly force job cannot repair it either, so it is now routed into the reload path where it surfaces as a countable `domain_failed` event. The handler catches `InvalidCredentialsError` only — transient login refusals such as Check Point's `Database revision is in progress` (a plain `AuthenticationError`) and every other probe failure keep the existing fail-open behaviour.
- **asdk**: `LoginCoordinator` now raises `InvalidCredentialsError` (an existing, previously unused subclass of `AuthenticationError`) when Check Point rejects the password or API key, and plain `AuthenticationError` for every other login refusal, so callers can distinguish a permanent credential problem from a transient one by type instead of by matching on message text. The marker string is exported as `arodonata.config.CREDENTIAL_REJECTION_MESSAGE`. Backwards compatible: existing `except AuthenticationError` handlers still catch the subclass.
- **asdk**: `RateLimiter.acquire()` is now a true semaphore over its `concurrent_limit` slots — it starts at the hashed slot but takes any free one, and only waits (up to `slot_timeout`) when every slot is busy. Previously each task was pinned to a single hashed slot with no fallback, so a login could starve for the full 90 s behind one long-running call on that slot while the other slots sat idle; observed in integration as `LockAcquisitionError: ratelimit:<ip>:slot_2` during rapid logout/login cycles. `DatabaseLockManager` gained the non-blocking `try_acquire_lock()` this requires.
- **asdk**: overlapping keepalive sweeps (`LoginCoordinator.maintain_keepalives`) now coalesce — a sweep that finds one already in flight returns immediately instead of launching another swarm of slot-holding keepalive tasks. Previously every `api_call` fired its own sweep, so a burst of calls against a throttled server multiplied rate-limiter contention.
- **tests**: every integration revert now routes through one helper carrying the 900 s `REVERT_TIMEOUT_SECONDS`, instead of individual call sites using the client's default API timeout; a unit test enforces that no integration test issues `revert-to-revision` directly.

## v1.8.0 (2026-09-04)

### Feat

- **cpcrud**: resolve NAT sentinel UIDs at runtime, cached per management server
- **cpcrud**: export NAT_ANY_OBJECT_UID for reuse by external consumers
- **domains**: opt-in include_global on domain readers and refresh paths
- **domains**: write an explicit Global domain row on multi-domain managers

### Fix

- NAT translated-* writes use the Original UID; domain list re-fetch gap
- backfill Global domain row on already-provisioned MDMs, gate on positive MDM detection

### Docs

- Added `docs/scripts/build_notebooklm_docs.py`, generating a three-file `docs-notebooklm/` bundle (concepts/guide, full API reference auto-extracted from source via `ast`, and examples with resolved snippets) sized for upload to NotebookLM or similar AI document-chat tools.
- Documented CPCRUD's section/layer-relative rule positioning (`docs/user-guide/cpcrud.md`), including cleanup-rule-aware `bottom` placement for access/HTTPS/threat-prevention layers.

## v1.7.0 (2026-08-21)

### Feat

- incremental refresh mode with show-changes diff and full object re-fetch

## v1.6.0 (2026-08-19)

### Feat

- **cache**: atomic replace_domain_objects (single-transaction delete+insert)
- **helpers**: rule getters accept and propagate cache_mode/cache_ttl
- Initial public release as **Arodonata** — renamed from the previously-internal `cpaiops` project, with a consistent identifier rename throughout (`ArodonataClient`/`ArodonataSettings`, `ARODONATA_*` environment variables, `arodonata.*` OpenTelemetry span namespace).
- Added `examples/08_otel_smart_refresh.py`, demonstrating how a standalone script wires up OpenTelemetry tracing itself via `arlogi.otel.setup_tracing()` and printing a per-span timing breakdown.

### Fix

- **cache**: collect-then-swap domain refresh; abort on partial failure without touching cache or freshness stamp
- **client**: get_gateways inner orchestration reads bypass object-cache coordinator as documented
- **helpers**: get_gateways no longer triggers object-cache coordinator
- reclaim stale read-write sessions with pending changes, configurable rate-limit slot timeout
- `client.cpcrud.apply()`'s outcome summary now correctly reports a `reuse` outcome for auto-created dependencies (e.g. an implicitly-created service referenced by an access rule) that already exist on re-apply, instead of omitting them.

### Docs

- Corrected the CPCRUD operation-type reference table (`docs/user-guide/cpcrud.md`) and the CPCRUD settings defaults (`docs/configuration/index.md`) to match the actual schema and code.
- Added narrated example pages for `07_crud_inverse.py`, `07_session_basics.py`, and `08_otel_smart_refresh.py`.
