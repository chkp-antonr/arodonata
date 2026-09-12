# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are generated from [Conventional Commits](https://www.conventionalcommits.org/)
via [commitizen](https://commitizen-tools.github.io/commitizen/) — do not
hand-edit released sections, only the `[Unreleased]` section above them.

## [Unreleased]

### Feat

- **cache**: `RefreshOutcome.failed_domains` records the `(mgmt, domain)` pairs whose reload failed, so callers can distinguish a domain that was already fresh from one the refresh failed to repair — previously both were simply absent from `refreshed_domains`. Additive and defaults to empty; existing callers are unaffected.

### Fix

- **cache**: rejected credentials during the domain staleness probe now report the domain as stale and log at `error` level, instead of falling through the generic fail-open handler and reporting it fresh. Unlike a transient probe error, a bad password or API key recurs on every tick and the nightly force job cannot repair it either, so it is now routed into the reload path where it surfaces as a countable `domain_failed` event. The handler catches `InvalidCredentialsError` only — transient login refusals such as Check Point's `Database revision is in progress` (a plain `AuthenticationError`) and every other probe failure keep the existing fail-open behaviour.
- **asdk**: `LoginCoordinator` now raises `InvalidCredentialsError` (an existing, previously unused subclass of `AuthenticationError`) when Check Point rejects the password or API key, and plain `AuthenticationError` for every other login refusal, so callers can distinguish a permanent credential problem from a transient one by type instead of by matching on message text. The marker string is exported as `arodonata.config.CREDENTIAL_REJECTION_MESSAGE`. Backwards compatible: existing `except AuthenticationError` handlers still catch the subclass.
- **asdk**: `RateLimiter.acquire()` is now a true semaphore over its `concurrent_limit` slots — it starts at the hashed slot but takes any free one, and only waits (up to `slot_timeout`) when every slot is busy. Previously each task was pinned to a single hashed slot with no fallback, so a login could starve for the full 90 s behind one long-running call on that slot while the other slots sat idle; observed in integration as `LockAcquisitionError: ratelimit:<ip>:slot_2` during rapid logout/login cycles. `DatabaseLockManager` gained the non-blocking `try_acquire_lock()` this requires.
- **asdk**: overlapping keepalive sweeps (`LoginCoordinator.maintain_keepalives`) now coalesce — a sweep that finds one already in flight returns immediately instead of launching another swarm of slot-holding keepalive tasks. Previously every `api_call` fired its own sweep, so a burst of calls against a throttled server multiplied rate-limiter contention.

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
