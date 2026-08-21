# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are generated from [Conventional Commits](https://www.conventionalcommits.org/)
via [commitizen](https://commitizen-tools.github.io/commitizen/) — do not
hand-edit released sections, only the `[Unreleased]` section above them.

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
