# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Python package structure (`pyproject.toml`, `src/arodonata/`, `tests/`) with optional extras `postgres`, `mcp`, and `all`.
- Dedicated `arodonata_services` cache specification, `(mgmt_name, domain_name, scope, item_type)` revision tracking in `domain_sync_state` (`last_published_at`, `last_session_uid`, `synced_at`), `VerifiedConnectionPool` for read-only commands, hybrid/dynamic authentication (`AuthContext` / `AuthProvider`), `contextvars`-bound `WriteSession` with `SessionOverlay`, and MCP `describe_objects` / `query_objects` / `cache_status` specifications.
- Initial repository structure, OpenSpec capability specifications, and developer tooling.
- Agent guidelines, linting rules, and workflows (`/archive-task`, `/save-plan`).
- Strict Git branching policy: separate working branches, integration to `master` only via PR and squash merge.

### Changed

- Revised all 9 OpenSpec capability specifications for Arodonata v2 clean-slate hexagonal architecture: native `aiohttp` transport (replacing `cpapi`), `SqlCacheAdapter` (replacing `PostgresCacheAdapter`/`CacheRepository`), canonical `CacheMode` names (`cache`, `smart`, `smart-fast`, `force`), paired coroutine and `stream_*` domain event APIs (removing `SSEEvent` from core), and unified `ArodonataClient` facade (replacing `arodonata.helpers`).
