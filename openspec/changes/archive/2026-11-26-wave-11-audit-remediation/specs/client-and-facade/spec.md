# Spec Delta

## ADDED Requirements

### Requirement: Extended Secret Redaction, Shielded Write-Session Cancellation, and Script Unsupported Error Handling

**ID**: REQ-CLIENT-020\
**Intent**: Prevent secret leakage in key-value and DB URL diagnostics, guarantee clean discard on write-session cancellation or pre-send publish failure, rollback standalone mutations cleanly, and surface unsupported script-repository responses explicitly.\
**Non-goals**: SSE wire frame formatting (`REQ-CLIENT-019`) or CLI logging configuration (`REQ-AIBUILD-003`).

`redact_sid()` SHALL mask key=value secrets and URL passwords, write-session lifecycle helpers SHALL shield discard/logout while propagating `CancelledError`/`ServerIdentityError`, standalone `_mutate_object()` SHALL discard on failure, and `ScriptRepositoryService` SHALL scrub active SIDs and map unsupported script responses cleanly.

#### Scenario: SCN-CLIENT-020-1 — Extended key-value/URL secret redaction, shielded write-session cancellation/discard, and standalone mutation rollback

- **GIVEN** text containing `password=...`/`api_key=...`/`secret=...` or `scheme://user:pass@host` URLs, a write session experiencing `CancelledError` or pre-send `publish` `TransportError`, or a standalone `_mutate_object()` failure
- **WHEN** `redact_sid()`, `run_write_session_lifecycle()`, or `_mutate_object()` executes
- **THEN** key-value and URL credentials SHALL be redacted consistently, cancellations and identity errors SHALL propagate after shielded discard/logout, and failed `_mutate_object()` calls SHALL execute `discard` without leaving dirty server state

#### Scenario: SCN-CLIENT-020-2 — Unsupported repository-script classification and active write-session SID scrubbing

- **GIVEN** a Check Point server returning an unsupported repository-script error on `show-repository-scripts` / `show-repository-script`, or an active `WriteSession` whose SID appears in `ScriptRepositoryService` errors or `RepositoryScriptStatus.error`
- **WHEN** `get_repository_script()`, `list_repository_scripts()`, `check_repository_script()`, `ensure_repository_script()`, or route script execution runs
- **THEN** unsupported errors SHALL map to `RepositoryScriptUnsupportedError`, `RouteCollectionService` SHALL handle fallback cleanly, and active `WriteSession` SIDs SHALL be scrubbed everywhere including `RepositoryScriptStatus.error`
