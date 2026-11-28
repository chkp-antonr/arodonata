# Spec Delta

## ADDED Requirements

### Requirement: Pinned Session Cleanup, Recursive Overlay Redaction, and Accurate Script Stage Attribution

**ID**: REQ-SESS-016\
**Intent**: Close DNS-rebinding windows in startup/recovery session cleanup, strip nested secrets from session overlays, and report accurate operation names on script errors.\
**Non-goals**: Changing Check Point session expiry thresholds or RBAC permissions.

`SessionCleaner` MUST preserve DNS-pinned IP and `tls_identity_host` when calling `show-sessions` and `discard`. Session overlay tracking MUST recursively strip sensitive keys at every nesting depth, and `ScriptRepositoryService` MUST attribute `RepositoryScriptPermissionError.operation` to the exact failing stage.

#### Scenario: SCN-SESS-016-1 — Pinned SessionCleaner TLS calls, recursive overlay stripping, and stage-accurate script errors

- **GIVEN** a DNS hostname management server during `SessionCleaner` cleanup, a `WriteSession` command containing nested sensitive keys, or a `ScriptRepositoryService` login/mutation/publish permission failure
- **WHEN** cleanup RPCs execute, overlay command history updates, or script repository methods raise `RepositoryScriptPermissionError`
- **THEN** `SessionCleaner` SHALL pass the DNS-pinned IP and `tls_identity_host` to `show-sessions` and `discard`
- **AND** `SessionOverlay` SHALL strip sensitive keys recursively and `ScriptRepositoryService` SHALL report the true failing phase in `operation`
