# Spec Delta

## ADDED Requirements

### Requirement: Replay Emulator RBAC Parity, Group Locks, Protocol Guards, and Reference Consistency

**ID**: REQ-ITEST-022\
**Intent**: Align `FileReplayApiMock` and `CheckPointReplayHttpServer` strictly with Check Point session, RBAC, group, and command-validation semantics.\
**Non-goals**: Simulating Check Point SmartConsole GUI interactions or hardware blade licensing.

`FileReplayApiMock` MUST validate `manage_repository_scripts` (`"write"`, `"read"`, `"none"`), restore constructor RBAC flags on `reset()`, enforce group non-self-containment and cross-session parent locks, use `DROP_UID` for default access-rule tracking, and share rulebase reference-column constants. `CheckPointReplayHttpServer` MUST return JSON HTTP 400 on malformed command names, and policy verification/installation MUST enforce session and domain guards.

#### Scenario: SCN-ITEST-022-1 — Constructor RBAC preservation, group lock/cycle checks, DROP_UID track, and shared ref columns

- **GIVEN** `FileReplayApiMock` configured with custom RBAC flags or `reset()`, group `add`/`set` self-containment or cross-session parent edits, a Drop access rule, or `where-used` on an Access `content` column
- **WHEN** `reset()`, group CRUD, access-rule creation, or `where-used` runs
- **THEN** `manage_repository_scripts` SHALL validate `"write"`/`"read"`/`"none"` and `reset()` SHALL restore constructor flags
- **AND** self-referential groups SHALL fail, cross-session parent locks SHALL block concurrent updates, Drop rules SHALL default to `None` track via `DROP_UID`, and `where-used` SHALL use shared projection reference columns

#### Scenario: SCN-ITEST-022-2 — JSON 400 on malformed commands and session/domain guards on verify/install-policy

- **GIVEN** a malformed command sent to `CheckPointReplayHttpServer` or a `verify-policy`/`install-policy` call on a locked, dirty, cross-domain, or read-only `FileReplayApiMock` session
- **WHEN** the HTTP server dispatches the command or `handle_verify_or_install_policy()` evaluates the session
- **THEN** malformed command names SHALL return Check Point JSON HTTP 400 instead of unhandled HTTP 500
- **AND** `verify-policy` and `install-policy` SHALL enforce open-session, same-domain, zero-uncommitted-changes, and write-session guards consistently
