# Client and Facade Specification Delta

## MODIFIED Requirements

### Requirement: Script Repository Read, Check, Ensure, and Delete Facade

**ID**: REQ-CLIENT-010\
**Intent**: Manage Check Point repository scripts idempotently across read-only checks and isolated write provisioning.\
**Non-goals**: Executing repository scripts against gateway targets (`REQ-CLIENT-012`) or route-script defaults (`REQ-CLIENT-011`).

`ArodonataClient` SHALL expose traced async methods `get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, and `delete_repository_script`—decoding plaintext or Base64 `"script-body"` payloads—using shared read-only sessions for reads/checks and isolated write sessions (omitting `"repository-script"` from `SessionOverlay`) only when creation, modification, or deletion is required.

#### Scenario: SCN-CLIENT-010-1 — Read-only script check and zero-write fast path in ensure_repository_script

- **GIVEN** `"arodonata-collect-routes-v1"` already exists in `"Corp"` with matching normalized line endings (`\r\n` -> `\n`, stripped trailing whitespace) and matching explicit metadata (`comments`, `color`, `tags`)
- **WHEN** `check_repository_script` or `ensure_repository_script(mgmt_name, "arodonata-collect-routes-v1", expected_body, domain="Corp")` runs
- **THEN** the inspection SHALL run strictly read-only over cached read-only sessions without opening a `WriteSession` or calling `publish`
- **AND** `ensure_repository_script` SHALL return `EnsureRepositoryScriptResult(action="unchanged")`

#### Scenario: SCN-CLIENT-010-2 — Missing or outdated script created or updated without SessionOverlay pollution

- **GIVEN** a repository script that is absent, differs in body, or has mismatched explicit `comments`/`color`/`tags`
- **WHEN** `ensure_repository_script(mgmt_name, script_name, script_body, domain="Corp")` runs standalone or inside an active `WriteSession`
- **THEN** standalone calls SHALL open an isolated `WriteSession`, execute `add-repository-script` or `set-repository-script`, publish and invalidate `"Corp"`, and return `action="created"` or `"updated"`
- **AND** active `WriteSession` calls SHALL reuse the caller's session without auto-publishing or polluting `SessionOverlay` object caches

#### Scenario: SCN-CLIENT-010-3 — Permission error during script check or provisioning raises RepositoryScriptPermissionError

- **GIVEN** an administrator lacking `manage-repository-scripts: write` or `publish-sessions` privileges
- **WHEN** `ensure_repository_script` or `delete_repository_script` is invoked
- **THEN** `ArodonataClient` SHALL discard any uncommitted session cleanly
- **AND** it SHALL raise `RepositoryScriptPermissionError` carrying `mgmt_name`, `domain_name`, `script_ref`, and `operation` without exposing `sid` or credentials

#### Scenario: SCN-CLIENT-010-4 — Base64-encoded script-body from Check Point R82 show-repository-script decodes cleanly without false outdated drift

- **GIVEN** Check Point `show-repository-script` returns Base64-encoded script text inside the `"script-body"` field (rather than `"script-body-base64"`) for an up-to-date repository script
- **WHEN** `get_repository_script`, `check_repository_script`, or `ensure_repository_script` inspects that script
- **THEN** `RepositoryScript.script_body` SHALL decode the Base64 payload to UTF-8 text without corrupting plaintext scripts
- **AND** `check_repository_script` SHALL report `matches_expected=True` and `ensure_repository_script` SHALL return `action="unchanged"` without opening a `WriteSession`
