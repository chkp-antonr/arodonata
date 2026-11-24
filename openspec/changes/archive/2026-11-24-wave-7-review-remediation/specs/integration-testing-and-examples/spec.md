# Spec Delta

## MODIFIED Requirements

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

**ID**: REQ-ITEST-007\
**Intent**: Emulate Check Point `ApiPort` pagination/queries and `GatewayCliPort` VSX context checks deterministically offline.\
**Non-goals**: Standalone HTTPS HTTP server wrapper (`REQ-ITEST-008`) or write overlays (`REQ-ITEST-009`).

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the disk raw dataset, validating commands against `^[a-z0-9]+(-[a-z0-9]+)*$` (optional `/web_api/` or `web_api/` prefix) and emulating pagination, `details-level`, filters, `use-object-dictionary=False` inlining, `where-used`, `run-script` + `show-task`, VSX CLI checks, per-`sid` writes, and redacted call logs.

#### Scenario: SCN-ITEST-007-1 — Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` (`limit`/`offset`, `uid`/`name`/`class-name`, `where-used`, `show-*-rulebase` with `use-object-dictionary=True | False`) and invokes `FileReplayCliMock` (or `run-script` + `show-task`)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve direct/indirect `where-used`, and inline `objects-dictionary` when `use-object-dictionary=False`
- **AND** `FileReplayApiMock` SHALL return Base64 `show-task` payloads and record per-command call counters
- **AND** `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

#### Scenario: SCN-ITEST-007-2 — Stateless read calls without SID continue reading published domain state

- **WHEN** read-only `FileReplayApiMock.api_call(...)` or `api_query(...)` is called with `sid=None`
- **THEN** `FileReplayApiMock` SHALL serve responses from the domain's published snapshot without failing authentication

#### Scenario: SCN-ITEST-007-3 — Replay mock enforces strict command-name validation parity with AMgmtClient

- **WHEN** `FileReplayApiMock.api_call(...)` or `api_query(...)` receives a malformed command (e.g., `"/show-hosts"`, `" show-hosts "`, `"SHOW-HOSTS"`, `"show-hosts/../publish"`, `"show-hosts?x=1"`) vs valid `"web_api/show-access-rulebase"` or `"/web_api/login"`
- **THEN** malformed commands SHALL raise `ValidationError` before mutating state or recording a valid command call, matching `AMgmtClient` validation
- **AND** valid `"web_api/"` / `"/web_api/"` prefixed commands SHALL normalize cleanly to the canonical lowercase hyphenated command name
