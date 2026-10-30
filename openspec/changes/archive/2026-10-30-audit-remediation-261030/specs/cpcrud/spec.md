# Spec Delta

## MODIFIED Requirements

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService` SHALL execute `apply` and `stream_apply` using allowlisted `(object_type, operation)` commands in an isolated `WriteSession` per domain (defaulting omitted session names to `arodonata-cpcrud*`), re-verify the domain head before each pass and pre-`publish`, shield `discard` before `logout` on any `BaseException`, and adopt staged sessions only after `show-session` provenance verification with non-disruptive takeover by default.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs (on the initial pass, on any `retry_remaining` pass, or immediately before issuing `publish`) and a target domain's current `show-last-published-session` UID or `last_published_at` differs from the `DomainStamp` recorded in `plan` (including when `stamp.last_session_uid is None` and the domain now has a published session, or when the head cannot be read)
- **THEN** the executor SHALL mark all remaining actions in that domain as `Outcome.PLAN_STALE` (or discard the uncommitted session if detected pre-publish) and publish no writes in that domain

#### Scenario: Forged or unlisted action command rejected before execution

- **WHEN** `apply(plan)` receives a `PlannedAction` whose `object_type` and `operation` do not map to the canonical CPCRUD command allowlist or whose `command` field disagrees with the allowlisted command for `(object_type, operation)`
- **THEN** the executor SHALL reject the action with `ValidationError` before opening a session or sending any Web API call

#### Scenario: Unhandled exception, cancellation, or publish failure discards uncommitted session before logout

- **WHEN** an exception, `asyncio.CancelledError`, or `publish` transport/task failure occurs while executing a domain in `apply()` or `stream_apply()` (unless `no_publish=True and keep_session=True` completed cleanly or recorded the staged session prior to error)
- **THEN** the executor SHALL shield `discard` followed by `logout_sid` in `finally` so no uncommitted changes or object locks remain orphaned on the management server, and record any staged session opened under `keep_session=True` as soon as the session is created

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL assign a default `arodonata-cpcrud-staged` session name when none was supplied, leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions` and the client's staged-session registry immediately upon creation, and emit a `StagedSessionEvent` in `stream_apply()`

#### Scenario: Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` or `client.stream_publish_staged_session(...)` is called for a previously staged session
- **THEN** the service SHALL reuse a caller-supplied `sid` directly when `show-session {}` confirms `uid == session_uid` in an open state, or otherwise open a dedicated session, verify via `show-session {"uid": session_uid}` that the session is open and Arodonata-staged (recorded by `keep_session=True` or carrying an `arodonata*` session name / `application == "arodonata"`), issue `take-over-session` (`{"uid": session_uid}` without `disconnect-active-session` unless explicit library-only `force_disconnect=True` is passed, falling back to `switch-session` only after provenance verification passes and reporting both errors if both fail), execute `publish` while polling task progress, log out cleanly, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: Staged session discard adopts ownership via take-over-session before discarding

- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` is called for an open or orphaned staged session
- **THEN** the service SHALL verify open Arodonata provenance via `show-session` (or reuse an active matching `sid` directly), adopt ownership via non-disruptive `take-over-session` (with `disconnect-active-session` omitted/`False` unless explicit library-only `force_disconnect=True` is passed, and provenance-gated `switch-session` fallback reporting both errors on failure), execute `discard`, and log out cleanly

#### Scenario: Foreign, active SmartConsole, or already-finalized session UID refused during staged adoption

- **WHEN** `publish_staged_session`, `stream_publish_staged_session`, or `discard_staged_session` is called with a `session_uid` belonging to a human SmartConsole/foreign session (not in the staged-session registry and lacking an `arodonata*` session name / `application == "arodonata"`), an already `published`/`discarded` session, or an actively connected session while `force_disconnect=False`
- **THEN** the service SHALL refuse adoption before issuing disruptive `take-over-session` or `switch-session`, log out any fresh helper session it opened, and return a failed `ApiCallResult` (or failure event) without disconnecting the active administrator or publishing/discarding their work

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold their `ApplyReport` into the cumulative report
