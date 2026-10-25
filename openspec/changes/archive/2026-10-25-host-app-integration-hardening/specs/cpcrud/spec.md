# CPCRUD Declarative Policy-as-Code Engine Specification Delta

## MODIFIED Requirements

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService` SHALL provide both `await apply(plan, ...) -> ApplyReport` and `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`, executing planned actions in an isolated `WriteSession` per `(mgmt_name, domain_name)` (updating `SessionOverlay` as each action succeeds), verifying that the domain's published head has not drifted since `plan()`, and providing `publish_staged_session` (`stream_publish_staged_session`) and `discard_staged_session` to finalize or abort sessions staged with `keep_session=True`.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs and a target domain's current `show-last-published-session` UID differs from the `DomainStamp` recorded in `plan` (or cannot be read)
- **THEN** the executor SHALL mark all actions in that domain as `Outcome.PLAN_STALE` and perform no writes in that domain

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions`, and emit a `StagedSessionEvent` (`CPCRUDEvent`) in `stream_apply()`

#### Scenario: Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid)` or `client.stream_publish_staged_session(...)` is called for a previously staged session
- **THEN** the service SHALL adopt ownership of `session_uid` via `take-over-session` (`uid=session_uid`), execute `publish` (`payload={}`) while polling task progress, log out the session, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: Staged session discard adopts ownership via take-over-session before discarding

- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid)` is called for an open or orphaned staged session
- **THEN** the service SHALL issue `take-over-session` (`uid=session_uid`) prior to `discard` so foreign locks or session ownership divergence do not prevent clean session termination

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL fold their `ApplyReport` into the cumulative report
