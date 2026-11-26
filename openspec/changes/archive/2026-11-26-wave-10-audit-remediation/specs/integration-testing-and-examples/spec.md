# Spec Delta

## ADDED Requirements

### Requirement: Atomic Emulator Rollback, Aliased SID Rotation, Read-Only Disconnect Guard, and Zero-Disk Mutation Baselines

**ID**: REQ-ITEST-021\
**Intent**: Ensure failed section/group CRUD calls leave overlays clean, `switch-session` isolates aliased SIDs and read-only sessions cannot disconnect peers, and direct-mutation helpers keep `reset()`/`restore_state()` free of disk reads.\
**Non-goals**: Base replay fixture loading (`REQ-ITEST-008`) or rule CRUD semantics (`REQ-ITEST-012`).

`FileReplayApiMock` SHALL roll back failed section `set` and group `add`/`set` mutations atomically (including sibling reverse `groups` links), rotate aliased SIDs on valid `switch-session`, reject read-only `disconnect` calls targeting other sessions, and capture clean baselines before direct domain mutations.

#### Scenario: SCN-ITEST-021-1 — Atomic rollback on failed section set and cross-field group add/set mutations

- **GIVEN** a `FileReplayApiMock` write session executing `set-*-section` with an invalid `new-position` or `add-group`/`set-group` with valid `members` and invalid `groups`
- **WHEN** the command fails validation
- **THEN** original section order/name and all sibling entity `groups` lists in the overlay SHALL remain completely unchanged

#### Scenario: SCN-ITEST-021-2 — Switch-session SID rotation, read-only disconnect rejection, and zero-disk direct-mutation baseline capture

- **GIVEN** two active SIDs aliased onto the same work session, a read-only session invoking `disconnect` on another session UID, or direct `assign-global-assignment` / `update_gateway_interfaces` / `bump_published_session` mutations
- **WHEN** `switch-session`, read-only `disconnect`, or `reset()` / `restore_state()` runs
- **THEN** `switch-session` SHALL rotate other active SIDs onto fresh work sessions, read-only `disconnect` on foreign sessions SHALL fail with HTTP 400, and `reset()` / `restore_state()` SHALL perform zero disk fixture reads
