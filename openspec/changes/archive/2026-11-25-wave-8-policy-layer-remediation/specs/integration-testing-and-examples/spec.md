# Spec Delta

## ADDED Requirements

### Requirement: Replay Emulator Mutation Atomicity, Read-Only Session Guards, and Zero-Disk Reset

**ID**: REQ-ITEST-019\
**Intent**: Ensure the replay mock enforces Check Point `track` wire formats, rolls back failed entity/section mutations, blocks read-only `switch-session` aliasing, and resets strictly in memory.\
**Non-goals**: Base replay CRUD (`REQ-ITEST-011`, `REQ-ITEST-013`) or initial dataset generation (`REQ-ITEST-006`).

`FileReplayApiMock` SHALL enforce per-rulebase `track` wire types (`access` object vs `https`/`threat` string), roll back in-memory overlay mutations on failed entity/section `add`/`set` calls, reject `switch-session`/`set-session`/`discard`/writes on `read_only` bindings while rotating aliased SIDs, and capture clean domain baselines in memory before first mutation so `restore_state()` and `reset()` perform zero disk I/O.

#### Scenario: SCN-ITEST-019-1 — Replay emulator validates track wire types, rolls back failed mutations, and blocks read-only switch-session

- **GIVEN** a `FileReplayApiMock` instance with clean disk fixtures and active read-only and read-write sessions
- **WHEN** a caller sends invalid `track` wire types, triggers a validation error in entity/section `add`/`set`, invokes `switch-session` on a read-only session, or calls `restore_state()`/`reset()` after domain mutations
- **THEN** invalid `track` wire types and read-only `switch-session` calls SHALL be rejected with `err_validation_failed` (rotating any aliased SIDs on valid switches)
- **AND** failed entity/section mutations SHALL leave overlay state unchanged, and `restore_state()`/`reset()` SHALL execute zero disk fixture reads
