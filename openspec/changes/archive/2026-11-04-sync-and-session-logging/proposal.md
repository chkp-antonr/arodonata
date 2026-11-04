# Proposal: Sync & Session Operational Logging

## Why

Previously, `arodonata_v2` emitted OpenTelemetry spans (`@traced`) and async `SyncProgressEvent` items during cache synchronization (`DomainSyncCoordinator`), domain discovery (`DomainService`), and Check Point session management (`LoginCoordinator`, `SessionCleaner`), but did not write standard `arlogi` (`DEBUG` / `WARNING`) log entries for those operations, nor did `DomainService` fall back to `details-level="standard"` when `show-domains` (`details-level="full"`) was rejected by Check Point RBAC permissions.

## What Changes

- Emit structured `arlogi` log messages in `DomainSyncCoordinator` (`src/arodonata/core/services/sync_coordinator.py`):
  - `SyncStartedEvent`, `DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent` at `DEBUG` level.
  - `DomainSyncFailedEvent` at `WARNING` level.
- Emit structured `arlogi` `DEBUG` / `WARNING` log messages in `DomainService` (`src/arodonata/core/services/domain_service.py`) when discovering domains on a management server, retrying with `details-level="standard"` if `details-level="full"` is rejected by Check Point RBAC (while preserving previously cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`), and logging a `WARNING` on discovery failure.
- Emit structured `arlogi` `DEBUG` / `WARNING` log messages in `src/arodonata/adapters/checkpoint/rate_limiter.py` and `src/arodonata/adapters/checkpoint/sessions.py`:
  - `WARNING` when `LoginGate` enters a Check Point login throttle or read-timeout cooldown window.
  - `DEBUG` when `LoginCoordinator.refresh_domain_active_ip` resolves or switches a domain's active CMA / MDS IP after failover or cold cache.
  - `DEBUG` when `LoginCoordinator` triggers `SessionCleaner` after a max-sessions error and when `SessionCleaner` discards stale Arodonata sessions.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `cache-and-sync`: `DomainSyncCoordinator` emits structured `arlogi` logs (`DEBUG` on domain sync progress and batch summary, `WARNING` on domain sync failure).
- `sessions-and-mdm`: `DomainService`, `LoginGate`, `LoginCoordinator`, and `SessionCleaner` emit structured `arlogi` logs (`DEBUG` for domain discovery, CMA active server failover resolution, and stale session cleanup; `WARNING` for login throttle cooldowns, RBAC `details-level="standard"` fallback, and domain discovery failures).

## Impact

- `src/arodonata/core/services/sync_coordinator.py`
- `src/arodonata/core/services/domain_service.py`
- `src/arodonata/adapters/checkpoint/rate_limiter.py`
- `src/arodonata/adapters/checkpoint/sessions.py`
