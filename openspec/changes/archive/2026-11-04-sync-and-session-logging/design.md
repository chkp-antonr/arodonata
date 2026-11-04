# Design: Sync & Session Operational Logging

## Context

`arodonata_v2` uses `DomainSyncCoordinator._emit` to publish `SyncProgressEvent` objects (`DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, `DomainSyncFailedEvent`, `SyncCompletedEvent`) both for streaming (`stream_ensure`) and non-streaming (`ensure`) cache refreshes across all scopes (`objects`, `services`, `assets`, `rulebase`, `topology`). Routing `arlogi` logging directly through `DomainSyncCoordinator` provides unified observability across every cache scope without duplicating log calls in each individual service.

## Goals / Non-Goals

**Goals:**

- Log cache synchronization start, per-domain progress, and overall batch summary at `DEBUG` level, and domain failures (`DomainSyncFailedEvent`) at `WARNING` level in `DomainSyncCoordinator` with structured `arlogi` keyword attributes.
- Log domain list discovery (`show-domains`), RBAC `details-level="standard"` fallback (preserving existing cached CMA server IPs), CMA active IP failover resolution, login throttle cooldowns, and stale Arodonata session cleanup in `DomainService`, `LoginGate`, and `sessions.py`.

**Non-Goals:**

- Logging raw Check Point SIDs or credentials (all errors continue to pass through `redact_sid`).

## Decisions

1. **Centralized sync event logging in `DomainSyncCoordinator`**:
   - Every sync scope (`objects`, `services`, `assets`, `rulebase`, `topology`) flows through `DomainSyncCoordinator.stream_ensure`.
   - `SyncStartedEvent`, `DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent` -> `logger.debug` with structured keyword attributes (`scope`, `mgmt_name`, `domain`, etc.).
   - `DomainSyncFailedEvent` -> `logger.warning` with structured keyword attributes (`scope`, `mgmt_name`, `domain`, `error`).
2. **Session & MDM lifecycle logging and RBAC fallback**:
   - `DomainService._discover_server_domains` logs `DEBUG` before querying `show-domains` and after caching the discovered domain rows, retries with `details-level="standard"` only when `details-level="full"` is rejected by RBAC/permissions (preserving cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers` when `standard` omits `servers`), and logs `WARNING` on discovery failure.
   - `LoginGate.record_cooldown` and `LoginCoordinator` log `WARNING` with the server IP and cooldown duration when entering a throttle or read-timeout cooldown.
   - `LoginCoordinator.refresh_domain_active_ip` (and failover retry branches) logs `DEBUG` when a domain's `active_ip` / `active_mds_ip` is resolved.
   - `SessionCleaner` logs `DEBUG` when discarding stale Arodonata sessions.

## Risks / Trade-offs

- **Preserving cached CMA IPs during `details-level="standard"` fallback**: Because `show-domains` at `standard` level omits the `servers` list, `DomainService` merges any previously cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers` for matching domain names so existing CMA routing is never overwritten with the MDS host IP.
