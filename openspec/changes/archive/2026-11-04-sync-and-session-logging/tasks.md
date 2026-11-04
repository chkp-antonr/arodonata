# Tasks: Sync & Session Operational Logging

## 1. Cache Synchronization Logging

- [x] 1.1 Initialize `arlogi` logger in `src/arodonata/core/services/sync_coordinator.py` and log `SyncStartedEvent`, `DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent` at `DEBUG` level and `DomainSyncFailedEvent` at `WARNING` level with structured attributes

## 2. Domain Discovery and Session Lifecycle Logging

- [x] 2.1 Initialize `arlogi` logger in `src/arodonata/core/services/domain_service.py`, log domain discovery start and completion (`DEBUG`) and discovery failures (`WARNING`), and retry `show-domains` with `details-level="standard"` on RBAC rejection while preserving cached CMA IPs
- [x] 2.2 Initialize `arlogi` logger in `src/arodonata/adapters/checkpoint/rate_limiter.py` and `src/arodonata/adapters/checkpoint/sessions.py` and log `LoginGate` throttle/read-timeout cooldowns (`WARNING`), `refresh_domain_active_ip` failover resolution (`DEBUG`), max-sessions cleanup triggers (`DEBUG`), and stale session discards (`DEBUG`)
