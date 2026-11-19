# Check Point Management API Quirks & SDK Mitigations

Real-world Check Point Management API versions (`R80.x`, `R81.x`, `R82.x`, Management API `v1.9`–`v2.2`) exhibit undocumented or subtle server behaviors that directly shape Arodonata v2's transport, session, caching, CPCRUD, and testing architecture.

## 1. Session Lifecycle & Login Throttling

- **Login Rate-Limit Window (`70s`)**: Check Point Management servers enforce per-source login throttling (roughly once per `60s`+ window). `LoginCoordinator` tracks shared cooldown gates per server IP (`login_throttle_window=70.0`, bounded by `login_max_wait=900.0`) so concurrent tasks back off together instead of hammering the server (`REQ-SESS-006`).
- **Gated Login Exception vs. General No-Resend**: General `/web_api/<command>` calls NEVER resend after request bytes leave the socket (`request_sent=True`) to avoid duplicating non-idempotent mutations (`REQ-TRANS-007`). Login attempts inside `LoginCoordinator` are an explicit single-retry exception alongside cooldown backoff.
- **Dirty `logout` Preserves Object Locks**: Calling `logout` on a Check Point session with uncommitted changes does **not** roll back or release locks—it transitions the session to `"disconnected"` while retaining object locks. Always call `discard` (or `publish`) before `logout` (`REQ-SESS-003`, `SCN-ITEST-010-2`).
- **`take-over-session` Ownership & `application` Quirk**: Check Point exposes no pre-flight flag showing whether an external Web API SID is actively mid-request. For non-disruptive staged adoption (`force_disconnect=False`), `CPCRUDService` omits `disconnect-active-session` from `take-over-session` so active sessions are not terminated, and accepts empty `application == ""` alongside `"web_api"` and `"arodonata"` in `show-session` (`SCN-CPCRUD-011-4`).
- **Unauthenticated Readiness Probe**: `show-api-versions` called with `sid=None` responds either with `success=True` or `generic_err_missing_required_header`, allowing readiness probes without consuming login rate-limit slots (`SCN-ITEST-004-2`).

## 2. Clean-Session Gate, Incremental Sync & Pagination

- **Fail-Closed Dirty Session Check (`show-session`)**: Before syncing shared cache tables (`arodonata_objects`, `arodonata_services`, `arodonata_rulebase_*`), `DomainSyncCoordinator` verifies the read session has `changes == 0` via `show-session` so uncommitted session state never leaks into the shared cache (`REQ-CACHE-005`, `REQ-RULE-001`).
- **`show-changes` Time & Payload Differences**:
  - Prefer `from-session` over `from-date` (when date fallback is needed, Check Point requires UTC `Z`-suffixed ISO-8601 timestamps).
  - R82+ servers may wrap changed objects inside `{"new-object": ...}` and `{"old-object": ...}` inside `changes[]` buckets (with `added-objects`, `modified-objects`, `deleted-objects`, etc. directly under `changes[i]`, without an intermediate `.operations` object).
  - Bare deleted or modified object UIDs in `show-changes` can be backfilled from pre-change snapshots or `objects-dictionary` (`REQ-REPORT-002`).
- **Task-Based Query Commands**: Commands such as `show-changes`, `show-logs`, and `show-gateways-and-servers-task` return a `task-id` rather than direct inline items and must be polled via `show-task` (`tasks[].task-details[]`) across pagination offsets (`REQ-TRANS-006`).
- **Boundary-Swap Duplicate UIDs on Pagination**: Check Point object listings sorted with equal keys can swap two objects across page boundaries. `AMgmtClient.api_query()` detects duplicate UIDs at page seams and re-reads a small boundary window instead of restarting full scans, restarting once if `total` drifts (`REQ-TRANS-006`).

## 3. Object Listings, Services & Sentinels

- **Multi-Version `show-objects` Fallback**: Older or restricted Management API versions may return `generic_err_command_not_recognized` for universal `show-objects`. CPCRUD cold-cache lookups automatically fall back to type-scoped endpoints (`show-hosts`, `show-networks`, `show-address-ranges`, `show-services-*`) (`REQ-CPCRUD-004`).
- **Built-In ICMP Names & Non-Numeric Matching**: Built-in ICMP services such as `echo-request` cannot be found by numeric `filter="8"` queries on `show-objects`; Arodonata queries single-page `show-services-icmp` / `show-services-icmp6` directly (`REQ-CPCRUD-005`).
- **`Any` and NAT `Original` Sentinels**: Access rules start empty cells at `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`), which Check Point strips automatically as soon as concrete members are added and restores when the last member is removed. NAT rules additionally normalize `"Original"` (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c`) (`REQ-CPCRUD-008`, `REQ-RULE-005`).
- **Zero-Mask Host Rules**: Gateway interfaces with `/32` (`255.255.255.255`) or unmasked points and VSX `CpmiVsxSlotObj` / `CpmiVsSlotObj` cross-domain Virtual System bindings require querying generic objects (`show-generic-objects`) beyond standard gateway listings (`REQ-CACHE-010`, `REQ-TOPO-001`).

## 4. MDSM Global Domain & Failover Semantics

- **Global Domain Routing**: Sessions to the `"Global"` MDS domain route to the active server returned by `show-global-domain` rather than treating `"Global"` as a regular CMA (`SCN-SESS-001-3`).
- **Global Read Visibility vs. Write Protection**: Local domain rulebases can reference `Global` objects (resolved in `objects-dictionary` with `domain.domain-type == "global domain"`), while local bulk listings (`show-hosts`, `show-networks`, etc.) remain domain-scoped and local CMA writes targeting `Global` entities fail with `generic_err_object_read_only` (`REQ-ITEST-014`).
- **Wildcard & Cross-Domain Lookups on MDS**: Unqualified lookups (`domain=None`) keep multi-domain MDS caches strictly local (`cache_mode="cache"`) to prevent costly accidental whole-MDS login storms (`REQ-CLIENT-006`, `REQ-CACHE-014`).
