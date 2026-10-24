# Design: Milestone 5 — Declarative CPCRUD Policy-as-Code Engine

## Context

See `proposal.md` for motivation and `openspec/specs/cpcrud/spec.md` for canonical requirements. Milestone 5 delivers `src/arodonata/cpcrud/` and wires `CPCRUDService` into `ArodonataClient` (`client.cpcrud`).

## Goals / Non-Goals

**Goals:**

- Keep `src/arodonata/cpcrud/` strictly decoupled from low-level HTTP/SQL drivers by operating against `ApiPort`, `CachePort`, and core domain models (`CPObject`, `CPService`, `DomainSyncState`, `WriteSession`, `SessionOverlay`, `CPCRUDEvent`).
- Provide zero-IO offline schema validation (`CPCRUDService.validate`) against `checkpoint_ops_schema.json` using `jsonschema.Draft7Validator`.
- Implement `HybridStateReader` gated per `(scope, item_type)` by exact `DomainStamp` match (`last_published_at` and `last_session_uid`) against `domain_sync_state`, with transparent live API fallback and in-run overlay tracking so intra-plan creations/updates/renames are visible to subsequent steps in the same `plan()`.
- Implement `Planner`, `Differ`, `rule_identity`, and `position_helper` supporting two-axis conflict resolution (`NameConflictPolicy` x `IpConflictPolicy`), `NamingPrefixes` auto-naming, fail-closed `Outcome.ERROR` + `skipped_dependency` planning on lookup failures, NAT `"Original"`/`"Any"` sentinel normalization, and cleanup-rule-aware `"bottom"` rule placement.
- Implement `Executor` with paired `await apply(...) -> ApplyReport` and `stream_apply(...) -> AsyncIterator[CPCRUDEvent]`, stale-plan verification (`Outcome.PLAN_STALE`), per-domain isolated `WriteSession` execution with `SessionOverlay` updates, `no_publish=True, keep_session=True` session staging, post-publish cache invalidation, and `retry_remaining` folding.
- Implement `build_inverse_template` (`CPCRUDService.inverse`) producing a schema-valid rollback template from `PlannedAction.prior_state`.

**Non-Goals:**

- Modifying `SSEEvent` wire formatting in `core` (`Executor.stream_apply` yields typed `CPCRUDEvent` models; `arodonata.adapters.sse` already converts `DomainEvent` / `CPCRUDEvent` to `SSEEvent`).

## Decisions

### 1. Package Layout (`src/arodonata/cpcrud/`)

```text
src/arodonata/cpcrud/
├── __init__.py
├── checkpoint_ops_schema.json   # Draft-07 JSON Schema for declarative CPCRUD templates
├── models.py                    # Outcome, policies, NamingPrefixes, DomainStamp, PlannedAction, Plan, ApplyReport
├── validator.py                 # Offline Draft7Validator template parser and validator
├── state_reader.py              # HybridStateReader (cache-first gated by DomainStamp + live API fallback)
├── differ.py                    # Field-level object, service, group, and rule diff computation
├── rule_identity.py             # NAT sentinel normalization & rule matching by key or traffic tuple
├── position_helper.py           # Cleanup-rule-aware "bottom" / section / relative rule positioning
├── planner.py                   # Planner.decide two-axis conflict resolution & dependency propagation
├── executor.py                  # Executor.apply & stream_apply in isolated WriteSession per domain
├── inverse.py                   # build_inverse_template compensating rollback generator
└── service.py                   # CPCRUDService unified facade (validate, plan, apply, stream_apply, inverse)
```

### 2. Offline JSON Schema Validation (`checkpoint_ops_schema.json`, `validator.py`)

- Accepts a `dict[str, Any]` or YAML/JSON `str` template.
- Validates against the bundled `checkpoint_ops_schema.json` (or `settings.cpcrud_schema_path` when configured) using `jsonschema.Draft7Validator`.
- Supports both multi-target templates (`targets` / `domains` list of `{mgmt_name, domain, conflict_policy, naming_prefixes, objects, services, groups, rules, operations}`) and flat single-domain templates (`mgmt_name`, `domain`, `conflict_policy`, `naming_prefixes`, `objects`, `services`, `groups`, `rules`, `operations`).
- Formats validation failures with JSON path + message into deterministic human-readable strings without making any network or database calls.

### 3. `HybridStateReader` & Exact `DomainStamp` Gating (`state_reader.py`)

- At the start of `plan()`, `Planner` queries `show-last-published-session` once per target `(mgmt_name, domain_name)` BEFORE any object, service, or rulebase lookups and records a `DomainStamp(mgmt_name, domain_name, last_session_uid, last_published_at, readable=True/False, error=...)`.
- If `show-last-published-session` fails or returns an error, `DomainStamp.readable` is `False`; all operations in that domain immediately plan as `Outcome.ERROR` (`"lookup failed, nothing planned (re-plan to retry): ..."`).
- When `HybridStateReader` looks up an object (`scope="objects"`, `item_type` in `{"host", "network", "address-range", "dns-domain", "group"}`) or service (`scope="services"`, `item_type` in `{"service-tcp", "service-udp", "service-icmp", "service-group", "service-other"}`):
  1. Checks the in-plan virtual overlay first (so objects planned for creation or rename earlier in the same template are resolved immediately).
  2. Checks `cache.get_sync_state(mgmt_name, domain_name, scope, item_type)`.
  3. Cache is considered fresh ONLY if `sync_state is not None`, `sync_state.status == "ok"`, `stamp.readable` is `True`, and the stored `(last_published_at, last_session_uid)` matches `stamp` (matching `last_session_uid` when present and `last_published_at` when present).
  4. If fresh, queries `cache.get_objects(...)` or `cache.get_services(...)`.
  5. Otherwise, falls back to live Management API calls (`show-host`, `show-network`, `show-objects`, `api_query("show-services-tcp")`, etc.).
  6. If any live API call or `api_query` fails (`success=False`, `code == "paging_inconsistent"`, or raises an exception other than "object not found" HTTP 404 / `generic_err_object_not_found`), `HybridStateReader` raises `StateLookupError`, which `Planner` converts into `Outcome.ERROR`.

### 4. Two-Axis Conflict Resolution, `Differ`, and Rule Helpers (`planner.py`, `differ.py`, `rule_identity.py`, `position_helper.py`)

- **Two-Axis Conflict Matrix**:
  - `NameConflictPolicy`: `update` (default) | `error`.
  - `IpConflictPolicy`: `reuse` (default) | `create_new` | `error`.
  - **Case A — Name exists**:
    - Compute field diff via `differ.py`. If no attributes differ -> `Outcome.UNCHANGED`.
    - If attributes differ and `on_name_conflict == "error"` -> `Outcome.ERROR`.
    - If attributes differ and `on_name_conflict == "update"` -> `Outcome.UPDATE` (capturing `prior_state` and `diffs`).
  - **Case B — Name does not exist, but IP / subnet / range / port-protocol exists under another object `existing`**:
    - `on_ip_conflict == "error"` -> `Outcome.ERROR`.
    - `on_ip_conflict == "reuse"` -> `Outcome.REUSE` (records `resolved_name = existing.name`, `target_uid = existing.uid`, and substitutes `existing.name` into dependent groups and rules in the same plan).
    - `on_ip_conflict == "create_new"` -> generates a convention-compliant name via `NamingPrefixes`:
      - Host: `{prefixes.host}{ipv4_or_ipv6}` (e.g. `Host_10.0.0.1`).
      - Network: `{prefixes.network}{subnet}_{mask_len}` (e.g. `Net_10.0.0.0_24`).
      - Address Range: `{prefixes.address_range}{first}-{last}` (e.g. `IPR_10.0.0.1-10.0.0.10`).
      - TCP/UDP/ICMP Service: `{prefixes.tcp}{port}`, `{prefixes.udp}{port}`, `{prefixes.icmp}{icmp_type}`.
      - If the generated convention name matches `existing.name` (or already exists with identical value), reuses or updates according to `NameConflictPolicy`; otherwise plans `Outcome.CREATE` under the convention name (with `ignore-warnings: True` in payload) and substitutes `resolved_name` into dependent groups and rules.
  - **Case C — Neither name nor IP/value exists**:
    - Plans `Outcome.CREATE`.
- **Failed Lookup & Dependency Propagation**:
  - Any `StateLookupError` during name lookup, IP/value lookup, rulebase lookup, or `where-used` check produces an `Outcome.ERROR` action with message `"lookup failed, nothing planned (re-plan to retry): <reason>"`.
  - Any subsequent group or rule action in the same domain that references an object/service whose action has `Outcome.ERROR` or `Outcome.SKIPPED_DEPENDENCY` is automatically planned with `Outcome.SKIPPED_DEPENDENCY` (`status="skipped_dependency"`).
- **NAT Sentinels & Rule Identity (`rule_identity.py`)**:
  - Defines `NAT_ORIGINAL_OBJECT_UID = "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"` and `NAT_ANY_OBJECT_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"`.
  - Normalizes `None`, `""`, `"Original"`, `"original"`, and `NAT_ORIGINAL_OBJECT_UID` (or dict `{"uid": NAT_ORIGINAL_OBJECT_UID}` / `{"name": "Original"}`) on `translated-source`, `translated-destination`, and `translated-service` to canonical `"Original"`.
  - Normalizes `None`, `""`, `"Any"`, `"any"`, and `NAT_ANY_OBJECT_UID` on traffic fields (`source`, `destination`, `service`, `original-source`, `original-destination`, `original-service`) to canonical `"Any"`.
  - Matches existing rules by explicit key (`uid`, `name`, `rule_number`) first, or by canonical traffic tuple when no explicit key is given.
- **Cleanup-Aware Positioning (`position_helper.py`)**:
  - Inspects the target layer or section's rules. A rule at the end of a layer or section is recognized as a cleanup rule if its name is `"Cleanup rule"` (case-insensitive) or if its `source == ["Any"]`, `destination == ["Any"]`, `service == ["Any"]` and `action` is `"Drop"` or `"Accept"` at the tail position.
  - When `position == "bottom"` or `position == {"bottom": "<section>"}` and the last rule in that layer/section is a cleanup rule, returns `{"above": cleanup_rule_uid}`.

### 5. Dedicated-Session Executor, Stale-Plan Safeguard, and Staging (`executor.py`)

- **Stale-Plan Safeguard (`Outcome.PLAN_STALE`)**:
  - For each target `(mgmt_name, domain_name)` that has executable write actions (`CREATE`, `UPDATE`, `DELETE`), when `force=False`, queries `show-last-published-session` before opening a `WriteSession`.
  - If the query fails or the current `last_session_uid` (or `last_published_at`) differs from `plan.domain_stamps["{mgmt_name}:{domain_name}"]`, marks all actions in that domain as `Outcome.PLAN_STALE` (`"Domain head drifted since plan..."`), emits `CPCRUDActionEvent` items with `outcome="plan_stale"`, and performs zero writes in that domain.
- **Dedicated `WriteSession` & `SessionOverlay`**:
  - Opens a dedicated session via `api.create_dedicated_session(mgmt_name, domain_name, ...)` and binds a `WriteSession` (`write_session_context(ws)`) per domain.
  - Executes each `CREATE` / `UPDATE` / `DELETE` action sequentially, updating `ws.overlay` (`_update_overlay_from_command`) and recording `ActionResult`.
  - If an action fails at runtime, marks any downstream actions in the same domain that depend on it as `Outcome.SKIPPED_DEPENDENCY`.
- **Publish vs Staging (`no_publish`, `keep_session`)**:
  - Normal mode (`no_publish=False`): publishes the session (`api_call(..., "publish")`), calls `invalidate_domain(mgmt_name, domain_name)`, emits `CPCRUDDomainPublishedEvent`, and logs out the dedicated SID.
  - Dry/discard mode (`no_publish=True, keep_session=False`): discards (`api_call(..., "discard")`) and logs out the dedicated SID.
  - Staging mode (`no_publish=True, keep_session=True`): leaves the dedicated session open without calling `publish`, `discard`, or `logout`, records `StagedSessionInfo(mgmt_name=..., domain_name=..., sid=ws.sid, server_ip=ws.server_ip, session_uid=..., session_name=...)` in `ApplyReport.staged_sessions`, and emits `StagedSessionEvent`.
- **Retry Remaining (`retry_remaining > 0`)**:
  - When `retry_remaining > 0` and transient action failures occurred, re-runs failed/remaining actions up to `retry_remaining` times and folds each retry pass's `ApplyReport` into the cumulative `ApplyReport`.

### 6. Compensating Rollback Template Generation (`inverse.py`)

- `build_inverse_template(plan, report=None)`:
  - Filters actions to those that were actually applied (if `report` is supplied, only actions that succeeded with `CREATE`, `UPDATE`, or `DELETE`; if `report` is `None`, all planned `CREATE`, `UPDATE`, and `DELETE` actions).
  - Reverses action order so dependent rules/groups are rolled back before the objects they reference:
    - `Outcome.CREATE` -> `operation: "delete"` identifying the created object/rule by `uid` (if known from `report`) or `name` / key.
    - `Outcome.UPDATE` -> `operation: "set"` (or `"update"`) restoring the prior attribute values captured in `PlannedAction.prior_state` (including restoring original `name` via `new-name` if renamed).
    - `Outcome.DELETE` -> `operation: "add"` (or `"present"`) populated from `PlannedAction.prior_state`.
  - Validates the resulting compensating dictionary against `checkpoint_ops_schema.json` so it is guaranteed to be schema-valid.

## Risks / Trade-offs

- **[Risk] Session SID leakage in `StagedSessionInfo` or `ApplyReport`** → Mitigation: `StagedSessionInfo.sid` uses `Field(repr=False, exclude=True)` with custom `__repr__` / `__str__` masking `sid` via `REDACTED_PLACEHOLDER`, while exposing `.sid` property for programmatic callers (such as `OwnedSession` in change reports).
- **[Risk] False `CREATE` on transient API / pagination errors during planning** → Mitigation: `HybridStateReader` explicitly distinguishes "object not found" from API/transport/pagination errors (`StateLookupError`), and `Planner` always converts `StateLookupError` into `Outcome.ERROR` + `Outcome.SKIPPED_DEPENDENCY`.
