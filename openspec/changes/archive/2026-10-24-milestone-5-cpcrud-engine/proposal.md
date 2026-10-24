# Proposal: Milestone 5 — Declarative CPCRUD Policy-as-Code Engine

## Why

With the transport, session management, database-backed object/service/rulebase cache, and change reporting subsystems in place from Milestones 1–4, Arodonata v2 requires the declarative Check Point CRUD engine (`src/arodonata/cpcrud/`) and its wiring into `ArodonataClient` (`client.cpcrud`). This capability allows operators, automation pipelines, and MCP tools to validate YAML/JSON policy templates offline against `checkpoint_ops_schema.json`, plan deterministic idempotent actions across multiple management servers and domains using two-axis conflict policies and hybrid cache-first reads, execute plans safely inside isolated `WriteSession` contexts with stale-plan protection and session staging, and generate compensating rollback templates from captured `prior_state`.

## What Changes

- Implement `src/arodonata/cpcrud/checkpoint_ops_schema.json` and `src/arodonata/cpcrud/validator.py`:
  - Offline YAML/JSON template validation (`CPCRUDService.validate` / `validate_template`) against `checkpoint_ops_schema.json` (or `settings.cpcrud_schema_path` override) using `jsonschema.Draft7Validator` without making any network or database calls.
- Implement `src/arodonata/cpcrud/models.py`:
  - Core CPCRUD domain models: `Outcome` (`CREATE`, `UPDATE`, `DELETE`, `REUSE`, `UNCHANGED`, `ERROR`, `SKIPPED`, `SKIPPED_DEPENDENCY`, `PLAN_STALE`), `NameConflictPolicy` (`"update"` | `"error"`), `IpConflictPolicy` (`"reuse"` | `"create_new"` | `"error"`), `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_`), `DomainStamp`, `PlannedAction`, `Plan`, `ActionResult`, `StagedSessionInfo` (with SID redaction), and `ApplyReport`.
- Implement `src/arodonata/cpcrud/state_reader.py` (`HybridStateReader`):
  - Isolated per-run state reader created for each `plan()` invocation.
  - Reads network objects (`host`, `network`, `address-range`, `dns-domain`, `group`) from `arodonata_objects` and services (`service-tcp`, `service-udp`, `service-icmp`, `service-group`, `service-other`) from `arodonata_services` ONLY when the domain's stored `domain_sync_state` row for that specific `(scope, item_type)` has `status == "ok"` and matches the `DomainStamp` (`last_published_at` and `last_session_uid`) captured at the start of `plan()`.
  - Transparently falls back to live Management API queries (`show-*` / `api_query`) when `domain_sync_state` is missing, stale, or mismatched, and surfaces lookup failures or `paging_inconsistent` errors via explicit `StateLookupError` so the planner never mistakes a failed read for "not found".
- Implement `src/arodonata/cpcrud/differ.py`, `src/arodonata/cpcrud/rule_identity.py`, `src/arodonata/cpcrud/position_helper.py`, and `src/arodonata/cpcrud/planner.py` (`Planner`):
  - Reads `show-last-published-session` (`DomainStamp`) for every target `(mgmt_name, domain_name)` BEFORE performing any object, service, or rulebase lookups.
  - Evaluates two-axis conflict policies (`NameConflictPolicy` x `IpConflictPolicy`) with convention-compliant auto-naming via `NamingPrefixes` when `on_ip_conflict="create_new"` encounters an IP/subnet/range/port match under a different name.
  - Produces `Outcome.ERROR` (`"lookup failed, nothing planned (re-plan to retry): ..."`) on any state lookup failure or unreadable domain head, marking dependent actions (e.g. groups or rules referencing the failed object) as `Outcome.SKIPPED_DEPENDENCY` (`skipped_dependency`).
  - Matches access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by normalized traffic tuple (`rule_identity.py`), normalizing Check Point NAT `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"` (`NAT_ANY_OBJECT_UID`) sentinel UIDs so re-planning an applied NAT rule yields `Outcome.UNCHANGED`.
  - Resolves `"bottom"` and `{"bottom": "<section>"}` rule positions via `position_helper.py`, anchoring above any trailing `Any / Any / Any` cleanup rule (`{"above": "<cleanup_rule_uid>"}`).
- Implement `src/arodonata/cpcrud/executor.py` (`Executor`):
  - Paired `await apply(plan, ...) -> ApplyReport` and `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]` methods.
  - Verifies each target domain's current `show-last-published-session` against the `DomainStamp` recorded in `Plan` when `force=False`; if drifted or unreadable, marks all actions in that domain as `Outcome.PLAN_STALE` and performs zero writes in that domain.
  - Executes mutations inside an isolated `WriteSession` per `(mgmt_name, domain_name)`, updating `SessionOverlay` as each action succeeds and propagating auto-named/reused object references across dependent actions.
  - Supports staging mode (`no_publish=True, keep_session=True`), leaving the dedicated session open without publishing or logging out, recording `StagedSessionInfo` in `ApplyReport.staged_sessions`, and emitting `StagedSessionEvent`.
  - Calls `invalidate_domain(mgmt_name, domain_name)` after publish and supports `retry_remaining > 0` passes that re-run failed/remaining actions and fold their results into the cumulative `ApplyReport`.
- Implement `src/arodonata/cpcrud/inverse.py` (`build_inverse_template` / `CPCRUDService.inverse`):
  - Builds a schema-valid compensating template from `Plan` (and optional `ApplyReport`) using captured `PlannedAction.prior_state` (`CREATE` -> `delete`, `UPDATE` -> restore prior fields, `DELETE` -> `add` from `prior_state`).
- Wire `CPCRUDService` as `client.cpcrud` on `ArodonataClient` (`src/arodonata/client.py`) and export CPCRUD public symbols in `src/arodonata/__init__.py`.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specification in openspec/specs/cpcrud/spec.md. -->

### Modified Capabilities

<!-- None: skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/cpcrud/` (`__init__.py`, `checkpoint_ops_schema.json`, `models.py`, `validator.py`, `state_reader.py`, `differ.py`, `rule_identity.py`, `position_helper.py`, `planner.py`, `executor.py`, `inverse.py`, `service.py`) and updates `src/arodonata/client.py` and `src/arodonata/__init__.py`.
- **Tests**: Adds comprehensive unit tests in `tests/test_cpcrud_validator.py`, `tests/test_cpcrud_state_reader.py`, `tests/test_cpcrud_planner.py`, `tests/test_cpcrud_executor.py`, and `tests/test_cpcrud_inverse.py`, plus facade tests in `tests/test_client.py`.
