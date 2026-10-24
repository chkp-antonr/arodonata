# Tasks: Milestone 5 — Declarative CPCRUD Policy-as-Code Engine

## 1. CPCRUD Schema, Models, and Offline Validator (`checkpoint_ops_schema.json`, `models.py`, `validator.py`)

- [x] 1.1 Implement `src/arodonata/cpcrud/checkpoint_ops_schema.json`, `src/arodonata/cpcrud/models.py` (`Outcome`, `NameConflictPolicy`, `IpConflictPolicy`, `NamingPrefixes`, `DomainStamp`, `FieldChange`, `PlannedAction`, `Plan`, `ActionResult`, `StagedSessionInfo`, `ApplyReport`), and `src/arodonata/cpcrud/validator.py` (`validate_template`, `parse_template` using `jsonschema.Draft7Validator` with zero network/DB calls) and verify unit tests in `tests/test_cpcrud_validator.py` pass

## 2. `HybridStateReader` with Exact `DomainStamp` Cache Gating (`state_reader.py`)

- [x] 2.1 Implement `src/arodonata/cpcrud/state_reader.py` (`HybridStateReader` and `StateLookupError` reading `arodonata_objects` and `arodonata_services` only when `domain_sync_state` for `(scope, item_type)` matches the planner's `DomainStamp` `last_published_at` and `last_session_uid`, falling back to live API calls otherwise, and tracking intra-plan virtual state) and verify unit tests in `tests/test_cpcrud_state_reader.py` pass

## 3. `Differ`, Rule Identity, Cleanup-Aware Positioning, and `Planner` (`differ.py`, `rule_identity.py`, `position_helper.py`, `planner.py`)

- [x] 3.1 Implement `src/arodonata/cpcrud/differ.py`, `src/arodonata/cpcrud/rule_identity.py` (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`, traffic tuple matching), `src/arodonata/cpcrud/position_helper.py` (cleanup-rule-aware `"bottom"` placement anchoring `{"above": "<cleanup_rule_uid>"}`), and `src/arodonata/cpcrud/planner.py` (`Planner` with pre-lookup `DomainStamp` acquisition, two-axis `NameConflictPolicy` x `IpConflictPolicy`, `NamingPrefixes` auto-naming, and `Outcome.ERROR` + `skipped_dependency` on lookup failure) and verify unit tests in `tests/test_cpcrud_planner.py` pass

## 4. Dedicated-Session `Executor` and Compensating Rollback `inverse` (`executor.py`, `inverse.py`, `service.py`)

- [x] 4.1 Implement `src/arodonata/cpcrud/executor.py` (`Executor.apply` and `Executor.stream_apply` with `Outcome.PLAN_STALE` safeguard, per-domain isolated `WriteSession` and `SessionOverlay` updates, `no_publish=True, keep_session=True` staging with `StagedSessionEvent`, post-publish `invalidate_domain`, and `retry_remaining` folding), `src/arodonata/cpcrud/inverse.py` (`build_inverse_template`), and `src/arodonata/cpcrud/service.py` (`CPCRUDService`) and verify unit tests in `tests/test_cpcrud_executor.py` and `tests/test_cpcrud_inverse.py` pass

## 5. Facade Wiring in `ArodonataClient` and Final Quality Gates

- [x] 5.1 Wire `CPCRUDService` (`client.cpcrud`) into `src/arodonata/client.py` and export public CPCRUD symbols in `src/arodonata/__init__.py` and `src/arodonata/cpcrud/__init__.py`, update `tests/test_client.py`, and pass all quality gates
