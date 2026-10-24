# Tasks: Milestone 4 — Rulebase Introspection, SmartConsole Numbering, and Auditable Change Reports

## 1. Rulebase Domain Models and Section-Stitching Pager (`src/arodonata/rulebase/models.py`, `pager.py`)

- [x] 1.1 Implement `src/arodonata/rulebase/models.py` (`PolicyPackageInfo`, `NumberedRule`, `NumberedSection`, `NumberedLayerRulebase`, `PackageRulebase`, `RuleLocation`, `LayerPrefixLocation`, `RuleLocations`, `FilteredRulebaseResult`) and `src/arodonata/rulebase/pager.py` (`fetch_paged_rulebase` paging `show-*-rulebase` in chunks of up to 100 rules, resolving `objects-dictionary` references, merging split `rulebase-section` headers across page boundaries, and preserving empty trailing sections) and verify unit tests in `tests/test_rulebase_pager.py` pass

## 2. Atomic Rulebase Snapshot Refresh (`src/arodonata/rulebase/refresh.py`)

- [x] 2.1 Implement `src/arodonata/rulebase/refresh.py` (`RulebaseRefreshService` with paired `await refresh_rulebases` and `stream_refresh_rulebases`, shared-session dirty check refusing dirty sessions and marking `domain_sync_state.status = "failed"`, traversal of `show-packages`, NAT rulebases, access/HTTPS/threat layers, inline layers, and Global `place-holder` resolution in package context, and atomic snapshot replacement under per-domain lock) and verify unit tests in `tests/test_rulebase_refresh.py` pass

## 3. SmartConsole Hierarchical Numbering, Local Filtering, and `CachedRulebaseSource` (`numbering.py`, `filter.py`, `source.py`)

- [x] 3.1 Implement `src/arodonata/rulebase/numbering.py`, `src/arodonata/rulebase/filter.py`, `src/arodonata/rulebase/source.py`, and `src/arodonata/rulebase/__init__.py` (hierarchical SmartConsole numbering `1`, `2.1`, `2.2.1`, section ranges, and `"No Rules"`, `get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`, automatic domain resolution with `AmbiguousLayerName`, and local rulebase filtering over cached rules/objects/services) and verify unit tests in `tests/test_rulebase_numbering.py` pass

## 4. Auditable Session Change Reports (`src/arodonata/reports/`)

- [x] 4.1 Implement `src/arodonata/reports/models.py`, `src/arodonata/reports/placement.py`, `src/arodonata/reports/collector.py`, `src/arodonata/reports/renderer.py`, and `src/arodonata/reports/__init__.py` (`SessionScope`, `RangeScope`, `OwnedSession` with SID redaction, `collect_change_report` with UTC conversion, deduplication, `ReportWarning` handling, and bounded 200-UID `show-object` resolution, live `OwnedSession` read-only numbering and cached snapshot fallback, and `render_change_report` / `build_change_report` for self-contained HTML, Markdown, and versioned JSON) and verify unit tests in `tests/test_change_reports.py` pass

## 5. Facade Wiring in `ArodonataClient` and Final Quality Gates

- [x] 5.1 Wire `RulebaseRefreshService`, `CachedRulebaseSource`, and change report methods (`refresh_rulebases`, `stream_refresh_rulebases`, `get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`, `filter_rulebase`, `collect_change_report`, `render_change_report`, `build_change_report`) into `src/arodonata/client.py` and `src/arodonata/__init__.py`, update `tests/test_client.py`, and pass all quality gates
