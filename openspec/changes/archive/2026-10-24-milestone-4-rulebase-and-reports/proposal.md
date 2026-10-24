# Proposal: Milestone 4 — Rulebase Introspection, SmartConsole Numbering, and Auditable Change Reports

## Why

With the core hexagonal services and `ArodonataClient` facade in place from Milestone 3, Arodonata v2 requires the policy rulebase introspection and numbering subsystem (`src/arodonata/rulebase/`) and the auditable session change report subsystem (`src/arodonata/reports/`), wired directly into `ArodonataClient`. These capabilities allow downstream applications, operators, and MCP tools to cache full multi-domain policy rulebases atomically, compute SmartConsole-identical hierarchical rule and section numbers (`1`, `2.1`, `2.2.1`, `No Rules`), filter cached rulebases locally without Check Point round-trips, and produce tamper-resistant, self-contained HTML, Markdown, and JSON change evidence reports across published or live unpublished sessions.

## What Changes

- Implement `src/arodonata/rulebase/pager.py`:
  - Paginated rulebase reader (`fetch_paged_rulebase`) querying `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, and `show-threat-rulebase` in chunks of up to 100 rules.
  - Boundary-split `rulebase-section` merging when Check Point repeats a section header across consecutive page boundaries, preserving rule ordering and recovering empty trailing sections.
- Implement `src/arodonata/rulebase/refresh.py` (`RulebaseRefreshService`):
  - Paired `await refresh_rulebases(...)` and `stream_refresh_rulebases(...)` methods integrated with `DomainSyncCoordinator` (`scope="rulebase"`, `item_types=["*"]`).
  - Shared-session dirty check (`locks == 0` and `number-of-published-changes == 0`), refusing to overwrite cached snapshots on dirty sessions and recording `domain_sync_state.status = "failed"` with `last_error`.
  - Complete traversal of `show-packages`, NAT rulebases for packages with `nat-policy`, ordered access/HTTPS/threat layers, standalone layer listings (`show-access-layers`, `show-https-layers`, `show-threat-layers`), inline layers referenced by rules, and `Global` layer `place-holder` resolution in `package` context.
  - Atomic domain snapshot replacement (`CachePort.replace_domain_rulebase`) under the per-domain distributed lock (`sync:{mgmt_name}:{domain_name}:rulebase`).
- Implement `src/arodonata/rulebase/numbering.py`, `src/arodonata/rulebase/filter.py`, and `src/arodonata/rulebase/source.py` (`CachedRulebaseSource`):
  - Dynamic SmartConsole hierarchical rule and section numbering (`1`, `2`, `2.1`, `2.2.1`, section ranges `1-2`, `2.1-2.2`, or `"No Rules"`) for both package context (`get_package_rulebase`) and standalone layer context (`get_layer_rulebase`).
  - Policy package introspection (`get_policy_packages`) and cross-package/layer rule & layer locator (`locate_rules` returning `RuleLocations` with `snapshot_session_uid`, `snapshot_published_at`, and sync status).
  - Automatic domain resolution for domainless calls (`domain_name=None` or `""`), raising `AmbiguousLayerName` listing all `(domain, uid)` candidates when multiple domains match.
  - Local rulebase filtering (`filter_rulebase`) evaluating text, IP/CIDR, object/group, and service filters locally against the cached rulebase snapshot and cached `CPObject` / `CPService` models in `markdown`, `model_friendly`, or `raw` format.
- Implement `src/arodonata/reports/` (`models.py`, `collector.py`, `placement.py`, `renderer.py`):
  - Strict scope validation (`SessionScope`, `RangeScope`, `OwnedSession`, `RenderOptions`) raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes.
  - `collect_change_report`: timezone-aware date conversion to UTC, safe query window widening, exact UTC publish-time filtering, session deduplication across scopes, bounded `show-object` UID name resolution (up to 200 distinct UIDs per report with `names_unresolved` `ReportWarning`), and resilient `ReportWarning` recording on partial runtime failures.
  - `placement.py`: SmartConsole rule placement numbering for added, modified, moved, and deleted rules using either a caller-supplied unpublished `OwnedSession` (verified via `show-session`, strictly read-only, with complete SID redaction and `"Numbering read live in the owned session at <time> UTC"` basis) or graceful fallback (`owned_session_not_used` / `owned_session_error` warning) to the cached rulebase snapshot.
  - `render_change_report` and `build_change_report`: offline rendering into `"html"` (self-contained UTF-8 `bytes` with inline CSS, zero `<script>` tags, zero external assets, `NEW` / `DELETED` / yellow field diff / moved / disabled `✗` indicators, and per-rule field diff detail tables), `"markdown"`, and `"json"` (round-trip `ChangeReport` with `format_version` validation), raising `UnsupportedFormat` for `"pdf"` and escaping all Check Point strings while supporting safe inline markdown in `RenderOptions.title` and `header_fields`.
- Wire rulebase and change report methods into `ArodonataClient` (`src/arodonata/client.py`) and export public types in `src/arodonata/__init__.py`.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specifications. -->

### Modified Capabilities

<!-- None: skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/rulebase/` (`__init__.py`, `models.py`, `pager.py`, `refresh.py`, `numbering.py`, `filter.py`, `source.py`) and `src/arodonata/reports/` (`__init__.py`, `models.py`, `collector.py`, `placement.py`, `renderer.py`), and updates `src/arodonata/client.py` and `src/arodonata/__init__.py`.
- **Tests**: Adds comprehensive unit tests in `tests/test_rulebase_pager.py`, `tests/test_rulebase_refresh.py`, `tests/test_rulebase_numbering.py`, and `tests/test_change_reports.py`.
