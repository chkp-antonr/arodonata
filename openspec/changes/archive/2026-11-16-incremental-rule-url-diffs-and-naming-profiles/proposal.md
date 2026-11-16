# Proposal: Incremental Rule and URL-List Diffs, Naming Profiles, and Dry-Run Plan ChangeReports

## Why

Downstream automation and interactive policy/object editors (such as MMP's Object Updater and Rule Creator) require three foundational capabilities inside `arodonata`: (1) configurable customer naming profiles resolved from `os.environ` (supporting compressed same-`/24` address-range names like `Range_10.1.1.1_9`, group suffixes like `GroupName_Grp`, and Check Point-safe wildcard application-site names like `Site__chinacloudapi.cn` for `*chinacloudapi.cn` / `*.chinacloudapi.cn`) alongside a canonical expression parser and value-first reuse for legacy-named objects; (2) incremental `{"add": [...], "remove": [...]}` patch operations for `application-site` `url-list` and policy rule list cells (`source`, `destination`, `service`, and future rule types `protected-scope`, `site-category`, `install-on`) with strict guards preventing accidental widening to `"Any"` or unintended creation when updating missing targets; and (3) offline synthesis of SmartConsole-styled `ChangeReport` evidence directly from a `CPCRUDService` Dry-Run `Plan`.

## What Changes

- **Environment-Backed `NamingPrefixes` & Shorthand Expression Parser (`configuration`, `cpcrud`)**:
  - Extend `NamingPrefixes` (`src/arodonata/core/config.py`, re-exported via `src/arodonata/cpcrud/models.py`, and `checkpoint_ops_schema.json`) with `range_separator: str = "-"`, `compress_range_same_subnet: bool = False`, `group: str = "grp"` (allowing `""` when `group_suffix` is configured), `group_suffix: str = ""`, `app_site: str = "Site_"`, and `app_site_wildcard_marker: str = "_"`, plus `format_group(base_name)` and `format_app_site(domain, *, is_wildcard: bool = False)` (producing `Site__chinacloudapi.cn` for `*chinacloudapi.cn` and `*.chinacloudapi.cn`).
  - Extend `ArodonataSettings` (`src/arodonata/core/config.py`) with an `ARODONATA_CPCRUD_*` (and secondary `CPCRUD_*`) backed `cpcrud_naming_prefixes` profile resolved from `os.environ` without implicit `.env` file loading, used as the default in `CPCRUDService` / `Planner` when callers omit `naming_prefixes`.
  - Add `src/arodonata/cpcrud/expressions.py` (re-exported via `arodonata.cpcrud`) providing pure parsing of shorthand expressions: hosts (`Host_10.1.1.1` / `10.1.1.1`), networks (`Net_10.1.1.0_24` / `10.1.1.0/24`), full and last-octet shorthand IPv4 ranges (`Range_10.1.1.1_9`, `10.1.1.1-9`, `10.1.1.1-10.1.1.9`), DNS domains (`.abc.com`), wildcard `application-site` entries (`*chinacloudapi.cn`, `*.chinacloudapi.cn`, and `SiteName(*d1, *.d2)` producing `["\\/<escaped>", "\\.<escaped>"]`), TCP/UDP/ICMP services, and inline groups (`GroupName_Grp(m1, m2)`).
- **Incremental `application-site` `url-list` Updates & Value-First Reuse (`cpcrud`)**:
  - Extend `ObjectOperation` and `ServiceOperation` in `checkpoint_ops_schema.json` so `url_list` / `url-list` accepts either `string[]` or `{"add": [...], "remove": [...]}`.
  - Update `differ.py` (`compute_object_diff`) and `planner.py` to compute idempotent `url-list` add/remove deltas, fail closed (`Outcome.ERROR`) when a removal would leave `url-list` empty without `application-signature`, fail closed (`Outcome.ERROR`) when `operation in ("set", "update")` targets an absent object, and reuse legacy-named `application-site` objects by normalized `(urls_defined_as_regular_expression, frozenset(url_list))` when `on_ip_conflict="reuse"`.
- **Incremental Rule List-Cell Diffs & Safety Invariants (`cpcrud`)**:
  - Extend `RuleOperation` in `checkpoint_ops_schema.json`, `differ.py`, `planner.py`, `executor.py`, `inverse.py`, and `testing/_emulator_crud.py` so list-valued rule cells (`source`, `destination`, `service`, `protected_scope`/`protected-scope`, `site_category`/`site-category`, `install_on`/`install-on`) accept `{"add": [...], "remove": [...]}` with `name_resolutions` substitution and `depends_on` dependency ordering.
  - Enforce safety guards in `Planner` and `Differ`:
    - Fail closed (`Outcome.ERROR`) when `operation in ("set", "update")` targets a missing rule, group, service, or object instead of silently creating a new entity, and fail closed when an unmatched rule carries incremental `{add, remove}` cell deltas under any verb (including `present`).
    - Fail closed (`Outcome.ERROR`) when an incremental removal would empty a rule list cell (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`) and silently widen the rule to `"Any"`.
    - Fail closed (`Outcome.ERROR`) when an incremental `add` targets a rule cell currently set to `"Any"` unless `"Any"` is explicitly listed in `remove` (and fail closed if `"Any"` itself is passed in incremental `add`, while stripping `"Any"` from Check Point wire `remove`).
    - Dereference UIDs via `obj_dict` when recording `_build_prior_rule_state` so `CPCRUDService.inverse()` generates clean compensating `set-*-rule` templates.
  - Update `FileReplayApiMock` (`src/arodonata/testing/_emulator_crud.py`) so `set-application-site` and `set-*-rule` faithfully process `{"add": [...], "remove": [...]}` patches in replay tests.
- **Offline Dry-Run `ChangeReport` Synthesis from `Plan` (`change-reports`)**:
  - Add `build_change_report_from_plan(plan: Plan, *, title: str | None = None, header_fields: Mapping[str, str] | None = None) -> ChangeReport` in `src/arodonata/reports/` (re-exported via `arodonata.reports`) so callers can render SmartConsole-styled HTML/Markdown/JSON Dry-Run Evidence with `render_change_report` before opening any Check Point write session.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `configuration`: Resolve `cpcrud_naming_prefixes` in `ArodonataSettings` from `ARODONATA_CPCRUD_*` and secondary `CPCRUD_*` environment variables (without implicit `.env` loading), including compressed range naming, group suffixes, and wildcard application-site markers.
- `cpcrud`: Add `NamingPrefixes` formatting enhancements, `arodonata.cpcrud.expressions` shorthand parser, incremental `{add, remove}` diffs for `application-site` `url-list` and rule list cells (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), strict `set`/`update` existence checks, anti-`Any`-widening guards, value-first reuse, `inverse()` rollback support, and `FileReplayApiMock` incremental mutation handling.
- `change-reports`: Add offline `build_change_report_from_plan(plan, ...)` to synthesize a `ChangeReport` (with `ObjectChangeEntry` and `RuleChangeEntry` `FieldDiff` `added_items`/`removed_items`) directly from a `Plan` for `render_change_report`.

## Impact

- `src/arodonata/core/config.py`: `NamingPrefixes` integration (`cpcrud_naming_prefixes` field + `ARODONATA_CPCRUD_*` / `CPCRUD_*` aliases).
- `src/arodonata/cpcrud/`: `models.py`, `expressions.py` (new), `checkpoint_ops_schema.json`, `differ.py`, `planner.py`, `inverse.py`, `service.py`, `state_reader.py`, `__init__.py` (plus `src/arodonata/__init__.py` re-exports if appropriate).
- `src/arodonata/reports/`: `plan_report.py` (new) or `renderer.py` + `__init__.py` (`build_change_report_from_plan`).
- `src/arodonata/testing/_emulator_crud.py`: incremental `url-list` and rule cell `{add, remove}` support for `FileReplayApiMock`.
- `tests/`: unit and replay tests covering naming profiles, expression parsing, incremental `url-list` and `access-rule` / `threat-rule` / `https-rule` diffs, safety guards, `inverse()`, and Dry-Run `ChangeReport` rendering.
