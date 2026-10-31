# Design

## Context

See `proposal.md` (`Why`) for motivation and `specs/change-reports/spec.md` for normative requirements.

Live verification against Check Point R82 (`show-changes` with `{"to-session": s_uid, "details-level": "full"}`) established three concrete wire-format behaviors that `arodonata.reports` must handle:

1. **No `field-changes` key in live payloads**: Every entry in `operations["modified-objects"]` contains `{"new-object": {...}, "old-object": {...}}` snapshots without an explicit `field-changes` list.
2. **Asymmetric reference representations across rules and groups**:
   - Rule list cells (`source`, `destination`, `service`, `install-on`, `vpn`, `content`, `time`) embed full object dictionaries (`{"uid": "...", "name": "...", "type": "..."}`), including nested `members` arrays when a rule cell points to a `group`.
   - `group.members` inside both `old-object` and `new-object` contains **bare UUID strings** (`["4377dc76-...", ...]`) even at `details-level: "full"`.
3. **Background `"System"` maintenance objects in inter-session deltas**: When an administrator publishes a session after automatic Check Point background updates (such as nightly Trusted CA bundle updates or IPS updates), `show-changes` includes `"System"`-modified internal objects (`IpsProtectionUserSettings` with `name: null`, `cp-trusted-ca-certificate`, `TrustedCaPackageConf`, and typeless `type: ""` objects with `meta-info.last-modifier == "System"`).

## Goals / Non-Goals

**Goals:**

- Synthesize accurate `FieldDiff` records from `old-object` vs `new-object` snapshots for rules and policy objects while preserving compatibility with explicit `field-changes` payloads.
- Avoid false-positive rule cell diffs when a referenced group's internal membership changes in the same session.
- Index nested `{uid, name}` dictionaries across `old-object` and `new-object` and resolve bare UUIDs appearing only in `old-object` (such as removed group members) via `CachePort` and bounded `show-object` calls (`MAX_UID_LOOKUPS = 200`).
- Exclude background `"System"` maintenance non-rule objects by default (`RenderOptions.include_system_objects = False`) while preserving complete `ChangeReport.raw_responses`.
- Surface removed, added, and replaced objects inline inside HTML and Markdown `Rule Changes` and `Object Changes` cells without breaking `format_version = 1` JSON round-trip serialization.

**Non-Goals:**

- Incrementing `CURRENT_FORMAT_VERSION` beyond `1` or adding duplicate pre-rendered fields to `RuleChangeEntry` / `ObjectChangeEntry`.
- Mutating `CachePort` tables during `collect_change_report`.
- Expanding a referenced group's internal member diff inside every rule cell that references that group (group member diffs belong on the group's own `ObjectChangeEntry`).

## Decisions

### 1. Reference-Identity Snapshot Diffing Merged with Explicit `field-changes`

In `src/arodonata/reports/collector.py`:

- Parse explicit `field-changes` / `field_changes` / `fields` / `diff` first via `_extract_field_diffs()` and record their lowercase `field_name` set.
- When `op == "modified"` and `old_core` is a non-empty `dict`, synthesize `FieldDiff` entries for tracked fields not already in that set:
  - **Rule list-reference fields** (`source`, `destination`, `service`, `install-on`, `protected-scope`, `vpn`, `content`, `time`, `blade`, `site-category`): extract `old_refs` and `new_refs` using `_extract_ref_list(..., known_names, bare_uids_out)` (treating empty/missing rule match cells `source`, `destination`, `service` consistently with their effective list representation). If `old_refs != new_refs`, emit `FieldDiff` with `old_value=old_refs`, `new_value=new_refs`, `removed_items=[x for x in old_refs if x not in set(new_refs)]`, and `added_items=[x for x in new_refs if x not in set(old_refs)]` (order-preserving, deduplicated).
    - *Why reference-name/UID comparison over raw dict comparison*: Comparing extracted reference identities ignores volatile `meta-info` timestamps and internal `group.members` changes inside embedded group dicts on rules whose cell reference (`["t_grp_clients_G"]`) did not change, while capturing both partial removals (`["t_grp_servers_G", "t_ar03_G"]` to `["t_grp_servers_G"]` -> `removed_items=["t_ar03_G"]`) and sole-member `Any` replacements (`["t_h02_G"]` to `["Any"]` -> `removed_items=["t_h02_G"]`, `added_items=["Any"]`).
  - **Rule scalar and single-reference fields** (`enabled`, `name`, `action`, `method`, `track`, `comments`, `source-negate`, `destination-negate`, `service-negate`, `original-source`, `original-destination`, `original-service`, `translated-source`, `translated-destination`, `translated-service`): extract references on both `old_core` and `core` via `_extract_ref_str_or_uid(...)` (normalizing `track` via `track.get("type") or track` when `dict`), skip fields absent from both snapshots, and emit `FieldDiff(field_name=..., old_value=old_v, new_value=new_v)` when `old_v != new_v`.
  - **Non-rule object fields**:
    - List fields (`members`, `groups`, `tags`): extract `old_refs` and `new_refs` via `_extract_ref_list(...)` and emit `FieldDiff` with `added_items` and `removed_items` when `old_refs != new_refs`.
    - Scalar fields (`name`, `ipv4-address`, `ipv6-address`, `subnet4`, `subnet6`, `mask-length4`, `mask-length6`, `subnet-mask`, `ipv4-address-first`, `ipv4-address-last`, `ipv6-address-first`, `ipv6-address-last`, `port`, `protocol`, `fqdn`, `comments`, `color`): skip fields absent from both snapshots and emit `FieldDiff(field_name=..., old_value=old_v, new_value=new_v)` when `old_v != new_v`.
- Re-evaluate `moved` / `eff_op` using the merged `f_diffs` list so a rule that moved **and** changed a tracked field stays `"modified"` (`moved=True`), whereas a rule that only changed `rule-number` / `position` remains `"moved"`.

*Alternative considered*: Generic recursive JSON diff across all keys of `old-object` and `new-object`. Rejected because Check Point objects include dozens of internal/volatile keys (`meta-info`, `read-only`, `available-actions`, `icon`, nested group `members`) that produce noisy, non-actionable diffs.

### 2. Recursive `{uid, name}` Harvesting and `old-object` Bare-UID Resolution

- Extend `_collect_known_names_from_operations()` with a bounded recursive traversal (for example, depth limit `6`) over operation items, `new-object`, and `old-object` structures to record every `{uid, name}` pair into `known_names` before UID lookup budgeting runs.
- Because Decision 1 passes `old_core` fields through `_extract_ref_list()` and `_extract_ref_str_or_uid()`, any bare UUID present only in `old-object` (such as a member UUID removed from `group.members` or a bare reference removed from a rule cell) is automatically added to `bare_uids_out`.
- Existing Step 3 in `collect_change_report()` resolves `unresolved_uids` via `global_resolved_uids` -> `cache.get_object_by_uid()` -> `cache.get_service_by_uid()` -> bounded `show-object` (`MAX_UID_LOOKUPS = 200`), and `_replace_resolved_uids_in_session()` substitutes resolved names across `FieldDiff.old_value`, `FieldDiff.new_value`, `FieldDiff.added_items`, `FieldDiff.removed_items`, and `ObjectChangeEntry.summary`.

### 3. Enriched Object Summaries and `"System"` Maintenance Noise Filtering

- **Object summaries**: Expand `_build_object_summary(core, members)` to format:
  - `ipv4-address`, `ipv6-address`
  - `subnet4` (with `/mask-length4` CIDR suffix when `mask-length4` is present, or `subnet-mask`), `subnet6` (with `/mask-length6` when present)
  - `ipv4-address-first`..`ipv4-address-last` as `range=<first>-<last>` (and IPv6 equivalent)
  - `port`, `protocol`, `fqdn`
  - `members=[...]` when non-empty
  - `comments=...` when non-empty on added/deleted objects (or when unchanged on modified objects; modified comments render as inline diffs).
- **Background `"System"` object filtering**:
  - Add `include_system_objects: bool = False` to `RenderOptions` (`src/arodonata/reports/models.py`).
  - Pass `session_user_name` (from `s_meta_dict.get("user-name") or s_meta_dict.get("user")` or the `changes[].session.user-name` block) and `include_system_objects=eff_opts.include_system_objects` into `_parse_rule_and_object_changes()`.
  - Never filter `is_rule` entries. For non-rule entries, when `not include_system_objects`, skip entries where `meta-info.last-modifier == "System"` (checked on `core` or `old_core`) and either:
    1. `session_user_name` is non-empty and `session_user_name.strip().lower() != "system"`, or
    2. the entry has an empty/null `name` or empty `type` (internal records such as `IpsProtectionUserSettings`, `TrustedCaPackageConf`, or `type == ""`).

*Alternative considered*: Hardcoded denylist of Check Point internal class names (`IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, `TrustedCaPackageConf`). Rejected as sole mechanism because Check Point adds internal `"System"` classes across R81.20/R82/R82.10 blades; keying on `meta-info.last-modifier == "System"` relative to a non-`"System"` `session_user_name` (plus nameless/typeless `"System"` records) generalizes cleanly across blades while keeping an explicit `include_system_objects=True` escape hatch.

### 4. Inline Cell Diff Rendering and SmartConsole Visual Layout Driven Purely by `field_diffs`

All HTML and Markdown inline diffs in `src/arodonata/reports/renderer.py` derive solely from `rc.field_diffs` and `oc.field_diffs` (no schema changes to `RuleChangeEntry` or `ObjectChangeEntry`):

| Surface | HTML Inline Presentation | Markdown Inline Presentation |
| --- | --- | --- |
| Modified list cell (`source`, `destination`, `service`, `members`) | Kept items plain; removed items `<span class="diff-removed">- name</span>`; added/replacement items `<span class="diff-added">+ name</span>` | Kept items plain, `[-name]`, `[+name]` |
| Modified `enabled` cell | `<span class="diff-removed">✓</span><span class="diff-arrow">→</span><span class="disabled-marker" title="Disabled">✗</span>` (or `✗ → ✓`) | `✓ -> ✗` (or `✗ -> ✓`) |
| Modified scalar / single-ref cell (`name`, `action`, `method`, `track`, `comments`, NAT `original-*` / `translated-*`) | `<span class="diff-removed">old</span><span class="diff-arrow">→</span><span class="diff-highlight">new</span>` (or `<span class="diff-added">+ new</span>` when `old` was empty) | `old -> new` (or `[+new]` when `old` was empty) |
| Modified `Object Changes` `Details` cell | Static identity summary (`ipv4-address=...`, `range=...`) + inline `members` and scalar (`comments`, IP/port) diffs | Static identity summary + inline `members=[..., [-removed], [+added]]` and `field: old -> new` |

- **SmartConsole Visual Styling in HTML**:
  - **Dark Navy-Slate Table Headers (`thead th`)**: Background `#253245`, text `#ffffff`, border `1px solid #37475e`, matching SmartConsole column headers (`No.`, `Status`, `Enabled`, `Name`, `Source`, `Destination`, `Services & Applications`, `Action`, `Track`, `Comments`).
  - **Yellow Access Section Banner Rows (`tr.section-row td`)**: Instead of repeating `Layer / Section` as a column in every HTML row, group consecutive rules sharing `(layer, section_name, section_range)` under a full-width `<tr class="section-row"><td colspan="10">▾ ...</td></tr>` row on a warm pale-yellow background (`#eee8aa`, border `#d4c87a`, text `#262626`) showing `▾ <section_name> (<section_range>)` and layer context (or `▾ <layer_name>` when unsectioned).
  - **Rule Number Column (`td.col-num`)**: Light cool-gray background (`#f1f3f5`), centered rule number (`1`, `2`, `—`).
  - **Action Indicators**: Green indicator (`<span class="action-accept">●</span>`) for `Accept` and red indicator (`<span class="action-drop">●</span>`) for `Drop` / `Reject`.
- Inline CSS additions remain 100% self-contained (`<style>` block only, zero `<script>`, WCAG-friendly red/green/amber contrast matching existing `.badge-deleted` / `.badge-new` / `.badge-modified` tokens).
- Every string interpolated into `.diff-removed`, `.diff-added`, `.diff-highlight`, or `.section-row` passes through `_esc_html()` / `_esc_md()` before wrapping in HTML tags or Markdown brackets.
- Existing `Field Diffs for Rule ...` and `Field Diffs for Object ...` sub-tables remain gated by `options.include_field_diffs` (now populated on live Check Point sessions as well!).

## Risks / Trade-offs

- **[Risk] Permanently deleted object referenced only by bare UUID in `old-object.members` of a historical session** → If the object was deleted in an earlier session and is absent from both `CachePort` and the current session's `deleted-objects`, `show-object` returns not-found. **Mitigation**: Existing bounded lookup records a `names_unresolved` `ReportWarning` and renders the raw UUID string cleanly without aborting report collection.
- **[Risk] Long before/after `comments` strings widen the `Comments` or `Details` column** → **Mitigation**: Omit the empty `old →` prefix when `old_value` was `""` (rendering `+ <new comment>` instead), and allow normal table cell wrapping in CSS while preserving full untruncated audit strings (`[DECOMM: ...]`, `[CTASK...]`).
- **[Risk] Synthetic test fixtures supplying both `field-changes` and `old-object` / `new-object`** → **Mitigation**: Merge explicit `field-changes` first by normalized field name and synthesize snapshot diffs only for remaining changed fields, keeping existing assertions deterministic while enriching uncovered changed fields (such as `enabled` or `source`).

## Migration Plan

1. Add `include_system_objects: bool = False` to `RenderOptions` in `src/arodonata/reports/models.py` (`CURRENT_FORMAT_VERSION = 1` unchanged).
2. Implement recursive `{uid, name}` harvesting, `old-object` vs `new-object` `FieldDiff` synthesis, `"System"` maintenance object filtering, and enriched object summaries in `src/arodonata/reports/collector.py`.
3. Implement inline HTML and Markdown cell diff helpers and CSS classes in `src/arodonata/reports/renderer.py`.
4. Add unit tests (`tests/unit/test_change_reports.py`) modeled directly on live Check Point R82 `show-changes` payloads and extend live Bucket 5 integration assertions (`tests/integration/b5/test_change_report_session.py`).
5. Downstream consumers (including MMP Decom evidence generation) require zero API call changes; rollback is a pure code revert with no database schema migration.
