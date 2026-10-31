# Proposal

## Why

Live Check Point R82 `show-changes` responses do not emit an explicit `field-changes` array on `modified-objects` entries; instead, Check Point returns full `new-object` and `old-object` snapshots (and sweeps background `"System"` maintenance objects such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, and `TrustedCaPackageConf` into inter-session deltas). Because `arodonata.reports.collector` only inspects `field-changes` and discards `old-object` contents, `field_diffs` is always empty on live servers and `render_change_report` renders only post-change cell values (such as `Destination: Any` or remaining group members), completely hiding which decommissioned objects were removed or replaced.

## What Changes

- **Synthesize `FieldDiff`s from `old-object` vs `new-object` Snapshots**:
  - Update `arodonata.reports.collector` to compute structured `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) directly from `old-object` and `new-object` whenever explicit `field-changes` do not already cover a modified field (merging cleanly with any explicit `field-changes` payload).
  - Compare tracked list-reference rule fields (`source`, `destination`, `service`, `install-on`, `protected-scope`, `vpn`, `content`, `time`, `blade`, `site-category`) by resolved reference names/UIDs so partial removals (for example, removing 1 of 2 objects from `destination`) and sole-member replacements with `Any` (for example, `["t_h02_G"]` to `["Any"]`, yielding `removed_items=["t_h02_G"]` and `added_items=["Any"]`) are explicitly captured without producing false-positive diffs when an unchanged referenced group has internal member edits.
  - Compare tracked scalar and single-reference rule fields (`enabled`, `name`, `action`, `method`, `track`, `comments`, `source-negate`, `destination-negate`, `service-negate`, and NAT `original-source`, `original-destination`, `original-service`, `translated-source`, `translated-destination`, `translated-service`) and tracked non-rule object fields (`members`, `ipv4-address`, `ipv6-address`, `subnet4`, `subnet6`, `mask-length4`, `mask-length6`, `subnet-mask`, `ipv4-address-first`, `ipv4-address-last`, `ipv6-address-first`, `ipv6-address-last`, `port`, `protocol`, `fqdn`, `comments`, `color`, `tags`, `groups`).
- **Pre-Change (`old-object`) UID Indexing and Bare-UID Name Resolution**:
  - Recursively index `{uid, name}` dictionaries embedded inside both `old-object` and `new-object` trees in `_collect_known_names_from_operations()` before spending `show-object` lookups.
  - Queue bare UUID references appearing only in `old-object` (such as removed `group.members` UUIDs, which Check Point `show-changes` returns as bare UUID strings even at `details-level: "full"`) into `bare_uids` so they resolve to human-readable object names via `CachePort` and bounded `show-object` lookups (`MAX_UID_LOOKUPS = 200`).
- **Richer Object Summaries and Background `"System"` Noise Filtering**:
  - Expand `ObjectChangeEntry.summary` to include `address-range` bounds (`ipv4-address-first`..`ipv4-address-last`, `ipv6-address-first`..`ipv6-address-last`), IPv6 and CIDR mask attributes (`ipv6-address`, `subnet4/mask-length4`, `subnet6/mask-length6`), and `comments` when present.
  - Filter out background Check Point `"System"` maintenance non-rule objects (`meta-info.last-modifier == "System"` when the target session's `user-name` is known and not `"System"`, or nameless/typeless `System` internal records) by default, gated by `RenderOptions.include_system_objects: bool = False`, while preserving unfiltered `ChangeReport.raw_responses` for forensic auditability.
- **Inline Cell Diff Rendering and SmartConsole Visual Table Styling in HTML and Markdown**:
  - Upgrade `arodonata.reports.renderer` so `Rule Changes` and `Object Changes` cells display removed, added, and replaced values inline right inside the main tables (for example, red struck-through `- t_h02_G` removal badges alongside `+ Any` or remaining items in `Source` / `Destination` / `Service` and group `members`, `✓ → ✗` for `Enabled`, `old → new` transitions for NAT / `Action` / `Track` / scalar fields, and inline member/comment diffs in `Object Changes` `Details`), in addition to the existing per-rule and per-object `Field Diffs` detail tables (`include_field_diffs=True`).
  - Style HTML evidence tables to visually mirror Check Point SmartConsole: dark navy-slate column headers (`#253245` background, white bold text), full-width pale-yellow access section banner rows (`<tr class="section-row">` on `#eee8aa` background displaying `▾ <section_name> (<section_range>)` and layer context), a shaded gray `No.` rule-number column (`.col-num` on `#f1f3f5`), SmartConsole column headers (`No.`, `Status`, `Enabled`, `Name`, `Source`, `Destination`, `Services & Applications`, `Action`, `Track`, `Comments`), and visual action indicators (`Accept` / `Drop` / `Reject`).
  - Maintain strict HTML/Markdown escaping, self-contained inline CSS with zero `<script>` tags, and full `format_version = 1` JSON round-trip compatibility.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `change-reports`: Synthesize per-field rule and object `FieldDiff` entries (including `added_items` and `removed_items`) from `old-object` and `new-object` snapshots when explicit `field-changes` are absent or partial, resolve bare reference UIDs appearing only in `old-object` (such as removed group members), filter background `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects=True`, enrich `ObjectChangeEntry.summary`, and render inline before/after and added/removed indicators directly inside SmartConsole-styled HTML and Markdown `Rule Changes` and `Object Changes` tables.

## Impact

- **Report Models (`src/arodonata/reports/models.py`)**: Adds `include_system_objects: bool = False` to `RenderOptions` (`format_version = 1` schema remains backward-compatible).
- **Collector (`src/arodonata/reports/collector.py`)**: Synthesizes rule and object `FieldDiff`s from `old-object` vs `new-object`, recursively harvests `{uid: name}` pairs from `old-object`/`new-object` trees, resolves removed bare UIDs via `CachePort` / `show-object`, enriches `ObjectChangeEntry.summary`, and filters background `"System"` maintenance non-rule objects by default.
- **Renderer (`src/arodonata/reports/renderer.py`)**: Adds SmartConsole table styling (`th` on `#253245`, yellow `tr.section-row` access section headers on `#eee8aa`, gray `.col-num` column, `Track` column, and action indicators), inline diff styling (`.diff-removed`, `.diff-added`, `.diff-arrow`), and cell-level inline diff formatting in HTML and Markdown for modified rules and objects while preserving strict escaping and `Field Diffs` sub-tables.
- **Tests (`tests/unit/test_change_reports.py`, `tests/integration/b5/test_change_report_session.py`)**: Adds unit and live-schema regression coverage for Check Point R82 `old-object`/`new-object` payloads without `field-changes`, sole-member-to-`Any` decommissioning, partial rule cell removals, bare-UUID group member removals, `"System"` noise filtering, and inline HTML/Markdown diff escaping.
