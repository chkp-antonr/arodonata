# Design

## Context

`arodonata.reports` collects Check Point session change evidence (`collect_change_report`) and enriches rule changes with SmartConsole hierarchical numbering and package/layer/section context (`apply_session_rule_placement`). Originally, `placement.py` assumed only two operating modes:

1. **Pre-publish (`OwnedSession`)**: Caller passes an unpublished `OwnedSession(sid=..., server_ip=...)` before calling `publish`; `show-session {}` on `sid` returns `uid == session_uid` and `state == "open"`.
2. **Historical post-publish (`CachePort`)**: Caller passes no `OwnedSession` and relies on `arodonata_rulebase_*` tables having been previously populated by `refresh_rulebases()`.

In real orchestration workflows (`publish` -> `collect_change_report(owned_sessions=...)` -> `logout`), callers publish first so the evidence captures `State: published` and the exact server `Published` timestamp, and then reuse the still-open `sid` to collect the report before logging out. Furthermore, callers that only sync object caches (`refresh_objects`) without pre-syncing rulebases (`refresh_rulebases`) hit cold `arodonata_rulebase_*` tables, producing `"Numbering from cached rulebase snapshot (unavailable)"`, `—` rule numbers, raw layer UUIDs, and superfluous numbering banners even on object-only deletion sessions.

## Goals / Non-Goals

**Goals:**

- Enable zero-warning live rulebase numbering immediately after `publish` (before `logout`) using the caller's still-open `OwnedSession`.
- Eliminate unnecessary API/cache queries and `.basis-banner` / `Numbering Basis` noise when a session has zero `rule_changes`.
- Automatically recover from a cold local rulebase cache when `rule_changes` exist by fetching the published rulebase read-only via `ApiPort` and best-effort warming `CachePort.replace_domain_rulebase`.
- Resolve bare `layer_uid` UUIDs via cache and bounded `show-object` lookups in `collector.py` so `Layer / Section` never displays a raw UUID when the layer object is resolvable.
- Preserve strict SID redaction hygiene (`redact_sid`, `sanitize_mapping`) and `format_version = 1` JSON backward compatibility.

**Non-Goals:**

- Modifying `publish`, `discard`, or `logout` lifecycle ownership — `arodonata.reports` remains strictly read-only with respect to Check Point sessions.
- Changing `ChangeReport.format_version` (existing serialized v1 JSON reports remain 100% valid).

## Decisions

### Decision 1: Three-way `OwnedSession` classification in `apply_session_rule_placement`

When `session_report.rule_changes` is non-empty and `owned_session` is provided, `show-session {}` is called on `owned_session.sid`:

1. **Unpublished target match (`live_uid == session_uid` and not published/discarded)**:
   - Target session holds unpublished changes in `sid`.
   - Read live rulebase via `sid`, do **not** write to `CachePort` (contains uncommitted session overlay state), set `numbering_source = "owned_session"` and `numbering_basis = "Numbering read live in the owned session at <ts> UTC"`.
2. **Published target with clean `sid` (`target_is_published` and `live_state != "discarded"` and (`live_uid == session_uid` or `live_changes == 0`))**:
   - Here `target_is_published` is `session_report.state.strip().lower() == "published" or session_report.published_at is not None`, and `live_changes = int(s_data.get("changes") or 0)`.
   - After Check Point `publish`, `sid` rotates to a clean open session (`live_changes == 0`, `live_uid != session_uid`) viewing the newly published domain rulebase (or in test stubs echoes the published session itself with `live_changes == 0`).
   - Read live published rulebase via `collect_domain_rulebase_snapshot(api, mgmt_name, domain_name, sid=raw_sid, server_ip=srv_ip)`.
   - Best-effort persist `await cache.replace_domain_rulebase(live_snapshot)` when `live_snapshot` contains rules or layers (catching and ignoring any cache storage error so reporting never fails).
   - Set `numbering_source = "live_published"` and `numbering_basis = "Numbering read live after publish at <ts> UTC"` with **no** `owned_session_not_used` warning.
3. **Mismatch / dirty / discarded `sid` (all other cases)**:
   - For example: target session is unpublished (`open`) while `live_uid != session_uid`; `live_state == "discarded"`; or target session is published while `live_uid != session_uid` has `live_changes > 0` (uncommitted edits from a different session that would pollute published numbering).
   - Append `ReportWarning(code="owned_session_not_used", ...)` and fall through to cache / live-published fallback.

### Decision 2: Short-circuit object-only sessions (`not session_report.rule_changes`)

At the very top of `apply_session_rule_placement()`, check:

```python
if not session_report.rule_changes:
    session_report.numbering_basis = ""
    session_report.numbering_source = "not_applicable"
    return
```

In `renderer.py`:

- `_render_session_html`: render `<div class="basis-banner">` only when `s.rule_changes and s.numbering_basis`.
- `_render_markdown`: render `- **Numbering Basis**:` only when `s.rule_changes and s.numbering_basis`.

This avoids wasted `show-session` / SQLite calls and removes misleading `(unavailable)` banners on host/group/object deletion reports.

### Decision 3: Cold-cache on-demand live rulebase fallback

When `session_report.rule_changes` is non-empty and cache lookup (`cache.get_domain_rulebase`) returns an empty snapshot (`not has_cached_rules`):

- Attempt `live_snapshot = await collect_domain_rulebase_snapshot(api, mgmt_name, domain_name)` inside a `try / except Exception` block (re-raising `ServerIdentityError`).
- Check `has_live_rules` (`access_rules`, `nat_rules`, `https_rules`, `threat_rules`, or `layers` non-empty):
  - If `True`: apply `_apply_snapshot_locations_to_rules(session_report.rule_changes, live_snapshot)`, best-effort call `await cache.replace_domain_rulebase(live_snapshot)`, and set `numbering_source = "live_published"`, `numbering_basis = f"Numbering read live from published rulebase at {ts_str} UTC"`.
  - If `False` (or an exception occurred other than `ServerIdentityError`): preserve existing graceful degradation (`numbering_source = "unnumbered"`, `numbering_basis = "Numbering from cached rulebase snapshot (unavailable)"`).

Because minimal unit-test stubs (`FakeReportsApi`) return `{}` for unconfigured `show-packages` calls, `has_live_rules` evaluates to `False` when unconfigured, keeping existing offline/stub fallback behavior intact while eliminating cold-cache `(unavailable)` reports against real management servers.

### Decision 4: Bare `layer_uid` resolution in `collector.py`

In `_parse_rule_and_object_changes()`:

- When `raw_layer` yields a `layer_uid` without a `layer_name` (`not layer_name and is_bare_uid(layer_uid)`):
  - If `layer_uid in known_names`, assign `layer_name = known_names[layer_uid]`.
  - Otherwise add `layer_uid` to `bare_uids_out` so step 3 of `collect_change_report` resolves it via `cache.get_object_by_uid` or bounded `show-object` (`MAX_UID_LOOKUPS = 200`).
- In `_replace_resolved_uids_in_session()`:
  - For each `rc` in `session_report.rule_changes`, if `not rc.layer_name and rc.layer_uid in resolved`, set `rc.layer_name = resolved[rc.layer_uid]`.

## Risks / Trade-offs

- **[Risk] Cold-cache live rulebase fetch latency on huge domains** -> Mitigation: Only triggered when `session_report.rule_changes` is non-empty AND local `arodonata_rulebase_*` cache is completely empty for `(mgmt_name, domain_name)`; once fetched, `cache.replace_domain_rulebase(live_snapshot)` warms the SQL cache so subsequent sessions in the same domain hit warm cache.
- **[Risk] Existing unit test `test_owned_session_already_published_falls_back_to_cache_with_warning` tested the old rejection behavior on an empty-changes published session** -> Mitigation: Replace/split that test in `tests/unit/test_change_reports.py` into (a) post-publish clean `OwnedSession` with rule changes succeeds via `live_published` without warning, (b) post-publish dirty `OwnedSession` (`live_uid != session_uid`, `changes > 0`) emits `owned_session_not_used` and falls back to cache, and (c) object-only published session (`rule_changes == []`) sets `numbering_source == "not_applicable"` and omits `.basis-banner`.
