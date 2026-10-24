# Design: Milestone 4 — Rulebase Introspection, SmartConsole Numbering, and Auditable Change Reports

## Context

See `proposal.md` for motivation and `openspec/specs/rulebase-and-numbering/spec.md` and `openspec/specs/change-reports/spec.md` for canonical requirements. Milestone 4 delivers `src/arodonata/rulebase/` and `src/arodonata/reports/` and integrates both subsystems into `ArodonataClient`.

## Goals / Non-Goals

**Goals:**

- Keep `src/arodonata/rulebase/` and `src/arodonata/reports/` decoupled from low-level HTTP/SQL drivers by operating strictly against `ApiPort`, `CachePort`, `LockPort`, and core domain models.
- Implement `rulebase/pager.py` to page `show-*-rulebase` in chunks of up to 100 rules, stitch `rulebase-section` headers split across consecutive pages, and recover empty trailing sections.
- Implement `RulebaseRefreshService` (`refresh.py`) with `DomainSyncCoordinator` integration (`scope="rulebase"`), dirty-session protection, full traversal of packages, NAT policies, access/HTTPS/threat layers, inline layers, and Global `place-holder` resolution in package context.
- Implement `rulebase/numbering.py`, `rulebase/filter.py`, and `CachedRulebaseSource` (`source.py`) to compute SmartConsole-identical hierarchical numbers (`1`, `2.1`, `2.2.1`, section ranges, `"No Rules"`), locate rules/layers across a domain (`locate_rules`), resolve domains automatically (`AmbiguousLayerName`), and evaluate rule filters locally against cached snapshots and objects/services.
- Implement `reports/` (`models.py`, `collector.py`, `placement.py`, `renderer.py`) for read-only session change collection (`SessionScope`, `RangeScope`), live `OwnedSession` or cached rulebase placement numbering with strict SID hygiene, and offline rendering to self-contained HTML, Markdown, and versioned JSON.
- Expose all rulebase and report operations on `ArodonataClient`.

**Non-Goals:**

- PDF rendering (`render_change_report` raises `UnsupportedFormat` when `"pdf"` is requested).
- Mutating or closing caller-supplied `OwnedSession` instances (all `OwnedSession` operations are strictly read-only).

## Decisions

### 1. Rulebase Pager & Split-Section Stitching (`src/arodonata/rulebase/pager.py`)

- **Chunking**: Queries `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase` with `limit <= 100` (default `100`), `offset`, `details-level="standard"` (or caller-specified), `use-object-dictionary=True`.
- **Object Dictionary Expansion**: Resolves UIDs referenced in rules against the page's `objects-dictionary` so rule fields (`action`, `track`, `inline-layer`, `source`, `destination`, `service`, `install-on`, etc.) carry both UIDs and human-readable names/metadata in `raw_data`.
- **Section Boundary Stitching**:
  - Check Point's `show-*-rulebase` returns top-level nodes in `rulebase`: either direct rule dicts (`type` in `access-rule`, `nat-rule`, `https-rule`, `threat-rule`, `place-holder`) or section nodes (`type == "access-section"` / `"nat-section"` / `"https-section"` / `"threat-section"` or containing a nested `rulebase` list).
  - When a section spans a page boundary (e.g. rules 1..100 on page 1 and 101..150 on page 2), Check Point repeats the section header (`uid`, `name`) on the next page with the continuation slice of `rulebase` items.
  - `pager.py` maintains an ordered map of seen sections by `uid` (or `(name, position)` when UID is absent). When a subsequent page contains a section with the same `uid` as an already-seen section, its child rules are appended in order (deduplicating any overlapping rule UID) and its `to` bound is updated.
- **Empty Trailing Sections**:
  - Check Point's `total` count in `show-*-rulebase` counts rules rather than empty sections, or an empty section at the end of a layer may have `from == to == 0` / `rulebase == []`. The pager inspects every returned `rulebase` node on the final page (and performs a trailing check when needed) so sections with zero rules (`rule_uids=[]`, `from_rule=None`, `to_rule=None`) are preserved in their exact position.

### 2. Atomic Rulebase Snapshot Refresh (`src/arodonata/rulebase/refresh.py`)

- **Coordinator Integration**:
  - Uses `DomainSyncCoordinator.stream_ensure` / `ensure` with `scope="rulebase"` and `item_types=["*"]`.
  - Under the per-domain lock `sync:{mgmt_name}:{domain_name}:rulebase`, `DomainSyncCoordinator.verify_session_clean` verifies `locks == 0` and `number-of-published-changes == 0`. If dirty, `DirtySessionError` is raised, preserving any existing cached rulebase snapshot and marking `domain_sync_state.status = "failed"` with `last_error`.
- **Complete Traversal**:
  1. Queries `show-packages` (`details-level="full"`) for the domain.
  2. Extracts ordered access, HTTPS, and threat layers from each package (`access-layers`, `https-layers`, `threat-layers` / `layers`), recording `RulebasePackageLayerEntry` rows with 1-based `position`.
  3. For each package where `nat-policy` is True (or present), pages `show-nat-rulebase` (`package=pkg_name`), recording `RulebasePackageLayerEntry(rulebase_type="nat", ...)` and `NatRuleEntry` + `RulebaseSectionEntry` rows.
  4. Also queries `show-access-layers`, `show-https-layers`, and `show-threat-layers` so standalone or unattached layers in the domain are discovered.
  5. Pages each discovered access/HTTPS/threat layer via `pager.py`. When a rule references an `inline-layer` (by UID or name) not yet visited, queues that inline layer for traversal and records `parent_layer_uid` and `parent_rule_uid` on its `RulebaseLayerEntry`.
  6. **Global Placeholder Resolution**: When an access/HTTPS/threat layer is a Global layer (or contains a rule with `type == "place-holder"` / `domain-layer`), queries `show-*-rulebase` for that layer passing `package=pkg_name` (or resolves the domain sub-layer attached to the placeholder) so `AccessRuleEntry.placeholder_domain_layer_uid` (and the nested domain layer's `parent_layer_uid` / `parent_rule_uid`) are recorded in the snapshot.
  7. Replaces the domain's entire rulebase snapshot atomically via `cache.replace_domain_rulebase(snapshot)` and updates `domain_sync_state` (`scope="rulebase"`, `item_type="*"`, `status="ok"`, `last_published_at`, `last_session_uid`, `synced_at`, `object_count`).

### 3. SmartConsole Hierarchical Numbering & Local Filtering (`numbering.py`, `source.py`, `filter.py`)

- **Numbering Algorithm (`numbering.py`)**:
  - **Standalone Layer View (`get_layer_rulebase`)**:
    - Top-level rules in the layer are numbered sequentially `1, 2, 3, ...` in `position` order.
    - If a rule has `inline_layer_uid`, the inline layer's rules are expanded beneath the calling rule with prefix `f"{parent_num}."` (`2.1`, `2.2`, and recursively `2.2.1`).
    - Each section's display range is computed from the hierarchical numbers of the rules belonging to that section: `"{first_num}-{last_num}"` (or `"{first_num}"` if single rule, or `"No Rules"` if the section contains zero rules).
  - **Package View (`get_package_rulebase`)**:
    - Iterates through the package's ordered layers for the requested `rulebase_type`.
    - Top-level rules in an ordered layer are numbered sequentially (`1`, `2`, ...).
    - When a top-level rule is a `place-holder` (in a Global layer) that resolves to a domain layer (`placeholder_domain_layer_uid` or domain layer in the package), the placeholder rule itself receives top-level number `N` (e.g. `2`), and the domain layer's rules are expanded under it as `N.1`, `N.2`, etc. Any inline layer called by rule `2.2` is expanded as `2.2.1`, `2.2.2`, etc.
    - For NAT rulebases (`rulebase_type="nat"`), rules and sections belonging to the package are numbered sequentially `1, 2, ...` with section ranges or `"No Rules"`.
- **Rule & Layer Location (`locate_rules`)**:
  - Scans all packages and layers in the domain's cached snapshot, computing every SmartConsole position (`RuleLocation`: `package_name`, `package_uid`, `layer_name`, `layer_uid`, `rulebase_type`, `rule_uid`, `rule_number`, `section_name`, `section_uid`, `parent_rule_uid`) for requested `rule_uids`, and every layer numbering prefix (`""` for top-level, `"2."` for placeholder/inline child, `"2.2."` for nested inline) for requested `layer_uids`, bundled with `snapshot_session_uid`, `snapshot_published_at`, and `sync_status`.
- **Automatic Domain Resolution (`AmbiguousLayerName`)**:
  - When `domain_name` is `None` or `""`, inspects all cached domains on `mgmt_name`. If only one domain exists on the server, or if a unique domain contains the target package/layer name or UID, selects that domain automatically. If multiple domains contain a matching package or layer, raises `AmbiguousLayerName(name_or_uid, candidates=[(domain, uid), ...])`.
- **Local Rulebase Filtering (`filter.py`)**:
  - Evaluates a filter string locally against a numbered layer/package rulebase and cached `CPObject` / `CPService` dictionaries (supporting free-text substring, `name:`, `source:`/`src:`, `destination:`/`dst:`, `service:`/`svc:`, `action:`, `enabled:true/false`, `comment:`, IP/CIDR containment against cached host/network/range/group objects, and port/protocol matching against cached services) and formats output in `"markdown"`, `"model_friendly"`, or `"raw"` structure.

### 4. Auditable Session Change Reports (`src/arodonata/reports/`)

- **Scope & Option Models (`reports/models.py`)**:
  - `OwnedSession`: holds `sid` (`Field(repr=False, exclude=True)`) and `server_ip`. Custom `__repr__` and `__str__` redact `sid` so it never leaks in logs or tracebacks.
  - `SessionScope`: `mgmt_name`, `domain` (optional), `session_uids` (non-empty list of UIDs), optional `owned_sessions: dict[str, OwnedSession] | list[OwnedSession]`. Validates non-empty `session_uids`.
  - `RangeScope`: `mgmt_name`, `domain` (optional), `from_date: datetime | None`, `to_date: datetime | None`, `from_session: str | None`, `to_session: str | None`. Validates that at least one bound is provided, rejects naive datetimes (`tzinfo is None` or `tzinfo.utcoffset(dt) is None`), and rejects `from_date > to_date`.
  - `ChangeReport`: `format_version: int = 1`, `generated_at: datetime`, `sessions: list[SessionChangeReport]`, `warnings: list[ReportWarning]`, `raw_responses: list[RawResponse]`. Validator rejects `format_version > CURRENT_FORMAT_VERSION` when loading via `model_validate` / `model_validate_json`.
- **Collector (`reports/collector.py`)**:
  - Converts timezone-aware `from_date` / `to_date` to UTC, widens server query bounds (`±1 day` or omits server date bounds when `from_session` is also supplied), and filters returned sessions by exact UTC publish timestamp (`from_date <= published_at <= to_date`).
  - Deduplicates sessions across multiple `SessionScope` and `RangeScope` entries by `(mgmt_name, domain_name, session_uid)` while merging any attached `OwnedSession`.
  - Queries `show-session` and `show-changes` read-only. Records partial failures as `ReportWarning` items without aborting the report.
  - Resolves bare object UIDs referenced in group memberships or NAT fields via read-only `show-object` calls capped at `MAX_UID_LOOKUPS = 200` distinct UIDs per report, emitting a `names_unresolved` `ReportWarning` if the cap is exceeded or any lookup fails.
- **Placement Numbering (`reports/placement.py`)**:
  - For each session with rule changes:
    - If an `OwnedSession` is supplied for that session UID: verifies via `show-session` (using `sid` and `server_ip`) that the session is still unpublished and matches. If valid, reads `show-packages` and `show-*-rulebase` live using that `sid` (strictly read-only — never calling `publish`, `discard`, or `logout`), computes SmartConsole rule numbers, and sets `numbering_basis = f"Numbering read live in the owned session at {ts} UTC"`. Any occurrence of `sid` in raw responses or errors is scrubbed.
    - If `OwnedSession` is already published, mismatched, or fails with an error: emits an `owned_session_not_used` or `owned_session_error` `ReportWarning` and falls back to numbering from the cached rulebase snapshot (`numbering_basis = "Numbering from cached rulebase snapshot ..."`).
    - Labels added (`NEW`), modified, moved, and deleted (`DELETED`) rules with their hierarchical SmartConsole numbers and section headers.
- **Multi-Format Renderer (`reports/renderer.py`)**:
  - Raises `UnsupportedFormat` if `"pdf"` (or any format outside `{"html", "json", "markdown"}`) is requested.
  - Escapes all Check Point strings (`html.escape` in HTML, markdown cell escaping in Markdown) while rendering safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http://...|https://...|mailto:...)` — rejecting `javascript:` / `data:` URLs) in `RenderOptions.title` and `header_fields`.
  - `"html"` returns UTF-8 `bytes` with inline CSS, zero `<script>` tags, zero external URLs/stylesheets/fonts/images, visual badges (`NEW`, `DELETED`, moved badge, disabled `✗` marker, yellow field diff highlights), and per-rule field diff detail tables.
  - `"json"` serializes `ChangeReport` with `format_version=1` so `ChangeReport.model_validate_json(...)` round-trips offline into identical HTML and Markdown.

## Risks / Trade-offs

- **[Risk] Circular inline layer references in malformed Check Point test data** → Mitigation: Track a `visited_layer_uids: set[str]` path stack during both `RulebaseRefreshService` traversal and `numbering.py` recursive tree expansion to prevent infinite recursion.
- **[Risk] Accidental leakage of `OwnedSession.sid` into `RawResponse` or warning messages** → Mitigation: Redact `owned_session.sid` via `sanitize_mapping(..., known_sids=[owned.sid])` and `redact_sid(..., known_sids=[owned.sid])` before constructing any `RawResponse`, `ReportWarning`, or log entry.
