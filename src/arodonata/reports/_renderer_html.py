"""Self-contained HTML document rendering and CSS styles (`arodonata.reports._renderer_html`)."""

from __future__ import annotations

import html
from collections.abc import Sequence
from typing import Any

from arodonata.reports._renderer_formatting import (
    _HTML_FMT,
    _esc_html,
    _format_dt_utc,
    _render_enabled_cell,
    _render_list_cell,
    _render_nat_rule_cells,
    _render_object_details,
    _render_scalar_cell,
    render_safe_inline_markdown_html,
)
from arodonata.reports.models import (
    ChangeReport,
    FieldDiff,
    RenderOptions,
    RuleChangeEntry,
    SessionChangeReport,
)

_INLINE_CSS = """
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #1f2937;
  background-color: #f9fafb;
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}
.report-container {
  max-width: 1280px;
  margin: 0 auto;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 28px;
}
h1, h2, h3, h4 {
  color: #111827;
  margin-top: 0;
}
.header-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  background: #f3f4f6;
  padding: 14px 18px;
  border-radius: 6px;
  margin-bottom: 24px;
  font-size: 0.9rem;
}
.session-card {
  border: 1px solid #d1d5db;
  border-radius: 6px;
  padding: 20px;
  margin-bottom: 24px;
}
.session-meta {
  font-size: 0.875rem;
  color: #4b5563;
  margin-bottom: 14px;
}
.basis-banner {
  background: #eff6ff;
  border-left: 4px solid #3b82f6;
  padding: 8px 12px;
  font-size: 0.85rem;
  color: #1e40af;
  margin-bottom: 16px;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 16px;
  font-size: 0.85rem;
}
th, td {
  border: 1px solid #d1d5db;
  padding: 7px 10px;
  text-align: left;
  vertical-align: middle;
}
th {
  background: #253245;
  color: #ffffff;
  border-color: #37475e;
  font-weight: 600;
  font-size: 0.8125rem;
  white-space: nowrap;
}
tr.section-row td {
  background: #eee8aa;
  color: #262626;
  border-top: 1px solid #d4c87a;
  border-bottom: 1px solid #d4c87a;
  font-weight: 600;
  padding: 5px 10px;
}
.section-caret {
  display: inline-block;
  margin-right: 6px;
  font-size: 0.75rem;
  color: #1f2937;
}
.section-layer {
  font-weight: 400;
  color: #57534e;
  margin-left: 8px;
  font-size: 0.8rem;
}
td.col-num {
  background: #f1f3f5;
  color: #374151;
  text-align: center;
  width: 44px;
  font-variant-numeric: tabular-nums;
}
.action-accept {
  color: #16a34a;
  font-weight: 700;
  margin-right: 4px;
}
.action-drop {
  color: #dc2626;
  font-weight: 700;
  margin-right: 4px;
}
.any-token {
  color: #6b7280;
}
.badge {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
}
.badge-new {
  background: #dcfce7;
  color: #166534;
  border: 1px solid #86efac;
}
.badge-deleted {
  background: #fee2e2;
  color: #991b1b;
  border: 1px solid #fca5a5;
}
.badge-modified {
  background: #fef9c3;
  color: #854d0e;
  border: 1px solid #fde047;
}
.badge-moved {
  background: #e0e7ff;
  color: #3730a3;
  border: 1px solid #a5b4fc;
}
.disabled-marker {
  color: #dc2626;
  font-weight: 700;
}
.diff-highlight {
  background-color: #fef08a;
  padding: 1px 4px;
  border-radius: 3px;
}
.diff-removed {
  background-color: #fee2e2;
  color: #991b1b;
  text-decoration: line-through;
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.82rem;
}
.diff-added {
  background-color: #dcfce7;
  color: #166534;
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.82rem;
  font-weight: 600;
}
.diff-arrow {
  color: #6b7280;
  padding: 0 3px;
  font-weight: 600;
}
.diff-table {
  margin-top: 8px;
  margin-bottom: 14px;
  background: #fffbeb;
}
.warning-box {
  background: #fff7ed;
  border-left: 4px solid #f97316;
  padding: 10px 14px;
  margin-bottom: 16px;
  font-size: 0.875rem;
}
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background: #f3f4f6;
  padding: 1px 4px;
  border-radius: 3px;
}
""".strip()


def _operation_badge_html(rc: RuleChangeEntry) -> str:
    badges: list[str] = []
    if rc.operation == "added":
        badges.append('<span class="badge badge-new">NEW</span>')
    elif rc.operation == "deleted":
        badges.append('<span class="badge badge-deleted">DELETED</span>')
    elif rc.operation == "moved":
        badges.append('<span class="badge badge-moved">MOVED</span>')
    else:
        badges.append('<span class="badge badge-modified">MODIFIED</span>')

    if rc.moved and rc.operation != "moved":
        move_lbl = f"MOVED (from #{_esc_html(rc.old_rule_number)})" if rc.old_rule_number else "MOVED"
        badges.append(f'<span class="badge badge-moved">{move_lbl}</span>')
    return " ".join(badges)


def _render_field_diffs_html(diffs: Sequence[FieldDiff]) -> str:
    if not diffs:
        return ""
    rows: list[str] = [
        '<table class="diff-table">',
        "<thead><tr><th>Field</th><th>Before</th><th>After</th><th>Added</th><th>Removed</th></tr></thead>",
        "<tbody>",
    ]
    for d in diffs:
        rows.append(
            "<tr>"
            f'<td><span class="diff-highlight">{_esc_html(d.field_name)}</span></td>'
            f"<td>{_esc_html(d.old_value)}</td>"
            f'<td><span class="diff-highlight">{_esc_html(d.new_value)}</span></td>'
            f"<td>{_esc_html(d.added_items)}</td>"
            f"<td>{_esc_html(d.removed_items)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _format_action_token_html(action_val: str) -> str:
    low = action_val.strip().lower()
    escaped = _esc_html(action_val)
    if low == "accept":
        return f'<span class="action-accept">●</span>{escaped}'
    if low in ("drop", "reject"):
        return f'<span class="action-drop">●</span>{escaped}'
    return escaped


def _render_action_cell_html(current_val: Any, diff: FieldDiff | None) -> tuple[str, bool]:
    curr_str = str(current_val) if current_val is not None else ""
    if diff is None:
        return _format_action_token_html(curr_str), False
    return _render_scalar_cell(curr_str, diff, _HTML_FMT)


def _render_section_banner_html(rc: RuleChangeEntry) -> str:
    layer_label = rc.layer_name or rc.package_name or rc.layer_uid or "Policy"
    if rc.section_name:
        sec_r = f" ({_esc_html(rc.section_range)})" if rc.section_range else ""
        title_html = (
            f'<span class="section-caret">▾</span>{_esc_html(rc.section_name)}{sec_r}'
            f'<span class="section-layer">[{_esc_html(layer_label)}]</span>'
        )
    else:
        title_html = f'<span class="section-caret">▾</span>{_esc_html(layer_label)}'
    return f'<tr class="section-row"><td colspan="10">{title_html}</td></tr>'


def _render_session_html(s: SessionChangeReport, options: RenderOptions) -> str:
    dom_str = s.domain_name or "default"
    lines: list[str] = [
        '<div class="session-card">',
        f"<h2>Session: {_esc_html(s.session_name or s.session_uid)} ({_esc_html(s.mgmt_name)} / {_esc_html(dom_str)})</h2>",
        '<div class="session-meta">',
        f"<strong>UID:</strong> <code>{_esc_html(s.session_uid)}</code> | "
        f"<strong>Admin:</strong> {_esc_html(s.user_name or 'N/A')} | "
        f"<strong>State:</strong> {_esc_html(s.state)} | "
        f"<strong>Published:</strong> {_esc_html(_format_dt_utc(s.published_at))}",
    ]
    if s.description:
        lines.append(f"<br><strong>Description:</strong> {_esc_html(s.description)}")
    lines.append("</div>")
    if s.rule_changes and s.numbering_basis:
        lines.append(f'<div class="basis-banner">{_esc_html(s.numbering_basis)}</div>')

    if s.rule_changes:
        lines.append("<h3>Rule Changes</h3>")
        lines.append("<table>")
        lines.append(
            "<thead><tr>"
            "<th>No.</th><th>Status</th><th>Enabled</th><th>Name</th>"
            "<th>Source</th><th>Destination</th><th>Services &amp; Applications</th>"
            "<th>Action</th><th>Track</th><th>Comments</th>"
            "</tr></thead><tbody>"
        )
        diff_fields_by_rule: dict[str, set[str]] = {
            rc.uid: {d.field_name.lower() for d in rc.field_diffs} for rc in s.rule_changes
        }
        last_section_key: tuple[str, str, str] | None = None
        for rc in s.rule_changes:
            changed_f = diff_fields_by_rule.get(rc.uid, set())
            diffs_map: dict[str, FieldDiff] = (
                {d.field_name.strip().lower(): d for d in rc.field_diffs} if rc.operation == "modified" else {}
            )
            layer_label = rc.layer_name or rc.package_name or rc.layer_uid or "Policy"
            section_key = (layer_label, rc.section_name or "", rc.section_range or "")
            if section_key != last_section_key:
                lines.append(_render_section_banner_html(rc))
                last_section_key = section_key

            en_cell, en_ann = _render_enabled_cell(rc.enabled, diffs_map.get("enabled"), _HTML_FMT)
            if rc.rulebase_type == "nat":
                src_str, src_ann, dst_str, dst_ann, svc_str, svc_ann, act_str, act_ann = _render_nat_rule_cells(
                    rc, diffs_map, _HTML_FMT, arrow="→"
                )
            else:
                src_str, src_ann = _render_list_cell(
                    rc.source, diffs_map.get("source"), _HTML_FMT, empty_fallback="Any", negate=rc.source_negate
                )
                dst_str, dst_ann = _render_list_cell(
                    rc.destination,
                    diffs_map.get("destination"),
                    _HTML_FMT,
                    empty_fallback="Any",
                    negate=rc.destination_negate,
                )
                svc_str, svc_ann = _render_list_cell(
                    rc.service, diffs_map.get("service"), _HTML_FMT, empty_fallback="Any", negate=rc.service_negate
                )
                act_str, act_ann = _render_action_cell_html(rc.action or "", diffs_map.get("action"))

            track_str, track_ann = _render_scalar_cell(rc.track or "", diffs_map.get("track"), _HTML_FMT)
            name_str, name_ann = _render_scalar_cell(rc.name, diffs_map.get("name"), _HTML_FMT)
            comments_str, comments_ann = _render_scalar_cell(rc.comments, diffs_map.get("comments"), _HTML_FMT)

            def _hl(cell_html: str, is_annotated: bool, *field_names: str, _cf: set[str] = changed_f) -> str:
                if not is_annotated and any(fn in _cf for fn in field_names):
                    return f'<span class="diff-highlight">{cell_html}</span>'
                return cell_html

            num_display = _esc_html(rc.rule_number or "—")
            lines.append(
                "<tr>"
                f'<td class="col-num">{num_display}</td>'
                f"<td>{_operation_badge_html(rc)}</td>"
                f"<td>{_hl(en_cell, en_ann, 'enabled')}</td>"
                f"<td>{_hl(name_str, name_ann, 'name')}</td>"
                f"<td>{_hl(src_str, src_ann, 'source', 'source-negate', 'original-source', 'translated-source')}</td>"
                f"<td>{_hl(dst_str, dst_ann, 'destination', 'destination-negate', 'original-destination', 'translated-destination')}</td>"
                f"<td>{_hl(svc_str, svc_ann, 'service', 'service-negate', 'original-service', 'translated-service')}</td>"
                f"<td>{_hl(act_str, act_ann, 'action', 'method')}</td>"
                f"<td>{_hl(track_str, track_ann, 'track')}</td>"
                f"<td>{_hl(comments_str, comments_ann, 'comments')}</td>"
                "</tr>"
            )
        lines.append("</tbody></table>")

        if options.include_field_diffs:
            for rc in s.rule_changes:
                if rc.field_diffs:
                    lines.append(
                        f"<h4>Field Diffs for Rule #{_esc_html(rc.rule_number or rc.uid)} "
                        f"({_esc_html(rc.name or rc.uid)})</h4>"
                    )
                    lines.append(_render_field_diffs_html(rc.field_diffs))

    if options.include_object_changes and s.object_changes:
        lines.append("<h3>Object Changes</h3>")
        lines.append("<table>")
        lines.append(
            "<thead><tr><th>Status</th><th>Type</th><th>Name</th><th>UID</th><th>Details</th></tr></thead><tbody>"
        )
        for oc in s.object_changes:
            op_badge = (
                '<span class="badge badge-new">NEW</span>'
                if oc.operation == "added"
                else (
                    '<span class="badge badge-deleted">DELETED</span>'
                    if oc.operation == "deleted"
                    else '<span class="badge badge-modified">MODIFIED</span>'
                )
            )
            oc_diffs_map: dict[str, FieldDiff] = (
                {d.field_name.strip().lower(): d for d in oc.field_diffs} if oc.operation == "modified" else {}
            )
            oc_name_html, _ = _render_scalar_cell(oc.name, oc_diffs_map.get("name"), _HTML_FMT)
            lines.append(
                "<tr>"
                f"<td>{op_badge}</td>"
                f"<td>{_esc_html(oc.object_type)}</td>"
                f"<td>{oc_name_html}</td>"
                f"<td><code>{_esc_html(oc.uid)}</code></td>"
                f"<td>{_render_object_details(oc, _HTML_FMT)}</td>"
                "</tr>"
            )
        lines.append("</tbody></table>")
        if options.include_field_diffs:
            for oc in s.object_changes:
                if oc.field_diffs:
                    lines.append(
                        f"<h4>Field Diffs for Object {_esc_html(oc.name or oc.uid)} ({_esc_html(oc.object_type)})</h4>"
                    )
                    lines.append(_render_field_diffs_html(oc.field_diffs))

    lines.append("</div>")
    return "\n".join(lines)


def _render_html_document(
    report: ChangeReport,
    options: RenderOptions,
) -> bytes:
    """Render a self-contained UTF-8 HTML document (`bytes`) with inline CSS and zero `<script>` tags."""
    eff_title_raw = options.title if options.title else report.title
    eff_headers = dict(report.header_fields)
    eff_headers.update(options.header_fields)

    title_html = render_safe_inline_markdown_html(eff_title_raw)
    plain_title = html.escape(eff_title_raw, quote=True)

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{plain_title}</title>",
        f"<style>{_INLINE_CSS}</style>",
        "</head>",
        "<body>",
        '<div class="report-container">',
        f"<h1>{title_html}</h1>",
        '<div class="header-meta">',
        f"<div><strong>Generated At:</strong> {_esc_html(_format_dt_utc(report.generated_at))}</div>",
        f"<div><strong>Format Version:</strong> {_esc_html(report.format_version)}</div>",
        f"<div><strong>Sessions:</strong> {len(report.sessions)}</div>",
    ]

    for k, v in eff_headers.items():
        parts.append(f"<div><strong>{html.escape(k, quote=True)}:</strong> {render_safe_inline_markdown_html(v)}</div>")
    parts.append("</div>")

    if options.include_warnings and report.warnings:
        parts.append('<div class="warning-box"><h3>Warnings</h3><ul>')
        for w in report.warnings:
            ctx_bits = [b for b in (w.mgmt_name, w.domain, w.session_uid) if b]
            prefix = f"[{_esc_html(':'.join(ctx_bits))}] " if ctx_bits else ""
            parts.append(f"<li><strong>{_esc_html(w.code)}</strong>: {prefix}{_esc_html(w.message)}</li>")
        parts.append("</ul></div>")

    for s in report.sessions:
        parts.append(_render_session_html(s, options))

    parts.append("</div></body></html>")
    return "\n".join(parts).encode("utf-8")
