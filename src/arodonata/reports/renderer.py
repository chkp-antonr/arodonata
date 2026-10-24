"""Multi-format offline evidence rendering (`arodonata.reports.renderer`).

Implements `render_change_report` and `build_change_report`:
- Offline rendering of `ChangeReport` into `"html"` (`bytes`), `"markdown"` (`str`), and
  `"json"` (`str`), raising `UnsupportedFormat` for `"pdf"` or unknown formats.
- Escapes all Check Point strings in every format while supporting safe inline markdown
  (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title`
  and `header_fields`.
- Produces self-contained UTF-8 HTML (`bytes`) with inline CSS, zero `<script>` tags, zero
  external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs,
  moved rule badges, disabled `✗` markers), and per-rule field diff detail tables.
"""

from __future__ import annotations

import html
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from arodonata.core.errors import UnsupportedFormat
from arodonata.core.models.common import utc_now
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports.collector import MAX_UID_LOOKUPS, collect_change_report
from arodonata.reports.models import (
    ChangeReport,
    FieldDiff,
    RenderedReportBundle,
    RenderOptions,
    ReportScope,
    RuleChangeEntry,
    SessionChangeReport,
)

SUPPORTED_REPORT_FORMATS: frozenset[str] = frozenset({"html", "json", "markdown"})

_INLINE_TOKEN_RE = re.compile(r"(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\))")

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
  font-size: 0.875rem;
}
th, td {
  border: 1px solid #e5e7eb;
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
}
th {
  background: #f3f4f6;
  font-weight: 600;
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


def _is_safe_href(url: str) -> bool:
    clean = url.strip().lower()
    return clean.startswith(("http://", "https://", "mailto:"))


def render_safe_inline_markdown_html(text: str) -> str:
    """Escape `text` for HTML while converting safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[label](http/https/mailto)`)."""
    if not text:
        return ""
    parts = _INLINE_TOKEN_RE.split(text)
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("`") and part.endswith("`") and len(part) >= 2:
            out.append(f"<code>{html.escape(part[1:-1], quote=True)}</code>")
        elif part.startswith("**") and part.endswith("**") and len(part) >= 4:
            out.append(f"<strong>{html.escape(part[2:-2], quote=True)}</strong>")
        elif part.startswith("*") and part.endswith("*") and len(part) >= 2:
            out.append(f"<em>{html.escape(part[1:-1], quote=True)}</em>")
        elif part.startswith("[") and "](" in part and part.endswith(")"):
            bracket_end = part.find("](")
            label = part[1:bracket_end]
            href = part[bracket_end + 2 : -1].strip()
            if _is_safe_href(href):
                out.append(
                    f'<a href="{html.escape(href, quote=True)}" rel="noopener noreferrer">'
                    f"{html.escape(label, quote=True)}</a>"
                )
            else:
                out.append(html.escape(part, quote=True))
        else:
            out.append(html.escape(part, quote=True))
    return "".join(out)


def render_safe_inline_markdown_md(text: str) -> str:
    """Sanitize inline markdown for Markdown output (neutralizing HTML tags and unsafe link schemes)."""
    if not text:
        return ""
    parts = _INLINE_TOKEN_RE.split(text)
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("`") and part.endswith("`") and len(part) >= 2:
            out.append(f"`{part[1:-1]}`")
        elif part.startswith("**") and part.endswith("**") and len(part) >= 4:
            out.append(f"**{html.escape(part[2:-2], quote=False)}**")
        elif part.startswith("*") and part.endswith("*") and len(part) >= 2:
            out.append(f"*{html.escape(part[1:-1], quote=False)}*")
        elif part.startswith("[") and "](" in part and part.endswith(")"):
            bracket_end = part.find("](")
            label = html.escape(part[1:bracket_end], quote=False)
            href = part[bracket_end + 2 : -1].strip()
            if _is_safe_href(href):
                out.append(f"[{label}]({href})")
            else:
                out.append(html.escape(part, quote=False))
        else:
            out.append(html.escape(part, quote=False))
    return "".join(out)


def _esc_html(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(html.escape(str(x), quote=True) for x in val)
    return html.escape(str(val), quote=True)


def _esc_md(val: Any) -> str:
    if val is None:
        return ""
    raw = ", ".join(str(x) for x in val) if isinstance(val, list) else str(val)
    escaped = html.escape(raw, quote=False)
    return escaped.replace("|", "\\|").replace("\n", " ")


def _format_dt_utc(dt: datetime | None) -> str:
    if dt is None:
        return "N/A"
    utc_dt = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")


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


def _operation_label_md(rc: RuleChangeEntry) -> str:
    parts: list[str] = []
    if rc.operation == "added":
        parts.append("NEW")
    elif rc.operation == "deleted":
        parts.append("DELETED")
    elif rc.operation == "moved":
        parts.append("MOVED")
    else:
        parts.append("MODIFIED")
    if rc.moved and rc.operation != "moved":
        parts.append(f"MOVED (from #{_esc_md(rc.old_rule_number)})" if rc.old_rule_number else "MOVED")
    return ", ".join(parts)


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
    lines.append(f'<div class="basis-banner">{_esc_html(s.numbering_basis)}</div>')

    # Rule changes table
    if s.rule_changes:
        lines.append("<h3>Rule Changes</h3>")
        lines.append("<table>")
        lines.append(
            "<thead><tr>"
            "<th>#</th><th>Status</th><th>Enabled</th><th>Layer / Section</th><th>Name</th>"
            "<th>Source</th><th>Destination</th><th>Service</th><th>Action / Method</th><th>Comments</th>"
            "</tr></thead><tbody>"
        )
        diff_fields_by_rule: dict[str, set[str]] = {
            rc.uid: {d.field_name.lower() for d in rc.field_diffs} for rc in s.rule_changes
        }
        for rc in s.rule_changes:
            changed_f = diff_fields_by_rule.get(rc.uid, set())
            en_cell = "✓" if rc.enabled else '<span class="disabled-marker" title="Disabled">✗</span>'
            layer_sec = _esc_html(rc.layer_name or rc.package_name or rc.layer_uid)
            if rc.section_name:
                sec_r = f" ({_esc_html(rc.section_range)})" if rc.section_range else ""
                layer_sec = f"{layer_sec} / {_esc_html(rc.section_name)}{sec_r}"

            if rc.rulebase_type == "nat":
                src_str = f"{_esc_html(rc.original_source or 'Any')} → {_esc_html(rc.translated_source or 'Original')}"
                dst_str = (
                    f"{_esc_html(rc.original_destination or 'Any')} → "
                    f"{_esc_html(rc.translated_destination or 'Original')}"
                )
                svc_str = (
                    f"{_esc_html(rc.original_service or 'Any')} → {_esc_html(rc.translated_service or 'Original')}"
                )
                act_str = _esc_html(rc.method or "nat")
            else:
                src_str = _esc_html(rc.source if rc.source else ["Any"])
                if rc.source_negate:
                    src_str = f"NOT ({src_str})"
                dst_str = _esc_html(rc.destination if rc.destination else ["Any"])
                if rc.destination_negate:
                    dst_str = f"NOT ({dst_str})"
                svc_str = _esc_html(rc.service if rc.service else ["Any"])
                if rc.service_negate:
                    svc_str = f"NOT ({svc_str})"
                act_str = _esc_html(rc.action or "")

            def _hl(cell_html: str, *field_names: str, _cf: set[str] = changed_f) -> str:
                if any(fn in _cf for fn in field_names):
                    return f'<span class="diff-highlight">{cell_html}</span>'
                return cell_html

            num_display = _esc_html(rc.rule_number or "—")
            lines.append(
                "<tr>"
                f"<td><code>{num_display}</code></td>"
                f"<td>{_operation_badge_html(rc)}</td>"
                f"<td>{_hl(en_cell, 'enabled')}</td>"
                f"<td>{layer_sec}</td>"
                f"<td>{_hl(_esc_html(rc.name), 'name')}</td>"
                f"<td>{_hl(src_str, 'source', 'original-source', 'translated-source')}</td>"
                f"<td>{_hl(dst_str, 'destination', 'original-destination', 'translated-destination')}</td>"
                f"<td>{_hl(svc_str, 'service', 'original-service', 'translated-service')}</td>"
                f"<td>{_hl(act_str, 'action', 'method')}</td>"
                f"<td>{_hl(_esc_html(rc.comments), 'comments')}</td>"
                "</tr>"
            )
        lines.append("</tbody></table>")

        # Per-rule field diff detail tables
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
            lines.append(
                "<tr>"
                f"<td>{op_badge}</td>"
                f"<td>{_esc_html(oc.object_type)}</td>"
                f"<td>{_esc_html(oc.name)}</td>"
                f"<td><code>{_esc_html(oc.uid)}</code></td>"
                f"<td>{_esc_html(oc.summary)}</td>"
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


def _render_markdown_document(
    report: ChangeReport,
    options: RenderOptions,
) -> str:
    """Render `report` into a standalone Markdown document (`str`)."""
    eff_title_raw = options.title if options.title else report.title
    eff_headers = dict(report.header_fields)
    eff_headers.update(options.header_fields)

    lines: list[str] = [
        f"# {render_safe_inline_markdown_md(eff_title_raw)}",
        "",
        f"- **Generated At**: {_esc_md(_format_dt_utc(report.generated_at))}",
        f"- **Format Version**: {report.format_version}",
        f"- **Sessions**: {len(report.sessions)}",
    ]
    for k, v in eff_headers.items():
        lines.append(f"- **{_esc_md(k)}**: {render_safe_inline_markdown_md(v)}")
    lines.append("")

    if options.include_warnings and report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in report.warnings:
            ctx_bits = [b for b in (w.mgmt_name, w.domain, w.session_uid) if b]
            prefix = f"[{_esc_md(':'.join(ctx_bits))}] " if ctx_bits else ""
            lines.append(f"- **{_esc_md(w.code)}**: {prefix}{_esc_md(w.message)}")
        lines.append("")

    for s in report.sessions:
        dom_str = s.domain_name or "default"
        lines.append(
            f"## Session: {_esc_md(s.session_name or s.session_uid)} ({_esc_md(s.mgmt_name)} / {_esc_md(dom_str)})"
        )
        lines.append("")
        lines.append(f"- **UID**: `{_esc_md(s.session_uid)}`")
        lines.append(f"- **Admin**: {_esc_md(s.user_name or 'N/A')}")
        lines.append(f"- **State**: {_esc_md(s.state)}")
        lines.append(f"- **Published**: {_esc_md(_format_dt_utc(s.published_at))}")
        if s.description:
            lines.append(f"- **Description**: {_esc_md(s.description)}")
        lines.append(f"- **Numbering Basis**: {_esc_md(s.numbering_basis)}")
        lines.append("")

        if s.rule_changes:
            lines.append("### Rule Changes")
            lines.append("")
            lines.append(
                "| # | Status | Enabled | Layer / Section | Name | Source | Destination | Service | Action | Comments |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for rc in s.rule_changes:
                en_mark = "✓" if rc.enabled else "✗"
                layer_sec = _esc_md(rc.layer_name or rc.package_name or rc.layer_uid)
                if rc.section_name:
                    sec_r = f" ({_esc_md(rc.section_range)})" if rc.section_range else ""
                    layer_sec = f"{layer_sec} / {_esc_md(rc.section_name)}{sec_r}"
                if rc.rulebase_type == "nat":
                    src = f"{_esc_md(rc.original_source or 'Any')} -> {_esc_md(rc.translated_source or 'Original')}"
                    dst = (
                        f"{_esc_md(rc.original_destination or 'Any')} -> "
                        f"{_esc_md(rc.translated_destination or 'Original')}"
                    )
                    svc = f"{_esc_md(rc.original_service or 'Any')} -> {_esc_md(rc.translated_service or 'Original')}"
                    act = _esc_md(rc.method or "nat")
                else:
                    src = _esc_md(rc.source if rc.source else ["Any"])
                    dst = _esc_md(rc.destination if rc.destination else ["Any"])
                    svc = _esc_md(rc.service if rc.service else ["Any"])
                    act = _esc_md(rc.action or "")
                lines.append(
                    f"| {_esc_md(rc.rule_number or '—')} | {_operation_label_md(rc)} | {en_mark} | "
                    f"{layer_sec} | {_esc_md(rc.name)} | {src} | {dst} | {svc} | {act} | {_esc_md(rc.comments)} |"
                )
            lines.append("")

            if options.include_field_diffs:
                for rc in s.rule_changes:
                    if rc.field_diffs:
                        lines.append(
                            f"#### Field Diffs for Rule #{_esc_md(rc.rule_number or rc.uid)} ({_esc_md(rc.name or rc.uid)})"
                        )
                        lines.append("")
                        lines.append("| Field | Before | After | Added | Removed |")
                        lines.append("| --- | --- | --- | --- | --- |")
                        for d in rc.field_diffs:
                            lines.append(
                                f"| {_esc_md(d.field_name)} | {_esc_md(d.old_value)} | {_esc_md(d.new_value)} | "
                                f"{_esc_md(d.added_items)} | {_esc_md(d.removed_items)} |"
                            )
                        lines.append("")

        if options.include_object_changes and s.object_changes:
            lines.append("### Object Changes")
            lines.append("")
            lines.append("| Status | Type | Name | UID | Details |")
            lines.append("| --- | --- | --- | --- | --- |")
            for oc in s.object_changes:
                op_lbl = "NEW" if oc.operation == "added" else ("DELETED" if oc.operation == "deleted" else "MODIFIED")
                lines.append(
                    f"| {op_lbl} | {_esc_md(oc.object_type)} | {_esc_md(oc.name)} | "
                    f"`{_esc_md(oc.uid)}` | {_esc_md(oc.summary)} |"
                )
            lines.append("")

    return "\n".join(lines)


@traced
def render_change_report(
    report: ChangeReport,
    *,
    formats: Sequence[str] = ("html", "markdown", "json"),
    options: RenderOptions | None = None,
) -> RenderedReportBundle:
    """Render `report` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`.

    Raises `UnsupportedFormat` if `'pdf'` or any unrecognized format is requested.
    """
    normalized_formats: list[str] = []
    for fmt in formats:
        clean = str(fmt).strip().lower()
        if clean == "md":
            clean = "markdown"
        if clean not in SUPPORTED_REPORT_FORMATS:
            raise UnsupportedFormat(f"Unsupported report format {fmt!r}. Supported formats are: html, json, markdown.")
        if clean not in normalized_formats:
            normalized_formats.append(clean)

    span_attrs(formats=normalized_formats, session_count=len(report.sessions))
    eff_options = options or RenderOptions(
        title=report.title,
        header_fields=dict(report.header_fields),
    )

    html_bytes: bytes | None = None
    md_text: str | None = None
    json_text: str | None = None

    if "html" in normalized_formats:
        html_bytes = _render_html_document(report, eff_options)
    if "markdown" in normalized_formats:
        md_text = _render_markdown_document(report, eff_options)
    if "json" in normalized_formats:
        json_text = report.model_dump_json(indent=2)

    return RenderedReportBundle(
        report=report,
        html=html_bytes,
        markdown=md_text,
        json_text=json_text,
    )


@traced
async def build_change_report(
    api: ApiPort,
    cache: CachePort,
    scopes: Sequence[ReportScope | dict[str, Any]],
    *,
    formats: Sequence[str] = ("html", "markdown", "json"),
    options: RenderOptions | None = None,
    max_uid_lookups: int = MAX_UID_LOOKUPS,
    now_fn: Callable[[], datetime] = utc_now,
) -> RenderedReportBundle:
    """Collect a `ChangeReport` and render it into `formats` in a single call."""
    # Pre-validate requested formats before making network calls
    for fmt in formats:
        clean = str(fmt).strip().lower()
        if clean == "md":
            clean = "markdown"
        if clean not in SUPPORTED_REPORT_FORMATS:
            raise UnsupportedFormat(f"Unsupported report format {fmt!r}. Supported formats are: html, json, markdown.")

    report = await collect_change_report(
        api,
        cache,
        scopes,
        options=options,
        max_uid_lookups=max_uid_lookups,
        now_fn=now_fn,
    )
    return render_change_report(report, formats=formats, options=options)


__all__ = [
    "SUPPORTED_REPORT_FORMATS",
    "build_change_report",
    "render_change_report",
    "render_safe_inline_markdown_html",
    "render_safe_inline_markdown_md",
]
