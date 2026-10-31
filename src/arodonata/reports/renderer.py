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
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
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
    ObjectChangeEntry,
    RenderedReportBundle,
    RenderOptions,
    ReportScope,
    RuleChangeEntry,
    SessionChangeReport,
)

SUPPORTED_REPORT_FORMATS: frozenset[str] = frozenset({"html", "json", "markdown"})

_INLINE_TOKEN_RE = re.compile(r"(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\))")
_SUMMARY_SPLIT_RE = re.compile(
    r", (?=(?:ipv4-address|ipv6-address|subnet4|subnet6|range|range6|port|protocol|fqdn|members|comments)=)"
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


@dataclass(frozen=True)
class _CellFormatter:
    esc: Callable[[Any], str]
    added_item: Callable[[str], str]
    removed_item: Callable[[str], str]
    transition: Callable[[str, str], str]
    same_highlight: Callable[[str], str]
    enabled_mark: Callable[[bool], str]
    enabled_transition: Callable[[bool, bool], str]


_HTML_FMT = _CellFormatter(
    esc=_esc_html,
    added_item=lambda s: f'<span class="diff-added">+ {_esc_html(s)}</span>',
    removed_item=lambda s: f'<span class="diff-removed">- {_esc_html(s)}</span>',
    transition=lambda old_s, new_s: (
        f'<span class="diff-removed">{_esc_html(old_s)}</span>'
        f'<span class="diff-arrow">→</span>'
        f'<span class="diff-highlight">{_esc_html(new_s)}</span>'
    ),
    same_highlight=lambda s: f'<span class="diff-highlight">{_esc_html(s)}</span>',
    enabled_mark=lambda en: "✓" if en else '<span class="disabled-marker" title="Disabled">✗</span>',
    enabled_transition=lambda old_b, new_b: (
        f'<span class="diff-removed">{"✓" if old_b else "✗"}</span>'
        f'<span class="diff-arrow">→</span>'
        f"{'✓' if new_b else '''<span class="disabled-marker" title="Disabled">✗</span>'''}"
    ),
)

_MD_FMT = _CellFormatter(
    esc=_esc_md,
    added_item=lambda s: f"[+{_esc_md(s)}]",
    removed_item=lambda s: f"[-{_esc_md(s)}]",
    transition=lambda old_s, new_s: f"{_esc_md(old_s)} -> {_esc_md(new_s)}",
    same_highlight=_esc_md,
    enabled_mark=lambda en: "✓" if en else "✗",
    enabled_transition=lambda old_b, new_b: f"{'✓' if old_b else '✗'} -> {'✓' if new_b else '✗'}",
)


def _parse_bool_diff_val(val: Any, *, default: bool) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        norm = val.strip().lower()
        if norm in ("true", "1", "yes", "on", "enabled"):
            return True
        if norm in ("false", "0", "no", "off", "disabled", ""):
            return False
    return default


def _extract_added_removed(diff: FieldDiff) -> tuple[list[str], list[str]] | None:
    if diff.removed_items or diff.added_items:
        return list(diff.removed_items), list(diff.added_items)
    if isinstance(diff.old_value, list) and isinstance(diff.new_value, list):
        old_l = [str(x) for x in diff.old_value]
        new_l = [str(x) for x in diff.new_value]
        old_s = set(old_l)
        new_s = set(new_l)
        return (
            list(dict.fromkeys(x for x in old_l if x not in new_s)),
            list(dict.fromkeys(x for x in new_l if x not in old_s)),
        )
    return None


def _render_enabled_cell(enabled: bool, diff: FieldDiff | None, fmt: _CellFormatter) -> tuple[str, bool]:
    curr = fmt.enabled_mark(enabled)
    if diff is None:
        return curr, False
    old_bool = _parse_bool_diff_val(diff.old_value, default=(not enabled))
    if old_bool == enabled:
        return curr, False
    return fmt.enabled_transition(old_bool, enabled), True


def _render_scalar_cell(
    current_val: Any,
    diff: FieldDiff | None,
    fmt: _CellFormatter,
    *,
    fallback: str = "",
) -> tuple[str, bool]:
    curr_str = str(current_val) if (current_val is not None and str(current_val) != "") else fallback
    if diff is None:
        return fmt.esc(curr_str), False
    old_str = str(diff.old_value) if diff.old_value is not None else ""
    new_str = str(diff.new_value) if (diff.new_value is not None and str(diff.new_value) != "") else curr_str
    if not old_str and new_str:
        return fmt.added_item(new_str), True
    if old_str and not new_str:
        return fmt.removed_item(old_str), True
    if old_str == new_str:
        return fmt.same_highlight(new_str), True
    return fmt.transition(old_str, new_str), True


def _render_list_cell(
    current_items: Sequence[str],
    diff: FieldDiff | None,
    fmt: _CellFormatter,
    *,
    empty_fallback: str = "Any",
    negate: bool = False,
) -> tuple[str, bool]:
    eff_curr = list(current_items) if current_items else ([empty_fallback] if empty_fallback else [])
    annotated = False
    if diff is None:
        base = fmt.esc(eff_curr)
    else:
        ar = _extract_added_removed(diff)
        if ar is None:
            base, annotated = _render_scalar_cell(", ".join(eff_curr), diff, fmt)
        else:
            removed_list, added_list = ar
            added_set = set(added_list)
            kept_items = [x for x in eff_curr if x not in added_set]
            tokens: list[str] = [fmt.esc(k) for k in kept_items]
            tokens.extend(fmt.removed_item(r) for r in removed_list)
            tokens.extend(fmt.added_item(a) for a in added_list)
            base = ", ".join(tokens) if tokens else fmt.esc(eff_curr)
            annotated = bool(removed_list or added_list)
    if negate:
        base = f"NOT ({base})"
    return base, annotated


def _summary_fields_for_object(oc: ObjectChangeEntry) -> dict[str, Any]:
    if oc.summary_fields:
        return dict(oc.summary_fields)
    fields: dict[str, Any] = {}
    if not oc.summary:
        return fields
    for raw_clause in _SUMMARY_SPLIT_RE.split(oc.summary):
        if "=" not in raw_clause:
            fields.setdefault("_raw", raw_clause)
            continue
        k, v = raw_clause.split("=", 1)
        key = k.strip()
        if key == "subnet4" and "/" in v:
            net4, mask4 = v.split("/", 1)
            fields["subnet4"] = net4
            fields["mask-length4" if mask4.isdigit() else "subnet-mask"] = mask4
        elif key == "subnet6" and "/" in v:
            net6, mask6 = v.split("/", 1)
            fields["subnet6"] = net6
            fields["mask-length6"] = mask6
        elif key == "range" and "-" in v:
            f4, l4 = v.split("-", 1)
            fields["ipv4-address-first"] = f4
            fields["ipv4-address-last"] = l4
        elif key == "range6" and "-" in v:
            f6, l6 = v.split("-", 1)
            fields["ipv6-address-first"] = f6
            fields["ipv6-address-last"] = l6
        elif key == "members" and v.startswith("[") and v.endswith("]"):
            fields["members"] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        else:
            fields[key] = v
    return fields


def _render_object_details(oc: ObjectChangeEntry, fmt: _CellFormatter) -> str:
    if oc.operation != "modified" or not oc.field_diffs:
        return fmt.esc(oc.summary)
    diffs_by_name: dict[str, FieldDiff] = {d.field_name.strip().lower(): d for d in oc.field_diffs}
    sfields = _summary_fields_for_object(oc)
    if not sfields and oc.summary:
        return fmt.esc(oc.summary)

    rendered_fields: set[str] = set()
    parts: list[str] = []

    def _scalar_val(field_key: str) -> str:
        val = sfields.get(field_key)
        d = diffs_by_name.get(field_key)
        rendered_fields.add(field_key)
        return _render_scalar_cell(val, d, fmt)[0]

    for addr_k in ("ipv4-address", "ipv6-address"):
        if addr_k in sfields or addr_k in diffs_by_name:
            parts.append(f"{fmt.esc(addr_k)}={_scalar_val(addr_k)}")

    if any(k in sfields or k in diffs_by_name for k in ("subnet4", "mask-length4", "subnet-mask")):
        net4_s = _scalar_val("subnet4") if ("subnet4" in sfields or "subnet4" in diffs_by_name) else ""
        if "mask-length4" in sfields or "mask-length4" in diffs_by_name:
            mask4_s = _scalar_val("mask-length4")
            parts.append(f"subnet4={net4_s}/{mask4_s}" if net4_s else f"mask-length4={mask4_s}")
        elif "subnet-mask" in sfields or "subnet-mask" in diffs_by_name:
            smask_s = _scalar_val("subnet-mask")
            parts.append(f"subnet4={net4_s}/{smask_s}" if net4_s else f"subnet-mask={smask_s}")
        else:
            parts.append(f"subnet4={net4_s}")

    if any(k in sfields or k in diffs_by_name for k in ("subnet6", "mask-length6")):
        net6_s = _scalar_val("subnet6") if ("subnet6" in sfields or "subnet6" in diffs_by_name) else ""
        if "mask-length6" in sfields or "mask-length6" in diffs_by_name:
            mask6_s = _scalar_val("mask-length6")
            parts.append(f"subnet6={net6_s}/{mask6_s}" if net6_s else f"mask-length6={mask6_s}")
        else:
            parts.append(f"subnet6={net6_s}")

    if any(k in sfields or k in diffs_by_name for k in ("ipv4-address-first", "ipv4-address-last")):
        f4_s = _scalar_val("ipv4-address-first")
        l4_s = _scalar_val("ipv4-address-last")
        parts.append(f"range={f4_s}-{l4_s}")

    if any(k in sfields or k in diffs_by_name for k in ("ipv6-address-first", "ipv6-address-last")):
        f6_s = _scalar_val("ipv6-address-first")
        l6_s = _scalar_val("ipv6-address-last")
        parts.append(f"range6={f6_s}-{l6_s}")

    for k in ("port", "protocol", "fqdn"):
        if k in sfields or k in diffs_by_name:
            parts.append(f"{fmt.esc(k)}={_scalar_val(k)}")

    if "members" in sfields or "members" in diffs_by_name:
        mdiff = diffs_by_name.get("members")
        raw_m = sfields.get("members")
        curr_members = (
            [str(x) for x in mdiff.new_value]
            if (mdiff is not None and isinstance(mdiff.new_value, list))
            else ([str(x) for x in raw_m] if isinstance(raw_m, list) else [])
        )
        m_rendered, _ = _render_list_cell(curr_members, mdiff, fmt, empty_fallback="")
        parts.append(f"members=[{m_rendered}]")
        rendered_fields.add("members")

    if "comments" in sfields or "comments" in diffs_by_name:
        parts.append(f"comments={_scalar_val('comments')}")

    if "_raw" in sfields:
        parts.append(fmt.esc(sfields["_raw"]))

    for d in oc.field_diffs:
        low_f = d.field_name.strip().lower()
        if low_f in rendered_fields or low_f == "name":
            continue
        rendered_fields.add(low_f)
        if low_f in ("members", "groups", "tags") or d.added_items or d.removed_items:
            curr_l = [str(x) for x in d.new_value] if isinstance(d.new_value, list) else []
            l_str, _ = _render_list_cell(curr_l, d, fmt, empty_fallback="")
            parts.append(f"{fmt.esc(d.field_name)}=[{l_str}]")
        else:
            s_str, _ = _render_scalar_cell(d.new_value, d, fmt)
            parts.append(f"{fmt.esc(d.field_name)}={s_str}")

    return ", ".join(parts)


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

    # Rule changes table
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
                orig_src_h, os_ann = _render_scalar_cell(
                    rc.original_source or "Any",
                    diffs_map.get("original-source"),
                    _HTML_FMT,
                    fallback="Any",
                )
                trans_src_h, ts_ann = _render_scalar_cell(
                    rc.translated_source or "Original",
                    diffs_map.get("translated-source"),
                    _HTML_FMT,
                    fallback="Original",
                )
                src_str = f"{orig_src_h} → {trans_src_h}"
                src_ann = os_ann or ts_ann

                orig_dst_h, od_ann = _render_scalar_cell(
                    rc.original_destination or "Any",
                    diffs_map.get("original-destination"),
                    _HTML_FMT,
                    fallback="Any",
                )
                trans_dst_h, td_ann = _render_scalar_cell(
                    rc.translated_destination or "Original",
                    diffs_map.get("translated-destination"),
                    _HTML_FMT,
                    fallback="Original",
                )
                dst_str = f"{orig_dst_h} → {trans_dst_h}"
                dst_ann = od_ann or td_ann

                orig_svc_h, osvc_ann = _render_scalar_cell(
                    rc.original_service or "Any",
                    diffs_map.get("original-service"),
                    _HTML_FMT,
                    fallback="Any",
                )
                trans_svc_h, tsvc_ann = _render_scalar_cell(
                    rc.translated_service or "Original",
                    diffs_map.get("translated-service"),
                    _HTML_FMT,
                    fallback="Original",
                )
                svc_str = f"{orig_svc_h} → {trans_svc_h}"
                svc_ann = osvc_ann or tsvc_ann
                act_str, act_ann = _render_scalar_cell(
                    rc.method or "nat", diffs_map.get("method"), _HTML_FMT, fallback="nat"
                )
            else:
                src_str, src_ann = _render_list_cell(
                    rc.source,
                    diffs_map.get("source"),
                    _HTML_FMT,
                    empty_fallback="Any",
                    negate=rc.source_negate,
                )
                dst_str, dst_ann = _render_list_cell(
                    rc.destination,
                    diffs_map.get("destination"),
                    _HTML_FMT,
                    empty_fallback="Any",
                    negate=rc.destination_negate,
                )
                svc_str, svc_ann = _render_list_cell(
                    rc.service,
                    diffs_map.get("service"),
                    _HTML_FMT,
                    empty_fallback="Any",
                    negate=rc.service_negate,
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
        if s.rule_changes and s.numbering_basis:
            lines.append(f"- **Numbering Basis**: {_esc_md(s.numbering_basis)}")
        lines.append("")

        if s.rule_changes:
            lines.append("### Rule Changes")
            lines.append("")
            lines.append(
                "| # | Status | Enabled | Layer / Section | Name | Source | Destination | Service | Action | Track | Comments |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for rc in s.rule_changes:
                diffs_map_md: dict[str, FieldDiff] = (
                    {d.field_name.strip().lower(): d for d in rc.field_diffs} if rc.operation == "modified" else {}
                )
                en_mark, _ = _render_enabled_cell(rc.enabled, diffs_map_md.get("enabled"), _MD_FMT)
                layer_sec = _esc_md(rc.layer_name or rc.package_name or rc.layer_uid)
                if rc.section_name:
                    sec_r = f" ({_esc_md(rc.section_range)})" if rc.section_range else ""
                    layer_sec = f"{layer_sec} / {_esc_md(rc.section_name)}{sec_r}"
                if rc.rulebase_type == "nat":
                    orig_src_md, _ = _render_scalar_cell(
                        rc.original_source or "Any",
                        diffs_map_md.get("original-source"),
                        _MD_FMT,
                        fallback="Any",
                    )
                    trans_src_md, _ = _render_scalar_cell(
                        rc.translated_source or "Original",
                        diffs_map_md.get("translated-source"),
                        _MD_FMT,
                        fallback="Original",
                    )
                    src = f"{orig_src_md} -> {trans_src_md}"

                    orig_dst_md, _ = _render_scalar_cell(
                        rc.original_destination or "Any",
                        diffs_map_md.get("original-destination"),
                        _MD_FMT,
                        fallback="Any",
                    )
                    trans_dst_md, _ = _render_scalar_cell(
                        rc.translated_destination or "Original",
                        diffs_map_md.get("translated-destination"),
                        _MD_FMT,
                        fallback="Original",
                    )
                    dst = f"{orig_dst_md} -> {trans_dst_md}"

                    orig_svc_md, _ = _render_scalar_cell(
                        rc.original_service or "Any",
                        diffs_map_md.get("original-service"),
                        _MD_FMT,
                        fallback="Any",
                    )
                    trans_svc_md, _ = _render_scalar_cell(
                        rc.translated_service or "Original",
                        diffs_map_md.get("translated-service"),
                        _MD_FMT,
                        fallback="Original",
                    )
                    svc = f"{orig_svc_md} -> {trans_svc_md}"
                    act, _ = _render_scalar_cell(
                        rc.method or "nat", diffs_map_md.get("method"), _MD_FMT, fallback="nat"
                    )
                else:
                    src, _ = _render_list_cell(
                        rc.source,
                        diffs_map_md.get("source"),
                        _MD_FMT,
                        empty_fallback="Any",
                        negate=rc.source_negate,
                    )
                    dst, _ = _render_list_cell(
                        rc.destination,
                        diffs_map_md.get("destination"),
                        _MD_FMT,
                        empty_fallback="Any",
                        negate=rc.destination_negate,
                    )
                    svc, _ = _render_list_cell(
                        rc.service,
                        diffs_map_md.get("service"),
                        _MD_FMT,
                        empty_fallback="Any",
                        negate=rc.service_negate,
                    )
                    act, _ = _render_scalar_cell(rc.action or "", diffs_map_md.get("action"), _MD_FMT)
                track_md, _ = _render_scalar_cell(rc.track or "", diffs_map_md.get("track"), _MD_FMT)
                name_md, _ = _render_scalar_cell(rc.name, diffs_map_md.get("name"), _MD_FMT)
                comments_md, _ = _render_scalar_cell(rc.comments, diffs_map_md.get("comments"), _MD_FMT)
                lines.append(
                    f"| {_esc_md(rc.rule_number or '—')} | {_operation_label_md(rc)} | {en_mark} | "
                    f"{layer_sec} | {name_md} | {src} | {dst} | {svc} | {act} | {track_md} | {comments_md} |"
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
                oc_diffs_md: dict[str, FieldDiff] = (
                    {d.field_name.strip().lower(): d for d in oc.field_diffs} if oc.operation == "modified" else {}
                )
                oc_name_md, _ = _render_scalar_cell(oc.name, oc_diffs_md.get("name"), _MD_FMT)
                lines.append(
                    f"| {op_lbl} | {_esc_md(oc.object_type)} | {oc_name_md} | "
                    f"`{_esc_md(oc.uid)}` | {_render_object_details(oc, _MD_FMT)} |"
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
    refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None,
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
        refresh_rulebase_fn=refresh_rulebase_fn,
    )
    return render_change_report(report, formats=formats, options=options)


__all__ = [
    "SUPPORTED_REPORT_FORMATS",
    "build_change_report",
    "render_change_report",
    "render_safe_inline_markdown_html",
    "render_safe_inline_markdown_md",
]
