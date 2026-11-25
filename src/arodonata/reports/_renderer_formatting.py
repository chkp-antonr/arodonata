"""Safe inline markdown, cell formatters, and object detail renderers (`arodonata.reports._renderer_formatting`)."""

from __future__ import annotations

import html
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arodonata.reports.models import FieldDiff, ObjectChangeEntry, RuleChangeEntry

SUPPORTED_REPORT_FORMATS: frozenset[str] = frozenset({"html", "json", "markdown"})

_INLINE_TOKEN_RE = re.compile(r"(`[^`\r\n]+`|\*\*[^*\r\n]+\*\*|\*[^*\r\n]+\*|\[[^\]\r\n]+\]\([^)\r\n]+\))")
_SUMMARY_SPLIT_RE = re.compile(
    r", (?=(?:ipv4-address|ipv6-address|subnet4|subnet6|range|range6|port|protocol|fqdn|members|comments)=)"
)


def _is_safe_href(url: str) -> bool:
    stripped = url.strip()
    if any(ch.isspace() or ch in "<>\"'" or ord(ch) < 32 for ch in stripped):
        return False
    clean = stripped.lower()
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
            out.append(f"`{html.escape(part[1:-1], quote=False)}`")
        elif part.startswith("**") and part.endswith("**") and len(part) >= 4:
            out.append(f"**{html.escape(part[2:-2], quote=False)}**")
        elif part.startswith("*") and part.endswith("*") and len(part) >= 2:
            out.append(f"*{html.escape(part[1:-1], quote=False)}*")
        elif part.startswith("[") and "](" in part and part.endswith(")"):
            bracket_end = part.find("](")
            label = html.escape(part[1:bracket_end], quote=False)
            href = part[bracket_end + 2 : -1].strip()
            if _is_safe_href(href):
                out.append(f"[{label}]({html.escape(href, quote=True)})")
            else:
                out.append(html.escape(part, quote=True).replace("[", "\\[").replace("]", "\\]"))
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
    return escaped.replace("|", "\\|").replace("\r\n", " ").replace("\r", " ").replace("\n", " ")


def _format_dt_utc(dt: datetime | None) -> str:
    if dt is None:
        return "N/A"
    utc_dt = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")


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


def _render_nat_rule_cells(
    rc: RuleChangeEntry,
    diffs_map: dict[str, FieldDiff],
    fmt: _CellFormatter,
    *,
    arrow: str,
) -> tuple[str, bool, str, bool, str, bool, str, bool]:
    """Render `(src, src_ann, dst, dst_ann, svc, svc_ann, act, act_ann)` for a NAT rule."""
    orig_src, os_ann = _render_scalar_cell(
        rc.original_source or "Any", diffs_map.get("original-source"), fmt, fallback="Any"
    )
    trans_src, ts_ann = _render_scalar_cell(
        rc.translated_source or "Original", diffs_map.get("translated-source"), fmt, fallback="Original"
    )
    orig_dst, od_ann = _render_scalar_cell(
        rc.original_destination or "Any", diffs_map.get("original-destination"), fmt, fallback="Any"
    )
    trans_dst, td_ann = _render_scalar_cell(
        rc.translated_destination or "Original", diffs_map.get("translated-destination"), fmt, fallback="Original"
    )
    orig_svc, osvc_ann = _render_scalar_cell(
        rc.original_service or "Any", diffs_map.get("original-service"), fmt, fallback="Any"
    )
    trans_svc, tsvc_ann = _render_scalar_cell(
        rc.translated_service or "Original", diffs_map.get("translated-service"), fmt, fallback="Original"
    )
    act_str, act_ann = _render_scalar_cell(rc.method or "nat", diffs_map.get("method"), fmt, fallback="nat")
    return (
        f"{orig_src} {arrow} {trans_src}",
        os_ann or ts_ann,
        f"{orig_dst} {arrow} {trans_dst}",
        od_ann or td_ann,
        f"{orig_svc} {arrow} {trans_svc}",
        osvc_ann or tsvc_ann,
        act_str,
        act_ann,
    )


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
        parts.append(f"range={_scalar_val('ipv4-address-first')}-{_scalar_val('ipv4-address-last')}")

    if any(k in sfields or k in diffs_by_name for k in ("ipv6-address-first", "ipv6-address-last")):
        parts.append(f"range6={_scalar_val('ipv6-address-first')}-{_scalar_val('ipv6-address-last')}")

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
