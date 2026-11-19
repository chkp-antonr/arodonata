"""Standalone Markdown document rendering (`arodonata.reports._renderer_markdown`)."""

from __future__ import annotations

from collections.abc import Sequence

from arodonata.reports._renderer_formatting import (
    _MD_FMT,
    _esc_md,
    _format_dt_utc,
    _render_enabled_cell,
    _render_list_cell,
    _render_nat_rule_cells,
    _render_object_details,
    _render_scalar_cell,
    render_safe_inline_markdown_md,
)
from arodonata.reports.models import ChangeReport, FieldDiff, RenderOptions, RuleChangeEntry


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


def _append_field_diffs_markdown(lines: list[str], heading: str, diffs: Sequence[FieldDiff]) -> None:
    """Append a Markdown `Field Diffs` table for a rule or object change entry."""
    lines.append(heading)
    lines.append("")
    lines.append("| Field | Before | After | Added | Removed |")
    lines.append("| --- | --- | --- | --- | --- |")
    for d in diffs:
        lines.append(
            f"| {_esc_md(d.field_name)} | {_esc_md(d.old_value)} | {_esc_md(d.new_value)} | "
            f"{_esc_md(d.added_items)} | {_esc_md(d.removed_items)} |"
        )
    lines.append("")


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
                    src, _, dst, _, svc, _, act, _ = _render_nat_rule_cells(rc, diffs_map_md, _MD_FMT, arrow="->")
                else:
                    src, _ = _render_list_cell(
                        rc.source, diffs_map_md.get("source"), _MD_FMT, empty_fallback="Any", negate=rc.source_negate
                    )
                    dst, _ = _render_list_cell(
                        rc.destination,
                        diffs_map_md.get("destination"),
                        _MD_FMT,
                        empty_fallback="Any",
                        negate=rc.destination_negate,
                    )
                    svc, _ = _render_list_cell(
                        rc.service, diffs_map_md.get("service"), _MD_FMT, empty_fallback="Any", negate=rc.service_negate
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
                        _append_field_diffs_markdown(
                            lines,
                            f"#### Field Diffs for Rule #{_esc_md(rc.rule_number or rc.uid)} ({_esc_md(rc.name or rc.uid)})",
                            rc.field_diffs,
                        )

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
            if options.include_field_diffs:
                for oc in s.object_changes:
                    if oc.field_diffs:
                        _append_field_diffs_markdown(
                            lines,
                            f"#### Field Diffs for Object {_esc_md(oc.name or oc.uid)} ({_esc_md(oc.object_type)})",
                            oc.field_diffs,
                        )

    return "\n".join(lines)
