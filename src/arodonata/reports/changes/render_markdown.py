"""Markdown change report for MCP (spec 6.4): the HTML structure without colour.

Markers: ``[+]`` added, ``[-]`` deleted (row cells struck through), ``[~]`` modified, ``[x]`` appended for disabled;
items ``+added``, ``~~removed~~``, ``modified*``; changed scalars bold; negation ``not (a, b)``. Every CP-sourced string
goes through escape_md first, so these markers are the only live markup. No raw appendix.
"""

from __future__ import annotations

from dataclasses import dataclass

from .markup import escape_md, inline_markdown
from .model import ChangeReport, FieldChange, ObjectChange
from .render import RenderOptions
from .view import CellView, DetailView, RowView, SessionView, TableView, report_view

MARKER = {"added": "[+]", "deleted": "[-]", "modified": "[~]"}


@dataclass
class _Budget:
    limit: int | None
    used: int = 0
    skipped: int = 0

    def take(self) -> bool:
        if self.limit is not None and self.used >= self.limit:
            self.skipped += 1
            return False
        self.used += 1
        return True


def _cell(cell: CellView) -> str:
    if cell.items is None:
        text = escape_md(cell.text or "")
        return f"**{text}**" if cell.changed and text else text
    parts = []
    for item in cell.items:
        name = escape_md(item.name)
        parts.append({"added": f"+{name}", "removed": f"~~{name}~~", "modified": f"{name}\\*"}.get(item.status, name))
    text = ", ".join(parts)
    return f"not ({text})" if cell.negated else text


def _rule_line(row: RowView) -> str:
    marker = MARKER.get(row.status or "", "") + (" [x]" if row.disabled else "")
    number = row.number or "–"
    if row.section_position is not None:
        number += f" (position {row.section_position} in its section)"
    if row.previous_number:
        number += f" (was {row.previous_number})"
    elif row.moved:
        number += " (moved)"
    if row.basis_label:
        number += f" ({row.basis_label})"
    cells = [_cell(c) for c in row.cells]
    if row.status == "deleted":
        cells = [f"~~{c}~~" if c else c for c in cells]
    return "| " + " | ".join([marker, number, *cells]) + " |"


def _section_line(row: RowView, width: int) -> str:
    text = f"**{escape_md(row.name)}**" + (f" ({row.section_range})" if row.section_range else "")
    for change in row.section_changes:
        if change.field == "name" and change.old:
            text += f" (renamed from {escape_md(change.old)})"
    if row.status:
        text += f" {MARKER[row.status]}"
    return "| | " + text + " |" + " |" * width


def _change(change: FieldChange) -> str:
    field = escape_md(change.field)
    if change.removed or change.added:
        refs = [f"-{escape_md(r.name)}" for r in change.removed] + [f"+{escape_md(r.name)}" for r in change.added]
        return f"{field}: {' '.join(refs)}"
    return f"{field}: {escape_md(change.old or '')} → {escape_md(change.new or '')}"


def _changes_text(changes: tuple[FieldChange, ...] | list[FieldChange], others: tuple[str, ...] | list[str]) -> str:
    parts = [_change(c) for c in changes]
    if others:
        parts.append(f"other fields changed: {', '.join(escape_md(o) for o in others)}")
    return "; ".join(parts) or "no compared field differs (see JSON)"


def _detail(d: DetailView) -> str:
    return f"- {escape_md(d.label)}: {_changes_text(d.changes, d.other_fields)}"


def _table(table: TableView, heading: str, budget: _Budget, out: list[str]) -> None:
    lines: list[str] = []
    pending: str | None = None
    shown: set[str] = set()
    for row in table.rows:
        if row.kind == "section":
            pending = _section_line(row, len(table.columns))
            continue
        if not budget.take():
            continue
        if pending is not None:
            lines.append(pending)
            pending = None
        lines.append(_rule_line(row))
        shown.add(row.anchor or "")
    if not lines:
        return
    titles = ["", "No.", *(escape_md(title) for _, title in table.columns)]
    out += ["", heading, "", "| " + " | ".join(titles) + " |", "|" + "---|" * len(titles), *lines]
    details = [_detail(d) for d in table.details if d.anchor in shown]
    if details:
        out += ["", *details]


def _object_line(o: ObjectChange) -> str:
    head = f"- {MARKER[o.status]} {escape_md(o.type)} {escape_md(o.name)}"
    if o.status == "modified":
        return f"{head}: {_changes_text(o.changes, o.other_fields)}"
    return f"{head} ({escape_md(o.key_value)})" if o.key_value else head


def _session(s: SessionView, rules: _Budget, objects: _Budget, out: list[str]) -> None:
    session = s.session
    out += [
        "",
        f"#### {escape_md(session.name)}",
        "",
        f"- Session: {escape_md(session.uid)}",
        f"- Administrator: {escape_md(session.user_name)}",
    ]
    if session.description:
        out.append(f"- Description: {escape_md(session.description)}")
    out.append(f"- {s.published_label}")
    if s.numbering_label:
        out.append(f"- {escape_md(s.numbering_label)}")
    if s.empty:
        out += ["", "No visible changes"]
    for rb in s.rulebases:
        for table in rb.tables:
            _table(table, f"##### {rb.title} / {escape_md(table.title)}", rules, out)
        if rb.unplaced is not None:
            _table(rb.unplaced, f"##### {rb.title} / Not placed in a package", rules, out)
    for title, items in (
        ("Section changes", s.sections),
        ("Objects", (*s.added_deleted, *s.modified_objects)),
        ("Other changes", s.other),
    ):
        lines = [_object_line(o) for o in items if objects.take()]
        if lines:
            out += ["", f"##### {title}", "", *lines]
    if s.internal_count:
        out += ["", f"Hidden internal changes: {s.internal_count} (see JSON)"]


def render_markdown(report: ChangeReport, options: RenderOptions) -> str:
    view = report_view(report)
    out = [f"# {inline_markdown(options.title)}", ""]
    if options.header_fields:
        out += [f"- {inline_markdown(k)}: {inline_markdown(v)}" for k, v in options.header_fields.items()]
        out.append("")
    meta = f"Generated {view.generated_at} UTC"
    if options.generated_by:
        meta += f" · Generated by {escape_md(options.generated_by)}"
    out.append(f"{meta} · arodonata {escape_md(view.version)}")
    if view.warnings:
        out += ["", "## Warnings", ""]
        out += [
            f"- [{w.severity}] {escape_md(g.mgmt)} / {escape_md(g.domain or 'SMC User')}: {escape_md(w.code)}: "
            f"{escape_md(w.message)}"
            for g in view.warnings
            for w in g.items
        ]
    rules, objects = _Budget(options.markdown_max_rules), _Budget(options.markdown_max_objects)
    for server in view.servers:
        out += ["", f"## {escape_md(server.name)}"]
        for domain in server.domains:
            out += ["", f"### {escape_md(domain.display_name)}"]
            for s in domain.sessions:
                _session(s, rules, objects, out)
            if domain.unavailable is not None:
                out += [
                    "",
                    f"Domain unavailable: {escape_md(domain.unavailable.code)}: "
                    f"{escape_md(domain.unavailable.message)}",
                ]
    if rules.skipped:
        out += ["", f"…and {rules.skipped} more rules, full report via the library"]
    if objects.skipped:
        out += ["", f"…and {objects.skipped} more objects, full report via the library"]
    return "\n".join(out) + "\n"
