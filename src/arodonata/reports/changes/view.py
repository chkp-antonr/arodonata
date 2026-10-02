"""Pure: a ChangeReport as render-ready rows shared by the HTML and markdown renderers (plan decision 4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .columns import COLUMNS, RULEBASE_TITLES
from .model import (
    ChangeReport,
    ChangeStatus,
    DomainError,
    FieldChange,
    ItemStatus,
    ObjectChange,
    RawResponse,
    ReportWarning,
    RulebaseKind,
    RuleChange,
    RulePlacement,
    SectionHeader,
    SessionChanges,
)

BASIS_LABELS = {
    "before-deletion": "before deletion",
    "at-time-of-change": "at time of change",
    "provisional": "provisional",
}
PROVISIONAL_LABEL = (
    "Provisional numbering: unpublished session; numbers are the last published policy plus in-layer positions"
)


@dataclass(frozen=True)
class ItemView:
    name: str
    status: ItemStatus
    link: str | None  # object detail anchor, only when that object is rendered


@dataclass(frozen=True)
class CellView:
    key: str
    items: tuple[ItemView, ...] | None
    text: str | None
    changed: bool
    negated: bool
    link: str | None  # the placement's detail anchor (changed cells of modified rules)


@dataclass(frozen=True)
class RowView:
    kind: Literal["rule", "section"]
    status: ChangeStatus | None
    name: str = ""
    disabled: bool = False
    enabled_changed: bool = False
    number: str | None = None
    previous_number: str | None = None
    moved: bool = False
    basis_label: str = ""
    cells: tuple[CellView, ...] = ()
    section_range: str | None = None
    section_changes: tuple[FieldChange, ...] = ()
    section_position: int | None = None  # D27: no number, the position within its section
    anchor: str | None = None


@dataclass(frozen=True)
class DetailView:
    anchor: str
    label: str
    changes: tuple[FieldChange, ...]
    other_fields: tuple[str, ...]


@dataclass(frozen=True)
class TableView:
    title: str
    columns: tuple[tuple[str, str], ...]  # visible data columns (key, title); enabled/number are always rendered
    rows: tuple[RowView, ...]
    details: tuple[DetailView, ...]


@dataclass(frozen=True)
class RulebaseView:
    kind: RulebaseKind
    title: str
    tables: tuple[TableView, ...]
    unplaced: TableView | None


@dataclass(frozen=True)
class SessionView:
    session: SessionChanges
    anchor: str
    published_label: str
    numbering_label: str
    rulebases: tuple[RulebaseView, ...]
    sections: tuple[ObjectChange, ...]
    added_deleted: tuple[ObjectChange, ...]
    modified_objects: tuple[ObjectChange, ...]
    other: tuple[ObjectChange, ...]
    internal_count: int
    empty: bool
    counts_text: str


@dataclass(frozen=True)
class DomainView:
    domain: str
    display_name: str
    unavailable: DomainError | None
    sessions: tuple[SessionView, ...]


@dataclass(frozen=True)
class ServerView:
    name: str
    domains: tuple[DomainView, ...]


@dataclass(frozen=True)
class WarningGroup:
    mgmt: str
    domain: str
    items: tuple[ReportWarning, ...]


@dataclass(frozen=True)
class ReportView:
    generated_at: str
    version: str
    servers: tuple[ServerView, ...]
    warnings: tuple[WarningGroup, ...]
    raw: tuple[RawResponse, ...]


def fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt is not None else ""


def _at_utc(dt: datetime | None) -> str:
    return f" at {fmt_time(dt)} UTC" if dt is not None else ""


def numbering_label(session: SessionChanges) -> str:
    info = session.numbering
    if info.source == "none":
        return ""
    if info.status == "failed":
        return f"Numbering unavailable: {info.last_error or 'unknown error'}"
    if info.source == "live":
        return f"Numbering read live in the owned session{_at_utc(info.snapshot_refreshed_at)}"
    if info.provisional:
        return PROVISIONAL_LABEL
    if info.snapshot_session_uid == session.uid:
        label = "Numbering as of this session's publish"
    else:
        label = (
            f"Numbering as of publish of {info.snapshot_session_uid or 'an unversioned snapshot'}"
            f"{_at_utc(info.snapshot_published_at)}"
        )
    return f"{label} (Global packages)" if info.global_packages else label


def _cells(rule: RuleChange, keys: list[str], anchor: str, rendered: set[str]) -> tuple[CellView, ...]:
    out: list[CellView] = []
    for key in keys:
        cell = rule.cells.get(key)
        if cell is None:
            out.append(CellView(key, None, "", False, False, None))
            continue
        items = (
            None
            if cell.items is None
            else tuple(ItemView(i.name, i.status, i.anchor if i.anchor in rendered else None) for i in cell.items)
        )
        link = anchor if rule.status == "modified" and cell.changed else None
        out.append(CellView(key, items, cell.text, cell.changed, cell.negated, link))
    return tuple(out)


def _rule_row(rule: RuleChange, p: RulePlacement, keys: list[str], rendered: set[str]) -> RowView:
    return RowView(
        kind="rule",
        status=rule.status,
        name=rule.name,
        disabled=not rule.enabled,
        enabled_changed=rule.enabled_changed,
        number=p.number,
        previous_number=p.previous_number if rule.moved else None,
        moved=rule.moved,
        basis_label=BASIS_LABELS.get(p.basis, ""),
        section_position=p.section_position if p.number is None else None,
        cells=_cells(rule, keys, p.anchor, rendered),
        anchor=p.anchor,
    )


def _detail(rule: RuleChange, p: RulePlacement) -> DetailView | None:
    if rule.status != "modified":
        return None
    label = " ".join(x for x in (p.number, rule.name) if x) or rule.uid
    return DetailView(p.anchor, label, tuple(rule.changes), tuple(rule.other_fields))


def _table(
    title: str,
    columns: tuple[tuple[str, str], ...],
    rows_in: list[RulePlacement | SectionHeader],
    rules: dict[str, RuleChange],
    rendered: set[str],
) -> TableView:
    keys = [k for k, _ in columns]
    rows: list[RowView] = []
    details: list[DetailView] = []
    for row in rows_in:
        if isinstance(row, SectionHeader):
            rows.append(
                RowView(
                    kind="section",
                    status=row.status,
                    name=row.name,
                    section_range=row.range,
                    section_changes=tuple(row.changes),
                )
            )
            continue
        rule = rules[row.rule_uid]
        rows.append(_rule_row(rule, row, keys, rendered))
        detail = _detail(rule, row)
        if detail is not None:
            details.append(detail)
    return TableView(title, columns, tuple(rows), tuple(details))


def _counts(s: SessionChanges) -> str:
    by = {status: sum(1 for r in s.rules if r.status == status) for status in ("added", "modified", "deleted")}
    return (
        f"{len(s.rules)} rules ({by['added']} added, {by['modified']} modified, {by['deleted']} deleted), "
        f"{len(s.objects) + len(s.sections)} objects, {len(s.other)} other"
    )


def session_view(s: SessionChanges) -> SessionView:
    rules = {r.uid: r for r in s.rules}
    rendered = {o.anchor for o in (*s.objects, *s.other, *s.sections)}
    rulebases: list[RulebaseView] = []
    for block in s.rulebases:
        columns = tuple(
            (c.key, c.title) for c in COLUMNS[block.rulebase] if not c.structural and c.key in block.columns
        )
        tables = tuple(
            _table(f"{pkg.package_name} — {layer.ordered_layer_name}", columns, list(layer.rows), rules, rendered)
            for pkg in block.packages
            for layer in pkg.layers
        )
        unplaced = (
            _table("Not placed in a package", columns, list(block.unplaced), rules, rendered)
            if block.unplaced
            else None
        )
        rulebases.append(RulebaseView(block.rulebase, RULEBASE_TITLES[block.rulebase], tables, unplaced))
    return SessionView(
        session=s,
        anchor=f"s-{s.uid}",
        published_label=f"Published {fmt_time(s.published_at)} UTC" if s.published else "Not published",
        numbering_label=numbering_label(s),
        rulebases=tuple(rulebases),
        sections=tuple(s.sections),
        added_deleted=tuple(o for o in s.objects if o.status != "modified"),
        modified_objects=tuple(o for o in s.objects if o.status == "modified"),
        other=tuple(s.other),
        internal_count=len(s.internal),
        empty=not (rulebases or s.sections or s.objects or s.other),
        counts_text=_counts(s),
    )


def report_view(report: ChangeReport) -> ReportView:
    groups: dict[tuple[str, str], list[ReportWarning]] = {}
    for w in report.warnings:
        groups.setdefault((w.mgmt, w.domain), []).append(w)
    return ReportView(
        generated_at=fmt_time(report.generated_at),
        version=report.arodonata_version,
        servers=tuple(
            ServerView(
                m.mgmt_name,
                tuple(
                    DomainView(d.domain, d.display_name, d.unavailable, tuple(session_view(s) for s in d.sessions))
                    for d in m.domains
                ),
            )
            for m in report.servers
        ),
        warnings=tuple(WarningGroup(m, d, tuple(ws)) for (m, d), ws in groups.items()),
        raw=tuple(report.raw or ()),
    )
