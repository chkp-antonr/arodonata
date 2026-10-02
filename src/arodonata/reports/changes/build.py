"""Pure: one show-changes session entry -> SessionChanges (spec 4).

added-objects -> added; deleted-objects -> deleted (the body is the pre-session state); modified-objects with
old-object -> modified, without old-object -> added (created in the session). Rules get one cell per data column and,
when modified, field deltas; objects, sections, other and internal types get key values and field deltas.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from .columns import (
    COLUMNS,
    IGNORED_FIELDS,
    OBJECT_COMPARE_FIELDS,
    OBJECT_KEY_FIELDS,
    Column,
    data_columns,
    is_internal_type,
    key_value,
)
from .model import (
    Cell,
    CellItem,
    ChangeStatus,
    FieldChange,
    ItemStatus,
    NamedRef,
    NumberingInfo,
    ObjectChange,
    RulebaseKind,
    RuleChange,
    SessionChanges,
)

RULE_TYPES: dict[str, RulebaseKind] = {
    "access-rule": "access",
    "nat-rule": "nat",
    "threat-rule": "threat",
    "https-rule": "https",
}
SECTION_TYPES = frozenset({"access-section", "nat-section", "threat-section", "https-section"})
_RULE_TAIL_FIELDS = ("enabled", "position", "layer", "inline-layer")
Category = Literal["rule", "section", "object", "other", "internal"]


def session_uid(entry: dict[str, Any]) -> str:
    return str((entry.get("session") or {}).get("session-uid") or "")


def published_at(meta: dict[str, Any]) -> datetime | None:
    """``publish-time.posix`` (milliseconds) as an aware UTC datetime; None for an unpublished session."""
    posix = (meta.get("publish-time") or {}).get("posix")
    return datetime.fromtimestamp(int(posix) / 1000, UTC) if posix is not None else None


def classify(obj_type: str) -> Category:
    if obj_type in RULE_TYPES:
        return "rule"
    if obj_type in SECTION_TYPES:
        return "section"
    if obj_type in OBJECT_KEY_FIELDS:
        return "object"
    if is_internal_type(obj_type):
        return "internal"
    return "other"


@dataclass(frozen=True)
class _Entry:
    status: ChangeStatus
    old: dict[str, Any] | None  # modified: old-object; deleted: the pre-session body
    new: dict[str, Any] | None  # added / modified: the session's body

    @property
    def body(self) -> dict[str, Any]:
        """What the report shows: the new body, the pre-session body for a deleted object."""
        return self.new if self.new is not None else (self.old or {})

    @property
    def uid(self) -> str:
        return str(self.body.get("uid") or "")

    @property
    def type(self) -> str:
        return str(self.body.get("type") or "")


def _entries(operations: dict[str, Any]) -> list[_Entry]:
    out = [_Entry("added", None, e) for e in operations.get("added-objects") or [] if isinstance(e, dict)]
    for e in operations.get("modified-objects") or []:
        if not isinstance(e, dict) or not isinstance(e.get("new-object"), dict):
            continue
        if isinstance(e.get("old-object"), dict):
            out.append(_Entry("modified", e["old-object"], e["new-object"]))
        else:
            out.append(_Entry("added", None, e["new-object"]))
    out += [_Entry("deleted", e, None) for e in operations.get("deleted-objects") or [] if isinstance(e, dict)]
    seen: set[tuple[str, str]] = set()
    unique: list[_Entry] = []
    for e in out:  # R1 (F3): a moved rule can appear twice, byte-identical
        if (e.status, e.uid) not in seen:
            seen.add((e.status, e.uid))
            unique.append(e)
    return unique


def _uid_of(value: Any) -> str | None:
    if isinstance(value, dict):
        return str(value["uid"]) if value.get("uid") else None
    return str(value) if isinstance(value, str) and value else None


def ref(value: Any) -> NamedRef | None:
    """A reference: dereferenced object -> uid and name; bare uid string -> the uid as both (names.py resolves)."""
    uid = _uid_of(value)
    if uid is None:
        return None
    name = value.get("name") if isinstance(value, dict) else None
    return NamedRef(uid=uid, name=str(name) if name else uid)


def refs(value: Any) -> list[NamedRef]:
    items = value if isinstance(value, list) else ([] if value in (None, "") else [value])
    return [r for r in (ref(v) for v in items) if r is not None]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return str(value.get("name") or value.get("uid") or "")
    if isinstance(value, list):
        return ", ".join(_text(v) for v in value)
    return str(value)


def _norm(value: Any) -> Any:
    """Structural compare form: references reduce to their uid (dereferenced bodies carry changing meta-info)."""
    if isinstance(value, dict):
        if value.get("uid") and "type" in value:
            return str(value["uid"])
        return {k: _norm(v) for k, v in value.items() if k not in IGNORED_FIELDS}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, dict | list)


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _column_ref(column: Column, body: dict[str, Any] | None) -> NamedRef | None:
    if body is None or column.field is None:
        return None
    value = body.get(column.field)
    if column.kind == "track" and isinstance(value, dict) and isinstance(value.get("type"), dict):
        value = value["type"]
    return ref(value)


def _list_delta(old: Any, new: Any) -> tuple[list[NamedRef], list[NamedRef]]:
    o, n = refs(old), refs(new)
    o_uids, n_uids = {r.uid for r in o}, {r.uid for r in n}
    return [r for r in o if r.uid not in n_uids], [r for r in n if r.uid not in o_uids]


def _cell(column: Column, e: _Entry, session_modified: set[str], sid: str) -> Cell:
    current = e.body
    before = e.old if e.status == "modified" else None
    negated = bool(current.get(column.negate_field)) if column.negate_field else False
    negate_changed = (
        before is not None and column.negate_field is not None and bool(before.get(column.negate_field)) != negated
    )
    if column.kind == "list":
        new_items = refs(current.get(column.field)) if column.field else []
        old_items = refs(before.get(column.field)) if before is not None and column.field else new_items
        old_uids, new_uids = {r.uid for r in old_items}, {r.uid for r in new_items}
        items: list[CellItem] = []
        for r in new_items:
            status: ItemStatus = (
                "added" if r.uid not in old_uids else ("modified" if r.uid in session_modified else "unchanged")
            )
            items.append(
                CellItem(
                    uid=r.uid, name=r.name, status=status, anchor=f"o-{sid}-{r.uid}" if status == "modified" else None
                )
            )
        items += [CellItem(uid=r.uid, name=r.name, status="removed") for r in old_items if r.uid not in new_uids]
        changed = negate_changed or any(i.status in ("added", "removed") for i in items)
        default = (
            not changed
            and not negated
            and (not new_items or (len(new_items) == 1 and new_items[0].name in column.default_names))
        )
        return Cell(items=items, changed=changed, negated=negated, default=default)
    if column.kind in ("ref", "track"):
        new_ref, old_ref = _column_ref(column, current), _column_ref(column, before)
        text = new_ref.name if new_ref else ""
        changed = before is not None and (old_ref.uid if old_ref else None) != (new_ref.uid if new_ref else None)
    else:
        text = _text(current.get(column.field)) if column.field else ""
        changed = before is not None and column.field is not None and _text(before.get(column.field)) != text
    default = not changed and (text == "" or (column.kind in ("ref", "track") and text in column.default_names))
    return Cell(text=text, changed=changed, negated=negated, default=default)


def _outside(old: dict[str, Any], new: dict[str, Any], compared: set[str]) -> tuple[list[FieldChange], list[str]]:
    """Fields outside the allowlist: scalars -> FieldChange; dicts one level deep (scalar subkeys -> "a.b"); anything
    deeper or a list -> a name in other_fields."""
    changes: list[FieldChange] = []
    others: list[str] = []
    for key in dict.fromkeys([*old, *new]):
        if key in compared or key in IGNORED_FIELDS:
            continue
        o, n = old.get(key), new.get(key)
        if _norm(o) == _norm(n):
            continue
        if isinstance(o, dict | None) and isinstance(n, dict | None) and (isinstance(o, dict) or isinstance(n, dict)):
            od, nd = o or {}, n or {}
            for sub in dict.fromkeys([*od, *nd]):
                so, sn = od.get(sub), nd.get(sub)
                if _norm(so) == _norm(sn):
                    continue
                if _is_scalar(so) and _is_scalar(sn):
                    changes.append(FieldChange(field=f"{key}.{sub}", old=_text(so), new=_text(sn)))
                elif key not in others:
                    others.append(key)
        elif _is_scalar(o) and _is_scalar(n):
            changes.append(FieldChange(field=key, old=_text(o), new=_text(n)))
        else:
            others.append(key)
    return changes, others


def _rule_layer(body: dict[str, Any] | None) -> str | None:
    """The layer holding the rule: ``layer``; NAT bodies may carry ``package`` instead (R1)."""
    if body is None:
        return None
    return _uid_of(body.get("layer")) or _uid_of(body.get("package"))


def _field_change(column: Column, old: dict[str, Any], new: dict[str, Any]) -> FieldChange | None:
    """The delta of a column's main field, or None when unchanged."""
    field = column.field
    if field is None:
        return None
    if column.kind == "list":
        removed, added = _list_delta(old.get(field), new.get(field))
        return FieldChange(field=field, removed=removed, added=added) if removed or added else None
    if column.kind in ("ref", "track"):
        o, n = _column_ref(column, old), _column_ref(column, new)
        if (o.uid if o else None) == (n.uid if n else None):
            return None
        return FieldChange(field=field, old=o.name if o else None, new=n.name if n else None)
    if _text(old.get(field)) == _text(new.get(field)):
        return None
    return FieldChange(field=field, old=_text(old.get(field)), new=_text(new.get(field)))


def _tail_changes(old: dict[str, Any], new: dict[str, Any]) -> list[FieldChange]:
    changes: list[FieldChange] = []
    for field in _RULE_TAIL_FIELDS:
        if field == "enabled":
            o_text, n_text = _text(bool(old.get(field, True))), _text(bool(new.get(field, True)))
        elif field in ("layer", "inline-layer"):
            o_text, n_text = _uid_of(old.get(field)) or "", _uid_of(new.get(field)) or ""
        else:
            o_text, n_text = _text(old.get(field)), _text(new.get(field))
        if o_text != n_text:
            changes.append(FieldChange(field=field, old=o_text, new=n_text))
    return changes


def _rule_changes(kind: RulebaseKind, old: dict[str, Any], new: dict[str, Any]) -> tuple[list[FieldChange], list[str]]:
    changes: list[FieldChange] = []
    compared: set[str] = set(_RULE_TAIL_FIELDS)
    for column in data_columns(kind):
        if column.field is not None:
            compared.add(column.field)
            change = _field_change(column, old, new)
            if change is not None:
                changes.append(change)
        if column.negate_field is not None:
            compared.add(column.negate_field)
            o_neg, n_neg = bool(old.get(column.negate_field)), bool(new.get(column.negate_field))
            if o_neg != n_neg:
                changes.append(FieldChange(field=column.negate_field, old=_text(o_neg), new=_text(n_neg)))
    changes += _tail_changes(old, new)
    if kind == "nat":
        compared.add("package")
    outside, others = _outside(old, new, compared)
    return changes + outside, others


def _moved_rules(rules: list[_Entry]) -> set[str]:
    """Modified rules the session moved (D27): CP sends ``position`` in a modified rule's old/new pair only when the
    rule itself moved (F1), and a move to another section can keep the same number (F2) — so presence decides."""
    return {
        e.uid
        for e in rules
        if e.status == "modified"
        and ("position" in (e.old or {}) or "position" in (e.new or {}) or _rule_layer(e.old) != _rule_layer(e.new))
    }


def _with_position(changes: list[FieldChange], old: dict[str, Any], new: dict[str, Any]) -> list[FieldChange]:
    """A rule moved to another section can keep its position (F2): still say where it was and where it is."""
    if any(c.field == "position" for c in changes) or ("position" not in old and "position" not in new):
        return changes
    return [*changes, FieldChange(field="position", old=_text(old.get("position")), new=_text(new.get("position")))]


def _rule(e: _Entry, sid: str, session_modified: set[str], moved: set[str]) -> RuleChange:
    kind = RULE_TYPES[e.type]
    current = e.body
    old = e.old if e.status != "added" else None
    enabled = bool(current.get("enabled", True))
    changes, others = _rule_changes(kind, e.old or {}, e.new or {}) if e.status == "modified" else ([], [])
    if e.uid in moved:
        changes = _with_position(changes, e.old or {}, e.new or {})
    return RuleChange(
        uid=e.uid,
        type=e.type,
        rulebase=kind,
        name=str(current.get("name") or ""),
        status=e.status,
        enabled=enabled,
        enabled_changed=e.status == "modified" and bool((e.old or {}).get("enabled", True)) != enabled,
        layer_uid=_rule_layer(current),
        position=_int(current.get("position")),
        old_layer_uid=_rule_layer(old),
        old_position=_int(old.get("position")) if old is not None else None,
        moved=e.uid in moved,
        inline_layer_uid=_uid_of(current.get("inline-layer")),
        cells={c.key: _cell(c, e, session_modified, sid) for c in COLUMNS[kind] if not c.structural},
        changes=changes,
        other_fields=others,
        anchor_base=f"r-{sid}-{e.uid}",
    )


def _object_changes(e: _Entry, category: Category) -> tuple[list[FieldChange], list[str]]:
    old, new = e.old or {}, e.new or {}
    fields: tuple[str, ...] = ()
    if category == "object":
        fields = OBJECT_KEY_FIELDS.get(e.type, ()) + OBJECT_COMPARE_FIELDS
    elif category == "section":
        fields = ("name",)
    changes: list[FieldChange] = []
    compared = set(fields)
    for field in fields:
        if field == "tags":
            removed, added = _list_delta(old.get(field), new.get(field))
            if removed or added:
                changes.append(FieldChange(field=field, removed=removed, added=added))
        elif _text(old.get(field)) != _text(new.get(field)):
            changes.append(FieldChange(field=field, old=_text(old.get(field)), new=_text(new.get(field))))
    if isinstance(old.get("members"), list) or isinstance(new.get("members"), list):
        compared.add("members")
        removed, added = _list_delta(old.get("members"), new.get("members"))
        if removed or added:
            changes.append(FieldChange(field="members", removed=removed, added=added))
    outside, others = _outside(old, new, compared)
    return changes + outside, others


def _object(e: _Entry, sid: str, category: Category) -> ObjectChange:
    changes, others = _object_changes(e, category) if e.status == "modified" else ([], [])
    return ObjectChange(
        uid=e.uid,
        type=e.type,
        name=str(e.body.get("name") or ""),
        status=e.status,
        category="object" if category == "object" else ("section" if category == "section" else "other"),
        internal=category == "internal",
        key_value=key_value(e.type, e.body) if e.status != "modified" else "",
        changes=changes,
        other_fields=others,
        anchor=f"o-{sid}-{e.uid}",
    )


def build_session(entry: dict[str, Any]) -> SessionChanges:
    """One show-changes session entry as SessionChanges; numbering source "none" and no rulebase blocks yet."""
    meta = entry.get("session") or {}
    sid = session_uid(entry)
    entries = _entries(entry.get("operations") or {})
    session_modified = {e.uid for e in entries if e.status == "modified"}
    rule_entries = [e for e in entries if classify(e.type) == "rule"]
    moved = _moved_rules(rule_entries)
    groups: dict[Category, list[ObjectChange]] = {"section": [], "object": [], "other": [], "internal": []}
    for e in entries:
        category = classify(e.type)
        if category != "rule":
            groups[category].append(_object(e, sid, category))
    return SessionChanges(
        uid=sid,
        name=str(meta.get("session-name") or ""),
        description=str(meta.get("session-description") or ""),
        user_name=str(meta.get("user-name") or ""),
        published=bool(meta.get("published")),
        published_at=published_at(meta),
        numbering=NumberingInfo(source="none"),
        rules=[_rule(e, sid, session_modified, moved) for e in rule_entries],
        rulebases=[],
        sections=groups["section"],
        objects=groups["object"],
        other=groups["other"],
        internal=groups["internal"],
    )
