"""Turn numbered rulebase entries (cache or live) into rows, then into markdown or compact structured text.

Ported in spirit from the reference server's rulebase parser. The reference's padded fixed-width table is intentionally
not reproduced (decision 2026-09-27): cells always carry full values.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..rulebase.model import OrderedLayer, RulebaseType, RuleItem
from ..rulebase.numbering import NumberedEntry, number_layer
from ..rulebase.parse import parse_layer_response
from .projection import project

if TYPE_CHECKING:
    from ..rulebase.source import PackageRulebase


@dataclass
class RuleRow:
    number: str
    name: str
    enabled: bool
    sources: list[str]
    destinations: list[str]
    services: list[str]
    action: str
    track: str
    section: str = ""
    inline_layer: str = ""
    comments: str = ""
    depth: int = 0
    negate: dict[str, bool] = field(default_factory=dict)
    extra: dict[str, str] = field(default_factory=dict)
    kind: str = "rule"  # rule | place-holder | parent-rule | section | layer
    section_range: str = ""


def _names(values: Any, lookup: dict[str, str]) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    out: list[str] = []
    for v in values:
        if isinstance(v, dict):
            out.append(str(v.get("name") or lookup.get(str(v.get("uid")), v.get("uid", ""))))
        else:
            out.append(lookup.get(str(v), str(v)))
    return out


def _one(value: Any, lookup: dict[str, str]) -> str:
    if isinstance(value, dict):
        inner = value.get("type", value.get("name", value.get("uid", "")))
        return (
            _one(inner, lookup) if isinstance(inner, dict) else lookup.get(str(inner), str(value.get("name") or inner))
        )
    return lookup.get(str(value), str(value or ""))


def _rule_from_raw(raw: dict[str, Any], lookup: dict[str, str], number: str, depth: int, section: str) -> RuleRow:
    negate = {k: True for k in ("source", "destination", "service") if raw.get(f"{k}-negate")}
    inline = raw.get("inline-layer")
    inline_name = (
        inline.get("name", "") if isinstance(inline, dict) else lookup.get(str(inline), str(inline)) if inline else ""
    )
    extra: dict[str, str] = {}
    for key in (
        "method",
        "original-source",
        "original-destination",
        "original-service",
        "translated-source",
        "translated-destination",
        "translated-service",
        "protection",
        "site-category",
        "blade",
    ):
        if key in raw:
            extra[key] = ", ".join(_names(raw[key], lookup))
    return RuleRow(
        number=number,
        name=str(raw.get("name") or ""),
        enabled=bool(raw.get("enabled", True)),
        sources=_names(raw.get("source"), lookup),
        destinations=_names(raw.get("destination"), lookup),
        services=_names(raw.get("service"), lookup),
        action=_one(raw.get("action"), lookup),
        track=_one(raw.get("track"), lookup),
        section=section,
        inline_layer=inline_name,
        comments=str(raw.get("comments") or ""),
        depth=depth,
        negate=negate,
        extra=extra,
    )


def _lookup(dictionary: Sequence[Mapping[str, str]]) -> dict[str, str]:
    return {str(o["uid"]): str(o.get("name") or o["uid"]) for o in dictionary if o.get("uid")}


def _header(kind: str, name: str, depth: int, section_range: str = "") -> RuleRow:
    return RuleRow(
        number="",
        name=name,
        enabled=True,
        sources=[],
        destinations=[],
        services=[],
        action="",
        track="",
        depth=depth,
        kind=kind,
        section_range=section_range,
    )


def layer_header(name: str) -> RuleRow:
    """The header row printed before an ordered layer when a package view shows several."""
    return _header("layer", name, 0)


def rows_from_entries(
    entries: Sequence[NumberedEntry],
    layer_names: Mapping[str, str],
    layer_dictionaries: Mapping[str, Sequence[Mapping[str, str]]],
) -> list[RuleRow]:
    """Rows of numbered entries; references resolve through the dictionary of the layer that holds each entry."""
    lookups: dict[str, dict[str, str]] = {}
    rows: list[RuleRow] = []
    for entry in entries:
        if entry.kind == "section":
            rows.append(_header("section", entry.name, entry.depth, entry.range))
            continue
        lookup = lookups.setdefault(entry.layer_uid, _lookup(layer_dictionaries.get(entry.layer_uid, ())))
        inline_uid = entry.inline_layer_uid or ""
        inline_name = (layer_names.get(inline_uid) or lookup.get(inline_uid, "")) if inline_uid else ""
        if entry.kind == "parent-rule":
            rows.append(
                RuleRow(
                    number=entry.number,
                    name=entry.name,
                    enabled=True,
                    sources=[],
                    destinations=[],
                    services=[],
                    action="Domain Layer",
                    track="",
                    section=entry.section_name or "",
                    inline_layer=inline_name or inline_uid,
                    depth=entry.depth,
                    kind="parent-rule",
                )
            )
            continue
        raw = entry.item.raw if isinstance(entry.item, RuleItem) else {}
        row = _rule_from_raw(raw, lookup, entry.number, entry.depth, entry.section_name or "")
        row.kind = entry.kind
        # Keep the rule's own inline-layer name (a live dict) unless the snapshot or dictionary resolves the uid.
        row.inline_layer = inline_name or row.inline_layer or inline_uid
        rows.append(row)
    return rows


def drop_disabled(entries: Sequence[NumberedEntry]) -> list[NumberedEntry]:
    """Remove disabled rules and their inline subtree (deeper entries that follow); numbers are unchanged."""
    kept: list[NumberedEntry] = []
    skip_deeper_than: int | None = None
    for entry in entries:
        if skip_deeper_than is not None and entry.depth > skip_deeper_than:
            continue
        skip_deeper_than = None
        if entry.kind == "rule" and isinstance(entry.item, RuleItem) and not entry.item.enabled:
            skip_deeper_than = entry.depth
            continue
        kept.append(entry)
    return kept


OrderedEntries = tuple[OrderedLayer, tuple[NumberedEntry, ...]]


def package_layers(
    result: PackageRulebase, layer: str | None = None, *, enabled_only: bool = False
) -> list[OrderedEntries]:
    """The package's ordered layers, or only the one whose uid or name is ``layer``; ``enabled_only`` applies
    ``drop_disabled`` to each.

    Raises:
        LookupError: ``layer`` is not an ordered layer of the package (the message lists the package's layers).
    """
    chosen = list(result.layers)
    if layer is not None:
        chosen = [(o, es) for o, es in chosen if layer in (o.layer_uid, o.layer_name)]
        if not chosen:
            names = ", ".join(o.layer_name for o, _ in result.layers) or "none"
            raise LookupError(
                f"{layer!r} is not a {result.rulebase_type} ordered layer of package {result.package_name}; "
                f"its layers: {names}"
            )
    return [(o, tuple(drop_disabled(es))) for o, es in chosen] if enabled_only else chosen


def _announced(layers: Sequence[OrderedEntries]) -> Iterator[tuple[OrderedLayer | None, tuple[NumberedEntry, ...]]]:
    """Each ordered layer's entries, with the layer to announce first: only when the view shows several."""
    several = len(layers) > 1
    for ordered, entries in layers:
        yield (ordered if several else None), entries


def rows_from_package(result: PackageRulebase, layers: Sequence[OrderedEntries] | None = None) -> list[RuleRow]:
    """Rows of a package's ordered layers (default: all of them; pass ``package_layers(...)`` to narrow or filter),
    with a ``layer`` header row before each when there are several."""
    rows: list[RuleRow] = []
    for ordered, entries in _announced(result.layers if layers is None else layers):
        if ordered is not None:
            rows.append(layer_header(ordered.layer_name))
        rows += rows_from_entries(entries, result.layer_names, result.layer_dictionaries)
    return rows


def raw_entries(entries: Sequence[NumberedEntry], details_level: str) -> list[dict[str, Any]]:
    """``format='raw'`` entries: rules/place-holders as projected raw items plus number/depth/layer; sections and parent
    rules as small records."""
    out: list[dict[str, Any]] = []
    for e in entries:
        if e.kind == "section":
            raw_type = e.item.raw.get("type", "section") if e.item is not None else "section"
            out.append({"type": raw_type, "uid": e.uid, "name": e.name, "range": e.range, "depth": e.depth})
        elif e.kind == "parent-rule":
            out.append(
                {
                    "type": "parent-rule",
                    "uid": e.uid,
                    "name": e.name,
                    "number": e.number,
                    "depth": e.depth,
                    "layer": e.layer_name,
                    "inline-layer": e.inline_layer_uid,
                }
            )
        else:
            raw = e.item.raw if isinstance(e.item, RuleItem) else {}
            out.append({**project(raw, details_level), "number": e.number, "depth": e.depth, "layer": e.layer_name})
    return out


def raw_package_entries(layers: Sequence[OrderedEntries], details_level: str) -> list[dict[str, Any]]:
    """``format='raw'`` entries of a package view, with an ``ordered-layer`` record before each layer when there are
    several (the same rule as the header rows of ``rows_from_package``)."""
    out: list[dict[str, Any]] = []
    for ordered, entries in _announced(layers):
        if ordered is not None:
            out.append(
                {
                    "type": "ordered-layer",
                    "uid": ordered.layer_uid,
                    "name": ordered.layer_name,
                    "position": ordered.position,
                }
            )
        out += raw_entries(entries, details_level)
    return out


def rows_from_live(response: dict[str, Any], rulebase_type: RulebaseType = "access") -> list[RuleRow]:
    """Rows of one live layer, numbered with sections; inline layers are named, not expanded (one layer fetched)."""
    data = {**response, "uid": response.get("uid") or response.get("name") or "live-layer"}
    layer = parse_layer_response(data, rulebase_type)
    entries = number_layer(layer.layer_uid, {layer.layer_uid: layer}, expand_inline=False)
    return rows_from_entries(entries, {layer.layer_uid: layer.layer_name}, {layer.layer_uid: layer.objects_dictionary})


def _cell(values: list[str], negated: bool) -> str:
    joined = ", ".join(values) if values else "-"
    return f"`!{joined}`" if negated else joined


def render_markdown(rows: Sequence[RuleRow], title: str) -> str:
    lines = [f"# Rulebase: {title}", ""]
    if not rows:
        lines.append("_No rules._")
        return "\n".join(lines)
    lines += [
        "| # | Name | Source | Destination | Service | Action | Track | Enabled |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        indent = "↳ " * r.depth
        if r.kind == "layer":
            lines.append(f"| | **Layer: {r.name}** | | | | | | |")
            continue
        if r.kind == "section":
            rng = f" ({r.section_range})" if r.section_range else ""
            lines.append(f"| | {indent}**Section: {r.name}**{rng} | | | | | | |")
            continue
        name = r.name or "(unnamed)"
        if r.kind == "place-holder":
            name += " *(place-holder)*"
        if r.inline_layer:
            name += f" → {'domain' if r.kind == 'parent-rule' else 'inline'} layer *{r.inline_layer}*"
        row = [
            r.number,
            indent + name,
            _cell(r.sources, r.negate.get("source", False)),
            _cell(r.destinations, r.negate.get("destination", False)),
            _cell(r.services, r.negate.get("service", False)),
            r.action or "-",
            r.track or "-",
            "yes" if r.enabled else "no",
        ]
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in row) + " |")
    notes = [f"- Rule {r.number}: {r.comments}" for r in rows if r.comments]
    if notes:
        lines += ["", "Comments:", *notes]
    extras = [f"- Rule {r.number}: " + "; ".join(f"{k}={v}" for k, v in r.extra.items()) for r in rows if r.extra]
    if extras:
        lines += ["", "Additional fields:", *extras]
    return "\n".join(lines)


def render_model_friendly(rows: Sequence[RuleRow], title: str) -> str:
    rule_rows = [r for r in rows if r.kind not in ("section", "layer")]
    lines = [f"Rulebase: {title}", f"Rules: {len(rule_rows)}", ""]
    if not rows:
        lines.append("No rules.")
        return "\n".join(lines)
    for r in rows:
        pad = "  " * r.depth
        if r.kind == "layer":
            lines += [f"LAYER: {r.name}", ""]
            continue
        if r.kind == "section":
            lines += [f"{pad}SECTION: {r.name}" + (f" ({r.section_range})" if r.section_range else ""), ""]
            continue
        label = {"place-holder": "PLACE-HOLDER", "parent-rule": "PARENT RULE"}.get(r.kind, "RULE")
        flag = "" if r.enabled else " [DISABLED]"
        lines.append(f"{pad}{label} {r.number}: {r.name or '(unnamed)'}{flag}")

        def lst(label: str, values: list[str], key: str, pad: str = pad, r: RuleRow = r) -> str:
            joined = ", ".join(values) if values else "-"
            return f"{pad}  {label}: {'NOT ' if r.negate.get(key) else ''}{joined}"

        lines += [
            lst("Sources", r.sources, "source"),
            lst("Destinations", r.destinations, "destination"),
            lst("Services", r.services, "service"),
        ]
        lines.append(f"{pad}  Action: {r.action or '-'}; Track: {r.track or '-'}")
        for k, v in r.extra.items():
            lines.append(f"{pad}  {k}: {v}")
        if r.inline_layer:
            lines.append(f"{pad}  {'Domain' if r.kind == 'parent-rule' else 'Inline'} layer: {r.inline_layer}")
        if r.comments:
            lines.append(f"{pad}  Comments: {r.comments}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
