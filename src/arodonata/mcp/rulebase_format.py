"""Turn cached or live rulebases into rows, then into markdown or compact structured text.

Ported in spirit from the reference server's rulebase parser. The reference's padded fixed-width table is intentionally
not reproduced (decision 2026-09-27): cells always carry full values.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any


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


def rows_from_live(response: dict[str, Any]) -> list[RuleRow]:
    lookup = {
        str(o.get("uid")): str(o.get("name", o.get("uid")))
        for o in response.get("objects-dictionary", [])
        if isinstance(o, dict)
    }
    rows: list[RuleRow] = []

    def walk(items: Sequence[dict[str, Any]], section: str, prefix: str, depth: int) -> None:
        for item in items:
            kind = str(item.get("type", ""))
            if kind.endswith("-section"):
                walk(item.get("rulebase", []), str(item.get("name") or section), prefix, depth)
                continue
            number = f"{prefix}{item.get('rule-number', len(rows) + 1)}"
            rows.append(_rule_from_raw(item, lookup, number, depth, section))
            inline_rules = item.get("inline-layer-rulebase")
            if isinstance(inline_rules, list):
                walk(inline_rules, section, f"{number}.", depth + 1)

    walk(response.get("rulebase", []), "", "", 0)
    return rows


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _endpoints_from_model(model: Any) -> tuple[list[str], list[str], list[str]]:
    """``AccessRule``/``HTTPSRule`` carry ``sources``/``destinations``/``services`` lists directly.

    ``NATRule`` has no such lists: it carries singular ``original_source``/``original_destination``/
    ``original_service`` strings instead, used here as the source/destination/service columns.
    """
    sources = getattr(model, "sources", None)
    if sources is None and hasattr(model, "original_source"):
        sources = _as_list(model.original_source)
    destinations = getattr(model, "destinations", None)
    if destinations is None and hasattr(model, "original_destination"):
        destinations = _as_list(model.original_destination)
    services = getattr(model, "services", None)
    if services is None and hasattr(model, "original_service"):
        services = _as_list(model.original_service)
    return list(sources or []), list(destinations or []), list(services or [])


def _extra_from_model(model: Any) -> dict[str, str]:
    """``NATRule``'s ``translated_*`` fields and ``ThreatRule``'s ``protections`` have no row column, so they land here."""
    extra: dict[str, str] = {}
    if hasattr(model, "translated_source"):
        extra["translated_source"] = str(model.translated_source)
        extra["translated_destination"] = str(model.translated_destination)
        extra["translated_service"] = str(model.translated_service)
    if hasattr(model, "protections"):
        extra["protections"] = ", ".join(model.protections)
    return extra


def rows_from_cached(
    rules: Sequence[Any], inline_lookup: Callable[[str], Sequence[Any]] | None = None
) -> list[RuleRow]:
    """Build rows from cached rule models (``AccessRule``, ``NATRule``, ``HTTPSRule`` or ``ThreatRule``)."""

    rows: list[RuleRow] = []

    def add(model: Any, prefix: str, depth: int, seen: frozenset[str]) -> None:
        raw = model.raw_data if isinstance(model.raw_data, dict) else {}
        number = f"{prefix}{model.rule_number}"
        sources, destinations, services = _endpoints_from_model(model)
        row = RuleRow(
            number=number,
            name=model.name,
            enabled=model.enabled,
            sources=sources,
            destinations=destinations,
            services=services,
            action=str(getattr(model, "action", "") or ""),
            track=str(getattr(model, "track", "") or ""),
            section=str(raw.get("section", "") or ""),
            comments=str(raw.get("comments") or ""),
            depth=depth,
            negate={k: True for k in ("source", "destination", "service") if raw.get(f"{k}-negate")},
            extra=_extra_from_model(model),
        )
        inline = raw.get("inline-layer")
        if isinstance(inline, dict):
            row.inline_layer = str(inline.get("name", ""))
        rows.append(row)
        if row.inline_layer and inline_lookup and row.inline_layer not in seen:
            for child in inline_lookup(row.inline_layer):
                add(child, f"{number}.", depth + 1, seen | {row.inline_layer})

    for model in rules:
        add(model, "", 0, frozenset())
    return rows


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
    section = None
    for r in rows:
        if r.section and r.section != section and r.depth == 0:
            section = r.section
            lines.append(f"| | **Section: {section}** | | | | | | |")
        indent = "↳ " * r.depth
        name = r.name or "(unnamed)"
        if r.inline_layer:
            name += f" → inline layer *{r.inline_layer}*"
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
    lines = [f"Rulebase: {title}", f"Rules: {len(rows)}", ""]
    if not rows:
        lines.append("No rules.")
        return "\n".join(lines)
    for r in rows:
        pad = "  " * r.depth
        flag = "" if r.enabled else " [DISABLED]"
        lines.append(f"{pad}RULE {r.number}: {r.name or '(unnamed)'}{flag}")
        if r.section and r.depth == 0:
            lines.append(f"{pad}  Section: {r.section}")

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
            lines.append(f"{pad}  Inline layer: {r.inline_layer}")
        if r.comments:
            lines.append(f"{pad}  Comments: {r.comments}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
