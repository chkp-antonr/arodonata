"""SmartConsole rule numbering over parsed rulebase snapshots (pure).

Each ordered layer numbers from 1. A rule with an inline layer, and a global place-holder linked to its package's
domain layer, number their children with the parent's number as prefix ("2." -> "2.1", "2.2.1"). Sections carry a
range ("2.1-2.2", "2.3", "No Rules") and precede their first rule; an empty section stays where it sits in the layer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from ..logger import lazy_logger
from .model import LayerSnapshot, OrderedLayer, PackageLayout, RulebaseType, RuleItem, SectionItem

log = lazy_logger("arodonata.rulebase.numbering")

EMPTY_SECTION_RANGE = "No Rules"


@dataclass(frozen=True)
class NumberedEntry:
    kind: Literal["rule", "section", "place-holder", "parent-rule"]
    rulebase_type: RulebaseType
    number: str  # "2.2.1"; '' for sections
    range: str  # sections only (section_range)
    depth: int  # 0 = ordered layer, +1 per inline/domain-layer descent
    uid: str  # rule/section/place-holder uid; parent-rule: parent_rule_uid
    name: str
    layer_uid: str  # layer that physically holds the item
    layer_name: str
    rule_number: int | None
    section_uid: str | None  # enclosing section (None for a section entry itself)
    section_name: str | None
    inline_layer_uid: str | None  # rule: its inline layer; parent-rule: the domain layer
    item: RuleItem | SectionItem | None  # parent-rule: the place-holder item


def section_range(prefix: str, from_number: int | None, to_number: int | None) -> str:
    """SmartConsole's section range: ``2.1-2.2``, ``2.3`` for one rule, ``No Rules`` for an empty section."""
    if from_number is None or to_number is None:
        return EMPTY_SECTION_RANGE
    if from_number == to_number:
        return f"{prefix}{from_number}"
    return f"{prefix}{from_number}-{prefix}{to_number}"


def number_layer(
    layer_uid: str,
    layers: Mapping[str, LayerSnapshot],
    *,
    prefix: str = "",
    depth: int = 0,
    ordered_layer: OrderedLayer | None = None,
    expand_inline: bool = True,
    _path: frozenset[str] = frozenset(),
) -> list[NumberedEntry]:
    """Number one layer and, recursively, its inline layers and (with ``ordered_layer`` link context) the domain
    layer under a global place-holder.

    The cycle guard holds only the layers on the current descent path, so a layer shared by two parents is expanded
    under both and only a true cycle stops. A layer missing from ``layers`` is logged and yields no entries.
    ``expand_inline=False`` names inline layers (``inline_layer_uid``) without descending (a single fetched layer).
    """
    layer = layers.get(layer_uid)
    if layer is None:
        log().warning(f"Layer {layer_uid} is not in the snapshot; numbered without its rules")
        return []
    if layer_uid in _path:
        log().warning(f"Inline layer cycle at {layer_uid}; not descended again")
        return []
    path = _path | {layer_uid}
    sections_by_uid = {s.uid: s for s in layer.sections}
    pending = sorted(layer.sections, key=lambda s: (s.rules_before, s.seq))
    out: list[NumberedEntry] = []

    def emit_sections(before: float) -> None:
        while pending and pending[0].rules_before < before:
            s = pending.pop(0)
            out.append(
                NumberedEntry(
                    kind="section",
                    rulebase_type=layer.rulebase_type,
                    number="",
                    range=section_range(prefix, s.from_number, s.to_number),
                    depth=depth,
                    uid=s.uid,
                    name=s.name,
                    layer_uid=layer.layer_uid,
                    layer_name=layer.layer_name,
                    rule_number=None,
                    section_uid=None,
                    section_name=None,
                    inline_layer_uid=None,
                    item=s,
                )
            )

    # rules_before counts items seen in the walk, so compare against the walk position, not rule_number: a filtered
    # (sparse) read has gaps in its rule numbers. For a complete layer the two agree.
    for index, item in enumerate(layer.items):
        emit_sections(index + 1)
        number = f"{prefix}{item.rule_number}"
        enclosing = sections_by_uid.get(item.section_uid) if item.section_uid else None

        def entry(
            kind: Literal["rule", "place-holder", "parent-rule"],
            uid: str,
            name: str,
            inline_layer_uid: str | None,
            item: RuleItem = item,
            number: str = number,
            section_name: str | None = enclosing.name if enclosing else None,
        ) -> NumberedEntry:
            return NumberedEntry(
                kind=kind,
                rulebase_type=layer.rulebase_type,
                number=number,
                range="",
                depth=depth,
                uid=uid,
                name=name,
                layer_uid=layer.layer_uid,
                layer_name=layer.layer_name,
                rule_number=item.rule_number,
                section_uid=item.section_uid,
                section_name=section_name,
                inline_layer_uid=inline_layer_uid,
                item=item,
            )

        linked = (
            item.kind == "place-holder"
            and ordered_layer is not None
            and ordered_layer.placeholder_uid == item.uid
            and ordered_layer.domain_layer_uid
        )
        if linked:
            assert ordered_layer is not None and ordered_layer.domain_layer_uid is not None
            out.append(
                entry(
                    "parent-rule",
                    ordered_layer.parent_rule_uid or item.uid,
                    ordered_layer.parent_rule_name or item.name,
                    ordered_layer.domain_layer_uid,
                )
            )
            out.extend(
                number_layer(
                    ordered_layer.domain_layer_uid,
                    layers,
                    prefix=f"{number}.",
                    depth=depth + 1,
                    expand_inline=expand_inline,
                    _path=path,
                )
            )
        elif item.kind == "place-holder":
            out.append(entry("place-holder", item.uid, item.name, None))
        else:
            out.append(entry("rule", item.uid, item.name, item.inline_layer_uid))
            if item.inline_layer_uid and expand_inline:
                out.extend(
                    number_layer(
                        item.inline_layer_uid,
                        layers,
                        prefix=f"{number}.",
                        depth=depth + 1,
                        expand_inline=expand_inline,
                        _path=path,
                    )
                )
    emit_sections(float("inf"))
    return out


def number_package(
    layout: PackageLayout, rulebase_type: RulebaseType, layers: Mapping[str, LayerSnapshot]
) -> list[list[NumberedEntry]]:
    """One numbered list per ordered layer of ``rulebase_type`` in the package, in position order."""
    ordered = sorted((o for o in layout.layers if o.rulebase_type == rulebase_type), key=lambda o: o.position)
    return [number_layer(o.layer_uid, layers, ordered_layer=o) for o in ordered]
