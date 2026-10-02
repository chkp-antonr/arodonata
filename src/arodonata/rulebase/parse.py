"""Parse Check Point show-* responses into the frozen structures of ``arodonata.rulebase.model`` (pure)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import replace
from typing import Any

from ..logger import lazy_logger
from .model import (
    PLACEHOLDER_TYPE,
    RULE_ITEM_TYPES,
    LayerSnapshot,
    OrderedLayer,
    PackageLayout,
    ParentRule,
    RulebaseType,
    RuleItem,
    SectionItem,
)

log = lazy_logger("arodonata.rulebase.parse")


def _uid_of(value: Any) -> str | None:
    if isinstance(value, dict):
        uid = value.get("uid")
        return str(uid) if uid else None
    return str(value) if value else None


def _domain_type(entry: Any) -> str:
    domain = entry.get("domain") if isinstance(entry, dict) else None
    return str(domain.get("domain-type") or "") if isinstance(domain, dict) else ""


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_section(entry: Any) -> bool:
    return isinstance(entry, dict) and str(entry.get("type", "")).endswith("-section")


def _trim_dictionary(objects: Any) -> tuple[dict[str, str], ...]:
    return tuple(
        {"uid": str(o["uid"]), "name": str(o.get("name") or ""), "type": str(o.get("type") or "")}
        for o in objects or []
        if isinstance(o, dict) and o.get("uid")
    )


def objects_map(dictionary: Iterable[Mapping[str, str]]) -> dict[str, str]:
    """{uid: name} of a trimmed objects-dictionary (entries without a name are left out)."""
    return {d["uid"]: d["name"] for d in dictionary if d.get("name")}


def parse_layer_response(
    data: dict[str, Any],
    rulebase_type: RulebaseType,
    *,
    layer_name: str | None = None,
    layer_domain_type: str = "",
) -> LayerSnapshot:
    """One complete ``show-*-rulebase`` response (``fetch_full_rulebase``) as a LayerSnapshot.

    Sections at any depth become SectionItems and their children inherit ``section_uid``; ``<type>-rule`` items
    become ``kind='rule'``, ``place-holder`` items ``kind='place-holder'``; anything else is skipped (debug log).

    Args:
        data: The merged response; its top-level ``uid`` is the layer uid (required).
        rulebase_type: "access", "nat", "https" or "threat".
        layer_name: Overrides the response's ``name`` (NAT responses have none: pass the package name).
        layer_domain_type: The layer's domain-type from its package or listing entry.

    Raises:
        ValueError: The response has no ``uid``.
    """
    layer_uid = str(data.get("uid") or "")
    if not layer_uid:
        raise ValueError(f"{rulebase_type} rulebase response has no uid")
    rule_type = RULE_ITEM_TYPES[rulebase_type]
    sections: list[SectionItem] = []
    items: list[RuleItem] = []

    def walk(entries: Any, section_uid: str | None) -> None:
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            item_type = str(entry.get("type", ""))
            if _is_section(entry):
                uid = str(entry.get("uid") or "")
                sections.append(
                    SectionItem(
                        uid=uid,
                        name=str(entry.get("name") or ""),
                        from_number=_int_or_none(entry.get("from")),
                        to_number=_int_or_none(entry.get("to")),
                        rules_before=len(items),
                        seq=len(sections),
                        raw={k: v for k, v in entry.items() if k != "rulebase"},
                    )
                )
                walk(entry.get("rulebase"), uid)
            elif item_type in (rule_type, PLACEHOLDER_TYPE):
                items.append(
                    RuleItem(
                        uid=str(entry.get("uid") or ""),
                        name=str(entry.get("name") or ""),
                        kind="rule" if item_type == rule_type else "place-holder",
                        rule_number=int(entry.get("rule-number") or 0),
                        enabled=bool(entry.get("enabled", True)),
                        section_uid=section_uid,
                        inline_layer_uid=_uid_of(entry.get("inline-layer")),
                        domain_type=_domain_type(entry),
                        auto_generated=bool(entry.get("auto-generated", False)) if rulebase_type == "nat" else False,
                        raw=entry,
                    )
                )
            else:
                log().debug(f"Skipping {item_type!r} item {entry.get('uid')} in {rulebase_type} layer {layer_uid}")

    walk(data.get("rulebase"), None)
    return LayerSnapshot(
        rulebase_type=rulebase_type,
        layer_uid=layer_uid,
        layer_name=layer_name if layer_name is not None else str(data.get("name") or ""),
        layer_domain_type=layer_domain_type,
        total=int(data.get("total") or 0),
        sections=tuple(sections),
        items=tuple(sorted(items, key=lambda i: i.rule_number)),
        objects_dictionary=_trim_dictionary(data.get("objects-dictionary")),
    )


def _walk_rules(entries: Any) -> Iterator[dict[str, Any]]:
    """Non-section entries at any depth, in order."""
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        if _is_section(entry):
            yield from _walk_rules(entry.get("rulebase"))
        else:
            yield entry


def _enabled(pkg: Mapping[str, Any], flag: str) -> bool:
    """A blade flag; a missing flag counts as enabled."""
    return pkg.get(flag, True) is not False


def _ordered(rulebase_type: RulebaseType, position: int, slot: str, entry: Any) -> OrderedLayer:
    if not isinstance(entry, dict) or not entry.get("uid"):
        raise ValueError(f"{rulebase_type} layer entry without uid: {entry!r}")
    return OrderedLayer(
        rulebase_type=rulebase_type,
        position=position,
        slot=slot,
        layer_uid=str(entry["uid"]),
        layer_name=str(entry.get("name") or ""),
        layer_domain_type=_domain_type(entry),
    )


def _sorted_layers(layers: Iterable[OrderedLayer]) -> tuple[OrderedLayer, ...]:
    return tuple(sorted(layers, key=lambda o: (o.rulebase_type, o.position)))


def parse_packages(packages: Iterable[Any], *, nat_layer_uids: Mapping[str, str] | None = None) -> list[PackageLayout]:
    """``show-packages details-level full`` objects as PackageLayouts (listing order).

    Access and threat layers keep their list order; HTTPS uses fixed slots (inbound 0, outbound 1); a package gets one
    NAT ordered layer when ``nat-policy`` is true and its uid is in ``nat_layer_uids`` (package uid -> the NAT
    response's uid). A blade flag set to false (``access``, ``threat-prevention``, ``https-inspection-policy``) gives
    no ordered layers of that type. A global layer's nested domain layer is still listed here; ``link_placeholder``
    removes it.

    Raises:
        ValueError: A package without uid/name, or a layer reference without uid.
    """
    nat_uids = nat_layer_uids or {}
    layouts: list[PackageLayout] = []
    for pkg in packages:
        if not isinstance(pkg, dict) or not pkg.get("uid") or not pkg.get("name"):
            raise ValueError(f"invalid package listing entry: {pkg!r}")
        uid, name = str(pkg["uid"]), str(pkg["name"])
        layers: list[OrderedLayer] = []
        if _enabled(pkg, "access"):
            layers += [_ordered("access", i, "", e) for i, e in enumerate(pkg.get("access-layers") or [])]
        if _enabled(pkg, "threat-prevention"):
            layers += [_ordered("threat", i, "", e) for i, e in enumerate(pkg.get("threat-layers") or [])]
        if _enabled(pkg, "https-inspection-policy"):
            https = pkg.get("https-inspection-layers") or {}
            for position, slot in enumerate(("inbound", "outbound")):
                entry = https.get(f"{slot}-https-layer")
                if isinstance(entry, dict) and entry.get("uid"):
                    layers.append(_ordered("https", position, slot, entry))
        if pkg.get("nat-policy") and uid in nat_uids:
            layers.append(
                OrderedLayer(
                    rulebase_type="nat",
                    position=0,
                    slot="",
                    layer_uid=nat_uids[uid],
                    layer_name=name,
                    layer_domain_type="",
                )
            )
        layouts.append(PackageLayout(package_uid=uid, package_name=name, layers=_sorted_layers(layers)))
    return layouts


def find_parent_rule(data: dict[str, Any], rulebase_type: RulebaseType, rule_number: int) -> ParentRule | None:
    """The domain parent rule at a place-holder's position in a global layer read with ``package``.

    Returns None unless the entry at ``rule_number`` is a ``<type>-rule`` of domain-type ``domain`` with an
    ``inline-layer`` (the domain layer).
    """
    for entry in _walk_rules(data.get("rulebase")):
        if entry.get("rule-number") != rule_number:
            continue
        domain_layer = _uid_of(entry.get("inline-layer"))
        if (
            entry.get("type") != RULE_ITEM_TYPES[rulebase_type]
            or _domain_type(entry) != "domain"
            or not domain_layer
            or not entry.get("uid")
        ):
            return None
        return ParentRule(uid=str(entry["uid"]), name=str(entry.get("name") or ""), domain_layer_uid=domain_layer)
    return None


def link_placeholder(
    layout: PackageLayout, rulebase_type: RulebaseType, layer_uid: str, placeholder_uid: str, parent: ParentRule
) -> PackageLayout:
    """Record the place-holder link on the global ordered layer and drop the nested domain layer from the ordered
    layers of that type (it is numbered only under the parent rule). Positions of that type are renumbered from 0,
    except HTTPS, whose positions are fixed slots."""
    kept: list[OrderedLayer] = []
    for layer in layout.layers:
        same_type = layer.rulebase_type == rulebase_type
        if same_type and layer.layer_uid == parent.domain_layer_uid and layer.layer_uid != layer_uid:
            continue
        if same_type and layer.layer_uid == layer_uid:
            layer = replace(
                layer,
                placeholder_uid=placeholder_uid,
                parent_rule_uid=parent.uid,
                parent_rule_name=parent.name,
                domain_layer_uid=parent.domain_layer_uid,
            )
        kept.append(layer)
    if rulebase_type != "https":
        renumbered: list[OrderedLayer] = []
        position = 0
        for layer in kept:
            if layer.rulebase_type == rulebase_type:
                layer = replace(layer, position=position)
                position += 1
            renumbered.append(layer)
        kept = renumbered
    return replace(layout, layers=_sorted_layers(kept))
