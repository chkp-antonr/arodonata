"""A domain's rulebase snapshot as cache rows, and back. The only code that knows both shapes."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlmodel import SQLModel

from ..extractors.base import ExtractionContext
from ..extractors.rulebases import AccessRuleExtractor, HTTPSRuleExtractor, NATRuleExtractor, ThreatRuleExtractor
from ..rulebase.model import (
    DomainRulebaseSnapshot,
    LayerSnapshot,
    OrderedLayer,
    PackageLayout,
    RuleItem,
    SectionItem,
)
from ..rulebase.parse import objects_map
from .models import RULEBASE_MODELS, PolicyPackageLayer, RulebaseLayer, RulebaseSection, RulebaseSyncState

_EXTRACTORS: dict[str, Any] = {
    "access": AccessRuleExtractor(),
    "nat": NATRuleExtractor(),
    "https": HTTPSRuleExtractor(),
    "threat": ThreatRuleExtractor(),
}


def _rule_rows(mgmt: str, domain: str, layer: LayerSnapshot) -> list[SQLModel]:
    context = ExtractionContext(mgmt_name=mgmt, domain_name=domain, objects_map=objects_map(layer.objects_dictionary))
    model = RULEBASE_MODELS[layer.rulebase_type]
    rows: list[SQLModel] = []
    for item in layer.items:
        fields = {
            **_EXTRACTORS[layer.rulebase_type].extract(item.raw, context),
            "layer_name": layer.layer_name,
            "layer_uid": layer.layer_uid,
            "kind": item.kind,
            "section_uid": item.section_uid,
            "inline_layer_uid": item.inline_layer_uid,
            "domain_type": item.domain_type,
        }
        if layer.rulebase_type == "nat":
            fields["auto_generated"] = item.auto_generated
        rows.append(model(id=f"{mgmt}:{domain}:{layer.layer_uid}:{item.uid}", **fields))
    return rows


def build_rulebase_rows(snapshot: DomainRulebaseSnapshot) -> list[SQLModel]:
    """Rule, layer, section and package-layer rows of one domain (the sync state is built by the caller)."""
    mgmt, domain = snapshot.mgmt_name, snapshot.domain_name
    rows: list[SQLModel] = []
    for layer in snapshot.layers:
        rows.append(
            RulebaseLayer(
                id=f"{mgmt}:{domain}:{layer.rulebase_type}:{layer.layer_uid}",
                mgmt_name=mgmt,
                domain_name=domain,
                rulebase_type=layer.rulebase_type,
                layer_uid=layer.layer_uid,
                layer_name=layer.layer_name,
                layer_domain_type=layer.layer_domain_type,
                total=layer.total,
                objects_dictionary=[dict(o) for o in layer.objects_dictionary],
            )
        )
        rows += [
            RulebaseSection(
                id=f"{mgmt}:{domain}:{layer.layer_uid}:{s.uid}",
                mgmt_name=mgmt,
                domain_name=domain,
                rulebase_type=layer.rulebase_type,
                layer_uid=layer.layer_uid,
                section_uid=s.uid,
                name=s.name,
                from_number=s.from_number,
                to_number=s.to_number,
                rules_before=s.rules_before,
                seq=s.seq,
                raw_data=dict(s.raw),
            )
            for s in layer.sections
        ]
        rows += _rule_rows(mgmt, domain, layer)
    for package in snapshot.packages:
        rows += [
            PolicyPackageLayer(
                id=f"{mgmt}:{domain}:{package.package_uid}:{o.rulebase_type}:{o.position}",
                mgmt_name=mgmt,
                domain_name=domain,
                package_uid=package.package_uid,
                package_name=package.package_name,
                rulebase_type=o.rulebase_type,
                position=o.position,
                slot=o.slot,
                layer_uid=o.layer_uid,
                layer_name=o.layer_name,
                layer_domain_type=o.layer_domain_type,
                placeholder_uid=o.placeholder_uid,
                parent_rule_uid=o.parent_rule_uid,
                parent_rule_name=o.parent_rule_name,
                domain_layer_uid=o.domain_layer_uid,
            )
            for o in package.layers
        ]
    return rows


def snapshot_from_rows(
    state: RulebaseSyncState,
    layer_rows: Iterable[RulebaseLayer],
    section_rows: Iterable[RulebaseSection],
    rule_rows: Iterable[Any],
    package_rows: Iterable[PolicyPackageLayer],
) -> DomainRulebaseSnapshot:
    """Rebuild the snapshot in canonical order. Rule rows without ``layer_uid`` (pre-v2) are ignored."""
    sections: dict[str, list[SectionItem]] = defaultdict(list)
    for s in section_rows:
        sections[s.layer_uid].append(
            SectionItem(
                uid=s.section_uid,
                name=s.name,
                from_number=s.from_number,
                to_number=s.to_number,
                rules_before=s.rules_before,
                seq=s.seq,
                raw=dict(s.raw_data or {}),
            )
        )
    items: dict[str, list[RuleItem]] = defaultdict(list)
    for r in rule_rows:
        if r.layer_uid is None:
            continue
        items[r.layer_uid].append(
            RuleItem(
                uid=r.uid,
                name=r.name,
                kind=r.kind,
                rule_number=r.rule_number,
                enabled=r.enabled,
                section_uid=r.section_uid,
                inline_layer_uid=r.inline_layer_uid,
                domain_type=r.domain_type,
                auto_generated=bool(getattr(r, "auto_generated", False)),
                raw=dict(r.raw_data or {}),
            )
        )
    layers = tuple(
        LayerSnapshot(
            rulebase_type=lr.rulebase_type,  # type: ignore[arg-type]
            layer_uid=lr.layer_uid,
            layer_name=lr.layer_name,
            layer_domain_type=lr.layer_domain_type,
            total=lr.total,
            sections=tuple(sorted(sections[lr.layer_uid], key=lambda s: s.seq)),
            items=tuple(sorted(items[lr.layer_uid], key=lambda i: i.rule_number)),
            objects_dictionary=tuple({k: str(v) for k, v in o.items()} for o in lr.objects_dictionary or []),
        )
        for lr in sorted(layer_rows, key=lambda r: (r.rulebase_type, r.layer_uid))
    )
    by_package: dict[tuple[str, str], list[OrderedLayer]] = defaultdict(list)
    for p in package_rows:
        by_package[(p.package_name, p.package_uid)].append(
            OrderedLayer(
                rulebase_type=p.rulebase_type,  # type: ignore[arg-type]
                position=p.position,
                slot=p.slot,
                layer_uid=p.layer_uid,
                layer_name=p.layer_name,
                layer_domain_type=p.layer_domain_type,
                placeholder_uid=p.placeholder_uid,
                parent_rule_uid=p.parent_rule_uid,
                parent_rule_name=p.parent_rule_name,
                domain_layer_uid=p.domain_layer_uid,
            )
        )
    packages = tuple(
        PackageLayout(
            package_uid=uid,
            package_name=name,
            layers=tuple(sorted(ols, key=lambda o: (o.rulebase_type, o.position))),
        )
        for (name, uid), ols in sorted(by_package.items())
    )
    return DomainRulebaseSnapshot(
        mgmt_name=state.mgmt_name,
        domain_name=state.domain_name,
        session_uid=state.session_uid,
        session_published_time=state.session_published_time,
        refreshed_at=state.refreshed_at,
        packages=packages,
        layers=layers,
    )
