"""SmartConsole-identical hierarchical rule and section numbering (`rulebase/numbering.py`).

Computes hierarchical rule numbers (`1`, `2`, `2.1`, `2.2.1`) and section range labels
(`1-3`, `2.1-2.2`, or `"No Rules"`) dynamically from a `DomainRulebaseSnapshot` both in
standalone layer context (`number_layer_rulebase`) and policy package context
(`number_package_rulebase`), and locates rules and layer prefixes across a domain
(`locate_rules_in_snapshot`).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from arodonata.core.models.common import SyncStatus
from arodonata.core.models.rulebase import (
    DomainRulebaseSnapshot,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    RulebaseType,
)
from arodonata.rulebase.models import (
    LayerPrefixLocation,
    NumberedLayerRulebase,
    NumberedRule,
    NumberedSection,
    PackageRulebase,
    PolicyPackageInfo,
    RuleLocation,
    RuleLocations,
)


def extract_policy_packages(snapshot: DomainRulebaseSnapshot) -> list[PolicyPackageInfo]:
    """Build `PolicyPackageInfo` models from `snapshot.package_layers`."""
    pkgs_by_uid: dict[str, PolicyPackageInfo] = {}
    ordered_uids: list[str] = []

    sorted_entries = sorted(
        snapshot.package_layers,
        key=lambda e: (e.package_name, e.package_uid, e.rulebase_type, e.position),
    )

    for entry in sorted_entries:
        if entry.package_uid not in pkgs_by_uid:
            pkgs_by_uid[entry.package_uid] = PolicyPackageInfo(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                uid=entry.package_uid,
                name=entry.package_name,
                raw_data=dict(entry.raw_data),
                updated_at=entry.updated_at,
            )
            ordered_uids.append(entry.package_uid)

        pkg = pkgs_by_uid[entry.package_uid]
        if entry.rulebase_type == "nat":
            pkg.has_nat_policy = True
        elif entry.rulebase_type == "access":
            pkg.access_layers.append(entry)
        elif entry.rulebase_type == "https":
            pkg.https_layers.append(entry)
        elif entry.rulebase_type == "threat":
            pkg.threat_layers.append(entry)

    # Also detect packages that have NAT rules even if package_layers had no explicit nat entry
    for nr in snapshot.nat_rules:
        if nr.package_uid not in pkgs_by_uid:
            pkgs_by_uid[nr.package_uid] = PolicyPackageInfo(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                uid=nr.package_uid,
                name=nr.package_name,
                has_nat_policy=True,
                updated_at=nr.updated_at,
            )
            ordered_uids.append(nr.package_uid)
        else:
            pkgs_by_uid[nr.package_uid].has_nat_policy = True

    return [pkgs_by_uid[u] for u in ordered_uids]


def _find_layer_entry(
    snapshot: DomainRulebaseSnapshot,
    layer_name_or_uid: str,
    rulebase_type: RulebaseType | None = None,
) -> RulebaseLayerEntry | None:
    target = layer_name_or_uid.strip()
    for layer in snapshot.layers:
        if rulebase_type is not None and layer.rulebase_type != rulebase_type:
            continue
        if layer.uid == target or layer.name == target:
            return layer
    # Fallback: check package_layers or rule entries if layer table entry was omitted in synthetic tests
    for pl in snapshot.package_layers:
        if rulebase_type is not None and pl.rulebase_type != rulebase_type:
            continue
        if pl.layer_uid == target or pl.layer_name == target:
            return RulebaseLayerEntry(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                uid=pl.layer_uid,
                name=pl.layer_name,
                rulebase_type=pl.rulebase_type,
            )
    if rulebase_type in (None, "access"):
        for ar in snapshot.access_rules:
            if ar.layer_uid == target or ar.layer_name == target:
                return RulebaseLayerEntry(
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    uid=ar.layer_uid,
                    name=ar.layer_name,
                    rulebase_type="access",
                )
    if rulebase_type in (None, "https"):
        for hr in snapshot.https_rules:
            if hr.layer_uid == target or hr.layer_name == target:
                return RulebaseLayerEntry(
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    uid=hr.layer_uid,
                    name=hr.layer_name,
                    rulebase_type="https",
                )
    if rulebase_type in (None, "threat"):
        for tr in snapshot.threat_rules:
            if tr.layer_uid == target or tr.layer_name == target:
                return RulebaseLayerEntry(
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    uid=tr.layer_uid,
                    name=tr.layer_name,
                    rulebase_type="threat",
                )
    return None


def _build_sections_for_layer(
    layer_sections: list[RulebaseSectionEntry],
    top_rules: list[NumberedRule],
) -> list[NumberedSection]:
    """Attach numbered rules to their section entries and compute SmartConsole section ranges."""
    sorted_secs = sorted(layer_sections, key=lambda s: s.position)
    rules_by_uid = {r.uid: r for r in top_rules}
    rules_by_sec_uid: dict[str, list[NumberedRule]] = {}
    for r in top_rules:
        if r.section_uid:
            rules_by_sec_uid.setdefault(r.section_uid, []).append(r)

    numbered_secs: list[NumberedSection] = []
    for sec in sorted_secs:
        sec_rules: list[NumberedRule] = []
        if sec.rule_uids:
            for r_uid in sec.rule_uids:
                if r_uid in rules_by_uid:
                    sec_rules.append(rules_by_uid[r_uid])
        if not sec_rules and sec.uid in rules_by_sec_uid:
            sec_rules = list(rules_by_sec_uid[sec.uid])
        if not sec_rules and sec.from_rule is not None and sec.to_rule is not None:
            for r in top_rules:
                if sec.from_rule <= r.position <= sec.to_rule:
                    sec_rules.append(r)
        numbered_secs.append(NumberedSection.from_section_entry(sec, sec_rules))
    return numbered_secs


def number_layer_rulebase(
    snapshot: DomainRulebaseSnapshot,
    layer_name_or_uid: str,
    *,
    rulebase_type: RulebaseType | None = None,
    prefix: str = "",
    package_uid: str | None = None,
    package_name: str | None = None,
    parent_rule_uid: str | None = None,
    fallback_domain_layer_uid: str | None = None,
    expand_placeholders: bool = False,
    expand_inline_layers: bool = True,
    snapshot_session_uid: str | None = None,
    snapshot_published_at: datetime | None = None,
    sync_status: SyncStatus = "idle",
    _visited_layers: set[str] | None = None,
) -> NumberedLayerRulebase:
    """Compute SmartConsole hierarchical numbering for a layer (and its inline / placeholder sub-layers)."""
    visited = set(_visited_layers) if _visited_layers is not None else set()
    layer_entry = _find_layer_entry(snapshot, layer_name_or_uid, rulebase_type=rulebase_type)

    if layer_entry is None:
        eff_type: RulebaseType = rulebase_type or "access"
        return NumberedLayerRulebase(
            mgmt_name=snapshot.mgmt_name,
            domain_name=snapshot.domain_name,
            layer_uid=layer_name_or_uid,
            layer_name=layer_name_or_uid,
            rulebase_type=eff_type,
            package_uid=package_uid,
            package_name=package_name,
            prefix=prefix,
            snapshot_session_uid=snapshot_session_uid,
            snapshot_published_at=snapshot_published_at,
            sync_status=sync_status,
        )

    eff_uid = layer_entry.uid
    eff_name = layer_entry.name
    eff_type = layer_entry.rulebase_type
    visited.add(eff_uid)

    layer_sections = [
        s
        for s in snapshot.sections
        if (s.layer_uid == eff_uid or s.layer_name == eff_name) and s.rulebase_type == eff_type
    ]

    top_rules: list[NumberedRule] = []
    flat_rules: list[NumberedRule] = []

    if eff_type == "access":
        raw_access = sorted(
            [r for r in snapshot.access_rules if r.layer_uid == eff_uid or r.layer_name == eff_name],
            key=lambda r: r.position,
        )
        for idx, entry in enumerate(raw_access, start=1):
            rule_num = f"{prefix}{idx}"
            children: list[NumberedRule] = []
            nested_sections: list[NumberedSection] = []

            # 1. Global placeholder expansion in package context
            target_dom_layer_uid = entry.placeholder_domain_layer_uid or (
                fallback_domain_layer_uid if entry.rule_type == "place-holder" else None
            )
            if expand_placeholders and entry.rule_type == "place-holder" and target_dom_layer_uid:
                if target_dom_layer_uid not in visited:
                    sub_rb = number_layer_rulebase(
                        snapshot,
                        target_dom_layer_uid,
                        rulebase_type="access",
                        prefix=f"{rule_num}.",
                        package_uid=package_uid,
                        package_name=package_name,
                        parent_rule_uid=entry.uid,
                        expand_placeholders=True,
                        expand_inline_layers=expand_inline_layers,
                        snapshot_session_uid=snapshot_session_uid,
                        snapshot_published_at=snapshot_published_at,
                        sync_status=sync_status,
                        _visited_layers=visited,
                    )
                    children.extend(sub_rb.rules)
                    nested_sections.extend(sub_rb.sections)

            # 2. Inline layer expansion
            elif expand_inline_layers and entry.inline_layer_uid and entry.inline_layer_uid not in visited:
                inline_rb = number_layer_rulebase(
                    snapshot,
                    entry.inline_layer_uid,
                    rulebase_type="access",
                    prefix=f"{rule_num}.",
                    package_uid=package_uid,
                    package_name=package_name,
                    parent_rule_uid=entry.uid,
                    expand_placeholders=expand_placeholders,
                    expand_inline_layers=True,
                    snapshot_session_uid=snapshot_session_uid,
                    snapshot_published_at=snapshot_published_at,
                    sync_status=sync_status,
                    _visited_layers=visited,
                )
                children.extend(inline_rb.rules)
                nested_sections.extend(inline_rb.sections)

            numbered = NumberedRule.from_access_entry(
                entry,
                rule_number=rule_num,
                package_uid=package_uid,
                package_name=package_name,
                parent_rule_uid=parent_rule_uid,
                children=children,
                nested_sections=nested_sections,
            )
            top_rules.append(numbered)
            flat_rules.append(numbered)
            _collect_flat_children(children, flat_rules)

    elif eff_type == "https":
        raw_https = sorted(
            [r for r in snapshot.https_rules if r.layer_uid == eff_uid or r.layer_name == eff_name],
            key=lambda r: r.position,
        )
        for idx, h_entry in enumerate(raw_https, start=1):
            rule_num = f"{prefix}{idx}"
            children = []
            nested_sections = []
            if expand_inline_layers and h_entry.inline_layer_uid and h_entry.inline_layer_uid not in visited:
                inline_rb = number_layer_rulebase(
                    snapshot,
                    h_entry.inline_layer_uid,
                    rulebase_type="https",
                    prefix=f"{rule_num}.",
                    package_uid=package_uid,
                    package_name=package_name,
                    parent_rule_uid=h_entry.uid,
                    expand_placeholders=expand_placeholders,
                    expand_inline_layers=True,
                    snapshot_session_uid=snapshot_session_uid,
                    snapshot_published_at=snapshot_published_at,
                    sync_status=sync_status,
                    _visited_layers=visited,
                )
                children.extend(inline_rb.rules)
                nested_sections.extend(inline_rb.sections)

            numbered = NumberedRule.from_https_entry(
                h_entry,
                rule_number=rule_num,
                package_uid=package_uid,
                package_name=package_name,
                parent_rule_uid=parent_rule_uid,
                children=children,
                nested_sections=nested_sections,
            )
            top_rules.append(numbered)
            flat_rules.append(numbered)
            _collect_flat_children(children, flat_rules)

    elif eff_type == "threat":
        raw_threat = sorted(
            [r for r in snapshot.threat_rules if r.layer_uid == eff_uid or r.layer_name == eff_name],
            key=lambda r: r.position,
        )
        for idx, t_entry in enumerate(raw_threat, start=1):
            rule_num = f"{prefix}{idx}"
            numbered = NumberedRule.from_threat_entry(
                t_entry,
                rule_number=rule_num,
                package_uid=package_uid,
                package_name=package_name,
                parent_rule_uid=parent_rule_uid,
            )
            top_rules.append(numbered)
            flat_rules.append(numbered)

    numbered_sections = _build_sections_for_layer(layer_sections, top_rules)

    return NumberedLayerRulebase(
        mgmt_name=snapshot.mgmt_name,
        domain_name=snapshot.domain_name,
        layer_uid=eff_uid,
        layer_name=eff_name,
        rulebase_type=eff_type,
        package_uid=package_uid,
        package_name=package_name,
        prefix=prefix,
        is_global=layer_entry.is_global,
        implicit_cleanup_action=layer_entry.implicit_cleanup_action,
        sections=numbered_sections,
        rules=top_rules,
        flat_rules=flat_rules,
        snapshot_session_uid=snapshot_session_uid,
        snapshot_published_at=snapshot_published_at,
        sync_status=sync_status,
        layer_metadata=layer_entry,
    )


def _collect_flat_children(children: Sequence[NumberedRule], acc: list[NumberedRule]) -> None:
    for ch in children:
        acc.append(ch)
        if ch.children:
            _collect_flat_children(ch.children, acc)


def number_package_rulebase(
    snapshot: DomainRulebaseSnapshot,
    package_name_or_uid: str,
    *,
    rulebase_type: RulebaseType = "access",
    snapshot_session_uid: str | None = None,
    snapshot_published_at: datetime | None = None,
    sync_status: SyncStatus = "idle",
) -> PackageRulebase:
    """Compute SmartConsole-accurate hierarchical numbering for a policy package."""
    target = package_name_or_uid.strip()
    pkg_layers = sorted(
        [
            pl
            for pl in snapshot.package_layers
            if (pl.package_uid == target or pl.package_name == target) and pl.rulebase_type == rulebase_type
        ],
        key=lambda pl: pl.position,
    )

    pkg_uid = pkg_layers[0].package_uid if pkg_layers else target
    pkg_name = pkg_layers[0].package_name if pkg_layers else target

    # Also check if package name/uid is known from another rulebase_type or nat_rules
    if not pkg_layers:
        for pl in snapshot.package_layers:
            if pl.package_uid == target or pl.package_name == target:
                pkg_uid = pl.package_uid
                pkg_name = pl.package_name
                break
        for nr in snapshot.nat_rules:
            if nr.package_uid == target or nr.package_name == target:
                pkg_uid = nr.package_uid
                pkg_name = nr.package_name
                break

    if rulebase_type == "nat":
        nat_entries = sorted(
            [r for r in snapshot.nat_rules if r.package_uid == pkg_uid or r.package_name == pkg_name],
            key=lambda r: r.position,
        )
        nat_rules: list[NumberedRule] = []
        for idx, nr in enumerate(nat_entries, start=1):
            nat_rules.append(NumberedRule.from_nat_entry(nr, rule_number=str(idx)))

        nat_layer_uids = {f"nat:{pkg_uid}", pkg_uid, pkg_name}
        nat_sec_entries = [
            s
            for s in snapshot.sections
            if s.rulebase_type == "nat" and (s.layer_uid in nat_layer_uids or s.layer_name in nat_layer_uids)
        ]
        numbered_nat_secs = _build_sections_for_layer(nat_sec_entries, nat_rules)

        nat_layer_rb = NumberedLayerRulebase(
            mgmt_name=snapshot.mgmt_name,
            domain_name=snapshot.domain_name,
            layer_uid=f"nat:{pkg_uid}",
            layer_name=f"{pkg_name} NAT",
            rulebase_type="nat",
            package_uid=pkg_uid,
            package_name=pkg_name,
            prefix="",
            sections=numbered_nat_secs,
            rules=nat_rules,
            flat_rules=list(nat_rules),
            snapshot_session_uid=snapshot_session_uid,
            snapshot_published_at=snapshot_published_at,
            sync_status=sync_status,
        )
        return PackageRulebase(
            mgmt_name=snapshot.mgmt_name,
            domain_name=snapshot.domain_name,
            package_uid=pkg_uid,
            package_name=pkg_name,
            rulebase_type="nat",
            layers=[nat_layer_rb],
            sections=numbered_nat_secs,
            rules=nat_rules,
            flat_rules=list(nat_rules),
            snapshot_session_uid=snapshot_session_uid,
            snapshot_published_at=snapshot_published_at,
            sync_status=sync_status,
        )

    # Identify if a Global layer in this package contains a `place-holder` that embeds a domain layer
    embedded_domain_layer_uids: set[str] = set()
    candidate_domain_layers: list[RulebasePackageLayerEntry] = []
    for pl in pkg_layers:
        l_entry = _find_layer_entry(snapshot, pl.layer_uid, rulebase_type=rulebase_type)
        is_glob = l_entry.is_global if l_entry is not None else pl.layer_name.lower().startswith("global")
        if not is_glob:
            candidate_domain_layers.append(pl)

    fallback_dom_layer_uid = candidate_domain_layers[0].layer_uid if candidate_domain_layers else None

    for pl in pkg_layers:
        for ar in snapshot.access_rules:
            if (ar.layer_uid == pl.layer_uid or ar.layer_name == pl.layer_name) and ar.rule_type == "place-holder":
                resolved_dom_uid = ar.placeholder_domain_layer_uid or fallback_dom_layer_uid
                if resolved_dom_uid and resolved_dom_uid != pl.layer_uid:
                    embedded_domain_layer_uids.add(resolved_dom_uid)

    numbered_layers: list[NumberedLayerRulebase] = []
    all_sections: list[NumberedSection] = []
    all_top_rules: list[NumberedRule] = []
    all_flat_rules: list[NumberedRule] = []

    for pl in pkg_layers:
        if pl.layer_uid in embedded_domain_layer_uids:
            # This domain layer is already expanded under the Global layer's place-holder rule
            continue
        layer_rb = number_layer_rulebase(
            snapshot,
            pl.layer_uid,
            rulebase_type=rulebase_type,
            prefix="",
            package_uid=pkg_uid,
            package_name=pkg_name,
            fallback_domain_layer_uid=fallback_dom_layer_uid,
            expand_placeholders=True,
            expand_inline_layers=True,
            snapshot_session_uid=snapshot_session_uid,
            snapshot_published_at=snapshot_published_at,
            sync_status=sync_status,
        )
        numbered_layers.append(layer_rb)
        all_sections.extend(layer_rb.sections)
        all_top_rules.extend(layer_rb.rules)
        all_flat_rules.extend(layer_rb.flat_rules)

    return PackageRulebase(
        mgmt_name=snapshot.mgmt_name,
        domain_name=snapshot.domain_name,
        package_uid=pkg_uid,
        package_name=pkg_name,
        rulebase_type=rulebase_type,
        layers=numbered_layers,
        sections=all_sections,
        rules=all_top_rules,
        flat_rules=all_flat_rules,
        snapshot_session_uid=snapshot_session_uid,
        snapshot_published_at=snapshot_published_at,
        sync_status=sync_status,
    )


def _index_section_ranges(sections: Sequence[NumberedSection], out: dict[tuple[str, str], str]) -> None:
    for sec in sections:
        out[(sec.layer_uid, sec.uid)] = sec.range_label
        for r in sec.rules:
            if r.nested_sections:
                _index_section_ranges(r.nested_sections, out)


def _record_layer_prefixes_from_rules(
    rules: Sequence[NumberedRule],
    *,
    mgmt_name: str,
    domain_name: str,
    package_uid: str | None,
    package_name: str | None,
    context: str,
    layer_prefixes: dict[str, list[LayerPrefixLocation]],
) -> None:
    for r in rules:
        if r.children:
            child_layer_uid = r.children[0].layer_uid
            child_layer_name = r.children[0].layer_name
            child_prefix = f"{r.rule_number}."
            loc = LayerPrefixLocation(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid=child_layer_uid,
                layer_name=child_layer_name,
                rulebase_type=r.rulebase_type,
                prefix=child_prefix,
                package_uid=package_uid,
                package_name=package_name,
                parent_layer_uid=r.layer_uid,
                parent_rule_uid=r.uid,
                context=context,  # type: ignore[arg-type]
            )
            existing = layer_prefixes.setdefault(child_layer_uid, [])
            if loc not in existing:
                existing.append(loc)
            _record_layer_prefixes_from_rules(
                r.children,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                package_uid=package_uid,
                package_name=package_name,
                context=context,
                layer_prefixes=layer_prefixes,
            )


def locate_rules_in_snapshot(
    snapshot: DomainRulebaseSnapshot,
    *,
    rule_uids: Sequence[str] | None = None,
    layer_uids: Sequence[str] | None = None,
    snapshot_session_uid: str | None = None,
    snapshot_published_at: datetime | None = None,
    sync_status: SyncStatus = "idle",
) -> RuleLocations:
    """Locate rules and layer numbering prefixes across all packages and layers in `snapshot`."""
    wanted_rules = {u.strip() for u in (rule_uids or []) if u and u.strip()}
    wanted_layers = {u.strip() for u in (layer_uids or []) if u and u.strip()}

    rule_locations: dict[str, list[RuleLocation]] = {u: [] for u in wanted_rules}
    layer_prefixes: dict[str, list[LayerPrefixLocation]] = {u: [] for u in wanted_layers}

    packages = extract_policy_packages(snapshot)
    seen_package_layer_uids: set[str] = set()

    # 1. Traverse all packages across access, nat, https, threat
    all_rb_types: tuple[RulebaseType, ...] = ("access", "nat", "https", "threat")
    for pkg in packages:
        for r_type in all_rb_types:
            if r_type == "nat" and not pkg.has_nat_policy:
                continue
            if r_type == "access" and not pkg.access_layers:
                continue
            if r_type == "https" and not pkg.https_layers:
                continue
            if r_type == "threat" and not pkg.threat_layers:
                continue

            pkg_rb = number_package_rulebase(
                snapshot,
                pkg.uid,
                rulebase_type=r_type,
                snapshot_session_uid=snapshot_session_uid,
                snapshot_published_at=snapshot_published_at,
                sync_status=sync_status,
            )

            sec_ranges: dict[tuple[str, str], str] = {}
            _index_section_ranges(pkg_rb.sections, sec_ranges)
            for r in pkg_rb.flat_rules:
                if r.nested_sections:
                    _index_section_ranges(r.nested_sections, sec_ranges)

            for l_rb in pkg_rb.layers:
                seen_package_layer_uids.add(l_rb.layer_uid)
                top_loc = LayerPrefixLocation(
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    layer_uid=l_rb.layer_uid,
                    layer_name=l_rb.layer_name,
                    rulebase_type=l_rb.rulebase_type,
                    prefix=l_rb.prefix,
                    package_uid=pkg.uid,
                    package_name=pkg.name,
                    context="package",
                )
                if not wanted_layers or l_rb.layer_uid in wanted_layers or l_rb.layer_name in wanted_layers:
                    existing_l = layer_prefixes.setdefault(l_rb.layer_uid, [])
                    if top_loc not in existing_l:
                        existing_l.append(top_loc)

                _record_layer_prefixes_from_rules(
                    l_rb.rules,
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    package_uid=pkg.uid,
                    package_name=pkg.name,
                    context="package",
                    layer_prefixes=layer_prefixes,
                )

            for r in pkg_rb.flat_rules:
                seen_package_layer_uids.add(r.layer_uid)
                if not wanted_rules or r.uid in wanted_rules:
                    sec_range = sec_ranges.get((r.layer_uid, r.section_uid or "")) if r.section_uid else None
                    r_loc = RuleLocation(
                        mgmt_name=snapshot.mgmt_name,
                        domain_name=snapshot.domain_name,
                        rule_uid=r.uid,
                        rule_name=r.name,
                        rule_number=r.rule_number,
                        position=r.position,
                        rulebase_type=r.rulebase_type,
                        package_uid=pkg.uid,
                        package_name=pkg.name,
                        layer_uid=r.layer_uid,
                        layer_name=r.layer_name,
                        section_uid=r.section_uid,
                        section_name=r.section_name,
                        section_range=sec_range,
                        parent_rule_uid=r.parent_rule_uid,
                        context="package",
                    )
                    existing_r = rule_locations.setdefault(r.uid, [])
                    if r_loc not in existing_r:
                        existing_r.append(r_loc)

    # 2. Traverse standalone layers (or any layer when no package covered it)
    for layer in snapshot.layers:
        layer_rb = number_layer_rulebase(
            snapshot,
            layer.uid,
            rulebase_type=layer.rulebase_type,
            prefix="",
            expand_placeholders=False,
            expand_inline_layers=True,
            snapshot_session_uid=snapshot_session_uid,
            snapshot_published_at=snapshot_published_at,
            sync_status=sync_status,
        )
        sec_ranges = {}
        _index_section_ranges(layer_rb.sections, sec_ranges)
        for r in layer_rb.flat_rules:
            if r.nested_sections:
                _index_section_ranges(r.nested_sections, sec_ranges)

        if layer.uid not in seen_package_layer_uids:
            top_loc = LayerPrefixLocation(
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                layer_uid=layer.uid,
                layer_name=layer.name,
                rulebase_type=layer.rulebase_type,
                prefix="",
                parent_layer_uid=layer.parent_layer_uid,
                parent_rule_uid=layer.parent_rule_uid,
                context="layer",
            )
            if not wanted_layers or layer.uid in wanted_layers or layer.name in wanted_layers:
                existing_l = layer_prefixes.setdefault(layer.uid, [])
                if top_loc not in existing_l:
                    existing_l.append(top_loc)

            _record_layer_prefixes_from_rules(
                layer_rb.rules,
                mgmt_name=snapshot.mgmt_name,
                domain_name=snapshot.domain_name,
                package_uid=None,
                package_name=None,
                context="layer",
                layer_prefixes=layer_prefixes,
            )

        for r in layer_rb.flat_rules:
            if r.layer_uid in seen_package_layer_uids and r.uid in rule_locations and rule_locations[r.uid]:
                continue
            if not wanted_rules or r.uid in wanted_rules:
                sec_range = sec_ranges.get((r.layer_uid, r.section_uid or "")) if r.section_uid else None
                r_loc = RuleLocation(
                    mgmt_name=snapshot.mgmt_name,
                    domain_name=snapshot.domain_name,
                    rule_uid=r.uid,
                    rule_name=r.name,
                    rule_number=r.rule_number,
                    position=r.position,
                    rulebase_type=r.rulebase_type,
                    package_uid=None,
                    package_name=None,
                    layer_uid=r.layer_uid,
                    layer_name=r.layer_name,
                    section_uid=r.section_uid,
                    section_name=r.section_name,
                    section_range=sec_range,
                    parent_rule_uid=r.parent_rule_uid,
                    context="layer",
                )
                existing_r = rule_locations.setdefault(r.uid, [])
                if r_loc not in existing_r:
                    existing_r.append(r_loc)

    # Filter layer_prefixes if caller specified explicit layer_uids
    if wanted_layers:
        filtered_lp: dict[str, list[LayerPrefixLocation]] = {}
        for k, locs in layer_prefixes.items():
            if k in wanted_layers or any(loc.layer_name in wanted_layers for loc in locs):
                filtered_lp[k] = locs
        for u in wanted_layers:
            filtered_lp.setdefault(u, [])
        layer_prefixes = filtered_lp

    return RuleLocations(
        mgmt_name=snapshot.mgmt_name,
        domain_name=snapshot.domain_name,
        rule_locations=rule_locations,
        layer_prefixes=layer_prefixes,
        snapshot_session_uid=snapshot_session_uid,
        snapshot_published_at=snapshot_published_at,
        sync_status=sync_status,
    )


__all__ = [
    "extract_policy_packages",
    "locate_rules_in_snapshot",
    "number_layer_rulebase",
    "number_package_rulebase",
]
