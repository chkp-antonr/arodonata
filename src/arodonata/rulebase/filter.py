"""Local cache-backed rulebase filtering and formatting (`rulebase/filter.py`).

Evaluates search/filter expressions locally against a numbered rulebase (`PackageRulebase`
or `NumberedLayerRulebase`) and cached `CPObject` / `CPService` dictionaries without
Check Point Management API round-trips, formatting output as `"markdown"`,
`"model_friendly"`, `"raw"`, or `"cpcrud"`.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
from collections.abc import Sequence
from typing import Any, Literal

from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.cpcrud.rule_identity import (
    normalize_any_sentinel,
    normalize_nat_original_sentinel,
)
from arodonata.rulebase.models import (
    FilteredRulebaseResult,
    NumberedLayerRulebase,
    NumberedRule,
    NumberedSection,
    PackageRulebase,
    RuleFormat,
)


def _object_matches_ip_or_subnet(obj: CPObject, query_term: str) -> bool:
    """Return `True` if `obj` matches an IPv4 address or CIDR query."""
    try:
        if "/" in query_term:
            q_net = ipaddress.IPv4Network(query_term, strict=False)
            if obj.ipv4_address:
                return ipaddress.IPv4Address(obj.ipv4_address) in q_net
            if obj.subnet4 and obj.mask_length4 is not None:
                o_net = ipaddress.IPv4Network(f"{obj.subnet4}/{obj.mask_length4}", strict=False)
                return o_net.overlaps(q_net)
            if obj.ipv4_address_first and obj.ipv4_address_last:
                first_int = int(ipaddress.IPv4Address(obj.ipv4_address_first))
                last_int = int(ipaddress.IPv4Address(obj.ipv4_address_last))
                q_first = int(q_net.network_address)
                q_last = int(q_net.broadcast_address)
                return first_int <= q_last and q_first <= last_int
        else:
            q_ip = ipaddress.IPv4Address(query_term)
            if obj.ipv4_address:
                return ipaddress.IPv4Address(obj.ipv4_address) == q_ip
            if obj.subnet4 and obj.mask_length4 is not None:
                o_net = ipaddress.IPv4Network(f"{obj.subnet4}/{obj.mask_length4}", strict=False)
                return q_ip in o_net
            if obj.ipv4_address_first and obj.ipv4_address_last:
                first_ip = ipaddress.IPv4Address(obj.ipv4_address_first)
                last_ip = ipaddress.IPv4Address(obj.ipv4_address_last)
                return first_ip <= q_ip <= last_ip
    except ValueError:
        return False
    return False


def _service_matches_term(svc: CPService, term_lower: str) -> bool:
    """Return `True` if `svc` matches a service name, UID, port, or protocol term."""
    if term_lower in svc.name.lower() or term_lower == svc.uid.lower():
        return True
    if svc.protocol and term_lower == svc.protocol.lower():
        return True
    if svc.port:
        port_str = svc.port.strip().lower()
        if term_lower == port_str or f"/{port_str}" in term_lower:
            return True
        # Handle port ranges like "8000-8080" when searching for "8080" or "8050"
        if "-" in port_str and term_lower.isdigit():
            parts = port_str.split("-", 1)
            if parts[0].isdigit() and parts[1].isdigit():
                q_port = int(term_lower)
                if int(parts[0]) <= q_port <= int(parts[1]):
                    return True
    if svc.protocol and svc.port:
        combo = f"{svc.protocol.lower()}/{svc.port.lower()}"
        if term_lower == combo or term_lower == svc.type.lower():
            return True
    return False


def _build_matching_object_identifiers(
    term: str,
    objects: Sequence[CPObject],
) -> set[str]:
    """Resolve all object names and UIDs (including parent groups) matching `term`."""
    term_lower = term.strip().lower()
    if not term_lower:
        return set()

    by_uid: dict[str, CPObject] = {o.uid: o for o in objects}
    by_name: dict[str, CPObject] = {o.name.lower(): o for o in objects}

    direct_uids: set[str] = set()
    matched_identifiers: set[str] = set()

    for obj in objects:
        if (
            term_lower in obj.name.lower()
            or term_lower == obj.uid.lower()
            or (obj.ipv4_address and term_lower in obj.ipv4_address.lower())
            or (obj.subnet4 and term_lower in obj.subnet4.lower())
            or (obj.fqdn and term_lower in obj.fqdn.lower())
            or _object_matches_ip_or_subnet(obj, term.strip())
        ):
            direct_uids.add(obj.uid)
            matched_identifiers.add(obj.name.lower())
            matched_identifiers.add(obj.uid.lower())

    if not direct_uids:
        return matched_identifiers

    # Expand to parent groups that contain any direct match (up to 5 levels)
    reverse_parents: dict[str, set[str]] = {}
    for obj in objects:
        if obj.members:
            for m in obj.members:
                reverse_parents.setdefault(m, set()).add(obj.uid)
                m_obj = by_name.get(m.lower())
                if m_obj is not None:
                    reverse_parents.setdefault(m_obj.uid, set()).add(obj.uid)

    frontier = set(direct_uids)
    visited = set(direct_uids)
    for _ in range(5):
        next_frontier: set[str] = set()
        for u in frontier:
            for p_uid in reverse_parents.get(u, ()):
                if p_uid not in visited:
                    visited.add(p_uid)
                    next_frontier.add(p_uid)
                    p_obj = by_uid.get(p_uid)
                    if p_obj is not None:
                        matched_identifiers.add(p_obj.name.lower())
                        matched_identifiers.add(p_obj.uid.lower())
        if not next_frontier:
            break
        frontier = next_frontier

    return matched_identifiers


def _build_matching_service_identifiers(
    term: str,
    services: Sequence[CPService],
) -> set[str]:
    """Resolve all service names and UIDs (including service-groups) matching `term`."""
    term_lower = term.strip().lower()
    if not term_lower:
        return set()

    by_uid: dict[str, CPService] = {s.uid: s for s in services}
    by_name: dict[str, CPService] = {s.name.lower(): s for s in services}

    direct_uids: set[str] = set()
    matched_identifiers: set[str] = set()

    for svc in services:
        if _service_matches_term(svc, term_lower):
            direct_uids.add(svc.uid)
            matched_identifiers.add(svc.name.lower())
            matched_identifiers.add(svc.uid.lower())

    if not direct_uids:
        return matched_identifiers

    reverse_parents: dict[str, set[str]] = {}
    for svc in services:
        if svc.members:
            for m in svc.members:
                reverse_parents.setdefault(m, set()).add(svc.uid)
                m_svc = by_name.get(m.lower())
                if m_svc is not None:
                    reverse_parents.setdefault(m_svc.uid, set()).add(svc.uid)

    frontier = set(direct_uids)
    visited = set(direct_uids)
    for _ in range(5):
        next_frontier: set[str] = set()
        for u in frontier:
            for p_uid in reverse_parents.get(u, ()):
                if p_uid not in visited:
                    visited.add(p_uid)
                    next_frontier.add(p_uid)
                    p_svc = by_uid.get(p_uid)
                    if p_svc is not None:
                        matched_identifiers.add(p_svc.name.lower())
                        matched_identifiers.add(p_svc.uid.lower())
        if not next_frontier:
            break
        frontier = next_frontier

    return matched_identifiers


def _parse_filter_tokens(filter_text: str) -> list[tuple[str | None, str]]:
    """Split a filter string into `(field_qualifier, value)` tokens."""
    clean = filter_text.strip()
    if not clean:
        return []
    try:
        parts = shlex.split(clean)
    except ValueError:
        parts = clean.split()

    tokens: list[tuple[str | None, str]] = []
    for part in parts:
        if ":" in part and not part.startswith(":"):
            prefix, val = part.split(":", 1)
            qual = prefix.strip().lower()
            if qual in {
                "name",
                "src",
                "source",
                "dst",
                "destination",
                "svc",
                "service",
                "action",
                "enabled",
                "comment",
                "comments",
                "track",
                "install",
                "install-on",
                "uid",
                "rule",
                "number",
            }:
                tokens.append((qual, val.strip()))
                continue
        tokens.append((None, part.strip()))
    return [t for t in tokens if t[1]]


def _rule_ref_values(rule: NumberedRule, field: str) -> list[str]:
    """Return lowercase string tokens for a rule field (`source`, `destination`, `service`, including raw UIDs)."""
    values: list[str] = []
    if field == "source":
        values.extend(s.lower() for s in rule.source)
        if rule.original_source:
            values.append(rule.original_source.lower())
        if rule.translated_source:
            values.append(rule.translated_source.lower())
    elif field == "destination":
        values.extend(d.lower() for d in rule.destination)
        if rule.original_destination:
            values.append(rule.original_destination.lower())
        if rule.translated_destination:
            values.append(rule.translated_destination.lower())
    elif field == "service":
        values.extend(s.lower() for s in rule.service)
        if rule.original_service:
            values.append(rule.original_service.lower())
        if rule.translated_service:
            values.append(rule.translated_service.lower())

    raw_val = rule.raw_data.get(field)
    if isinstance(raw_val, list):
        for item in raw_val:
            if isinstance(item, str):
                values.append(item.lower())
            elif isinstance(item, dict):
                if isinstance(item.get("uid"), str):
                    values.append(item["uid"].lower())
                if isinstance(item.get("name"), str):
                    values.append(item["name"].lower())
    return values


def rule_matches_filter(
    rule: NumberedRule,
    tokens: Sequence[tuple[str | None, str]],
    *,
    objects: Sequence[CPObject] = (),
    services: Sequence[CPService] = (),
) -> bool:
    """Return `True` if `rule` satisfies all `(qualifier, value)` filter tokens."""
    if not tokens:
        return True

    for qual, val in tokens:
        v_low = val.lower()
        if qual == "enabled":
            want = v_low in ("true", "1", "yes", "on")
            if rule.enabled != want:
                return False
        elif qual in ("uid",):
            if v_low not in rule.uid.lower():
                return False
        elif qual in ("rule", "number"):
            if rule.rule_number.lower() != v_low:
                return False
        elif qual == "name":
            if v_low not in rule.name.lower():
                return False
        elif qual == "action":
            act = (rule.action or rule.method or "").lower()
            if v_low not in act:
                return False
        elif qual in ("comment", "comments"):
            if v_low not in rule.comments.lower():
                return False
        elif qual == "track":
            if v_low not in (rule.track or "").lower():
                return False
        elif qual in ("install", "install-on"):
            if not any(v_low in inst.lower() for inst in rule.install_on):
                return False
        elif qual in ("src", "source"):
            refs = _rule_ref_values(rule, "source")
            obj_ids = _build_matching_object_identifiers(val, objects)
            if not any(v_low in r or r in obj_ids for r in refs):
                return False
        elif qual in ("dst", "destination"):
            refs = _rule_ref_values(rule, "destination")
            obj_ids = _build_matching_object_identifiers(val, objects)
            if not any(v_low in r or r in obj_ids for r in refs):
                return False
        elif qual in ("svc", "service"):
            refs = _rule_ref_values(rule, "service")
            svc_ids = _build_matching_service_identifiers(val, services)
            if not any(v_low in r or r in svc_ids for r in refs):
                return False
        else:
            # Unqualified token: match rule number, uid, name, comments, action/method, source, destination, service, or resolved objects/services
            haystack_parts = [
                rule.uid.lower(),
                rule.name.lower(),
                rule.rule_number.lower(),
                rule.comments.lower(),
                (rule.action or "").lower(),
                (rule.method or "").lower(),
                (rule.track or "").lower(),
                (rule.section_name or "").lower(),
                *_rule_ref_values(rule, "source"),
                *_rule_ref_values(rule, "destination"),
                *_rule_ref_values(rule, "service"),
                *(inst.lower() for inst in rule.install_on),
            ]
            if any(v_low in part for part in haystack_parts if part):
                continue

            obj_ids = _build_matching_object_identifiers(val, objects)
            svc_ids = _build_matching_service_identifiers(val, services)
            all_refs = set(
                _rule_ref_values(rule, "source")
                + _rule_ref_values(rule, "destination")
                + _rule_ref_values(rule, "service")
            )
            if not (all_refs & (obj_ids | svc_ids)):
                return False

    return True


def format_rules_markdown(
    target_name: str,
    rulebase_type: str,
    rules: Sequence[NumberedRule],
    sections: Sequence[NumberedSection] | None = None,
) -> str:
    """Format numbered rules (and optional sections) into a Markdown table."""
    lines: list[str] = [f"# Rulebase: {target_name} ({rulebase_type})", ""]
    if sections:
        lines.append("## Sections")
        lines.append("")
        for sec in sections:
            lines.append(f"- **{sec.name}** (`{sec.range_label}`)")
        lines.append("")

    if rulebase_type == "nat":
        lines.append(
            "| # | Name | Enabled | Method | Orig Src | Orig Dst | Orig Svc | Trans Src | Trans Dst | Trans Svc | Comments |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in rules:
            en = "yes" if r.enabled else "no"
            lines.append(
                f"| {r.rule_number} | {r.name} | {en} | {r.method or ''} | "
                f"{r.original_source or 'Any'} | {r.original_destination or 'Any'} | {r.original_service or 'Any'} | "
                f"{r.translated_source or 'Original'} | {r.translated_destination or 'Original'} | "
                f"{r.translated_service or 'Original'} | {r.comments} |"
            )
    else:
        lines.append("| # | Name | Enabled | Source | Destination | Service | Action | Track | Comments |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in rules:
            en = "yes" if r.enabled else "no"
            src = ", ".join(r.source) if r.source else "Any"
            dst = ", ".join(r.destination) if r.destination else "Any"
            svc = ", ".join(r.service) if r.service else "Any"
            if r.source_negate:
                src = f"NOT ({src})"
            if r.destination_negate:
                dst = f"NOT ({dst})"
            if r.service_negate:
                svc = f"NOT ({svc})"
            lines.append(
                f"| {r.rule_number} | {r.name} | {en} | {src} | {dst} | {svc} | "
                f"{r.action or ''} | {r.track or ''} | {r.comments} |"
            )
    return "\n".join(lines)


def format_rules_model_friendly(
    target_name: str,
    rulebase_type: str,
    rules: Sequence[NumberedRule],
) -> str:
    """Format numbered rules into compact, LLM-friendly one-line entries."""
    lines: list[str] = [f"Rulebase {target_name} ({rulebase_type}) — {len(rules)} rule(s):"]
    for r in rules:
        status = "" if r.enabled else " [DISABLED]"
        sec = f" [Section: {r.section_name}]" if r.section_name else ""
        if rulebase_type == "nat":
            lines.append(
                f"#{r.rule_number}{status} {r.name!r} (uid={r.uid}){sec}: "
                f"method={r.method or 'static'} "
                f"orig=({r.original_source or 'Any'} -> {r.original_destination or 'Any'} : {r.original_service or 'Any'}) "
                f"xlate=({r.translated_source or 'Original'} -> {r.translated_destination or 'Original'} : {r.translated_service or 'Original'})"
            )
        else:
            src = ", ".join(r.source) if r.source else "Any"
            dst = ", ".join(r.destination) if r.destination else "Any"
            svc = ", ".join(r.service) if r.service else "Any"
            lines.append(
                f"#{r.rule_number}{status} {r.name!r} (uid={r.uid}){sec}: "
                f"{src} -> {dst} [{svc}] => {r.action or r.rule_type}"
            )
    return "\n".join(lines)


def rule_to_cpcrud_operation(
    rule: AccessRuleEntry | NatRuleEntry | HttpsRuleEntry | ThreatRuleEntry | NumberedRule,
    *,
    operation: Literal["add", "set", "delete", "present", "absent"] = "set",
    package: str | None = None,
    layer: str | None = None,
) -> dict[str, Any]:
    """Convert a cached or numbered rule into a schema-valid `cpcrud` `RuleOperation` dict.

    Normalizes Check Point NAT `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"`
    (`NAT_ANY_OBJECT_UID`) sentinel UIDs so the resulting dict passes
    `CPCRUDService.validate()` and `Planner.decide()` without false diffs.
    """
    is_nat = isinstance(rule, NatRuleEntry) or (isinstance(rule, NumberedRule) and rule.rulebase_type == "nat")
    is_https = isinstance(rule, HttpsRuleEntry) or (isinstance(rule, NumberedRule) and rule.rulebase_type == "https")
    is_threat = isinstance(rule, ThreatRuleEntry) or (isinstance(rule, NumberedRule) and rule.rulebase_type == "threat")

    if is_nat:
        rb_type = "nat"
        rule_type = "nat-rule"
    elif is_https:
        rb_type = "https"
        rule_type = "https-rule"
    elif is_threat:
        rb_type = "threat"
        rule_type = "threat-rule"
    else:
        rb_type = "access"
        rule_type = "access-rule"

    op: dict[str, Any] = {
        "operation": operation,
        "type": rule_type,
        "rulebase_type": rb_type,
        "uid": rule.uid,
        "name": rule.name,
        "enabled": rule.enabled,
    }

    if rule.rule_number:
        op["rule_number"] = rule.rule_number
    if rule.position > 0:
        op["position"] = rule.position
    if rule.comments:
        op["comments"] = rule.comments

    if is_nat:
        eff_pkg = package
        if not eff_pkg:
            if isinstance(rule, NatRuleEntry):
                eff_pkg = rule.package_name or rule.package_uid
            elif isinstance(rule, NumberedRule):
                eff_pkg = rule.package_name or rule.layer_name or rule.package_uid or rule.layer_uid
        op["package"] = eff_pkg or "Standard"

        raw = rule.raw_data or {}
        method_raw = getattr(rule, "method", None) or raw.get("method") or "static"
        method_str = str(method_raw).strip().lower()
        op["method"] = method_str if method_str in {"static", "hide", "nat64", "nat46", "cgnat"} else "static"

        orig_src = getattr(rule, "original_source", None)
        if orig_src is None:
            orig_src = raw.get("original-source")
        orig_dst = getattr(rule, "original_destination", None)
        if orig_dst is None:
            orig_dst = raw.get("original-destination")
        orig_svc = getattr(rule, "original_service", None)
        if orig_svc is None:
            orig_svc = raw.get("original-service")

        trans_src = getattr(rule, "translated_source", None)
        if trans_src is None:
            trans_src = raw.get("translated-source")
        trans_dst = getattr(rule, "translated_destination", None)
        if trans_dst is None:
            trans_dst = raw.get("translated-destination")
        trans_svc = getattr(rule, "translated_service", None)
        if trans_svc is None:
            trans_svc = raw.get("translated-service")

        op["original-source"] = normalize_any_sentinel(orig_src)
        op["original-destination"] = normalize_any_sentinel(orig_dst)
        op["original-service"] = normalize_any_sentinel(orig_svc)
        op["translated-source"] = normalize_nat_original_sentinel(trans_src)
        op["translated-destination"] = normalize_nat_original_sentinel(trans_dst)
        op["translated-service"] = normalize_nat_original_sentinel(trans_svc)
    else:
        eff_layer = layer or getattr(rule, "layer_name", "") or getattr(rule, "layer_uid", "")
        op["layer"] = eff_layer or "Network"
        eff_pkg_opt = package or getattr(rule, "package_name", None)
        if eff_pkg_opt:
            op["package"] = eff_pkg_opt

        src_list = [normalize_any_sentinel(s) for s in (getattr(rule, "source", None) or [])]
        dst_list = [normalize_any_sentinel(d) for d in (getattr(rule, "destination", None) or [])]
        svc_list = [normalize_any_sentinel(s) for s in (getattr(rule, "service", None) or [])]
        op["source"] = src_list if src_list else ["Any"]
        op["destination"] = dst_list if dst_list else ["Any"]
        op["service"] = svc_list if svc_list else ["Any"]

        rule_act = getattr(rule, "action", None)
        if rule_act:
            op["rule_action"] = rule_act
        track_val = getattr(rule, "track", None)
        if track_val:
            op["track"] = track_val

        if isinstance(rule, (AccessRuleEntry, NumberedRule)):
            if getattr(rule, "source_negate", False):
                op["source-negate"] = True
            if getattr(rule, "destination_negate", False):
                op["destination-negate"] = True
            if getattr(rule, "service_negate", False):
                op["service-negate"] = True
            inline_layer = getattr(rule, "inline_layer_name", None) or getattr(rule, "inline_layer_uid", None)
            if inline_layer:
                op["inline-layer"] = inline_layer

        if is_https:
            site_cat = getattr(rule, "site_category", None)
            if site_cat:
                op["site-category"] = list(site_cat)
            cert = getattr(rule, "certificate", None)
            if cert:
                op["certificate"] = cert

        if is_threat:
            prot_scope = getattr(rule, "protected_scope", None)
            if prot_scope:
                op["protected-scope"] = list(prot_scope)

    if rule.install_on:
        op["install-on"] = list(rule.install_on)

    return op


def filter_numbered_rulebase(
    rulebase: PackageRulebase | NumberedLayerRulebase,
    *,
    filter_query: str = "",
    output_format: RuleFormat = "model_friendly",
    objects: Sequence[CPObject] = (),
    services: Sequence[CPService] = (),
    cache_age_seconds: float | None = None,
) -> FilteredRulebaseResult:
    """Evaluate `filter_query` locally against `rulebase` and format the matching rules."""
    tokens = _parse_filter_tokens(filter_query)
    all_rules = rulebase.flat_rules
    matched_rules = [r for r in all_rules if rule_matches_filter(r, tokens, objects=objects, services=services)]

    if isinstance(rulebase, PackageRulebase):
        target_name = rulebase.package_name
        target_uid = rulebase.package_uid
        pkg_ctx: str | None = rulebase.package_name
    else:
        target_name = rulebase.layer_name
        target_uid = rulebase.layer_uid
        pkg_ctx = rulebase.package_name

    if output_format == "cpcrud":
        raw_items = [rule_to_cpcrud_operation(r, package=pkg_ctx) for r in matched_rules]
        rendered = json.dumps(raw_items, indent=2)
    else:
        if output_format == "markdown":
            rendered = format_rules_markdown(
                target_name,
                rulebase.rulebase_type,
                matched_rules,
                sections=rulebase.sections if not tokens else None,
            )
        elif output_format == "raw":
            rendered = ""
        else:
            rendered = format_rules_model_friendly(target_name, rulebase.rulebase_type, matched_rules)
        raw_items = [r.model_dump(mode="json") for r in matched_rules]

    return FilteredRulebaseResult(
        mgmt_name=rulebase.mgmt_name,
        domain_name=rulebase.domain_name,
        target_name=target_name,
        target_uid=target_uid,
        rulebase_type=rulebase.rulebase_type,
        query=filter_query,
        format=output_format,
        total_rules=len(all_rules),
        matched_count=len(matched_rules),
        rules=matched_rules,
        rendered_text=rendered,
        raw_items=raw_items,
        source="cache",
        cache_age_seconds=cache_age_seconds,
        snapshot_session_uid=rulebase.snapshot_session_uid,
        snapshot_published_at=rulebase.snapshot_published_at,
    )


__all__ = [
    "filter_numbered_rulebase",
    "format_rules_markdown",
    "format_rules_model_friendly",
    "rule_matches_filter",
    "rule_to_cpcrud_operation",
]
