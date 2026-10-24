"""Rule identity matching and Check Point NAT sentinel normalization (`src/arodonata/cpcrud/rule_identity.py`).

Handles:
- Check Point NAT `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"` (`NAT_ANY_OBJECT_UID`) sentinel UIDs.
- Matching access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`)
  or by canonical traffic tuple.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)

# Check Point built-in sentinel object UIDs
NAT_ORIGINAL_OBJECT_UID = "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"
NAT_ANY_OBJECT_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"

_ORIGINAL_ALIASES: frozenset[str] = frozenset(
    {
        "",
        "original",
        NAT_ORIGINAL_OBJECT_UID.lower(),
    }
)

_ANY_ALIASES: frozenset[str] = frozenset(
    {
        "",
        "any",
        NAT_ANY_OBJECT_UID.lower(),
    }
)


def normalize_nat_original_sentinel(
    value: Any,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    """Normalize a NAT `translated-*` field (`None`, `""`, `"Original"`, `NAT_ORIGINAL_OBJECT_UID`, or dict) to `"Original"`."""
    if value is None:
        return "Original"
    if isinstance(value, dict):
        uid = str(value.get("uid") or "").strip()
        name = str(value.get("name") or "").strip()
        if uid.lower() == NAT_ORIGINAL_OBJECT_UID.lower() or name.lower() == "original":
            return "Original"
        if name:
            return name
        if uid and obj_dict and uid in obj_dict:
            resolved_name = str(obj_dict[uid].get("name") or "").strip()
            if resolved_name.lower() == "original":
                return "Original"
            if resolved_name:
                return resolved_name
        return uid or "Original"
    if isinstance(value, str):
        clean = value.strip()
        if clean.lower() in _ORIGINAL_ALIASES:
            return "Original"
        if obj_dict and clean in obj_dict:
            resolved_name = str(obj_dict[clean].get("name") or "").strip()
            if resolved_name.lower() == "original":
                return "Original"
            if resolved_name:
                return resolved_name
        return clean
    return str(value)


def normalize_any_sentinel(
    value: Any,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    """Normalize a traffic reference (`None`, `""`, `"Any"`, `NAT_ANY_OBJECT_UID`, or dict) to `"Any"` or object name."""
    if value is None:
        return "Any"
    if isinstance(value, dict):
        uid = str(value.get("uid") or "").strip()
        name = str(value.get("name") or "").strip()
        if uid.lower() == NAT_ANY_OBJECT_UID.lower() or name.lower() == "any":
            return "Any"
        if uid.lower() == NAT_ORIGINAL_OBJECT_UID.lower() or name.lower() == "original":
            return "Original"
        if name:
            return name
        if uid and obj_dict and uid in obj_dict:
            resolved_name = str(obj_dict[uid].get("name") or "").strip()
            if resolved_name.lower() == "any":
                return "Any"
            if resolved_name:
                return resolved_name
        return uid or "Any"
    if isinstance(value, str):
        clean = value.strip()
        if clean.lower() in _ANY_ALIASES:
            return "Any"
        if clean.lower() in _ORIGINAL_ALIASES:
            return "Original"
        if obj_dict and clean in obj_dict:
            resolved_name = str(obj_dict[clean].get("name") or "").strip()
            if resolved_name.lower() == "any":
                return "Any"
            if resolved_name.lower() == "original":
                return "Original"
            if resolved_name:
                return resolved_name
        return clean
    return str(value)


def normalize_traffic_list(
    value: Any,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Normalize a rule traffic field (`source`, `destination`, `service`) into a sorted canonical tuple of names."""
    if value is None:
        return ("Any",)
    items = value if isinstance(value, (list, tuple, set)) else [value]
    normalized: list[str] = []
    for item in items:
        ref = normalize_any_sentinel(item, obj_dict)
        if name_resolutions and ref in name_resolutions:
            ref = name_resolutions[ref]
        normalized.append(ref)
    if not normalized or all(x.lower() == "any" for x in normalized):
        return ("Any",)
    return tuple(sorted(dict.fromkeys(normalized)))


def normalize_nat_traffic_ref(
    value: Any,
    *,
    is_translated: bool,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
    name_resolutions: Mapping[str, str] | None = None,
) -> str:
    """Normalize a single NAT rule traffic reference (`original-*` or `translated-*`)."""
    ref = normalize_nat_original_sentinel(value, obj_dict) if is_translated else normalize_any_sentinel(value, obj_dict)
    if name_resolutions and ref in name_resolutions:
        ref = name_resolutions[ref]
    return ref


def desired_access_traffic_tuple(
    spec: Mapping[str, Any],
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
    """Compute canonical `(source, destination, service, action)` tuple for a desired access/HTTPS/threat rule."""
    src = normalize_traffic_list(spec.get("source"), name_resolutions=name_resolutions)
    dst = normalize_traffic_list(spec.get("destination"), name_resolutions=name_resolutions)
    svc = normalize_traffic_list(spec.get("service"), name_resolutions=name_resolutions)
    raw_act = spec.get("rule_action") or spec.get("action")
    if isinstance(raw_act, str) and raw_act.lower() in ("present", "absent", "add", "set", "update", "delete"):
        raw_act = spec.get("rule_action") or "Drop"
    act = str(raw_act or "Drop").strip().capitalize()
    return (src, dst, svc, act)


def existing_access_traffic_tuple(
    rule: AccessRuleEntry | HttpsRuleEntry | ThreatRuleEntry,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
    """Compute canonical `(source, destination, service, action)` tuple for an existing access/HTTPS/threat rule."""
    raw = rule.raw_data or {}
    src = normalize_traffic_list(rule.source or raw.get("source"), obj_dict=obj_dict)
    dst = normalize_traffic_list(rule.destination or raw.get("destination"), obj_dict=obj_dict)
    svc = normalize_traffic_list(rule.service or raw.get("service"), obj_dict=obj_dict)
    act = str(rule.action or "Drop").strip().capitalize()
    return (src, dst, svc, act)


def desired_nat_traffic_tuple(
    spec: Mapping[str, Any],
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[str, str, str, str, str, str, str]:
    """Compute canonical 7-tuple for a desired NAT rule, normalizing `Original` and `Any` sentinels."""
    orig_src = normalize_nat_traffic_ref(
        spec.get("original_source", spec.get("original-source")),
        is_translated=False,
        name_resolutions=name_resolutions,
    )
    orig_dst = normalize_nat_traffic_ref(
        spec.get("original_destination", spec.get("original-destination")),
        is_translated=False,
        name_resolutions=name_resolutions,
    )
    orig_svc = normalize_nat_traffic_ref(
        spec.get("original_service", spec.get("original-service")),
        is_translated=False,
        name_resolutions=name_resolutions,
    )
    trans_src = normalize_nat_traffic_ref(
        spec.get("translated_source", spec.get("translated-source")),
        is_translated=True,
        name_resolutions=name_resolutions,
    )
    trans_dst = normalize_nat_traffic_ref(
        spec.get("translated_destination", spec.get("translated-destination")),
        is_translated=True,
        name_resolutions=name_resolutions,
    )
    trans_svc = normalize_nat_traffic_ref(
        spec.get("translated_service", spec.get("translated-service")),
        is_translated=True,
        name_resolutions=name_resolutions,
    )
    method = str(spec.get("method") or "static").strip().lower()
    return (orig_src, orig_dst, orig_svc, trans_src, trans_dst, trans_svc, method)


def existing_nat_traffic_tuple(
    rule: NatRuleEntry,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[str, str, str, str, str, str, str]:
    """Compute canonical 7-tuple for an existing `NatRuleEntry`, normalizing `NAT_ORIGINAL_OBJECT_UID` and `NAT_ANY_OBJECT_UID`."""
    raw = rule.raw_data or {}
    orig_src = normalize_nat_traffic_ref(
        rule.original_source if rule.original_source is not None else raw.get("original-source"),
        is_translated=False,
        obj_dict=obj_dict,
    )
    orig_dst = normalize_nat_traffic_ref(
        rule.original_destination if rule.original_destination is not None else raw.get("original-destination"),
        is_translated=False,
        obj_dict=obj_dict,
    )
    orig_svc = normalize_nat_traffic_ref(
        rule.original_service if rule.original_service is not None else raw.get("original-service"),
        is_translated=False,
        obj_dict=obj_dict,
    )
    trans_src = normalize_nat_traffic_ref(
        rule.translated_source if rule.translated_source is not None else raw.get("translated-source"),
        is_translated=True,
        obj_dict=obj_dict,
    )
    trans_dst = normalize_nat_traffic_ref(
        rule.translated_destination if rule.translated_destination is not None else raw.get("translated-destination"),
        is_translated=True,
        obj_dict=obj_dict,
    )
    trans_svc = normalize_nat_traffic_ref(
        rule.translated_service if rule.translated_service is not None else raw.get("translated-service"),
        is_translated=True,
        obj_dict=obj_dict,
    )
    method = str(rule.method or raw.get("method") or "static").strip().lower()
    return (orig_src, orig_dst, orig_svc, trans_src, trans_dst, trans_svc, method)


RuleEntryUnion = AccessRuleEntry | NatRuleEntry | HttpsRuleEntry | ThreatRuleEntry


def match_rule(
    spec: Mapping[str, Any],
    rules: Sequence[RuleEntryUnion],
    *,
    rulebase_type: RulebaseType,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
    name_resolutions: Mapping[str, str] | None = None,
) -> RuleEntryUnion | None:
    """Match a desired rule specification against existing rules by explicit key (`uid`, `name`, `rule_number`) or traffic tuple."""
    req_uid = str(spec.get("uid") or "").strip()
    if req_uid:
        for r in rules:
            if r.uid == req_uid:
                return r
        return None

    req_name = str(spec.get("name") or "").strip()
    if req_name:
        for r in rules:
            if r.name == req_name:
                return r

    req_num_raw = spec.get("rule_number") if "rule_number" in spec else spec.get("rule-number")
    if req_num_raw is not None:
        req_num_str = str(req_num_raw).strip()
        for r in rules:
            if r.rule_number == req_num_str or str(r.position) == req_num_str:
                return r
        return None

    # Traffic tuple matching when no explicit uid/rule_number matched (and either name wasn't set or didn't match)
    if rulebase_type == "nat":
        des_nat = desired_nat_traffic_tuple(spec, name_resolutions=name_resolutions)
        for r in rules:
            if isinstance(r, NatRuleEntry) and existing_nat_traffic_tuple(r, obj_dict=obj_dict) == des_nat:
                return r
        return None

    # Access / HTTPS / Threat rule traffic tuple matching (only if at least one traffic attribute is specified or name is empty)
    has_traffic_fields = any(
        k in spec
        for k in (
            "source",
            "destination",
            "service",
            "rule_action",
            "action",
        )
    )
    if not req_name or has_traffic_fields:
        des_acc = desired_access_traffic_tuple(spec, name_resolutions=name_resolutions)
        for r in rules:
            if isinstance(r, (AccessRuleEntry, HttpsRuleEntry, ThreatRuleEntry)):
                # Skip matching the trailing Cleanup rule unless explicitly named "Cleanup rule"
                if r.name.strip().lower() == "cleanup rule" and req_name.lower() != "cleanup rule":
                    continue
                if existing_access_traffic_tuple(r, obj_dict=obj_dict) == des_acc:
                    return r
    return None


__all__ = [
    "NAT_ANY_OBJECT_UID",
    "NAT_ORIGINAL_OBJECT_UID",
    "RuleEntryUnion",
    "desired_access_traffic_tuple",
    "desired_nat_traffic_tuple",
    "existing_access_traffic_tuple",
    "existing_nat_traffic_tuple",
    "match_rule",
    "normalize_any_sentinel",
    "normalize_nat_original_sentinel",
    "normalize_nat_traffic_ref",
    "normalize_traffic_list",
]
