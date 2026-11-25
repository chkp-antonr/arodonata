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
from arodonata.core.models.sentinels import (
    NAT_ANY_OBJECT_UID,
    NAT_ORIGINAL_OBJECT_UID,
    normalize_any_sentinel,
    normalize_nat_original_sentinel,
)

RULE_DELTA_CELL_KEYS: tuple[str, ...] = (
    "source",
    "destination",
    "service",
    "install_on",
    "install-on",
    "protected_scope",
    "protected-scope",
    "site_category",
    "site-category",
)


def rule_spec_has_delta_mapping(spec: Mapping[str, Any]) -> bool:
    """Return `True` if `spec` contains an incremental `{add, remove}` mapping on any rule list cell."""
    return any(isinstance(spec.get(k), Mapping) for k in RULE_DELTA_CELL_KEYS)


def build_effective_obj_dict(
    raw_data: Mapping[str, Any] | None,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Mapping[str, Any]]:
    """Merge `_resolved_objects` from `raw_data` with `obj_dict` into a unified lookup dictionary."""
    eff_obj_dict: dict[str, Mapping[str, Any]] = {}
    if isinstance(raw_data, Mapping):
        raw_resolved = raw_data.get("_resolved_objects")
        if isinstance(raw_resolved, Mapping):
            for k, v in raw_resolved.items():
                if isinstance(v, Mapping):
                    eff_obj_dict[str(k)] = v
    if obj_dict:
        for k, v in obj_dict.items():
            eff_obj_dict[str(k)] = v
    return eff_obj_dict


def normalize_traffic_list(
    value: Any,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Normalize a rule traffic field (`source`, `destination`, `service`) into a sorted canonical tuple of names."""
    if value is None:
        return ("Any",)
    if isinstance(value, Mapping) and ("add" in value or "remove" in value):
        raise ValueError("Incremental {add, remove} delta mapping cannot be normalized as a full traffic list.")
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


def deref_rule_list(
    items: Sequence[str] | None,
    raw_fallback: Any,
    eff_obj_dict: Mapping[str, Mapping[str, Any]],
    *,
    default_any: bool = False,
) -> list[str]:
    """Dereference UIDs/dicts in a rule list cell via `eff_obj_dict`, preserving order and deduplicating."""
    if items:
        raw_items: Sequence[Any] = items
    elif isinstance(raw_fallback, list):
        raw_items = raw_fallback
    elif raw_fallback is not None:
        raw_items = [raw_fallback]
    else:
        raw_items = []
    resolved: list[str] = []
    for elem in raw_items:
        name = normalize_any_sentinel(elem, eff_obj_dict)
        if name:
            resolved.append(name)
    dedup = list(dict.fromkeys(resolved))
    if (not dedup or all(x.lower() == "any" for x in dedup)) and default_any:
        return ["Any"]
    return dedup


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


DEFAULT_RULE_ACTION_BY_TYPE: dict[str, str] = {
    "access": "Drop",
    "https": "Inspect",
    "threat": "Optimized",
}


def resolve_desired_rule_action(spec: Mapping[str, Any], rulebase_type: str = "access") -> str:
    """Resolve the desired Check Point rule action, defaulting fail-closed per `rulebase_type`."""
    raw_act = spec.get("rule_action")
    if raw_act is None and "action" in spec:
        cand = spec["action"]
        if isinstance(cand, str) and cand.lower() not in ("present", "absent", "add", "set", "update", "delete"):
            raw_act = cand
    default_act = DEFAULT_RULE_ACTION_BY_TYPE.get(rulebase_type, "Drop")
    return str(raw_act or default_act).strip()


def encode_track_for_rulebase(value: Any, rulebase_type: str) -> Any:
    """Encode `track` into Check Point's per-rulebase wire representation."""
    if rulebase_type == "access":
        if isinstance(value, str):
            return {"type": value.strip()}
        if isinstance(value, Mapping):
            return dict(value)
        return {"type": str(value).strip()}
    if isinstance(value, Mapping):
        return str(value.get("type") or "").strip()
    return str(value).strip()


def normalize_track_dict(
    value: Any,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize an `access` `track` value (str or TrackSettingsForRequest dict) for equality comparison."""
    if value is None:
        return {}
    if isinstance(value, str):
        raw_t = value.strip()
        if obj_dict and raw_t in obj_dict:
            raw_t = str(obj_dict[raw_t].get("name") or raw_t).strip()
        return {"type": raw_t.lower()} if raw_t else {}
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if v is None:
                continue
            if k == "type":
                t_val = str(v.get("name") or v.get("uid") or "").strip() if isinstance(v, Mapping) else str(v).strip()
                if obj_dict and t_val in obj_dict:
                    t_val = str(obj_dict[t_val].get("name") or t_val).strip()
                if t_val:
                    out["type"] = t_val.lower()
            else:
                out[str(k)] = v
        return out
    return {"type": str(value).strip().lower()}


def desired_access_traffic_tuple(
    spec: Mapping[str, Any],
    name_resolutions: Mapping[str, str] | None = None,
    *,
    rulebase_type: str = "access",
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
    """Compute canonical `(source, destination, service, action)` tuple for a desired access/HTTPS/threat rule."""
    src = normalize_traffic_list(spec.get("source"), name_resolutions=name_resolutions)
    dst = normalize_traffic_list(spec.get("destination"), name_resolutions=name_resolutions)
    svc = normalize_traffic_list(spec.get("service"), name_resolutions=name_resolutions)
    act = resolve_desired_rule_action(spec, rulebase_type=rulebase_type).capitalize()
    return (src, dst, svc, act)


def existing_access_traffic_tuple(
    rule: AccessRuleEntry | HttpsRuleEntry | ThreatRuleEntry,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
    """Compute canonical `(source, destination, service, action)` tuple for an existing access/HTTPS/threat rule."""
    raw = rule.raw_data or {}
    eff_obj_dict = build_effective_obj_dict(raw, obj_dict)
    src = normalize_traffic_list(rule.source or raw.get("source"), obj_dict=eff_obj_dict)
    dst = normalize_traffic_list(rule.destination or raw.get("destination"), obj_dict=eff_obj_dict)
    svc = normalize_traffic_list(rule.service or raw.get("service"), obj_dict=eff_obj_dict)
    if isinstance(rule, HttpsRuleEntry):
        default_act = "Inspect"
    elif isinstance(rule, ThreatRuleEntry):
        default_act = "Optimized"
    else:
        default_act = "Drop"
    act = str(rule.action or default_act).strip().capitalize()
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
    eff_obj_dict = build_effective_obj_dict(raw, obj_dict)
    orig_src = normalize_nat_traffic_ref(
        rule.original_source if rule.original_source is not None else raw.get("original-source"),
        is_translated=False,
        obj_dict=eff_obj_dict,
    )
    orig_dst = normalize_nat_traffic_ref(
        rule.original_destination if rule.original_destination is not None else raw.get("original-destination"),
        is_translated=False,
        obj_dict=eff_obj_dict,
    )
    orig_svc = normalize_nat_traffic_ref(
        rule.original_service if rule.original_service is not None else raw.get("original-service"),
        is_translated=False,
        obj_dict=eff_obj_dict,
    )
    trans_src = normalize_nat_traffic_ref(
        rule.translated_source if rule.translated_source is not None else raw.get("translated-source"),
        is_translated=True,
        obj_dict=eff_obj_dict,
    )
    trans_dst = normalize_nat_traffic_ref(
        rule.translated_destination if rule.translated_destination is not None else raw.get("translated-destination"),
        is_translated=True,
        obj_dict=eff_obj_dict,
    )
    trans_svc = normalize_nat_traffic_ref(
        rule.translated_service if rule.translated_service is not None else raw.get("translated-service"),
        is_translated=True,
        obj_dict=eff_obj_dict,
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
    strict_name: bool = False,
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

    if req_name and strict_name:
        return None

    # Incremental list-delta payloads cannot match by full traffic tuple
    if rule_spec_has_delta_mapping(spec):
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
        des_acc = desired_access_traffic_tuple(
            spec,
            name_resolutions=name_resolutions,
            rulebase_type=rulebase_type,
        )
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
    "RULE_DELTA_CELL_KEYS",
    "RuleEntryUnion",
    "build_effective_obj_dict",
    "deref_rule_list",
    "desired_access_traffic_tuple",
    "desired_nat_traffic_tuple",
    "existing_access_traffic_tuple",
    "existing_nat_traffic_tuple",
    "match_rule",
    "normalize_any_sentinel",
    "normalize_nat_original_sentinel",
    "normalize_nat_traffic_ref",
    "normalize_traffic_list",
    "rule_spec_has_delta_mapping",
]
