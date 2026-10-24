"""Cleanup-rule-aware rule positioning helper (`src/arodonata/cpcrud/position_helper.py`).

Resolves rule `position` values (`"top"`, `"bottom"`, `{"bottom": "<section>"}`, `{"above": ...}`,
`{"below": ...}`) against a layer or package rulebase, automatically anchoring `"bottom"` placements
at `{"above": "<cleanup_rule_uid>"}` when the last rule in the layer or target section is an
`Any / Any / Any` cleanup rule.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseSectionEntry,
    ThreatRuleEntry,
)
from arodonata.cpcrud.rule_identity import (
    RuleEntryUnion,
    normalize_any_sentinel,
    normalize_traffic_list,
)


def is_cleanup_rule(
    rule: RuleEntryUnion,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> bool:
    """Return `True` if `rule` is an `Any / Any / Any` cleanup rule."""
    name_low = (rule.name or "").strip().lower()
    if "cleanup" in name_low:
        # Verify traffic is Any / Any / Any if traffic fields are present
        if isinstance(rule, (AccessRuleEntry, HttpsRuleEntry, ThreatRuleEntry)):
            raw = rule.raw_data or {}
            src = normalize_traffic_list(rule.source or raw.get("source"), obj_dict=obj_dict)
            dst = normalize_traffic_list(rule.destination or raw.get("destination"), obj_dict=obj_dict)
            svc = normalize_traffic_list(rule.service or raw.get("service"), obj_dict=obj_dict)
            if src == ("Any",) and dst == ("Any",) and svc == ("Any",):
                return True
        elif isinstance(rule, NatRuleEntry):
            raw = rule.raw_data or {}
            o_src = normalize_any_sentinel(rule.original_source or raw.get("original-source"), obj_dict)
            o_dst = normalize_any_sentinel(rule.original_destination or raw.get("original-destination"), obj_dict)
            o_svc = normalize_any_sentinel(rule.original_service or raw.get("original-service"), obj_dict)
            if o_src == "Any" and o_dst == "Any" and o_svc == "Any":
                return True
        return True

    # Even without "Cleanup" in the rule name, a trailing Any / Any / Any Drop/Accept rule at the end of a layer
    if isinstance(rule, (AccessRuleEntry, HttpsRuleEntry, ThreatRuleEntry)):
        raw = rule.raw_data or {}
        src = normalize_traffic_list(rule.source or raw.get("source"), obj_dict=obj_dict)
        dst = normalize_traffic_list(rule.destination or raw.get("destination"), obj_dict=obj_dict)
        svc = normalize_traffic_list(rule.service or raw.get("service"), obj_dict=obj_dict)
        if src == ("Any",) and dst == ("Any",) and svc == ("Any",):
            return True

    return False


def resolve_rule_position(
    requested_position: Any,
    rules: Sequence[RuleEntryUnion],
    sections: Sequence[RulebaseSectionEntry] = (),
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> str | int | dict[str, str]:
    """Resolve `requested_position` into the Check Point API `position` payload value.

    - When `requested_position` is `"bottom"` (or `None`, defaulting to `"bottom"`) and the last rule
      in `rules` is an `Any / Any / Any` cleanup rule, returns `{"above": "<cleanup_rule_uid>"}`.
    - When `requested_position` is `{"bottom": "<section_name_or_uid>"}` and the last rule in that
      section is a cleanup rule, returns `{"above": "<cleanup_rule_uid>"}`.
    """
    pos = "bottom" if requested_position is None else requested_position

    if isinstance(pos, int):
        return pos

    if isinstance(pos, str):
        clean = pos.strip().lower()
        if clean == "bottom":
            if rules and is_cleanup_rule(rules[-1], obj_dict=obj_dict):
                return {"above": rules[-1].uid}
            return "bottom"
        if clean == "top":
            return "top"
        if clean.isdigit():
            return int(clean)
        return pos

    if isinstance(pos, dict):
        if "bottom" in pos:
            sec_target = str(pos["bottom"]).strip()
            # Find rules belonging to this section
            sec_rules: list[RuleEntryUnion] = [
                r for r in rules if r.section_name == sec_target or r.section_uid == sec_target
            ]
            if not sec_rules and sections:
                for sec in sections:
                    if sec.name == sec_target or sec.uid == sec_target:
                        uid_set = set(sec.rule_uids)
                        sec_rules = [r for r in rules if r.uid in uid_set]
                        break
            if sec_rules and is_cleanup_rule(sec_rules[-1], obj_dict=obj_dict):
                return {"above": sec_rules[-1].uid}
            return {"bottom": sec_target}
        return {str(k): str(v) for k, v in pos.items()}

    return "bottom"


__all__ = [
    "is_cleanup_rule",
    "resolve_rule_position",
]
