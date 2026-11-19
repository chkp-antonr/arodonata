"""Canonical Check Point built-in sentinel object UIDs, token sets, and normalizers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Check Point built-in sentinel and rulebase object UIDs
NAT_ANY_OBJECT_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
NAT_ORIGINAL_OBJECT_UID = "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"

ANY_UID = NAT_ANY_OBJECT_UID
ORIGINAL_UID = NAT_ORIGINAL_OBJECT_UID
POLICY_TARGETS_UID = "6c488338-8eec-4103-ad21-cd461ac2c476"

ACCEPT_UID = "6c488338-8eec-4103-ad21-cd461ac2c472"
DROP_UID = "6c488338-8eec-4103-ad21-cd461ac2c473"
REJECT_UID = "6c488338-8eec-4103-ad21-cd461ac2c474"
APPLY_LAYER_UID = "6c488338-8eec-4103-ad21-cd461ac2c475"

LOG_TRACK_UID = "598ead32-aa42-4615-90ed-f51a5928d41d"
NONE_TRACK_UID = "29e53e3d-23bf-48fe-b6b1-d59bd88036f1"
NONE_TRACK_UID_ALT = "29e53e3d-23bf-48fe-b6b1-d59bd88036f9"

ANY_SENTINEL_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "any",
        NAT_ANY_OBJECT_UID.lower(),
    }
)

ORIGINAL_SENTINEL_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "original",
        NAT_ORIGINAL_OBJECT_UID.lower(),
    }
)

ANY_RULE_TOKENS: frozenset[str] = frozenset(
    {
        "any",
        "cpmianyobject",
        NAT_ANY_OBJECT_UID.lower(),
        "0.0.0.0/0",
    }
)

ORIGINAL_NAT_TOKENS: frozenset[str] = frozenset(
    {
        "original",
        NAT_ORIGINAL_OBJECT_UID.lower(),
    }
)

POLICY_TARGETS_TOKENS: frozenset[str] = frozenset(
    {
        "policy targets",
        "policy-targets",
        "policy_targets",
        "all",
        "*",
        POLICY_TARGETS_UID.lower(),
    }
)

BUILTIN_SENTINELS: dict[str, dict[str, Any]] = {
    ANY_UID: {"uid": ANY_UID, "name": "Any", "type": "CpmiAnyObject"},
    ORIGINAL_UID: {"uid": ORIGINAL_UID, "name": "Original", "type": "CpmiAnyObject"},
    POLICY_TARGETS_UID: {"uid": POLICY_TARGETS_UID, "name": "Policy Targets", "type": "Global"},
    ACCEPT_UID: {"uid": ACCEPT_UID, "name": "Accept", "type": "RulebaseAction"},
    DROP_UID: {"uid": DROP_UID, "name": "Drop", "type": "RulebaseAction"},
    REJECT_UID: {"uid": REJECT_UID, "name": "Reject", "type": "RulebaseAction"},
    APPLY_LAYER_UID: {"uid": APPLY_LAYER_UID, "name": "Apply Layer", "type": "RulebaseAction"},
    LOG_TRACK_UID: {"uid": LOG_TRACK_UID, "name": "Log", "type": "Track"},
    NONE_TRACK_UID: {"uid": NONE_TRACK_UID, "name": "None", "type": "Track"},
    NONE_TRACK_UID_ALT: {"uid": NONE_TRACK_UID_ALT, "name": "None", "type": "Track"},
}

SENTINEL_NAME_TO_UID: dict[str, str] = {
    "any": ANY_UID,
    "original": ORIGINAL_UID,
    "policy targets": POLICY_TARGETS_UID,
}

ACTION_NAME_TO_UID: dict[str, str] = {
    "accept": ACCEPT_UID,
    "drop": DROP_UID,
    "reject": REJECT_UID,
    "apply layer": APPLY_LAYER_UID,
    "inner layer": APPLY_LAYER_UID,
}

ACTION_UID_TO_NAME: dict[str, str] = {
    ACCEPT_UID: "Accept",
    DROP_UID: "Drop",
    REJECT_UID: "Reject",
    APPLY_LAYER_UID: "Apply Layer",
}

TRACK_NAME_TO_UID: dict[str, str] = {
    "log": LOG_TRACK_UID,
    "none": NONE_TRACK_UID,
}

TRACK_UID_TO_NAME: dict[str, str] = {
    LOG_TRACK_UID: "Log",
    NONE_TRACK_UID: "None",
    NONE_TRACK_UID_ALT: "None",
}


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
        if clean.lower() in ORIGINAL_SENTINEL_TOKENS:
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
        if clean.lower() in ANY_SENTINEL_TOKENS:
            return "Any"
        if clean.lower() in ORIGINAL_SENTINEL_TOKENS:
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


__all__ = [
    "ACCEPT_UID",
    "ACTION_NAME_TO_UID",
    "ACTION_UID_TO_NAME",
    "ANY_RULE_TOKENS",
    "ANY_SENTINEL_TOKENS",
    "ANY_UID",
    "APPLY_LAYER_UID",
    "BUILTIN_SENTINELS",
    "DROP_UID",
    "LOG_TRACK_UID",
    "NAT_ANY_OBJECT_UID",
    "NAT_ORIGINAL_OBJECT_UID",
    "NONE_TRACK_UID",
    "NONE_TRACK_UID_ALT",
    "ORIGINAL_NAT_TOKENS",
    "ORIGINAL_SENTINEL_TOKENS",
    "ORIGINAL_UID",
    "POLICY_TARGETS_TOKENS",
    "POLICY_TARGETS_UID",
    "REJECT_UID",
    "SENTINEL_NAME_TO_UID",
    "TRACK_NAME_TO_UID",
    "TRACK_UID_TO_NAME",
    "normalize_any_sentinel",
    "normalize_nat_original_sentinel",
]
