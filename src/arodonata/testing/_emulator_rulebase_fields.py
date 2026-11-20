"""Rule cell reference resolution, normalization, and response formatting for rulebase CRUD."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_lookup import as_list, find_effective_object, ref_uid
from ._emulator_models import (
    ACTION_NAME_TO_UID,
    ACTION_UID_TO_NAME,
    ANY_UID,
    BUILTIN_SENTINELS,
    LOG_TRACK_UID,
    ORIGINAL_UID,
    SENTINEL_NAME_TO_UID,
    TRACK_NAME_TO_UID,
    TRACK_UID_TO_NAME,
    cp_error,
    format_domain_meta,
)
from ._emulator_projection import (
    RULE_KIND_CONFIGS,
    build_objects_dictionary,
    inline_rule_objects,
)


def resolve_rule_cell_ref(
    ref: Any,
    *,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, str | None]:
    """Resolve a rule object reference (`uid`, `name`, or dict) to a UID or `(None, error_ref)`."""
    if ref is None:
        return ANY_UID, None
    lookup = ref_uid(ref) if isinstance(ref, Mapping) else str(ref).strip()
    if not lookup:
        return ANY_UID, None
    if lookup in BUILTIN_SENTINELS:
        return lookup, None
    lowered = lookup.lower()
    if lowered in SENTINEL_NAME_TO_UID:
        return SENTINEL_NAME_TO_UID[lowered], None

    found = find_effective_object(
        dom_files,
        global_files,
        dom_name,
        lookup,
        allow_sentinels=True,
        include_extras=True,
    )
    if found is not None:
        return str(found[0]["uid"]), None
    if lookup in existing_dict_map:
        return lookup, None
    for uid, entry in existing_dict_map.items():
        if entry.get("name") == lookup:
            return uid, None
    return None, lookup


def apply_cell_list_update(
    current_uids: list[str],
    spec_val: Any,
    *,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
    revert_empty_to_any: bool = True,
    allow_literal_strings: bool = False,
) -> tuple[list[str], ApiCallResult | None]:
    """Apply full list replacement or `{add, remove}` patch to a rule cell UID list."""
    if isinstance(spec_val, Mapping) and ("add" in spec_val or "remove" in spec_val):
        rem_uids: set[str] = set()
        rem_names: set[str] = set()
        for rem in as_list(spec_val.get("remove")):
            r_uid, _ = resolve_rule_cell_ref(
                rem,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                existing_dict_map=existing_dict_map,
            )
            raw_ref = ref_uid(rem)
            if r_uid:
                rem_uids.add(r_uid)
            if raw_ref:
                rem_names.add(raw_ref)
        kept = [u for u in current_uids if u not in rem_uids and u not in rem_names]
        for add_item in as_list(spec_val.get("add")):
            a_uid, missing = resolve_rule_cell_ref(
                add_item,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                existing_dict_map=existing_dict_map,
            )
            if a_uid is None:
                if allow_literal_strings and missing:
                    a_uid = missing
                else:
                    return current_uids, cp_error(
                        "generic_err_object_not_found",
                        f"Referenced object [{missing}] not found in {dom_name}",
                        status_code=404,
                    )
            if a_uid != ANY_UID and kept == [ANY_UID]:
                kept = []
            if a_uid not in kept:
                kept.append(a_uid)
        if not kept and revert_empty_to_any:
            kept = [ANY_UID]
        return kept, None

    replaced: list[str] = []
    for elem in as_list(spec_val):
        r_uid, missing = resolve_rule_cell_ref(
            elem,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            existing_dict_map=existing_dict_map,
        )
        if r_uid is None:
            if allow_literal_strings and missing:
                r_uid = missing
            else:
                return current_uids, cp_error(
                    "generic_err_object_not_found",
                    f"Referenced object [{missing}] not found in {dom_name}",
                    status_code=404,
                )
        if r_uid not in replaced:
            replaced.append(r_uid)
    if not replaced and revert_empty_to_any:
        replaced = [ANY_UID]
    return replaced, None


def normalize_action(val: Any, *, rule_kind: str = "access") -> str | ApiCallResult:
    """Normalize a rule `action` UID or display name for the given rulebase kind."""
    default_by_kind = {"access": "Drop", "https": "Inspect", "threat": "Optimized"}
    default_action = default_by_kind.get(rule_kind, "Drop")
    if isinstance(val, Mapping):
        lookup = str(val.get("uid") or val.get("name") or default_action).strip()
    else:
        lookup = str(val if val is not None else default_action).strip() or default_action

    if rule_kind == "access":
        if lookup in ACTION_UID_TO_NAME:
            return lookup
        lowered = lookup.lower()
        if lowered in ACTION_NAME_TO_UID:
            return ACTION_NAME_TO_UID[lowered]
        return cp_error("err_validation_failed", f"Invalid rule action [{lookup}]", status_code=400)

    if rule_kind == "https":
        https_canonical = {"inspect": "Inspect", "bypass": "Bypass", "hold": "Hold", "ask": "Ask"}
        return https_canonical.get(lookup.lower(), lookup)

    if rule_kind == "threat":
        threat_canonical = {
            "optimized": "Optimized",
            "basic": "Basic",
            "strict": "Strict",
            "detect": "Detect",
            "prevent": "Prevent",
            "inactive": "Inactive",
        }
        return threat_canonical.get(lookup.lower(), lookup)

    return lookup


def normalize_track(val: Any) -> dict[str, Any]:
    """Normalize a rule `track` field into `{"type": <track_uid>}`."""
    if isinstance(val, Mapping):
        raw_t = ref_uid(val.get("type") or val.get("name") or LOG_TRACK_UID)
    else:
        raw_t = str(val or LOG_TRACK_UID).strip()
    lowered = raw_t.lower()
    t_uid = TRACK_NAME_TO_UID.get(lowered, raw_t if raw_t in TRACK_UID_TO_NAME else LOG_TRACK_UID)
    return {"type": t_uid}


def normalize_inline_layer(
    val: Any,
    *,
    rule_kind: str,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, ApiCallResult | None]:
    """Resolve an `inline-layer` UID or layer name within domain/Global layer stores."""
    if val is None:
        return None, None
    lookup = str(val.get("uid") or val.get("name") or "").strip() if isinstance(val, Mapping) else str(val).strip()
    if not lookup:
        return None, None

    cfg = RULE_KIND_CONFIGS.get(rule_kind, RULE_KIND_CONFIGS["access"])
    scopes: tuple[Mapping[str, Any], ...] = (dom_files, global_files) if dom_name != "Global" else (dom_files,)
    for scope_files in scopes:
        layers = scope_files.get(cfg["layer_store"], {}).get(cfg["layer_key"], [])
        if isinstance(layers, list):
            for lyr in layers:
                if isinstance(lyr, Mapping) and (lyr.get("uid") == lookup or lyr.get("name") == lookup):
                    return str(lyr.get("uid") or lookup), None
        rb_store = scope_files.get(cfg["store_key"], {})
        if isinstance(rb_store, Mapping):
            direct = rb_store.get(lookup)
            if isinstance(direct, Mapping):
                return str(direct.get("uid") or lookup), None
            for cand in rb_store.values():
                if isinstance(cand, Mapping) and (cand.get("uid") == lookup or cand.get("name") == lookup):
                    return str(cand.get("uid") or lookup), None

    if lookup in existing_dict_map:
        return lookup, None
    for uid, entry in existing_dict_map.items():
        if entry.get("name") == lookup:
            return uid, None

    return None, cp_error(
        "generic_err_object_not_found",
        f"Requested inline layer [{lookup}] not found in {dom_name}",
        status_code=404,
    )


def format_rule_response(
    rule: Mapping[str, Any],
    *,
    layer_payload: Mapping[str, Any],
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    rule_kind: str = "access",
) -> dict[str, Any]:
    """Return a single Check Point rule response with resolved object summary dicts."""
    dict_list = build_objects_dictionary(
        dom_files,
        global_files,
        dom_name,
        [copy.deepcopy(dict(rule))],
        existing_dict=layer_payload.get("objects-dictionary", []),
    )
    obj_map = {str(entry["uid"]): entry for entry in dict_list if isinstance(entry, dict) and entry.get("uid")}
    inlined = inline_rule_objects(copy.deepcopy(dict(rule)), obj_map)
    inlined.setdefault("domain", format_domain_meta(dom_name))
    if rule_kind == "nat":
        inlined.setdefault("package", layer_payload.get("package") or layer_payload.get("name") or "")
    else:
        layer_type = RULE_KIND_CONFIGS.get(rule_kind, RULE_KIND_CONFIGS["access"])["layer_type"]
        inlined.setdefault(
            "layer",
            {
                "uid": layer_payload.get("uid", ""),
                "name": layer_payload.get("name", ""),
                "type": layer_type,
            },
        )
    return inlined


def normalize_nat_scalar_field(
    val: Any,
    *,
    is_translated: bool,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, ApiCallResult | None]:
    """Resolve a scalar NAT cell reference (`Original`, `Any`, object UID, or object name)."""
    if val is None or (isinstance(val, str) and not val.strip()):
        return (ORIGINAL_UID if is_translated else ANY_UID), None
    lookup = ref_uid(val) if isinstance(val, Mapping) else str(val).strip()
    if lookup.lower() == "original":
        return ORIGINAL_UID, None
    if lookup.lower() == "any":
        return ANY_UID, None
    r_uid, missing = resolve_rule_cell_ref(
        val,
        dom_files=dom_files,
        global_files=global_files,
        dom_name=dom_name,
        existing_dict_map=existing_dict_map,
    )
    if r_uid is None:
        return None, cp_error(
            "generic_err_object_not_found",
            f"Referenced object [{missing}] not found in {dom_name}",
            status_code=404,
        )
    return r_uid, None


def detect_rule_kind(command: str) -> str | None:
    """Return the rulebase kind (`access`, `nat`, `https`, `threat`) for a rule/section command."""
    for kind in ("access", "nat", "https", "threat"):
        if command.endswith(f"-{kind}-rule") or command.endswith(f"-{kind}-section"):
            return kind
    return None
