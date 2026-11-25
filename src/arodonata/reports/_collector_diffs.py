"""Field-diff synthesis, UID harvesting, and object summary builders (`arodonata.reports._collector_diffs`)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.primitives import is_uuid
from arodonata.reports._object_summary import build_object_summary_fields, format_plain_object_summary
from arodonata.reports.models import ChangeOperation, FieldDiff

RULE_OBJECT_TYPES: frozenset[str] = frozenset(
    {
        "access-rule",
        "nat-rule",
        "https-rule",
        "threat-rule",
        "place-holder",
    }
)

RULE_LIST_REF_FIELDS: tuple[str, ...] = (
    "source",
    "destination",
    "service",
    "install-on",
    "protected-scope",
    "vpn",
    "content",
    "time",
    "blade",
    "site-category",
)

RULE_SCALAR_FIELDS: tuple[str, ...] = (
    "enabled",
    "name",
    "action",
    "method",
    "track",
    "comments",
    "source-negate",
    "destination-negate",
    "service-negate",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)

OBJECT_LIST_REF_FIELDS: tuple[str, ...] = (
    "members",
    "groups",
    "tags",
    "url-list",
)

OBJECT_SCALAR_FIELDS: tuple[str, ...] = (
    "name",
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "subnet6",
    "mask-length4",
    "mask-length6",
    "subnet-mask",
    "ipv4-address-first",
    "ipv4-address-last",
    "ipv6-address-first",
    "ipv6-address-last",
    "port",
    "protocol",
    "ip-protocol",
    "icmp-type",
    "icmp-code",
    "fqdn",
    "primary-category",
    "urls-defined-as-regular-expression",
    "description",
    "comments",
    "color",
)

SYSTEM_INTERNAL_OBJECT_TYPES: frozenset[str] = frozenset(
    {
        "ipsprotectionusersettings",
        "cp-trusted-ca-certificate",
        "trustedcapackageconf",
    }
)


def is_bare_uid(value: Any) -> bool:
    """Return `True` if `value` is a bare UUID string (`8-4-4-4-12` hex)."""
    return is_uuid(value)


def _rulebase_type_from_obj_type(obj_type: str) -> RulebaseType:
    low = obj_type.strip().lower()
    if "nat" in low:
        return "nat"
    if "https" in low:
        return "https"
    if "threat" in low:
        return "threat"
    return "access"


def _extract_ref_str_or_uid(val: Any, known_names: dict[str, str], bare_uids_out: set[str]) -> str | None:
    if val is None:
        return None
    if isinstance(val, dict):
        name = val.get("name")
        uid = val.get("uid")
        if isinstance(uid, str) and uid and isinstance(name, str) and name:
            known_names[uid] = name
            return name
        if isinstance(name, str) and name:
            return name
        if isinstance(uid, str) and uid:
            if uid in known_names:
                return known_names[uid]
            if is_bare_uid(uid):
                bare_uids_out.add(uid)
            return uid
        return None
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        if s in known_names:
            return known_names[s]
        if is_bare_uid(s):
            bare_uids_out.add(s)
        return s
    return str(val)


def _extract_ref_list(val: Any, known_names: dict[str, str], bare_uids_out: set[str]) -> list[str]:
    if val is None:
        return []
    if not isinstance(val, list):
        single = _extract_ref_str_or_uid(val, known_names, bare_uids_out)
        return [single] if single else []
    res: list[str] = []
    for item in val:
        extracted = _extract_ref_str_or_uid(item, known_names, bare_uids_out)
        if extracted:
            res.append(extracted)
    return res


def _parse_field_diff_entry(
    field_name: str,
    fc: Mapping[str, Any],
    known_names: dict[str, str],
    bare_uids_out: set[str],
) -> FieldDiff:
    old_v = fc.get("old-value", fc.get("old_value", fc.get("before")))
    new_v = fc.get("new-value", fc.get("new_value", fc.get("after")))
    added_raw = fc.get("added") or fc.get("added-items") or fc.get("added_items") or []
    removed_raw = fc.get("removed") or fc.get("removed-items") or fc.get("removed_items") or []
    added_list = _extract_ref_list(added_raw, known_names, bare_uids_out)
    removed_list = _extract_ref_list(removed_raw, known_names, bare_uids_out)
    if isinstance(old_v, (str, dict)):
        old_v = _extract_ref_str_or_uid(old_v, known_names, bare_uids_out)
    elif isinstance(old_v, list):
        old_v = _extract_ref_list(old_v, known_names, bare_uids_out)
    if isinstance(new_v, (str, dict)):
        new_v = _extract_ref_str_or_uid(new_v, known_names, bare_uids_out)
    elif isinstance(new_v, list):
        new_v = _extract_ref_list(new_v, known_names, bare_uids_out)
    return FieldDiff(
        field_name=field_name,
        old_value=old_v,
        new_value=new_v,
        added_items=added_list,
        removed_items=removed_list,
    )


def _extract_field_diffs(
    raw_item: dict[str, Any],
    known_names: dict[str, str],
    bare_uids_out: set[str],
) -> list[FieldDiff]:
    """Extract `FieldDiff` entries from Check Point `field-changes` / `changes` / `diff` dicts."""
    diffs: list[FieldDiff] = []
    raw_fc = (
        raw_item.get("field-changes") or raw_item.get("field_changes") or raw_item.get("fields") or raw_item.get("diff")
    )
    if isinstance(raw_fc, list):
        for fc in raw_fc:
            if not isinstance(fc, dict):
                continue
            f_name = str(fc.get("field-name") or fc.get("field") or fc.get("name") or "field")
            diffs.append(_parse_field_diff_entry(f_name, fc, known_names, bare_uids_out))
    elif isinstance(raw_fc, dict):
        for f_name, fc in raw_fc.items():
            if isinstance(fc, dict):
                diffs.append(_parse_field_diff_entry(str(f_name), fc, known_names, bare_uids_out))
    return diffs


def _harvest_uid_names_recursive(
    node: Any,
    known_names: dict[str, str],
    *,
    depth: int = 0,
    max_depth: int = 6,
) -> None:
    """Recursively index `{uid, name}` dictionaries up to `max_depth`."""
    if depth > max_depth:
        return
    if isinstance(node, dict):
        uid = node.get("uid")
        name = node.get("name")
        if isinstance(uid, str) and uid and isinstance(name, str) and name:
            known_names[uid] = name
        for val in node.values():
            if isinstance(val, (dict, list)):
                _harvest_uid_names_recursive(val, known_names, depth=depth + 1, max_depth=max_depth)
    elif isinstance(node, list):
        for elem in node:
            if isinstance(elem, (dict, list)):
                _harvest_uid_names_recursive(elem, known_names, depth=depth + 1, max_depth=max_depth)


def _collect_known_names_from_operations(ops_list: list[dict[str, Any]], known_names: dict[str, str]) -> None:
    """First pass over session change entries to index all `(uid -> name)` pairs already present."""
    for ops in ops_list:
        for bucket_key in (
            "added-objects",
            "modified-objects",
            "deleted-objects",
            "added_objects",
            "modified_objects",
            "deleted_objects",
            "added-rules",
            "modified-rules",
            "deleted-rules",
        ):
            items = ops.get(bucket_key)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    _harvest_uid_names_recursive(item, known_names)


def _extract_track_str(
    track_val: Any,
    known_names: dict[str, str],
    bare_uids_out: set[str],
) -> str | None:
    if isinstance(track_val, dict):
        return _extract_ref_str_or_uid(
            track_val.get("type") or track_val,
            known_names,
            bare_uids_out,
        )
    return _extract_ref_str_or_uid(track_val, known_names, bare_uids_out)


def _list_field_diff(field_name: str, old_refs: list[str], new_refs: list[str]) -> FieldDiff | None:
    """Return a `FieldDiff` with deduplicated `added_items` and `removed_items` if `old_refs != new_refs`."""
    if old_refs == new_refs:
        return None
    old_set = set(old_refs)
    new_set = set(new_refs)
    removed_items = list(dict.fromkeys(x for x in old_refs if x not in new_set))
    added_items = list(dict.fromkeys(x for x in new_refs if x not in old_set))
    if not removed_items and not added_items:
        return None
    return FieldDiff(
        field_name=field_name,
        old_value=old_refs,
        new_value=new_refs,
        added_items=added_items,
        removed_items=removed_items,
    )


def _synthesize_rule_snapshot_diffs(
    old_core: dict[str, Any],
    core: dict[str, Any],
    existing_diff_fields: set[str],
    known_names: dict[str, str],
    bare_uids_out: set[str],
) -> list[FieldDiff]:
    """Synthesize `FieldDiff` entries for a modified rule from `old-object` and `new-object` snapshots."""
    synth: list[FieldDiff] = []
    for field in RULE_LIST_REF_FIELDS:
        if field.lower() in existing_diff_fields or (field not in old_core and field not in core):
            continue
        old_refs = _extract_ref_list(old_core.get(field), known_names, bare_uids_out)
        new_refs = _extract_ref_list(core.get(field), known_names, bare_uids_out)
        ldiff = _list_field_diff(field, old_refs, new_refs)
        if ldiff is not None:
            synth.append(ldiff)

    for field in RULE_SCALAR_FIELDS:
        if field.lower() in existing_diff_fields or (field not in old_core and field not in core):
            continue
        if field == "enabled":
            old_v: Any = bool(old_core.get("enabled", True))
            new_v: Any = bool(core.get("enabled", True))
        elif field in ("source-negate", "destination-negate", "service-negate"):
            old_v = bool(old_core.get(field, False))
            new_v = bool(core.get(field, False))
        elif field == "comments":
            old_v = str(old_core.get("comments") or "")
            new_v = str(core.get("comments") or "")
        elif field == "track":
            old_v = _extract_track_str(old_core.get("track"), known_names, bare_uids_out)
            new_v = _extract_track_str(core.get("track"), known_names, bare_uids_out)
        else:
            old_v = _extract_ref_str_or_uid(old_core.get(field), known_names, bare_uids_out)
            new_v = _extract_ref_str_or_uid(core.get(field), known_names, bare_uids_out)
        if old_v != new_v:
            synth.append(FieldDiff(field_name=field, old_value=old_v, new_value=new_v))

    return synth


def _synthesize_object_snapshot_diffs(
    old_core: dict[str, Any],
    core: dict[str, Any],
    existing_diff_fields: set[str],
    known_names: dict[str, str],
    bare_uids_out: set[str],
) -> list[FieldDiff]:
    """Synthesize `FieldDiff` entries for a modified non-rule object from `old-object` and `new-object` snapshots."""
    synth: list[FieldDiff] = []
    for field in OBJECT_LIST_REF_FIELDS:
        if field.lower() in existing_diff_fields or (field not in old_core and field not in core):
            continue
        old_refs = _extract_ref_list(old_core.get(field), known_names, bare_uids_out)
        new_refs = _extract_ref_list(core.get(field), known_names, bare_uids_out)
        ldiff = _list_field_diff(field, old_refs, new_refs)
        if ldiff is not None:
            synth.append(ldiff)

    for field in OBJECT_SCALAR_FIELDS:
        if field.lower() in existing_diff_fields or (field not in old_core and field not in core):
            continue
        if field == "comments":
            old_v: Any = str(old_core.get("comments") or "")
            new_v: Any = str(core.get("comments") or "")
        else:
            old_raw = old_core.get(field)
            new_raw = core.get(field)
            old_v = (
                _extract_ref_str_or_uid(old_raw, known_names, bare_uids_out)
                if isinstance(old_raw, (str, dict))
                else old_raw
            )
            new_v = (
                _extract_ref_str_or_uid(new_raw, known_names, bare_uids_out)
                if isinstance(new_raw, (str, dict))
                else new_raw
            )
        if old_v != new_v:
            synth.append(FieldDiff(field_name=field, old_value=old_v, new_value=new_v))

    return synth


def _get_last_modifier(*dicts: dict[str, Any]) -> str:
    for d in dicts:
        meta = d.get("meta-info") or d.get("meta_info")
        if isinstance(meta, dict):
            mod = meta.get("last-modifier") or meta.get("last_modifier")
            if isinstance(mod, str) and mod.strip():
                return mod.strip()
    return ""


def _is_system_maintenance_object(
    raw: dict[str, Any],
    core: dict[str, Any],
    old_core: dict[str, Any],
    *,
    op: ChangeOperation,
    session_user_name: str = "",
) -> bool:
    """Return `True` if a non-rule change entry is a background Check Point `'System'` maintenance object.

    Never filters deletions (`op == "deleted"`), and inspects only post-change metadata (`core`, `raw`)
    so user deletions or modifications of objects originally created by `'System'` are never hidden.
    """
    if op == "deleted":
        return False
    raw_name = str(core.get("name") or raw.get("name") or old_core.get("name") or "").strip()
    raw_type = str(core.get("type") or raw.get("type") or old_core.get("type") or "").strip()
    last_mod = _get_last_modifier(core, raw)
    norm_user = session_user_name.strip().lower()
    if last_mod.lower() == "system":
        if norm_user and norm_user != "system":
            return True
        if not raw_name or not raw_type or raw_type.lower() in SYSTEM_INTERNAL_OBJECT_TYPES:
            return True
    return bool(raw_type.lower() in SYSTEM_INTERNAL_OBJECT_TYPES and last_mod.lower() in ("", "system"))


def _build_object_summary_fields(core: dict[str, Any], members: list[str]) -> dict[str, Any]:
    """Extract structured summary attributes for a non-rule policy object."""
    return build_object_summary_fields(core, members=members)


def _format_object_summary_from_fields(fields: dict[str, Any]) -> str:
    """Format `summary_fields` into a human-readable summary string."""
    return format_plain_object_summary(fields)


def _build_object_summary(core: dict[str, Any], members: list[str]) -> str:
    """Build a human-readable summary string for a non-rule policy object."""
    return format_plain_object_summary(build_object_summary_fields(core, members=members))
