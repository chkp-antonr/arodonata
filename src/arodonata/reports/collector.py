"""Read-only session change collector (`arodonata.reports.collector`).

Implements `collect_change_report`:
- Validates `SessionScope` and `RangeScope` inputs strictly (raising `ValidationError` or
  `ChangeReportInputError` on invalid bounds or naive datetimes).
- Converts timezone-aware `from_date` / `to_date` to UTC, widens server query bounds safely
  (or omits server date parameters when `from_session` is also given), and filters returned
  sessions by exact UTC publish timestamp.
- Deduplicates sessions named across multiple scopes while preserving any attached `OwnedSession`.
- Resolves up to 200 distinct bare reference UIDs per report via read-only `show-object` calls,
  emitting a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails.
- Applies SmartConsole rule placement numbering via `apply_session_rule_placement`.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import arlogi

from arodonata.core.errors import ChangeReportInputError, ServerIdentityError, redact_sid, sanitize_mapping
from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.sync_coordinator import parse_cp_publish_timestamp
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports.models import (
    ChangeOperation,
    ChangeReport,
    FieldDiff,
    ObjectChangeEntry,
    OwnedSession,
    RangeScope,
    RawResponse,
    RenderOptions,
    ReportScope,
    ReportWarning,
    RuleChangeEntry,
    SessionChangeReport,
    SessionScope,
)
from arodonata.reports.placement import apply_session_rule_placement

logger = arlogi.get_logger(__name__)

MAX_UID_LOOKUPS = 200

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

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
    "fqdn",
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
    if not isinstance(value, str):
        return False
    return bool(_UUID_RE.match(value.strip()))


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
            diffs.append(
                FieldDiff(
                    field_name=f_name,
                    old_value=old_v,
                    new_value=new_v,
                    added_items=added_list,
                    removed_items=removed_list,
                )
            )
    elif isinstance(raw_fc, dict):
        for f_name, fc in raw_fc.items():
            if isinstance(fc, dict):
                old_v = fc.get("old-value", fc.get("old_value", fc.get("before")))
                new_v = fc.get("new-value", fc.get("new_value", fc.get("after")))
                added_list = _extract_ref_list(
                    fc.get("added") or fc.get("added-items") or [],
                    known_names,
                    bare_uids_out,
                )
                removed_list = _extract_ref_list(
                    fc.get("removed") or fc.get("removed-items") or [],
                    known_names,
                    bare_uids_out,
                )
                if isinstance(old_v, (str, dict)):
                    old_v = _extract_ref_str_or_uid(old_v, known_names, bare_uids_out)
                elif isinstance(old_v, list):
                    old_v = _extract_ref_list(old_v, known_names, bare_uids_out)
                if isinstance(new_v, (str, dict)):
                    new_v = _extract_ref_str_or_uid(new_v, known_names, bare_uids_out)
                elif isinstance(new_v, list):
                    new_v = _extract_ref_list(new_v, known_names, bare_uids_out)
                diffs.append(
                    FieldDiff(
                        field_name=str(f_name),
                        old_value=old_v,
                        new_value=new_v,
                        added_items=added_list,
                        removed_items=removed_list,
                    )
                )
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
                if not isinstance(item, dict):
                    continue
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
        if field.lower() in existing_diff_fields:
            continue
        if field not in old_core and field not in core:
            continue
        old_refs = _extract_ref_list(old_core.get(field), known_names, bare_uids_out)
        new_refs = _extract_ref_list(core.get(field), known_names, bare_uids_out)
        ldiff = _list_field_diff(field, old_refs, new_refs)
        if ldiff is not None:
            synth.append(ldiff)

    for field in RULE_SCALAR_FIELDS:
        if field.lower() in existing_diff_fields:
            continue
        if field not in old_core and field not in core:
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
        if field.lower() in existing_diff_fields:
            continue
        if field not in old_core and field not in core:
            continue
        old_refs = _extract_ref_list(old_core.get(field), known_names, bare_uids_out)
        new_refs = _extract_ref_list(core.get(field), known_names, bare_uids_out)
        ldiff = _list_field_diff(field, old_refs, new_refs)
        if ldiff is not None:
            synth.append(ldiff)

    for field in OBJECT_SCALAR_FIELDS:
        if field.lower() in existing_diff_fields:
            continue
        if field not in old_core and field not in core:
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
    fields: dict[str, Any] = {}
    for key in (
        "ipv4-address",
        "ipv6-address",
        "subnet4",
        "mask-length4",
        "subnet-mask",
        "subnet6",
        "mask-length6",
        "ipv4-address-first",
        "ipv4-address-last",
        "ipv6-address-first",
        "ipv6-address-last",
        "port",
        "protocol",
        "fqdn",
    ):
        if core.get(key) is not None:
            fields[key] = core[key]
    if members:
        fields["members"] = list(members)
    comments_str = str(core.get("comments") or "").strip()
    if comments_str:
        fields["comments"] = comments_str
    return fields


def _format_object_summary_from_fields(fields: dict[str, Any]) -> str:
    """Format `summary_fields` into a human-readable summary string."""
    summary_parts: list[str] = []
    if fields.get("ipv4-address") is not None:
        summary_parts.append(f"ipv4-address={fields['ipv4-address']}")
    if fields.get("ipv6-address") is not None:
        summary_parts.append(f"ipv6-address={fields['ipv6-address']}")
    if fields.get("subnet4") is not None:
        if fields.get("mask-length4") is not None:
            summary_parts.append(f"subnet4={fields['subnet4']}/{fields['mask-length4']}")
        elif fields.get("subnet-mask") is not None:
            summary_parts.append(f"subnet4={fields['subnet4']}/{fields['subnet-mask']}")
        else:
            summary_parts.append(f"subnet4={fields['subnet4']}")
    if fields.get("subnet6") is not None:
        if fields.get("mask-length6") is not None:
            summary_parts.append(f"subnet6={fields['subnet6']}/{fields['mask-length6']}")
        else:
            summary_parts.append(f"subnet6={fields['subnet6']}")
    if fields.get("ipv4-address-first") is not None or fields.get("ipv4-address-last") is not None:
        first4 = fields.get("ipv4-address-first") or ""
        last4 = fields.get("ipv4-address-last") or ""
        summary_parts.append(f"range={first4}-{last4}")
    if fields.get("ipv6-address-first") is not None or fields.get("ipv6-address-last") is not None:
        first6 = fields.get("ipv6-address-first") or ""
        last6 = fields.get("ipv6-address-last") or ""
        summary_parts.append(f"range6={first6}-{last6}")
    for key in ("port", "protocol", "fqdn"):
        if fields.get(key) is not None:
            summary_parts.append(f"{key}={fields[key]}")
    members = fields.get("members")
    if isinstance(members, list) and members:
        summary_parts.append(f"members=[{', '.join(str(m) for m in members)}]")
    comments_str = str(fields.get("comments") or "").strip()
    if comments_str:
        summary_parts.append(f"comments={comments_str}")
    return ", ".join(summary_parts)


def _build_object_summary(core: dict[str, Any], members: list[str]) -> str:
    """Build a human-readable summary string for a non-rule policy object."""
    return _format_object_summary_from_fields(_build_object_summary_fields(core, members))


def _extract_session_user_from_changes(
    data: dict[str, Any],
    *,
    session_uid: str | None = None,
) -> str:
    """Extract `user-name` from a `show-changes` response's `changes[].session` block if present."""
    containers: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        for task in data["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("task-details"), list):
                for detail in task["task-details"]:
                    if isinstance(detail, dict) and isinstance(detail.get("changes"), list):
                        for ch in detail["changes"]:
                            if isinstance(ch, dict):
                                containers.append(ch)
    if isinstance(data.get("changes"), list):
        for ch in data["changes"]:
            if isinstance(ch, dict):
                containers.append(ch)
    for c in containers:
        sess_dict = c.get("session")
        if isinstance(sess_dict, dict):
            c_uid = str(sess_dict.get("session-uid") or sess_dict.get("uid") or "")
            if session_uid and c_uid and c_uid != session_uid:
                continue
            u_name = str(sess_dict.get("user-name") or sess_dict.get("user") or "").strip()
            if u_name:
                return u_name
    return ""


def _parse_change_containers(
    data: dict[str, Any],
    *,
    session_uid: str | None = None,
) -> list[dict[str, Any]]:
    """Extract normalized operation containers from a `show-changes` response payload."""
    containers: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        for task in data["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("task-details"), list):
                for detail in task["task-details"]:
                    if isinstance(detail, dict):
                        if isinstance(detail.get("changes"), list):
                            for ch in detail["changes"]:
                                if isinstance(ch, dict):
                                    containers.append(ch)
                        else:
                            containers.append(detail)
    if isinstance(data.get("changes"), list):
        for ch in data["changes"]:
            if isinstance(ch, dict):
                containers.append(ch)
    if isinstance(data.get("operations"), dict) or any(
        k in data
        for k in (
            "added-objects",
            "modified-objects",
            "deleted-objects",
            "added-rules",
            "modified-rules",
            "deleted-rules",
        )
    ):
        containers.append(data)

    ops_list: list[dict[str, Any]] = []
    for c in containers:
        if session_uid:
            sess_dict = c.get("session")
            if isinstance(sess_dict, dict):
                c_uid = str(sess_dict.get("session-uid") or sess_dict.get("uid") or "")
                if c_uid and c_uid != session_uid:
                    continue
        ops = c.get("operations")
        if isinstance(ops, dict):
            ops_list.append(ops)
        else:
            ops_list.append(c)
    return ops_list


def _parse_rule_and_object_changes(
    ops_list: list[dict[str, Any]],
    known_names: dict[str, str],
    bare_uids_out: set[str],
    *,
    session_user_name: str = "",
    include_system_objects: bool = False,
) -> tuple[list[RuleChangeEntry], list[ObjectChangeEntry], int]:
    """Parse `RuleChangeEntry` and `ObjectChangeEntry` models from `show-changes` operation buckets."""
    _collect_known_names_from_operations(ops_list, known_names)

    rules: list[RuleChangeEntry] = []
    objects: list[ObjectChangeEntry] = []
    filtered_system_count = 0

    bucket_specs: list[tuple[str, ChangeOperation, bool]] = [
        ("added-rules", "added", True),
        ("added_rules", "added", True),
        ("modified-rules", "modified", True),
        ("modified_rules", "modified", True),
        ("deleted-rules", "deleted", True),
        ("deleted_rules", "deleted", True),
        ("added-objects", "added", False),
        ("added_objects", "added", False),
        ("modified-objects", "modified", False),
        ("modified_objects", "modified", False),
        ("deleted-objects", "deleted", False),
        ("deleted_objects", "deleted", False),
    ]

    for ops in ops_list:
        for bucket_key, bucket_op, force_rule in bucket_specs:
            items = ops.get(bucket_key)
            if not isinstance(items, list):
                continue
            for raw in items:
                if not isinstance(raw, dict):
                    continue
                # Unwrap `new-object` / `old-object` if Check Point nested the payload
                old_core = raw.get("old-object") if isinstance(raw.get("old-object"), dict) else {}
                if isinstance(raw.get("new-object"), dict):
                    core = raw["new-object"]
                elif bucket_op == "deleted" and old_core:
                    core = old_core
                else:
                    core = raw
                assert isinstance(core, dict)
                assert isinstance(old_core, dict)
                # When an entry in `modified-objects` has `new-object` without `old-object`,
                # Check Point is reporting an object/rule created in that session.
                op: ChangeOperation = (
                    "added"
                    if (bucket_op == "modified" and isinstance(raw.get("new-object"), dict) and not old_core)
                    else bucket_op
                )

                uid = str(core.get("uid") or raw.get("uid") or old_core.get("uid") or "")
                name = str(core.get("name") or raw.get("name") or old_core.get("name") or "")
                obj_type = str(core.get("type") or raw.get("type") or old_core.get("type") or "object")

                is_rule = force_rule or obj_type.lower() in RULE_OBJECT_TYPES or obj_type.lower().endswith("-rule")
                if (
                    not is_rule
                    and not include_system_objects
                    and _is_system_maintenance_object(
                        raw,
                        core,
                        old_core,
                        op=op,
                        session_user_name=session_user_name,
                    )
                ):
                    filtered_system_count += 1
                    continue

                f_diffs = _extract_field_diffs(raw, known_names, bare_uids_out)
                existing_diff_fields = {d.field_name.strip().lower() for d in f_diffs}

                if is_rule:
                    if op == "modified" and old_core:
                        f_diffs.extend(
                            _synthesize_rule_snapshot_diffs(
                                old_core,
                                core,
                                existing_diff_fields,
                                known_names,
                                bare_uids_out,
                            )
                        )
                    rb_type = _rulebase_type_from_obj_type(obj_type)
                    layer_raw = core.get("layer") or raw.get("layer") or old_core.get("layer")
                    layer_uid = ""
                    layer_name = ""
                    if isinstance(layer_raw, dict):
                        layer_uid = str(layer_raw.get("uid") or "")
                        layer_name = str(layer_raw.get("name") or "")
                    elif isinstance(layer_raw, str):
                        if is_bare_uid(layer_raw):
                            layer_uid = layer_raw
                            layer_name = known_names.get(layer_raw, "")
                        else:
                            layer_name = layer_raw
                            layer_uid = layer_raw
                    if not layer_uid and isinstance(core.get("layer-uid") or raw.get("layer_uid"), str):
                        layer_uid = str(core.get("layer-uid") or raw.get("layer_uid"))
                    if not layer_name and isinstance(core.get("layer-name") or raw.get("layer_name"), str):
                        layer_name = str(core.get("layer-name") or raw.get("layer_name"))
                    if not layer_name and is_bare_uid(layer_uid):
                        if layer_uid in known_names:
                            layer_name = known_names[layer_uid]
                        else:
                            bare_uids_out.add(layer_uid)

                    pkg_raw = core.get("package") or raw.get("package") or old_core.get("package")
                    pkg_uid: str | None = None
                    pkg_name: str | None = None
                    if isinstance(pkg_raw, dict):
                        pkg_uid = str(pkg_raw.get("uid") or "") or None
                        pkg_name = str(pkg_raw.get("name") or "") or None
                    elif isinstance(pkg_raw, str) and pkg_raw:
                        pkg_name = pkg_raw
                        pkg_uid = pkg_raw

                    rule_num_raw = core.get("rule-number") or raw.get("rule-number") or raw.get("rule_number")
                    old_num_raw = (
                        old_core.get("rule-number") or raw.get("old-rule-number") or raw.get("old_rule_number")
                    )
                    rule_num = str(rule_num_raw) if rule_num_raw is not None else None
                    old_rule_num = str(old_num_raw) if old_num_raw is not None else None
                    moved = bool(
                        raw.get("moved", False)
                        or (rule_num and old_rule_num and rule_num != old_rule_num)
                        or any(d.field_name in ("rule-number", "position") for d in f_diffs)
                    )
                    non_move_diffs = [d for d in f_diffs if d.field_name.lower() not in ("rule-number", "position")]
                    eff_op: ChangeOperation = "moved" if (op == "modified" and moved and not non_move_diffs) else op

                    track_str = _extract_track_str(core.get("track"), known_names, bare_uids_out)

                    rc = RuleChangeEntry(
                        uid=uid or f"rule:{len(rules) + 1}",
                        name=name,
                        operation=eff_op,
                        rulebase_type=rb_type,
                        package_uid=pkg_uid,
                        package_name=pkg_name,
                        layer_uid=layer_uid,
                        layer_name=layer_name,
                        section_uid=str(core["section-uid"]) if core.get("section-uid") else None,
                        section_name=str(core["section-name"]) if core.get("section-name") else None,
                        rule_number=rule_num,
                        old_rule_number=old_rule_num,
                        moved=moved,
                        enabled=bool(core.get("enabled", True)),
                        action=_extract_ref_str_or_uid(core.get("action"), known_names, bare_uids_out),
                        method=str(core["method"]) if core.get("method") is not None else None,
                        source=_extract_ref_list(core.get("source"), known_names, bare_uids_out),
                        destination=_extract_ref_list(core.get("destination"), known_names, bare_uids_out),
                        service=_extract_ref_list(core.get("service"), known_names, bare_uids_out),
                        source_negate=bool(core.get("source-negate", False)),
                        destination_negate=bool(core.get("destination-negate", False)),
                        service_negate=bool(core.get("service-negate", False)),
                        original_source=_extract_ref_str_or_uid(
                            core.get("original-source"), known_names, bare_uids_out
                        ),
                        original_destination=_extract_ref_str_or_uid(
                            core.get("original-destination"), known_names, bare_uids_out
                        ),
                        original_service=_extract_ref_str_or_uid(
                            core.get("original-service"), known_names, bare_uids_out
                        ),
                        translated_source=_extract_ref_str_or_uid(
                            core.get("translated-source"), known_names, bare_uids_out
                        ),
                        translated_destination=_extract_ref_str_or_uid(
                            core.get("translated-destination"), known_names, bare_uids_out
                        ),
                        translated_service=_extract_ref_str_or_uid(
                            core.get("translated-service"), known_names, bare_uids_out
                        ),
                        track=track_str,
                        install_on=_extract_ref_list(core.get("install-on"), known_names, bare_uids_out),
                        comments=str(core.get("comments") or ""),
                        field_diffs=f_diffs,
                        raw_data=sanitize_mapping(dict(raw)),
                    )
                    rules.append(rc)
                else:
                    # Non-rule object change (e.g., host, network, group, service)
                    if op == "modified" and old_core:
                        f_diffs.extend(
                            _synthesize_object_snapshot_diffs(
                                old_core,
                                core,
                                existing_diff_fields,
                                known_names,
                                bare_uids_out,
                            )
                        )
                    members = _extract_ref_list(core.get("members"), known_names, bare_uids_out)
                    nat_settings = core.get("nat-settings") or core.get("nat_settings")
                    if isinstance(nat_settings, dict):
                        for nk in ("ipv4-address", "install-on", "hide-behind-ip"):
                            if nk in nat_settings:
                                _extract_ref_str_or_uid(nat_settings[nk], known_names, bare_uids_out)

                    summary_fields = _build_object_summary_fields(core, members)
                    oc = ObjectChangeEntry(
                        uid=uid or f"obj:{len(objects) + 1}",
                        name=name,
                        object_type=obj_type,
                        operation=op,
                        summary=_format_object_summary_from_fields(summary_fields),
                        summary_fields=summary_fields,
                        field_diffs=f_diffs,
                        raw_data=sanitize_mapping(dict(raw)),
                    )
                    objects.append(oc)

    return rules, objects, filtered_system_count


def _replace_resolved_uids_in_session(
    session_report: SessionChangeReport,
    resolved: dict[str, str],
) -> None:
    """Substitute resolved UID->name mappings into rule and object change fields and diffs."""
    if not resolved:
        return

    def _sub(val: str | None) -> str | None:
        if val is not None and val in resolved:
            return resolved[val]
        return val

    def _sub_list(items: list[str]) -> list[str]:
        return [resolved.get(x, x) for x in items]

    def _sub_any(val: Any) -> Any:
        if isinstance(val, str):
            return resolved.get(val, val)
        if isinstance(val, list):
            return [_sub_any(x) for x in val]
        return val

    for rc in session_report.rule_changes:
        if not rc.layer_name and rc.layer_uid in resolved:
            rc.layer_name = resolved[rc.layer_uid]
        rc.action = _sub(rc.action)
        rc.track = _sub(rc.track)
        rc.source = _sub_list(rc.source)
        rc.destination = _sub_list(rc.destination)
        rc.service = _sub_list(rc.service)
        rc.original_source = _sub(rc.original_source)
        rc.original_destination = _sub(rc.original_destination)
        rc.original_service = _sub(rc.original_service)
        rc.translated_source = _sub(rc.translated_source)
        rc.translated_destination = _sub(rc.translated_destination)
        rc.translated_service = _sub(rc.translated_service)
        rc.install_on = _sub_list(rc.install_on)
        for fd in rc.field_diffs:
            fd.old_value = _sub_any(fd.old_value)
            fd.new_value = _sub_any(fd.new_value)
            fd.added_items = _sub_list(fd.added_items)
            fd.removed_items = _sub_list(fd.removed_items)

    for oc in session_report.object_changes:
        if oc.summary_fields:
            for k, v in list(oc.summary_fields.items()):
                oc.summary_fields[k] = _sub_any(v)
            oc.summary = _format_object_summary_from_fields(oc.summary_fields)
        else:
            for uid, name in resolved.items():
                if uid in oc.summary:
                    oc.summary = oc.summary.replace(uid, name)
        for fd in oc.field_diffs:
            fd.old_value = _sub_any(fd.old_value)
            fd.new_value = _sub_any(fd.new_value)
            fd.added_items = _sub_list(fd.added_items)
            fd.removed_items = _sub_list(fd.removed_items)


@traced
async def collect_change_report(
    api: ApiPort,
    cache: CachePort,
    scopes: Sequence[ReportScope | dict[str, Any]],
    *,
    options: RenderOptions | None = None,
    max_uid_lookups: int = MAX_UID_LOOKUPS,
    now_fn: Callable[[], datetime] = utc_now,
    refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None,
) -> ChangeReport:
    """Collect read-only session change evidence across `SessionScope` and `RangeScope` definitions."""
    if not scopes:
        raise ChangeReportInputError("collect_change_report requires at least one SessionScope or RangeScope.")

    validated_scopes: list[ReportScope] = []
    for raw_s in scopes:
        if isinstance(raw_s, (SessionScope, RangeScope)):
            validated_scopes.append(raw_s)
        elif isinstance(raw_s, dict):
            if "session_uids" in raw_s:
                validated_scopes.append(SessionScope.model_validate(raw_s))
            else:
                validated_scopes.append(RangeScope.model_validate(raw_s))
        else:
            raise ChangeReportInputError(f"Unsupported scope type: {type(raw_s).__name__}")

    span_attrs(scope_count=len(validated_scopes), max_uid_lookups=max_uid_lookups)

    warnings: list[ReportWarning] = []
    raw_responses: list[RawResponse] = []

    # Target sessions deduplicated by (mgmt_name, domain_name, session_uid)
    # Value: (mgmt_name, domain_name, session_uid, preloaded_session_meta, owned_session)
    target_sessions: dict[
        tuple[str, str, str],
        tuple[str, str, str, dict[str, Any] | None, OwnedSession | None],
    ] = {}
    session_order: list[tuple[str, str, str]] = []

    for scope in validated_scopes:
        mgmt_name = scope.mgmt_name
        dom_name = (scope.domain or "").strip()

        if isinstance(scope, SessionScope):
            for s_uid in scope.session_uids:
                key = (mgmt_name, dom_name, s_uid)
                owned = scope.resolve_owned_session(s_uid)
                if key not in target_sessions:
                    target_sessions[key] = (mgmt_name, dom_name, s_uid, None, owned)
                    session_order.append(key)
                elif owned is not None and target_sessions[key][4] is None:
                    prev = target_sessions[key]
                    target_sessions[key] = (prev[0], prev[1], prev[2], prev[3], owned)

        elif isinstance(scope, RangeScope):
            # Query show-sessions with safe widened UTC window (or omit server date parameters if from_session is set)
            payload: dict[str, Any] = {
                "details-level": "full",
                "view-published-sessions": True,
            }
            if scope.from_session is None:
                if scope.from_date is not None:
                    widened_from = (scope.from_date.astimezone(UTC) - timedelta(days=1)).isoformat()
                    payload["from"] = widened_from
                if scope.to_date is not None:
                    widened_to = (scope.to_date.astimezone(UTC) + timedelta(days=1)).isoformat()
                    payload["to"] = widened_to

            try:
                q_res = await api.api_query(
                    mgmt_name,
                    "show-sessions",
                    domain=dom_name or None,
                    details_level="full",
                    payload=payload,
                )
                if not q_res.success:
                    warnings.append(
                        ReportWarning(
                            code="session_fetch_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            message=(
                                f"Failed to list published sessions on {mgmt_name}:{dom_name}: "
                                f"{q_res.error_message or q_res.code or 'query failed'}"
                            ),
                        )
                    )
                    continue

                raw_responses.append(
                    RawResponse(
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        command="show-sessions",
                        payload=payload,
                        response={"total": q_res.total, "objects": q_res.objects},
                    )
                )

                # Filter returned sessions by exact UTC publish timestamp and optional from_session/to_session bounds
                candidate_sessions = [s for s in q_res.objects if isinstance(s, dict) and s.get("uid")]
                filtered_sessions = _filter_range_sessions(candidate_sessions, scope)
                for s_meta in filtered_sessions:
                    s_uid = str(s_meta["uid"])
                    key = (mgmt_name, dom_name, s_uid)
                    if key not in target_sessions:
                        target_sessions[key] = (mgmt_name, dom_name, s_uid, s_meta, None)
                        session_order.append(key)
                    elif target_sessions[key][3] is None:
                        prev = target_sessions[key]
                        target_sessions[key] = (prev[0], prev[1], prev[2], s_meta, prev[4])
            except ServerIdentityError:
                raise
            except Exception as exc:
                warnings.append(
                    ReportWarning(
                        code="session_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        message=f"Error listing sessions on {mgmt_name}:{dom_name}: {exc}",
                    )
                )

    # Track total show-object lookups across the entire report (capped at max_uid_lookups = 200)
    uid_lookup_count = 0
    lookup_cap_warned = False
    global_resolved_uids: dict[tuple[str, str, str], str] = {}

    session_reports: list[SessionChangeReport] = []

    for key in session_order:
        mgmt_name, dom_name, s_uid, preloaded_meta, owned = target_sessions[key]
        known_sids = [owned.sid] if owned is not None else []

        # 1. Fetch session metadata if not already loaded from show-sessions
        session_meta: dict[str, Any] | None = preloaded_meta
        if session_meta is None:
            try:
                s_res = await api.api_call(
                    mgmt_name,
                    "show-session",
                    {"uid": s_uid},
                    domain=dom_name or None,
                    sid=owned.sid if owned is not None else None,
                    server_ip=owned.server_ip if (owned is not None and owned.server_ip) else None,
                )
                if s_res.success and isinstance(s_res.data, dict):
                    session_meta = s_res.data
                    raw_responses.append(
                        RawResponse(
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            command="show-session",
                            payload={"uid": s_uid},
                            response=sanitize_mapping(s_res.data, known_sids=known_sids),
                        )
                    )
                else:
                    err_txt = redact_sid(
                        s_res.error_message or s_res.error_code or "show-session failed",
                        known_sids=known_sids,
                    )
                    warnings.append(
                        ReportWarning(
                            code="session_fetch_failed",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"Failed to fetch session metadata for {s_uid}: {err_txt}",
                        )
                    )
                    session_meta = {"uid": s_uid}
            except ServerIdentityError:
                raise
            except Exception as exc:
                safe_err = redact_sid(str(exc), known_sids=known_sids)
                warnings.append(
                    ReportWarning(
                        code="session_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Error fetching session metadata for {s_uid}: {safe_err}",
                    )
                )
                session_meta = {"uid": s_uid}
        s_meta_dict: dict[str, Any] = session_meta

        # 2. Fetch show-changes for this session
        eff_opts = options or RenderOptions()
        changes_payload: dict[str, Any] = {
            "to-session": s_uid,
            "details-level": "full",
        }
        ops_list: list[dict[str, Any]] = []
        changes_user_name = ""
        try:
            ch_res = await api.api_call(
                mgmt_name,
                "show-changes",
                changes_payload,
                domain=dom_name or None,
                sid=owned.sid if owned is not None else None,
                server_ip=owned.server_ip if (owned is not None and owned.server_ip) else None,
                wait_for_task=True,
            )
            if ch_res.success and isinstance(ch_res.data, dict):
                raw_responses.append(
                    RawResponse(
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        command="show-changes",
                        payload=changes_payload,
                        response=sanitize_mapping(ch_res.data, known_sids=known_sids),
                    )
                )
                ops_list = _parse_change_containers(ch_res.data, session_uid=s_uid)
                changes_user_name = _extract_session_user_from_changes(ch_res.data, session_uid=s_uid)
            else:
                err_txt = redact_sid(
                    ch_res.error_message or ch_res.error_code or "show-changes failed",
                    known_sids=known_sids,
                )
                warnings.append(
                    ReportWarning(
                        code="changes_fetch_failed",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Failed to fetch changes for session {s_uid}: {err_txt}",
                    )
                )
        except ServerIdentityError:
            raise
        except Exception as exc:
            safe_err = redact_sid(str(exc), known_sids=known_sids)
            warnings.append(
                ReportWarning(
                    code="changes_fetch_failed",
                    mgmt_name=mgmt_name,
                    domain=dom_name or None,
                    session_uid=s_uid,
                    message=f"Error fetching changes for session {s_uid}: {safe_err}",
                )
            )

        session_user_name = str(s_meta_dict.get("user-name") or s_meta_dict.get("user") or changes_user_name or "")
        known_names: dict[str, str] = {}
        bare_uids: set[str] = set()
        rule_changes, object_changes, filtered_sys_cnt = _parse_rule_and_object_changes(
            ops_list,
            known_names,
            bare_uids,
            session_user_name=session_user_name,
            include_system_objects=eff_opts.include_system_objects,
        )
        if filtered_sys_cnt > 0:
            logger.debug(
                "Filtered background 'System' maintenance objects from session change report",
                mgmt_name=mgmt_name,
                domain=dom_name or None,
                session_uid=s_uid,
                filtered_count=filtered_sys_cnt,
            )

        # 3. Resolve bare UIDs not already named in the session's own change entries (bounded at 200 per report)
        unresolved_uids = [u for u in sorted(bare_uids) if u not in known_names]
        for u in unresolved_uids:
            cache_key = (mgmt_name, dom_name, u)
            if cache_key in global_resolved_uids:
                known_names[u] = global_resolved_uids[cache_key]
                continue

            # Check local SQL cache first before spending a live show-object lookup
            cached_obj = await cache.get_object_by_uid(mgmt_name, dom_name, u)
            if cached_obj is not None and cached_obj.name:
                known_names[u] = cached_obj.name
                global_resolved_uids[cache_key] = cached_obj.name
                continue
            cached_svc = await cache.get_service_by_uid(mgmt_name, dom_name, u)
            if cached_svc is not None and cached_svc.name:
                known_names[u] = cached_svc.name
                global_resolved_uids[cache_key] = cached_svc.name
                continue

            if uid_lookup_count >= max_uid_lookups:
                if not lookup_cap_warned:
                    lookup_cap_warned = True
                    warnings.append(
                        ReportWarning(
                            code="names_unresolved",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=(
                                f"Reached maximum show-object lookup cap ({max_uid_lookups} UIDs); "
                                "remaining bare UIDs left unresolved."
                            ),
                            details={"cap": max_uid_lookups},
                        )
                    )
                continue

            uid_lookup_count += 1
            try:
                obj_res = await api.api_call(
                    mgmt_name,
                    "show-object",
                    {"uid": u, "details-level": "standard"},
                    domain=dom_name or None,
                    sid=owned.sid if owned is not None else None,
                    server_ip=owned.server_ip if (owned is not None and owned.server_ip) else None,
                )
                if obj_res.success and isinstance(obj_res.data, dict):
                    inner = obj_res.data.get("object") if isinstance(obj_res.data.get("object"), dict) else obj_res.data
                    resolved_name = inner.get("name") if isinstance(inner, dict) else None
                    if isinstance(resolved_name, str) and resolved_name:
                        known_names[u] = resolved_name
                        global_resolved_uids[cache_key] = resolved_name
                    else:
                        warnings.append(
                            ReportWarning(
                                code="names_unresolved",
                                mgmt_name=mgmt_name,
                                domain=dom_name or None,
                                session_uid=s_uid,
                                message=f"show-object returned no name for UID {u}.",
                                details={"uid": u},
                            )
                        )
                else:
                    err_txt = redact_sid(
                        obj_res.error_message or obj_res.error_code or "show-object failed",
                        known_sids=known_sids,
                    )
                    warnings.append(
                        ReportWarning(
                            code="names_unresolved",
                            mgmt_name=mgmt_name,
                            domain=dom_name or None,
                            session_uid=s_uid,
                            message=f"Failed to resolve object name for UID {u}: {err_txt}",
                            details={"uid": u},
                        )
                    )
            except ServerIdentityError:
                raise
            except Exception as exc:
                safe_err = redact_sid(str(exc), known_sids=known_sids)
                warnings.append(
                    ReportWarning(
                        code="names_unresolved",
                        mgmt_name=mgmt_name,
                        domain=dom_name or None,
                        session_uid=s_uid,
                        message=f"Error resolving object name for UID {u}: {safe_err}",
                        details={"uid": u},
                    )
                )

        pub_at = parse_cp_publish_timestamp(s_meta_dict.get("publish-time"))
        last_mod = parse_cp_publish_timestamp(s_meta_dict.get("last-modify-time"))
        session_state = str(s_meta_dict.get("state") or ("published" if pub_at is not None else "open"))
        session_report = SessionChangeReport(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            session_uid=s_uid,
            session_name=str(s_meta_dict.get("name") or s_meta_dict.get("session-name") or ""),
            description=str(s_meta_dict.get("description") or ""),
            user_name=session_user_name,
            state=session_state,
            published_at=pub_at,
            last_modify_time=last_mod,
            locks=int(s_meta_dict.get("locks") or 0),
            changes_count=int(
                s_meta_dict.get("changes")
                or s_meta_dict.get("number-of-published-changes")
                or (len(rule_changes) + len(object_changes))
            ),
            rule_changes=rule_changes,
            object_changes=object_changes,
            resolved_names=dict(known_names),
        )
        _replace_resolved_uids_in_session(session_report, known_names)

        # 4. Compute rulebase placement numbering (live OwnedSession or cached snapshot fallback)
        await apply_session_rule_placement(
            session_report,
            api=api,
            cache=cache,
            owned_session=owned,
            warnings=warnings,
            now_fn=now_fn,
            refresh_rulebase_fn=refresh_rulebase_fn,
        )

        session_reports.append(session_report)

    eff_opts = options or RenderOptions()
    return ChangeReport(
        generated_at=now_fn(),
        title=eff_opts.title,
        header_fields=dict(eff_opts.header_fields),
        sessions=session_reports,
        warnings=warnings,
        raw_responses=raw_responses,
    )


def _filter_range_sessions(
    sessions: list[dict[str, Any]],
    scope: RangeScope,
) -> list[dict[str, Any]]:
    """Filter `show-sessions` objects by exact UTC publish timestamp and optional `from_session` / `to_session`."""
    # Parse publish timestamps and sort chronologically (oldest to newest, or preserve relative order)
    with_ts: list[tuple[datetime | None, int, dict[str, Any]]] = []
    for idx, s in enumerate(sessions):
        pub_dt = parse_cp_publish_timestamp(s.get("publish-time") or s.get("last-modify-time"))
        with_ts.append((pub_dt, idx, s))

    # Check if we need session UID range slicing
    uid_to_dt: dict[str, datetime] = {str(s.get("uid")): dt for dt, _, s in with_ts if dt is not None and s.get("uid")}
    from_bound_dt = to_naive_utc(scope.from_date)
    to_bound_dt = to_naive_utc(scope.to_date)

    if scope.from_session and scope.from_session in uid_to_dt:
        s_dt = uid_to_dt[scope.from_session]
        from_bound_dt = max(from_bound_dt, s_dt) if from_bound_dt is not None else s_dt
    if scope.to_session and scope.to_session in uid_to_dt:
        s_dt = uid_to_dt[scope.to_session]
        to_bound_dt = min(to_bound_dt, s_dt) if to_bound_dt is not None else s_dt

    # If from_session or to_session was given without timestamps on those sessions, slice by index
    uids_in_order = [str(s.get("uid") or "") for _, _, s in with_ts]
    allowed_uids: set[str] | None = None
    if (scope.from_session and scope.from_session not in uid_to_dt) or (
        scope.to_session and scope.to_session not in uid_to_dt
    ):
        start_idx = 0
        end_idx = len(uids_in_order) - 1
        if scope.from_session and scope.from_session in uids_in_order:
            pos_a = uids_in_order.index(scope.from_session)
            start_idx = pos_a
        if scope.to_session and scope.to_session in uids_in_order:
            pos_b = uids_in_order.index(scope.to_session)
            end_idx = pos_b
        lo, hi = min(start_idx, end_idx), max(start_idx, end_idx)
        allowed_uids = set(uids_in_order[lo : hi + 1])

    filtered: list[dict[str, Any]] = []
    for pub_dt, _idx, s in with_ts:
        s_uid = str(s.get("uid") or "")
        if allowed_uids is not None and s_uid not in allowed_uids:
            continue
        if from_bound_dt is not None and (pub_dt is None or pub_dt < from_bound_dt):
            continue
        if to_bound_dt is not None and (pub_dt is None or pub_dt > to_bound_dt):
            continue
        filtered.append(s)

    return filtered


__all__ = [
    "MAX_UID_LOOKUPS",
    "collect_change_report",
    "is_bare_uid",
]
