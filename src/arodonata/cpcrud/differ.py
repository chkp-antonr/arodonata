"""Field-level difference computation (`src/arodonata/cpcrud/differ.py`).

Computes deterministic field diffs (`dict[str, FieldChange]`) and update payloads between
desired template specifications and existing `CPObject`, `CPService`, or rule models.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from arodonata.core.errors import ValidationError
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.cpcrud.models import FieldChange
from arodonata.cpcrud.rule_identity import (
    RuleEntryUnion,
    build_effective_obj_dict,
    deref_rule_list,
    normalize_any_sentinel,
    normalize_nat_traffic_ref,
    normalize_traffic_list,
)
from arodonata.cpcrud.state_reader import normalize_app_site_url_key, normalize_mask_length


class DiffSafetyError(ValidationError):
    """Raised when an incremental diff violates Check Point safety invariants."""


def resolve_member_reference(
    ref: str,
    name_resolutions: Mapping[str, str] | None = None,
) -> str:
    """Substitute any auto-named or reused object/service name for `ref`."""
    clean = ref.strip()
    if name_resolutions and clean in name_resolutions:
        return name_resolutions[clean]
    return clean


def parse_existing_member_entries(
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Normalize existing group/service-group members into ordered `{uid, name, ...}` dicts."""
    raw_members = raw_data.get("members") if isinstance(raw_data, Mapping) else None
    if isinstance(raw_members, list):
        entries: list[dict[str, Any]] = []
        for item in raw_members:
            if isinstance(item, Mapping):
                entry = dict(item)
                uid_val = str(entry.get("uid") or "").strip()
                name_val = str(entry.get("name") or "").strip()
                if uid_val:
                    entry["uid"] = uid_val
                else:
                    entry.pop("uid", None)
                if name_val:
                    entry["name"] = name_val
                else:
                    entry.pop("name", None)
                if uid_val or name_val:
                    entries.append(entry)
            elif isinstance(item, str) and item.strip():
                entries.append({"name": item.strip()})
        if entries or len(raw_members) == 0:
            return entries
    return [{"name": str(m).strip()} for m in existing_members if str(m).strip()]


def _resolve_existing_member_names(
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any] | None,
) -> list[str]:
    """Resolve existing group `members` into a list of member names (or UIDs if names are unavailable)."""
    return [
        str(entry.get("name") or entry.get("uid"))
        for entry in parse_existing_member_entries(existing_members, raw_data)
        if entry.get("name") or entry.get("uid")
    ]


def compute_object_diff(
    desired: Mapping[str, Any],
    existing: CPObject,
    *,
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[dict[str, FieldChange], dict[str, Any]]:
    """Compute field diffs and `set-<type>` update payload between `desired` spec and `existing` `CPObject`."""
    diffs: dict[str, FieldChange] = {}
    update_payload: dict[str, Any] = {}

    obj_type = existing.type
    new_name = desired.get("new_name") or desired.get("new-name")
    if isinstance(new_name, str) and new_name.strip() and new_name.strip() != existing.name:
        diffs["name"] = FieldChange(field="name", old_value=existing.name, new_value=new_name.strip())
        update_payload["new-name"] = new_name.strip()

    if obj_type == "host":
        req_ipv4 = (
            desired.get("ipv4_address")
            or desired.get("ipv4-address")
            or desired.get("ip_address")
            or desired.get("ip-address")
        )
        if isinstance(req_ipv4, str) and req_ipv4.strip():
            clean_ip = req_ipv4.strip()
            if clean_ip != existing.ipv4_address:
                diffs["ipv4-address"] = FieldChange(
                    field="ipv4-address",
                    old_value=existing.ipv4_address,
                    new_value=clean_ip,
                )
                update_payload["ipv4-address"] = clean_ip

        req_ipv6 = desired.get("ipv6_address") or desired.get("ipv6-address")
        if isinstance(req_ipv6, str) and req_ipv6.strip():
            clean_ip6 = req_ipv6.strip()
            if clean_ip6 != existing.ipv6_address:
                diffs["ipv6-address"] = FieldChange(
                    field="ipv6-address",
                    old_value=existing.ipv6_address,
                    new_value=clean_ip6,
                )
                update_payload["ipv6-address"] = clean_ip6

    elif obj_type == "network":
        req_sub = desired.get("subnet4") or desired.get("subnet")
        if isinstance(req_sub, str) and req_sub.strip():
            clean_sub = req_sub.strip()
            if clean_sub != existing.subnet4:
                diffs["subnet4"] = FieldChange(
                    field="subnet4",
                    old_value=existing.subnet4,
                    new_value=clean_sub,
                )
                update_payload["subnet4"] = clean_sub

        req_mask = desired.get("mask_length4") if "mask_length4" in desired else desired.get("mask-length4")
        req_submask = desired.get("subnet_mask") or desired.get("subnet-mask")
        norm_req_mask = normalize_mask_length(req_mask, req_submask, strict=True)
        norm_exist_mask = normalize_mask_length(existing.mask_length4, existing.subnet_mask)
        if norm_req_mask is not None and norm_req_mask != norm_exist_mask:
            diffs["mask-length4"] = FieldChange(
                field="mask-length4",
                old_value=norm_exist_mask,
                new_value=norm_req_mask,
            )
            update_payload["mask-length4"] = norm_req_mask

    elif obj_type == "address-range":
        req_first = desired.get("ipv4_address_first") or desired.get("ipv4-address-first")
        if isinstance(req_first, str) and req_first.strip():
            clean_first = req_first.strip()
            if clean_first != existing.ipv4_address_first:
                diffs["ipv4-address-first"] = FieldChange(
                    field="ipv4-address-first",
                    old_value=existing.ipv4_address_first,
                    new_value=clean_first,
                )
                update_payload["ipv4-address-first"] = clean_first

        req_last = desired.get("ipv4_address_last") or desired.get("ipv4-address-last")
        if isinstance(req_last, str) and req_last.strip():
            clean_last = req_last.strip()
            if clean_last != existing.ipv4_address_last:
                diffs["ipv4-address-last"] = FieldChange(
                    field="ipv4-address-last",
                    old_value=existing.ipv4_address_last,
                    new_value=clean_last,
                )
                update_payload["ipv4-address-last"] = clean_last

    elif obj_type == "dns-domain":
        req_sub_dom = desired.get("is_sub_domain") if "is_sub_domain" in desired else desired.get("is-sub-domain")
        if isinstance(req_sub_dom, bool) and req_sub_dom != bool(existing.is_sub_domain):
            diffs["is-sub-domain"] = FieldChange(
                field="is-sub-domain",
                old_value=existing.is_sub_domain,
                new_value=req_sub_dom,
            )
            update_payload["is-sub-domain"] = req_sub_dom

    elif obj_type == "group":
        _compute_group_members_diff(
            desired, existing.members, existing.raw_data, diffs, update_payload, name_resolutions
        )

    elif obj_type == "application-site":
        req_cat = desired.get("primary-category") or desired.get("primary_category")
        if isinstance(req_cat, str) and req_cat.strip():
            clean_cat = req_cat.strip()
            exist_cat = str(
                existing.primary_category
                or (existing.raw_data.get("primary-category") if isinstance(existing.raw_data, dict) else None)
                or ""
            ).strip()
            if clean_cat != exist_cat:
                diffs["primary-category"] = FieldChange(
                    field="primary-category",
                    old_value=existing.primary_category or exist_cat or None,
                    new_value=clean_cat,
                )
                update_payload["primary-category"] = clean_cat

        raw_req_urls = desired.get("url-list") if "url-list" in desired else desired.get("url_list")
        if raw_req_urls is not None:
            raw_exist_urls: Sequence[Any] = existing.url_list
            if not raw_exist_urls and isinstance(existing.raw_data, Mapping):
                fallback_urls = existing.raw_data.get("url-list") or existing.raw_data.get("url_list")
                if isinstance(fallback_urls, list):
                    raw_exist_urls = fallback_urls
            exist_urls = list(dict.fromkeys(str(u).strip() for u in raw_exist_urls if str(u).strip()))
            raw_req_regex_for_url = (
                desired.get("urls-defined-as-regular-expression")
                if "urls-defined-as-regular-expression" in desired
                else desired.get("urls_defined_as_regular_expression")
            )
            eff_is_regex = (
                bool(raw_req_regex_for_url)
                if raw_req_regex_for_url is not None
                else bool(existing.urls_defined_as_regular_expression)
            )
            req_sig_raw = desired.get("application-signature") or desired.get("application_signature")
            exist_sig_raw = (
                existing.raw_data.get("application-signature") or existing.raw_data.get("application_signature")
                if isinstance(existing.raw_data, Mapping)
                else None
            )
            effective_has_sig = bool(str(req_sig_raw or "").strip() or str(exist_sig_raw or "").strip())
            _compute_url_list_diff(
                existing.name,
                raw_req_urls,
                exist_urls,
                is_regex=eff_is_regex,
                has_signature=effective_has_sig,
                diffs=diffs,
                update_payload=update_payload,
            )

        if "urls-defined-as-regular-expression" in desired or "urls_defined_as_regular_expression" in desired:
            raw_req_regex = (
                desired.get("urls-defined-as-regular-expression")
                if "urls-defined-as-regular-expression" in desired
                else desired.get("urls_defined_as_regular_expression")
            )
            if raw_req_regex is not None:
                req_regex = bool(raw_req_regex)
                exist_regex = bool(existing.urls_defined_as_regular_expression)
                if req_regex != exist_regex:
                    diffs["urls-defined-as-regular-expression"] = FieldChange(
                        field="urls-defined-as-regular-expression",
                        old_value=existing.urls_defined_as_regular_expression,
                        new_value=req_regex,
                    )
                    update_payload["urls-defined-as-regular-expression"] = req_regex

        if "description" in desired and desired["description"] is not None:
            req_desc = str(desired["description"])
            exist_desc = str(existing.description or "")
            if req_desc != exist_desc:
                diffs["description"] = FieldChange(
                    field="description",
                    old_value=existing.description,
                    new_value=req_desc,
                )
                update_payload["description"] = req_desc

        req_sig = desired.get("application-signature") or desired.get("application_signature")
        if isinstance(req_sig, str) and req_sig.strip():
            clean_sig = req_sig.strip()
            exist_sig = str(
                (existing.raw_data.get("application-signature") if isinstance(existing.raw_data, dict) else None) or ""
            ).strip()
            if clean_sig != exist_sig:
                diffs["application-signature"] = FieldChange(
                    field="application-signature",
                    old_value=exist_sig or None,
                    new_value=clean_sig,
                )
                update_payload["application-signature"] = clean_sig

        raw_add_cats = (
            desired.get("additional-categories")
            if "additional-categories" in desired
            else desired.get("additional_categories")
        )
        if isinstance(raw_add_cats, list):
            req_add_cats = [str(c).strip() for c in raw_add_cats if str(c).strip()]
            raw_exist_cats = (
                existing.raw_data.get("additional-categories") if isinstance(existing.raw_data, dict) else None
            )
            exist_add_cats = (
                [str(c).strip() for c in raw_exist_cats if str(c).strip()] if isinstance(raw_exist_cats, list) else []
            )
            if set(req_add_cats) != set(exist_add_cats):
                diffs["additional-categories"] = FieldChange(
                    field="additional-categories",
                    old_value=exist_add_cats,
                    new_value=req_add_cats,
                )
                update_payload["additional-categories"] = req_add_cats

    # Common optional metadata fields
    _compute_common_metadata_diff(
        desired,
        existing_comments=existing.comments,
        existing_color=existing.color,
        existing_tags=existing.tags,
        diffs=diffs,
        update_payload=update_payload,
    )

    req_nat = desired.get("nat_settings") if "nat_settings" in desired else desired.get("nat-settings")
    if isinstance(req_nat, dict) and req_nat != (existing.nat_settings or {}):
        diffs["nat-settings"] = FieldChange(
            field="nat-settings",
            old_value=existing.nat_settings,
            new_value=req_nat,
        )
        update_payload["nat-settings"] = dict(req_nat)

    return diffs, update_payload


def compute_service_diff(
    desired: Mapping[str, Any],
    existing: CPService,
    *,
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[dict[str, FieldChange], dict[str, Any]]:
    """Compute field diffs and `set-<service-type>` update payload between `desired` spec and `existing` `CPService`."""
    diffs: dict[str, FieldChange] = {}
    update_payload: dict[str, Any] = {}

    new_name = desired.get("new_name") or desired.get("new-name")
    if isinstance(new_name, str) and new_name.strip() and new_name.strip() != existing.name:
        diffs["name"] = FieldChange(field="name", old_value=existing.name, new_value=new_name.strip())
        update_payload["new-name"] = new_name.strip()

    if "port" in desired and desired["port"] is not None:
        req_port = str(desired["port"]).strip()
        if req_port != (existing.port or ""):
            diffs["port"] = FieldChange(field="port", old_value=existing.port, new_value=req_port)
            update_payload["port"] = req_port

    req_proto = desired.get("protocol") or desired.get("ip_protocol") or desired.get("ip-protocol")
    if req_proto is not None:
        req_proto_str = str(req_proto).strip()
        exist_proto_str = str(existing.protocol or "").strip()
        if req_proto_str.upper() != exist_proto_str.upper():
            diffs["protocol"] = FieldChange(field="protocol", old_value=existing.protocol, new_value=req_proto)
            if existing.type == "service-other":
                update_payload["ip-protocol"] = req_proto
            else:
                update_payload["protocol"] = req_proto

    req_icmp_type = desired.get("icmp_type") if "icmp_type" in desired else desired.get("icmp-type")
    if isinstance(req_icmp_type, int) and req_icmp_type != existing.icmp_type:
        diffs["icmp-type"] = FieldChange(field="icmp-type", old_value=existing.icmp_type, new_value=req_icmp_type)
        update_payload["icmp-type"] = req_icmp_type

    req_icmp_code = desired.get("icmp_code") if "icmp_code" in desired else desired.get("icmp-code")
    if isinstance(req_icmp_code, int) and req_icmp_code != existing.icmp_code:
        diffs["icmp-code"] = FieldChange(field="icmp-code", old_value=existing.icmp_code, new_value=req_icmp_code)
        update_payload["icmp-code"] = req_icmp_code

    req_timeout = desired.get("session_timeout") if "session_timeout" in desired else desired.get("session-timeout")
    if isinstance(req_timeout, int) and req_timeout != existing.session_timeout:
        diffs["session-timeout"] = FieldChange(
            field="session-timeout",
            old_value=existing.session_timeout,
            new_value=req_timeout,
        )
        update_payload["session-timeout"] = req_timeout

    req_mfa = desired.get("match_for_any") if "match_for_any" in desired else desired.get("match-for-any")
    if isinstance(req_mfa, bool) and req_mfa != existing.match_for_any:
        diffs["match-for-any"] = FieldChange(
            field="match-for-any",
            old_value=existing.match_for_any,
            new_value=req_mfa,
        )
        update_payload["match-for-any"] = req_mfa

    if existing.type == "service-group":
        _compute_group_members_diff(
            desired, existing.members, existing.raw_data, diffs, update_payload, name_resolutions
        )

    _compute_common_metadata_diff(
        desired,
        existing_comments=existing.comments,
        existing_color=existing.color,
        existing_tags=existing.tags,
        diffs=diffs,
        update_payload=update_payload,
    )

    return diffs, update_payload


def _build_member_uid_to_name_map(
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any],
    current_names: Sequence[str],
) -> dict[str, str]:
    uid_to_name: dict[str, str] = {}
    for elem in parse_existing_member_entries(existing_members, raw_data):
        u = str(elem.get("uid") or "").strip()
        n = str(elem.get("name") or "").strip()
        if u and n:
            uid_to_name[u] = n
    if len(existing_members) == len(current_names):
        for u, n in zip(existing_members, current_names, strict=False):
            if u and n and u not in uid_to_name:
                uid_to_name[str(u)] = str(n)
    return uid_to_name


def _compute_group_members_diff(
    desired: Mapping[str, Any],
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any],
    diffs: dict[str, FieldChange],
    update_payload: dict[str, Any],
    name_resolutions: Mapping[str, str] | None = None,
) -> None:
    if "members" not in desired or desired["members"] is None:
        return

    req_members = desired["members"]
    current_names = _resolve_existing_member_names(existing_members, raw_data)
    current_uids = set(existing_members)
    current_set = set(current_names) | current_uids

    if isinstance(req_members, list):
        resolved_req = [resolve_member_reference(str(m), name_resolutions) for m in req_members]
        uid_to_name = _build_member_uid_to_name_map(existing_members, raw_data, current_names)
        canonical_req = [uid_to_name.get(m, m) for m in resolved_req]
        # Compare order-insensitively across both resolved names and UIDs
        if (
            set(resolved_req) != set(current_names)
            and set(resolved_req) != current_uids
            and set(canonical_req) != set(current_names)
        ):
            canonical_req_set = set(canonical_req)
            added_items = list(
                dict.fromkeys(m for m in canonical_req if m not in current_set and m not in set(current_names))
            )
            removed_items = list(dict.fromkeys(m for m in current_names if m not in canonical_req_set))
            diffs["members"] = FieldChange(
                field="members",
                old_value=list(current_names),
                new_value=resolved_req,
                added_items=added_items,
                removed_items=removed_items,
            )
            update_payload["members"] = resolved_req
    elif isinstance(req_members, dict):
        to_add = [resolve_member_reference(str(m), name_resolutions) for m in (req_members.get("add") or [])]
        to_remove = [resolve_member_reference(str(m), name_resolutions) for m in (req_members.get("remove") or [])]
        missing_adds = list(dict.fromkeys(m for m in to_add if m not in current_set))
        present_removes = list(dict.fromkeys(m for m in to_remove if m in current_set))
        if missing_adds or present_removes:
            member_op: dict[str, list[str]] = {}
            if missing_adds:
                member_op["add"] = missing_adds
            if present_removes:
                member_op["remove"] = present_removes
            diffs["members"] = FieldChange(
                field="members",
                old_value=list(current_names),
                new_value=member_op,
                added_items=missing_adds,
                removed_items=present_removes,
            )
            update_payload["members"] = member_op


def _dedup_urls_by_key(urls: Sequence[str], *, is_regex: bool) -> list[str]:
    seen_keys: set[str] = set()
    out: list[str] = []
    for raw_u in urls:
        clean = str(raw_u).strip()
        if not clean:
            continue
        key = normalize_app_site_url_key(clean, is_regex=is_regex)
        if key not in seen_keys:
            seen_keys.add(key)
            out.append(clean)
    return out


def _compute_url_list_diff(
    obj_name: str,
    raw_req_urls: Any,
    exist_urls: list[str],
    *,
    is_regex: bool = True,
    has_signature: bool,
    diffs: dict[str, FieldChange],
    update_payload: dict[str, Any],
) -> None:
    exist_by_key = {normalize_app_site_url_key(u, is_regex=is_regex): u for u in exist_urls}
    exist_keys = set(exist_by_key.keys())

    if isinstance(raw_req_urls, list):
        merged_raw = _dedup_urls_by_key([str(u) for u in raw_req_urls], is_regex=is_regex)
        merged_urls = [exist_by_key.get(normalize_app_site_url_key(u, is_regex=is_regex), u) for u in merged_raw]
    elif isinstance(raw_req_urls, Mapping):
        raw_adds = _dedup_urls_by_key([str(u) for u in (raw_req_urls.get("add") or [])], is_regex=is_regex)
        raw_rem_keys = {
            normalize_app_site_url_key(str(u), is_regex=is_regex)
            for u in (raw_req_urls.get("remove") or [])
            if str(u).strip()
        }
        kept = [u for u in exist_urls if normalize_app_site_url_key(u, is_regex=is_regex) not in raw_rem_keys]
        merged_urls = _dedup_urls_by_key([*kept, *raw_adds], is_regex=is_regex)
    else:
        return

    if not merged_urls and not has_signature:
        raise DiffSafetyError(
            f"application-site {obj_name!r} cannot have an empty url-list without an application-signature."
        )

    merged_keys = {normalize_app_site_url_key(u, is_regex=is_regex) for u in merged_urls}
    if merged_keys != exist_keys:
        effective_adds = [u for u in merged_urls if normalize_app_site_url_key(u, is_regex=is_regex) not in exist_keys]
        effective_removes = [
            u for u in exist_urls if normalize_app_site_url_key(u, is_regex=is_regex) not in merged_keys
        ]
        diffs["url-list"] = FieldChange(
            field="url-list",
            old_value=list(exist_urls),
            new_value=merged_urls,
            added_items=effective_adds,
            removed_items=effective_removes,
        )
        update_payload["url-list"] = merged_urls


def _resolve_rule_delta_items(
    raw_items: Any,
    *,
    eff_obj_dict: Mapping[str, Mapping[str, Any]],
    name_resolutions: Mapping[str, str] | None,
) -> list[str]:
    if raw_items is None:
        return []
    seq = raw_items if isinstance(raw_items, (list, tuple, set)) else [raw_items]
    out: list[str] = []
    for item in seq:
        norm = normalize_any_sentinel(item, eff_obj_dict)
        resolved = resolve_member_reference(norm, name_resolutions)
        if resolved:
            out.append(resolved)
    return list(dict.fromkeys(out))


def _compute_rule_list_cell_diff(
    field_key: str,
    raw_desired_val: Any,
    exist_list: Sequence[str] | None,
    raw_exist: Mapping[str, Any],
    *,
    eff_obj_dict: Mapping[str, Mapping[str, Any]],
    name_resolutions: Mapping[str, str] | None,
    diffs: dict[str, FieldChange],
    update_payload: dict[str, Any],
) -> None:
    if isinstance(raw_desired_val, Mapping):
        exist_names = deref_rule_list(exist_list, raw_exist.get(field_key), eff_obj_dict, default_any=True)
        req_adds = _resolve_rule_delta_items(
            raw_desired_val.get("add"),
            eff_obj_dict=eff_obj_dict,
            name_resolutions=name_resolutions,
        )
        req_removes = _resolve_rule_delta_items(
            raw_desired_val.get("remove"),
            eff_obj_dict=eff_obj_dict,
            name_resolutions=name_resolutions,
        )

        if any(x.lower() == "any" for x in req_adds):
            raise DiffSafetyError(
                f"Cannot include 'Any' in incremental 'add' on rule field {field_key!r}: "
                "adding 'Any' widens or corrupts the rule cell; pass full list ['Any'] if widening is intended."
            )

        exist_has_any = any(x.lower() == "any" for x in exist_names)
        non_any_adds = [x for x in req_adds if x.lower() != "any"]
        removes_any = any(x.lower() == "any" for x in req_removes)
        if exist_has_any and non_any_adds and not removes_any:
            raise DiffSafetyError(
                f"Cannot add {non_any_adds} to {field_key!r} while it is set to 'Any'; "
                "include 'Any' in 'remove' explicitly when narrowing a rule cell."
            )

        rem_set = set(req_removes)
        kept = [x for x in exist_names if x not in rem_set]
        post_items = list(dict.fromkeys([*kept, *req_adds]))
        if not post_items:
            raise DiffSafetyError(
                f"Refusing to remove all items from rule field {field_key!r}: "
                "an empty rule cell silently widens to 'Any' in Check Point."
            )

        exist_set = set(exist_names)
        post_set = set(post_items)
        effective_adds = [x for x in req_adds if x not in exist_set and x in post_set]
        effective_removes = [x for x in exist_names if x not in post_set]
        if effective_adds or effective_removes:
            # Strip 'Any' sentinel from Check Point wire `remove`; keeping `effective_removes` on FieldChange.
            wire_removes = [x for x in effective_removes if x.lower() != "any"]
            delta_op: dict[str, list[str]] = {}
            if effective_adds:
                delta_op["add"] = effective_adds
            if wire_removes:
                delta_op["remove"] = wire_removes
            diffs[field_key] = FieldChange(
                field=field_key,
                old_value=list(exist_names),
                new_value=delta_op,
                added_items=effective_adds,
                removed_items=effective_removes,
            )
            update_payload[field_key] = delta_op
        return

    norm_des_t = normalize_traffic_list(raw_desired_val, name_resolutions=name_resolutions)
    norm_exist_t = normalize_traffic_list(
        exist_list or raw_exist.get(field_key),
        obj_dict=eff_obj_dict,
    )
    if norm_des_t != norm_exist_t:
        old_set = set(norm_exist_t)
        new_set = set(norm_des_t)
        added_items = [x for x in norm_des_t if x not in old_set]
        removed_items = [x for x in norm_exist_t if x not in new_set]
        diffs[field_key] = FieldChange(
            field=field_key,
            old_value=list(norm_exist_t),
            new_value=list(norm_des_t),
            added_items=added_items,
            removed_items=removed_items,
        )
        update_payload[field_key] = list(norm_des_t)


def _compute_common_metadata_diff(
    desired: Mapping[str, Any],
    *,
    existing_comments: str,
    existing_color: str | None,
    existing_tags: Sequence[str],
    diffs: dict[str, FieldChange],
    update_payload: dict[str, Any],
) -> None:
    if "comments" in desired and desired["comments"] is not None:
        req_comments = str(desired["comments"])
        if req_comments != (existing_comments or ""):
            diffs["comments"] = FieldChange(
                field="comments",
                old_value=existing_comments,
                new_value=req_comments,
            )
            update_payload["comments"] = req_comments

    if "color" in desired and desired["color"] is not None:
        req_color = str(desired["color"]).strip()
        if req_color.lower() != str(existing_color or "").strip().lower():
            diffs["color"] = FieldChange(
                field="color",
                old_value=existing_color,
                new_value=req_color,
            )
            update_payload["color"] = req_color

    if "tags" in desired and desired["tags"] is not None and isinstance(desired["tags"], list):
        req_tags = sorted(str(t).strip() for t in desired["tags"] if str(t).strip())
        exist_tags = sorted(str(t).strip() for t in existing_tags if str(t).strip())
        if req_tags != exist_tags:
            diffs["tags"] = FieldChange(
                field="tags",
                old_value=list(existing_tags),
                new_value=req_tags,
            )
            update_payload["tags"] = req_tags


def compute_rule_diff(
    desired: Mapping[str, Any],
    existing: RuleEntryUnion,
    *,
    rulebase_type: RulebaseType,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
    name_resolutions: Mapping[str, str] | None = None,
) -> tuple[dict[str, FieldChange], dict[str, Any]]:
    """Compute field diffs and `set-*-rule` update payload between `desired` spec and `existing` rule."""
    diffs: dict[str, FieldChange] = {}
    update_payload: dict[str, Any] = {}

    new_name = desired.get("new_name") or desired.get("new-name")
    if isinstance(new_name, str) and new_name.strip() and new_name.strip() != existing.name:
        diffs["name"] = FieldChange(field="name", old_value=existing.name, new_value=new_name.strip())
        update_payload["new-name"] = new_name.strip()
    elif "name" in desired and desired["name"] is not None:
        req_name = str(desired["name"]).strip()
        if req_name and req_name != existing.name:
            diffs["name"] = FieldChange(field="name", old_value=existing.name, new_value=req_name)
            update_payload["new-name"] = req_name

    if "enabled" in desired and desired["enabled"] is not None:
        req_en = bool(desired["enabled"])
        if req_en != existing.enabled:
            diffs["enabled"] = FieldChange(field="enabled", old_value=existing.enabled, new_value=req_en)
            update_payload["enabled"] = req_en

    if "comments" in desired and desired["comments"] is not None:
        req_comm = str(desired["comments"])
        if req_comm != (existing.comments or ""):
            diffs["comments"] = FieldChange(field="comments", old_value=existing.comments, new_value=req_comm)
            update_payload["comments"] = req_comm

    raw_exist = existing.raw_data or {}
    eff_obj_dict = build_effective_obj_dict(raw_exist, obj_dict)

    if rulebase_type == "nat" and isinstance(existing, NatRuleEntry):
        # NAT rule diff with Original and Any sentinel normalization
        if "method" in desired and desired["method"] is not None:
            req_method = str(desired["method"]).strip().lower()
            exist_method = str(existing.method or raw_exist.get("method") or "static").strip().lower()
            if req_method != exist_method:
                diffs["method"] = FieldChange(field="method", old_value=existing.method, new_value=req_method)
                update_payload["method"] = req_method

        nat_fields: list[tuple[str, str, str | None, bool]] = [
            ("original_source", "original-source", existing.original_source, False),
            ("original_destination", "original-destination", existing.original_destination, False),
            ("original_service", "original-service", existing.original_service, False),
            ("translated_source", "translated-source", existing.translated_source, True),
            ("translated_destination", "translated-destination", existing.translated_destination, True),
            ("translated_service", "translated-service", existing.translated_service, True),
        ]
        for snake_k, kebab_k, exist_attr, is_trans in nat_fields:
            if snake_k in desired or kebab_k in desired:
                raw_des_val = desired.get(snake_k) if snake_k in desired else desired.get(kebab_k)
                norm_des = normalize_nat_traffic_ref(
                    raw_des_val,
                    is_translated=is_trans,
                    name_resolutions=name_resolutions,
                )
                norm_exist = normalize_nat_traffic_ref(
                    exist_attr if exist_attr is not None else raw_exist.get(kebab_k),
                    is_translated=is_trans,
                    obj_dict=obj_dict,
                )
                if norm_des != norm_exist:
                    diffs[kebab_k] = FieldChange(field=kebab_k, old_value=norm_exist, new_value=norm_des)
                    update_payload[kebab_k] = norm_des

    elif isinstance(existing, (AccessRuleEntry, HttpsRuleEntry, ThreatRuleEntry)):
        for field_key, exist_list in (
            ("source", existing.source),
            ("destination", existing.destination),
            ("service", existing.service),
        ):
            if field_key in desired and desired[field_key] is not None:
                _compute_rule_list_cell_diff(
                    field_key,
                    desired[field_key],
                    exist_list,
                    raw_exist,
                    eff_obj_dict=eff_obj_dict,
                    name_resolutions=name_resolutions,
                    diffs=diffs,
                    update_payload=update_payload,
                )

        # Action diff
        raw_act = desired.get("rule_action")
        if raw_act is None and "action" in desired:
            cand = desired["action"]
            if isinstance(cand, str) and cand.lower() not in ("present", "absent", "add", "set", "update", "delete"):
                raw_act = cand
        if raw_act is not None:
            req_act = str(raw_act).strip()
            exist_act = str(existing.action or "").strip()
            if req_act.lower() != exist_act.lower():
                diffs["action"] = FieldChange(field="action", old_value=existing.action, new_value=req_act)
                update_payload["action"] = req_act

        if "track" in desired and desired["track"] is not None:
            req_track = desired["track"]
            req_track_str = str(req_track.get("type") or "") if isinstance(req_track, dict) else str(req_track).strip()
            exist_track_str = str(existing.track or "").strip()
            if req_track_str.lower() != exist_track_str.lower():
                diffs["track"] = FieldChange(field="track", old_value=existing.track, new_value=req_track)
                update_payload["track"] = req_track

    if isinstance(existing, AccessRuleEntry):
        for snake_k, kebab_k, exist_neg in (
            ("source_negate", "source-negate", existing.source_negate),
            ("destination_negate", "destination-negate", existing.destination_negate),
            ("service_negate", "service-negate", existing.service_negate),
        ):
            if snake_k in desired or kebab_k in desired:
                raw_neg = desired.get(snake_k) if snake_k in desired else desired.get(kebab_k)
                if raw_neg is not None and bool(raw_neg) != bool(exist_neg):
                    diffs[kebab_k] = FieldChange(field=kebab_k, old_value=bool(exist_neg), new_value=bool(raw_neg))
                    update_payload[kebab_k] = bool(raw_neg)

        if "inline_layer" in desired or "inline-layer" in desired:
            req_inline = desired.get("inline_layer") or desired.get("inline-layer")
            exist_inline = existing.inline_layer_name or existing.inline_layer_uid or raw_exist.get("inline-layer")
            if isinstance(req_inline, str) and req_inline.strip() != str(exist_inline or "").strip():
                diffs["inline-layer"] = FieldChange(
                    field="inline-layer", old_value=exist_inline, new_value=req_inline.strip()
                )
                update_payload["inline-layer"] = req_inline.strip()

    if isinstance(existing, HttpsRuleEntry):
        if "site_category" in desired or "site-category" in desired:
            raw_sc = desired.get("site_category") if "site_category" in desired else desired.get("site-category")
            if raw_sc is not None:
                _compute_rule_list_cell_diff(
                    "site-category",
                    raw_sc,
                    existing.site_category,
                    raw_exist,
                    eff_obj_dict=eff_obj_dict,
                    name_resolutions=name_resolutions,
                    diffs=diffs,
                    update_payload=update_payload,
                )
        if "certificate" in desired and desired["certificate"] is not None:
            req_cert = str(desired["certificate"]).strip()
            if req_cert != str(existing.certificate or "").strip():
                diffs["certificate"] = FieldChange(
                    field="certificate", old_value=existing.certificate, new_value=req_cert
                )
                update_payload["certificate"] = req_cert

    if isinstance(existing, ThreatRuleEntry) and ("protected_scope" in desired or "protected-scope" in desired):
        raw_ps = desired.get("protected_scope") if "protected_scope" in desired else desired.get("protected-scope")
        if raw_ps is not None:
            _compute_rule_list_cell_diff(
                "protected-scope",
                raw_ps,
                existing.protected_scope,
                raw_exist,
                eff_obj_dict=eff_obj_dict,
                name_resolutions=name_resolutions,
                diffs=diffs,
                update_payload=update_payload,
            )

    if "install_on" in desired or "install-on" in desired:
        raw_inst = desired.get("install_on") if "install_on" in desired else desired.get("install-on")
        if raw_inst is not None:
            _compute_rule_list_cell_diff(
                "install-on",
                raw_inst,
                existing.install_on,
                raw_exist,
                eff_obj_dict=eff_obj_dict,
                name_resolutions=name_resolutions,
                diffs=diffs,
                update_payload=update_payload,
            )

    return diffs, update_payload


__all__ = [
    "DiffSafetyError",
    "compute_object_diff",
    "compute_rule_diff",
    "compute_service_diff",
    "resolve_member_reference",
]
