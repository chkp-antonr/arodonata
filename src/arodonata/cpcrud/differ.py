"""Field-level difference computation (`src/arodonata/cpcrud/differ.py`).

Computes deterministic field diffs (`dict[str, FieldChange]`) and update payloads between
desired template specifications and existing `CPObject`, `CPService`, or rule models.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

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
    normalize_nat_traffic_ref,
    normalize_traffic_list,
)
from arodonata.cpcrud.state_reader import normalize_mask_length


def resolve_member_reference(
    ref: str,
    name_resolutions: Mapping[str, str] | None = None,
) -> str:
    """Substitute any auto-named or reused object/service name for `ref`."""
    clean = ref.strip()
    if name_resolutions and clean in name_resolutions:
        return name_resolutions[clean]
    return clean


def _resolve_existing_member_names(
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any],
) -> list[str]:
    """Resolve existing group `members` into a list of member names (or UIDs if names are unavailable)."""
    raw_members = raw_data.get("members")
    if isinstance(raw_members, list) and raw_members:
        names: list[str] = []
        for item in raw_members:
            if isinstance(item, dict):
                n = item.get("name") or item.get("uid")
                if isinstance(n, str) and n:
                    names.append(n)
            elif isinstance(item, str) and item:
                names.append(item)
        if names:
            return names
    return list(existing_members)


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
        norm_req_mask = normalize_mask_length(req_mask, req_submask)
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
        # Compare order-insensitively by resolved name or UID
        if set(resolved_req) != set(current_names) and set(resolved_req) != current_uids:
            diffs["members"] = FieldChange(
                field="members",
                old_value=list(current_names),
                new_value=resolved_req,
            )
            update_payload["members"] = resolved_req
    elif isinstance(req_members, dict):
        to_add = [resolve_member_reference(str(m), name_resolutions) for m in (req_members.get("add") or [])]
        to_remove = [resolve_member_reference(str(m), name_resolutions) for m in (req_members.get("remove") or [])]
        missing_adds = [m for m in to_add if m not in current_set]
        present_removes = [m for m in to_remove if m in current_set]
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
            )
            update_payload["members"] = member_op


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
                norm_des_t = normalize_traffic_list(desired[field_key], name_resolutions=name_resolutions)
                norm_exist_t = normalize_traffic_list(
                    exist_list or raw_exist.get(field_key),
                    obj_dict=obj_dict,
                )
                if norm_des_t != norm_exist_t:
                    diffs[field_key] = FieldChange(
                        field=field_key,
                        old_value=list(norm_exist_t),
                        new_value=list(norm_des_t),
                    )
                    update_payload[field_key] = list(norm_des_t)

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
                norm_des_sc = normalize_traffic_list(raw_sc, name_resolutions=name_resolutions)
                norm_exist_sc = normalize_traffic_list(
                    existing.site_category or raw_exist.get("site-category"), obj_dict=obj_dict
                )
                if norm_des_sc != norm_exist_sc:
                    diffs["site-category"] = FieldChange(
                        field="site-category", old_value=list(norm_exist_sc), new_value=list(norm_des_sc)
                    )
                    update_payload["site-category"] = list(norm_des_sc)
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
            norm_des_ps = normalize_traffic_list(raw_ps, name_resolutions=name_resolutions)
            norm_exist_ps = normalize_traffic_list(
                existing.protected_scope or raw_exist.get("protected-scope"), obj_dict=obj_dict
            )
            if norm_des_ps != norm_exist_ps:
                diffs["protected-scope"] = FieldChange(
                    field="protected-scope", old_value=list(norm_exist_ps), new_value=list(norm_des_ps)
                )
                update_payload["protected-scope"] = list(norm_des_ps)

    if "install_on" in desired or "install-on" in desired:
        raw_inst = desired.get("install_on") if "install_on" in desired else desired.get("install-on")
        if raw_inst is not None:
            norm_des_inst = normalize_traffic_list(raw_inst, name_resolutions=name_resolutions)
            norm_exist_inst = normalize_traffic_list(
                existing.install_on or raw_exist.get("install-on"),
                obj_dict=obj_dict,
            )
            if norm_des_inst != norm_exist_inst:
                diffs["install-on"] = FieldChange(
                    field="install-on",
                    old_value=list(norm_exist_inst),
                    new_value=list(norm_des_inst),
                )
                update_payload["install-on"] = list(norm_des_inst)

    return diffs, update_payload


__all__ = [
    "compute_object_diff",
    "compute_rule_diff",
    "compute_service_diff",
    "resolve_member_reference",
]
