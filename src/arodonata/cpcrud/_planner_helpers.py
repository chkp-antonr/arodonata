"""Shared constants, reference extractors, prior-state builders, and payload builders (`arodonata.cpcrud._planner_helpers`)."""

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
from arodonata.cpcrud.differ import DiffSafetyError, resolve_member_reference
from arodonata.cpcrud.models import FieldChange, Outcome, PlannedAction
from arodonata.cpcrud.rule_identity import (
    RuleEntryUnion,
    build_effective_obj_dict,
    deref_rule_list,
    normalize_nat_traffic_ref,
    normalize_traffic_list,
    rule_spec_has_delta_mapping,
)
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES, normalize_mask_length

LOOKUP_ERROR_PREFIX = "lookup failed, nothing planned (re-plan to retry): "

RULE_OPERATION_TYPES: frozenset[str] = frozenset(
    {
        "access-rule",
        "nat-rule",
        "https-rule",
        "threat-rule",
        "access",
        "nat",
        "https",
        "threat",
    }
)

CANONICAL_CPCRUD_TYPES: frozenset[str] = OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | RULE_OPERATION_TYPES


def _entity_wire_identity(existing: CPObject | CPService) -> dict[str, Any]:
    """Return concrete Check Point wire selector (`uid` when real, else `name`) for `set`/`delete` payloads."""
    if existing.uid and not existing.uid.startswith("planned:"):
        return {"uid": existing.uid}
    return {"name": existing.name}


def _make_error_action(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    operation: str,
    object_type: str,
    name: str,
    desired_spec: Mapping[str, Any],
    error: str,
    requested_name: str | None = None,
    resolved_name: str | None = None,
    target_uid: str | None = None,
    layer: str | None = None,
    package: str | None = None,
    prior_state: dict[str, Any] | None = None,
    diffs: dict[str, FieldChange] | None = None,
) -> PlannedAction:
    return PlannedAction(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation=operation,
        object_type=object_type,
        name=name,
        requested_name=requested_name if requested_name is not None else name,
        resolved_name=resolved_name if resolved_name is not None else name,
        target_uid=target_uid,
        layer=layer,
        package=package,
        outcome=Outcome.ERROR,
        status="error",
        diffs=diffs or {},
        prior_state=prior_state,
        desired_spec=dict(desired_spec),
        message=error,
        error=error,
    )


def _normalize_verb(spec: Mapping[str, Any], *, is_rule: bool = False) -> str:
    """Resolve the desired operation verb (`present` / `add`, `set` / `update`, `absent` / `delete`)."""
    raw_op = spec.get("operation") or spec.get("state")
    if raw_op is None and not is_rule:
        raw_op = spec.get("action")
    elif raw_op is None and is_rule:
        cand = spec.get("action")
        if isinstance(cand, str) and cand.strip().lower() in (
            "present",
            "absent",
            "add",
            "set",
            "update",
            "delete",
        ):
            raw_op = cand
    verb = str(raw_op or "present").strip().lower()
    if verb in ("absent", "delete"):
        return "delete"
    if verb in ("set", "update"):
        return "set"
    return "present"


def _resolve_rulebase_type(spec: Mapping[str, Any]) -> tuple[RulebaseType, str]:
    """Return `(rulebase_type, canonical_rule_type)` for a rule operation dict."""
    raw_rb = str(spec.get("rulebase_type") or spec.get("type") or "").strip().lower()
    if raw_rb and raw_rb not in RULE_OPERATION_TYPES:
        raise ValidationError(f"Unsupported CPCRUD rule type: {raw_rb!r}")
    if raw_rb in ("nat", "nat-rule") or any(
        k in spec
        for k in (
            "original_source",
            "original-source",
            "translated_source",
            "translated-source",
            "method",
        )
    ):
        return "nat", "nat-rule"
    if raw_rb in ("https", "https-rule"):
        return "https", "https-rule"
    if raw_rb in ("threat", "threat-rule"):
        return "threat", "threat-rule"
    return "access", "access-rule"


def _extract_rule_references(spec: Mapping[str, Any]) -> set[str]:
    """Collect object/service names referenced by a rule specification for dependency checking."""
    refs: set[str] = set()
    for list_key in (
        "source",
        "destination",
        "service",
        "install_on",
        "install-on",
        "protected_scope",
        "protected-scope",
        "site_category",
        "site-category",
    ):
        val = spec.get(list_key)
        if isinstance(val, str) and val.strip():
            refs.add(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    refs.add(item.strip())
        elif isinstance(val, Mapping):
            add_items = val.get("add")
            if isinstance(add_items, list):
                for item in add_items:
                    if isinstance(item, str) and item.strip():
                        refs.add(item.strip())
    for str_key in (
        "original_source",
        "original-source",
        "original_destination",
        "original-destination",
        "original_service",
        "original-service",
        "translated_source",
        "translated-source",
        "translated_destination",
        "translated-destination",
        "translated_service",
        "translated-service",
    ):
        val = spec.get(str_key)
        if isinstance(val, str) and val.strip():
            refs.add(val.strip())
    refs.discard("Any")
    refs.discard("any")
    refs.discard("Original")
    refs.discard("original")
    return refs


def _extract_group_references(spec: Mapping[str, Any]) -> set[str]:
    """Collect member names referenced by a group or service-group specification."""
    refs: set[str] = set()
    members = spec.get("members")
    if isinstance(members, list):
        for m in members:
            if isinstance(m, str) and m.strip():
                refs.add(m.strip())
    elif isinstance(members, dict):
        for k in ("add", "remove"):
            sub = members.get(k)
            if isinstance(sub, list):
                for m in sub:
                    if isinstance(m, str) and m.strip():
                        refs.add(m.strip())
    return refs


def _extract_prior_members(existing_members: Sequence[str], raw_data: Mapping[str, Any] | None) -> list[str]:
    """Extract readable member names (or UIDs) from `raw_data['members']` or `existing_members`."""
    raw_members = raw_data.get("members") if isinstance(raw_data, Mapping) else None
    if isinstance(raw_members, list):
        names: list[str] = []
        for m in raw_members:
            if isinstance(m, Mapping):
                val = m.get("name") or m.get("uid")
                if val is not None and str(val).strip():
                    names.append(str(val).strip())
            elif isinstance(m, str) and m.strip():
                names.append(m.strip())
        if names:
            return names
        if len(raw_members) == 0:
            return []
    return list(existing_members)


def _extract_raw_group_names(raw_data: Mapping[str, Any] | None) -> list[str]:
    """Extract parent group names from `raw_data['groups']` if present."""
    if not isinstance(raw_data, Mapping):
        return []
    raw_grps = raw_data.get("groups")
    if not isinstance(raw_grps, list) or not raw_grps:
        return []
    grp_names: list[str] = []
    for g in raw_grps:
        if isinstance(g, Mapping):
            val = g.get("name") or g.get("uid")
            if val:
                grp_names.append(str(val))
        elif isinstance(g, str) and g:
            grp_names.append(g)
    return grp_names


def _build_prior_object_state(obj: CPObject) -> dict[str, Any]:
    """Capture reversible state from an existing `CPObject` for `build_inverse_template`."""
    state: dict[str, Any] = {
        "uid": obj.uid,
        "name": obj.name,
        "type": obj.type,
        "comments": obj.comments,
    }
    if obj.color:
        state["color"] = obj.color
    if obj.tags:
        state["tags"] = list(obj.tags)
    if obj.type == "host":
        if obj.ipv4_address:
            state["ipv4-address"] = obj.ipv4_address
        if obj.ipv6_address:
            state["ipv6-address"] = obj.ipv6_address
    elif obj.type == "network":
        if obj.subnet4:
            state["subnet4"] = obj.subnet4
        mask = normalize_mask_length(obj.mask_length4, obj.subnet_mask)
        if mask is not None:
            state["mask-length4"] = mask
    elif obj.type == "address-range":
        if obj.ipv4_address_first:
            state["ipv4-address-first"] = obj.ipv4_address_first
        if obj.ipv4_address_last:
            state["ipv4-address-last"] = obj.ipv4_address_last
    elif obj.type == "dns-domain":
        if obj.is_sub_domain is not None:
            state["is-sub-domain"] = obj.is_sub_domain
    elif obj.type == "group":
        state["members"] = _extract_prior_members(obj.members, obj.raw_data)
    elif obj.type == "application-site":
        if obj.primary_category:
            state["primary-category"] = obj.primary_category
        if obj.url_list:
            state["url-list"] = list(obj.url_list)
        if obj.urls_defined_as_regular_expression is not None:
            state["urls-defined-as-regular-expression"] = obj.urls_defined_as_regular_expression
        if obj.description:
            state["description"] = obj.description
        if isinstance(obj.raw_data, dict):
            raw_sig = obj.raw_data.get("application-signature") or obj.raw_data.get("application_signature")
            if isinstance(raw_sig, str) and raw_sig.strip():
                state["application-signature"] = raw_sig.strip()
            raw_add_cats = obj.raw_data.get("additional-categories") or obj.raw_data.get("additional_categories")
            if isinstance(raw_add_cats, list) and raw_add_cats:
                state["additional-categories"] = [str(c) for c in raw_add_cats if str(c)]
    if obj.nat_settings:
        state["nat-settings"] = dict(obj.nat_settings)
    grp_names = _extract_raw_group_names(obj.raw_data)
    if grp_names:
        state["groups"] = grp_names
    return state


def _build_prior_service_state(svc: CPService) -> dict[str, Any]:
    """Capture reversible state from an existing `CPService` for `build_inverse_template`."""
    state: dict[str, Any] = {
        "uid": svc.uid,
        "name": svc.name,
        "type": svc.type,
        "comments": svc.comments,
    }
    if svc.color:
        state["color"] = svc.color
    if svc.tags:
        state["tags"] = list(svc.tags)
    if svc.port is not None:
        state["port"] = svc.port
    if svc.protocol is not None:
        state["protocol"] = svc.protocol
    if svc.icmp_type is not None:
        state["icmp-type"] = svc.icmp_type
    if svc.icmp_code is not None:
        state["icmp-code"] = svc.icmp_code
    if svc.session_timeout is not None:
        state["session-timeout"] = svc.session_timeout
    if svc.match_for_any is not None:
        state["match-for-any"] = svc.match_for_any
    if svc.type == "service-group":
        state["members"] = _extract_prior_members(svc.members, svc.raw_data)
    grp_names = _extract_raw_group_names(svc.raw_data)
    if grp_names:
        state["groups"] = grp_names
    return state


def _build_prior_rule_state(
    rule: RuleEntryUnion,
    *,
    rulebase_type: RulebaseType,
    layer: str | None,
    package: str | None,
    obj_dict: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Capture reversible state from an existing rule for `build_inverse_template`."""
    raw_exist = rule.raw_data or {}
    eff_obj_dict = build_effective_obj_dict(raw_exist, obj_dict)

    state: dict[str, Any] = {
        "uid": rule.uid,
        "name": rule.name,
        "type": f"{rulebase_type}-rule",
        "rulebase_type": rulebase_type,
        "enabled": rule.enabled,
        "comments": rule.comments,
        "position": rule.position if rule.position > 0 else "bottom",
    }
    if layer:
        state["layer"] = layer
    if package:
        state["package"] = package
    if isinstance(rule, NatRuleEntry):
        state["method"] = rule.method or "static"
        for snake_attr, kebab_key, is_trans in (
            ("original_source", "original-source", False),
            ("original_destination", "original-destination", False),
            ("original_service", "original-service", False),
            ("translated_source", "translated-source", True),
            ("translated_destination", "translated-destination", True),
            ("translated_service", "translated-service", True),
        ):
            attr_val = getattr(rule, snake_attr)
            state[kebab_key] = normalize_nat_traffic_ref(
                attr_val if attr_val is not None else raw_exist.get(kebab_key),
                is_translated=is_trans,
                obj_dict=eff_obj_dict,
            )
        inst_list = deref_rule_list(rule.install_on, raw_exist.get("install-on"), eff_obj_dict)
        if inst_list:
            state["install-on"] = inst_list
    else:
        state["source"] = deref_rule_list(rule.source, raw_exist.get("source"), eff_obj_dict, default_any=True)
        state["destination"] = deref_rule_list(
            rule.destination, raw_exist.get("destination"), eff_obj_dict, default_any=True
        )
        state["service"] = deref_rule_list(rule.service, raw_exist.get("service"), eff_obj_dict, default_any=True)
        if rule.action:
            act_val = rule.action
            if act_val in eff_obj_dict:
                act_val = str(eff_obj_dict[act_val].get("name") or act_val)
            state["rule_action"] = act_val
        if rule.track:
            trk_val = rule.track
            if trk_val in eff_obj_dict:
                trk_val = str(eff_obj_dict[trk_val].get("name") or trk_val)
            state["track"] = trk_val
        inst_list = deref_rule_list(rule.install_on, raw_exist.get("install-on"), eff_obj_dict)
        if inst_list:
            state["install-on"] = inst_list
        if isinstance(rule, AccessRuleEntry):
            state["source-negate"] = bool(rule.source_negate)
            state["destination-negate"] = bool(rule.destination_negate)
            state["service-negate"] = bool(rule.service_negate)
            inline_ref = rule.inline_layer_name or rule.inline_layer_uid
            if inline_ref:
                if inline_ref in eff_obj_dict:
                    inline_ref = str(eff_obj_dict[inline_ref].get("name") or inline_ref)
                state["inline-layer"] = inline_ref
        elif isinstance(rule, HttpsRuleEntry):
            sc_list = deref_rule_list(rule.site_category, raw_exist.get("site-category"), eff_obj_dict)
            if sc_list:
                state["site-category"] = sc_list
            if rule.certificate:
                state["certificate"] = rule.certificate
            if rule.inline_layer_uid:
                inline_ref = rule.inline_layer_uid
                if inline_ref in eff_obj_dict:
                    inline_ref = str(eff_obj_dict[inline_ref].get("name") or inline_ref)
                state["inline-layer"] = inline_ref
        elif isinstance(rule, ThreatRuleEntry):
            ps_list = deref_rule_list(rule.protected_scope, raw_exist.get("protected-scope"), eff_obj_dict)
            if ps_list:
                state["protected-scope"] = ps_list
    return state


def _extract_add_url_list(spec: Mapping[str, Any]) -> list[str]:
    """Extract initial `url-list` entries from a list or `{add, remove}` mapping."""
    raw_urls = spec.get("url-list") if "url-list" in spec else spec.get("url_list")
    if isinstance(raw_urls, list):
        return list(dict.fromkeys(str(u).strip() for u in raw_urls if str(u).strip()))
    if isinstance(raw_urls, Mapping):
        raw_add = raw_urls.get("add")
        if isinstance(raw_add, list):
            return list(dict.fromkeys(str(u).strip() for u in raw_add if str(u).strip()))
    return []


def _append_common_create_metadata(payload: dict[str, Any], spec: Mapping[str, Any]) -> None:
    """Populate common metadata and flags (`comments`, `color`, `tags`, `groups`, `ignore-warnings`, `set-if-exists`)."""
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])
    if "color" in spec and spec["color"] is not None:
        payload["color"] = str(spec["color"])
    if "tags" in spec and isinstance(spec["tags"], list):
        payload["tags"] = [str(t) for t in spec["tags"]]
    if "groups" in spec and isinstance(spec["groups"], list):
        payload["groups"] = [str(g) for g in spec["groups"]]
    ig_warn = spec.get("ignore_warnings") if "ignore_warnings" in spec else spec.get("ignore-warnings")
    if isinstance(ig_warn, bool):
        payload["ignore-warnings"] = ig_warn
    set_exist = spec.get("set_if_exists") if "set_if_exists" in spec else spec.get("set-if-exists")
    if isinstance(set_exist, bool):
        payload["set-if-exists"] = set_exist


def _build_add_object_payload(
    obj_type: str,
    name: str,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    if obj_type == "host":
        ipv4 = spec.get("ipv4_address") or spec.get("ipv4-address") or spec.get("ip_address") or spec.get("ip-address")
        ipv6 = spec.get("ipv6_address") or spec.get("ipv6-address")
        if isinstance(ipv4, str) and ipv4.strip():
            payload["ipv4-address"] = ipv4.strip()
        if isinstance(ipv6, str) and ipv6.strip():
            payload["ipv6-address"] = ipv6.strip()
    elif obj_type == "network":
        sub = spec.get("subnet4") or spec.get("subnet")
        if isinstance(sub, str) and sub.strip():
            payload["subnet4"] = sub.strip()
        mask = normalize_mask_length(
            spec.get("mask_length4") if "mask_length4" in spec else spec.get("mask-length4"),
            spec.get("subnet_mask") or spec.get("subnet-mask"),
            strict=True,
        )
        if mask is not None:
            payload["mask-length4"] = mask
    elif obj_type == "address-range":
        first_ip = spec.get("ipv4_address_first") or spec.get("ipv4-address-first")
        last_ip = spec.get("ipv4_address_last") or spec.get("ipv4-address-last")
        if isinstance(first_ip, str) and first_ip.strip():
            payload["ipv4-address-first"] = first_ip.strip()
        if isinstance(last_ip, str) and last_ip.strip():
            payload["ipv4-address-last"] = last_ip.strip()
    elif obj_type == "dns-domain":
        is_sub = spec.get("is_sub_domain") if "is_sub_domain" in spec else spec.get("is-sub-domain")
        payload["is-sub-domain"] = bool(is_sub) if is_sub is not None else False
    elif obj_type == "application-site":
        url_list = _extract_add_url_list(spec)
        raw_cat = spec.get("primary-category") or spec.get("primary_category")
        payload["primary-category"] = (
            raw_cat.strip() if isinstance(raw_cat, str) and raw_cat.strip() else "Custom_Application_Site"
        )
        if url_list:
            payload["url-list"] = url_list
        if "urls-defined-as-regular-expression" in spec or "urls_defined_as_regular_expression" in spec:
            raw_regex = (
                spec.get("urls-defined-as-regular-expression")
                if "urls-defined-as-regular-expression" in spec
                else spec.get("urls_defined_as_regular_expression")
            )
            if raw_regex is not None:
                payload["urls-defined-as-regular-expression"] = bool(raw_regex)
        if "description" in spec and spec["description"] is not None:
            payload["description"] = str(spec["description"])
        raw_sig = spec.get("application-signature") or spec.get("application_signature")
        if isinstance(raw_sig, str) and raw_sig.strip():
            payload["application-signature"] = raw_sig.strip()
        raw_add_cats = (
            spec.get("additional-categories") if "additional-categories" in spec else spec.get("additional_categories")
        )
        if isinstance(raw_add_cats, list):
            payload["additional-categories"] = [str(c).strip() for c in raw_add_cats if str(c).strip()]

    nat_s = spec.get("nat_settings") if "nat_settings" in spec else spec.get("nat-settings")
    if isinstance(nat_s, dict):
        payload["nat-settings"] = dict(nat_s)
    _append_common_create_metadata(payload, spec)
    return payload


def _build_add_service_payload(
    svc_type: str,
    name: str,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    if spec.get("port") is not None:
        payload["port"] = str(spec["port"]).strip()
    proto = spec.get("protocol") or spec.get("ip_protocol") or spec.get("ip-protocol")
    if proto is not None:
        payload["ip-protocol" if svc_type == "service-other" else "protocol"] = proto
    icmp_t = spec.get("icmp_type") if "icmp_type" in spec else spec.get("icmp-type")
    if isinstance(icmp_t, int):
        payload["icmp-type"] = icmp_t
    icmp_c = spec.get("icmp_code") if "icmp_code" in spec else spec.get("icmp-code")
    if isinstance(icmp_c, int):
        payload["icmp-code"] = icmp_c
    s_to = spec.get("session_timeout") if "session_timeout" in spec else spec.get("session-timeout")
    if isinstance(s_to, int):
        payload["session-timeout"] = s_to
    mfa = spec.get("match_for_any") if "match_for_any" in spec else spec.get("match-for-any")
    if isinstance(mfa, bool):
        payload["match-for-any"] = mfa
    _append_common_create_metadata(payload, spec)
    return payload


def _build_add_group_payload(
    name: str,
    spec: Mapping[str, Any],
    *,
    name_resolutions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    raw_members = spec.get("members")
    if isinstance(raw_members, list):
        payload["members"] = [resolve_member_reference(str(m), name_resolutions) for m in raw_members]
    elif isinstance(raw_members, dict):
        adds = raw_members.get("add") or []
        payload["members"] = [resolve_member_reference(str(m), name_resolutions) for m in adds]
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])
    if "color" in spec and spec["color"] is not None:
        payload["color"] = str(spec["color"])
    if "tags" in spec and isinstance(spec["tags"], list):
        payload["tags"] = [str(t) for t in spec["tags"]]
    return payload


def _build_add_rule_payload(
    *,
    rb_type: RulebaseType,
    spec: Mapping[str, Any],
    layer: str,
    package: str,
    position: str | int | dict[str, str],
    name_resolutions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if rule_spec_has_delta_mapping(spec):
        raise DiffSafetyError("Cannot build add-*-rule payload with incremental {add, remove} cell deltas.")
    payload: dict[str, Any] = {"position": position}
    if spec.get("name"):
        payload["name"] = str(spec["name"]).strip()
    if "enabled" in spec and spec["enabled"] is not None:
        payload["enabled"] = bool(spec["enabled"])
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])

    if rb_type == "nat":
        payload["package"] = package
        payload["method"] = str(spec.get("method") or "static").strip().lower()
        for snake_k, kebab_k, is_trans in (
            ("original_source", "original-source", False),
            ("original_destination", "original-destination", False),
            ("original_service", "original-service", False),
            ("translated_source", "translated-source", True),
            ("translated_destination", "translated-destination", True),
            ("translated_service", "translated-service", True),
        ):
            payload[kebab_k] = normalize_nat_traffic_ref(
                spec.get(snake_k, spec.get(kebab_k)),
                is_translated=is_trans,
                name_resolutions=name_resolutions,
            )
    else:
        payload["layer"] = layer
        payload["source"] = list(normalize_traffic_list(spec.get("source"), name_resolutions=name_resolutions))
        payload["destination"] = list(
            normalize_traffic_list(spec.get("destination"), name_resolutions=name_resolutions)
        )
        payload["service"] = list(normalize_traffic_list(spec.get("service"), name_resolutions=name_resolutions))
        raw_act = spec.get("rule_action")
        if raw_act is None and "action" in spec:
            cand = spec["action"]
            if isinstance(cand, str) and cand.lower() not in ("present", "absent", "add", "set", "update", "delete"):
                raw_act = cand
        payload["action"] = str(raw_act or "Accept").strip()
        if "track" in spec and spec["track"] is not None:
            t_val = spec["track"]
            payload["track"] = {"type": t_val} if isinstance(t_val, str) else t_val
        for snake_k, kebab_k in (
            ("source_negate", "source-negate"),
            ("destination_negate", "destination-negate"),
            ("service_negate", "service-negate"),
        ):
            if snake_k in spec or kebab_k in spec:
                neg_v = spec.get(snake_k) if snake_k in spec else spec.get(kebab_k)
                if neg_v is not None:
                    payload[kebab_k] = bool(neg_v)
        inline_val = spec.get("inline_layer") or spec.get("inline-layer")
        if isinstance(inline_val, str) and inline_val.strip():
            payload["inline-layer"] = inline_val.strip()
        sc_val = spec.get("site_category") if "site_category" in spec else spec.get("site-category")
        if sc_val is not None:
            payload["site-category"] = list(normalize_traffic_list(sc_val, name_resolutions=name_resolutions))
        if isinstance(spec.get("certificate"), str) and spec["certificate"].strip():
            payload["certificate"] = spec["certificate"].strip()
        ps_val = spec.get("protected_scope") if "protected_scope" in spec else spec.get("protected-scope")
        if ps_val is not None:
            payload["protected-scope"] = list(normalize_traffic_list(ps_val, name_resolutions=name_resolutions))

    inst_val = spec.get("install_on") if "install_on" in spec else spec.get("install-on")
    if inst_val is not None:
        payload["install-on"] = list(normalize_traffic_list(inst_val, name_resolutions=name_resolutions))

    return payload
