"""Rulebase pagination (`rulebase/pager.py`) for `show-*-rulebase` commands.

Pages `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, and `show-threat-rulebase`
in chunks of up to 100 rules, merges split `rulebase-section` headers repeated across consecutive
page boundaries, resolves `objects-dictionary` references, and recovers empty trailing sections.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.models.common import utc_now
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseSectionEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.ports import ApiPort
from arodonata.core.telemetry import span_attrs, traced

MAX_RULEBASE_PAGE_LIMIT = 100

RULEBASE_TYPE_TO_COMMAND: dict[RulebaseType, str] = {
    "access": "show-access-rulebase",
    "nat": "show-nat-rulebase",
    "https": "show-https-rulebase",
    "threat": "show-threat-rulebase",
}

SECTION_NODE_TYPES: frozenset[str] = frozenset(
    {
        "access-section",
        "nat-section",
        "https-section",
        "threat-section",
        "rulebase-section",
    }
)


class PagedRulebaseResult(BaseModel):
    """Normalized result of paging a single layer or package NAT rulebase."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    rulebase_type: RulebaseType
    layer_uid: str
    layer_name: str
    package_uid: str | None = None
    package_name: str | None = None
    sections: list[RulebaseSectionEntry] = Field(default_factory=list)
    access_rules: list[AccessRuleEntry] = Field(default_factory=list)
    nat_rules: list[NatRuleEntry] = Field(default_factory=list)
    https_rules: list[HttpsRuleEntry] = Field(default_factory=list)
    threat_rules: list[ThreatRuleEntry] = Field(default_factory=list)
    objects_dictionary: dict[str, dict[str, Any]] = Field(default_factory=dict)
    raw_rules: list[dict[str, Any]] = Field(default_factory=list)
    raw_sections: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


def _is_section_node(node: dict[str, Any]) -> bool:
    node_type = str(node.get("type") or "").strip().lower()
    if node_type in SECTION_NODE_TYPES or node_type.endswith("-section"):
        return True
    return isinstance(node.get("rulebase"), list) and "rule-number" not in node


def _resolve_ref_name(
    val: Any,
    obj_dict: dict[str, dict[str, Any]],
) -> str | None:
    """Resolve a single reference (dict, UID string, or name string) to its display name or UID."""
    if val is None:
        return None
    if isinstance(val, dict):
        name = val.get("name")
        if isinstance(name, str) and name:
            return name
        uid = val.get("uid")
        if isinstance(uid, str) and uid:
            resolved = obj_dict.get(uid)
            if isinstance(resolved, dict) and isinstance(resolved.get("name"), str) and resolved["name"]:
                return str(resolved["name"])
            return uid
        return None
    if isinstance(val, str):
        clean = val.strip()
        if not clean:
            return None
        resolved = obj_dict.get(clean)
        if isinstance(resolved, dict) and isinstance(resolved.get("name"), str) and resolved["name"]:
            return str(resolved["name"])
        return clean
    return str(val)


def _resolve_ref_uid(
    val: Any,
    obj_dict: dict[str, dict[str, Any]],
) -> str | None:
    """Resolve a single reference (dict or string) to its UID if known."""
    if val is None:
        return None
    if isinstance(val, dict):
        uid = val.get("uid")
        if isinstance(uid, str) and uid:
            return uid
        name = val.get("name")
        if isinstance(name, str) and name:
            for k, v in obj_dict.items():
                if v.get("name") == name:
                    return k
            return name
        return None
    if isinstance(val, str):
        clean = val.strip()
        if not clean:
            return None
        if clean in obj_dict:
            return clean
        for k, v in obj_dict.items():
            if v.get("name") == clean:
                return k
        return clean
    return None


def _resolve_ref_list(
    raw_list: Any,
    obj_dict: dict[str, dict[str, Any]],
) -> list[str]:
    """Resolve a list of object/service references to human-readable names (falling back to UIDs)."""
    if raw_list is None:
        return []
    if not isinstance(raw_list, list):
        single = _resolve_ref_name(raw_list, obj_dict)
        return [single] if single else []
    result: list[str] = []
    for item in raw_list:
        name = _resolve_ref_name(item, obj_dict)
        if name:
            result.append(name)
    return result


def _extract_track_name(raw_track: Any, obj_dict: dict[str, dict[str, Any]]) -> str | None:
    if raw_track is None:
        return None
    if isinstance(raw_track, dict):
        t_type = raw_track.get("type")
        if t_type is not None:
            resolved = _resolve_ref_name(t_type, obj_dict)
            if resolved:
                return resolved
        return _resolve_ref_name(raw_track, obj_dict)
    return _resolve_ref_name(raw_track, obj_dict)


def _enrich_rule_raw_data(
    raw_rule: dict[str, Any],
    obj_dict: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Attach resolved object names into a copy of `raw_rule` for downstream consumers."""
    enriched = dict(raw_rule)
    resolved_refs: dict[str, dict[str, Any]] = {}
    for key in (
        "source",
        "destination",
        "service",
        "install-on",
        "protected-scope",
        "site-category",
    ):
        val = raw_rule.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item in obj_dict:
                    resolved_refs[item] = obj_dict[item]
                elif isinstance(item, dict) and isinstance(item.get("uid"), str) and item["uid"] in obj_dict:
                    resolved_refs[item["uid"]] = obj_dict[item["uid"]]
    for key in (
        "action",
        "inline-layer",
        "domain-layer",
        "original-source",
        "original-destination",
        "original-service",
        "translated-source",
        "translated-destination",
        "translated-service",
        "certificate",
    ):
        val = raw_rule.get(key)
        if isinstance(val, str) and val in obj_dict:
            resolved_refs[val] = obj_dict[val]
        elif isinstance(val, dict) and isinstance(val.get("uid"), str) and val["uid"] in obj_dict:
            resolved_refs[val["uid"]] = obj_dict[val["uid"]]
    if isinstance(raw_rule.get("track"), dict):
        t_type = raw_rule["track"].get("type")
        if isinstance(t_type, str) and t_type in obj_dict:
            resolved_refs[t_type] = obj_dict[t_type]
    if resolved_refs:
        enriched["_resolved_objects"] = resolved_refs
    return enriched


def parse_access_rule_entry(
    *,
    mgmt_name: str,
    domain_name: str,
    layer_uid: str,
    layer_name: str,
    raw_rule: dict[str, Any],
    position: int,
    section_uid: str | None = None,
    section_name: str | None = None,
    obj_dict: dict[str, dict[str, Any]] | None = None,
) -> AccessRuleEntry:
    """Convert a raw Check Point access rule or `place-holder` dict into `AccessRuleEntry`."""
    od = obj_dict or {}
    uid = str(raw_rule.get("uid") or f"rule:{layer_uid}:{position}")
    name = str(raw_rule.get("name") or "")
    rule_type = str(raw_rule.get("type") or "access-rule")
    rule_num_raw = raw_rule.get("rule-number")
    rule_number = str(rule_num_raw) if rule_num_raw is not None else None
    enabled = bool(raw_rule.get("enabled", True))
    action = _resolve_ref_name(raw_rule.get("action"), od)

    inline_raw = raw_rule.get("inline-layer")
    inline_uid = _resolve_ref_uid(inline_raw, od)
    inline_name = _resolve_ref_name(inline_raw, od)

    # Check Point Global placeholder rules can expose domain sub-layer under `domain-layer`,
    # `placeholder-domain-layer`, or inline/sub-layer keys when queried with `package` context.
    placeholder_raw = (
        raw_rule.get("domain-layer")
        or raw_rule.get("placeholder-domain-layer")
        or raw_rule.get("placeholder_domain_layer_uid")
        or (inline_raw if rule_type == "place-holder" else None)
    )
    placeholder_uid = _resolve_ref_uid(placeholder_raw, od)

    return AccessRuleEntry(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        layer_uid=layer_uid,
        layer_name=layer_name,
        section_uid=section_uid,
        section_name=section_name,
        uid=uid,
        name=name,
        rule_type=rule_type,
        position=position,
        rule_number=rule_number,
        enabled=enabled,
        action=action,
        inline_layer_uid=inline_uid,
        inline_layer_name=inline_name,
        placeholder_domain_layer_uid=placeholder_uid,
        source=_resolve_ref_list(raw_rule.get("source"), od),
        destination=_resolve_ref_list(raw_rule.get("destination"), od),
        service=_resolve_ref_list(raw_rule.get("service"), od),
        source_negate=bool(raw_rule.get("source-negate", False)),
        destination_negate=bool(raw_rule.get("destination-negate", False)),
        service_negate=bool(raw_rule.get("service-negate", False)),
        track=_extract_track_name(raw_rule.get("track"), od),
        install_on=_resolve_ref_list(raw_rule.get("install-on"), od),
        comments=str(raw_rule.get("comments") or ""),
        raw_data=_enrich_rule_raw_data(raw_rule, od),
        updated_at=utc_now(),
    )


def parse_nat_rule_entry(
    *,
    mgmt_name: str,
    domain_name: str,
    package_uid: str,
    package_name: str,
    raw_rule: dict[str, Any],
    position: int,
    section_uid: str | None = None,
    section_name: str | None = None,
    obj_dict: dict[str, dict[str, Any]] | None = None,
) -> NatRuleEntry:
    """Convert a raw Check Point NAT rule dict into `NatRuleEntry`."""
    od = obj_dict or {}
    uid = str(raw_rule.get("uid") or f"nat-rule:{package_uid}:{position}")
    name = str(raw_rule.get("name") or "")
    rule_type = str(raw_rule.get("type") or "nat-rule")
    rule_num_raw = raw_rule.get("rule-number")
    rule_number = str(rule_num_raw) if rule_num_raw is not None else None
    enabled = bool(raw_rule.get("enabled", True))
    method = str(raw_rule["method"]) if raw_rule.get("method") is not None else None
    auto_generated = bool(raw_rule.get("auto-generated", False))

    return NatRuleEntry(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        package_uid=package_uid,
        package_name=package_name,
        section_uid=section_uid,
        section_name=section_name,
        uid=uid,
        name=name,
        rule_type=rule_type,
        position=position,
        rule_number=rule_number,
        enabled=enabled,
        method=method,
        auto_generated=auto_generated,
        original_source=_resolve_ref_name(raw_rule.get("original-source"), od),
        original_destination=_resolve_ref_name(raw_rule.get("original-destination"), od),
        original_service=_resolve_ref_name(raw_rule.get("original-service"), od),
        translated_source=_resolve_ref_name(raw_rule.get("translated-source"), od),
        translated_destination=_resolve_ref_name(raw_rule.get("translated-destination"), od),
        translated_service=_resolve_ref_name(raw_rule.get("translated-service"), od),
        install_on=_resolve_ref_list(raw_rule.get("install-on"), od),
        comments=str(raw_rule.get("comments") or ""),
        raw_data=_enrich_rule_raw_data(raw_rule, od),
        updated_at=utc_now(),
    )


def parse_https_rule_entry(
    *,
    mgmt_name: str,
    domain_name: str,
    layer_uid: str,
    layer_name: str,
    raw_rule: dict[str, Any],
    position: int,
    section_uid: str | None = None,
    section_name: str | None = None,
    obj_dict: dict[str, dict[str, Any]] | None = None,
) -> HttpsRuleEntry:
    """Convert a raw Check Point HTTPS rule dict into `HttpsRuleEntry`."""
    od = obj_dict or {}
    uid = str(raw_rule.get("uid") or f"https-rule:{layer_uid}:{position}")
    name = str(raw_rule.get("name") or "")
    rule_type = str(raw_rule.get("type") or "https-rule")
    rule_num_raw = raw_rule.get("rule-number")
    rule_number = str(rule_num_raw) if rule_num_raw is not None else None
    enabled = bool(raw_rule.get("enabled", True))
    action = _resolve_ref_name(raw_rule.get("action"), od)
    inline_uid = _resolve_ref_uid(raw_rule.get("inline-layer") or raw_rule.get(" blade"), od)

    return HttpsRuleEntry(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        layer_uid=layer_uid,
        layer_name=layer_name,
        section_uid=section_uid,
        section_name=section_name,
        uid=uid,
        name=name,
        rule_type=rule_type,
        position=position,
        rule_number=rule_number,
        enabled=enabled,
        action=action,
        inline_layer_uid=inline_uid,
        source=_resolve_ref_list(raw_rule.get("source"), od),
        destination=_resolve_ref_list(raw_rule.get("destination"), od),
        service=_resolve_ref_list(raw_rule.get("service"), od),
        site_category=_resolve_ref_list(raw_rule.get("site-category"), od),
        certificate=_resolve_ref_name(raw_rule.get("certificate"), od),
        track=_extract_track_name(raw_rule.get("track"), od),
        install_on=_resolve_ref_list(raw_rule.get("install-on"), od),
        comments=str(raw_rule.get("comments") or ""),
        raw_data=_enrich_rule_raw_data(raw_rule, od),
        updated_at=utc_now(),
    )


def parse_threat_rule_entry(
    *,
    mgmt_name: str,
    domain_name: str,
    layer_uid: str,
    layer_name: str,
    raw_rule: dict[str, Any],
    position: int,
    section_uid: str | None = None,
    section_name: str | None = None,
    obj_dict: dict[str, dict[str, Any]] | None = None,
) -> ThreatRuleEntry:
    """Convert a raw Check Point Threat Prevention rule dict into `ThreatRuleEntry`."""
    od = obj_dict or {}
    uid = str(raw_rule.get("uid") or f"threat-rule:{layer_uid}:{position}")
    name = str(raw_rule.get("name") or "")
    rule_type = str(raw_rule.get("type") or "threat-rule")
    rule_num_raw = raw_rule.get("rule-number")
    rule_number = str(rule_num_raw) if rule_num_raw is not None else None
    enabled = bool(raw_rule.get("enabled", True))
    action = _resolve_ref_name(raw_rule.get("action"), od)

    return ThreatRuleEntry(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        layer_uid=layer_uid,
        layer_name=layer_name,
        section_uid=section_uid,
        section_name=section_name,
        uid=uid,
        name=name,
        rule_type=rule_type,
        position=position,
        rule_number=rule_number,
        enabled=enabled,
        action=action,
        protected_scope=_resolve_ref_list(raw_rule.get("protected-scope"), od),
        source=_resolve_ref_list(raw_rule.get("source"), od),
        destination=_resolve_ref_list(raw_rule.get("destination"), od),
        service=_resolve_ref_list(raw_rule.get("service"), od),
        track=_extract_track_name(raw_rule.get("track"), od),
        install_on=_resolve_ref_list(raw_rule.get("install-on"), od),
        comments=str(raw_rule.get("comments") or ""),
        raw_data=_enrich_rule_raw_data(raw_rule, od),
        updated_at=utc_now(),
    )


@traced
async def fetch_paged_rulebase(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str | None,
    *,
    rulebase_type: RulebaseType,
    layer_uid: str = "",
    layer_name: str = "",
    package_uid: str | None = None,
    package_name: str | None = None,
    details_level: str = "standard",
    use_object_dictionary: bool = True,
    limit: int = MAX_RULEBASE_PAGE_LIMIT,
    extra_payload: dict[str, Any] | None = None,
    sid: str | None = None,
    server_ip: str | None = None,
) -> PagedRulebaseResult:
    """Page `show-*-rulebase` in chunks of up to 100 rules, stitching split sections and preserving empty trailing sections."""
    page_limit = max(1, min(int(limit), MAX_RULEBASE_PAGE_LIMIT))
    command = RULEBASE_TYPE_TO_COMMAND[rulebase_type]
    eff_domain = domain_name or ""

    target_layer_uid = layer_uid
    target_layer_name = layer_name
    if rulebase_type == "nat":
        target_layer_uid = target_layer_uid or (package_uid or package_name or "")
        target_layer_name = target_layer_name or (package_name or package_uid or "")

    span_attrs(
        mgmt_name=mgmt_name,
        domain=domain_name,
        rulebase_type=rulebase_type,
        layer_uid=target_layer_uid or None,
        layer_name=target_layer_name or None,
        package_name=package_name,
        limit=page_limit,
    )

    combined_obj_dict: dict[str, dict[str, Any]] = {}
    sections_by_key: dict[str, RulebaseSectionEntry] = {}
    section_order: list[str] = []
    raw_sections_by_key: dict[str, dict[str, Any]] = {}

    seen_rule_uids: set[str] = set()
    ordered_raw_rules: list[tuple[dict[str, Any], str | None, str | None]] = []

    offset = 0
    total_reported: int | None = None
    resolved_layer_uid = target_layer_uid
    resolved_layer_name = target_layer_name
    did_trailing_probe = False

    while True:
        payload: dict[str, Any] = {
            "limit": page_limit,
            "offset": offset,
            "details-level": details_level,
            "use-object-dictionary": use_object_dictionary,
        }
        if rulebase_type == "nat":
            pkg_identifier = package_name or package_uid or target_layer_name or target_layer_uid
            if pkg_identifier:
                payload["package"] = pkg_identifier
        else:
            if target_layer_uid:
                payload["uid"] = target_layer_uid
            elif target_layer_name:
                payload["name"] = target_layer_name
            if package_name:
                payload["package"] = package_name
            elif package_uid:
                payload["package"] = package_uid

        if extra_payload:
            payload.update(extra_payload)

        res = await api.api_call(
            mgmt_name,
            command,
            payload,
            domain=domain_name,
            sid=sid,
            server_ip=server_ip,
        )
        if not res.success:
            raise RuntimeError(
                f"Failed to fetch {command} for {target_layer_name or target_layer_uid or package_name!r} "
                f"on {mgmt_name}:{eff_domain}: {res.error_message or res.error_code or 'API error'}"
            )

        data = res.data if isinstance(res.data, dict) else {}
        if not resolved_layer_uid and isinstance(data.get("uid"), str) and data["uid"]:
            resolved_layer_uid = str(data["uid"])
        if not resolved_layer_name and isinstance(data.get("name"), str) and data["name"]:
            resolved_layer_name = str(data["name"])

        # Collect objects-dictionary entries from this page
        raw_obj_dict = data.get("objects-dictionary")
        if isinstance(raw_obj_dict, list):
            for obj_item in raw_obj_dict:
                if isinstance(obj_item, dict) and isinstance(obj_item.get("uid"), str):
                    combined_obj_dict[obj_item["uid"]] = obj_item
        elif isinstance(raw_obj_dict, dict):
            for k, v in raw_obj_dict.items():
                if isinstance(v, dict):
                    combined_obj_dict[str(k)] = v

        raw_rulebase = data.get("rulebase")
        nodes = raw_rulebase if isinstance(raw_rulebase, list) else []

        if total_reported is None and isinstance(data.get("total"), int):
            total_reported = int(data["total"])

        rules_seen_in_page = 0

        for node in nodes:
            if not isinstance(node, dict):
                continue
            if _is_section_node(node):
                sec_uid = str(node.get("uid") or node.get("name") or f"sec:{len(section_order) + 1}")
                sec_name = str(node.get("name") or "")
                from_val = node.get("from")
                to_val = node.get("to")
                sec_from = int(from_val) if isinstance(from_val, int) and from_val > 0 else None
                sec_to = int(to_val) if isinstance(to_val, int) and to_val > 0 else None

                nested_items = node.get("rulebase")
                child_rules = nested_items if isinstance(nested_items, list) else []

                if sec_uid not in sections_by_key:
                    sec_pos = len(section_order) + 1
                    eff_l_uid = resolved_layer_uid or target_layer_uid or (package_uid or "")
                    eff_l_name = resolved_layer_name or target_layer_name or (package_name or "")
                    sec_entry = RulebaseSectionEntry(
                        mgmt_name=mgmt_name,
                        domain_name=eff_domain,
                        layer_uid=eff_l_uid,
                        layer_name=eff_l_name,
                        rulebase_type=rulebase_type,
                        uid=sec_uid,
                        name=sec_name,
                        position=sec_pos,
                        from_rule=sec_from,
                        to_rule=sec_to,
                        rule_uids=[],
                        raw_data=dict(node),
                        updated_at=utc_now(),
                    )
                    sections_by_key[sec_uid] = sec_entry
                    section_order.append(sec_uid)
                    raw_sections_by_key[sec_uid] = dict(node)
                    raw_sections_by_key[sec_uid]["rulebase"] = []
                else:
                    sec_entry = sections_by_key[sec_uid]
                    if sec_entry.from_rule is None and sec_from is not None:
                        sec_entry.from_rule = sec_from
                    if sec_to is not None:
                        sec_entry.to_rule = sec_to
                        raw_sections_by_key[sec_uid]["to"] = sec_to

                for child in child_rules:
                    if not isinstance(child, dict):
                        continue
                    rules_seen_in_page += 1
                    r_uid = str(child.get("uid") or f"rule:{len(ordered_raw_rules) + 1}")
                    if r_uid not in sec_entry.rule_uids:
                        sec_entry.rule_uids.append(r_uid)
                        raw_sections_by_key[sec_uid]["rulebase"].append(child)
                    if r_uid not in seen_rule_uids:
                        seen_rule_uids.add(r_uid)
                        ordered_raw_rules.append((child, sec_uid, sec_name))
            else:
                rules_seen_in_page += 1
                r_uid = str(node.get("uid") or f"rule:{len(ordered_raw_rules) + 1}")
                if r_uid not in seen_rule_uids:
                    seen_rule_uids.add(r_uid)
                    ordered_raw_rules.append((node, None, None))

        to_index = data.get("to")
        if isinstance(to_index, int) and to_index > offset:
            next_offset = to_index
        elif rules_seen_in_page > 0:
            next_offset = offset + rules_seen_in_page
        else:
            break

        if total_reported is not None:
            if next_offset < total_reported and rules_seen_in_page > 0:
                offset = next_offset
                continue
            # If we just reached total_reported on a full page boundary (e.g. 100 of 100),
            # do a single trailing probe at offset=total_reported in case Check Point has
            # an empty trailing section after the last rule.
            if (
                not did_trailing_probe
                and total_reported > 0
                and next_offset == total_reported
                and rules_seen_in_page >= page_limit
            ):
                did_trailing_probe = True
                offset = next_offset
                continue
            break

        if rules_seen_in_page < page_limit:
            break
        offset = next_offset

    final_layer_uid = resolved_layer_uid or target_layer_uid or (package_uid or "")
    final_layer_name = resolved_layer_name or target_layer_name or (package_name or "")
    final_pkg_uid = package_uid or final_layer_uid
    final_pkg_name = package_name or final_layer_name

    # Finalize section entries with resolved layer_uid/layer_name and from_rule/to_rule bounds
    rule_pos_by_uid: dict[str, int] = {}
    access_rules: list[AccessRuleEntry] = []
    nat_rules: list[NatRuleEntry] = []
    https_rules: list[HttpsRuleEntry] = []
    threat_rules: list[ThreatRuleEntry] = []
    raw_rules_list: list[dict[str, Any]] = []

    for idx, (raw_rule, rule_sec_uid, rule_sec_name) in enumerate(ordered_raw_rules, start=1):
        raw_rules_list.append(raw_rule)
        r_uid = str(raw_rule.get("uid") or f"rule:{idx}")
        rule_pos_by_uid[r_uid] = idx

        if rulebase_type == "access":
            access_rules.append(
                parse_access_rule_entry(
                    mgmt_name=mgmt_name,
                    domain_name=eff_domain,
                    layer_uid=final_layer_uid,
                    layer_name=final_layer_name,
                    raw_rule=raw_rule,
                    position=idx,
                    section_uid=rule_sec_uid,
                    section_name=rule_sec_name,
                    obj_dict=combined_obj_dict,
                )
            )
        elif rulebase_type == "nat":
            nat_rules.append(
                parse_nat_rule_entry(
                    mgmt_name=mgmt_name,
                    domain_name=eff_domain,
                    package_uid=final_pkg_uid,
                    package_name=final_pkg_name,
                    raw_rule=raw_rule,
                    position=idx,
                    section_uid=rule_sec_uid,
                    section_name=rule_sec_name,
                    obj_dict=combined_obj_dict,
                )
            )
        elif rulebase_type == "https":
            https_rules.append(
                parse_https_rule_entry(
                    mgmt_name=mgmt_name,
                    domain_name=eff_domain,
                    layer_uid=final_layer_uid,
                    layer_name=final_layer_name,
                    raw_rule=raw_rule,
                    position=idx,
                    section_uid=rule_sec_uid,
                    section_name=rule_sec_name,
                    obj_dict=combined_obj_dict,
                )
            )
        elif rulebase_type == "threat":
            threat_rules.append(
                parse_threat_rule_entry(
                    mgmt_name=mgmt_name,
                    domain_name=eff_domain,
                    layer_uid=final_layer_uid,
                    layer_name=final_layer_name,
                    raw_rule=raw_rule,
                    position=idx,
                    section_uid=rule_sec_uid,
                    section_name=rule_sec_name,
                    obj_dict=combined_obj_dict,
                )
            )

    final_sections: list[RulebaseSectionEntry] = []
    final_raw_sections: list[dict[str, Any]] = []
    for pos, s_key in enumerate(section_order, start=1):
        sec = sections_by_key[s_key]
        positions = [rule_pos_by_uid[u] for u in sec.rule_uids if u in rule_pos_by_uid]
        from_pos = min(positions) if positions else sec.from_rule
        to_pos = max(positions) if positions else sec.to_rule
        if not sec.rule_uids:
            from_pos = None
            to_pos = None
        updated_sec = RulebaseSectionEntry(
            mgmt_name=mgmt_name,
            domain_name=eff_domain,
            layer_uid=final_layer_uid,
            layer_name=final_layer_name,
            rulebase_type=rulebase_type,
            uid=sec.uid,
            name=sec.name,
            position=pos,
            from_rule=from_pos,
            to_rule=to_pos,
            rule_uids=list(sec.rule_uids),
            raw_data=dict(raw_sections_by_key.get(s_key, sec.raw_data)),
            updated_at=utc_now(),
        )
        final_sections.append(updated_sec)
        final_raw_sections.append(raw_sections_by_key[s_key])

    return PagedRulebaseResult(
        mgmt_name=mgmt_name,
        domain_name=eff_domain,
        rulebase_type=rulebase_type,
        layer_uid=final_layer_uid,
        layer_name=final_layer_name,
        package_uid=package_uid,
        package_name=package_name,
        sections=final_sections,
        access_rules=access_rules,
        nat_rules=nat_rules,
        https_rules=https_rules,
        threat_rules=threat_rules,
        objects_dictionary=combined_obj_dict,
        raw_rules=raw_rules_list,
        raw_sections=final_raw_sections,
        total=len(ordered_raw_rules),
    )


__all__ = [
    "MAX_RULEBASE_PAGE_LIMIT",
    "PagedRulebaseResult",
    "RULEBASE_TYPE_TO_COMMAND",
    "fetch_paged_rulebase",
    "parse_access_rule_entry",
    "parse_https_rule_entry",
    "parse_nat_rule_entry",
    "parse_threat_rule_entry",
]
