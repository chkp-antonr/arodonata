"""Per-entity planning helpers for objects, services, and groups (`arodonata.cpcrud._planner_entity_steps`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.cpcrud._planner_diff import (
    _lookup_error_action,
    _plan_create_entity,
    _plan_entity_delete,
    _plan_existing_object_diff,
    _plan_existing_service_diff,
    _plan_missing_set_action,
    _plan_value_conflict_action,
)
from arodonata.cpcrud._planner_helpers import (
    _build_add_group_payload,
    _build_add_object_payload,
    _build_add_service_payload,
    _extract_add_url_list,
    _make_error_action,
    _normalize_verb,
)
from arodonata.cpcrud.models import ConflictPolicy, NamingPrefixes, Outcome, PlannedAction
from arodonata.cpcrud.state_reader import HybridStateReader, StateLookupError, normalize_mask_length


async def _find_active_where_used_refs(
    usage: Mapping[str, Any],
    *,
    mgmt_name: str,
    domain_name: str,
    reader: HybridStateReader,
) -> list[str]:
    """Collect active reference labels from Check Point `where-used` payload, ignoring virtually deleted entities."""
    refs: list[str] = []
    for bucket_name in ("used-directly", "used-indirectly"):
        bucket = usage.get(bucket_name)
        if not isinstance(bucket, Mapping):
            continue
        for category, items in bucket.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                ref_uid = str(item.get("uid") or "").strip()
                ref_name = str(item.get("name") or "").strip()
                ref_type = str(item.get("type") or "").strip().lower() or None
                if (ref_uid or ref_name) and reader.is_entity_virtually_deleted(
                    mgmt_name,
                    domain_name,
                    uid=ref_uid or None,
                    name=ref_name or None,
                    entity_type=ref_type,
                ):
                    continue
                label = ref_name or ref_uid or f"{category}-entry"
                if ref_uid and ref_name:
                    label = f"{ref_name} ({ref_uid})"
                elif not ref_uid and not ref_name:
                    rule_obj = item.get("rule")
                    if isinstance(rule_obj, Mapping):
                        r_name = str(rule_obj.get("name") or "").strip()
                        r_uid = str(rule_obj.get("uid") or "").strip()
                        r_num = item.get("position")
                        label = r_name or r_uid or (f"rule#{r_num}" if r_num is not None else label)
                if label not in refs:
                    refs.append(label)
    return refs


async def _plan_delete_with_where_used(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    entity_type: str,
    display_name: str,
    spec: Mapping[str, Any],
    existing: CPObject | CPService | None,
    reader: HybridStateReader,
) -> PlannedAction:
    """Enforce `check_where_used: true` before planning an entity delete across objects, services, and groups."""
    if existing is not None and not str(existing.uid).startswith("planned:") and spec.get("check_where_used"):
        usage = await reader.check_where_used(mgmt_name, domain_name, uid=existing.uid, name=existing.name)
        active_refs = await _find_active_where_used_refs(
            usage,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            reader=reader,
        )
        if active_refs:
            preview = ", ".join(active_refs[:5])
            if len(active_refs) > 5:
                preview = f"{preview}, +{len(active_refs) - 5} more"
            return _make_error_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="delete",
                object_type=entity_type,
                name=existing.name,
                requested_name=display_name,
                resolved_name=existing.name,
                target_uid=existing.uid,
                desired_spec=spec,
                error=(
                    f"Cannot delete {entity_type} {existing.name!r}: referenced by {len(active_refs)} "
                    f"active object(s)/rule(s) ({preview}) while check_where_used=True."
                ),
            )
    return _plan_entity_delete(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        entity_type=entity_type,
        display_name=display_name,
        spec=spec,
        existing=existing,
        reader=reader,
    )


async def _find_object_value_matches(
    *,
    mgmt_name: str,
    domain_name: str,
    obj_type: str,
    spec: Mapping[str, Any],
    prefixes: NamingPrefixes,
    reader: HybridStateReader,
) -> tuple[list[CPObject], str | None]:
    if obj_type == "host":
        ip_val = (
            spec.get("ipv4_address")
            or spec.get("ipv4-address")
            or spec.get("ip_address")
            or spec.get("ip-address")
            or spec.get("ipv6_address")
            or spec.get("ipv6-address")
        )
        if isinstance(ip_val, str) and ip_val.strip():
            clean_ip = ip_val.strip()
            matches = await reader.find_objects_by_value(mgmt_name, domain_name, obj_type="host", ip_address=clean_ip)
            return matches, prefixes.format_host(clean_ip)
    elif obj_type == "network":
        sub_val = spec.get("subnet4") or spec.get("subnet")
        mask_raw = spec.get("mask_length4") if "mask_length4" in spec else spec.get("mask-length4")
        submask_raw = spec.get("subnet_mask") or spec.get("subnet-mask")
        norm_mask = normalize_mask_length(mask_raw, submask_raw, strict=True)
        if isinstance(sub_val, str) and sub_val.strip() and norm_mask is not None:
            clean_sub = sub_val.strip()
            matches = await reader.find_objects_by_value(
                mgmt_name, domain_name, obj_type="network", subnet4=clean_sub, mask_length4=norm_mask
            )
            return matches, prefixes.format_network(clean_sub, norm_mask)
    elif obj_type == "address-range":
        f_val = spec.get("ipv4_address_first") or spec.get("ipv4-address-first")
        l_val = spec.get("ipv4_address_last") or spec.get("ipv4-address-last")
        if isinstance(f_val, str) and f_val.strip() and isinstance(l_val, str) and l_val.strip():
            f_clean, l_clean = f_val.strip(), l_val.strip()
            matches = await reader.find_objects_by_value(
                mgmt_name, domain_name, obj_type="address-range", first_ip=f_clean, last_ip=l_clean
            )
            return matches, prefixes.format_address_range(f_clean, l_clean)
    elif obj_type == "application-site":
        url_vals = _extract_add_url_list(spec)
        raw_regex = (
            spec.get("urls-defined-as-regular-expression")
            if "urls-defined-as-regular-expression" in spec
            else spec.get("urls_defined_as_regular_expression")
        )
        if url_vals:
            matches = await reader.find_objects_by_value(
                mgmt_name,
                domain_name,
                obj_type="application-site",
                url_list=url_vals,
                urls_defined_as_regular_expression=bool(raw_regex),
            )
            return matches, None
    return [], None


async def plan_object_step(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    spec: Mapping[str, Any],
    policy: ConflictPolicy,
    prefixes: NamingPrefixes,
    reader: HybridStateReader,
    res_map: dict[str, str],
    collect_known_sids: Callable[[str], Awaitable[list[str]]],
) -> PlannedAction:
    """Plan a `host`, `network`, `address-range`, `dns-domain`, or `application-site` operation."""
    obj_type = str(spec.get("type") or "host").strip().lower()
    verb = _normalize_verb(spec)
    req_name = str(spec.get("name") or "").strip()
    req_uid = str(spec.get("uid") or "").strip()
    display_name = req_name or req_uid

    try:
        existing: CPObject | None = None
        if req_uid:
            existing = await reader.get_object_by_uid(mgmt_name, domain_name, obj_type, req_uid)
        if existing is None and req_name:
            existing = await reader.get_object_by_name(mgmt_name, domain_name, obj_type, req_name)

        if verb == "delete":
            return await _plan_delete_with_where_used(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=obj_type,
                display_name=display_name,
                spec=spec,
                existing=existing,
                reader=reader,
            )

        if existing is not None:
            return _plan_existing_object_diff(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                verb=verb,
                obj_type=obj_type,
                display_name=display_name,
                spec=spec,
                existing=existing,
                policy=policy,
                reader=reader,
                res_map=res_map,
            )

        if verb == "set":
            return _plan_missing_set_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=obj_type,
                display_name=display_name,
                spec=spec,
            )

        ip_matches, auto_name = await _find_object_value_matches(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            obj_type=obj_type,
            spec=spec,
            prefixes=prefixes,
            reader=reader,
        )
        target_create_name = req_name
        extra_create_flags: dict[str, Any] = {}
        if ip_matches:
            conflict_act = _plan_value_conflict_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                verb=verb,
                entity_type=obj_type,
                req_name=req_name,
                matched=ip_matches[0],
                conflict_label="IP/subnet",
                policy=policy,
                spec=spec,
                res_map=res_map,
            )
            if conflict_act is not None:
                return conflict_act
            if policy.on_ip_conflict == "create_new" and (auto_name or obj_type == "application-site"):
                target_create_name = auto_name or req_name
                extra_create_flags["ignore-warnings"] = True
                if auto_name:
                    existing_auto = await reader.get_object_by_name(mgmt_name, domain_name, obj_type, auto_name)
                    if existing_auto is not None:
                        act_auto = _plan_existing_object_diff(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            verb=verb,
                            obj_type=obj_type,
                            display_name=req_name,
                            spec=spec,
                            existing=existing_auto,
                            policy=policy,
                            reader=reader,
                            res_map=res_map,
                        )
                        if act_auto.outcome != Outcome.ERROR:
                            res_map[req_name] = act_auto.resolved_name or existing_auto.name
                        return act_auto

        if obj_type == "application-site":
            has_urls = bool(_extract_add_url_list(spec))
            raw_sig = spec.get("application-signature") or spec.get("application_signature")
            if not has_urls and not str(raw_sig or "").strip():
                return _make_error_action(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation=verb,
                    object_type=obj_type,
                    name=target_create_name,
                    requested_name=req_name or target_create_name,
                    resolved_name=target_create_name,
                    desired_spec=spec,
                    error=(
                        f"Cannot create application-site {target_create_name!r}: "
                        "'url-list' (or 'url_list') or 'application-signature' (or 'application_signature') is required."
                    ),
                )

        add_payload = _build_add_object_payload(obj_type, target_create_name, spec)
        add_payload.update(extra_create_flags)
        return _plan_create_entity(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            entity_type=obj_type,
            target_create_name=target_create_name,
            req_name=req_name,
            add_payload=add_payload,
            spec=spec,
            reader=reader,
            res_map=res_map,
            is_service=False,
        )
    except StateLookupError as exc:
        return await _lookup_error_action(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            verb=verb,
            entity_type=obj_type,
            display_name=display_name,
            spec=spec,
            exc=exc,
            collect_known_sids=collect_known_sids,
        )


async def plan_service_step(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    spec: Mapping[str, Any],
    policy: ConflictPolicy,
    prefixes: NamingPrefixes,
    reader: HybridStateReader,
    res_map: dict[str, str],
    collect_known_sids: Callable[[str], Awaitable[list[str]]],
) -> PlannedAction:
    """Plan a `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, or `service-other` operation."""
    svc_type = str(spec.get("type") or "service-tcp").strip().lower()
    verb = _normalize_verb(spec)
    req_name = str(spec.get("name") or "").strip()
    req_uid = str(spec.get("uid") or "").strip()
    display_name = req_name or req_uid

    try:
        existing: CPService | None = None
        if req_uid:
            existing = await reader.get_service_by_uid(mgmt_name, domain_name, svc_type, req_uid)
        if existing is None and req_name:
            existing = await reader.get_service_by_name(mgmt_name, domain_name, svc_type, req_name)

        if verb == "delete":
            return await _plan_delete_with_where_used(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=svc_type,
                display_name=display_name,
                spec=spec,
                existing=existing,
                reader=reader,
            )

        if existing is not None:
            return _plan_existing_service_diff(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                verb=verb,
                svc_type=svc_type,
                display_name=display_name,
                spec=spec,
                existing=existing,
                policy=policy,
                reader=reader,
                res_map=res_map,
            )

        if verb == "set":
            return _plan_missing_set_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=svc_type,
                display_name=display_name,
                spec=spec,
            )

        port_matches: list[CPService] = []
        auto_name: str | None = None
        if svc_type in ("service-tcp", "service-udp") and spec.get("port") is not None:
            port_str = str(spec["port"]).strip()
            proto_str = str(spec["protocol"]).strip() if spec.get("protocol") is not None else None
            port_matches = await reader.find_service_by_port(mgmt_name, domain_name, svc_type, port_str, proto_str)
            auto_name = prefixes.format_tcp(port_str) if svc_type == "service-tcp" else prefixes.format_udp(port_str)
        elif svc_type in ("service-icmp", "service-icmp6"):
            icmp_t = spec.get("icmp_type") if "icmp_type" in spec else spec.get("icmp-type")
            icmp_c = spec.get("icmp_code") if "icmp_code" in spec else spec.get("icmp-code")
            if isinstance(icmp_t, int):
                port_matches = await reader.find_icmp_service(
                    mgmt_name, domain_name, svc_type, icmp_t, icmp_c if isinstance(icmp_c, int) else None
                )
                auto_name = prefixes.format_icmp(icmp_t, icmp_c if isinstance(icmp_c, int) else None)

        target_create_name = req_name
        extra_flags: dict[str, Any] = {}
        if port_matches:
            conflict_act = _plan_value_conflict_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                verb=verb,
                entity_type=svc_type,
                req_name=req_name,
                matched=port_matches[0],
                conflict_label="Port/protocol",
                policy=policy,
                spec=spec,
                res_map=res_map,
            )
            if conflict_act is not None:
                return conflict_act
            if policy.on_ip_conflict == "create_new" and auto_name:
                target_create_name = auto_name
                extra_flags["ignore-warnings"] = True
                existing_auto = await reader.get_service_by_name(mgmt_name, domain_name, svc_type, auto_name)
                if existing_auto is not None:
                    act_auto = _plan_existing_service_diff(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        verb=verb,
                        svc_type=svc_type,
                        display_name=req_name,
                        spec=spec,
                        existing=existing_auto,
                        policy=policy,
                        reader=reader,
                        res_map=res_map,
                    )
                    if act_auto.outcome != Outcome.ERROR:
                        res_map[req_name] = act_auto.resolved_name or existing_auto.name
                    return act_auto

        add_payload = _build_add_service_payload(svc_type, target_create_name, spec)
        add_payload.update(extra_flags)
        return _plan_create_entity(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            entity_type=svc_type,
            target_create_name=target_create_name,
            req_name=req_name,
            add_payload=add_payload,
            spec=spec,
            reader=reader,
            res_map=res_map,
            is_service=True,
        )
    except StateLookupError as exc:
        return await _lookup_error_action(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            verb=verb,
            entity_type=svc_type,
            display_name=display_name,
            spec=spec,
            exc=exc,
            collect_known_sids=collect_known_sids,
        )


async def plan_group_step(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    spec: Mapping[str, Any],
    policy: ConflictPolicy,
    reader: HybridStateReader,
    res_map: dict[str, str],
    collect_known_sids: Callable[[str], Awaitable[list[str]]],
) -> PlannedAction:
    """Plan a `group` or `service-group` operation while keeping the virtual overlay coherent."""
    grp_type = str(spec.get("type") or "group").strip().lower()
    verb = _normalize_verb(spec)
    req_name = str(spec.get("name") or "").strip()
    req_uid = str(spec.get("uid") or "").strip()
    display_name = req_name or req_uid
    is_service_group = grp_type == "service-group"

    try:
        existing: CPService | CPObject | None = None
        if is_service_group:
            if req_uid:
                existing = await reader.get_service_by_uid(mgmt_name, domain_name, "service-group", req_uid)
            if existing is None and req_name:
                existing = await reader.get_service_by_name(mgmt_name, domain_name, "service-group", req_name)
        else:
            if req_uid:
                existing = await reader.get_object_by_uid(mgmt_name, domain_name, "group", req_uid)
            if existing is None and req_name:
                existing = await reader.get_object_by_name(mgmt_name, domain_name, "group", req_name)

        if verb == "delete":
            return await _plan_delete_with_where_used(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=grp_type,
                display_name=display_name,
                spec=spec,
                existing=existing,
                reader=reader,
            )

        if existing is not None:
            if isinstance(existing, CPService):
                return _plan_existing_service_diff(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    verb=verb,
                    svc_type="service-group",
                    display_name=display_name,
                    spec=spec,
                    existing=existing,
                    policy=policy,
                    reader=reader,
                    res_map=res_map,
                )
            return _plan_existing_object_diff(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                verb=verb,
                obj_type="group",
                display_name=display_name,
                spec=spec,
                existing=existing,
                policy=policy,
                reader=reader,
                res_map=res_map,
            )

        if verb == "set":
            return _plan_missing_set_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                entity_type=grp_type,
                display_name=display_name,
                spec=spec,
            )

        add_payload = _build_add_group_payload(req_name, spec, name_resolutions=res_map)
        return _plan_create_entity(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            entity_type=grp_type,
            target_create_name=req_name,
            req_name=req_name,
            add_payload=add_payload,
            spec=spec,
            reader=reader,
            res_map=res_map,
            is_service=is_service_group,
        )
    except StateLookupError as exc:
        return await _lookup_error_action(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            verb=verb,
            entity_type=grp_type,
            display_name=display_name,
            spec=spec,
            exc=exc,
            collect_known_sids=collect_known_sids,
        )
