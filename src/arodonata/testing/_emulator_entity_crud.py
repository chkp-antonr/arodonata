"""Entity CRUD, group membership synchronization, and rename propagation for the replay emulator."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult
from arodonata.core.primitives import mask_to_prefix_len, prefix_len_to_mask

from ._emulator_lookup import (
    as_list,
    collect_blocking_references,
    ensure_entity_bucket,
    find_effective_object,
    find_in_scope,
    global_read_only_error,
    is_global_owned,
    ref_uid,
    refresh_entity_bucket_counts,
)
from ._emulator_models import (
    CMD_TO_ENTITY_ACTION,
    ENTITY_SPECS,
    OBJ_TYPE_TO_SPEC,
    EntitySpec,
    cp_error,
    cp_ok,
    format_domain_meta,
    format_timestamp,
)
from ._emulator_projection import (
    NETWORK_NAMESPACE_TYPES,
    SERVICE_NAMESPACE_TYPES,
    extract_ref_uids,
    make_object_summary,
    project_details_level,
)


def _check_name_conflict(
    dom_files: Mapping[str, Any],
    name: str,
    spec: EntitySpec,
    *,
    exclude_uid: str | None = None,
) -> dict[str, Any] | None:
    """Return an existing object sharing `name` inside the same Check Point namespace."""
    namespace = SERVICE_NAMESPACE_TYPES if spec.is_service else NETWORK_NAMESPACE_TYPES
    for cand_spec in ENTITY_SPECS:
        if cand_spec.obj_type not in namespace:
            continue
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if exclude_uid and item.get("uid") == exclude_uid:
                continue
            if item.get("name") == name:
                return item
    return None


def _sync_member_refs_on_group_list(
    group_obj: dict[str, Any],
    member_refs: list[Any],
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    spec: EntitySpec,
) -> ApiCallResult | None:
    resolved_members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in member_refs:
        lookup = str(ref.get("uid") or ref.get("name") or "") if isinstance(ref, Mapping) else str(ref)
        found = find_effective_object(dom_files, global_files, dom_name, lookup, include_extras=False)
        if found is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Member object [{lookup}] not found in {dom_name}",
                status_code=404,
            )
        m_obj, m_owner, _ = found
        m_uid = str(m_obj["uid"])
        if spec.obj_type == "group" and m_uid == group_obj.get("uid"):
            return cp_error("err_validation_failed", "Group cannot contain itself", status_code=400)
        if m_uid not in seen:
            seen.add(m_uid)
            resolved_members.append(make_object_summary(m_obj, default_domain=m_owner))

    old_uids = extract_ref_uids(group_obj.get("members"))
    new_uids = {str(m["uid"]) for m in resolved_members}
    group_obj["members"] = resolved_members

    # Keep reverse `groups` field consistent on local domain objects
    grp_summary = make_object_summary(group_obj, default_domain=dom_name)
    g_uid = str(group_obj["uid"])
    for cand_spec in ENTITY_SPECS:
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            i_uid = str(item.get("uid") or "")
            if i_uid in (old_uids - new_uids):
                cur_groups = [g for g in item.get("groups", []) if ref_uid(g) != g_uid]
                item["groups"] = cur_groups
            elif i_uid in new_uids:
                cur_groups = list(item.get("groups", []))
                if all(ref_uid(g) != g_uid for g in cur_groups):
                    cur_groups.append(copy.deepcopy(grp_summary))
                    item["groups"] = cur_groups
    return None


def _sync_object_groups_field(
    obj: dict[str, Any],
    groups_spec: Any,
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    target_group_spec: EntitySpec,
) -> ApiCallResult | None:
    """Apply `groups` list or `{add, remove}` onto local group objects."""
    cur_uids = [ref_uid(g) for g in obj.get("groups", []) if ref_uid(g)]
    if isinstance(groups_spec, Mapping) and ("add" in groups_spec or "remove" in groups_spec):
        to_remove: set[str] = set()
        for rem_ref in as_list(groups_spec.get("remove")):
            hit = find_in_scope(dom_files, ref_uid(rem_ref), preferred_spec=target_group_spec, include_extras=False)
            if hit:
                to_remove.add(str(hit[0]["uid"]))
            else:
                to_remove.add(ref_uid(rem_ref))
        desired = [u for u in cur_uids if u not in to_remove]
        for add_ref in as_list(groups_spec.get("add")):
            eff_hit = find_effective_object(
                dom_files, global_files, dom_name, ref_uid(add_ref), preferred_spec=target_group_spec
            )
            if eff_hit is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Group [{ref_uid(add_ref)}] not found",
                    status_code=404,
                )
            g_obj, g_owner, _ = eff_hit
            if is_global_owned(g_obj, g_owner, dom_name):
                return global_read_only_error(ref_uid(add_ref), dom_name)
            g_uid = str(g_obj["uid"])
            if g_uid not in desired:
                desired.append(g_uid)
    else:
        desired = []
        for g_ref in as_list(groups_spec):
            eff_hit = find_effective_object(
                dom_files, global_files, dom_name, ref_uid(g_ref), preferred_spec=target_group_spec
            )
            if eff_hit is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Group [{ref_uid(g_ref)}] not found",
                    status_code=404,
                )
            g_obj, g_owner, _ = eff_hit
            if is_global_owned(g_obj, g_owner, dom_name):
                return global_read_only_error(ref_uid(g_ref), dom_name)
            g_uid = str(g_obj["uid"])
            if g_uid not in desired:
                desired.append(g_uid)

    obj_uid = str(obj["uid"])
    new_groups_list: list[dict[str, Any]] = []
    for g_obj in ensure_entity_bucket(dom_files, target_group_spec):
        g_uid = str(g_obj.get("uid") or "")
        members = [m for m in g_obj.get("members", []) if isinstance(m, Mapping)]
        if g_uid in desired:
            if all(ref_uid(m) != obj_uid for m in members):
                members.append(make_object_summary(obj, default_domain=dom_name))
                g_obj["members"] = members
            new_groups_list.append(make_object_summary(g_obj, default_domain=dom_name))
        else:
            filtered_m = [m for m in members if ref_uid(m) != obj_uid]
            if len(filtered_m) != len(members):
                g_obj["members"] = filtered_m
    obj["groups"] = new_groups_list
    return None


def _propagate_object_rename(dom_files: dict[str, Any], renamed_obj: Mapping[str, Any]) -> None:
    """Propagate an object's updated `name` into local group `members`, reverse `groups`, and `objects-dictionary`."""
    obj_uid = str(renamed_obj["uid"])
    new_name = str(renamed_obj["name"])

    for cand_spec in ENTITY_SPECS:
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for field in ("members", "groups", "include", "except"):
                ref_list = item.get(field)
                if not isinstance(ref_list, list):
                    continue
                for entry in ref_list:
                    if isinstance(entry, dict) and entry.get("uid") == obj_uid:
                        entry["name"] = new_name

    for rb_cmd in ("show-access-rulebase", "show-nat-rulebase", "show-https-rulebase", "show-threat-rulebase"):
        rb_store = dom_files.get(rb_cmd, {})
        if not isinstance(rb_store, dict):
            continue
        for layer_val in rb_store.values():
            if not isinstance(layer_val, dict):
                continue
            for dict_entry in layer_val.get("objects-dictionary", []):
                if isinstance(dict_entry, dict) and dict_entry.get("uid") == obj_uid:
                    dict_entry["name"] = new_name


def _normalize_subnet_fields(target: dict[str, Any], updates: Mapping[str, Any]) -> None:
    """Keep `subnet4` / `mask-length4` / `subnet-mask` synchronized for network objects."""
    if "subnet4" in updates:
        target["subnet4"] = str(updates["subnet4"])
    if "subnet-mask" in updates and updates["subnet-mask"]:
        mask_str = str(updates["subnet-mask"])
        target["subnet-mask"] = mask_str
        prefix = mask_to_prefix_len(mask_str, allow_prefix_int=False)
        if prefix is not None:
            target["mask-length4"] = prefix
    if "mask-length4" in updates and updates["mask-length4"] is not None:
        plen = int(updates["mask-length4"])
        target["mask-length4"] = plen
        computed_mask = prefix_len_to_mask(plen)
        if computed_mask is not None and "subnet-mask" not in updates:
            target["subnet-mask"] = computed_mask


def _apply_entity_fields(
    obj: dict[str, Any],
    req: Mapping[str, Any],
    spec: EntitySpec,
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
) -> ApiCallResult | None:
    ignored = {
        "uid",
        "domain",
        "details-level",
        "set-if-exists",
        "ignore-warnings",
        "ignore-errors",
        "new-name",
        "name",
        "members",
        "groups",
        "tags",
        "url-list",
    }
    if spec.obj_type == "network":
        _normalize_subnet_fields(obj, req)
        ignored |= {"subnet4", "subnet-mask", "mask-length4"}

    for key, val in req.items():
        if key in ignored:
            continue
        obj[key] = copy.deepcopy(val)

    if "tags" in req:
        raw_tags = req["tags"]
        if isinstance(raw_tags, Mapping) and ("add" in raw_tags or "remove" in raw_tags):
            cur_tags = list(obj.get("tags", []))
            rem = {str(t) for t in as_list(raw_tags.get("remove"))}
            cur_tags = [t for t in cur_tags if ref_uid(t) not in rem]
            for add_t in as_list(raw_tags.get("add")):
                if add_t not in cur_tags:
                    cur_tags.append(copy.deepcopy(add_t))
            obj["tags"] = cur_tags
        else:
            obj["tags"] = copy.deepcopy(as_list(raw_tags))

    if spec.obj_type == "application-site" and "url-list" in req:
        raw_urls = req["url-list"]
        eff_is_regex = bool(
            req["urls-defined-as-regular-expression"]
            if "urls-defined-as-regular-expression" in req
            else obj.get("urls-defined-as-regular-expression", False)
        )

        def _url_key(raw_u: str) -> str:
            return raw_u if eff_is_regex else raw_u.lower()

        if isinstance(raw_urls, Mapping) and ("add" in raw_urls or "remove" in raw_urls):
            cur_urls = [str(u).strip() for u in as_list(obj.get("url-list")) if str(u).strip()]
            rem_keys = {_url_key(str(u).strip()) for u in as_list(raw_urls.get("remove")) if str(u).strip()}
            kept_urls = [u for u in cur_urls if _url_key(u) not in rem_keys]
            adds = [str(u).strip() for u in as_list(raw_urls.get("add")) if str(u).strip()]
            candidates = [*kept_urls, *adds]
        else:
            candidates = [str(u).strip() for u in as_list(raw_urls) if str(u).strip()]

        seen_url_keys: set[str] = set()
        new_urls: list[str] = []
        for cand in candidates:
            u_key = _url_key(cand)
            if u_key not in seen_url_keys:
                seen_url_keys.add(u_key)
                new_urls.append(cand)
        has_sig = bool(str(req.get("application-signature") or obj.get("application-signature") or "").strip())
        if not new_urls and not has_sig:
            return cp_error(
                "err_validation_failed",
                "application-site url-list cannot be empty without application-signature",
                status_code=400,
            )
        obj["url-list"] = new_urls

    if spec.is_group and "members" in req:
        raw_members = req["members"]
        if isinstance(raw_members, Mapping) and ("add" in raw_members or "remove" in raw_members):
            cur_refs = [copy.deepcopy(m) for m in obj.get("members", [])]
            rem_refs = {ref_uid(r) for r in as_list(raw_members.get("remove"))}
            rem_uids: set[str] = set()
            for r_ref in rem_refs:
                found_rem = find_effective_object(dom_files, global_files, dom_name, r_ref, include_extras=False)
                rem_uids.add(str(found_rem[0]["uid"]) if found_rem else r_ref)
            kept: list[Any] = [m for m in cur_refs if ref_uid(m) not in rem_uids and ref_uid(m) not in rem_refs]
            for add_r in as_list(raw_members.get("add")):
                kept.append(add_r)
            err = _sync_member_refs_on_group_list(
                obj, kept, dom_files=dom_files, global_files=global_files, dom_name=dom_name, spec=spec
            )
            if err is not None:
                return err
        else:
            err = _sync_member_refs_on_group_list(
                obj,
                as_list(raw_members),
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                spec=spec,
            )
            if err is not None:
                return err

    if "groups" in req:
        grp_spec = OBJ_TYPE_TO_SPEC["service-group" if spec.is_service else "group"]
        err = _sync_object_groups_field(
            obj,
            req["groups"],
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            target_group_spec=grp_spec,
        )
        if err is not None:
            return err

    return None


def handle_entity_crud(
    command: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    all_domains_effective: Mapping[str, Mapping[str, Any]],
    uid_allocator: Callable[[str], str],
    now_ms: int,
    user_name: str,
    locked_uids_out: set[str],
) -> tuple[ApiCallResult, str | None] | None:
    """Execute `show-*`, `add-*`, `set-*`, `delete-*` for all 12 `ENTITY_SPECS` types."""
    mapping = CMD_TO_ENTITY_ACTION.get(command)
    if mapping is None:
        return None
    spec, action = mapping
    details_level = str(req.get("details-level") or "standard")

    if action == "show":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, _, found_spec = found
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        return cp_ok(project_details_level(obj, details_level)), None

    if action == "add":
        name = str(req.get("name") or "").strip()
        if not name:
            return cp_error("err_validation_failed", f"{command}: 'name' is required", status_code=400), None

        conflict = _check_name_conflict(dom_files, name, spec)
        if conflict is not None:
            if bool(req.get("set-if-exists", False)):
                set_req = dict(req)
                set_req["uid"] = conflict["uid"]
                return handle_entity_crud(
                    spec.set_cmd,
                    set_req,
                    dom_name=dom_name,
                    dom_files=dom_files,
                    global_files=global_files,
                    all_domains_effective=all_domains_effective,
                    uid_allocator=uid_allocator,
                    now_ms=now_ms,
                    user_name=user_name,
                    locked_uids_out=locked_uids_out,
                )
            return (
                cp_error(
                    "err_validation_failed",
                    f"More than one object named [{name}] exists",
                    status_code=400,
                ),
                None,
            )

        assigned_uid = str(req.get("uid") or "").strip() or uid_allocator(spec.obj_type)
        ts = format_timestamp(now_ms)
        new_obj: dict[str, Any] = {
            "uid": assigned_uid,
            "name": name,
            "type": spec.obj_type,
            "domain": format_domain_meta(dom_name),
            "color": str(req.get("color") or "black"),
            "comments": str(req.get("comments") or ""),
            "tags": [],
            "groups": [],
            "meta-info": {
                "lock": "unlocked",
                "validation-state": "ok",
                "creator": user_name,
                "creation-time": dict(ts),
                "last-modifier": user_name,
                "last-modify-time": dict(ts),
            },
        }
        for k, default_v in spec.default_fields:
            new_obj[k] = copy.deepcopy(default_v)
        if spec.is_group:
            new_obj["members"] = []

        bucket = ensure_entity_bucket(dom_files, spec)
        bucket.append(new_obj)
        err = _apply_entity_fields(
            new_obj,
            req,
            spec,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
        )
        if err is not None:
            bucket.remove(new_obj)
            return err, None
        refresh_entity_bucket_counts(dom_files, spec)
        locked_uids_out.add(assigned_uid)
        return cp_ok(project_details_level(new_obj, details_level)), assigned_uid

    if action == "set":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, owning_dom, found_spec = found
        if is_global_owned(obj, owning_dom, dom_name):
            return global_read_only_error(lookup, dom_name), None
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )

        obj_uid = str(obj["uid"])
        locked_uids_out.add(obj_uid)
        new_name = str(req.get("new-name") or "").strip()
        if new_name and new_name != obj.get("name"):
            conflict = _check_name_conflict(dom_files, new_name, spec, exclude_uid=obj_uid)
            if conflict is not None:
                return (
                    cp_error(
                        "err_validation_failed",
                        f"More than one object named [{new_name}] exists",
                        status_code=400,
                    ),
                    None,
                )
            obj["name"] = new_name
            _propagate_object_rename(dom_files, obj)

        err = _apply_entity_fields(
            obj,
            req,
            spec,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
        )
        if err is not None:
            return err, None

        meta = obj.setdefault("meta-info", {})
        if isinstance(meta, dict):
            meta["last-modifier"] = user_name
            meta["last-modify-time"] = format_timestamp(now_ms)
        return cp_ok(project_details_level(obj, details_level)), obj_uid

    if action == "delete":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, owning_dom, found_spec = found
        if is_global_owned(obj, owning_dom, dom_name):
            return global_read_only_error(lookup, dom_name), None
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )

        obj_uid = str(obj["uid"])
        blocking = collect_blocking_references(
            obj_uid,
            dom_name=dom_name,
            dom_files=dom_files,
            all_domains_effective=all_domains_effective,
        )
        if blocking:
            return (
                cp_error(
                    "generic_err_object_cannot_be_deleted",
                    f"Object [{obj.get('name', obj_uid)}] cannot be deleted because it is still referenced",
                    status_code=400,
                    blocking_errors=[{"message": msg} for msg in blocking],
                ),
                None,
            )

        locked_uids_out.add(obj_uid)
        bucket_list = ensure_entity_bucket(dom_files, spec)
        bucket_list[:] = [o for o in bucket_list if o.get("uid") != obj_uid]
        refresh_entity_bucket_counts(dom_files, spec)
        return cp_ok({"message": "OK"}), obj_uid

    return None
