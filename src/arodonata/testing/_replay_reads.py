"""Read-only `show-*` and `where-used` command handlers for `FileReplayApiMock`."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_lookup import filter_show_objects, find_effective_object, find_unused_objects
from ._emulator_models import SidBinding, cp_error, cp_ok
from ._emulator_projection import paginate_items, project_details_level, slice_rulebase_with_sections
from ._replay_queries import (
    SHOW_OBJECTS_TYPE_TO_CMD,
    build_where_used_response,
    find_domain_object_by_ref,
    matches_show_objects_filter,
    resolve_layer_payload,
    resolve_nat_package_payload,
)
from ._replay_repo_scripts import handle_show_repository_scripts

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def handle_show_checkpoint_host(
    mock: FileReplayApiMock,
    mgmt_name: str,
    dom_name: str,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
) -> ApiCallResult:
    """Resolve `show-checkpoint-host` across effective domain, system scopes, and MDS records."""
    lookup = str(req.get("name") or req.get("uid") or "").strip()
    details_level = str(req.get("details-level") or "full")
    candidate_scopes: list[dict[str, Any]] = []
    eff_dom = mock._effective_domain_files(dom_name, binding)
    if isinstance(eff_dom, dict):
        candidate_scopes.append(eff_dom)
    for extra_dom in ("System Data", "SMC User", "Global"):
        if extra_dom != dom_name and isinstance(mock._domain_data.get(extra_dom), dict):
            candidate_scopes.append(mock._domain_data[extra_dom])
    for d_name, d_files in mock._domain_data.items():
        if d_name not in (dom_name, "System Data", "SMC User", "Global") and isinstance(d_files, dict):
            candidate_scopes.append(d_files)
    for scope_files in candidate_scopes:
        for bucket_cmd in ("show-checkpoint-hosts", "show-gateways-and-servers"):
            for obj in scope_files.get(bucket_cmd, {}).get("objects", []):
                if isinstance(obj, dict) and (not lookup or obj.get("uid") == lookup or obj.get("name") == lookup):
                    return cp_ok(project_details_level(obj, details_level, strict_standard=True))
    for mds_obj in mock._show_mdss.get("objects", []):
        if isinstance(mds_obj, dict) and (mds_obj.get("uid") == lookup or mds_obj.get("name") == lookup):
            return cp_ok(project_details_level(mds_obj, details_level, strict_standard=True))
    if lookup == mgmt_name and "SMC User" in mock._domain_data:
        return cp_ok(
            {
                "uid": f"uid-chost-{mgmt_name}",
                "name": mgmt_name,
                "type": "checkpoint-host",
                "domain": {"uid": "uid-dom-smc-user", "name": "SMC User", "domain-type": "domain"},
            }
        )
    return cp_error(
        "generic_err_object_not_found",
        f"Requested Check Point host [{lookup}] not found",
        status_code=404,
    )


def handle_domain_read_command(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: dict[str, Any],
    *,
    dom_name: str,
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    binding: SidBinding | None,
) -> ApiCallResult | None:
    """Handle domain-scoped read queries (`show-*` and `where-used`)."""
    if clean_cmd == "show-unused-objects":
        unused = find_unused_objects(
            dom_files,
            dom_name=dom_name,
            all_domains_effective=mock._effective_all_domains(binding),
            req=req,
        )
        return cp_ok(paginate_items(unused, req, collection_key="objects"))

    if clean_cmd in ("show-repository-script", "show-repository-scripts"):
        return handle_show_repository_scripts(mock, clean_cmd, req, dom_files=dom_files)

    if clean_cmd in ("show-last-published-session", "show-session"):
        sess_data = dom_files.get(clean_cmd) or dom_files.get("show-last-published-session") or {}
        return cp_ok(copy.deepcopy(sess_data))

    if clean_cmd in ("show-simple-gateway", "show-simple-cluster", "show-generic-object"):
        lookup_key = str(req.get("uid") or req.get("name") or "")
        mock.gateway_detail_queries.append((dom_name, clean_cmd, lookup_key))
        store = dom_files.get(clean_cmd, {})
        details_lvl = str(req.get("details-level") or "full")
        if lookup_key in store:
            return cp_ok(project_details_level(store[lookup_key], details_lvl, strict_standard=True))
        for item_val in store.values():
            if isinstance(item_val, dict) and item_val.get("name") == lookup_key:
                return cp_ok(project_details_level(item_val, details_lvl, strict_standard=True))
        if clean_cmd == "show-generic-object":
            raw_gen = dom_files.get("show-generic-objects", {})
            gen_lists = (
                [raw_gen["objects"]]
                if isinstance(raw_gen.get("objects"), list)
                else [v for v in raw_gen.values() if isinstance(v, list)]
            )
            for g_list in gen_lists:
                for g_obj in g_list:
                    if isinstance(g_obj, dict) and (g_obj.get("uid") == lookup_key or g_obj.get("name") == lookup_key):
                        return cp_ok(project_details_level(g_obj, details_lvl, strict_standard=True))
        return cp_error("generic_err_object_not_found", f"Requested object [{lookup_key}] not found", status_code=404)

    if clean_cmd == "show-generic-objects":
        raw_gen = dom_files.get("show-generic-objects", {})
        cls_filter = req.get("class-name")
        name_filter = req.get("name")
        if isinstance(raw_gen.get("objects"), list):
            all_generic = [g for g in raw_gen["objects"] if not cls_filter or g.get("class-name") == cls_filter]
        elif cls_filter:
            all_generic = list(raw_gen.get(str(cls_filter), []))
        else:
            all_generic = [g for v in raw_gen.values() if isinstance(v, list) for g in v if isinstance(g, dict)]
        filtered = [g for g in all_generic if not name_filter or g.get("name") == name_filter]
        return cp_ok(mock._paginate_list(filtered, req, collection_key="objects"))

    if clean_cmd in ("show-access-rulebase", "show-https-rulebase", "show-threat-rulebase"):
        rb_specs = {
            "show-access-rulebase": ("show-access-layers", "access-layers", "access"),
            "show-https-rulebase": ("show-https-layers", "https-layers", "HTTPS"),
            "show-threat-rulebase": ("show-threat-layers", "threat-layers", "Threat"),
        }
        lyr_store, lyr_key, label = rb_specs[clean_cmd]
        lookup = str(req.get("uid") or req.get("name") or "")
        layer_payload = resolve_layer_payload(
            dom_files,
            global_files,
            lookup,
            store_key=clean_cmd,
            layer_store_key=lyr_store,
            layer_list_key=lyr_key,
        )
        if layer_payload is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Requested {label} layer [{lookup}] not found in {dom_name}",
                status_code=404,
            )
        sliced_rb = slice_rulebase_with_sections(
            layer_payload,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            offset=int(req.get("offset", 0)),
            limit=int(req.get("limit", 100)),
            use_object_dictionary=bool(req.get("use-object-dictionary", True)),
        )
        return cp_ok(sliced_rb)

    if clean_cmd == "show-nat-rulebase":
        pkg_lookup = str(req.get("package") or req.get("uid") or req.get("name") or "")
        nat_payload = resolve_nat_package_payload(dom_files, pkg_lookup)
        if nat_payload is None and dom_name != "Global":
            nat_payload = resolve_nat_package_payload(global_files, pkg_lookup)
        if nat_payload is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Requested NAT package [{pkg_lookup}] not found in {dom_name}",
                status_code=404,
            )
        sliced_nat = slice_rulebase_with_sections(
            nat_payload,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            offset=int(req.get("offset", 0)),
            limit=int(req.get("limit", 100)),
            use_object_dictionary=bool(req.get("use-object-dictionary", True)),
        )
        return cp_ok(sliced_nat)

    if clean_cmd == "where-used":
        lookup_ref = str(req.get("uid") or req.get("name") or "")
        target_obj = find_domain_object_by_ref(dom_files, lookup_ref)
        if target_obj is None and dom_name != "Global":
            target_obj = find_domain_object_by_ref(global_files, lookup_ref)
        if target_obj is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Requested object [{lookup_ref}] not found in {dom_name}",
                status_code=404,
            )
        target_uid = str(target_obj.get("uid") or lookup_ref)
        indirect_flag = bool(req.get("indirect", False))
        max_depth = max(1, int(req.get("indirect-max-depth", 5)))
        wu_data = build_where_used_response(
            dom_files,
            global_files,
            dom_name,
            target_uid,
            indirect=indirect_flag,
            max_depth=max_depth,
        )
        return cp_ok(wu_data)

    if clean_cmd == "show-package":
        pkg_lookup = str(req.get("name") or req.get("uid") or "")
        for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
            for pkg in scope_files.get("show-packages", {}).get("packages", []):
                if pkg.get("name") == pkg_lookup or pkg.get("uid") == pkg_lookup:
                    return cp_ok(copy.deepcopy(pkg))
        return cp_error("generic_err_object_not_found", f"Package [{pkg_lookup}] not found", status_code=404)

    if clean_cmd in ("show-access-layer", "show-https-layer", "show-threat-layer"):
        layer_cmd_meta = {
            "show-access-layer": ("show-access-layers", "access-layers", "Access"),
            "show-https-layer": ("show-https-layers", "https-layers", "HTTPS"),
            "show-threat-layer": ("show-threat-layers", "threat-layers", "Threat"),
        }
        lyr_store, lyr_key, lyr_label = layer_cmd_meta[clean_cmd]
        layer_lookup = str(req.get("name") or req.get("uid") or "")
        for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
            for lyr in scope_files.get(lyr_store, {}).get(lyr_key, []):
                if lyr.get("name") == layer_lookup or lyr.get("uid") == layer_lookup:
                    return cp_ok(copy.deepcopy(lyr))
        return cp_error(
            "generic_err_object_not_found", f"{lyr_label} layer [{layer_lookup}] not found", status_code=404
        )

    if clean_cmd == "show-object":
        lookup_uid = str(req.get("uid") or req.get("name") or "")
        found_eff = find_effective_object(
            dom_files, global_files, dom_name, lookup_uid, allow_sentinels=False, include_extras=True
        )
        if found_eff is not None:
            return cp_ok({"object": copy.deepcopy(found_eff[0])})
        for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
            for file_val in scope_files.values():
                if not isinstance(file_val, dict):
                    continue
                items = file_val.get("objects")
                if isinstance(items, list):
                    for obj in items:
                        if isinstance(obj, dict) and (obj.get("uid") == lookup_uid or obj.get("name") == lookup_uid):
                            return cp_ok({"object": copy.deepcopy(obj)})
                elif lookup_uid in file_val and isinstance(file_val[lookup_uid], dict):
                    return cp_ok({"object": copy.deepcopy(file_val[lookup_uid])})
        return cp_error("generic_err_object_not_found", f"Object [{lookup_uid}] not found", status_code=404)

    if clean_cmd == "show-objects":
        filter_raw = req.get("filter")
        filter_needle = str(filter_raw).strip().lower() if filter_raw is not None else ""
        ip_only = bool(req.get("ip-only", False))
        matched = filter_show_objects(
            dom_files,
            global_files,
            dom_name,
            req,
            SHOW_OBJECTS_TYPE_TO_CMD,
            lambda item: matches_show_objects_filter(item, filter_needle=filter_needle, ip_only=ip_only),
        )
        return cp_ok(mock._paginate_list(matched, req, collection_key="objects"))

    if clean_cmd in dom_files and isinstance(dom_files[clean_cmd], dict):
        file_payload = dom_files[clean_cmd]
        col_key = "objects"
        for candidate_key in (
            "objects",
            "packages",
            "access-layers",
            "https-layers",
            "threat-layers",
            "nat-rules",
            "sessions",
        ):
            if isinstance(file_payload.get(candidate_key), list):
                col_key = candidate_key
                break
        items = file_payload.get(col_key, [])
        return cp_ok(mock._paginate_list(items, req, collection_key=col_key))

    if clean_cmd == "show-https-layers":
        return cp_ok({"https-layers": [], "from": 0, "to": 0, "total": 0})
    if clean_cmd == "show-threat-layers":
        return cp_ok({"threat-layers": [], "from": 0, "to": 0, "total": 0})

    if clean_cmd.startswith(("show-services-", "show-groups-with-", "show-threat-", "show-https-")) or clean_cmd in {
        "show-multicast-address-ranges",
        "show-security-zones",
        "show-dynamic-objects",
        "show-tags",
        "show-time-groups",
        "show-times",
        "show-wildcard",
        "show-wildcards",
        "show-gsn-handover-groups",
    }:
        return cp_ok({"objects": [], "from": 0, "to": 0, "total": 0})

    return None
