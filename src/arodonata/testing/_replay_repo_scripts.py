"""Repository script CRUD and listing handlers for `FileReplayApiMock`."""

from __future__ import annotations

import base64
import copy
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT
from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.scripts import decode_base64_task_message

from ._emulator_models import cp_error, cp_ok, format_domain_meta, format_timestamp
from ._emulator_projection import paginate_items

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def project_repository_script(item: Mapping[str, Any], details_level: str) -> dict[str, Any]:
    """Project a repository script object according to Check Point `details-level`."""
    lvl = (details_level or "standard").strip().lower()
    if lvl == "uid":
        uid = item.get("uid")
        return {"uid": uid} if uid is not None else copy.deepcopy(dict(item))
    return copy.deepcopy(dict(item))


def extract_repo_script_body(req: Mapping[str, Any], *, fallback: str | None = None) -> str | None:
    """Extract `script-body` or Base64-decoded `script-body-base64` from a request payload."""
    raw_body = req.get("script-body")
    if isinstance(raw_body, str):
        return raw_body
    raw_b64 = req.get("script-body-base64")
    if isinstance(raw_b64, str) and raw_b64.strip():
        try:
            padded = raw_b64.strip() + "=" * ((4 - len(raw_b64.strip()) % 4) % 4)
            return base64.b64decode(padded, validate=True).decode("utf-8", errors="replace")
        except Exception:
            return decode_base64_task_message(raw_b64)
    return fallback


def handle_repository_script_mutation(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    target_files: dict[str, Any],
    now_ms: int,
    user_name: str,
    locked_uids_out: set[str],
) -> tuple[ApiCallResult, str | None] | None:
    """Execute `add-repository-script`, `set-repository-script`, or `delete-repository-script`."""
    if clean_cmd not in ("add-repository-script", "set-repository-script", "delete-repository-script"):
        return None
    if mock.manage_repository_scripts != "write":
        return (
            cp_error(
                "generic_err_no_permissions",
                "Permission denied: administrator lacks write permission for repository scripts",
                status_code=400,
            ),
            None,
        )

    details_level = str(req.get("details-level") or "standard")
    bucket = target_files.setdefault("show-repository-scripts", {"objects": [], "from": 0, "to": 0, "total": 0})
    scripts_list: list[dict[str, Any]] = bucket.setdefault("objects", [])

    def _refresh_counts() -> None:
        bucket["total"] = len(scripts_list)
        bucket["from"] = 1 if scripts_list else 0
        bucket["to"] = len(scripts_list)

    def _find_idx(lookup: str) -> int | None:
        for idx, item in enumerate(scripts_list):
            if isinstance(item, dict) and (item.get("uid") == lookup or item.get("name") == lookup):
                return idx
        return None

    if clean_cmd == "add-repository-script":
        name = str(req.get("name") or "").strip()
        if not name:
            return cp_error("err_validation_failed", "add-repository-script: 'name' is required", status_code=400), None
        body = extract_repo_script_body(req)
        if body is None:
            return (
                cp_error(
                    "err_validation_failed",
                    "add-repository-script: 'script-body' or 'script-body-base64' is required",
                    status_code=400,
                ),
                None,
            )
        existing_idx = _find_idx(name)
        if existing_idx is not None:
            if bool(req.get("set-if-exists", False)):
                set_req = dict(req)
                set_req["uid"] = scripts_list[existing_idx]["uid"]
                return handle_repository_script_mutation(
                    mock,
                    "set-repository-script",
                    set_req,
                    dom_name=dom_name,
                    target_files=target_files,
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
        assigned_uid = str(req.get("uid") or "").strip() or mock._allocate_repo_script_uid()
        ts = format_timestamp(now_ms)
        raw_tags = req.get("tags")
        if isinstance(raw_tags, list):
            tags_list = [str(t) for t in raw_tags if str(t).strip()]
        elif isinstance(raw_tags, str) and raw_tags.strip():
            tags_list = [raw_tags.strip()]
        else:
            tags_list = []
        new_obj: dict[str, Any] = {
            "uid": assigned_uid,
            "name": name,
            "type": "script",
            "domain": format_domain_meta(dom_name),
            "script-body": body,
            "args": str(req.get("args") or ""),
            "color": str(req.get("color") or "black"),
            "comments": str(req.get("comments") or ""),
            "tags": tags_list,
            "meta-info": {
                "lock": "unlocked",
                "validation-state": "ok",
                "creator": user_name,
                "creation-time": dict(ts),
                "last-modifier": user_name,
                "last-modify-time": dict(ts),
            },
        }
        scripts_list.append(new_obj)
        _refresh_counts()
        locked_uids_out.add(assigned_uid)
        return cp_ok(project_repository_script(new_obj, details_level)), assigned_uid

    if clean_cmd == "set-repository-script":
        lookup = str(req.get("uid") or req.get("name") or "").strip()
        idx = _find_idx(lookup)
        if idx is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested repository script [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        target_obj = scripts_list[idx]
        new_name = str(req.get("new-name") or "").strip()
        if new_name and new_name != target_obj.get("name"):
            dup_idx = _find_idx(new_name)
            if dup_idx is not None and dup_idx != idx:
                return (
                    cp_error(
                        "err_validation_failed",
                        f"More than one object named [{new_name}] exists",
                        status_code=400,
                    ),
                    None,
                )
            target_obj["name"] = new_name
        new_body = extract_repo_script_body(req)
        if new_body is not None:
            target_obj["script-body"] = new_body
        if "args" in req:
            target_obj["args"] = str(req.get("args") or "")
        if "color" in req and req.get("color") is not None:
            target_obj["color"] = str(req["color"])
        if "comments" in req and req.get("comments") is not None:
            target_obj["comments"] = str(req["comments"])
        if "tags" in req and req.get("tags") is not None:
            raw_tags = req["tags"]
            if isinstance(raw_tags, list):
                target_obj["tags"] = [str(t) for t in raw_tags if str(t).strip()]
            elif isinstance(raw_tags, str):
                target_obj["tags"] = [raw_tags.strip()] if raw_tags.strip() else []
            elif isinstance(raw_tags, Mapping):
                cur_tags = list(target_obj.get("tags") or [])
                if "add" in raw_tags:
                    adds = raw_tags["add"] if isinstance(raw_tags["add"], list) else [raw_tags["add"]]
                    for t in adds:
                        if str(t).strip() and str(t) not in cur_tags:
                            cur_tags.append(str(t))
                if "remove" in raw_tags:
                    rems = raw_tags["remove"] if isinstance(raw_tags["remove"], list) else [raw_tags["remove"]]
                    rem_set = {str(t) for t in rems}
                    cur_tags = [t for t in cur_tags if t not in rem_set]
                target_obj["tags"] = cur_tags
        ts = format_timestamp(now_ms)
        meta = target_obj.setdefault("meta-info", {})
        if isinstance(meta, dict):
            meta["last-modifier"] = user_name
            meta["last-modify-time"] = dict(ts)
        uid_str = str(target_obj["uid"])
        locked_uids_out.add(uid_str)
        return cp_ok(project_repository_script(target_obj, details_level)), uid_str

    lookup = str(req.get("uid") or req.get("name") or "").strip()
    idx = _find_idx(lookup)
    if idx is None:
        return (
            cp_error(
                "generic_err_object_not_found",
                f"Requested repository script [{lookup}] not found",
                status_code=404,
            ),
            None,
        )
    removed = scripts_list.pop(idx)
    _refresh_counts()
    uid_str = str(removed["uid"])
    locked_uids_out.add(uid_str)
    return cp_ok({"message": "OK", "uid": uid_str}), uid_str


def handle_show_repository_scripts(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: Mapping[str, Any],
    *,
    dom_files: Mapping[str, Any],
) -> ApiCallResult:
    """Handle `show-repository-script` and `show-repository-scripts` with optional R82 Base64 parity."""
    if mock.manage_repository_scripts == "none":
        return cp_error(
            "generic_err_no_permissions",
            "Permission denied: administrator lacks read permission for repository scripts",
            status_code=400,
        )
    scripts_list = [
        item for item in dom_files.get("show-repository-scripts", {}).get("objects", []) if isinstance(item, dict)
    ]
    details_level = str(req.get("details-level") or "standard")
    if clean_cmd == "show-repository-script":
        lookup = str(req.get("uid") or req.get("name") or "").strip()
        matched_script = next(
            (s for s in scripts_list if s.get("uid") == lookup or s.get("name") == lookup),
            None,
        )
        if matched_script is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Requested repository script [{lookup}] not found",
                status_code=404,
            )
        projected_obj = project_repository_script(matched_script, details_level)
        if mock.encode_repository_script_body_base64 and isinstance(projected_obj.get("script-body"), str):
            raw_str = projected_obj["script-body"]
            projected_obj["script-body"] = base64.b64encode(raw_str.encode("utf-8")).decode("ascii")
        return cp_ok(projected_obj)

    order_desc = False
    raw_order = req.get("order")
    if isinstance(raw_order, list) and raw_order and isinstance(raw_order[0], Mapping):
        order_desc = "DESC" in raw_order[0]
    sorted_scripts = sorted(scripts_list, key=lambda s: str(s.get("name") or ""), reverse=order_desc)
    page = paginate_items(
        sorted_scripts,
        req,
        collection_key="objects",
        default_limit=DEFAULT_PAGE_LIMIT,
        default_details_level="standard",
        min_limit=0,
        projector=project_repository_script,
    )
    if mock.encode_repository_script_body_base64:
        for obj in page["objects"]:
            if isinstance(obj.get("script-body"), str):
                obj["script-body"] = base64.b64encode(obj["script-body"].encode("utf-8")).decode("ascii")
    return cp_ok(page)
