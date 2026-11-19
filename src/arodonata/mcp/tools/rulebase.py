"""MCP rulebase inspection and numbering tools (`show_rulebase`, `locate_rules`)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.models.rulebase import DomainRulebaseSnapshot, RulebaseType
from arodonata.core.primitives import is_uuid
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.errors import (
    ToolFailure,
    json_tool_result,
    mcp_tool_guard,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.mcp.quota import MCPToolQuotaManager
from arodonata.mcp.tools._common import (
    _is_live_cache_mode,
    _is_live_rulebase_call,
    _normalize_cache_mode,
    _serialize_layer,
    _serialize_package,
)
from arodonata.rulebase import RULEBASE_TYPE_TO_COMMAND, RuleFormat
from arodonata.rulebase.numbering import extract_policy_packages


def _build_catalog_payload(
    snap: DomainRulebaseSnapshot,
    snap_age: float | None,
    *,
    eff_mgmt: str,
    target_domain: str,
    rulebase_type: RulebaseType,
    hint_message: str | None = None,
) -> dict[str, Any]:
    """Serialize cached policy packages and layers into a rulebase catalog payload."""
    packages = [_serialize_package(p, details_level="standard") for p in extract_policy_packages(snap)]
    layers = [
        _serialize_layer(l_entry, details_level="standard")
        for l_entry in snap.layers
        if rulebase_type == "nat" or l_entry.rulebase_type == rulebase_type
    ]
    catalog_payload: dict[str, Any] = {
        "mode": "catalog",
        "from": 1 if (packages or layers) else 0,
        "to": len(packages) if packages else len(layers),
        "total": len(packages) if packages else len(layers),
        "source": "cache",
        "cache_age_seconds": round(snap_age, 3) if snap_age is not None else None,
        "mgmt_name": eff_mgmt,
        "domain": target_domain,
        "rulebase_type": rulebase_type,
        "packages": packages,
        "layers": layers,
        "objects": packages if packages else layers,
    }
    if hint_message:
        catalog_payload["hint"] = hint_message
    return catalog_payload


def _find_missing_target_hint(
    snap: DomainRulebaseSnapshot,
    *,
    eff_mgmt: str,
    target_domain: str,
    rulebase_type: RulebaseType,
    eff_package: str | None,
    eff_layer: str | None,
) -> str | None:
    """Return a discovery hint if `eff_package` or `eff_layer` is missing from a populated snapshot."""
    known_pkgs = {p.uid.lower() for p in extract_policy_packages(snap)} | {
        p.name.lower() for p in extract_policy_packages(snap)
    }
    known_layers = (
        {l_e.uid.lower() for l_e in snap.layers}
        | {l_e.name.lower() for l_e in snap.layers}
        | {pl.layer_uid.lower() for pl in snap.package_layers}
        | {pl.layer_name.lower() for pl in snap.package_layers}
    )
    if not (known_pkgs or known_layers):
        return None
    if rulebase_type == "nat":
        target_check = (eff_package or eff_layer or "").lower()
        if target_check and target_check not in known_pkgs:
            return (
                f"Policy package {eff_package or eff_layer!r} was not found in cached NAT rulebases on "
                f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
            )
        return None
    if eff_package and eff_package.lower() not in known_pkgs:
        return (
            f"Policy package {eff_package!r} was not found in cached {rulebase_type!r} rulebases on "
            f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
        )
    if eff_layer and eff_layer.lower() not in known_layers:
        return (
            f"Layer {eff_layer!r} was not found in cached {rulebase_type!r} rulebases on "
            f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
        )
    return None


async def _fetch_live_rulebase(
    client: ArodonataClient,
    *,
    live_command: str,
    eff_mgmt: str,
    eff_domain: str | None,
    rulebase_type: RulebaseType,
    eff_package: str | None,
    eff_layer: str | None,
    filter_query: str,
    format: RuleFormat,
    limit: int,
    offset: int,
    show_hits: bool,
    order: list[dict[str, Any]] | None,
    show_as_ranges: bool,
    show_expiration_settings: bool,
    filter_settings: dict[str, Any] | None,
    hits_settings: dict[str, Any] | None,
    dereference_group_members: bool,
    show_membership: bool,
) -> CallToolResult:
    """Execute a live `show-*-rulebase` Management API query."""
    payload: dict[str, Any] = {
        "limit": max(1, min(limit, 500)),
        "offset": max(0, offset),
        "details-level": "standard",
    }
    if rulebase_type == "nat":
        payload["package"] = eff_package or eff_layer
    else:
        if eff_layer:
            if is_uuid(eff_layer):
                payload["uid"] = eff_layer
            else:
                payload["name"] = eff_layer
        if eff_package:
            payload["package"] = eff_package

    if filter_query:
        payload["filter"] = filter_query
    if show_hits:
        payload["show-hits"] = True
    if order is not None:
        payload["order"] = order
    if show_as_ranges:
        payload["show-as-ranges"] = True
    if show_expiration_settings:
        payload["show-expiration-settings"] = True
    if filter_settings is not None:
        payload["filter-settings"] = filter_settings
    if hits_settings is not None:
        payload["hits-settings"] = hits_settings
    if dereference_group_members:
        payload["dereference-group-members"] = True
    if show_membership:
        payload["show-membership"] = True

    res = await client.api_call(eff_mgmt, live_command, payload, domain=eff_domain)
    if not res.success:
        raise ToolFailure(
            f"{live_command} failed on {eff_mgmt!r} ({eff_domain or 'default'}): {res.error_message or 'API error'}",
            mgmt_name=eff_mgmt,
            domain=eff_domain,
        )
    rb_items = res.data.get("rulebase", []) if isinstance(res.data.get("rulebase"), list) else []
    return json_tool_result(
        {
            "from": res.data.get("from", (offset + 1) if rb_items else 0),
            "to": res.data.get("to", offset + len(rb_items)),
            "total": res.data.get("total", len(rb_items)),
            "source": "live",
            "cache_age_seconds": None,
            "mgmt_name": eff_mgmt,
            "domain": eff_domain,
            "rulebase_type": rulebase_type,
            "format": format,
            "rulebase": rb_items,
        }
    )


def register_rulebase_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    _mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register `show_rulebase` and `locate_rules`."""

    @server.tool(
        name="show_rulebase",
        description=(
            "Show SmartConsole-numbered rulebase (rulebase_type='access'|'nat'|'https'|'threat') from cache "
            "(evaluating filter locally against cached objects/services in markdown, model_friendly, raw, or cpcrud format) "
            "or live API (when live-only parameters like show_hits or cache_mode='live' are used). "
            "When package and layer are omitted (or when a requested package/layer is not found), returns the "
            "domain's cached policy packages and layers (including inline layers and implicit_cleanup_action)."
        ),
    )
    @mcp_tool_guard("show_rulebase", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_rulebase_call)
    async def show_rulebase(
        mgmt_name: str | None = None,
        domain: str | None = None,
        rulebase_type: RulebaseType = "access",
        package: str | None = None,
        layer: str | None = None,
        name: str | None = None,
        uid: str | None = None,
        filter: str = "",
        format: RuleFormat = "markdown",
        limit: int = 100,
        offset: int = 0,
        cache_mode: str = "smart",
        show_hits: bool = False,
        order: list[dict[str, Any]] | None = None,
        show_as_ranges: bool = False,
        show_expiration_settings: bool = False,
        filter_settings: dict[str, Any] | None = None,
        hits_settings: dict[str, Any] | None = None,
        dereference_group_members: bool = False,
        show_membership: bool = False,
    ) -> CallToolResult:
        if rulebase_type not in RULEBASE_TYPE_TO_COMMAND:
            raise ToolFailure(
                f"Invalid rulebase_type {rulebase_type!r}. Expected 'access', 'nat', 'https', or 'threat'."
            )
        live_command = RULEBASE_TYPE_TO_COMMAND[rulebase_type]
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domain = eff_domain or "default"
        mode, is_live_mode = _normalize_cache_mode(cache_mode, default="smart")

        eff_package = package.strip() if package and package.strip() else None
        eff_layer = layer.strip() if layer and layer.strip() else None
        if rulebase_type == "nat":
            eff_package = eff_package or (name.strip() if name else None) or (uid.strip() if uid else None) or eff_layer
        elif not eff_layer and not eff_package:
            eff_layer = (name.strip() if name else None) or (uid.strip() if uid else None)

        # Discovery mode: when neither package nor layer is specified, return cached packages and layers
        if not eff_package and not eff_layer:
            snap, _, _, _, snap_age = await client.rulebase_source.ensure_and_load_snapshot(
                eff_mgmt, target_domain, cache_mode=mode
            )
            return json_tool_result(
                _build_catalog_payload(
                    snap,
                    snap_age,
                    eff_mgmt=eff_mgmt,
                    target_domain=target_domain,
                    rulebase_type=rulebase_type,
                )
            )

        has_live_only_params = any(
            [
                show_hits,
                order is not None,
                show_as_ranges,
                show_expiration_settings,
                filter_settings is not None,
                hits_settings is not None,
                dereference_group_members,
                show_membership,
            ]
        )

        if is_live_mode or has_live_only_params:
            return await _fetch_live_rulebase(
                client,
                live_command=live_command,
                eff_mgmt=eff_mgmt,
                eff_domain=eff_domain,
                rulebase_type=rulebase_type,
                eff_package=eff_package,
                eff_layer=eff_layer,
                filter_query=filter,
                format=format,
                limit=limit,
                offset=offset,
                show_hits=show_hits,
                order=order,
                show_as_ranges=show_as_ranges,
                show_expiration_settings=show_expiration_settings,
                filter_settings=filter_settings,
                hits_settings=hits_settings,
                dereference_group_members=dereference_group_members,
                show_membership=show_membership,
            )

        snap_check, _, _, _, snap_age = await client.rulebase_source.ensure_and_load_snapshot(
            eff_mgmt, target_domain, cache_mode=mode
        )
        missing_hint = _find_missing_target_hint(
            snap_check,
            eff_mgmt=eff_mgmt,
            target_domain=target_domain,
            rulebase_type=rulebase_type,
            eff_package=eff_package,
            eff_layer=eff_layer,
        )
        if missing_hint is not None:
            return json_tool_result(
                _build_catalog_payload(
                    snap_check,
                    snap_age,
                    eff_mgmt=eff_mgmt,
                    target_domain=target_domain,
                    rulebase_type=rulebase_type,
                    hint_message=missing_hint,
                )
            )

        filtered_res = await client.filter_rulebase(
            eff_mgmt,
            eff_domain,
            package=eff_package,
            layer=eff_layer if rulebase_type != "nat" else None,
            rulebase_type=rulebase_type,
            filter_query=filter,
            output_format=format,
            cache_mode="cache",
        )
        sliced_raw = filtered_res.raw_items[offset : offset + max(1, limit)]
        return json_tool_result(
            {
                "from": (offset + 1) if sliced_raw else 0,
                "to": offset + len(sliced_raw),
                "total": filtered_res.matched_count,
                "total_unfiltered": filtered_res.total_rules,
                "source": "cache",
                "cache_age_seconds": (
                    round(filtered_res.cache_age_seconds, 3) if filtered_res.cache_age_seconds is not None else None
                ),
                "mgmt_name": filtered_res.mgmt_name,
                "domain": filtered_res.domain_name,
                "target_name": filtered_res.target_name,
                "target_uid": filtered_res.target_uid,
                "rulebase_type": filtered_res.rulebase_type,
                "format": filtered_res.format,
                "query": filtered_res.query,
                "rendered_text": filtered_res.rendered_text,
                "rules": sliced_raw,
            }
        )

    @server.tool(
        name="locate_rules",
        description="Locate SmartConsole rule numbers and layer prefixes across all policy packages and layers of a domain.",
    )
    @mcp_tool_guard("locate_rules", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def locate_rules(
        mgmt_name: str | None = None,
        domain: str | None = None,
        rule_uids: list[str] | None = None,
        layer_uids: list[str] | None = None,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        locations = await client.locate_rules(
            eff_mgmt,
            eff_domain,
            rule_uids=rule_uids,
            layer_uids=layer_uids,
            cache_mode=mode,
        )
        return json_tool_result(locations.model_dump(mode="json"))
