"""MCP lookup tools (`list_domains`, `show_object`, `get_group_members`)."""

from __future__ import annotations

from collections.abc import Callable
from fnmatch import fnmatchcase

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.context import SERVICE_COMMAND_TYPES
from arodonata.core.errors import AmbiguousObjectError
from arodonata.core.models.common import CANONICAL_ASSET_TYPES
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
    CANONICAL_LAYER_AND_PACKAGE_TYPES,
    _build_page_envelope,
    _compute_cache_age,
    _is_live_cache_mode,
    _normalize_cache_mode,
    _serialize_any_entity,
    _serialize_domain,
    _upgrade_uninitialized_cache_mode,
)
from arodonata.mcp.tools._show_object import (
    ambiguous_show_result,
    dedupe_exact_candidates,
    exact_match_result,
    live_show_object,
    load_show_object_candidates,
    sliced_candidate_result,
    validate_show_object_type,
)


def register_lookup_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    _mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register `list_domains`, `show_object`, and `get_group_members`."""

    @server.tool(
        name="list_domains",
        description="List Check Point domains on a management server from arodonata_domains with server-level metadata and cache freshness.",
    )
    @mcp_tool_guard("list_domains", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def list_domains(
        mgmt_name: str | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        if not is_live:
            mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, None, "domains", mode)
        domains = await client.get_domains(
            mgmt_name=eff_mgmt,
            include_global=include_global,
            cache_mode="force" if is_live else mode,
        )
        age = None if is_live else await _compute_cache_age(client, eff_mgmt, None, "domains", "*")
        serialized = [_serialize_domain(d, details_level=details_level) for d in domains]
        return json_tool_result(
            _build_page_envelope(
                serialized,
                limit=limit,
                offset=offset,
                source="live" if is_live else "cache",
                cache_age_seconds=age,
                extra={"mgmt_name": eff_mgmt},
            )
        )

    @server.tool(
        name="show_object",
        description=(
            "Retrieve a Check Point object, service, gateway/cluster/VSX asset (including cached interfaces, "
            "blades, and cluster/VSX members), policy package, or rulebase layer by UID, exact name, explicit "
            "wildcard pattern (e.g. 'gw-*01', evaluated strictly as written without implicit prefix/suffix '*'), "
            "or substring fallback (returning up to limit=20 compact candidates when no exact match exists)."
        ),
    )
    @mcp_tool_guard("show_object", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def show_object(
        uid_or_name: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        obj_type: str | None = None,
        details_level: str = "full",
        limit: int = 20,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domain = eff_domain or "default"
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        clean_obj_type = validate_show_object_type(obj_type, eff_mgmt, eff_domain)

        query_str = uid_or_name.strip() if uid_or_name else ""
        if not query_str:
            raise ToolFailure("uid_or_name must not be empty or whitespace", mgmt_name=eff_mgmt, domain=eff_domain)
        query_lower = query_str.lower()
        has_explicit_wildcard = "*" in query_str or "?" in query_str

        if not is_live:
            sync_domain, eff_mode = await client.search_service.resolve_implicit_domain_mode(eff_mgmt, eff_domain, mode)
            is_service_type = clean_obj_type is not None and (
                clean_obj_type in SERVICE_COMMAND_TYPES or clean_obj_type.startswith("service-")
            )
            is_asset_type = clean_obj_type is not None and clean_obj_type in {t.lower() for t in CANONICAL_ASSET_TYPES}
            is_layer_or_pkg_type = clean_obj_type is not None and clean_obj_type in CANONICAL_LAYER_AND_PACKAGE_TYPES

            if not has_explicit_wildcard and not is_layer_or_pkg_type:
                try:
                    found_exact = await client.find_object(
                        eff_mgmt, eff_domain, query_str, obj_type=clean_obj_type, cache_mode=eff_mode
                    )
                except AmbiguousObjectError as exc:
                    return ambiguous_show_result(eff_mgmt, exc.candidates, str(exc))
                if found_exact is not None:
                    return await exact_match_result(
                        client, found_exact, eff_mgmt=eff_mgmt, target_domain=target_domain, details_level=details_level
                    )

            candidates = await load_show_object_candidates(
                client,
                eff_mgmt=eff_mgmt,
                eff_domain=eff_domain,
                sync_domain=sync_domain,
                clean_obj_type=clean_obj_type,
                eff_mode=eff_mode,
                has_explicit_wildcard=has_explicit_wildcard,
                is_service_type=is_service_type,
                is_asset_type=is_asset_type,
                is_layer_or_pkg_type=is_layer_or_pkg_type,
            )

            if not has_explicit_wildcard:
                exact_cands = dedupe_exact_candidates(
                    [c for c in candidates if c.uid.lower() == query_lower or c.name.lower() == query_lower]
                )
                if exact_cands:
                    cand_domains = {
                        getattr(c, "original_domain", None) or getattr(c, "domain_name", None) or target_domain
                        for c in exact_cands
                    }
                    if eff_domain is None and len(cand_domains) > 1:
                        return ambiguous_show_result(
                            eff_mgmt,
                            [_serialize_any_entity(c, details_level="standard") for c in exact_cands],
                            f"Ambiguous lookup for {uid_or_name!r} on {eff_mgmt!r} matched across "
                            f"multiple domains ({', '.join(sorted(cand_domains))}). Specify 'domain'.",
                        )
                    return await exact_match_result(
                        client,
                        exact_cands[0],
                        eff_mgmt=eff_mgmt,
                        target_domain=target_domain,
                        details_level=details_level,
                    )

            if has_explicit_wildcard:
                wildcard_matches = [c for c in candidates if fnmatchcase(c.name.lower(), query_lower)]
                age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", "*")
                if len(wildcard_matches) == 1:
                    matched_domain = getattr(wildcard_matches[0], "domain_name", None) or target_domain
                    single_dict = _serialize_any_entity(wildcard_matches[0], details_level=details_level)
                    return json_tool_result(
                        {
                            "from": 1,
                            "to": 1,
                            "total": 1,
                            "match_type": "wildcard",
                            "source": "cache",
                            "cache_age_seconds": age,
                            "mgmt_name": eff_mgmt,
                            "domain": matched_domain,
                            "object": single_dict,
                            "objects": [single_dict],
                        }
                    )
                return sliced_candidate_result(
                    wildcard_matches,
                    match_type="wildcard",
                    age=age,
                    eff_mgmt=eff_mgmt,
                    domain=eff_domain or target_domain,
                    offset=offset,
                    limit=limit,
                )

            substring_matches = [c for c in candidates if query_lower and query_lower in c.name.lower()]
            if substring_matches:
                age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", "*")
                matched_sub_domain = (
                    (getattr(substring_matches[0], "domain_name", None) or target_domain)
                    if len(substring_matches) == 1
                    else (eff_domain or target_domain)
                )
                eff_offset = max(0, offset)
                eff_limit = max(1, min(limit, 500))
                sliced_first = (
                    _serialize_any_entity(substring_matches[0], details_level="standard")
                    if len(substring_matches) == 1 and eff_offset == 0 and eff_limit >= 1
                    else None
                )
                shown_count = len(substring_matches[eff_offset : eff_offset + eff_limit])
                return sliced_candidate_result(
                    substring_matches,
                    match_type="substring_candidates",
                    age=age,
                    eff_mgmt=eff_mgmt,
                    domain=matched_sub_domain,
                    offset=offset,
                    limit=limit,
                    single_object=sliced_first,
                    hint=(
                        f"No exact match for {uid_or_name!r}; returning {shown_count} of "
                        f"{len(substring_matches)} cached substring candidate(s). Pass an exact name/UID "
                        "or an explicit wildcard pattern (e.g. 'prefix*suffix')."
                    ),
                )

        return await live_show_object(
            client,
            query_str=query_str,
            uid_or_name=uid_or_name,
            eff_mgmt=eff_mgmt,
            eff_domain=eff_domain,
            target_domain=target_domain,
            clean_obj_type=clean_obj_type,
            details_level=details_level,
        )

    @server.tool(
        name="get_group_members",
        description=(
            "Expand direct and recursive members of a Check Point network group (arodonata_objects), "
            "service-group (arodonata_services), or cluster/VSX container (arodonata_assets) from cache."
        ),
    )
    @mcp_tool_guard("get_group_members", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def get_group_members(
        group_name_or_uid: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        recursive: bool = True,
        max_depth: int = 5,
        limit: int = 100,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domain = eff_domain or "default"
        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        sync_domain, eff_mode = await client.search_service.resolve_implicit_domain_mode(eff_mgmt, eff_domain, mode)

        try:
            resolved_group, members = await client.search_service.resolve_group_with_members(
                eff_mgmt, eff_domain, group_name_or_uid, recursive=recursive, max_depth=max_depth, cache_mode=eff_mode
            )
        except AmbiguousObjectError as exc:
            return json_tool_result(
                {
                    "from": 1 if exc.candidates else 0,
                    "to": len(exc.candidates),
                    "total": len(exc.candidates),
                    "match_type": "ambiguous",
                    "source": "cache",
                    "cache_age_seconds": None,
                    "group": group_name_or_uid,
                    "mgmt_name": eff_mgmt,
                    "domain": None,
                    "objects": exc.candidates,
                    "hint": str(exc),
                }
            )
        matched_domain = (
            (getattr(resolved_group, "domain_name", None) if resolved_group is not None else None)
            or eff_domain
            or sync_domain
            or target_domain
        )
        age = await _compute_cache_age(client, eff_mgmt, matched_domain, "objects", "group")
        serialized = [_serialize_any_entity(m, details_level="standard") for m in members]
        return json_tool_result(
            _build_page_envelope(
                serialized,
                limit=limit,
                offset=offset,
                source="cache",
                cache_age_seconds=age,
                extra={"group": group_name_or_uid, "mgmt_name": eff_mgmt, "domain": matched_domain},
            )
        )
