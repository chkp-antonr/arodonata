"""MCP tools for listing, searching, and structured querying of objects, services, and assets."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    DEFAULT_OBJECT_TYPES,
    DEFAULT_SERVICE_TYPES,
    expand_asset_types,
    normalize_object_type,
    normalize_service_type,
)
from arodonata.core.services.object_service import resolve_object_query_command
from arodonata.core.services.service_cache import resolve_service_query_command
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
    _build_page_envelope,
    _compute_cache_age,
    _enforce_live_quota_if_sync_required,
    _fetch_live_collection,
    _filter_assets,
    _filter_cp_objects,
    _filter_cp_services,
    _is_live_cache_mode,
    _normalize_cache_mode,
    _raise_if_sync_failed,
    _serialize_asset,
    _serialize_object,
    _serialize_service,
    _upgrade_uninitialized_cache_mode,
    _validate_optional_domains,
)


def _filter_assets_by_parent(
    all_assets: Sequence[Asset],
    parent: str,
    expanded_types: Sequence[str] | None,
) -> list[Asset]:
    """Filter cached assets matching a parent cluster or VSX container by UID, ID, or name."""
    parent_clean = parent.strip()
    parent_lower = parent_clean.lower()
    parent_child_uids: set[str] = set()
    parent_child_asset_ids: set[str] = set()
    matched_parent_uids: set[str] = set()
    matched_parent_ids: set[str] = set()
    matched_parent_asset_ids: set[str] = set()
    for a in all_assets:
        if (
            a.uid == parent_clean
            or a.id == parent_clean
            or a.asset_id.lower() == parent_lower
            or a.name.lower() == parent_lower
        ):
            matched_parent_uids.add(a.uid)
            matched_parent_ids.add(a.id)
            matched_parent_asset_ids.add(a.asset_id.lower())
            parent_child_uids.update(a.member_uids)
            parent_child_uids.update(a.virtual_system_uids)
            parent_child_asset_ids.update(aid.lower() for aid in a.member_asset_ids)
            parent_child_asset_ids.update(aid.lower() for aid in a.virtual_system_asset_ids)

    matched = [
        a
        for a in all_assets
        if a.uid in parent_child_uids
        or a.asset_id.lower() in parent_child_asset_ids
        or a.parent_uid == parent_clean
        or a.parent_id == parent_clean
        or (a.parent_asset_id is not None and a.parent_asset_id.lower() == parent_lower)
        or (a.parent_uid is not None and a.parent_uid in matched_parent_uids)
        or (a.parent_id is not None and a.parent_id in matched_parent_ids)
        or (a.parent_asset_id is not None and a.parent_asset_id.lower() in matched_parent_asset_ids)
        or (a.parent_name is not None and a.parent_name.lower() == parent_lower)
    ]
    if expanded_types:
        t_set = {t.lower() for t in expanded_types}
        matched = [a for a in matched if a.type.lower() in t_set]
    return matched


def register_object_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    _mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register `list_objects`, `list_services`, `list_assets`, `search_objects`, and `query_objects`."""

    @server.tool(
        name="list_objects",
        description=(
            "List Check Point network objects from arodonata_objects (hosts, networks, address-ranges, "
            "dns-domains, groups, dynamic-objects, etc.) with optional types filter (e.g. types=['host', 'network'] "
            "or aliases 'range', 'dns', 'dynamic')."
        ),
    )
    @mcp_tool_guard("list_objects", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def list_objects(
        mgmt_name: str | None = None,
        domain: str | None = None,
        types: list[str] | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        normalized_types = [normalize_object_type(t) for t in types if t and t.strip()] if types else None

        if is_live:
            live_envelope = await _fetch_live_collection(
                client,
                eff_mgmt=eff_mgmt,
                eff_domain=eff_domain,
                live_types=normalized_types or list(DEFAULT_OBJECT_TYPES),
                command_resolver=resolve_object_query_command,
                filter_text=filter,
                details_level=details_level,
                limit=limit,
                offset=offset,
            )
            return json_tool_result(live_envelope)

        mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, eff_domain, "objects", mode)
        await _enforce_live_quota_if_sync_required(
            client,
            eff_mgmt,
            eff_domain,
            "objects",
            mode,
            item_types=normalized_types or list(DEFAULT_OBJECT_TYPES),
        )
        objs = await client.get_objects(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=normalized_types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=mode,
        )
        obj_item_type = normalized_types[0] if normalized_types and len(normalized_types) == 1 else "*"
        if mode != "cache":
            await _raise_if_sync_failed(
                client, eff_mgmt, eff_domain, "objects", obj_item_type, has_cached_data=bool(objs)
            )
        filtered = _filter_cp_objects(objs, filter)
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", obj_item_type)
        serialized = [_serialize_object(o, details_level=details_level) for o in filtered]
        envelope = _build_page_envelope(
            serialized,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
        )
        return json_tool_result(envelope)

    @server.tool(
        name="list_services",
        description=(
            "List Check Point service objects from arodonata_services (service-tcp, service-udp, service-icmp, "
            "service-group, service-other, etc.) supporting short type aliases ('tcp', 'udp', 'icmp', 'group', 'other')."
        ),
    )
    @mcp_tool_guard("list_services", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def list_services(
        mgmt_name: str | None = None,
        domain: str | None = None,
        types: list[str] | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        normalized_types = [normalize_service_type(t) for t in types if t and t.strip()] if types else None

        if is_live:
            live_envelope = await _fetch_live_collection(
                client,
                eff_mgmt=eff_mgmt,
                eff_domain=eff_domain,
                live_types=normalized_types or list(DEFAULT_SERVICE_TYPES),
                command_resolver=resolve_service_query_command,
                filter_text=filter,
                details_level=details_level,
                limit=limit,
                offset=offset,
            )
            return json_tool_result(live_envelope)

        mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, eff_domain, "services", mode)
        await _enforce_live_quota_if_sync_required(
            client,
            eff_mgmt,
            eff_domain,
            "services",
            mode,
            item_types=normalized_types or list(DEFAULT_SERVICE_TYPES),
        )
        svcs = await client.get_services(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=normalized_types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=mode,
        )
        svc_item_type = normalized_types[0] if normalized_types and len(normalized_types) == 1 else "*"
        if mode != "cache":
            await _raise_if_sync_failed(
                client, eff_mgmt, eff_domain, "services", svc_item_type, has_cached_data=bool(svcs)
            )
        filtered = _filter_cp_services(svcs, filter)
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "services", svc_item_type)
        serialized = [_serialize_service(s, details_level=details_level) for s in filtered]
        envelope = _build_page_envelope(
            serialized,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
        )
        return json_tool_result(envelope)

    @server.tool(
        name="list_assets",
        description=(
            "List Check Point gateways, clusters, cluster members, VSX systems, virtual systems, and management "
            "servers (checkpoint-host) from arodonata_assets with optional types filter ('gateway', 'cluster', "
            "'member', 'vsx', 'vs', 'server' — automatically matching both REST and Check Point Cpmi* classes such as "
            "CpmiGatewayCluster, CpmiVsxNetobj, CpmiVsNetobj) and parent cluster/VSX filter."
        ),
    )
    @mcp_tool_guard("list_assets", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def list_assets(
        mgmt_name: str | None = None,
        domain: str | None = None,
        types: list[str] | None = None,
        parent: str | None = None,
        filter: str | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")
        expanded_types = expand_asset_types(types) if types else None

        if is_live:
            payload: dict[str, Any] = {
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
                "details-level": details_level,
            }
            res = await client.api_call(eff_mgmt, "show-gateways-and-servers", payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"show-gateways-and-servers failed on {eff_mgmt!r} ({eff_domain or 'default'}): "
                    f"{res.error_message or 'API error'}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            objs_raw = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
            return json_tool_result(
                {
                    "from": res.data.get("from", (offset + 1) if objs_raw else 0),
                    "to": res.data.get("to", offset + len(objs_raw)),
                    "total": res.data.get("total", len(objs_raw)),
                    "source": "live",
                    "cache_age_seconds": None,
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "objects": objs_raw,
                }
            )

        # When filtering by `parent`, load all domain assets first so parent -> member_uids can be resolved
        mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, eff_domain, "assets", mode)
        await _enforce_live_quota_if_sync_required(client, eff_mgmt, eff_domain, "assets", mode)
        all_assets = await client.get_gateways(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=expanded_types if not parent else None,
            include_global=include_global,
            cache_mode=mode,
        )
        if mode != "cache":
            await _raise_if_sync_failed(client, eff_mgmt, eff_domain, "assets", "*", has_cached_data=bool(all_assets))

        assets = (
            _filter_assets_by_parent(all_assets, parent, expanded_types)
            if parent and parent.strip()
            else list(all_assets)
        )
        filtered = _filter_assets(assets, filter)
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "assets", "*")
        serialized = [_serialize_asset(a, details_level=details_level) for a in filtered]
        envelope = _build_page_envelope(
            serialized,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
        )
        return json_tool_result(envelope)

    @server.tool(
        name="search_objects",
        description=(
            "Search Check Point objects across IPv4, CIDR, range, wildcard, UID, or name with recursive parent "
            "group memberships across all configured management servers and domains. Defaults to cache_mode='smart' "
            "(auto-syncing uncached or stale domains); leave cache_mode='smart' unless offline-only inspection is required."
        ),
    )
    @mcp_tool_guard("search_objects", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def search_objects(
        query: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: list[str] | None = None,
        types: list[str] | None = None,
        include_global: bool = False,
        max_depth: int = 2,
        exact_match: bool = False,
        limit: int = 100,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if (mgmt_name or domain or domains) else None
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain) if eff_mgmt else None
        target_domains = domains if domains is not None else ([eff_domain] if eff_domain else None)
        await _validate_optional_domains(client, eff_mgmt, target_domains)

        raw_types = [t.strip() for t in types if t and t.strip()] if types else None
        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, eff_domain, "objects", mode)
        await _enforce_live_quota_if_sync_required(
            client,
            eff_mgmt,
            eff_domain,
            "objects",
            mode,
            domains=target_domains,
        )
        result = await client.search_objects(
            query,
            mgmt_name=eff_mgmt,
            domains=target_domains,
            types=raw_types,
            include_global=include_global,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=mode,
        )
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", "*")
        envelope_mgmt = eff_mgmt or (client.settings.mgmt_names[0] if len(client.settings.mgmt_names) == 1 else None)
        serialized_matches = [_serialize_object(o, details_level="standard") for o in result.matches]
        envelope = _build_page_envelope(
            serialized_matches,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={
                "query": result.query,
                "mgmt_name": envelope_mgmt,
                "domain": eff_domain,
                "memberships": {
                    uid: [node.model_dump(mode="json") for node in nodes] for uid, nodes in result.memberships.items()
                },
            },
        )
        return json_tool_result(envelope)

    @server.tool(
        name="query_objects",
        description=(
            "Execute structured cross-domain filtering, grouping (group_by), counting (aggregate='count'|'list'), "
            "or progressive-disclosure schema introspection (aggregate='describe') over arodonata_objects, "
            "arodonata_services, and arodonata_assets, distinguishing local vs Global objects via original_domain. "
            "Groupable fields: mgmt_name (aliases: mgmt, server), domain_name (alias: domain), original_domain, "
            "type (aliases: object_type, asset_type), color, protocol. Asset type aliases ('gateway', 'cluster', "
            "'member', 'vsx', 'vs', 'server') match both REST and Check Point Cpmi* classes. "
            "Defaults to cache_mode='smart' (auto-syncing uncached or stale domains)."
        ),
    )
    @mcp_tool_guard("query_objects", client_getter, quota_manager=quota_manager, is_live_tool=_is_live_cache_mode)
    async def query_objects(
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: list[str] | None = None,
        types: list[str] | None = None,
        scope_origin: Literal["all", "local", "global"] = "all",
        name_pattern: str | None = None,
        ip_subnet: str | None = None,
        port: str | None = None,
        protocol: str | None = None,
        tags: list[str] | None = None,
        parent_id: str | None = None,
        parent_asset_id: str | None = None,
        include_global: bool = False,
        group_by: list[str] | None = None,
        aggregate: Literal["count", "list", "describe"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        eff_domain = (
            await validate_domain_or_fail(client, eff_mgmt, domain)
            if (eff_mgmt and domain)
            else (domain.strip() if domain else None)
        )
        await _validate_optional_domains(client, eff_mgmt, domains)

        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        mode = await _upgrade_uninitialized_cache_mode(client, eff_mgmt, eff_domain, "objects", mode)
        await _enforce_live_quota_if_sync_required(
            client,
            eff_mgmt,
            eff_domain,
            "objects",
            mode,
            domains=domains,
        )
        result = await client.query_objects(
            mgmt_name=eff_mgmt,
            domain_name=eff_domain,
            domains=domains,
            types=types,
            scope_origin=scope_origin,
            name_pattern=name_pattern,
            ip_subnet=ip_subnet,
            port=port,
            protocol=protocol,
            tags=tags,
            parent_id=parent_id,
            parent_asset_id=parent_asset_id,
            include_global=include_global,
            group_by=group_by,
            aggregate=aggregate,
            limit=limit,
            offset=offset,
            cache_mode=mode,
        )
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", "*")
        result["source"] = "cache"
        result["cache_age_seconds"] = age
        return json_tool_result(result)
