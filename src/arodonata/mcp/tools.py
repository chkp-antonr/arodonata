"""MCP tool surface registration (`arodonata.mcp.tools`).

Exposes:
- Cached listing and lookup tools (`show_domains`, `show_hosts`, `show_networks`,
  `show_address_ranges`, `show_dns_domains`, `show_services`, `show_groups`,
  `show_gateways_and_servers`, `show_object`, `find_object`, `search_objects`,
  `get_group_members`) with `from`, `to`, `total`, `source`, and `cache_age_seconds`.
- Progressive-disclosure aggregation and cache status tools (`describe_objects`,
  `query_objects`, `cache_status`, `refresh_cache`).
- Hybrid rulebase tools (`show_access_rulebase`, `show_nat_rulebase`,
  `show_https_rulebase`, `show_threat_rulebase`, `show_policy_packages`,
  `locate_rules`).
- Change report tool (`change_report`) and write-protected `api_call`.
- Optional live-compatibility tools (`ARODONATA_MCP_LIVE_COMPAT=true`).
- Opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`: `cpcrud_validate`,
  `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from collections import OrderedDict
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.adapters.checkpoint.client import is_readonly_command
from arodonata.adapters.checkpoint.transport import validate_command_name
from arodonata.client import ArodonataClient
from arodonata.core.errors import InvalidCredentialsError, ValidationError, redact_sid, sanitize_mapping
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, SyncScope, utc_now
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.models.services import CPService
from arodonata.core.services.search_service import classify_search_term, matches_classified_term
from arodonata.cpcrud import ApplyReport, IpConflictPolicy, NameConflictPolicy, Plan
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.errors import (
    ToolFailure,
    collect_known_sids,
    json_tool_result,
    mcp_tool_guard,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.reports import RangeScope, RenderOptions, ReportScope, SessionScope
from arodonata.rulebase import RuleFormat

MCPCacheModeInput = Literal["cache", "smart", "smart-fast", "force", "live"]
MAX_MCP_API_TIMEOUT_SECONDS: float = 300.0
MAX_STORED_PLANS: int = 256
CANONICAL_SHOW_OBJECT_TYPES: frozenset[str] = (
    OBJECT_ITEM_TYPES
    | SERVICE_ITEM_TYPES
    | frozenset(
        {
            "simple-gateway",
            "simple-cluster",
            "checkpoint-host",
            "vsx-gateway",
            "vsx-cluster",
            "interoperable-device",
            "generic-object",
        }
    )
)


def _canonical_plan_payload(plan_dict: dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for a CPCRUD `Plan` dictionary excluding `plan_id` / `plan_signature`."""
    stripped = {k: v for k, v in plan_dict.items() if k not in ("plan_id", "plan_signature")}
    normalized = Plan.model_validate(stripped).model_dump(mode="json")
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_plan(hmac_key: bytes, plan_dict: dict[str, Any]) -> str:
    """Compute HMAC-SHA256 hex digest over the canonical serialized `Plan`."""
    return hmac.new(hmac_key, _canonical_plan_payload(plan_dict), hashlib.sha256).hexdigest()


def _normalize_cache_mode(mode: str | None, *, default: CacheMode = "smart") -> tuple[CacheMode, bool]:
    """Return `(cache_mode, is_live)` from a user-supplied `cache_mode` parameter."""
    if not mode or not mode.strip():
        return default, False
    cleaned = mode.strip().lower()
    if cleaned == "live":
        return "force", True
    if cleaned in ("cache", "smart", "smart-fast", "force"):
        return cleaned, False  # type: ignore[return-value]
    raise ToolFailure(f"Invalid cache_mode {mode!r}. Expected one of: 'cache', 'smart', 'smart-fast', 'force', 'live'.")


async def _compute_cache_age(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str | None,
    scope: SyncScope,
    item_type: str = "*",
    *,
    now_fn: Callable[[], datetime] = utc_now,
) -> float | None:
    """Compute `cache_age_seconds` from `domain_sync_state` for `(mgmt_name, domain, scope, item_type)`."""
    states = await client.cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if item_type != "*":
        matching = [s for s in states if s.item_type in (item_type, "*")]
        if matching:
            states = matching

    synced_times = [s.synced_at for s in states if s.synced_at is not None]
    if not synced_times:
        return 0.0
    latest = max(synced_times)
    return max(0.0, round((now_fn() - latest).total_seconds(), 3))


async def _raise_if_sync_failed(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str | None,
    scope: SyncScope,
    item_type: str = "*",
    *,
    has_cached_data: bool = False,
) -> None:
    """Inspect `domain_sync_state` and raise `InvalidCredentialsError` or `ToolFailure` if sync failed."""
    states = await client.cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if item_type != "*":
        matching = [s for s in states if s.item_type in (item_type, "*")]
        if matching:
            states = matching

    for st in states:
        if st.status == "failed" and st.last_error:
            lowered = st.last_error.lower()
            if any(kw in lowered for kw in ("login", "credential", "authentication", "rejected", "unauthorized")):
                raise InvalidCredentialsError(st.last_error)
            if not has_cached_data:
                raise ToolFailure(
                    f"Synchronization failed for {mgmt_name!r} ({domain or 'default'}): {st.last_error}",
                    mgmt_name=mgmt_name,
                    domain=domain,
                )


def _serialize_domain(dom: DomainInfo, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `DomainInfo` preserving server-level fields (`servers`, `domain-type`, etc.) at `standard` / `full`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": dom.uid,
            "name": dom.name,
            "type": dom.domain_type,
            "mgmt_name": dom.mgmt_name,
        }

    base: dict[str, Any] = {}
    if dom.raw_data:
        base.update(sanitize_mapping(dom.raw_data))

    base.update(
        {
            "uid": dom.uid,
            "name": dom.name,
            "type": dom.domain_type,
            "domain_type": dom.domain_type,
            "mgmt_name": dom.mgmt_name,
            "active_ip": dom.active_ip,
            "active_mds_ip": dom.active_mds_ip,
            "standby_ips": list(dom.standby_ips),
            "servers": list(dom.servers) if dom.servers else base.get("servers", []),
            "is_global": dom.is_global,
        }
    )
    return base


def _serialize_object(obj: CPObject, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `CPObject` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": obj.uid,
            "name": obj.name,
            "type": obj.type,
            "mgmt_name": obj.mgmt_name,
            "domain_name": obj.domain_name,
        }
    dumped = obj.model_dump(mode="json", exclude={"raw_data"} if level != "full" else set())
    if level == "full" and obj.raw_data:
        dumped["raw_data"] = sanitize_mapping(obj.raw_data)
    return dumped


def _serialize_service(svc: CPService, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `CPService` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": svc.uid,
            "name": svc.name,
            "type": svc.type,
            "mgmt_name": svc.mgmt_name,
            "domain_name": svc.domain_name,
        }
    dumped = svc.model_dump(mode="json", exclude={"raw_data"} if level != "full" else set())
    if level == "full" and svc.raw_data:
        dumped["raw_data"] = sanitize_mapping(svc.raw_data)
    return dumped


def _serialize_asset(asset: Asset, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `Asset` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": asset.uid,
            "name": asset.name,
            "type": asset.type,
            "mgmt_name": asset.mgmt_name,
            "domain_name": asset.domain_name,
        }
    dumped = asset.model_dump(mode="json", exclude={"raw_data"} if level != "full" else set())
    if level == "full" and asset.raw_data:
        dumped["raw_data"] = sanitize_mapping(asset.raw_data)
    return dumped


def _build_page_envelope(
    items: Sequence[dict[str, Any]],
    *,
    limit: int,
    offset: int,
    source: Literal["cache", "live"],
    cache_age_seconds: float | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build standard Check Point / Arodonata MCP paginated envelope."""
    eff_offset = max(0, offset)
    eff_limit = max(1, limit)
    total = len(items)
    sliced = list(items[eff_offset : eff_offset + eff_limit])
    envelope: dict[str, Any] = {
        "from": (eff_offset + 1) if sliced else 0,
        "to": eff_offset + len(sliced),
        "total": total,
        "source": source,
        "cache_age_seconds": cache_age_seconds if source == "cache" else None,
        "objects": sliced,
    }
    if extra:
        envelope.update(extra)
    return envelope


def _filter_cp_objects(objs: Sequence[CPObject], filter_text: str | None) -> list[CPObject]:
    if not filter_text or not filter_text.strip():
        return list(objs)
    term = classify_search_term(filter_text.strip())
    return [o for o in objs if matches_classified_term(o, term)]


def _filter_cp_services(svcs: Sequence[CPService], filter_text: str | None) -> list[CPService]:
    if not filter_text or not filter_text.strip():
        return list(svcs)
    needle = filter_text.strip().lower()
    out: list[CPService] = []
    for s in svcs:
        hay = [s.name, s.uid, s.port or "", s.protocol or "", s.comments or "", s.type]
        if any(needle in h.lower() for h in hay if h):
            out.append(s)
    return out


def _filter_assets(assets: Sequence[Asset], filter_text: str | None) -> list[Asset]:
    if not filter_text or not filter_text.strip():
        return list(assets)
    needle = filter_text.strip().lower()
    out: list[Asset] = []
    for a in assets:
        hay = [
            a.name,
            a.uid,
            a.ipv4_address or "",
            a.type,
            a.version or "",
            a.os_name or "",
            a.comments or "",
        ]
        if any(needle in h.lower() for h in hay if h):
            out.append(a)
    return out


def register_mcp_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    mcp_settings: ArodonataMCPSettings,
) -> None:
    """Register all configured MCP tools on `server`."""

    # ------------------------------------------------------------------
    # 1. Cached Listing & Object Discovery Tools
    # ------------------------------------------------------------------

    @server.tool(
        name="show_domains",
        description="List Check Point domains on a management server with server-level metadata and cache freshness.",
    )
    @mcp_tool_guard("show_domains", client_getter)
    async def show_domains(
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
        domains = await client.get_domains(
            mgmt_name=eff_mgmt,
            include_global=include_global,
            cache_mode="force" if is_live else mode,
        )
        age = None if is_live else await _compute_cache_age(client, eff_mgmt, "__root__", "domains", "*")
        serialized = [_serialize_domain(d, details_level=details_level) for d in domains]
        envelope = _build_page_envelope(
            serialized,
            limit=limit,
            offset=offset,
            source="live" if is_live else "cache",
            cache_age_seconds=age,
            extra={"mgmt_name": eff_mgmt},
        )
        return json_tool_result(envelope)

    async def _list_network_objects_tool(
        *,
        obj_type: str,
        live_command: str,
        mgmt_name: str | None,
        domain: str | None,
        filter_text: str | None,
        names: list[str] | None,
        uids: list[str] | None,
        include_global: bool,
        details_level: str,
        limit: int,
        offset: int,
        cache_mode: str,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")

        if is_live:
            payload: dict[str, Any] = {
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
                "details-level": details_level,
            }
            if filter_text:
                payload["filter"] = filter_text
            res = await client.api_call(eff_mgmt, live_command, payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"{live_command} failed on {eff_mgmt!r} ({eff_domain or 'default'}): "
                    f"{res.error_message or 'API error'}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            objs_raw = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
            envelope = {
                "from": res.data.get("from", (offset + 1) if objs_raw else 0),
                "to": res.data.get("to", offset + len(objs_raw)),
                "total": res.data.get("total", len(objs_raw)),
                "source": "live",
                "cache_age_seconds": None,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "objects": objs_raw,
            }
            return json_tool_result(envelope)

        objs = await client.get_objects(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=[obj_type],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=mode,
        )
        if mode != "cache":
            await _raise_if_sync_failed(client, eff_mgmt, eff_domain, "objects", obj_type, has_cached_data=bool(objs))
        filtered = _filter_cp_objects(objs, filter_text)
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", obj_type)
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
        name="show_hosts",
        description="List Check Point host objects from cache or live API with source and cache_age_seconds.",
    )
    @mcp_tool_guard("show_hosts", client_getter)
    async def show_hosts(
        mgmt_name: str | None = None,
        domain: str | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await _list_network_objects_tool(
            obj_type="host",
            live_command="show-hosts",
            mgmt_name=mgmt_name,
            domain=domain,
            filter_text=filter,
            names=names,
            uids=uids,
            include_global=include_global,
            details_level=details_level,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
        )

    @server.tool(
        name="show_networks",
        description="List Check Point network subnet objects from cache or live API with source and cache_age_seconds.",
    )
    @mcp_tool_guard("show_networks", client_getter)
    async def show_networks(
        mgmt_name: str | None = None,
        domain: str | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await _list_network_objects_tool(
            obj_type="network",
            live_command="show-networks",
            mgmt_name=mgmt_name,
            domain=domain,
            filter_text=filter,
            names=names,
            uids=uids,
            include_global=include_global,
            details_level=details_level,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
        )

    @server.tool(
        name="show_address_ranges",
        description="List Check Point address-range objects from cache or live API.",
    )
    @mcp_tool_guard("show_address_ranges", client_getter)
    async def show_address_ranges(
        mgmt_name: str | None = None,
        domain: str | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await _list_network_objects_tool(
            obj_type="address-range",
            live_command="show-address-ranges",
            mgmt_name=mgmt_name,
            domain=domain,
            filter_text=filter,
            names=names,
            uids=uids,
            include_global=include_global,
            details_level=details_level,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
        )

    @server.tool(
        name="show_dns_domains",
        description="List Check Point dns-domain objects from cache or live API.",
    )
    @mcp_tool_guard("show_dns_domains", client_getter)
    async def show_dns_domains(
        mgmt_name: str | None = None,
        domain: str | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await _list_network_objects_tool(
            obj_type="dns-domain",
            live_command="show-dns-domains",
            mgmt_name=mgmt_name,
            domain=domain,
            filter_text=filter,
            names=names,
            uids=uids,
            include_global=include_global,
            details_level=details_level,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
        )

    @server.tool(
        name="show_groups",
        description="List Check Point network group objects from cache or live API.",
    )
    @mcp_tool_guard("show_groups", client_getter)
    async def show_groups(
        mgmt_name: str | None = None,
        domain: str | None = None,
        filter: str | None = None,
        names: list[str] | None = None,
        uids: list[str] | None = None,
        include_global: bool = False,
        details_level: str = "standard",
        limit: int = 50,
        offset: int = 0,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await _list_network_objects_tool(
            obj_type="group",
            live_command="show-groups",
            mgmt_name=mgmt_name,
            domain=domain,
            filter_text=filter,
            names=names,
            uids=uids,
            include_global=include_global,
            details_level=details_level,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
        )

    @server.tool(
        name="show_services",
        description="List Check Point service objects (TCP, UDP, ICMP, service-group) from cache or live API.",
    )
    @mcp_tool_guard("show_services", client_getter)
    async def show_services(
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

        if is_live:
            cmd = "show-services-tcp"
            if types and len(types) == 1:
                t0 = types[0].strip().lower()
                type_cmd_map = {
                    "service-tcp": "show-services-tcp",
                    "service-udp": "show-services-udp",
                    "service-icmp": "show-services-icmp",
                    "service-group": "show-service-groups",
                    "service-other": "show-services-other",
                }
                cmd = type_cmd_map.get(t0, "show-services-tcp")
            payload: dict[str, Any] = {
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
                "details-level": details_level,
            }
            if filter:
                payload["filter"] = filter
            res = await client.api_call(eff_mgmt, cmd, payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"{cmd} failed on {eff_mgmt!r} ({eff_domain or 'default'}): {res.error_message or 'API error'}",
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

        svcs = await client.get_services(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=mode,
        )
        svc_item_type = types[0] if types and len(types) == 1 else "*"
        if mode != "cache":
            await _raise_if_sync_failed(
                client, eff_mgmt, eff_domain, "services", svc_item_type, has_cached_data=bool(svcs)
            )
        filtered = _filter_cp_services(svcs, filter)
        age = await _compute_cache_age(
            client,
            eff_mgmt,
            eff_domain,
            "services",
            svc_item_type,
        )
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
        name="show_gateways_and_servers",
        description="List Check Point gateways, clusters, VSX systems, and servers from cache or live API.",
    )
    @mcp_tool_guard("show_gateways_and_servers", client_getter)
    async def show_gateways_and_servers(
        mgmt_name: str | None = None,
        domain: str | None = None,
        types: list[str] | None = None,
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

        assets = await client.get_gateways(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=types,
            include_global=include_global,
            cache_mode=mode,
        )
        if mode != "cache":
            await _raise_if_sync_failed(client, eff_mgmt, eff_domain, "assets", "*", has_cached_data=bool(assets))
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
        name="show_object",
        description="Retrieve a single Check Point object or service by UID or name from cache or live API.",
    )
    @mcp_tool_guard("show_object", client_getter)
    async def show_object(
        uid_or_name: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        obj_type: str | None = None,
        details_level: str = "full",
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domain = eff_domain or "default"
        mode, is_live = _normalize_cache_mode(cache_mode, default="smart")

        clean_obj_type: str | None = None
        if obj_type is not None and obj_type.strip():
            raw_type = obj_type.strip()
            try:
                validated_cmd = validate_command_name(f"show-{raw_type}")
            except ValidationError as exc:
                raise ToolFailure(
                    f"Invalid obj_type {obj_type!r}: {exc}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                ) from exc
            clean_obj_type = validated_cmd.removeprefix("show-")
            if clean_obj_type not in CANONICAL_SHOW_OBJECT_TYPES:
                raise ToolFailure(
                    f"Unsupported obj_type {obj_type!r}. Expected a canonical Check Point object or service type.",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )

        if not is_live:
            found = await client.find_object(
                eff_mgmt,
                target_domain,
                uid_or_name,
                obj_type=clean_obj_type,
                cache_mode=mode,
            )
            if found is not None:
                is_svc = isinstance(found, CPService)
                age = await _compute_cache_age(
                    client,
                    eff_mgmt,
                    target_domain,
                    "services" if is_svc else "objects",
                    found.type,
                )
                if isinstance(found, CPService):
                    obj_dict = _serialize_service(found, details_level=details_level)
                else:
                    obj_dict = _serialize_object(found, details_level=details_level)
                return json_tool_result(
                    {
                        "from": 1,
                        "to": 1,
                        "total": 1,
                        "source": "cache",
                        "cache_age_seconds": age,
                        "mgmt_name": eff_mgmt,
                        "domain": target_domain,
                        "object": obj_dict,
                        "objects": [obj_dict],
                    }
                )

        # Fallback to live show-object or type-specific command
        cmd = f"show-{clean_obj_type}" if clean_obj_type else "show-object"
        payload: dict[str, Any] = {"details-level": details_level}
        if "-" in uid_or_name and len(uid_or_name) == 36 and not clean_obj_type:
            payload["uid"] = uid_or_name
        elif clean_obj_type:
            payload["name"] = uid_or_name
        else:
            payload["uid"] = uid_or_name

        res = await client.api_call(eff_mgmt, cmd, payload, domain=eff_domain)
        if not res.success:
            known_sids = await collect_known_sids(client, eff_mgmt)
            raise ToolFailure(
                f"Object {uid_or_name!r} not found on {eff_mgmt!r} ({target_domain}): "
                f"{redact_sid(res.error_message or 'not found', known_sids=known_sids)}",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
                known_sids=known_sids,
            )
        obj_payload = res.data.get("object", res.data)
        known_sids = await collect_known_sids(client, eff_mgmt)
        return json_tool_result(
            {
                "from": 1,
                "to": 1,
                "total": 1,
                "source": "live",
                "cache_age_seconds": None,
                "mgmt_name": eff_mgmt,
                "domain": target_domain,
                "object": obj_payload,
                "objects": [obj_payload],
            },
            known_sids=known_sids,
        )

    @server.tool(
        name="find_object",
        description="Find an object or service by exact UID or name in cache.",
    )
    @mcp_tool_guard("find_object", client_getter)
    async def find_object(
        name_or_uid: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        obj_type: str | None = None,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        return await show_object(
            uid_or_name=name_or_uid,
            mgmt_name=mgmt_name,
            domain=domain,
            obj_type=obj_type,
            details_level="standard",
            cache_mode=cache_mode,
        )

    @server.tool(
        name="search_objects",
        description="Search cached objects across IPv4, CIDR, range, wildcard, UID, or name with recursive parent group memberships.",
    )
    @mcp_tool_guard("search_objects", client_getter)
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
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domains = domains if domains is not None else ([eff_domain] if eff_domain else None)
        if target_domains:
            for d in target_domains:
                await validate_domain_or_fail(client, eff_mgmt, d)

        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        result = await client.search_objects(
            query,
            mgmt_name=eff_mgmt,
            domains=target_domains,
            types=types,
            include_global=include_global,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=mode,
        )
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "objects", "*")
        serialized_matches = [_serialize_object(o, details_level="standard") for o in result.matches]
        envelope = _build_page_envelope(
            serialized_matches,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={
                "query": result.query,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "memberships": {
                    uid: [node.model_dump(mode="json") for node in nodes] for uid, nodes in result.memberships.items()
                },
            },
        )
        return json_tool_result(envelope)

    @server.tool(
        name="get_group_members",
        description="Expand direct and recursive members of a Check Point group object from cache.",
    )
    @mcp_tool_guard("get_group_members", client_getter)
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

        members = await client.search_service.get_group_members(
            eff_mgmt,
            target_domain,
            group_name_or_uid,
            recursive=recursive,
            max_depth=max_depth,
            cache_mode=mode,
        )
        age = await _compute_cache_age(client, eff_mgmt, target_domain, "objects", "group")
        serialized = [_serialize_object(m, details_level="standard") for m in members]
        envelope = _build_page_envelope(
            serialized,
            limit=limit,
            offset=offset,
            source="cache",
            cache_age_seconds=age,
            extra={
                "group": group_name_or_uid,
                "mgmt_name": eff_mgmt,
                "domain": target_domain,
            },
        )
        return json_tool_result(envelope)

    # ------------------------------------------------------------------
    # 2. Progressive-Disclosure Aggregation & Cache Status Tools
    # ------------------------------------------------------------------

    @server.tool(
        name="describe_objects",
        description=(
            "Return progressive-disclosure schema, available domains, object/service type counts, "
            "and filterable/groupable fields for query_objects."
        ),
    )
    @mcp_tool_guard("describe_objects", client_getter)
    async def describe_objects(
        mgmt_name: str | None = None,
        domain: str | None = None,
        include_global: bool = True,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain) if (eff_mgmt and domain) else domain
        summary = await client.describe_objects(
            mgmt_name=eff_mgmt,
            domain_name=eff_domain,
            include_global=include_global,
        )
        return json_tool_result(summary)

    @server.tool(
        name="query_objects",
        description=(
            "Execute structured cross-domain filtering, grouping (group_by), and counting (aggregate='count'|'list') "
            "over cached arodonata_objects and arodonata_services, distinguishing local vs Global objects via original_domain."
        ),
    )
    @mcp_tool_guard("query_objects", client_getter)
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
        include_global: bool = False,
        group_by: list[str] | None = None,
        aggregate: Literal["count", "list"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: str = "cache",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        eff_domain = (
            await validate_domain_or_fail(client, eff_mgmt, domain)
            if (eff_mgmt and domain)
            else (domain.strip() if domain else None)
        )
        if eff_mgmt and domains:
            for d in domains:
                await validate_domain_or_fail(client, eff_mgmt, d)

        mode, _ = _normalize_cache_mode(cache_mode, default="cache")
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
            include_global=include_global,
            group_by=group_by,
            aggregate=aggregate,
            limit=limit,
            offset=offset,
            cache_mode=mode,
        )
        age = await _compute_cache_age(
            client,
            eff_mgmt or (client.settings.mgmt_names[0] if client.settings.mgmt_names else "default"),
            eff_domain,
            "objects",
            "*",
        )
        result["source"] = "cache"
        result["cache_age_seconds"] = age
        return json_tool_result(result)

    @server.tool(
        name="cache_status",
        description=(
            "Inspect domain_sync_state across scopes ('domains', 'objects', 'services', 'assets', 'rulebase'), "
            "returning per-domain and per-item_type status, last_published_at, last_session_uid, synced_at, and cache_age_seconds."
        ),
    )
    @mcp_tool_guard("cache_status", client_getter)
    async def cache_status(
        mgmt_name: str | None = None,
        domain: str | None = None,
        scope: SyncScope | None = None,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        status_data = await client.get_cache_status(
            mgmt_name=eff_mgmt,
            domain_name=domain.strip() if domain else None,
            scope=scope,
        )
        return json_tool_result(status_data)

    @server.tool(
        name="refresh_cache",
        description="Synchronize cached objects, services, assets, or rulebases for target domains.",
    )
    @mcp_tool_guard("refresh_cache", client_getter)
    async def refresh_cache(
        scope: Literal["objects", "services", "assets", "rulebase"] = "objects",
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: list[str] | None = None,
        types: list[str] | None = None,
        include_global: bool = False,
        mode: Literal["cache", "smart", "smart-fast", "force"] = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None
        target_domains = domains if domains is not None else ([domain] if domain else None)
        if eff_mgmt and target_domains:
            for d in target_domains:
                await validate_domain_or_fail(client, eff_mgmt, d)

        if scope == "objects":
            outcome = await client.refresh_objects(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=types,
                include_global=include_global,
                mode=mode,
            )
        elif scope == "services":
            outcome = await client.refresh_services(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=types,
                include_global=include_global,
                mode=mode,
            )
        elif scope == "assets":
            outcome = await client.refresh_assets(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                include_global=include_global,
                mode=mode,
            )
        else:
            outcome = await client.refresh_rulebases(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                include_global=include_global,
                mode=mode,
            )
        return json_tool_result(outcome.model_dump(mode="json"))

    # ------------------------------------------------------------------
    # 3. Hybrid Rulebase Tools
    # ------------------------------------------------------------------

    async def _run_hybrid_rulebase_tool(
        *,
        rulebase_type: RulebaseType,
        live_command: str,
        mgmt_name: str | None,
        domain: str | None,
        package: str | None,
        layer: str | None,
        name: str | None,
        uid: str | None,
        filter_text: str,
        output_format: RuleFormat,
        limit: int,
        offset: int,
        cache_mode: str,
        show_hits: bool,
        order: list[dict[str, Any]] | None,
        show_as_ranges: bool,
        show_expiration_settings: bool,
        filter_settings: dict[str, Any] | None,
        hits_settings: dict[str, Any] | None,
        dereference_group_members: bool,
        show_membership: bool,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, is_live_mode = _normalize_cache_mode(cache_mode, default="smart")

        # Resolve target package or layer from `package`, `layer`, `name`, or `uid`
        eff_package = package
        eff_layer = layer
        if rulebase_type == "nat":
            eff_package = eff_package or name or uid or layer
        else:
            if not eff_layer and not eff_package:
                eff_layer = name or uid

        if not eff_package and not eff_layer:
            raise ToolFailure(
                f"Specify 'package' or 'layer' (or 'name'/'uid') for show_{rulebase_type}_rulebase.",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
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
            payload: dict[str, Any] = {
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
                "details-level": "standard",
            }
            if rulebase_type == "nat":
                payload["package"] = eff_package or eff_layer
            else:
                if eff_layer:
                    if "-" in eff_layer and len(eff_layer) == 36:
                        payload["uid"] = eff_layer
                    else:
                        payload["name"] = eff_layer
                if eff_package:
                    payload["package"] = eff_package

            if filter_text:
                payload["filter"] = filter_text
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
                    f"{live_command} failed on {eff_mgmt!r} ({eff_domain or 'default'}): "
                    f"{res.error_message or 'API error'}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            rb_items = res.data.get("rulebase", []) if isinstance(res.data.get("rulebase"), list) else []
            live_envelope: dict[str, Any] = {
                "from": res.data.get("from", (offset + 1) if rb_items else 0),
                "to": res.data.get("to", offset + len(rb_items)),
                "total": res.data.get("total", len(rb_items)),
                "source": "live",
                "cache_age_seconds": None,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "rulebase_type": rulebase_type,
                "format": output_format,
                "rulebase": rb_items,
            }
            return json_tool_result(live_envelope)

        # Serve from cached rulebase snapshot and evaluate filter locally
        filtered_res = await client.filter_rulebase(
            eff_mgmt,
            eff_domain,
            package=eff_package,
            layer=eff_layer if rulebase_type != "nat" else None,
            rulebase_type=rulebase_type,
            filter_query=filter_text,
            output_format=output_format,
            cache_mode=mode,
        )
        sliced_raw = filtered_res.raw_items[offset : offset + max(1, limit)]
        envelope: dict[str, Any] = {
            "from": (offset + 1) if sliced_raw else 0,
            "to": offset + len(sliced_raw),
            "total": filtered_res.matched_count,
            "total_unfiltered": filtered_res.total_rules,
            "source": "cache",
            "cache_age_seconds": (
                round(filtered_res.cache_age_seconds, 3) if filtered_res.cache_age_seconds is not None else 0.0
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
        return json_tool_result(envelope)

    @server.tool(
        name="show_access_rulebase",
        description=(
            "Show SmartConsole-numbered access-control rulebase from cache (including local filter evaluation "
            "against cached objects/services) in markdown, model_friendly, or raw format; switches to live API "
            "query only when live-only parameters (show_hits, order, etc.) or cache_mode='live' are used."
        ),
    )
    @mcp_tool_guard("show_access_rulebase", client_getter)
    async def show_access_rulebase(
        mgmt_name: str | None = None,
        domain: str | None = None,
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
        return await _run_hybrid_rulebase_tool(
            rulebase_type="access",
            live_command="show-access-rulebase",
            mgmt_name=mgmt_name,
            domain=domain,
            package=package,
            layer=layer,
            name=name,
            uid=uid,
            filter_text=filter,
            output_format=format,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            show_hits=show_hits,
            order=order,
            show_as_ranges=show_as_ranges,
            show_expiration_settings=show_expiration_settings,
            filter_settings=filter_settings,
            hits_settings=hits_settings,
            dereference_group_members=dereference_group_members,
            show_membership=show_membership,
        )

    @server.tool(
        name="show_nat_rulebase",
        description=(
            "Show SmartConsole-numbered NAT rulebase for a policy package from cache (evaluating filter locally) "
            "or live API when live-only parameters or cache_mode='live' are passed."
        ),
    )
    @mcp_tool_guard("show_nat_rulebase", client_getter)
    async def show_nat_rulebase(
        mgmt_name: str | None = None,
        domain: str | None = None,
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
        return await _run_hybrid_rulebase_tool(
            rulebase_type="nat",
            live_command="show-nat-rulebase",
            mgmt_name=mgmt_name,
            domain=domain,
            package=package,
            layer=layer,
            name=name,
            uid=uid,
            filter_text=filter,
            output_format=format,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            show_hits=show_hits,
            order=order,
            show_as_ranges=show_as_ranges,
            show_expiration_settings=show_expiration_settings,
            filter_settings=filter_settings,
            hits_settings=hits_settings,
            dereference_group_members=dereference_group_members,
            show_membership=show_membership,
        )

    @server.tool(
        name="show_https_rulebase",
        description="Show SmartConsole-numbered HTTPS inspection rulebase from cache or live API.",
    )
    @mcp_tool_guard("show_https_rulebase", client_getter)
    async def show_https_rulebase(
        mgmt_name: str | None = None,
        domain: str | None = None,
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
        return await _run_hybrid_rulebase_tool(
            rulebase_type="https",
            live_command="show-https-rulebase",
            mgmt_name=mgmt_name,
            domain=domain,
            package=package,
            layer=layer,
            name=name,
            uid=uid,
            filter_text=filter,
            output_format=format,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            show_hits=show_hits,
            order=order,
            show_as_ranges=show_as_ranges,
            show_expiration_settings=show_expiration_settings,
            filter_settings=filter_settings,
            hits_settings=hits_settings,
            dereference_group_members=dereference_group_members,
            show_membership=show_membership,
        )

    @server.tool(
        name="show_threat_rulebase",
        description="Show SmartConsole-numbered Threat Prevention rulebase from cache or live API.",
    )
    @mcp_tool_guard("show_threat_rulebase", client_getter)
    async def show_threat_rulebase(
        mgmt_name: str | None = None,
        domain: str | None = None,
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
        return await _run_hybrid_rulebase_tool(
            rulebase_type="threat",
            live_command="show-threat-rulebase",
            mgmt_name=mgmt_name,
            domain=domain,
            package=package,
            layer=layer,
            name=name,
            uid=uid,
            filter_text=filter,
            output_format=format,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            show_hits=show_hits,
            order=order,
            show_as_ranges=show_as_ranges,
            show_expiration_settings=show_expiration_settings,
            filter_settings=filter_settings,
            hits_settings=hits_settings,
            dereference_group_members=dereference_group_members,
            show_membership=show_membership,
        )

    @server.tool(
        name="show_policy_packages",
        description="List cached Check Point policy packages and their attached layers for a domain.",
    )
    @mcp_tool_guard("show_policy_packages", client_getter)
    async def show_policy_packages(
        mgmt_name: str | None = None,
        domain: str | None = None,
        cache_mode: str = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        packages = await client.get_policy_packages(eff_mgmt, eff_domain, cache_mode=mode)
        age = await _compute_cache_age(client, eff_mgmt, eff_domain, "rulebase", "*")
        serialized = [p.model_dump(mode="json") for p in packages]
        return json_tool_result(
            {
                "from": 1 if serialized else 0,
                "to": len(serialized),
                "total": len(serialized),
                "source": "cache",
                "cache_age_seconds": age,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "packages": serialized,
                "objects": serialized,
            }
        )

    @server.tool(
        name="locate_rules",
        description="Locate SmartConsole rule numbers and layer prefixes across all policy packages and layers of a domain.",
    )
    @mcp_tool_guard("locate_rules", client_getter)
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

    # ------------------------------------------------------------------
    # 4. Change Report & Gated `api_call`
    # ------------------------------------------------------------------

    @server.tool(
        name="change_report",
        description=(
            "Collect and render an auditable Check Point session change report across explicit session UIDs "
            "or a published date/session range in markdown, json, or html format."
        ),
    )
    @mcp_tool_guard("change_report", client_getter)
    async def change_report(
        mgmt_name: str | None = None,
        domain: str | None = None,
        session_uids: list[str] | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        from_session: str | None = None,
        to_session: str | None = None,
        scopes: list[dict[str, Any]] | None = None,
        format: Literal["markdown", "json", "html"] = "markdown",
        title: str = "Check Point Policy Change Report",
        include_object_changes: bool = True,
        include_field_diffs: bool = True,
        include_warnings: bool = True,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)

        parsed_scopes: list[ReportScope | dict[str, Any]] = []
        if scopes:
            for raw_sc in scopes:
                sc_mgmt = resolve_mgmt_name(client, raw_sc.get("mgmt_name") or eff_mgmt)
                sc_dom = await validate_domain_or_fail(client, sc_mgmt, raw_sc.get("domain") or eff_domain)
                sc_copy = dict(raw_sc)
                sc_copy["mgmt_name"] = sc_mgmt
                sc_copy["domain"] = sc_dom
                parsed_scopes.append(sc_copy)
        elif session_uids:
            parsed_scopes.append(
                SessionScope(
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    session_uids=session_uids,
                )
            )
        elif any(x is not None for x in (from_date, to_date, from_session, to_session)):
            parsed_from = datetime.fromisoformat(from_date) if from_date else None
            parsed_to = datetime.fromisoformat(to_date) if to_date else None
            parsed_scopes.append(
                RangeScope(
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    from_date=parsed_from,
                    to_date=parsed_to,
                    from_session=from_session,
                    to_session=to_session,
                )
            )
        else:
            raise ToolFailure(
                "Provide 'session_uids', range bounds ('from_date', 'to_date', 'from_session', 'to_session'), or 'scopes'.",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
            )

        options = RenderOptions(
            title=title,
            include_object_changes=include_object_changes,
            include_field_diffs=include_field_diffs,
            include_warnings=include_warnings,
        )
        bundle = await client.build_change_report(
            parsed_scopes,
            formats=[format],
            options=options,
        )
        if format == "html" and bundle.html is not None:
            rendered = bundle.html.decode("utf-8")
        elif format == "json" and bundle.json_text is not None:
            rendered = bundle.json_text
        else:
            rendered = bundle.markdown or ""

        return json_tool_result(
            {
                "format": format,
                "title": bundle.report.title,
                "session_count": len(bundle.report.sessions),
                "warning_count": len(bundle.report.warnings),
                "rendered": redact_sid(rendered),
                "report": bundle.report.model_dump(mode="json"),
            }
        )

    @server.tool(
        name="api_call",
        description=(
            "Execute a direct Check Point Management Web API command. "
            "By default only read-only commands ('show-*', 'where-used', 'verify-policy') are permitted "
            "unless ARODONATA_MCP_ALLOW_WRITE_API=true."
        ),
    )
    @mcp_tool_guard("api_call", client_getter)
    async def api_call(
        command: str,
        payload: dict[str, Any] | None = None,
        mgmt_name: str | None = None,
        domain: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> CallToolResult:
        if not isinstance(command, str) or not command.strip():
            raise ToolFailure("Command must not be empty.")

        try:
            clean_cmd = validate_command_name(command)
        except ValidationError as exc:
            raise ToolFailure(str(exc), mgmt_name=mgmt_name, domain=domain) from exc

        if not mcp_settings.allow_write_api and not is_readonly_command(clean_cmd):
            raise ToolFailure(
                f"Write or non-read-only command {clean_cmd!r} is prohibited when "
                "ARODONATA_MCP_ALLOW_WRITE_API=false. Only read-only 'show-*', 'where-used', and 'verify-policy' "
                "commands are permitted."
            )

        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)

        eff_timeout: float | None = None
        if timeout is not None:
            if timeout <= 0:
                raise ToolFailure(
                    "timeout must be a positive number of seconds.", mgmt_name=eff_mgmt, domain=eff_domain
                )
            eff_timeout = min(float(timeout), MAX_MCP_API_TIMEOUT_SECONDS)

        if is_readonly_command(clean_cmd):
            res = await client.api_call(
                eff_mgmt,
                clean_cmd,
                payload or {},
                domain=eff_domain,
                wait_for_task=wait_for_task,
                timeout=eff_timeout,
            )
        else:
            # Isolate mutating api_call inside a dedicated session so shared sid_cache is never dirtied (W25/C8)
            sid, srv_ip = await client.api.create_dedicated_session(
                eff_mgmt,
                eff_domain,
                session_name="arodonata-mcp-api-call",
                session_description=f"MCP api_call: {clean_cmd}",
            )
            try:
                res = await client.api_call(
                    eff_mgmt,
                    clean_cmd,
                    payload or {},
                    domain=eff_domain,
                    sid=sid,
                    server_ip=srv_ip,
                    wait_for_task=wait_for_task,
                    timeout=eff_timeout,
                )
            finally:
                if clean_cmd != "logout":
                    await client.api.logout_sid(eff_mgmt, sid, server_ip=srv_ip)

        known_sids = await collect_known_sids(client, eff_mgmt)
        if not res.success:
            err_msg = redact_sid(res.error_message or f"API command {clean_cmd!r} failed", known_sids=known_sids)
            raise ToolFailure(
                f"{clean_cmd} failed (status {res.status_code}): {err_msg}",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
                known_sids=known_sids,
            )

        return json_tool_result(
            {
                "command": clean_cmd,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "status_code": res.status_code,
                "source": "live",
                "cache_age_seconds": None,
                "data": sanitize_mapping(res.data, known_sids=known_sids),
            },
            known_sids=known_sids,
        )

    # ------------------------------------------------------------------
    # 5. Optional Live-Compatibility Tools (`ARODONATA_MCP_LIVE_COMPAT=true`)
    # ------------------------------------------------------------------

    if mcp_settings.live_compat:

        @server.tool(
            name="where_used",
            description="Check where a Check Point object or service is referenced across rules and groups via live API.",
        )
        @mcp_tool_guard("where_used", client_getter)
        async def where_used(
            uid_or_name: str,
            mgmt_name: str | None = None,
            domain: str | None = None,
            indirect: bool = False,
            indirect_max_depth: int = 5,
        ) -> CallToolResult:
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            key = "uid" if ("-" in uid_or_name and len(uid_or_name) == 36) else "name"
            payload: dict[str, Any] = {key: uid_or_name, "indirect": indirect, "indirect-max-depth": indirect_max_depth}
            res = await client.api_call(eff_mgmt, "where-used", payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"where-used failed on {eff_mgmt!r}: {redact_sid(res.error_message or 'error')}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            return json_tool_result(
                {
                    "source": "live",
                    "cache_age_seconds": None,
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "data": sanitize_mapping(res.data),
                }
            )

        @server.tool(
            name="show_sessions",
            description="List Check Point management sessions via live API.",
        )
        @mcp_tool_guard("show_sessions", client_getter)
        async def show_sessions(
            mgmt_name: str | None = None,
            domain: str | None = None,
            view_published_sessions: bool = True,
            limit: int = 50,
            offset: int = 0,
        ) -> CallToolResult:
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            payload: dict[str, Any] = {
                "view-published-sessions": view_published_sessions,
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            }
            res = await client.api_call(eff_mgmt, "show-sessions", payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"show-sessions failed on {eff_mgmt!r}: {redact_sid(res.error_message or 'error')}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            objs = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
            return json_tool_result(
                {
                    "from": res.data.get("from", (offset + 1) if objs else 0),
                    "to": res.data.get("to", offset + len(objs)),
                    "total": res.data.get("total", len(objs)),
                    "source": "live",
                    "cache_age_seconds": None,
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "objects": sanitize_mapping({"objects": objs})["objects"],
                }
            )

        @server.tool(
            name="show_unused_objects",
            description="List unused objects in a Check Point domain via live API.",
        )
        @mcp_tool_guard("show_unused_objects", client_getter)
        async def show_unused_objects(
            mgmt_name: str | None = None,
            domain: str | None = None,
            limit: int = 50,
            offset: int = 0,
        ) -> CallToolResult:
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            payload: dict[str, Any] = {
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            }
            res = await client.api_call(eff_mgmt, "show-unused-objects", payload, domain=eff_domain)
            if not res.success:
                raise ToolFailure(
                    f"show-unused-objects failed on {eff_mgmt!r}: {redact_sid(res.error_message or 'error')}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            objs = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
            return json_tool_result(
                {
                    "from": res.data.get("from", (offset + 1) if objs else 0),
                    "to": res.data.get("to", offset + len(objs)),
                    "total": res.data.get("total", len(objs)),
                    "source": "live",
                    "cache_age_seconds": None,
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "objects": objs,
                }
            )

        @server.tool(
            name="show_task",
            description="Inspect a Check Point management task by task-id via live API.",
        )
        @mcp_tool_guard("show_task", client_getter)
        async def show_task(
            task_id: str,
            mgmt_name: str | None = None,
            domain: str | None = None,
            details_level: str = "full",
        ) -> CallToolResult:
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            res = await client.api_call(
                eff_mgmt,
                "show-task",
                {"task-id": task_id, "details-level": details_level},
                domain=eff_domain,
            )
            if not res.success:
                raise ToolFailure(
                    f"show-task failed on {eff_mgmt!r}: {redact_sid(res.error_message or 'error')}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            return json_tool_result(
                {
                    "source": "live",
                    "cache_age_seconds": None,
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "data": sanitize_mapping(res.data),
                }
            )

    # ------------------------------------------------------------------
    # 6. Opt-In CPCRUD Tools (`ARODONATA_MCP_CPCRUD=true`)
    # ------------------------------------------------------------------

    if mcp_settings.cpcrud:
        plan_hmac_key = secrets.token_bytes(32)
        plan_store: OrderedDict[str, tuple[Plan, ApplyReport | None]] = OrderedDict()

        def _store_plan_entry(plan_id: str, plan_obj: Plan, report_obj: ApplyReport | None = None) -> None:
            plan_store[plan_id] = (plan_obj, report_obj)
            plan_store.move_to_end(plan_id)
            while len(plan_store) > MAX_STORED_PLANS:
                plan_store.popitem(last=False)

        def _resolve_verified_plan(
            plan: dict[str, Any] | None,
            plan_id: str | None,
        ) -> tuple[str | None, Plan, ApplyReport | None]:
            if plan_id and plan is None:
                entry = plan_store.get(plan_id)
                if entry is None:
                    raise ToolFailure(f"Unknown or expired CPCRUD plan_id {plan_id!r}. Run cpcrud_plan first.")
                return plan_id, entry[0], entry[1]

            if not isinstance(plan, dict):
                raise ToolFailure("Provide a signed 'plan' dictionary returned by cpcrud_plan or a 'plan_id'.")

            sig = plan.get("plan_signature")
            embedded_id = plan.get("plan_id") if isinstance(plan.get("plan_id"), str) else plan_id

            try:
                expected_sig = _sign_plan(plan_hmac_key, plan)
                parsed_plan = Plan.model_validate(
                    {k: v for k, v in plan.items() if k not in ("plan_id", "plan_signature")}
                )
            except Exception as exc:
                raise ToolFailure(f"Invalid or tampered CPCRUD plan payload: {exc}") from exc

            if not isinstance(sig, str) or not hmac.compare_digest(sig, expected_sig):
                raise ToolFailure(
                    "Untrusted or tampered CPCRUD plan: plans passed to cpcrud_apply/cpcrud_inverse must be "
                    "created and signed by cpcrud_plan on this server."
                )

            stored_report: ApplyReport | None = None
            if embedded_id and embedded_id in plan_store:
                stored_report = plan_store[embedded_id][1]
            return embedded_id, parsed_plan, stored_report

        @server.tool(
            name="cpcrud_validate",
            description="Validate a declarative CPCRUD YAML/JSON template offline against checkpoint_ops_schema.json.",
        )
        @mcp_tool_guard("cpcrud_validate", client_getter)
        async def cpcrud_validate(
            template: dict[str, Any] | str,
        ) -> CallToolResult:
            client = client_getter()
            errors = client.cpcrud.validate(template)
            return json_tool_result(
                {
                    "valid": len(errors) == 0,
                    "error_count": len(errors),
                    "errors": errors,
                }
            )

        @server.tool(
            name="cpcrud_plan",
            description=(
                "Plan deterministic idempotent Check Point CRUD actions from a YAML/JSON template using "
                "HybridStateReader and two-axis conflict policies."
            ),
        )
        @mcp_tool_guard("cpcrud_plan", client_getter)
        async def cpcrud_plan(
            template: dict[str, Any] | str,
            on_name_conflict: NameConflictPolicy | None = None,
            on_ip_conflict: IpConflictPolicy | None = None,
        ) -> CallToolResult:
            client = client_getter()
            plan = await client.cpcrud.plan(
                template,
                on_name_conflict=on_name_conflict,
                on_ip_conflict=on_ip_conflict,
                validate_schema=True,
            )
            plan_id = str(uuid.uuid4())
            _store_plan_entry(plan_id, plan, None)
            plan_dict = plan.model_dump(mode="json")
            plan_dict["plan_id"] = plan_id
            plan_dict["plan_signature"] = _sign_plan(plan_hmac_key, plan_dict)
            known_sids = await collect_known_sids(client)
            return json_tool_result(plan_dict, known_sids=known_sids)

        @server.tool(
            name="cpcrud_apply",
            description=(
                "Execute a verified CPCRUD Plan inside an isolated WriteSession per domain with stale-plan "
                "verification, optional session staging, and post-publish cache invalidation."
            ),
        )
        @mcp_tool_guard("cpcrud_apply", client_getter)
        async def cpcrud_apply(
            plan: dict[str, Any] | None = None,
            plan_id: str | None = None,
            no_publish: bool = False,
            keep_session: bool = False,
            retry_remaining: int = 0,
            session_name: str | None = None,
            session_description: str | None = None,
        ) -> CallToolResult:
            if retry_remaining < 0 or retry_remaining > 3:
                raise ToolFailure("retry_remaining must be between 0 and 3.")

            eff_plan_id, parsed_plan, _ = _resolve_verified_plan(plan, plan_id)
            client = client_getter()
            report = await client.cpcrud.apply(
                parsed_plan,
                force=False,
                no_publish=no_publish,
                keep_session=keep_session,
                retry_remaining=retry_remaining,
                session_name=session_name,
                session_description=session_description,
            )
            if eff_plan_id:
                _store_plan_entry(eff_plan_id, parsed_plan, report)
            report_dict = report.model_dump(mode="json")
            if eff_plan_id:
                report_dict["plan_id"] = eff_plan_id
            known_sids = await collect_known_sids(client)
            return json_tool_result(report_dict, known_sids=known_sids)

        @server.tool(
            name="cpcrud_inverse",
            description="Generate a schema-valid compensating rollback template from a verified CPCRUD Plan and ApplyReport.",
        )
        @mcp_tool_guard("cpcrud_inverse", client_getter)
        async def cpcrud_inverse(
            plan: dict[str, Any] | None = None,
            plan_id: str | None = None,
            report: dict[str, Any] | None = None,
        ) -> CallToolResult:
            _, parsed_plan, stored_report = _resolve_verified_plan(plan, plan_id)
            client = client_getter()
            eff_report: ApplyReport | None = None
            if isinstance(report, dict):
                eff_report = ApplyReport.model_validate(report)
            elif stored_report is not None:
                eff_report = stored_report
            elif client.cpcrud.last_report is not None:
                eff_report = client.cpcrud.last_report

            if eff_report is None:
                raise ToolFailure(
                    "cpcrud_inverse requires an ApplyReport (pass 'report', use a 'plan_id' that was applied, "
                    "or call cpcrud_apply before cpcrud_inverse)."
                )
            inverse_tpl = client.cpcrud.inverse(parsed_plan, eff_report)
            known_sids = await collect_known_sids(client)
            return json_tool_result(inverse_tpl, known_sids=known_sids)

        @server.tool(
            name="cpcrud_publish_staged",
            description=(
                "Adopt a staged Check Point session (created with keep_session=True) via take-over-session, "
                "publish it, log out cleanly, and invalidate the domain cache."
            ),
        )
        @mcp_tool_guard("cpcrud_publish_staged", client_getter)
        async def cpcrud_publish_staged(
            session_uid: str,
            mgmt_name: str | None = None,
            domain: str | None = None,
            server_ip: str | None = None,
            timeout: float | None = None,
        ) -> CallToolResult:
            if not session_uid or not session_uid.strip():
                raise ToolFailure("session_uid must not be empty.")
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            eff_timeout = min(float(timeout), MAX_MCP_API_TIMEOUT_SECONDS) if timeout and timeout > 0 else None
            res = await client.cpcrud.publish_staged_session(
                eff_mgmt,
                eff_domain,
                session_uid=session_uid.strip(),
                server_ip=server_ip,
                timeout=eff_timeout,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            if not res.success:
                raise ToolFailure(
                    f"cpcrud_publish_staged failed for session {session_uid!r}: "
                    f"{redact_sid(res.error_message or 'publish failed', known_sids=known_sids)}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    known_sids=known_sids,
                )
            return json_tool_result(
                {
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "session_uid": session_uid.strip(),
                    "published": True,
                    "data": sanitize_mapping(res.data, known_sids=known_sids),
                },
                known_sids=known_sids,
            )

        @server.tool(
            name="cpcrud_discard_staged",
            description=(
                "Adopt a staged Check Point session (created with keep_session=True) via take-over-session, "
                "discard uncommitted changes, and log out cleanly."
            ),
        )
        @mcp_tool_guard("cpcrud_discard_staged", client_getter)
        async def cpcrud_discard_staged(
            session_uid: str,
            mgmt_name: str | None = None,
            domain: str | None = None,
            server_ip: str | None = None,
        ) -> CallToolResult:
            if not session_uid or not session_uid.strip():
                raise ToolFailure("session_uid must not be empty.")
            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
            res = await client.cpcrud.discard_staged_session(
                eff_mgmt,
                eff_domain,
                session_uid=session_uid.strip(),
                server_ip=server_ip,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            if not res.success:
                raise ToolFailure(
                    f"cpcrud_discard_staged failed for session {session_uid!r}: "
                    f"{redact_sid(res.error_message or 'discard failed', known_sids=known_sids)}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    known_sids=known_sids,
                )
            return json_tool_result(
                {
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "session_uid": session_uid.strip(),
                    "discarded": True,
                    "data": sanitize_mapping(res.data, known_sids=known_sids),
                },
                known_sids=known_sids,
            )


__all__ = [
    "register_mcp_tools",
]
