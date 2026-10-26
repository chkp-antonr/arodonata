"""MCP tool surface registration (`arodonata.mcp.tools`).

Exposes a consolidated, cache-aligned tool surface:
- Collection listing tools (`list_domains`, `list_objects`, `list_services`, `list_assets`)
  with `from`, `to`, `total`, `source`, and `cache_age_seconds`.
- Multi-table single-entity lookup (`show_object`) across `arodonata_objects`, `arodonata_services`,
  `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` with
  three-tier matching (exact match, strict explicit wildcard `fnmatchcase`, and paginated
  substring candidate fallback).
- Hybrid rulebase inspection and package/layer discovery (`show_rulebase`, `locate_rules`).
- Search, group/cluster membership, and structured aggregation (`search_objects`,
  `get_group_members`, `query_objects` with `aggregate="list" | "count" | "describe"`).
- Unified cache status and synchronization (`cache_control` with `action="status" | "refresh"`).
- Change report (`change_report`) and write-protected `api_call`.
- Opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`: `cpcrud_validate`, `cpcrud_plan`,
  `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`).
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
from fnmatch import fnmatchcase
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.adapters.checkpoint.client import SERVICE_COMMAND_TYPES, is_readonly_command
from arodonata.adapters.checkpoint.transport import validate_command_name
from arodonata.client import ArodonataClient
from arodonata.core.errors import InvalidCredentialsError, ValidationError, redact_sid, sanitize_mapping
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    CANONICAL_ASSET_TYPES,
    DEFAULT_OBJECT_TYPES,
    DEFAULT_SERVICE_TYPES,
    CacheMode,
    SyncScope,
    normalize_any_type,
    normalize_asset_type,
    normalize_object_type,
    normalize_service_type,
    utc_now,
)
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebaseLayerEntry, RulebaseType
from arodonata.core.models.services import CPService
from arodonata.core.services.object_service import resolve_object_query_command
from arodonata.core.services.search_service import classify_search_term, matches_classified_term
from arodonata.core.services.service_cache import resolve_service_query_command
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
from arodonata.rulebase import PolicyPackageInfo, RuleFormat
from arodonata.rulebase.numbering import extract_policy_packages

MCPCacheModeInput = Literal["cache", "smart", "smart-fast", "force", "live"]
MAX_MCP_API_TIMEOUT_SECONDS: float = 300.0
MAX_STORED_PLANS: int = 256
CANONICAL_LAYER_AND_PACKAGE_TYPES: frozenset[str] = frozenset(
    {
        "layer",
        "access-layer",
        "https-layer",
        "threat-layer",
        "package",
        "policy-package",
    }
)
CANONICAL_SHOW_OBJECT_TYPES: frozenset[str] = (
    OBJECT_ITEM_TYPES
    | SERVICE_ITEM_TYPES
    | frozenset({t.lower() for t in CANONICAL_ASSET_TYPES})
    | CANONICAL_LAYER_AND_PACKAGE_TYPES
    | frozenset({"interoperable-device", "generic-object"})
)
RULEBASE_TYPE_TO_LIVE_COMMAND: dict[RulebaseType, str] = {
    "access": "show-access-rulebase",
    "nat": "show-nat-rulebase",
    "https": "show-https-rulebase",
    "threat": "show-threat-rulebase",
}


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
            "id": obj.id,
            "object_id": obj.object_id,
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
            "id": svc.id,
            "service_id": svc.service_id,
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
            "id": asset.id,
            "asset_id": asset.asset_id,
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


def _serialize_layer(layer: RulebaseLayerEntry, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `RulebaseLayerEntry` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    base: dict[str, Any] = {
        "uid": layer.uid,
        "name": layer.name,
        "type": f"{layer.rulebase_type}-layer",
        "rulebase_type": layer.rulebase_type,
        "mgmt_name": layer.mgmt_name,
        "domain_name": layer.domain_name,
        "parent_layer_uid": layer.parent_layer_uid,
        "parent_rule_uid": layer.parent_rule_uid,
        "implicit_cleanup_action": layer.implicit_cleanup_action,
    }
    if level == "uid":
        return {
            "uid": layer.uid,
            "name": layer.name,
            "type": f"{layer.rulebase_type}-layer",
            "mgmt_name": layer.mgmt_name,
            "domain_name": layer.domain_name,
        }
    if level == "full" and layer.raw_data:
        base["raw_data"] = sanitize_mapping(layer.raw_data)
    return base


def _serialize_package(pkg: PolicyPackageInfo, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `PolicyPackageInfo` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": pkg.uid,
            "name": pkg.name,
            "type": "package",
            "mgmt_name": pkg.mgmt_name,
            "domain_name": pkg.domain_name,
        }
    dumped = pkg.model_dump(mode="json", exclude={"raw_data"} if level != "full" else set())
    dumped["type"] = "package"
    if level == "full" and pkg.raw_data:
        dumped["raw_data"] = sanitize_mapping(pkg.raw_data)
    return dumped


def _serialize_any_entity(
    entity: CPObject | CPService | Asset | RulebaseLayerEntry | PolicyPackageInfo,
    details_level: str = "standard",
) -> dict[str, Any]:
    """Serialize any cached entity (`CPObject`, `CPService`, `Asset`, `RulebaseLayerEntry`, `PolicyPackageInfo`)."""
    if isinstance(entity, CPObject):
        return _serialize_object(entity, details_level=details_level)
    if isinstance(entity, CPService):
        return _serialize_service(entity, details_level=details_level)
    if isinstance(entity, Asset):
        return _serialize_asset(entity, details_level=details_level)
    if isinstance(entity, RulebaseLayerEntry):
        return _serialize_layer(entity, details_level=details_level)
    return _serialize_package(entity, details_level=details_level)


def _entity_scope_and_type(
    entity: CPObject | CPService | Asset | RulebaseLayerEntry | PolicyPackageInfo,
) -> tuple[SyncScope, str]:
    if isinstance(entity, CPService):
        return "services", entity.type
    if isinstance(entity, Asset):
        return "assets", "*"
    if isinstance(entity, (RulebaseLayerEntry, PolicyPackageInfo)):
        return "rulebase", "*"
    return "objects", entity.type


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
    eff_limit = max(1, min(limit, 500))
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
    # 1. Collection Listing Tools (`list_domains`, `list_objects`, `list_services`, `list_assets`)
    # ------------------------------------------------------------------

    @server.tool(
        name="list_domains",
        description="List Check Point domains on a management server from arodonata_domains with server-level metadata and cache freshness.",
    )
    @mcp_tool_guard("list_domains", client_getter)
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

    @server.tool(
        name="list_objects",
        description=(
            "List Check Point network objects from arodonata_objects (hosts, networks, address-ranges, "
            "dns-domains, groups, dynamic-objects, etc.) with optional types filter (e.g. types=['host', 'network'] "
            "or aliases 'range', 'dns', 'dynamic')."
        ),
    )
    @mcp_tool_guard("list_objects", client_getter)
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
            live_types = normalized_types or list(DEFAULT_OBJECT_TYPES)
            combined_raw: list[dict[str, Any]] = []
            for t_name in live_types:
                live_cmd, extra_payload = resolve_object_query_command(t_name)
                payload: dict[str, Any] = {
                    **extra_payload,
                    "limit": max(1, min(limit, 500)),
                    "offset": max(0, offset) if len(live_types) == 1 else 0,
                    "details-level": details_level,
                }
                if filter:
                    payload["filter"] = filter
                res = await client.api_call(eff_mgmt, live_cmd, payload, domain=eff_domain)
                if not res.success:
                    raise ToolFailure(
                        f"{live_cmd} failed on {eff_mgmt!r} ({eff_domain or 'default'}): "
                        f"{res.error_message or 'API error'}",
                        mgmt_name=eff_mgmt,
                        domain=eff_domain,
                    )
                objs_raw = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
                if len(live_types) == 1:
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
                combined_raw.extend(objs_raw)

            return json_tool_result(
                _build_page_envelope(
                    combined_raw,
                    limit=limit,
                    offset=offset,
                    source="live",
                    cache_age_seconds=None,
                    extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
                )
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
    @mcp_tool_guard("list_services", client_getter)
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
            live_types = normalized_types or list(DEFAULT_SERVICE_TYPES)
            combined_raw: list[dict[str, Any]] = []
            for t_name in live_types:
                cmd, extra_payload = resolve_service_query_command(t_name)
                payload: dict[str, Any] = {
                    **extra_payload,
                    "limit": max(1, min(limit, 500)),
                    "offset": max(0, offset) if len(live_types) == 1 else 0,
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
                if len(live_types) == 1:
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
                combined_raw.extend(objs_raw)

            return json_tool_result(
                _build_page_envelope(
                    combined_raw,
                    limit=limit,
                    offset=offset,
                    source="live",
                    cache_age_seconds=None,
                    extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
                )
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
        name="list_assets",
        description=(
            "List Check Point gateways, clusters, cluster members, VSX systems, virtual systems, and management "
            "servers (checkpoint-host) from arodonata_assets with optional types filter ('gateway', 'cluster', "
            "'member', 'vsx', 'vs', 'server') and parent cluster/VSX filter."
        ),
    )
    @mcp_tool_guard("list_assets", client_getter)
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
        normalized_types = [normalize_asset_type(t) for t in types if t and t.strip()] if types else None

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
        all_assets = await client.get_gateways(
            mgmt_name=eff_mgmt,
            domain=eff_domain,
            types=normalized_types if not parent else None,
            include_global=include_global,
            cache_mode=mode,
        )
        if mode != "cache":
            await _raise_if_sync_failed(client, eff_mgmt, eff_domain, "assets", "*", has_cached_data=bool(all_assets))

        assets = list(all_assets)
        if parent and parent.strip():
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
            assets = [
                a
                for a in assets
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
            if normalized_types:
                t_set = {t.lower() for t in normalized_types}
                assets = [a for a in assets if a.type.lower() in t_set]

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

    # ------------------------------------------------------------------
    # 2. Multi-Table Single-Entity Lookup (`show_object`) with 3-Tier Matching
    # ------------------------------------------------------------------

    @server.tool(
        name="show_object",
        description=(
            "Retrieve a Check Point object, service, gateway/cluster/VSX asset (including cached interfaces, "
            "blades, and cluster/VSX members), policy package, or rulebase layer by UID, exact name, explicit "
            "wildcard pattern (e.g. 'gw-*01', evaluated strictly as written without implicit prefix/suffix '*'), "
            "or substring fallback (returning up to limit=20 compact candidates when no exact match exists)."
        ),
    )
    @mcp_tool_guard("show_object", client_getter)
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
            normalized_candidate = normalize_any_type(validated_cmd.removeprefix("show-"))
            if normalized_candidate not in CANONICAL_SHOW_OBJECT_TYPES:
                raise ToolFailure(
                    f"Unsupported obj_type {obj_type!r}. Expected a canonical Check Point object, service, asset, or layer type.",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                )
            clean_obj_type = normalized_candidate

        query_str = uid_or_name.strip()
        query_lower = query_str.lower()
        has_explicit_wildcard = "*" in query_str or "?" in query_str

        if not is_live:
            is_service_type = clean_obj_type is not None and (
                clean_obj_type in SERVICE_COMMAND_TYPES or clean_obj_type.startswith("service-")
            )
            is_asset_type = clean_obj_type is not None and clean_obj_type in {t.lower() for t in CANONICAL_ASSET_TYPES}
            is_layer_or_pkg_type = clean_obj_type is not None and clean_obj_type in CANONICAL_LAYER_AND_PACKAGE_TYPES

            # Tier 1: Fast path for exact UID or exact name match when no wildcard is present
            if not has_explicit_wildcard and not is_layer_or_pkg_type:
                found_exact = await client.find_object(
                    eff_mgmt,
                    target_domain,
                    query_str,
                    obj_type=clean_obj_type,
                    cache_mode=mode,
                )
                if found_exact is not None:
                    scope_name, item_type_val = _entity_scope_and_type(found_exact)
                    age = await _compute_cache_age(client, eff_mgmt, target_domain, scope_name, item_type_val)
                    obj_dict = _serialize_any_entity(found_exact, details_level=details_level)
                    return json_tool_result(
                        {
                            "from": 1,
                            "to": 1,
                            "total": 1,
                            "match_type": "exact",
                            "source": "cache",
                            "cache_age_seconds": age,
                            "mgmt_name": eff_mgmt,
                            "domain": target_domain,
                            "object": obj_dict,
                            "objects": [obj_dict],
                        }
                    )

            # Load candidate entities across the relevant cached tables for Tier 1 (layers/packages), Tier 2, or Tier 3
            candidates: list[CPObject | CPService | Asset | RulebaseLayerEntry | PolicyPackageInfo] = []
            want_objs = clean_obj_type is None or (
                not is_service_type and not is_asset_type and not is_layer_or_pkg_type
            )
            want_svcs = clean_obj_type is None or is_service_type
            want_assets = clean_obj_type is None or is_asset_type
            want_layers = clean_obj_type is None or is_layer_or_pkg_type

            if want_objs:
                objs = await client.get_objects(
                    mgmt_name=eff_mgmt,
                    domain=target_domain,
                    types=[clean_obj_type] if clean_obj_type else None,
                    include_global=(target_domain == "Global"),
                    cache_mode="cache" if not has_explicit_wildcard else mode,
                )
                candidates.extend(objs)

            if want_svcs:
                svcs = await client.get_services(
                    mgmt_name=eff_mgmt,
                    domain=target_domain,
                    types=[clean_obj_type] if clean_obj_type else None,
                    include_global=(target_domain == "Global"),
                    cache_mode="cache" if not has_explicit_wildcard else mode,
                )
                candidates.extend(svcs)

            if want_assets:
                assets = await client.get_gateways(
                    mgmt_name=eff_mgmt,
                    domain=target_domain,
                    types=[clean_obj_type] if clean_obj_type else None,
                    include_global=(target_domain == "Global"),
                    cache_mode="cache" if not has_explicit_wildcard else mode,
                )
                candidates.extend(assets)

            if want_layers:
                snap = await client.cache.get_domain_rulebase(eff_mgmt, target_domain)
                if clean_obj_type in (None, "package", "policy-package"):
                    candidates.extend(extract_policy_packages(snap))
                if clean_obj_type in (None, "layer", "access-layer", "https-layer", "threat-layer"):
                    for l_entry in snap.layers:
                        if (
                            clean_obj_type in ("access-layer", "https-layer", "threat-layer")
                            and f"{l_entry.rulebase_type}-layer" != clean_obj_type
                        ):
                            continue
                        candidates.append(l_entry)

            # Check Tier 1 exact match on layers/packages (or case-insensitive exact name across all candidates)
            if not has_explicit_wildcard:
                for cand in candidates:
                    if cand.uid.lower() == query_lower or cand.name.lower() == query_lower:
                        scope_name, item_type_val = _entity_scope_and_type(cand)
                        age = await _compute_cache_age(client, eff_mgmt, target_domain, scope_name, item_type_val)
                        obj_dict = _serialize_any_entity(cand, details_level=details_level)
                        return json_tool_result(
                            {
                                "from": 1,
                                "to": 1,
                                "total": 1,
                                "match_type": "exact",
                                "source": "cache",
                                "cache_age_seconds": age,
                                "mgmt_name": eff_mgmt,
                                "domain": target_domain,
                                "object": obj_dict,
                                "objects": [obj_dict],
                            }
                        )

            # Tier 2: Explicit wildcard (`*` or `?` in `uid_or_name`) — anchored fnmatchcase without extra `*`
            if has_explicit_wildcard:
                wildcard_matches = [c for c in candidates if fnmatchcase(c.name.lower(), query_lower)]
                age = await _compute_cache_age(client, eff_mgmt, target_domain, "objects", "*")
                if len(wildcard_matches) == 1:
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
                            "domain": target_domain,
                            "object": single_dict,
                            "objects": [single_dict],
                        }
                    )
                eff_offset = max(0, offset)
                eff_limit = max(1, min(limit, 500))
                sliced_wild = wildcard_matches[eff_offset : eff_offset + eff_limit]
                serialized_wild = [_serialize_any_entity(c, details_level="standard") for c in sliced_wild]
                return json_tool_result(
                    {
                        "from": (eff_offset + 1) if serialized_wild else 0,
                        "to": eff_offset + len(serialized_wild),
                        "total": len(wildcard_matches),
                        "match_type": "wildcard",
                        "source": "cache",
                        "cache_age_seconds": age,
                        "mgmt_name": eff_mgmt,
                        "domain": target_domain,
                        "object": None,
                        "objects": serialized_wild,
                    }
                )

            # Tier 3: Substring candidate fallback when no exact match was found
            substring_matches = [c for c in candidates if query_lower and query_lower in c.name.lower()]
            if substring_matches:
                age = await _compute_cache_age(client, eff_mgmt, target_domain, "objects", "*")
                eff_offset = max(0, offset)
                eff_limit = max(1, min(limit, 500))
                sliced_sub = substring_matches[eff_offset : eff_offset + eff_limit]
                serialized_sub = [_serialize_any_entity(c, details_level="standard") for c in sliced_sub]
                return json_tool_result(
                    {
                        "from": (eff_offset + 1) if serialized_sub else 0,
                        "to": eff_offset + len(serialized_sub),
                        "total": len(substring_matches),
                        "match_type": "substring_candidates",
                        "source": "cache",
                        "cache_age_seconds": age,
                        "mgmt_name": eff_mgmt,
                        "domain": target_domain,
                        "object": serialized_sub[0] if len(substring_matches) == 1 and serialized_sub else None,
                        "objects": serialized_sub,
                        "hint": (
                            f"No exact match for {uid_or_name!r}; returning {len(serialized_sub)} of "
                            f"{len(substring_matches)} cached substring candidate(s). Pass an exact name/UID "
                            "or an explicit wildcard pattern (e.g. 'prefix*suffix')."
                        ),
                    }
                )

        # Fallback to live show-object or type-specific command
        cmd = (
            f"show-{clean_obj_type}"
            if (clean_obj_type and clean_obj_type not in CANONICAL_LAYER_AND_PACKAGE_TYPES)
            else "show-object"
        )
        payload: dict[str, Any] = {"details-level": details_level}
        if "-" in query_str and len(query_str) == 36 and not clean_obj_type:
            payload["uid"] = query_str
        elif clean_obj_type and clean_obj_type not in CANONICAL_LAYER_AND_PACKAGE_TYPES:
            payload["name"] = query_str
        else:
            payload["uid"] = query_str

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
                "match_type": "exact",
                "source": "live",
                "cache_age_seconds": None,
                "mgmt_name": eff_mgmt,
                "domain": target_domain,
                "object": obj_payload,
                "objects": [obj_payload],
            },
            known_sids=known_sids,
        )

    # ------------------------------------------------------------------
    # 3. Search, Group/Cluster Membership & Structured Aggregation
    # ------------------------------------------------------------------

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

        normalized_types = [normalize_object_type(t) for t in types if t and t.strip()] if types else None
        mode, _ = _normalize_cache_mode(cache_mode, default="smart")
        result = await client.search_objects(
            query,
            mgmt_name=eff_mgmt,
            domains=target_domains,
            types=normalized_types,
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
        description=(
            "Expand direct and recursive members of a Check Point network group (arodonata_objects), "
            "service-group (arodonata_services), or cluster/VSX container (arodonata_assets) from cache."
        ),
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
        serialized = [_serialize_any_entity(m, details_level="standard") for m in members]
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

    @server.tool(
        name="query_objects",
        description=(
            "Execute structured cross-domain filtering, grouping (group_by), counting (aggregate='count'|'list'), "
            "or progressive-disclosure schema introspection (aggregate='describe') over cached arodonata_objects, "
            "arodonata_services, and arodonata_assets, distinguishing local vs Global objects via original_domain."
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
        aggregate: Literal["count", "list", "describe"] = "list",
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
        name="cache_control",
        description=(
            "Inspect cache freshness across scopes (action='status') or trigger scoped synchronization "
            "(action='refresh', scope='domains'|'objects'|'services'|'assets'|'rulebase')."
        ),
    )
    @mcp_tool_guard("cache_control", client_getter)
    async def cache_control(
        action: Literal["status", "refresh"] = "status",
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: list[str] | None = None,
        scope: SyncScope | None = None,
        types: list[str] | None = None,
        include_global: bool = False,
        mode: Literal["cache", "smart", "smart-fast", "force"] = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None

        if action == "status":
            status_data = await client.get_cache_status(
                mgmt_name=eff_mgmt,
                domain_name=domain.strip() if domain else None,
                scope=scope,
            )
            return json_tool_result(status_data)

        if action != "refresh":
            raise ToolFailure(f"Invalid cache_control action {action!r}. Expected 'status' or 'refresh'.")

        target_scope: SyncScope = scope or "objects"
        target_domains = domains if domains is not None else ([domain] if domain else None)
        if eff_mgmt and target_domains:
            for d in target_domains:
                await validate_domain_or_fail(client, eff_mgmt, d)

        if target_scope == "domains":
            refreshed_domains = await client.get_domains(
                mgmt_name=eff_mgmt,
                include_global=include_global,
                cache_mode="force" if mode == "force" else "smart",
            )
            return json_tool_result(
                {
                    "scope": "domains",
                    "mgmt_name": eff_mgmt,
                    "refreshed_count": len(refreshed_domains),
                    "domains": [d.name for d in refreshed_domains],
                }
            )
        if target_scope == "objects":
            normalized_obj_types = [normalize_object_type(t) for t in types if t and t.strip()] if types else None
            outcome = await client.refresh_objects(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=normalized_obj_types,
                include_global=include_global,
                mode=mode,
            )
        elif target_scope == "services":
            normalized_svc_types = [normalize_service_type(t) for t in types if t and t.strip()] if types else None
            outcome = await client.refresh_services(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=normalized_svc_types,
                include_global=include_global,
                mode=mode,
            )
        elif target_scope == "assets":
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
    # 4. Hybrid Rulebase & Policy Package/Layer Catalog Tool (`show_rulebase`, `locate_rules`)
    # ------------------------------------------------------------------

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
    @mcp_tool_guard("show_rulebase", client_getter)
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
        if rulebase_type not in RULEBASE_TYPE_TO_LIVE_COMMAND:
            raise ToolFailure(
                f"Invalid rulebase_type {rulebase_type!r}. Expected 'access', 'nat', 'https', or 'threat'."
            )
        live_command = RULEBASE_TYPE_TO_LIVE_COMMAND[rulebase_type]
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_domain = eff_domain or "default"
        mode, is_live_mode = _normalize_cache_mode(cache_mode, default="smart")

        eff_package = package.strip() if package and package.strip() else None
        eff_layer = layer.strip() if layer and layer.strip() else None
        if rulebase_type == "nat":
            eff_package = eff_package or (name.strip() if name else None) or (uid.strip() if uid else None) or eff_layer
        else:
            if not eff_layer and not eff_package:
                eff_layer = (name.strip() if name else None) or (uid.strip() if uid else None)

        async def _build_catalog_response(hint_message: str | None = None) -> CallToolResult:
            snap, _, _, _, snap_age = await client._rulebase_source._ensure_and_load_snapshot(
                eff_mgmt,
                target_domain,
                cache_mode=mode,
            )
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
                "cache_age_seconds": round(snap_age, 3) if snap_age is not None else 0.0,
                "mgmt_name": eff_mgmt,
                "domain": target_domain,
                "rulebase_type": rulebase_type,
                "packages": packages,
                "layers": layers,
                "objects": packages if packages else layers,
            }
            if hint_message:
                catalog_payload["hint"] = hint_message
            return json_tool_result(catalog_payload)

        # Discovery mode: when neither package nor layer is specified, return cached packages and layers
        if not eff_package and not eff_layer:
            return await _build_catalog_response()

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

            if filter:
                payload["filter"] = filter
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
                "format": format,
                "rulebase": rb_items,
            }
            return json_tool_result(live_envelope)

        # Serve from cached rulebase snapshot and evaluate filter locally; if target package/layer is not found,
        # return the domain's package/layer catalog with a helpful hint rather than an error.
        snap_check, _, _, _, _ = await client._rulebase_source._ensure_and_load_snapshot(
            eff_mgmt,
            target_domain,
            cache_mode=mode,
        )
        known_pkgs = {p.uid.lower() for p in extract_policy_packages(snap_check)} | {
            p.name.lower() for p in extract_policy_packages(snap_check)
        }
        known_layers = (
            {l_e.uid.lower() for l_e in snap_check.layers}
            | {l_e.name.lower() for l_e in snap_check.layers}
            | {pl.layer_uid.lower() for pl in snap_check.package_layers}
            | {pl.layer_name.lower() for pl in snap_check.package_layers}
        )
        if rulebase_type == "nat":
            target_check = (eff_package or eff_layer or "").lower()
            if target_check and target_check not in known_pkgs and (known_pkgs or known_layers):
                return await _build_catalog_response(
                    hint_message=(
                        f"Policy package {eff_package or eff_layer!r} was not found in cached NAT rulebases on "
                        f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
                    )
                )
        else:
            if eff_package and eff_package.lower() not in known_pkgs and (known_pkgs or known_layers):
                return await _build_catalog_response(
                    hint_message=(
                        f"Policy package {eff_package!r} was not found in cached {rulebase_type!r} rulebases on "
                        f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
                    )
                )
            if eff_layer and eff_layer.lower() not in known_layers and (known_pkgs or known_layers):
                return await _build_catalog_response(
                    hint_message=(
                        f"Layer {eff_layer!r} was not found in cached {rulebase_type!r} rulebases on "
                        f"{eff_mgmt!r} ({target_domain}). Returning available packages and layers."
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
    # 5. Change Report & Gated `api_call`
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
            "Execute a direct Check Point Management Web API command (e.g. 'where-used', 'show-sessions', "
            "'show-unused-objects', 'show-task', 'verify-policy'). By default only read-only commands "
            "('show-*', 'where-used', 'verify-policy') are permitted unless ARODONATA_MCP_ALLOW_WRITE_API=true."
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
            name="cpcrud_staged_session",
            description=(
                "Adopt a staged Check Point session (created with keep_session=True) via take-over-session "
                "and either publish (action='publish', invalidating the domain cache) or discard "
                "(action='discard') uncommitted changes before logging out cleanly."
            ),
        )
        @mcp_tool_guard("cpcrud_staged_session", client_getter)
        async def cpcrud_staged_session(
            session_uid: str,
            action: Literal["publish", "discard"] = "publish",
            mgmt_name: str | None = None,
            domain: str | None = None,
            server_ip: str | None = None,
            timeout: float | None = None,
        ) -> CallToolResult:
            if not session_uid or not session_uid.strip():
                raise ToolFailure("session_uid must not be empty.")
            if action not in ("publish", "discard"):
                raise ToolFailure(f"Invalid action {action!r}. Expected 'publish' or 'discard'.")

            client = client_getter()
            eff_mgmt = resolve_mgmt_name(client, mgmt_name)
            eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)

            if action == "publish":
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
                        f"cpcrud_staged_session(action='publish') failed for session {session_uid!r}: "
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
                        "action": "publish",
                        "published": True,
                        "discarded": False,
                        "data": sanitize_mapping(res.data, known_sids=known_sids),
                    },
                    known_sids=known_sids,
                )

            res = await client.cpcrud.discard_staged_session(
                eff_mgmt,
                eff_domain,
                session_uid=session_uid.strip(),
                server_ip=server_ip,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            if not res.success:
                raise ToolFailure(
                    f"cpcrud_staged_session(action='discard') failed for session {session_uid!r}: "
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
                    "action": "discard",
                    "published": False,
                    "discarded": True,
                    "data": sanitize_mapping(res.data, known_sids=known_sids),
                },
                known_sids=known_sids,
            )


__all__ = [
    "register_mcp_tools",
]
