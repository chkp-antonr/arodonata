"""Shared serialization, cache freshness, pagination, filtering, and plan-signing helpers for MCP tools."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Literal

from arodonata.client import ArodonataClient
from arodonata.core.errors import InvalidCredentialsError, sanitize_mapping
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CANONICAL_ASSET_TYPES, CacheMode, SyncScope, utc_now
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebaseLayerEntry, RulebaseType
from arodonata.core.models.services import CPService
from arodonata.core.ports import CachePort
from arodonata.core.services.search_service import classify_search_term, matches_classified_term
from arodonata.cpcrud import Plan
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES
from arodonata.mcp.errors import ToolFailure, validate_domain_or_fail
from arodonata.rulebase import RULEBASE_TYPE_TO_COMMAND, PolicyPackageInfo

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
RULEBASE_TYPE_TO_LIVE_COMMAND: dict[RulebaseType, str] = RULEBASE_TYPE_TO_COMMAND


def _is_live_cache_mode(kwargs: dict[str, Any]) -> bool:
    """Return `True` when `cache_mode` requests live Management API execution (`'force'` or `'live'`)."""
    raw = kwargs.get("cache_mode")
    return isinstance(raw, str) and raw.strip().lower() in ("force", "live")


def _is_live_rulebase_call(kwargs: dict[str, Any]) -> bool:
    """Return `True` when `show_rulebase` arguments force a live Management API call."""
    if _is_live_cache_mode(kwargs):
        return True
    bool_flags = (
        "show_hits",
        "show_as_ranges",
        "show_expiration_settings",
        "dereference_group_members",
        "show_membership",
    )
    if any(bool(kwargs.get(flag)) for flag in bool_flags):
        return True
    return any(kwargs.get(opt) is not None for opt in ("order", "filter_settings", "hits_settings"))


def _is_refresh_action(kwargs: dict[str, Any]) -> bool:
    """Return `True` when `cache_control` invokes `action='refresh'`."""
    return kwargs.get("action") == "refresh"


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


def _get_v2_cache(client: ArodonataClient) -> CachePort:
    """Return the active `CachePort` exposed by `client.cache`."""
    return client.cache


async def _upgrade_uninitialized_cache_mode(
    client: ArodonataClient,
    mgmt_name: str | None,
    domain: str | None,
    scope: Literal["domains", "objects", "services", "assets"],
    mode: CacheMode,
) -> CacheMode:
    """Upgrade `cache_mode='cache'` to `'smart'` when `scope` has never been synced and holds zero rows."""
    if mode != "cache":
        return mode
    v2_cache = _get_v2_cache(client)
    states = await v2_cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if states:
        return mode
    if scope == "domains":
        existing_domains = await v2_cache.get_domains(mgmt_name=mgmt_name, include_global=True)
        return mode if existing_domains else "smart"
    if scope == "objects":
        topo_states = await v2_cache.list_sync_states(
            mgmt_name=mgmt_name,
            domain_name=domain if domain else None,
            scope="topology",
        )
        if topo_states:
            return "smart"
        existing: Sequence[Any] = await v2_cache.get_objects(
            mgmt_name=mgmt_name, domain_name=domain if domain else None
        )
    elif scope == "services":
        existing = await v2_cache.get_services(mgmt_name=mgmt_name, domain_name=domain if domain else None)
    else:
        existing = await v2_cache.get_assets(mgmt_name=mgmt_name, domain_name=domain if domain else None)
    if existing:
        return mode
    return "smart"


async def _compute_cache_age(
    client: ArodonataClient,
    mgmt_name: str | None,
    domain: str | None,
    scope: SyncScope,
    item_type: str = "*",
    *,
    now_fn: Callable[[], datetime] = utc_now,
) -> float | None:
    """Compute `cache_age_seconds` from `domain_sync_state` for `(mgmt_name, domain, scope, item_type)`."""
    v2_cache = _get_v2_cache(client)
    states = await v2_cache.list_sync_states(
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
        return None
    latest = max(synced_times)
    return float(max(0.0, round((now_fn() - latest).total_seconds(), 3)))


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


def _serialize_cached_model(
    item: CPObject | CPService | Asset,
    details_level: str,
    id_field: str,
    id_value: Any,
) -> dict[str, Any]:
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "id": item.id,
            id_field: id_value,
            "uid": item.uid,
            "name": item.name,
            "type": item.type,
            "mgmt_name": item.mgmt_name,
            "domain_name": item.domain_name,
        }
    dumped = item.model_dump(mode="json", exclude={"raw_data"} if level != "full" else set())
    if level == "full" and item.raw_data:
        dumped["raw_data"] = sanitize_mapping(item.raw_data)
    return dumped


def _serialize_object(obj: CPObject, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `CPObject` according to `details_level`."""
    return _serialize_cached_model(obj, details_level, "object_id", obj.object_id)


def _serialize_service(svc: CPService, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `CPService` according to `details_level`."""
    return _serialize_cached_model(svc, details_level, "service_id", svc.service_id)


def _serialize_asset(asset: Asset, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `Asset` according to `details_level`."""
    return _serialize_cached_model(asset, details_level, "asset_id", asset.asset_id)


def _serialize_layer(layer: RulebaseLayerEntry, details_level: str = "standard") -> dict[str, Any]:
    """Serialize `RulebaseLayerEntry` according to `details_level`."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        return {
            "uid": layer.uid,
            "name": layer.name,
            "type": f"{layer.rulebase_type}-layer",
            "mgmt_name": layer.mgmt_name,
            "domain_name": layer.domain_name,
        }
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


async def _validate_optional_domains(
    client: ArodonataClient,
    eff_mgmt: str | None,
    domains: Sequence[str] | None,
) -> None:
    if eff_mgmt and domains:
        for dom in domains:
            await validate_domain_or_fail(client, eff_mgmt, dom)


async def _fetch_live_collection(
    client: ArodonataClient,
    *,
    eff_mgmt: str,
    eff_domain: str | None,
    live_types: Sequence[str],
    command_resolver: Callable[[str], tuple[str, dict[str, Any]]],
    filter_text: str | None,
    details_level: str,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Fetch live Check Point objects or services across one or more normalized types."""
    combined_raw: list[dict[str, Any]] = []
    for t_name in live_types:
        live_cmd, extra_payload = command_resolver(t_name)
        payload: dict[str, Any] = {
            **extra_payload,
            "limit": max(1, min(limit, 500)),
            "offset": max(0, offset) if len(live_types) == 1 else 0,
            "details-level": details_level,
        }
        if filter_text:
            payload["filter"] = filter_text
        res = await client.api_call(eff_mgmt, live_cmd, payload, domain=eff_domain)
        if not res.success:
            raise ToolFailure(
                f"{live_cmd} failed on {eff_mgmt!r} ({eff_domain or 'default'}): {res.error_message or 'API error'}",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
            )
        objs_raw = res.data.get("objects", []) if isinstance(res.data.get("objects"), list) else []
        if len(live_types) == 1:
            return {
                "from": res.data.get("from", (offset + 1) if objs_raw else 0),
                "to": res.data.get("to", offset + len(objs_raw)),
                "total": res.data.get("total", len(objs_raw)),
                "source": "live",
                "cache_age_seconds": None,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "objects": objs_raw,
            }
        combined_raw.extend(objs_raw)

    return _build_page_envelope(
        combined_raw,
        limit=limit,
        offset=offset,
        source="live",
        cache_age_seconds=None,
        extra={"mgmt_name": eff_mgmt, "domain": eff_domain},
    )
