"""Internal 3-tier candidate loading, matching, and live fallback helpers for MCP `show_object`."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.errors import ValidationError, redact_sid
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, normalize_any_type
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebaseLayerEntry
from arodonata.core.models.services import CPService
from arodonata.core.primitives import is_uuid, validate_command_name
from arodonata.mcp.errors import ToolFailure, collect_known_sids, consume_live_quota_if_needed, json_tool_result
from arodonata.mcp.tools._common import (
    CANONICAL_LAYER_AND_PACKAGE_TYPES,
    CANONICAL_SHOW_OBJECT_TYPES,
    _compute_cache_age,
    _entity_scope_and_type,
    _serialize_any_entity,
)
from arodonata.rulebase import PolicyPackageInfo
from arodonata.rulebase.numbering import extract_policy_packages

EntityUnion = CPObject | CPService | Asset | RulebaseLayerEntry | PolicyPackageInfo


_CPMI_TO_CANONICAL_ASSET_TYPE: dict[str, str] = {
    "cpmigatewayplain": "simple-gateway",
    "cpmigatewaycluster": "simple-cluster",
    "cpmiclustermember": "cluster-member",
    "cpmivsxnetobj": "vsx-gateway",
    "cpmivsxclusternetobj": "vsx-cluster",
    "cpmivsxclustermember": "vsx-cluster-member",
    "cpmivsnetobj": "virtual-system",
    "cpmivsclusternetobj": "virtual-system",
    "cpmihostckp": "checkpoint-host",
}

_ASSET_LIVE_REST_TYPES: frozenset[str] = frozenset({"simple-gateway", "simple-cluster"})


def validate_show_object_type(obj_type: str | None, eff_mgmt: str, eff_domain: str | None) -> str | None:
    """Validate and canonicalize an optional `show_object(obj_type=...)` parameter."""
    if obj_type is None or not obj_type.strip():
        return None
    raw_clean = obj_type.strip()
    lowered = raw_clean.lower()
    mapped = _CPMI_TO_CANONICAL_ASSET_TYPE.get(lowered, lowered)
    normalized = normalize_any_type(mapped)
    if normalized == lowered and "_" in normalized:
        normalized = normalize_any_type(normalized.replace("_", "-"))
    if normalized not in CANONICAL_SHOW_OBJECT_TYPES:
        raise ToolFailure(
            f"Unsupported obj_type {obj_type!r}. Expected a canonical Check Point object, service, asset, or layer type.",
            mgmt_name=eff_mgmt,
            domain=eff_domain,
        )
    try:
        validated_cmd = validate_command_name(f"show-{normalized}")
    except ValidationError as exc:
        raise ToolFailure(f"Invalid obj_type {obj_type!r}: {exc}", mgmt_name=eff_mgmt, domain=eff_domain) from exc
    return validated_cmd.removeprefix("show-")


async def _fetch_candidate_scope(
    sync_fn: Callable[..., Awaitable[Any]],
    get_fn: Callable[..., Awaitable[Sequence[EntityUnion]]],
    *,
    eff_mgmt: str,
    eff_domain: str | None,
    sync_targets: list[str] | None,
    type_filter: list[str] | None,
    eff_include_global: bool,
    cand_mode: CacheMode,
    fetch_mode: CacheMode,
    refresh_with_types: bool = True,
) -> Sequence[EntityUnion]:
    if sync_targets:
        refresh_kwargs: dict[str, Any] = {
            "mgmt_name": eff_mgmt,
            "domains": sync_targets,
            "include_global": False,
            "mode": cand_mode,
        }
        if refresh_with_types:
            refresh_kwargs["types"] = type_filter
        await sync_fn(**refresh_kwargs)
    return await get_fn(
        mgmt_name=eff_mgmt,
        domain=eff_domain,
        types=type_filter,
        include_global=eff_include_global,
        cache_mode=fetch_mode,
    )


async def load_show_object_candidates(
    client: ArodonataClient,
    *,
    eff_mgmt: str,
    eff_domain: str | None,
    sync_domain: str | None,
    clean_obj_type: str | None,
    eff_mode: CacheMode,
    has_explicit_wildcard: bool,
    is_service_type: bool,
    is_asset_type: bool,
    is_layer_or_pkg_type: bool,
) -> list[EntityUnion]:
    """Load candidate entities across cached tables for Tier 1 (layers/packages), Tier 2, or Tier 3."""
    candidates: list[EntityUnion] = []
    eff_include_global = True if eff_domain is None else (eff_domain == "Global")
    cand_mode: CacheMode = "cache" if not has_explicit_wildcard else eff_mode
    fetch_mode: CacheMode = "cache" if eff_domain is None else cand_mode
    type_filter = [clean_obj_type] if clean_obj_type else None
    sync_targets = [sync_domain] if (eff_domain is None and cand_mode != "cache" and sync_domain) else None

    scope_specs: list[
        tuple[bool, Callable[..., Awaitable[Any]], Callable[..., Awaitable[Sequence[EntityUnion]]], bool]
    ] = [
        (
            clean_obj_type is None or (not is_service_type and not is_asset_type and not is_layer_or_pkg_type),
            client.refresh_objects,
            client.get_objects,
            True,
        ),
        (clean_obj_type is None or is_service_type, client.refresh_services, client.get_services, True),
        (clean_obj_type is None or is_asset_type, client.refresh_assets, client.get_gateways, False),
    ]
    for enabled, sync_fn, get_fn, refresh_with_types in scope_specs:
        if enabled:
            candidates.extend(
                await _fetch_candidate_scope(
                    sync_fn,
                    get_fn,
                    eff_mgmt=eff_mgmt,
                    eff_domain=eff_domain,
                    sync_targets=sync_targets,
                    type_filter=type_filter,
                    eff_include_global=eff_include_global,
                    cand_mode=cand_mode,
                    fetch_mode=fetch_mode,
                    refresh_with_types=refresh_with_types,
                )
            )

    if clean_obj_type is None or is_layer_or_pkg_type:
        if eff_domain is not None:
            layer_domains = [eff_domain]
        else:
            cached_doms = await client.cache.get_domains(eff_mgmt, include_global=True)
            layer_domains = (
                [d.name for d in cached_doms] if cached_doms else ([sync_domain] if sync_domain else ["default"])
            )
        for l_dom in layer_domains:
            snap = await client.cache.get_domain_rulebase(eff_mgmt, l_dom)
            if clean_obj_type in (None, "package", "policy-package"):
                candidates.extend(extract_policy_packages(snap))
            if clean_obj_type in (None, "layer", "access-layer", "https-layer", "threat-layer"):
                candidates.extend(
                    l_entry
                    for l_entry in snap.layers
                    if clean_obj_type not in ("access-layer", "https-layer", "threat-layer")
                    or f"{l_entry.rulebase_type}-layer" == clean_obj_type
                )
    return candidates


def dedupe_exact_candidates(raw_exact_cands: Sequence[EntityUnion]) -> list[EntityUnion]:
    """Deduplicate exact UID matches across replicated Global objects, preferring owning domains."""
    by_cand_uid: dict[str, EntityUnion] = {}
    cand_order: list[str] = []
    for c in raw_exact_cands:
        if c.uid not in by_cand_uid:
            by_cand_uid[c.uid] = c
            cand_order.append(c.uid)
        else:
            prev = by_cand_uid[c.uid]
            c_dom = getattr(c, "domain_name", None)
            c_orig = getattr(c, "original_domain", None) or c_dom
            prev_dom = getattr(prev, "domain_name", None)
            prev_orig = getattr(prev, "original_domain", None) or prev_dom
            if (c_dom == c_orig and prev_dom != prev_orig) or (c_dom == "Global" and prev_dom != "Global"):
                by_cand_uid[c.uid] = c
    return [by_cand_uid[u] for u in cand_order]


async def exact_match_result(
    client: ArodonataClient,
    entity: EntityUnion,
    *,
    eff_mgmt: str,
    target_domain: str,
    details_level: str,
    known_sids: Sequence[str] | None = None,
) -> CallToolResult:
    matched_domain = getattr(entity, "domain_name", None) or target_domain
    scope_name, item_type_val = _entity_scope_and_type(entity)
    age = await _compute_cache_age(client, eff_mgmt, matched_domain, scope_name, item_type_val)
    obj_dict = _serialize_any_entity(entity, details_level=details_level)
    eff_sids = list(known_sids) if known_sids is not None else await collect_known_sids(client, eff_mgmt)
    return json_tool_result(
        {
            "from": 1,
            "to": 1,
            "total": 1,
            "match_type": "exact",
            "source": "cache",
            "cache_age_seconds": age,
            "mgmt_name": eff_mgmt,
            "domain": matched_domain,
            "object": obj_dict,
            "objects": [obj_dict],
        },
        known_sids=eff_sids,
    )


def ambiguous_show_result(
    eff_mgmt: str,
    serialized: list[dict[str, Any]],
    hint: str,
    *,
    known_sids: Sequence[str] | None = None,
) -> CallToolResult:
    return json_tool_result(
        {
            "from": 1 if serialized else 0,
            "to": len(serialized),
            "total": len(serialized),
            "match_type": "ambiguous",
            "source": "cache",
            "cache_age_seconds": None,
            "mgmt_name": eff_mgmt,
            "domain": None,
            "object": None,
            "objects": serialized,
            "hint": hint,
        },
        known_sids=known_sids,
    )


def sliced_candidate_result(
    matches: Sequence[EntityUnion],
    *,
    match_type: Literal["wildcard", "substring_candidates"],
    age: float | None,
    eff_mgmt: str,
    domain: str,
    offset: int,
    limit: int,
    single_object: dict[str, Any] | None = None,
    hint: str | None = None,
    known_sids: Sequence[str] | None = None,
) -> CallToolResult:
    eff_offset = max(0, offset)
    eff_limit = max(1, min(limit, 500))
    sliced = matches[eff_offset : eff_offset + eff_limit]
    serialized = [_serialize_any_entity(c, details_level="standard") for c in sliced]
    payload: dict[str, Any] = {
        "from": (eff_offset + 1) if serialized else 0,
        "to": eff_offset + len(serialized),
        "total": len(matches),
        "match_type": match_type,
        "source": "cache",
        "cache_age_seconds": age,
        "mgmt_name": eff_mgmt,
        "domain": domain,
        "object": single_object,
        "objects": serialized,
    }
    if hint is not None:
        payload["hint"] = hint
    return json_tool_result(payload, known_sids=known_sids)


async def live_show_object(
    client: ArodonataClient,
    *,
    query_str: str,
    uid_or_name: str,
    eff_mgmt: str,
    eff_domain: str | None,
    target_domain: str,
    clean_obj_type: str | None,
    details_level: str,
) -> CallToolResult:
    """Fallback live `show-*` API call when cached tiers miss or `cache_mode='live'` is requested."""
    is_typed = bool(clean_obj_type and clean_obj_type not in CANONICAL_LAYER_AND_PACKAGE_TYPES)
    use_show_object_for_asset = bool(
        clean_obj_type
        and clean_obj_type in {t.lower() for t in CANONICAL_SHOW_OBJECT_TYPES}
        and clean_obj_type
        in {
            "cluster-member",
            "vsx-gateway",
            "vsx-cluster",
            "vsx-cluster-member",
            "virtual-system",
            "vs-netobj",
            "checkpoint-host",
        }
    )
    cmd = "show-object" if (not is_typed or use_show_object_for_asset) else f"show-{clean_obj_type}"
    payload: dict[str, Any] = {"details-level": details_level}
    if is_uuid(query_str):
        payload["uid"] = query_str
    elif is_typed and not use_show_object_for_asset:
        payload["name"] = query_str
    else:
        payload["uid"] = query_str

    consume_live_quota_if_needed()
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
