"""Cache freshness, cold-cache upgrade, sync failure inspection, and deferred live-quota helpers for MCP tools."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Literal

from arodonata.client import ArodonataClient
from arodonata.core.errors import InvalidCredentialsError
from arodonata.core.models.common import CacheMode, SyncScope, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.ports import CachePort
from arodonata.mcp.errors import ToolFailure, consume_live_quota_if_needed


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
    """Return `True` when `cache_control` invokes `action='refresh'` with a live-capable `mode`."""
    if kwargs.get("action") != "refresh":
        return False
    mode_val = str(kwargs.get("mode") or "smart").strip().lower()
    return mode_val != "cache"


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


async def _is_domain_uninitialized(
    v2_cache: CachePort,
    mgmt_name: str | None,
    domain: str | None,
    scope: Literal["domains", "objects", "services", "assets"],
) -> bool:
    """Return `True` when `scope` has never been synced and holds zero rows for `(mgmt_name, domain)`."""
    states = await v2_cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if states:
        return False
    if scope == "domains":
        existing_domains = await v2_cache.get_domains(mgmt_name=mgmt_name, include_global=True)
        return not bool(existing_domains)
    if scope == "objects":
        topo_states = await v2_cache.list_sync_states(
            mgmt_name=mgmt_name,
            domain_name=domain if domain else None,
            scope="topology",
        )
        if topo_states:
            return True
        existing: Sequence[Any] = await v2_cache.get_objects(
            mgmt_name=mgmt_name, domain_name=domain if domain else None
        )
    elif scope == "services":
        existing = await v2_cache.get_services(mgmt_name=mgmt_name, domain_name=domain if domain else None)
    else:
        existing = await v2_cache.get_assets(mgmt_name=mgmt_name, domain_name=domain if domain else None)
    return not bool(existing)


async def _upgrade_uninitialized_cache_mode(
    client: ArodonataClient,
    mgmt_name: str | None,
    domain: str | None,
    scope: Literal["domains", "objects", "services", "assets"],
    mode: CacheMode,
    *,
    domains: Sequence[str] | None = None,
) -> CacheMode:
    """Upgrade `cache_mode='cache'` to `'smart'` when `scope` has never been synced and holds zero rows."""
    if mode != "cache":
        return mode
    v2_cache = _get_v2_cache(client)
    target_domains = [d.strip() for d in domains if d and d.strip()] if (domain is None and domains) else None
    if target_domains:
        for dom_name in target_domains:
            if await _is_domain_uninitialized(v2_cache, mgmt_name, dom_name, scope):
                return "smart"
        return mode
    return "smart" if await _is_domain_uninitialized(v2_cache, mgmt_name, domain, scope) else mode


def _is_sync_state_fresh(
    st: DomainSyncState,
    *,
    now: datetime,
    eff_ttl: float,
    coord: Any = None,
) -> bool:
    if st.status != "ok" or st.synced_at is None:
        return False
    synced_naive = to_naive_utc(st.synced_at)
    if synced_naive is None:
        return False
    if (
        coord is not None
        and hasattr(coord, "is_slice_invalidated")
        and coord.is_slice_invalidated(st.mgmt_name, st.domain_name, st.scope, st.item_type, synced_naive)
    ):
        return False
    return (now - synced_naive).total_seconds() < eff_ttl


def _domain_states_fresh(
    dom_states: Sequence[DomainSyncState],
    *,
    item_types: Sequence[str] | None,
    now: datetime,
    eff_ttl: float,
    coord: Any = None,
) -> bool:
    if not dom_states:
        return False
    if item_types:
        by_type = {st.item_type: st for st in dom_states}
        wildcard = by_type.get("*")
        for req_type in item_types:
            st = by_type.get(req_type) or wildcard
            if st is None or not _is_sync_state_fresh(st, now=now, eff_ttl=eff_ttl, coord=coord):
                return False
        return True
    return all(_is_sync_state_fresh(st, now=now, eff_ttl=eff_ttl, coord=coord) for st in dom_states)


async def _enforce_live_quota_if_sync_required(
    client: ArodonataClient,
    mgmt_name: str | None,
    domain: str | None,
    scope: SyncScope,
    mode: CacheMode,
    *,
    domains: Sequence[str] | None = None,
    item_types: Sequence[str] | None = None,
    now_fn: Callable[[], datetime] = utc_now,
) -> None:
    """Charge the active caller's `live` quota bucket when `mode` requires a remote Management API sync.

    Warm `smart` / `smart-fast` hits within `cache_ttl` (or `domain_list_ttl` for `scope="domains"`)
    and `cache_mode="cache"` calls stay strictly on the `general` bucket. Cold or stale `smart` /
    `smart-fast` / cold-upgraded calls and `force` calls consume a `live` quota slot before syncing.
    """
    if mode == "cache":
        return
    if mode == "force":
        consume_live_quota_if_needed()
        return

    eff_ttl = float(client.settings.domain_list_ttl if scope == "domains" else client.settings.cache_ttl)
    if eff_ttl <= 0:
        consume_live_quota_if_needed()
        return

    coord = getattr(client, "sync_coordinator", None)
    states = await client.cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if not states:
        consume_live_quota_if_needed()
        return

    by_dom: dict[tuple[str, str], list[DomainSyncState]] = defaultdict(list)
    for st in states:
        by_dom[(st.mgmt_name, st.domain_name)].append(st)

    now = to_naive_utc(now_fn()) or utc_now()
    target_doms: Sequence[str] | None = (
        [d.strip() for d in domains if d and d.strip()] if domains else ([domain] if domain else None)
    )
    if target_doms:
        if mgmt_name is not None:
            for dom_name in target_doms:
                if not _domain_states_fresh(
                    by_dom.get((mgmt_name, dom_name), ()),
                    item_types=item_types,
                    now=now,
                    eff_ttl=eff_ttl,
                    coord=coord,
                ):
                    consume_live_quota_if_needed()
                    return
            return
        for dom_name in target_doms:
            matched_keys = [k for k in by_dom if k[1] == dom_name]
            if not matched_keys or any(
                not _domain_states_fresh(by_dom[k], item_types=item_types, now=now, eff_ttl=eff_ttl, coord=coord)
                for k in matched_keys
            ):
                consume_live_quota_if_needed()
                return
        return

    if scope != "domains":
        cached_doms = await client.cache.get_domains(mgmt_name=mgmt_name, include_global=False)
        for d in cached_doms:
            if not _domain_states_fresh(
                by_dom.get((d.mgmt_name, d.name), ()),
                item_types=item_types,
                now=now,
                eff_ttl=eff_ttl,
                coord=coord,
            ):
                consume_live_quota_if_needed()
                return

    for dom_states in by_dom.values():
        if not _domain_states_fresh(dom_states, item_types=item_types, now=now, eff_ttl=eff_ttl, coord=coord):
            consume_live_quota_if_needed()
            return


async def _compute_cache_age(
    client: ArodonataClient,
    mgmt_name: str | None,
    domain: str | None,
    scope: SyncScope,
    item_type: str = "*",
    *,
    domains: Sequence[str] | None = None,
    item_types: Sequence[str] | None = None,
    now_fn: Callable[[], datetime] = utc_now,
) -> float | None:
    """Compute stalest `cache_age_seconds` (`min(synced_at)`) from `domain_sync_state` for touched scope/domains/types."""
    v2_cache = _get_v2_cache(client)
    states = await v2_cache.list_sync_states(
        mgmt_name=mgmt_name,
        domain_name=domain if domain else None,
        scope=scope,
    )
    if domains is not None:
        domain_filter = {d.strip() for d in domains if d and d.strip()}
        if domain_filter:
            states = [s for s in states if s.domain_name in domain_filter]

    if item_types is not None:
        explicit_types = {t.strip() for t in item_types if t and t.strip()}
        if explicit_types and explicit_types != {"*"}:
            has_explicit = any(s.item_type in explicit_types for s in states)
            if has_explicit:
                states = [s for s in states if s.item_type in explicit_types or s.item_type == "*"]
            else:
                states = [s for s in states if s.item_type == "*"]
    elif item_type != "*":
        states = [s for s in states if s.item_type in (item_type, "*")]

    synced_times = [
        s.synced_at
        for s in states
        if s.synced_at is not None
        and not (s.status == "failed" and s.object_count == 0 and s.last_published_at is None)
    ]
    if not synced_times:
        return None
    stalest = min(synced_times)
    return float(max(0.0, round((now_fn() - stalest).total_seconds(), 3)))


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
