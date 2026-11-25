"""Multi-Domain Security Management (MDSM) discovery, Global domain synthesis, and TTL tracking.

Implements `DomainListRefreshTracker` and `DomainService`:
- Discovers and caches domains across configured management servers via `show-domains`.
- Synthesizes an explicit `Global` domain row (`show-global-domain` or fallback synthesis).
- Excludes `Global` domains by default (`include_global=False`) and includes them when `include_global=True`.
- Tracks each domain's `active_ip`, `active_mds_ip`, and `standby_ips`, and re-resolves on failover.
- Enforces the 1-hour domain list TTL (`domain_list_ttl = 3600` seconds) via `DomainListRefreshTracker`.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

import arlogi

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import SYSTEM_DOMAIN_KEY
from arodonata.core.errors import (
    ConfigurationError,
    DomainNotFoundError,
    LockAcquisitionError,
)
from arodonata.core.models.common import ApiCallResult, CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import (
    DomainInfo,
    DomainSyncState,
    parse_domain_dict,
)
from arodonata.core.ports import ApiPort, DomainCachePort, LockPort, SyncStatePort
from arodonata.core.services._domain_discovery import (
    discover_mds_domains,
    fetch_global_domain_entry,
    fetch_mds_ip_map,
)
from arodonata.core.telemetry import span_attrs, traced


class _DomainServiceCachePort(DomainCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `DomainService`."""


logger = arlogi.get_logger(__name__)


class DomainListRefreshTracker:
    """Tracks per-server domain list freshness against the 1-hour (`domain_list_ttl`) TTL."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._ttl_seconds = float(ttl_seconds)
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())
        self._last_refreshed_at: dict[str, datetime] = {}
        self._invalidated_servers: set[str] = set()
        self._invalidated_at: dict[str, datetime] = {}
        self._global_invalidated_at: datetime | None = None
        self._invalidation_counter: int = 0
        self._global_invalidated_seq: int = 0
        self._server_invalidated_seq: dict[str, int] = {}
        self._server_refreshed_seq: dict[str, int] = {}

    @property
    def ttl_seconds(self) -> float:
        """Configured domain list TTL in seconds (default 3600s / 1 hour)."""
        return self._ttl_seconds

    def mark_refreshed(self, mgmt_name: str, refreshed_at: datetime | None = None) -> datetime:
        """Record that `mgmt_name`'s domain list was refreshed at `refreshed_at`."""
        ts = to_naive_utc(refreshed_at) if refreshed_at is not None else self._now()
        self._last_refreshed_at[mgmt_name] = ts
        self._invalidated_servers.discard(mgmt_name)
        self._server_refreshed_seq[mgmt_name] = self._invalidation_counter
        return ts

    def invalidate(self, mgmt_name: str | None = None) -> None:
        """Invalidate the domain list TTL memo for `mgmt_name` (or all servers if `None`)."""
        self._invalidation_counter += 1
        inv_ts = self._now()
        if mgmt_name is None:
            self._last_refreshed_at.clear()
            self._invalidated_servers.clear()
            self._invalidated_at.clear()
            self._global_invalidated_at = inv_ts
            self._global_invalidated_seq = self._invalidation_counter
        else:
            self._last_refreshed_at.pop(mgmt_name, None)
            self._invalidated_servers.add(mgmt_name)
            self._invalidated_at[mgmt_name] = inv_ts
            self._server_invalidated_seq[mgmt_name] = self._invalidation_counter

    def last_refreshed_at(self, mgmt_name: str) -> datetime | None:
        """Return the last recorded in-memory refresh timestamp for `mgmt_name`."""
        return self._last_refreshed_at.get(mgmt_name)

    def needs_refresh(
        self,
        mgmt_name: str,
        *,
        has_cached_domains: bool,
        persisted_synced_at: datetime | None = None,
        mode: CacheMode = "smart",
        ttl_override: float | None = None,
    ) -> bool:
        """Return `True` if `show-domains` should be re-fetched for `mgmt_name`."""
        if mode == "cache":
            return False
        if mode == "force":
            return True
        if not has_cached_domains:
            return True
        if mgmt_name in self._invalidated_servers:
            return True

        eff_ttl = float(ttl_override) if ttl_override is not None else self._ttl_seconds
        ref_time_raw = self._last_refreshed_at.get(mgmt_name) or persisted_synced_at
        if ref_time_raw is None:
            return True
        ref_time = to_naive_utc(ref_time_raw)

        inv_candidates: list[tuple[datetime, int]] = []
        if self._global_invalidated_at is not None:
            inv_candidates.append((self._global_invalidated_at, self._global_invalidated_seq))
        srv_inv = self._invalidated_at.get(mgmt_name)
        if srv_inv is not None:
            inv_candidates.append((srv_inv, self._server_invalidated_seq.get(mgmt_name, 0)))
        if inv_candidates:
            max_inv_ts, max_inv_seq = max(inv_candidates, key=lambda pair: (pair[0], pair[1]))
            if ref_time < max_inv_ts:
                return True
            if ref_time == max_inv_ts and self._server_refreshed_seq.get(mgmt_name, 0) < max_inv_seq:
                return True

        age = (self._now() - ref_time).total_seconds()
        return age >= eff_ttl


class DomainService:
    """Discovers, caches, and resolves MDSM domains (`show-domains`, `Global`, failover IPs)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: _DomainServiceCachePort,
        lock_port: LockPort | None = None,
        tracker: DomainListRefreshTracker | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._lock_port = lock_port
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())
        self._tracker = tracker or DomainListRefreshTracker(
            ttl_seconds=float(settings.domain_list_ttl),
            now_fn=self._now,
        )
        self._refresh_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @property
    def tracker(self) -> DomainListRefreshTracker:
        """Return the underlying `DomainListRefreshTracker`."""
        return self._tracker

    def resolve_mgmt_names(self, mgmt_name: str | None = None) -> list[str]:
        """Return the target management server name(s)."""
        servers = self._settings.servers
        if mgmt_name is not None:
            if mgmt_name not in servers:
                raise ConfigurationError(
                    f"Unknown management server {mgmt_name!r}. Configured servers: {sorted(servers.keys())}."
                )
            return [mgmt_name]
        return list(servers.keys())

    @traced
    async def get_domains(
        self,
        mgmt_name: str | None = None,
        *,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[DomainInfo]:
        """Return domains for `mgmt_name` (or all configured servers), refreshing when stale.

        Never triggers implicit background object-cache warm-up.
        """
        span_attrs(mgmt_name=mgmt_name, include_global=include_global, cache_mode=cache_mode)
        target_mgmts = self.resolve_mgmt_names(mgmt_name)

        if cache_mode != "cache":
            for m_name in target_mgmts:
                await self._ensure_server_domains_fresh(
                    m_name,
                    mode=cache_mode,
                    ttl_override=cache_ttl,
                )

        if mgmt_name is not None:
            return await self._cache.get_domains(mgmt_name, include_global=include_global)

        all_domains = await self._cache.get_domains(None, include_global=include_global)
        if target_mgmts:
            allowed = set(target_mgmts)
            return [d for d in all_domains if d.mgmt_name in allowed]
        return all_domains

    @traced
    async def get_domain(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        cache_mode: CacheMode = "smart",
    ) -> DomainInfo:
        """Resolve a single `DomainInfo` by `(mgmt_name, domain_name)`, refreshing once if missing."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, cache_mode=cache_mode)
        cached = await self._cache.get_domain(mgmt_name, domain_name)
        if cached is not None and cache_mode != "force":
            return cached

        if cache_mode != "cache":
            await self.refresh_domains(mgmt_name=mgmt_name, mode="force" if cached is None else cache_mode)
            cached = await self._cache.get_domain(mgmt_name, domain_name)
            if cached is not None:
                return cached

        known = [d.name for d in await self._cache.get_domains(mgmt_name, include_global=True)]
        raise DomainNotFoundError(
            f"Domain {domain_name!r} not found on management server {mgmt_name!r}. Known domains: {known}."
        )

    @traced
    async def refresh_domains(
        self,
        mgmt_name: str | None = None,
        *,
        mode: CacheMode = "force",
        include_global: bool = False,
    ) -> list[DomainInfo]:
        """Explicitly refresh the domain list for `mgmt_name` (or all configured servers)."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        target_mgmts = self.resolve_mgmt_names(mgmt_name)
        for m_name in target_mgmts:
            await self._ensure_server_domains_fresh(m_name, mode=mode)
        return await self._cache.get_domains(mgmt_name, include_global=include_global)

    @traced
    async def refresh_domain_failover(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainInfo | None:
        """Re-query the MDS system domain to update `active_ip` and `active_mds_ip` after a failover."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        await self._discover_server_domains(mgmt_name)
        return await self._cache.get_domain(mgmt_name, domain_name)

    async def _ensure_server_domains_fresh(
        self,
        mgmt_name: str,
        *,
        mode: CacheMode = "smart",
        ttl_override: float | None = None,
    ) -> None:
        existing = await self._cache.get_domains(mgmt_name, include_global=True)
        sync_state = await self._cache.get_sync_state(mgmt_name, SYSTEM_DOMAIN_KEY, "domains", "*")
        persisted_synced_at = sync_state.synced_at if sync_state is not None else None

        if not self._tracker.needs_refresh(
            mgmt_name,
            has_cached_domains=bool(existing),
            persisted_synced_at=persisted_synced_at,
            mode=mode,
            ttl_override=ttl_override,
        ):
            return

        async with self._refresh_locks[mgmt_name]:
            existing = await self._cache.get_domains(mgmt_name, include_global=True)
            sync_state = await self._cache.get_sync_state(mgmt_name, SYSTEM_DOMAIN_KEY, "domains", "*")
            persisted_synced_at = sync_state.synced_at if sync_state is not None else None
            if not self._tracker.needs_refresh(
                mgmt_name,
                has_cached_domains=bool(existing),
                persisted_synced_at=persisted_synced_at,
                mode=mode,
                ttl_override=ttl_override,
            ):
                return

            if self._lock_port is not None:
                lock_key = f"sync:{mgmt_name}:{SYSTEM_DOMAIN_KEY}:domains"
                try:
                    async with self._lock_port.lock(lock_key, ttl_seconds=60.0):
                        await self._discover_server_domains(mgmt_name)
                except LockAcquisitionError as exc:
                    logger.debug(
                        f"Domain discovery lock busy for '{mgmt_name}', using cached domains: {exc}",
                        mgmt_name=mgmt_name,
                    )
                    return
            else:
                await self._discover_server_domains(mgmt_name)

    async def _discover_server_domains(self, mgmt_name: str) -> list[DomainInfo]:
        """Execute `show-domains` and `show-global-domain` on `mgmt_name` and persist results."""
        servers = self._settings.servers
        endpoint = servers.get(mgmt_name)
        default_host = endpoint.host if endpoint is not None else None
        now = self._now()
        logger.debug(
            f"Discovering domains on '{mgmt_name}' ({default_host or mgmt_name})...",
            mgmt_name=mgmt_name,
            host=default_host or mgmt_name,
        )

        existing_domains = await self._cache.get_domains(mgmt_name, include_global=True)

        async def _exec_cmd(cmd: str, payload: dict[str, Any]) -> ApiCallResult:
            return await self._api.api_call(mgmt_name, cmd, payload, domain=None)

        discovery = await discover_mds_domains(
            mgmt_name,
            _exec_cmd,
            existing_domains=existing_domains,
            default_host=default_host,
            use_default_host_on_parse=True,
            fallback_uid=True,
            need_mdss_for_global=False,
            now_fn=self._now,
            log=logger,
        )
        res = discovery.res
        fallback_failed_res = discovery.fallback_failed_res
        is_single_domain = discovery.is_single_domain
        discovered = list(discovery.domains)
        mds_ip_by_name = discovery.mds_ip_by_name

        # If show-domains succeeded with no objects, or failed because server is single-domain SmartCenter,
        # synthesize the default single-domain entry if no user domains were returned.
        if not discovered and not res.success and not is_single_domain:
            err_summary = res.error_message or f"HTTP {res.status_code}"
            if fallback_failed_res is not None:
                fb_summary = fallback_failed_res.error_message or f"HTTP {fallback_failed_res.status_code}"
                err_summary = (
                    f"{err_summary} (standard fallback failed: "
                    f"{fallback_failed_res.error_code or fallback_failed_res.status_code} - {fb_summary})"
                )
            logger.warning(
                f"Domain discovery via show-domains failed on '{mgmt_name}' ({default_host or mgmt_name}): "
                f"{res.error_code or res.status_code} - {err_summary}",
                mgmt_name=mgmt_name,
                host=default_host or mgmt_name,
                error_code=res.error_code or str(res.status_code),
                error_message=err_summary,
            )
            # Record failure in domain_sync_state and return existing cached domains
            await self._cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name=mgmt_name,
                    domain_name=SYSTEM_DOMAIN_KEY,
                    scope="domains",
                    item_type="*",
                    synced_at=now,
                    status="failed",
                    last_error=err_summary,
                )
            )
            return existing_domains

        if not discovered:
            discovered.append(
                DomainInfo(
                    id=f"{mgmt_name}:{mgmt_name}",
                    mgmt_name=mgmt_name,
                    uid=f"smc:{mgmt_name}",
                    name=mgmt_name,
                    domain_type="domain",
                    active_ip=default_host,
                    active_mds_ip=default_host,
                    standby_ips=[],
                    servers=[],
                    is_global=False,
                    raw_data={"name": mgmt_name, "type": "domain"},
                    updated_at=now,
                )
            )

        # Ensure an explicit Global domain row is present (`show-global-domain` or synthesized)
        has_global = any(d.is_global or d.name == "Global" for d in discovered)
        if not has_global:
            global_dom = await self._fetch_or_synthesize_global_domain(
                mgmt_name,
                default_host=default_host,
                mds_ip_by_name=mds_ip_by_name,
            )
            discovered.append(global_dom)

        await self._cache.upsert_domains(discovered)
        refreshed_at = self._tracker.mark_refreshed(mgmt_name, now)
        await self._cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name=mgmt_name,
                domain_name=SYSTEM_DOMAIN_KEY,
                scope="domains",
                item_type="*",
                last_published_at=refreshed_at,
                synced_at=refreshed_at,
                status="ok",
                object_count=len(discovered),
                last_error=None,
            )
        )
        logger.debug(
            f"Cached {len(discovered)} domain(s) for '{mgmt_name}'.",
            mgmt_name=mgmt_name,
            count=len(discovered),
        )
        return discovered

    async def _fetch_mds_ip_map(self, mgmt_name: str) -> dict[str, str]:
        """Query `show-mdss` on the system domain to map MDS member names to IP addresses."""
        return await fetch_mds_ip_map(lambda cmd, payload: self._api.api_call(mgmt_name, cmd, payload, domain=None))

    async def _fetch_or_synthesize_global_domain(
        self,
        mgmt_name: str,
        *,
        default_host: str | None = None,
        mds_ip_by_name: dict[str, str] | None = None,
    ) -> DomainInfo:
        """Query `show-global-domain` or synthesize a canonical `Global` `DomainInfo` row."""
        now = self._now()
        eff_mds_ips = dict(mds_ip_by_name or {})

        async def _exec_global(cmd: str, payload: dict[str, Any]) -> ApiCallResult:
            return await self._api.api_call(mgmt_name, cmd, payload, domain=None)

        dom = await fetch_global_domain_entry(
            mgmt_name,
            _exec_global,
            default_host=default_host,
            mds_ip_by_name=eff_mds_ips,
            now_fn=self._now,
            require_uid=True,
            fallback_uid=True,
        )
        if dom is not None:
            if not eff_mds_ips and any(
                isinstance(srv, dict) and isinstance(srv.get("multi-domain-server"), str) for srv in dom.servers
            ):
                fetched_ips = await self._fetch_mds_ip_map(mgmt_name)
                if fetched_ips:
                    raw_with_ips = dict(dom.raw_data)
                    raw_with_ips.setdefault("name", "Global")
                    raw_with_ips["is_global"] = True
                    dom = parse_domain_dict(
                        mgmt_name,
                        raw_with_ips,
                        default_host=default_host,
                        mds_ip_by_name=fetched_ips,
                        now_fn=self._now,
                    ).model_copy(update={"name": "Global", "is_global": True, "domain_type": "global"})
            return dom

        return DomainInfo(
            id=f"{mgmt_name}:Global",
            mgmt_name=mgmt_name,
            uid=f"global:{mgmt_name}",
            name="Global",
            domain_type="global",
            active_ip=default_host,
            active_mds_ip=default_host,
            standby_ips=[],
            servers=[],
            is_global=True,
            raw_data={"name": "Global", "type": "global"},
            updated_at=now,
        )


__all__ = [
    "DomainListRefreshTracker",
    "DomainService",
    "SYSTEM_DOMAIN_KEY",
    "parse_domain_dict",
]
