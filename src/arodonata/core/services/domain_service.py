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
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ConfigurationError, DomainNotFoundError, ServerIdentityError
from arodonata.core.models.common import CacheMode, utc_now
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.ports import ApiPort, CachePort, LockPort
from arodonata.core.telemetry import span_attrs, traced

SYSTEM_DOMAIN_KEY = "System Data"


def parse_domain_dict(
    mgmt_name: str,
    raw: dict[str, Any],
    *,
    default_host: str | None = None,
    now_fn: Callable[[], datetime] = utc_now,
) -> DomainInfo:
    """Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` object into `DomainInfo`."""
    uid = str(raw.get("uid") or "")
    name = str(raw.get("name") or "")
    dom_type = str(raw.get("type") or raw.get("domain-type") or "domain")
    is_global = dom_type in ("global", "global-domain") or name == "Global" or bool(raw.get("is_global"))

    servers_raw = raw.get("servers")
    servers_list: list[dict[str, Any]] = (
        [s for s in servers_raw if isinstance(s, dict)] if isinstance(servers_raw, list) else []
    )

    active_ip: str | None = raw.get("active_ip") or raw.get("active-ip")
    active_mds_ip: str | None = raw.get("active_mds_ip") or raw.get("active-mds-ip")
    standby_ips: list[str] = []

    for srv in servers_list:
        srv_ip = srv.get("ipv4-address") or srv.get("ipv6-address") or srv.get("ip")
        mds_obj = srv.get("multi-domain-server")
        mds_ip: str | None = None
        if isinstance(mds_obj, dict):
            mds_ip = mds_obj.get("ipv4-address") or mds_obj.get("ipv6-address") or mds_obj.get("ip")
        elif isinstance(srv.get("multi-domain-server-ip"), str):
            mds_ip = srv.get("multi-domain-server-ip")

        is_active = bool(srv.get("active"))
        if is_active:
            if isinstance(srv_ip, str) and srv_ip:
                active_ip = srv_ip
            if isinstance(mds_ip, str) and mds_ip:
                active_mds_ip = mds_ip
        elif isinstance(srv_ip, str) and srv_ip:
            standby_ips.append(srv_ip)

    if active_ip is None and servers_list:
        first_srv = servers_list[0]
        first_ip = first_srv.get("ipv4-address") or first_srv.get("ipv6-address") or first_srv.get("ip")
        if isinstance(first_ip, str) and first_ip:
            active_ip = first_ip
        first_mds = first_srv.get("multi-domain-server")
        if active_mds_ip is None and isinstance(first_mds, dict):
            mds_candidate = first_mds.get("ipv4-address") or first_mds.get("ip")
            if isinstance(mds_candidate, str) and mds_candidate:
                active_mds_ip = mds_candidate

    if active_ip is None and default_host:
        active_ip = default_host
    if active_mds_ip is None:
        active_mds_ip = active_ip or default_host

    return DomainInfo(
        id=f"{mgmt_name}:{name}",
        mgmt_name=mgmt_name,
        uid=uid or f"domain:{mgmt_name}:{name}",
        name=name,
        domain_type="global" if is_global else dom_type,
        active_ip=active_ip,
        active_mds_ip=active_mds_ip,
        standby_ips=standby_ips,
        servers=servers_list,
        is_global=is_global,
        raw_data=dict(raw),
        updated_at=now_fn(),
    )


class DomainListRefreshTracker:
    """Tracks per-server domain list freshness against the 1-hour (`domain_list_ttl`) TTL."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._ttl_seconds = float(ttl_seconds)
        self._now = now_fn
        self._last_refreshed_at: dict[str, datetime] = {}
        self._invalidated_servers: set[str] = set()

    @property
    def ttl_seconds(self) -> float:
        """Configured domain list TTL in seconds (default 3600s / 1 hour)."""
        return self._ttl_seconds

    def mark_refreshed(self, mgmt_name: str, refreshed_at: datetime | None = None) -> datetime:
        """Record that `mgmt_name`'s domain list was refreshed at `refreshed_at`."""
        ts = refreshed_at if refreshed_at is not None else self._now()
        self._last_refreshed_at[mgmt_name] = ts
        self._invalidated_servers.discard(mgmt_name)
        return ts

    def invalidate(self, mgmt_name: str | None = None) -> None:
        """Invalidate the domain list TTL memo for `mgmt_name` (or all servers if `None`)."""
        if mgmt_name is None:
            self._last_refreshed_at.clear()
            self._invalidated_servers.clear()
        else:
            self._last_refreshed_at.pop(mgmt_name, None)
            self._invalidated_servers.add(mgmt_name)

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
        ref_time = self._last_refreshed_at.get(mgmt_name) or persisted_synced_at
        if ref_time is None:
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
        cache: CachePort,
        lock_port: LockPort | None = None,
        tracker: DomainListRefreshTracker | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._lock_port = lock_port
        self._now = now_fn
        self._tracker = tracker or DomainListRefreshTracker(
            ttl_seconds=float(settings.domain_list_ttl),
            now_fn=now_fn,
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
                async with self._lock_port.lock(lock_key, ttl_seconds=60.0):
                    await self._discover_server_domains(mgmt_name)
            else:
                await self._discover_server_domains(mgmt_name)

    async def _discover_server_domains(self, mgmt_name: str) -> list[DomainInfo]:
        """Execute `show-domains` and `show-global-domain` on `mgmt_name` and persist results."""
        servers = self._settings.servers
        endpoint = servers.get(mgmt_name)
        default_host = endpoint.host if endpoint is not None else None
        now = self._now()

        res = await self._api.api_call(
            mgmt_name,
            "show-domains",
            {"details-level": "full", "limit": 500},
            domain=None,
        )

        discovered: list[DomainInfo] = []

        if res.success:
            raw_objs = res.data.get("objects")
            if isinstance(raw_objs, list) and raw_objs:
                for raw in raw_objs:
                    if isinstance(raw, dict) and raw.get("name"):
                        dom = parse_domain_dict(
                            mgmt_name,
                            raw,
                            default_host=default_host,
                            now_fn=self._now,
                        )
                        discovered.append(dom)

        # If show-domains succeeded with no objects, or failed because server is single-domain SmartCenter,
        # synthesize the default single-domain entry if no user domains were returned.
        if not discovered and not res.success:
            err_lower = (res.error_message or "").lower()
            code_lower = (res.error_code or "").lower()
            is_single_domain_unsupported = any(
                tok in err_lower or tok in code_lower
                for tok in (
                    "command_not_found",
                    "not supported on non-mds",
                    "multi-domain",
                    "unknown command",
                )
            )
            if not is_single_domain_unsupported:
                # Record failure in domain_sync_state and return existing cached domains
                await self._cache.upsert_sync_state(
                    DomainSyncState(
                        mgmt_name=mgmt_name,
                        domain_name=SYSTEM_DOMAIN_KEY,
                        scope="domains",
                        item_type="*",
                        synced_at=now,
                        status="failed",
                        last_error=res.error_message or f"HTTP {res.status_code}",
                    )
                )
                return await self._cache.get_domains(mgmt_name, include_global=True)

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
            global_dom = await self._fetch_or_synthesize_global_domain(mgmt_name, default_host=default_host)
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
        return discovered

    async def _fetch_or_synthesize_global_domain(
        self,
        mgmt_name: str,
        *,
        default_host: str | None = None,
    ) -> DomainInfo:
        """Query `show-global-domain` or synthesize a canonical `Global` `DomainInfo` row."""
        now = self._now()
        try:
            res = await self._api.api_call(
                mgmt_name,
                "show-global-domain",
                {"name": "Global", "details-level": "full"},
                domain=None,
            )
            if res.success and isinstance(res.data, dict) and res.data.get("uid"):
                raw = dict(res.data)
                raw.setdefault("name", "Global")
                raw["is_global"] = True
                dom = parse_domain_dict(
                    mgmt_name,
                    raw,
                    default_host=default_host,
                    now_fn=self._now,
                )
                return dom.model_copy(update={"name": "Global", "is_global": True, "domain_type": "global"})
        except ServerIdentityError:
            raise
        except Exception:
            pass

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
