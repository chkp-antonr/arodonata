"""Shared session logger, target host/IP resolution, and MDS domain topology lookup helpers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from typing import Any, Protocol

import arlogi

from arodonata.adapters.checkpoint.rate_limiter import RateLimiter
from arodonata.adapters.checkpoint.response_classifiers import (
    is_session_expired_result,
    parse_domain_entry,
)
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings, ServerEndpointConfig
from arodonata.core.context import SYSTEM_DOMAIN_KEY, normalize_domain_key
from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.models.domains import DomainInfo
from arodonata.core.ports import DomainCachePort, SidCachePort

# Canonical logger shared across `sessions`, `session_cleaner`, and `target_resolver` so
# monkeypatching `arodonata.adapters.checkpoint.sessions.logger` intercepts all session logs.
logger = arlogi.get_logger("arodonata.adapters.checkpoint.sessions")


class TargetResolverCachePort(DomainCachePort, SidCachePort, Protocol):
    """Combined domain + SID cache port required by target/topology resolution."""


def _canonicalize_host(host: str) -> str:
    """Normalize an IP literal (IPv4/IPv6) or hostname into canonical lowercase string form."""
    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned.lower()


def _is_ip_literal(host: str) -> bool:
    """Return `True` if `host` is a valid IPv4 or IPv6 address literal."""
    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def resolve_tls_identity_host(raw_host: str | None, pinned_ip: str) -> str | None:
    """Return `raw_host` when it is a non-IP hostname that resolved to a different `pinned_ip`."""
    if not raw_host:
        return None
    cleaned = raw_host.strip()
    if not cleaned or cleaned == pinned_ip or _is_ip_literal(cleaned):
        return None
    return cleaned


async def _resolve_hostname_ips(host: str) -> set[str]:
    """Resolve a non-IP hostname to canonical IP strings (returning empty set on failure)."""
    if not host or _is_ip_literal(host):
        return set()
    resolved: set[str] = set()
    with suppress(Exception):
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host.strip(), None, type=socket.SOCK_STREAM)
        for info in infos:
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and sockaddr and isinstance(sockaddr[0], str):
                resolved.add(_canonicalize_host(sockaddr[0]))
    return resolved


def resolve_active_mds_ip_for_target(
    target_ip: str,
    default_mds_ip: str,
    cached_domains: Sequence[DomainInfo],
) -> str:
    """Resolve the active MDS member IP hosting `target_ip` from `cached_domains`."""
    canonical_target = _canonicalize_host(target_ip)
    for dom in cached_domains:
        dom_ips = [
            ip for ip in (dom.active_ip, dom.active_mds_ip, *dom.standby_ips) if isinstance(ip, str) and ip.strip()
        ]
        if any(_canonicalize_host(ip) == canonical_target for ip in dom_ips):
            if dom.active_mds_ip and dom.active_mds_ip.strip():
                return dom.active_mds_ip.strip()
            break
    return default_mds_ip


async def collect_trusted_hosts(
    *,
    cache: TargetResolverCachePort,
    known_mds_ips: set[str],
    active_dedicated_sids: Mapping[tuple[str, str], str],
    mgmt_name: str,
    endpoint_host: str,
) -> tuple[set[str], list[DomainInfo]]:
    """Collect canonicalized trusted host/IP strings and cached `DomainInfo` rows for `mgmt_name`."""
    trusted_ips: set[str] = {_canonicalize_host(endpoint_host)}
    for mds_ip in known_mds_ips:
        if mds_ip:
            trusted_ips.add(_canonicalize_host(mds_ip))
    cached_domains = await cache.get_domains(mgmt_name, include_global=True)
    for dom in cached_domains:
        if dom.active_ip:
            trusted_ips.add(_canonicalize_host(dom.active_ip))
        if dom.active_mds_ip:
            trusted_ips.add(_canonicalize_host(dom.active_mds_ip))
        for st_ip in dom.standby_ips:
            if st_ip:
                trusted_ips.add(_canonicalize_host(st_ip))
        for srv in dom.servers:
            if isinstance(srv, dict):
                for key in (
                    "ipv4-address",
                    "ipv6-address",
                    "ip",
                    "multi-domain-server-ip",
                ):
                    val = srv.get(key)
                    if isinstance(val, str) and val.strip():
                        trusted_ips.add(_canonicalize_host(val))
                mds_sub = srv.get("multi-domain-server")
                if isinstance(mds_sub, dict):
                    for key in ("ipv4-address", "ipv6-address", "ip"):
                        val = mds_sub.get(key)
                        if isinstance(val, str) and val.strip():
                            trusted_ips.add(_canonicalize_host(val))
    for entry in await cache.list_sids(mgmt_name=mgmt_name):
        if entry.server_ip:
            trusted_ips.add(_canonicalize_host(entry.server_ip))
    for (m_name, _sid), srv_ip in active_dedicated_sids.items():
        if m_name == mgmt_name and srv_ip:
            trusted_ips.add(_canonicalize_host(srv_ip))
    return trusted_ips, cached_domains


async def fetch_domain_topology_from_mds(
    *,
    mgmt_name: str,
    domain_name: str,
    endpoint: ServerEndpointConfig,
    transport: ApiTransport,
    cache: TargetResolverCachePort,
    rate_limiter: RateLimiter,
    settings: ArodonataSettings,
    known_mds_ips: set[str],
    get_readonly_session_fn: Callable[..., Awaitable[tuple[str, str]]],
    resolve_identity_fn: Callable[[], Awaitable[str | None]],
) -> DomainInfo | None:
    """Query the MDS system domain (`show-domains` / `show-global-domain` / `show-mdss`) to update `active_ip`."""
    try:
        sys_sid, sys_ip = await get_readonly_session_fn(
            mgmt_name,
            None,
            server_ip=endpoint.host,
        )
        async with rate_limiter.slot(endpoint.host):
            res = await transport.execute(
                sys_ip,
                "show-domains",
                {"details-level": "full", "limit": 500, "offset": 0},
                port=endpoint.port,
                sid=sys_sid,
                timeout=settings.api_timeout,
            )
        if is_session_expired_result(res):
            expired_identity = await resolve_identity_fn()
            await cache.evict_sid(mgmt_name, SYSTEM_DOMAIN_KEY, auth_identity=expired_identity)
            sys_sid, sys_ip = await get_readonly_session_fn(
                mgmt_name,
                None,
                server_ip=endpoint.host,
                force_new=True,
            )
            async with rate_limiter.slot(endpoint.host):
                res = await transport.execute(
                    sys_ip,
                    "show-domains",
                    {"details-level": "full", "limit": 500, "offset": 0},
                    port=endpoint.port,
                    sid=sys_sid,
                    timeout=settings.api_timeout,
                )
    except ServerIdentityError:
        raise
    except Exception:
        return None

    if not res.success:
        return None

    first_page_objs = res.data.get("objects")
    if not isinstance(first_page_objs, list):
        return None
    raw_domains: list[Any] = list(first_page_objs)
    total_domains = int(res.data.get("total") or len(raw_domains))
    page_offset = len(raw_domains)
    while page_offset < total_domains and len(first_page_objs) > 0:
        try:
            async with rate_limiter.slot(endpoint.host):
                page_res = await transport.execute(
                    sys_ip,
                    "show-domains",
                    {"details-level": "full", "limit": 500, "offset": page_offset},
                    port=endpoint.port,
                    sid=sys_sid,
                    timeout=settings.api_timeout,
                )
            if not page_res.success:
                break
            next_objs = page_res.data.get("objects")
            if not isinstance(next_objs, list) or not next_objs:
                break
            raw_domains.extend(next_objs)
            page_offset += len(next_objs)
        except ServerIdentityError:
            raise
        except Exception:
            break

    mds_ip_by_name: dict[str, str] = {}
    needs_mdss = domain_name == "Global" or any(
        isinstance(srv.get("multi-domain-server"), str)
        for item in raw_domains
        if isinstance(item, dict) and isinstance(item.get("servers"), list)
        for srv in item["servers"]
        if isinstance(srv, dict)
    )
    if needs_mdss:
        try:
            async with rate_limiter.slot(endpoint.host):
                mdss_res = await transport.execute(
                    sys_ip,
                    "show-mdss",
                    {"details-level": "full", "limit": 500},
                    port=endpoint.port,
                    sid=sys_sid,
                    timeout=settings.api_timeout,
                )
            if mdss_res.success and isinstance(mdss_res.data.get("objects"), list):
                for m_obj in mdss_res.data["objects"]:
                    if isinstance(m_obj, dict):
                        m_name = m_obj.get("name")
                        m_ip = (
                            m_obj.get("ipv4-address")
                            or m_obj.get("ip-address")
                            or m_obj.get("ipv6-address")
                            or m_obj.get("ip")
                        )
                        if isinstance(m_ip, str) and m_ip:
                            known_mds_ips.add(_canonicalize_host(m_ip))
                            if isinstance(m_name, str) and m_name:
                                mds_ip_by_name[m_name] = m_ip
        except ServerIdentityError:
            raise
        except Exception:
            pass

    parsed_domains: list[DomainInfo] = []
    matched: DomainInfo | None = None
    for item in raw_domains:
        if isinstance(item, dict) and item.get("name"):
            dom_info = parse_domain_entry(mgmt_name, item, mds_ip_by_name=mds_ip_by_name)
            if not dom_info.active_mds_ip:
                dom_info.active_mds_ip = endpoint.host
            parsed_domains.append(dom_info)
            if dom_info.name == domain_name:
                matched = dom_info

    if domain_name == "Global" and matched is None:
        try:
            async with rate_limiter.slot(endpoint.host):
                g_res = await transport.execute(
                    sys_ip,
                    "show-global-domain",
                    {"name": "Global", "details-level": "full"},
                    port=endpoint.port,
                    sid=sys_sid,
                    timeout=settings.api_timeout,
                )
            if g_res.success and isinstance(g_res.data, dict):
                g_raw = dict(g_res.data)
                g_raw.setdefault("name", "Global")
                g_raw["is_global"] = True
                g_info = parse_domain_entry(mgmt_name, g_raw, mds_ip_by_name=mds_ip_by_name)
                if not g_info.active_ip:
                    g_info.active_ip = endpoint.host
                if not g_info.active_mds_ip:
                    g_info.active_mds_ip = g_info.active_ip
                parsed_domains.append(g_info)
                matched = g_info
        except ServerIdentityError:
            raise
        except Exception:
            pass

    if parsed_domains:
        await cache.upsert_domains(parsed_domains)
    if matched is not None:
        logger.debug(
            f"Resolved active server for domain '{mgmt_name}:{domain_name}': "
            f"active_ip={matched.active_ip}, active_mds_ip={matched.active_mds_ip}.",
            mgmt_name=mgmt_name,
            domain=domain_name,
            active_ip=matched.active_ip,
            active_mds_ip=matched.active_mds_ip,
        )
    return matched


async def validate_explicit_server_ip(
    *,
    mgmt_name: str,
    domain: str | None,
    explicit_server_ip: str,
    endpoint: ServerEndpointConfig,
    collect_hosts_fn: Callable[[str, str], Awaitable[tuple[set[str], list[DomainInfo]]]],
    refresh_domain_fn: Callable[[str, str], Awaitable[DomainInfo | None]],
) -> tuple[str, str, int]:
    """Validate `explicit_server_ip` against trusted endpoints and return `(pinned_ip, mds_ip, port)`.

    Explicit hostnames are resolved and pinned to a trusted IP literal; hostnames that cannot be resolved fail
    closed with `ValidationError` before any connection is attempted.
    """
    cleaned_ip = explicit_server_ip.strip()
    canonical_ip = _canonicalize_host(cleaned_ip)
    trusted_ips, cached_domains = await collect_hosts_fn(mgmt_name, endpoint.host)

    if canonical_ip not in trusted_ips:
        dom_key = normalize_domain_key(domain)
        cached_names = {d.name for d in cached_domains}
        is_cold_or_missing_domain = not cached_domains or (dom_key != SYSTEM_DOMAIN_KEY and dom_key not in cached_names)
        if is_cold_or_missing_domain:
            await refresh_domain_fn(
                mgmt_name,
                dom_key if dom_key != SYSTEM_DOMAIN_KEY else "Global",
            )
            trusted_ips, _ = await collect_hosts_fn(mgmt_name, endpoint.host)

    if not _is_ip_literal(endpoint.host):
        endpoint_resolved = await _resolve_hostname_ips(endpoint.host)
        trusted_ips.update(endpoint_resolved)

    pinned_target: str | None = None
    if _is_ip_literal(cleaned_ip):
        if canonical_ip in trusted_ips:
            pinned_target = canonical_ip
    else:
        # Resolve explicit hostname and require EVERY returned A/AAAA record to be a subset of trusted_ips.
        explicit_resolved = await _resolve_hostname_ips(cleaned_ip)
        if explicit_resolved and explicit_resolved.issubset(trusted_ips):
            pinned_target = sorted(explicit_resolved)[0]
        # Unresolvable non-IP hostnames fail closed: forwarding a raw hostname would reintroduce connect-time DNS
        # resolution (TOCTOU), so `pinned_target` stays `None` and `ValidationError` is raised below.

    if pinned_target is None:
        raise ValidationError(
            f"Untrusted explicit server_ip {explicit_server_ip!r} for management server {mgmt_name!r}. "
            f"Known trusted hosts: {sorted(trusted_ips)}."
        )
    resolved_mds_ip = resolve_active_mds_ip_for_target(pinned_target, endpoint.host, cached_domains)
    return pinned_target, resolved_mds_ip, endpoint.port


async def resolve_failover_domain_ip(
    *,
    mgmt_name: str,
    dom_key: str,
    target_ip: str,
    require_change: bool,
    reason: str,
    refresh_domain_fn: Callable[[str, str], Awaitable[DomainInfo | None]],
) -> tuple[str, str] | None:
    """Re-query MDS for the domain's active IP and return `(active_ip, active_mds_ip)` if usable."""
    refreshed = await refresh_domain_fn(mgmt_name, dom_key)
    if refreshed is None or not refreshed.active_ip:
        return None
    if require_change and refreshed.active_ip == target_ip:
        return None
    if refreshed.active_ip != target_ip:
        logger.debug(
            f"Domain '{mgmt_name}:{dom_key}' active server {reason}: "
            f"{target_ip} -> {refreshed.active_ip}; retrying login.",
            mgmt_name=mgmt_name,
            domain=dom_key,
            old_ip=target_ip,
            active_ip=refreshed.active_ip,
            active_mds_ip=refreshed.active_mds_ip or refreshed.active_ip,
        )
    return refreshed.active_ip, refreshed.active_mds_ip or refreshed.active_ip


__all__ = [
    "TargetResolverCachePort",
    "_canonicalize_host",
    "_is_ip_literal",
    "_resolve_hostname_ips",
    "collect_trusted_hosts",
    "fetch_domain_topology_from_mds",
    "logger",
    "resolve_active_mds_ip_for_target",
    "resolve_failover_domain_ip",
    "validate_explicit_server_ip",
]
