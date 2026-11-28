"""Canonical bounded MDS domain discovery helper (`arodonata.core.services._domain_discovery`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import arlogi

from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.models.common import ApiCallResult, utc_now
from arodonata.core.models.domains import (
    DomainInfo,
    is_rbac_or_details_level_rejected,
    parse_domain_entry,
)

logger = arlogi.get_logger(__name__)

MAX_SHOW_DOMAINS_PAGES = 200

_SINGLE_DOMAIN_UNSUPPORTED_TOKENS: tuple[str, ...] = (
    "command_not_found",
    "not supported on non-mds",
    "multi-domain",
    "unknown command",
)


def is_single_domain_unsupported(res: ApiCallResult) -> bool:
    """Return `True` if `show-domains` failed because the server is a single-domain SmartCenter."""
    err_lower = (res.error_message or "").lower()
    code_lower = (res.error_code or "").lower()
    return any(tok in err_lower or tok in code_lower for tok in _SINGLE_DOMAIN_UNSUPPORTED_TOKENS)


def coerce_total_domains(raw_total: Any, fallback: int) -> int:
    """Safely parse server-reported `total` domain count without throwing on malformed payloads."""
    if raw_total is None or isinstance(raw_total, bool):
        return fallback
    try:
        parsed = int(raw_total)
    except (TypeError, ValueError):
        return fallback
    return max(fallback, parsed) if parsed > 0 else fallback


@dataclass(frozen=True, slots=True)
class MdsDiscoveryResult:
    """Structured result returned by `discover_mds_domains`."""

    res: ApiCallResult
    fallback_failed_res: ApiCallResult | None
    is_single_domain: bool
    saw_objects_list: bool
    domains: list[DomainInfo]
    mds_ip_by_name: dict[str, str]


async def fetch_mds_ip_map(
    execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]],
    *,
    on_mds_ip: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Query `show-mdss` on the system domain to map MDS member names to IP addresses."""
    try:
        res = await execute_cmd("show-mdss", {"details-level": "full", "limit": 500})
        if res.success and isinstance(res.data.get("objects"), list):
            result: dict[str, str] = {}
            for obj in res.data["objects"]:
                if not isinstance(obj, dict):
                    continue
                m_name = obj.get("name")
                m_ip = obj.get("ipv4-address") or obj.get("ip-address") or obj.get("ipv6-address") or obj.get("ip")
                if isinstance(m_ip, str) and m_ip:
                    if on_mds_ip is not None:
                        on_mds_ip(m_ip)
                    if isinstance(m_name, str) and m_name:
                        result[m_name] = m_ip
            return result
    except ServerIdentityError:
        raise
    except Exception:
        pass
    return {}


async def fetch_global_domain_entry(
    mgmt_name: str,
    execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]],
    *,
    default_host: str | None = None,
    mds_ip_by_name: dict[str, str] | None = None,
    now_fn: Callable[[], datetime] = utc_now,
    require_uid: bool = True,
    fallback_uid: bool = False,
) -> DomainInfo | None:
    """Query `show-global-domain` and parse it into a normalized `Global` `DomainInfo` row."""
    try:
        res = await execute_cmd("show-global-domain", {"name": "Global", "details-level": "full"})
        if res.success and isinstance(res.data, dict) and (not require_uid or res.data.get("uid")):
            raw = dict(res.data)
            raw.setdefault("name", "Global")
            raw["is_global"] = True
            dom = parse_domain_entry(
                mgmt_name,
                raw,
                default_host=default_host,
                mds_ip_by_name=mds_ip_by_name,
                now_fn=now_fn,
                fallback_uid=fallback_uid,
            )
            return dom.model_copy(
                update={
                    "name": "Global",
                    "is_global": True,
                    "domain_type": "global",
                }
            )
    except ServerIdentityError:
        raise
    except Exception:
        pass
    return None


def _preserve_cached_cma_fields(dom: DomainInfo, prev_dom: DomainInfo | None) -> DomainInfo:
    """Preserve cached CMA active/standby IPs when `details-level=standard` returns no `servers`."""
    if not dom.servers and prev_dom is not None and (prev_dom.servers or prev_dom.active_ip):
        return dom.model_copy(
            update={
                "active_ip": prev_dom.active_ip or dom.active_ip,
                "active_mds_ip": prev_dom.active_mds_ip or dom.active_mds_ip,
                "standby_ips": list(prev_dom.standby_ips) if prev_dom.standby_ips else dom.standby_ips,
                "servers": list(prev_dom.servers) if prev_dom.servers else dom.servers,
            }
        )
    return dom


async def discover_mds_domains(
    mgmt_name: str,
    execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]],
    *,
    existing_domains: Sequence[DomainInfo],
    default_host: str | None = None,
    use_default_host_on_parse: bool = True,
    fallback_uid: bool = False,
    need_mdss_for_global: bool = False,
    now_fn: Callable[[], datetime] = utc_now,
    on_mds_ip: Callable[[str], None] | None = None,
    log: Any = logger,
) -> MdsDiscoveryResult:
    """Execute bounded `show-domains` (with RBAC fallback) and `show-mdss` discovery."""
    existing_by_name: dict[str, DomainInfo] = {d.name: d for d in existing_domains}

    transport_or_auth_failed = False
    try:
        res = await execute_cmd("show-domains", {"details-level": "full", "limit": 500, "offset": 0})
    except ServerIdentityError:
        raise
    except Exception as exc:
        transport_or_auth_failed = True
        res = ApiCallResult(
            success=False,
            status_code=0,
            error_code=type(exc).__name__,
            error_message=redact_sid(str(exc)),
        )

    details_level = "full"
    is_single_domain = False
    fallback_failed_res: ApiCallResult | None = None

    if not res.success:
        is_single_domain = is_single_domain_unsupported(res)
        if not is_single_domain and not transport_or_auth_failed and is_rbac_or_details_level_rejected(res):
            safe_err = redact_sid(res.error_message or "")
            log.warning(
                f"show-domains (details-level=full) on '{mgmt_name}' rejected "
                f"({res.error_code or res.status_code}: {safe_err}); retrying with details-level=standard.",
                mgmt_name=mgmt_name,
                error_code=res.error_code or str(res.status_code),
                error_message=safe_err,
            )
            try:
                fb_res = await execute_cmd("show-domains", {"details-level": "standard", "limit": 500, "offset": 0})
            except ServerIdentityError:
                raise
            except Exception as exc:
                fb_res = ApiCallResult(
                    success=False,
                    status_code=0,
                    error_code=type(exc).__name__,
                    error_message=redact_sid(str(exc)),
                )
            if fb_res.success:
                res = fb_res
                details_level = "standard"
            else:
                fallback_failed_res = fb_res
                if is_single_domain_unsupported(fb_res):
                    is_single_domain = True

    discovered: list[DomainInfo] = []
    mds_ip_by_name: dict[str, str] = {}
    saw_objects_list = False

    if res.success:
        first_page = res.data.get("objects")
        saw_objects_list = isinstance(first_page, list)
        raw_objs: list[Any] = list(first_page) if isinstance(first_page, list) else []
        seen_domain_keys: set[tuple[str, str]] = {
            (str(item.get("uid") or ""), str(item.get("name") or ""))
            for item in raw_objs
            if isinstance(item, dict) and (item.get("uid") or item.get("name"))
        }
        total_domains = coerce_total_domains(res.data.get("total"), len(raw_objs))
        page_offset = len(raw_objs)
        page_count = 0

        while page_offset < total_domains and isinstance(first_page, list) and len(first_page) > 0:
            if page_count >= MAX_SHOW_DOMAINS_PAGES:
                log.warning(
                    f"Reached max show-domains page ceiling ({MAX_SHOW_DOMAINS_PAGES}) on '{mgmt_name}'; stopping pagination.",
                    mgmt_name=mgmt_name,
                    offset=page_offset,
                    total=total_domains,
                )
                break
            page_count += 1
            try:
                page_res = await execute_cmd(
                    "show-domains",
                    {"details-level": details_level, "limit": 500, "offset": page_offset},
                )
            except ServerIdentityError:
                raise
            except Exception as exc:
                safe_exc = redact_sid(str(exc))
                log.warning(
                    f"Pagination of show-domains on '{mgmt_name}' interrupted at offset {page_offset}: {safe_exc}",
                    mgmt_name=mgmt_name,
                    offset=page_offset,
                    error=safe_exc,
                )
                break
            if not page_res.success:
                break
            next_objs = page_res.data.get("objects")
            if not isinstance(next_objs, list) or not next_objs:
                break
            new_unique = 0
            for item in next_objs:
                if isinstance(item, dict) and (item.get("uid") or item.get("name")):
                    dkey = (str(item.get("uid") or ""), str(item.get("name") or ""))
                    if dkey not in seen_domain_keys:
                        seen_domain_keys.add(dkey)
                        new_unique += 1
                else:
                    new_unique += 1
            if new_unique == 0:
                log.warning(
                    f"Pagination of show-domains on '{mgmt_name}' returned no new unique domains at offset {page_offset}; stopping.",
                    mgmt_name=mgmt_name,
                    offset=page_offset,
                )
                break
            raw_objs.extend(next_objs)
            page_offset += len(next_objs)

        needs_mdss = need_mdss_for_global or any(
            isinstance(srv.get("multi-domain-server"), str)
            for raw in raw_objs
            if isinstance(raw, dict) and isinstance(raw.get("servers"), list)
            for srv in raw["servers"]
            if isinstance(srv, dict)
        )
        if needs_mdss:
            mds_ip_by_name = await fetch_mds_ip_map(execute_cmd, on_mds_ip=on_mds_ip)

        parse_default_host = default_host if use_default_host_on_parse else None
        for raw in raw_objs:
            if isinstance(raw, dict) and raw.get("name"):
                dom = parse_domain_entry(
                    mgmt_name,
                    raw,
                    default_host=parse_default_host,
                    mds_ip_by_name=mds_ip_by_name,
                    now_fn=now_fn,
                    fallback_uid=fallback_uid,
                )
                dom = _preserve_cached_cma_fields(dom, existing_by_name.get(dom.name))
                if not use_default_host_on_parse and not dom.active_mds_ip and default_host:
                    dom.active_mds_ip = default_host
                discovered.append(dom)

    return MdsDiscoveryResult(
        res=res,
        fallback_failed_res=fallback_failed_res,
        is_single_domain=is_single_domain,
        saw_objects_list=saw_objects_list,
        domains=discovered,
        mds_ip_by_name=mds_ip_by_name,
    )
