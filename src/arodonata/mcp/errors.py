"""MCP tool error handling, domain pre-validation, `InvalidCredentialsError` mapping, and SID masking."""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import arlogi
from mcp.types import CallToolResult, TextContent

from arodonata.client import ArodonataClient
from arodonata.core.errors import (
    AmbiguousLayerName,
    ArodonataError,
    ChangeReportInputError,
    ConfigurationError,
    DomainNotFoundError,
    InvalidCredentialsError,
    UnsupportedFormat,
    ValidationError,
    redact_sid,
    sanitize_mapping,
)

logger = arlogi.get_logger(__name__)


async def collect_known_sids(
    client: ArodonataClient,
    mgmt_name: str | None = None,
) -> list[str]:
    """Collect active session tokens from the SID cache and transport adapter for redaction."""
    sids: list[str] = []
    try:
        cached = await client.cache.list_sids(mgmt_name=mgmt_name)
        for entry in cached:
            if entry.sid and entry.sid not in sids:
                sids.append(entry.sid)
    except Exception:
        pass

    api_obj = getattr(client, "_api", None)
    if api_obj is not None:
        active_set = getattr(api_obj, "_active_dedicated_sids", None)
        if isinstance(active_set, (set, list, tuple)):
            for item in active_set:
                sid_val = item[1] if isinstance(item, tuple) and len(item) >= 2 else item
                if isinstance(sid_val, str) and sid_val and sid_val not in sids:
                    sids.append(sid_val)
    return sids


class ToolFailure(ArodonataError):
    """Actionable model-facing tool error logged at WARNING without arguments or secrets."""

    def __init__(
        self,
        message: str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        known_sids: Iterable[str] | None = None,
    ) -> None:
        super().__init__(message, known_sids=known_sids)
        self.mgmt_name = mgmt_name
        self.domain = domain


def resolve_mgmt_name(client: ArodonataClient, mgmt_name: str | None = None) -> str:
    """Resolve `mgmt_name`, defaulting to the single configured server or first server in `settings`."""
    if mgmt_name is not None and mgmt_name.strip():
        clean = mgmt_name.strip()
        if client.settings.mgmt_names and clean not in client.settings.mgmt_names:
            known = ", ".join(client.settings.mgmt_names)
            raise ToolFailure(
                f"Unknown management server {clean!r}. Configured servers: {known}.",
                mgmt_name=clean,
            )
        return clean

    if client.settings.mgmt_names:
        return client.settings.mgmt_names[0]
    if client.settings.mgmt_name:
        return client.settings.mgmt_name
    return "default"


async def get_known_domain_names(
    client: ArodonataClient,
    mgmt_name: str,
    *,
    refresh_if_empty: bool = False,
) -> list[str]:
    """Return sorted known domain names for `mgmt_name` from the `domains` cache table."""
    cached = await client.cache.get_domains(mgmt_name=mgmt_name, include_global=True)
    if not cached and refresh_if_empty:
        try:
            refreshed = await client.get_domains(
                mgmt_name=mgmt_name,
                include_global=True,
                cache_mode="force",
            )
            cached = refreshed
        except InvalidCredentialsError:
            raise
        except Exception:
            cached = await client.cache.get_domains(mgmt_name=mgmt_name, include_global=True)

    names: list[str] = []
    for d in cached:
        if d.name not in names:
            names.append(d.name)
    return names


async def validate_domain_or_fail(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str | None,
) -> str | None:
    """Pre-validate `domain` against the cached `domains` table before attempting a domain login.

    If `domain` is not present in the cached `domains` table, performs a single domain-list
    refresh (`client.get_domains(..., cache_mode="force")`). If still not present and the
    server has known domains, raises an actionable `ToolFailure` listing known domains.
    """
    if domain is None or not domain.strip():
        return None

    clean_domain = domain.strip()
    if clean_domain == "System Data":
        return clean_domain

    # 1. Check cached `domains` table without network round-trip
    cached_domains = await client.cache.get_domains(mgmt_name=mgmt_name, include_global=True)
    cached_names = {d.name for d in cached_domains}
    if clean_domain in cached_names:
        return clean_domain

    # 2. Perform at most a single domain-list refresh on a miss
    try:
        refreshed_domains = await client.get_domains(
            mgmt_name=mgmt_name,
            include_global=True,
            cache_mode="force",
        )
    except InvalidCredentialsError as exc:
        known = sorted(cached_names)
        known_sids = await collect_known_sids(client, mgmt_name)
        raise format_invalid_credentials_failure(
            mgmt_name=mgmt_name,
            domain=clean_domain,
            known_domains=known,
            exc=exc,
            known_sids=known_sids,
        ) from exc
    except Exception:
        refreshed_domains = await client.cache.get_domains(mgmt_name=mgmt_name, include_global=True)

    refreshed_names = [d.name for d in refreshed_domains]
    if clean_domain in refreshed_names:
        return clean_domain

    if refreshed_names:
        known_str = ", ".join(refreshed_names)
        raise ToolFailure(
            f"Unknown domain {clean_domain!r} on management server {mgmt_name!r}. "
            f"Known domains on {mgmt_name!r}: {known_str}.",
            mgmt_name=mgmt_name,
            domain=clean_domain,
        )

    return clean_domain


def format_invalid_credentials_failure(
    *,
    mgmt_name: str,
    domain: str | None,
    known_domains: Iterable[str],
    exc: InvalidCredentialsError | None = None,
    known_sids: Iterable[str] | None = None,
) -> ToolFailure:
    """Build an actionable model-facing `ToolFailure` for `InvalidCredentialsError`."""
    known_list = list(known_domains)
    known_part = (
        f"Known domains on {mgmt_name!r}: {', '.join(known_list)}."
        if known_list
        else f"No cached domains recorded yet on {mgmt_name!r} (call show_domains first)."
    )
    dom_part = f" for domain {domain!r}" if domain else ""
    detail_part = f" ({redact_sid(str(exc), known_sids=known_sids)})" if exc and str(exc) else ""
    return ToolFailure(
        f"Authentication rejected on management server {mgmt_name!r}{dom_part}{detail_part}. "
        f"Verify target domain name and credentials. {known_part}",
        mgmt_name=mgmt_name,
        domain=domain,
        known_sids=known_sids,
    )


def json_tool_result(
    payload: dict[str, Any] | list[Any] | str,
    *,
    is_error: bool = False,
    known_sids: Iterable[str] | None = None,
) -> CallToolResult:
    """Serialize `payload` into a sanitized MCP `CallToolResult`."""
    if isinstance(payload, str):
        text = redact_sid(payload, known_sids=known_sids)
    elif isinstance(payload, dict):
        clean_dict = sanitize_mapping(payload, known_sids=known_sids)
        text = json.dumps(clean_dict, ensure_ascii=False, default=str)
    else:
        raw_text = json.dumps(payload, ensure_ascii=False, default=str)
        text = redact_sid(raw_text, known_sids=known_sids)
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        is_error=is_error,
    )


def mcp_tool_guard(
    tool_name: str,
    client_getter: Callable[[], ArodonataClient],
) -> Callable[[Callable[..., Awaitable[CallToolResult]]], Callable[..., Awaitable[CallToolResult]]]:
    """Wrap an async MCP tool function with `ToolFailure` WARNING logging, `InvalidCredentialsError`
    translation, SID masking, and `"internal error: <ExceptionClass>"` crash protection.

    Never logs tool arguments or secrets.
    """

    def decorator(
        fn: Callable[..., Awaitable[CallToolResult]],
    ) -> Callable[..., Awaitable[CallToolResult]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> CallToolResult:
            mgmt_arg = kwargs.get("mgmt_name") if isinstance(kwargs.get("mgmt_name"), str) else None
            domain_arg = (
                kwargs.get("domain")
                if isinstance(kwargs.get("domain"), str)
                else (kwargs.get("domain_name") if isinstance(kwargs.get("domain_name"), str) else None)
            )
            try:
                return await fn(*args, **kwargs)
            except ToolFailure as tf:
                eff_mgmt = tf.mgmt_name or mgmt_arg
                eff_dom = tf.domain or domain_arg
                try:
                    known_sids = await collect_known_sids(client_getter(), eff_mgmt)
                except Exception:
                    known_sids = []
                sanitized_reason = redact_sid(tf.message, known_sids=known_sids)
                logger.warning(
                    "MCP ToolFailure",
                    tool=tool_name,
                    mgmt_name=eff_mgmt,
                    domain=eff_dom,
                    error=sanitized_reason,
                )
                return CallToolResult(
                    content=[TextContent(type="text", text=sanitized_reason)],
                    is_error=True,
                )
            except InvalidCredentialsError as cred_exc:
                client = client_getter()
                eff_mgmt = (
                    resolve_mgmt_name(client, mgmt_arg)
                    if mgmt_arg
                    else (client.settings.mgmt_names[0] if client.settings.mgmt_names else "default")
                )
                known = await get_known_domain_names(client, eff_mgmt, refresh_if_empty=False)
                known_sids = await collect_known_sids(client, eff_mgmt)
                cred_failure = format_invalid_credentials_failure(
                    mgmt_name=eff_mgmt,
                    domain=domain_arg,
                    known_domains=known,
                    exc=cred_exc,
                    known_sids=known_sids,
                )
                logger.warning(
                    "MCP ToolFailure",
                    tool=tool_name,
                    mgmt_name=eff_mgmt,
                    domain=domain_arg,
                    error=cred_failure.message,
                )
                return CallToolResult(
                    content=[TextContent(type="text", text=cred_failure.message)],
                    is_error=True,
                )
            except (
                DomainNotFoundError,
                AmbiguousLayerName,
                ChangeReportInputError,
                UnsupportedFormat,
                ConfigurationError,
                ValidationError,
            ) as dom_exc:
                client = client_getter()
                eff_mgmt = mgmt_arg or (client.settings.mgmt_names[0] if client.settings.mgmt_names else "default")
                known = await get_known_domain_names(client, eff_mgmt, refresh_if_empty=False)
                known_sids = await collect_known_sids(client, eff_mgmt)
                extra_known = f" Known domains on {eff_mgmt!r}: {', '.join(known)}." if known else ""
                msg = redact_sid(f"{dom_exc}{extra_known}", known_sids=known_sids)
                logger.warning(
                    "MCP ToolFailure",
                    tool=tool_name,
                    mgmt_name=eff_mgmt,
                    domain=domain_arg,
                    error=msg,
                )
                return CallToolResult(
                    content=[TextContent(type="text", text=msg)],
                    is_error=True,
                )
            except Exception as exc:
                exc_class = type(exc).__name__
                try:
                    known_sids = await collect_known_sids(client_getter(), mgmt_arg)
                except Exception:
                    known_sids = []
                logger.error(
                    "MCP tool internal error",
                    tool=tool_name,
                    exception_class=exc_class,
                    detail=redact_sid(str(exc), known_sids=known_sids),
                )
                return CallToolResult(
                    content=[TextContent(type="text", text=f"internal error: {exc_class}")],
                    is_error=True,
                )

        return wrapper

    return decorator


__all__ = [
    "ToolFailure",
    "collect_known_sids",
    "format_invalid_credentials_failure",
    "get_known_domain_names",
    "json_tool_result",
    "mcp_tool_guard",
    "resolve_mgmt_name",
    "validate_domain_or_fail",
]
