"""MCP tool error handling, domain pre-validation, `InvalidCredentialsError` mapping, and SID masking."""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable, Iterable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import arlogi
from mcp.types import CallToolResult, TextContent

from arodonata.client import ArodonataClient
from arodonata.core.context import get_user_context
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
from arodonata.core.telemetry import span_attrs
from arodonata.mcp.quota import MCPToolQuotaManager, QuotaDecision

logger = arlogi.get_logger(__name__)


async def collect_known_sids(
    client: ArodonataClient | None,
    mgmt_name: str | None = None,
) -> list[str]:
    """Collect active session tokens from the SID cache and public client dedicated-SID registry."""
    if client is None:
        return []
    sids: list[str] = []
    try:
        cached = await client.cache.list_sids(mgmt_name=mgmt_name)
        for entry in cached:
            if entry.sid and entry.sid not in sids:
                sids.append(entry.sid)
    except Exception:
        pass

    get_dedicated = getattr(client, "get_active_dedicated_sids", None)
    if callable(get_dedicated):
        try:
            for sid_val in get_dedicated(mgmt_name=mgmt_name):
                if isinstance(sid_val, str) and sid_val and sid_val not in sids:
                    sids.append(sid_val)
        except Exception:
            pass
    return sids


class ToolFailure(ArodonataError):
    """Actionable model-facing tool error logged at WARNING without arguments or secrets."""

    def __init__(
        self,
        message: str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
        known_sids: Iterable[str] | None = None,
    ) -> None:
        super().__init__(message, known_sids=known_sids)
        self.mgmt_name = mgmt_name
        self.domain = domain
        self.error_code = error_code
        self.details = dict(details) if details is not None else None


@dataclass(slots=True)
class _ActiveQuotaState:
    """Per-invocation quota context for deferred live-sync charging inside an MCP tool call."""

    quota_manager: MCPToolQuotaManager
    client_id: str
    tool_name: str
    live_consumed: bool = False


_ACTIVE_MCP_QUOTA_STATE: ContextVar[_ActiveQuotaState | None] = ContextVar(
    "arodonata_active_mcp_quota_state",
    default=None,
)


def resolve_mcp_caller_id() -> str:
    """Resolve the active MCP caller identity (`client_id[:user_id]`) from `UserContext`, or `'anonymous'`."""
    ctx = get_user_context()
    if ctx is not None:
        cid = ctx.client_id.strip() if isinstance(ctx.client_id, str) and ctx.client_id.strip() else None
        uid = ctx.user_id.strip() if isinstance(ctx.user_id, str) and ctx.user_id.strip() else None
        if cid and uid:
            return cid if cid == uid else f"{cid}:{uid}"
        if cid:
            return cid
        if uid:
            return uid
    return "anonymous"


_resolve_mcp_client_id = resolve_mcp_caller_id


def _emit_rate_limit_failure(tool_name: str, client_id: str, decision: QuotaDecision) -> ToolFailure:
    """Record rate-limit telemetry/audit warning and construct a structured `ToolFailure`."""
    span_attrs(
        mcp_rate_limited=True,
        mcp_client_id=client_id,
        mcp_tool=tool_name,
        mcp_quota_bucket=decision.bucket,
    )
    logger.warning(
        "MCP tool rate limit exceeded",
        tool=tool_name,
        client_id=client_id,
        bucket=decision.bucket,
        limit=decision.limit,
        retry_after_seconds=decision.retry_after_seconds,
    )
    return ToolFailure(
        f"Rate limit exceeded for MCP tool {tool_name!r} "
        f"(bucket={decision.bucket}, limit={decision.limit}/min). "
        f"Retry after {decision.retry_after_seconds}s.",
        error_code="rate_limit_exceeded",
        details={
            "client_id": client_id,
            "bucket": decision.bucket,
            "limit_per_minute": decision.limit,
            "retry_after_seconds": decision.retry_after_seconds,
        },
    )


def consume_live_quota_if_needed() -> None:
    """Consume a `live` quota slot for the active guarded tool call when remote sync is required."""
    state = _ACTIVE_MCP_QUOTA_STATE.get()
    if state is None or state.live_consumed:
        return
    decision = state.quota_manager.check_and_consume_live_only(state.client_id)
    if not decision.allowed:
        raise _emit_rate_limit_failure(state.tool_name, state.client_id, decision)
    state.live_consumed = True


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
    consume_live_quota_if_needed()
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


def _format_structured_tool_failure(
    tf: ToolFailure,
    *,
    tool_name: str,
    sanitized_reason: str,
) -> dict[str, Any]:
    """Build structured `ToolFailure` JSON payload where core envelope keys cannot be overridden by `details`."""
    payload: dict[str, Any] = dict(tf.details) if tf.details else {}
    payload.update(
        {
            "error": "ToolFailure",
            "error_code": tf.error_code,
            "message": sanitized_reason,
            "tool": tool_name,
        }
    )
    return payload


def mcp_tool_guard(
    tool_name: str,
    client_getter: Callable[[], ArodonataClient],
    *,
    quota_manager: MCPToolQuotaManager | None = None,
    is_live_tool: bool | Callable[[dict[str, Any]], bool] = False,
) -> Callable[[Callable[..., Awaitable[CallToolResult]]], Callable[..., Awaitable[CallToolResult]]]:
    """Wrap an async MCP tool function with per-client rate limiting, `ToolFailure` WARNING logging,
    `InvalidCredentialsError` translation, SID masking, and `"internal error: <ExceptionClass>"` crash protection.

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
            quota_token: Any = None
            try:
                if quota_manager is not None:
                    client_id = redact_sid(resolve_mcp_caller_id())
                    is_live = is_live_tool(kwargs) if callable(is_live_tool) else bool(is_live_tool)
                    decision = quota_manager.check_and_consume(client_id, is_live=is_live)
                    if not decision.allowed:
                        raise _emit_rate_limit_failure(tool_name, client_id, decision)
                    quota_token = _ACTIVE_MCP_QUOTA_STATE.set(
                        _ActiveQuotaState(
                            quota_manager=quota_manager,
                            client_id=client_id,
                            tool_name=tool_name,
                            live_consumed=is_live,
                        )
                    )
                try:
                    return await fn(*args, **kwargs)
                finally:
                    if quota_token is not None:
                        _ACTIVE_MCP_QUOTA_STATE.reset(quota_token)
            except ToolFailure as tf:
                eff_mgmt = tf.mgmt_name or mgmt_arg
                eff_dom = tf.domain or domain_arg
                try:
                    known_sids = await collect_known_sids(client_getter(), eff_mgmt)
                except Exception:
                    known_sids = []
                sanitized_reason = redact_sid(tf.message, known_sids=known_sids)
                if tf.error_code != "rate_limit_exceeded":
                    logger.warning(
                        "MCP ToolFailure",
                        tool=tool_name,
                        mgmt_name=eff_mgmt,
                        domain=eff_dom,
                        error=sanitized_reason,
                    )
                if tf.error_code is not None:
                    err_payload = _format_structured_tool_failure(
                        tf, tool_name=tool_name, sanitized_reason=sanitized_reason
                    )
                    return json_tool_result(err_payload, is_error=True, known_sids=known_sids)
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
    "consume_live_quota_if_needed",
    "format_invalid_credentials_failure",
    "get_known_domain_names",
    "json_tool_result",
    "mcp_tool_guard",
    "resolve_mcp_caller_id",
    "resolve_mgmt_name",
    "validate_domain_or_fail",
]
