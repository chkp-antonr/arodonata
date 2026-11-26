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


_ACTIVE_MCP_EXTRA_SIDS: ContextVar[set[str] | None] = ContextVar(
    "arodonata_active_mcp_extra_sids",
    default=None,
)


def register_active_mcp_sid(sid: str | None) -> None:
    """Register a session identifier created during the current MCP tool call for guaranteed redaction."""
    sids = _ACTIVE_MCP_EXTRA_SIDS.get()
    if sids is not None and isinstance(sid, str) and sid:
        sids.add(sid)


async def collect_known_sids(
    client: ArodonataClient | None,
    mgmt_name: str | None = None,
) -> list[str]:
    """Collect active session tokens from the SID cache, public dedicated-SID registry, and active MCP context."""
    sids: list[str] = []
    if client is not None:
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

    extra_sids = _ACTIVE_MCP_EXTRA_SIDS.get()
    if extra_sids:
        for sid_val in extra_sids:
            if sid_val and sid_val not in sids:
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
    general_units_consumed: int = 0
    live_units_consumed: int = 0

    @property
    def live_consumed(self) -> bool:
        """Whether at least one live quota slot has already been consumed for this call."""
        return self.live_units_consumed > 0


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


def _rollback_active_quota(state: _ActiveQuotaState) -> None:
    """Roll back all general and live quota slots consumed by the current invocation."""
    if state.general_units_consumed > 0 or state.live_units_consumed > 0:
        state.quota_manager.rollback_consumed(
            state.client_id,
            general=state.general_units_consumed,
            live=state.live_units_consumed,
        )
        state.general_units_consumed = 0
        state.live_units_consumed = 0


def consume_live_quota_if_needed(*, cost: int = 1, cap_at_limit_if_empty: bool = False) -> None:
    """Ensure at least `cost` `live` quota slots are consumed for the active guarded tool call."""
    eff_cost = max(1, int(cost))
    state = _ACTIVE_MCP_QUOTA_STATE.get()
    if state is None:
        return

    live_limit = state.quota_manager.live_rate_limit_per_minute
    if live_limit > 0:
        if cap_at_limit_if_empty and eff_cost >= live_limit:
            if state.quota_manager.live_bucket_count(state.client_id) <= state.live_units_consumed:
                eff_cost = live_limit
        elif not cap_at_limit_if_empty and eff_cost > live_limit:
            _rollback_active_quota(state)
            span_attrs(
                mcp_rate_limited=True,
                mcp_client_id=state.client_id,
                mcp_tool=state.tool_name,
                mcp_quota_bucket="live",
            )
            logger.warning(
                "MCP tool fan-out exceeds per-minute live rate limit",
                tool=state.tool_name,
                client_id=state.client_id,
                bucket="live",
                limit=live_limit,
                requested_cost=eff_cost,
            )
            raise ToolFailure(
                f"Rate limit exceeded for MCP tool {state.tool_name!r}: requested fan-out cost ({eff_cost}) "
                f"exceeds per-minute live limit ({live_limit}/min). Pass batches of <= {live_limit} items.",
                error_code="rate_limit_exceeded",
                details={
                    "client_id": state.client_id,
                    "bucket": "live",
                    "limit_per_minute": live_limit,
                    "requested_cost": eff_cost,
                    "retry_after_seconds": 0.0,
                    "exceeds_per_minute_limit": True,
                },
            )

    delta = eff_cost - state.live_units_consumed
    if delta <= 0:
        return
    decision = state.quota_manager.check_and_consume_live_only(state.client_id, cost=delta)
    if not decision.allowed:
        _rollback_active_quota(state)
        raise _emit_rate_limit_failure(state.tool_name, state.client_id, decision)
    state.live_units_consumed += delta


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
    *,
    allow_refresh: bool = True,
) -> str | None:
    """Pre-validate `domain` against the cached `domains` table before attempting a domain login.

    If `domain` is not present in the cached `domains` table and `allow_refresh` is `True`, performs a single
    domain-list refresh (`client.get_domains(..., cache_mode="force")`). With `allow_refresh=False` (caller
    `cache_mode="cache"`) no live call or quota charge occurs and only cached rows are consulted. If still not
    present and the server has known domains, raises an actionable `ToolFailure` listing known domains.
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

    if not allow_refresh:
        if cached_names:
            raise ToolFailure(
                f"Unknown domain {clean_domain!r} on management server {mgmt_name!r}. "
                f"Known cached domains on {mgmt_name!r}: {', '.join(sorted(cached_names))}.",
                mgmt_name=mgmt_name,
                domain=clean_domain,
            )
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
            extra_sids_token = _ACTIVE_MCP_EXTRA_SIDS.set(set())
            try:
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
                                general_units_consumed=1 if quota_manager.rate_limit_per_minute > 0 else 0,
                                live_units_consumed=(
                                    1 if (is_live and quota_manager.live_rate_limit_per_minute > 0) else 0
                                ),
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
                        known_sids = await collect_known_sids(None, eff_mgmt)
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
                    client_or_none: ArodonataClient | None = None
                    eff_mgmt = mgmt_arg or "default"
                    known: list[str] = []
                    try:
                        client_or_none = client_getter()
                        eff_mgmt = (
                            resolve_mgmt_name(client_or_none, mgmt_arg)
                            if mgmt_arg
                            else (
                                client_or_none.settings.mgmt_names[0]
                                if client_or_none.settings.mgmt_names
                                else "default"
                            )
                        )
                    except Exception:
                        pass
                    if client_or_none is not None:
                        try:
                            known = await get_known_domain_names(client_or_none, eff_mgmt, refresh_if_empty=False)
                        except Exception:
                            known = []
                    try:
                        known_sids = await collect_known_sids(client_or_none, eff_mgmt)
                    except Exception:
                        known_sids = await collect_known_sids(None, eff_mgmt)
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
                    client_or_none = None
                    eff_mgmt = mgmt_arg or "default"
                    known = []
                    try:
                        client_or_none = client_getter()
                        if not mgmt_arg and client_or_none.settings.mgmt_names:
                            eff_mgmt = client_or_none.settings.mgmt_names[0]
                    except Exception:
                        pass
                    if isinstance(dom_exc, (DomainNotFoundError, AmbiguousLayerName)) and client_or_none is not None:
                        try:
                            known = await get_known_domain_names(client_or_none, eff_mgmt, refresh_if_empty=False)
                        except Exception:
                            known = []
                    try:
                        known_sids = await collect_known_sids(client_or_none, eff_mgmt)
                    except Exception:
                        known_sids = await collect_known_sids(None, eff_mgmt)
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
                        known_sids = await collect_known_sids(None, mgmt_arg)
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
            finally:
                _ACTIVE_MCP_EXTRA_SIDS.reset(extra_sids_token)

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
    "register_active_mcp_sid",
    "resolve_mcp_caller_id",
    "resolve_mgmt_name",
    "validate_domain_or_fail",
]
