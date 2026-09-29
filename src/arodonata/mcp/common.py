"""Helpers shared by every MCP tool: server resolution, error mapping, envelopes, JSON."""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import BaseModel, Field, SecretStr

from ..api.schemas import ApiCallResult, ApiQueryResult
from ..logger import lazy_logger
from ._sdk import AccessToken, CallToolResult, MCPServer, TextContent, ToolError, get_access_token

log = lazy_logger(__name__)

if TYPE_CHECKING:
    from ..api.client import ArodonataClient


READ_CACHE_MODE_DESCRIPTION = (
    "cache: read the cache as-is; smart: re-sync stale domains first; smart-fast: incremental re-sync; "
    "force: full reload. Omit for the server default."
)
ReadCacheMode = Annotated[
    Literal["cache", "smart", "smart-fast", "force"] | None, Field(description=READ_CACHE_MODE_DESCRIPTION)
]
"""Model-facing read-cache mode for cache-backed tools; values mirror ``arodonata.core.cache_mode.CacheMode``.

This is the cached getters' data-freshness vocabulary, not the ``api_call``/``api_query`` session-cache mode
(``auto``/``refresh``/``off``), which live tools never expose. ``None`` means the client's default policy.
"""


class ToolFailure(ToolError):
    """A tool-level failure returned to the model as an error result (never a traceback)."""


def log_tool_call(name: str, access_token: AccessToken | None) -> None:
    """Log one INFO line naming the tool and the caller identity.

    The caller identity is the access token's ``client_id`` (the token's environment-variable name, see
    ``auth.py``), or ``anonymous`` when the request carries none (stdio, or HTTP without auth). Never logs the
    token value, the tool arguments or the result.
    """
    client_id = access_token.client_id if access_token is not None else "anonymous"
    log().info("tool %s called by %s", name, client_id)


def add_guarded_tool(
    server: MCPServer, fn: Callable[..., Awaitable[Any]], *, name: str, description: str | None = None
) -> None:
    """Register ``fn`` with exception redaction and plain JSON-text output.

    Unexpected exceptions are logged with their traceback and surfaced as ``internal error: <Class>`` so payload text
    never leaks to the caller. ``structured_output=False`` keeps results as JSON text (the SDK would otherwise wrap
    ``dict``/``str`` returns in a ``{"result": ...}`` object).

    A ``ToolError`` (including ``ToolFailure``) is returned as an already-built error ``CallToolResult`` rather than
    re-raised: the installed SDK's ``Tool.run()`` unconditionally prefixes any ``ToolError`` that escapes the tool
    body with ``"Error executing tool <name>: "`` before it reaches the client. Returning the result directly instead
    of raising bypasses that prefix, so the model sees exactly the message the tool raised.
    """

    @functools.wraps(fn)
    async def guarded(*args: Any, **kwargs: Any) -> Any:
        log_tool_call(name, get_access_token())
        try:
            return await fn(*args, **kwargs)
        except ToolError as exc:
            return CallToolResult(content=[TextContent(type="text", text=str(exc))], is_error=True)
        except Exception as exc:
            log().error("tool %s failed: %s", name, type(exc).__name__, exc_info=True)
            return CallToolResult(
                content=[TextContent(type="text", text=f"internal error: {type(exc).__name__}")], is_error=True
            )

    server.add_tool(guarded, name=name, description=description or fn.__doc__, structured_output=False)


def resolve_mgmt_name(client: ArodonataClient, mgmt_name: str | None) -> str:
    names = client.get_mgmt_names()
    if mgmt_name:
        if mgmt_name not in names:
            raise ToolFailure(f"unknown mgmt_name '{mgmt_name}'; configured servers: {', '.join(names)}")
        return mgmt_name
    if len(names) == 1:
        return names[0]
    raise ToolFailure(f"mgmt_name is required; configured servers: {', '.join(names)}")


def ensure_success(result: ApiCallResult | ApiQueryResult, command: str) -> None:
    if not result.success:
        code = result.code or "error"
        raise ToolFailure(f"{code}: {result.message or command + ' failed'}")


def _kebab(key: str) -> str:
    return key.replace("_", "-")


def to_api_payload(args: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values and convert snake_case keys to the API's kebab-case, recursively for dicts."""
    out: dict[str, Any] = {}
    for key, value in args.items():
        if value is None:
            continue
        if isinstance(value, dict):
            value = to_api_payload(value)
        out[_kebab(key)] = value
    return out


def list_envelope(
    objects: list[Any],
    *,
    offset: int,
    limit: int,
    total: int,
    source: str,
    cache_age_seconds: int | None = None,
    key: str = "objects",
) -> dict[str, Any]:
    page = objects[offset:] if limit == 0 else objects[offset : offset + limit]
    return {
        key: page,
        "from": offset + 1 if page else 0,
        "to": offset + len(page),
        "total": total,
        "source": source,
        "cache_age_seconds": cache_age_seconds,
    }


def _default(obj: Any) -> Any:
    if isinstance(obj, SecretStr):
        return "**********"
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return str(obj)


def dump_json(obj: Any) -> str:
    return json.dumps(obj, default=_default, ensure_ascii=False, indent=1)


def truncate_json(text: str, max_chars: int, *, offset: int, returned: int, total: int) -> str:
    if len(text) <= max_chars:
        return text
    cut = text.rfind("\n", 0, max_chars)
    head = text[: cut if cut > 0 else max_chars]
    hint = (
        f"\n... [truncated: response exceeded {max_chars} characters; {returned} of {total} items were requested "
        f"from offset {offset}. Re-run with a smaller limit, or continue with offset={offset + returned}]"
    )
    return head + hint
