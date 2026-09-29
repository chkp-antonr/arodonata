"""Build live ``show_*`` tool handlers from ``MANIFEST`` with synthesized signatures."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from ._sdk import MCPServer
from .common import (
    ToolFailure,
    add_guarded_tool,
    dump_json,
    ensure_success,
    list_envelope,
    resolve_mgmt_name,
    to_api_payload,
    truncate_json,
)
from .manifest import MANIFEST, CompatTool, ParamSpec

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from .registry import ToolOptions

_PY_TYPES: dict[str, Any] = {
    "str": str,
    "int": int,
    "bool": bool,
    "list_str": list[str],
    "list_dict": list[dict[str, str]],
    "dict": dict[str, Any],
}
_LIVE_NOTE = " Live: queries the management server through Arodonata's session cache and rate limiter."


def _annotation(spec: ParamSpec) -> Any:
    base = _PY_TYPES[spec.kind]
    return Annotated[base | None, Field(description=spec.description)] if spec.description else base | None


def _common_params(entry: CompatTool, default_limit: int) -> list[inspect.Parameter]:
    kw = inspect.Parameter.KEYWORD_ONLY
    params = [
        inspect.Parameter(
            "mgmt_name",
            kw,
            default=None,
            annotation=Annotated[
                str | None,
                Field(description="Configured management server name; optional when only one is configured."),
            ],
        ),
        inspect.Parameter(
            "domain",
            kw,
            default=None,
            annotation=Annotated[str | None, Field(description="MDS domain name; omit for single-domain servers.")],
        ),
        inspect.Parameter("details_level", kw, default="standard", annotation=Literal["uid", "standard", "full"]),
    ]
    if entry.kind == "list":
        params += [
            inspect.Parameter(
                "limit",
                kw,
                default=default_limit,
                annotation=Annotated[int, Field(description="Page size; 0 returns everything.")],
            ),
            inspect.Parameter("offset", kw, default=0, annotation=int),
        ]
    return params


def build_handler(
    entry: CompatTool, client: ArodonataClient, opts: ToolOptions
) -> Callable[..., Coroutine[Any, Any, str]]:
    extra_names = [p.name for p in entry.params]

    async def handler(**kwargs: Any) -> str:
        mgmt = resolve_mgmt_name(client, kwargs.pop("mgmt_name", None))
        domain = kwargs.pop("domain", None) or ""
        details_level = kwargs.pop("details_level", "standard")
        limit = int(kwargs.pop("limit", opts.default_limit))
        offset = int(kwargs.pop("offset", 0))
        payload = to_api_payload({k: kwargs.get(k) for k in extra_names})
        if entry.kind == "single":
            if entry.command != "where-used" and not (
                payload.get("name") or payload.get("uid") or payload.get("rule-number")
            ):
                raise ToolFailure(f"{entry.name} requires name or uid")
            result = await client.api_call(
                mgmt, entry.command, domain=domain, details_level=details_level, payload=payload
            )
            ensure_success(result, entry.command)
            return dump_json({"object": result.data or {}, "source": "live"})
        query = await client.api_query(
            mgmt,
            entry.command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            container_key=entry.container_key,
        )
        ensure_success(query, entry.command)
        envelope = list_envelope(query.objects, offset=offset, limit=limit, total=query.total, source="live")
        text = dump_json(envelope)
        return truncate_json(
            text, opts.max_result_chars, offset=offset, returned=len(envelope["objects"]), total=query.total
        )

    params = _common_params(entry, opts.default_limit) + [
        inspect.Parameter(p.name, inspect.Parameter.KEYWORD_ONLY, default=p.default, annotation=_annotation(p))
        for p in entry.params
    ]
    handler.__signature__ = inspect.Signature(params, return_annotation=str)  # type: ignore[attr-defined]
    handler.__annotations__ = {p.name: p.annotation for p in params} | {"return": str}
    handler.__name__ = entry.name
    handler.__doc__ = entry.description + _LIVE_NOTE
    return handler


def register_live_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    names: list[str] = []
    for entry in MANIFEST:
        add_guarded_tool(
            server,
            build_handler(entry, client, opts),
            name=opts.name(entry.name),
            description=entry.description + _LIVE_NOTE,
        )
        names.append(opts.name(entry.name))
    return names
