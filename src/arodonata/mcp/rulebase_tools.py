"""show_*_rulebase tools: cache-backed by default, live when a live-only parameter is given."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from ._sdk import MCPServer
from .common import (
    ReadCacheMode,
    ToolFailure,
    add_guarded_tool,
    dump_json,
    ensure_success,
    list_envelope,
    resolve_mgmt_name,
    to_api_payload,
    truncate_json,
)
from .projection import cache_age_seconds, project
from .rulebase_format import RuleRow, render_markdown, render_model_friendly, rows_from_cached, rows_from_live

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from .registry import ToolOptions

LIVE_ONLY_PARAMS: tuple[str, ...] = (
    "filter",
    "filter_settings",
    "show_hits",
    "hits_settings",
    "use_object_dictionary",
    "show_as_ranges",
    "show_expiration_settings",
    "order",
)
Format = Literal["raw", "markdown", "model_friendly"]
Order = Annotated[list[dict[str, str]] | None, Field(description='Sort, e.g. [{"ASC": "name"}]')]

_DESCRIPTION = (
    "Cache-backed by default (pass cache_mode='smart' to re-sync stale data or 'force' to reload first; cache_mode "
    "only affects the cache path). Any of these parameters forces a live "
    f"management-server query: {', '.join(LIVE_ONLY_PARAMS)}. format='markdown' (default) renders a table with full "
    "cell values; 'model_friendly' is compact structured text; 'raw' returns the API shape."
)

_SPECS: dict[str, tuple[str, str, bool]] = {
    # tool base name -> (api command, cached getter, requires package instead of name/uid)
    "show_access_rulebase": ("show-access-rulebase", "get_access_rules", False),
    "show_nat_rulebase": ("show-nat-rulebase", "get_nat_rules", True),
    "show_https_rulebase": ("show-https-rulebase", "get_https_rules", False),
    "show_threat_rulebase": ("show-threat-rulebase", "get_threat_rules", False),
}


def _footer(source: str, age: int | None, offset: int, shown: int, total: int) -> str:
    age_txt = f" (age {age}s)" if age is not None else ""
    first = offset + 1 if shown else 0
    return f"\n\nSource: {source}{age_txt} | rows {first}-{offset + shown} of {total}"


def _slice(rows: Sequence[RuleRow], offset: int, limit: int) -> list[RuleRow]:
    return list(rows[offset:] if limit == 0 else rows[offset : offset + limit])


async def _rows_with_inline(rules: Sequence[Any], lookup: Callable[[str], Awaitable[Sequence[Any]]]) -> list[RuleRow]:
    """Resolve inline layers asynchronously, then build rows with a synchronous lookup over the prefetched map."""
    prefetched: dict[str, Sequence[Any]] = {}
    pending = [
        str(r.raw_data.get("inline-layer", {}).get("name", ""))
        for r in rules
        if isinstance(r.raw_data, dict) and isinstance(r.raw_data.get("inline-layer"), dict)
    ]
    while pending:
        layer = pending.pop()
        if not layer or layer in prefetched:
            continue
        children = await lookup(layer)
        prefetched[layer] = children
        pending += [
            str(c.raw_data.get("inline-layer", {}).get("name", ""))
            for c in children
            if isinstance(c.raw_data, dict) and isinstance(c.raw_data.get("inline-layer"), dict)
        ]
    return rows_from_cached(rules, inline_lookup=lambda layer: prefetched.get(layer, []))


async def _live_rulebase(
    client: ArodonataClient,
    command: str,
    mgmt: str,
    domain: str | None,
    payload: dict[str, Any],
    format: Format,
    offset: int,
    limit: int,
    opts: ToolOptions,
) -> tuple[list[RuleRow], str, int | None, Any]:
    """Run the live ``api_query`` path. Returns ``(rows, source, age, raw_result_or_none)``.

    ``raw_result_or_none`` is the already-truncated JSON text to return immediately when ``format == "raw"``,
    ``None`` otherwise (the caller then renders markdown/model_friendly from ``rows``).
    """
    query = await client.api_query(
        mgmt,
        command,
        domain=domain or "",
        details_level="full",
        payload=payload,
        container_key="rulebase",
    )
    ensure_success(query, command)
    data = query.data if isinstance(query.data, dict) else {"rulebase": query.objects}
    rows = rows_from_live(data)
    if format == "raw":
        env = list_envelope(
            list(data.get("rulebase", [])), offset=offset, limit=limit, total=len(rows), source="live", key="rulebase"
        )
        env["objects-dictionary"] = data.get("objects-dictionary", [])
        raw = truncate_json(
            dump_json(env), opts.max_result_chars, offset=offset, returned=len(env["rulebase"]), total=len(rows)
        )
        return rows, "live", None, raw
    return rows, "live", None, None


async def _cached_rulebase(
    client: ArodonataClient,
    getter_name: str,
    rulebase_type: str,
    layer: str | None,
    mgmt: str,
    domain: str | None,
    enabled_only: bool | None,
    cache_mode: str | None,
    details_level: str,
    format: Format,
    offset: int,
    limit: int,
) -> tuple[list[RuleRow], str, int | None, Any]:
    """Run the cache-backed path. Returns ``(rows, source, age, raw_envelope_or_none)`` (see ``_live_rulebase``).

    Only expands inline layers (an extra cache call per distinct inline layer) when the caller actually needs rows
    to render — ``format == "raw"`` returns the flat top-level envelope straight from ``rules`` and skips it.
    """
    getter = getattr(client, getter_name)
    kwargs = {
        "mgmt_names": [mgmt],
        "domain_names": [domain] if domain else None,
        "enabled_only": enabled_only,
        "cache_mode": cache_mode,
    }
    rules = await getter(layer_name=layer, **kwargs)
    last = await client.cache.get_rulebase_last_update(
        rulebase_type, mgmt_names=[mgmt], domain_names=[domain] if domain else None
    )
    age = cache_age_seconds(last)
    if format == "raw":
        env = list_envelope(
            [project(r.raw_data or {}, details_level) for r in rules],
            offset=offset,
            limit=limit,
            total=len(rules),
            source="cache",
            cache_age_seconds=age,
            key="rulebase",
        )
        return [], "cache", age, env

    async def lookup(inline_layer: str) -> Sequence[Any]:
        return await getter(layer_name=inline_layer, **kwargs)

    rows = await _rows_with_inline(rules, lookup)
    return rows, "cache", age, None


async def _layer_name_from_uid(client: ArodonataClient, uid: str, mgmt: str, domain: str | None) -> str:
    """Resolve a layer uid to its name through the object cache (the cached rule getters are keyed on layer name)."""
    obj = await client.get_object_by_uid(uid=uid, mgmt_name=mgmt, domain_name=domain or "")
    if obj is None or not obj.name:
        raise ToolFailure(
            f"layer uid '{uid}' not found in cache for {mgmt}/{domain or 'system domain'}; pass the layer name, "
            f"or a live-only parameter (e.g. {LIVE_ONLY_PARAMS[0]}) to query the management server by uid"
        )
    return obj.name


def _build_run(
    base: str, command: str, getter_name: str, nat: bool, client: ArodonataClient, opts: ToolOptions
) -> Callable[..., Awaitable[Any]]:
    """The shared tool body, parameterised over which rulebase kind it serves.

    Kept separate from the per-kind public signatures below (``_wrap_nat_tool``/``_wrap_named_tool``) so that
    ``show_nat_rulebase``'s published input schema can omit ``name``/``uid`` (NAT addresses its rulebase by policy
    package, not name/uid) while the other three tools keep them, without duplicating this body.
    """
    rulebase_type = base.removeprefix("show_").removesuffix("_rulebase")

    async def run(
        name: str | None,
        uid: str | None,
        package: str | None,
        mgmt_name: str | None,
        domain: str | None,
        details_level: Literal["uid", "standard", "full"],
        limit: int,
        offset: int,
        cache_mode: ReadCacheMode,
        format: Format,
        enabled_only: bool | None,
        filter: str | None,
        filter_settings: dict[str, Any] | None,
        show_hits: bool | None,
        hits_settings: dict[str, Any] | None,
        use_object_dictionary: bool | None,
        show_as_ranges: bool | None,
        show_expiration_settings: bool | None,
        order: list[dict[str, str]] | None,
    ) -> Any:
        mgmt = resolve_mgmt_name(client, mgmt_name)
        layer = package if nat else (name or uid)
        if nat and not package:
            raise ToolFailure(f"{base} requires package")
        if not nat and not layer:
            raise ToolFailure(f"{base} requires name or uid")
        live_args = {
            "filter": filter,
            "filter_settings": filter_settings,
            "show_hits": show_hits,
            "hits_settings": hits_settings,
            "use_object_dictionary": use_object_dictionary,
            "show_as_ranges": show_as_ranges,
            "show_expiration_settings": show_expiration_settings,
            "order": order,
        }
        if any(v is not None for v in live_args.values()):
            payload = to_api_payload({"name": name, "uid": uid, "package": package, **live_args})
            payload.setdefault("use-object-dictionary", True)
            rows, source, age, raw = await _live_rulebase(
                client, command, mgmt, domain, payload, format, offset, limit, opts
            )
        else:
            if not nat and not name and uid:
                # The cached getters filter by layer *name*, so a bare uid would silently match nothing.
                layer = await _layer_name_from_uid(client, uid, mgmt, domain)
            rows, source, age, raw = await _cached_rulebase(
                client,
                getter_name,
                rulebase_type,
                layer,
                mgmt,
                domain,
                enabled_only,
                cache_mode,
                details_level,
                format,
                offset,
                limit,
            )
        title = str(layer)
        if raw is not None:
            return raw
        shown = _slice(rows, offset, limit)
        body = render_markdown(shown, title) if format == "markdown" else render_model_friendly(shown, title)
        body += _footer(source, age, offset, len(shown), len(rows))
        return truncate_json(body, opts.max_result_chars, offset=offset, returned=len(shown), total=len(rows))

    return run


def _wrap_nat_tool(run: Callable[..., Awaitable[Any]], opts: ToolOptions) -> Callable[..., Awaitable[Any]]:
    """NAT is addressed by policy package: no ``name``/``uid`` in the published schema."""

    async def tool(
        package: str | None = None,
        mgmt_name: str | None = None,
        domain: str | None = None,
        details_level: Literal["uid", "standard", "full"] = "standard",
        limit: int = opts.default_limit,
        offset: int = 0,
        cache_mode: ReadCacheMode = None,
        format: Format = "markdown",
        enabled_only: bool | None = None,
        filter: str | None = None,
        filter_settings: dict[str, Any] | None = None,
        show_hits: bool | None = None,
        hits_settings: dict[str, Any] | None = None,
        use_object_dictionary: bool | None = None,
        show_as_ranges: bool | None = None,
        show_expiration_settings: bool | None = None,
        order: Order = None,
    ) -> Any:
        return await run(
            None,
            None,
            package,
            mgmt_name,
            domain,
            details_level,
            limit,
            offset,
            cache_mode,
            format,
            enabled_only,
            filter,
            filter_settings,
            show_hits,
            hits_settings,
            use_object_dictionary,
            show_as_ranges,
            show_expiration_settings,
            order,
        )

    return tool


def _wrap_named_tool(run: Callable[..., Awaitable[Any]], opts: ToolOptions) -> Callable[..., Awaitable[Any]]:
    """Access/HTTPS/Threat rulebases are addressed by layer ``name`` or ``uid``.

    ``package`` is also accepted (the reference server's ``show-access-rulebase`` and friends take it, and the live
    API forwards it in the payload) but is not used to resolve the cache-path layer: the cached getter call is keyed
    on ``layer_name=name or uid`` regardless, since ``package`` is not a cache filter for these three tools.
    """

    async def tool(
        name: str | None = None,
        uid: str | None = None,
        package: str | None = None,
        mgmt_name: str | None = None,
        domain: str | None = None,
        details_level: Literal["uid", "standard", "full"] = "standard",
        limit: int = opts.default_limit,
        offset: int = 0,
        cache_mode: ReadCacheMode = None,
        format: Format = "markdown",
        enabled_only: bool | None = None,
        filter: str | None = None,
        filter_settings: dict[str, Any] | None = None,
        show_hits: bool | None = None,
        hits_settings: dict[str, Any] | None = None,
        use_object_dictionary: bool | None = None,
        show_as_ranges: bool | None = None,
        show_expiration_settings: bool | None = None,
        order: Order = None,
    ) -> Any:
        return await run(
            name,
            uid,
            package,
            mgmt_name,
            domain,
            details_level,
            limit,
            offset,
            cache_mode,
            format,
            enabled_only,
            filter,
            filter_settings,
            show_hits,
            hits_settings,
            use_object_dictionary,
            show_as_ranges,
            show_expiration_settings,
            order,
        )

    return tool


def register_rulebase_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    names: list[str] = []
    for base, (command, getter_name, nat) in _SPECS.items():
        run = _build_run(base, command, getter_name, nat, client, opts)
        tool = _wrap_nat_tool(run, opts) if nat else _wrap_named_tool(run, opts)
        tool.__name__ = base
        add_guarded_tool(server, tool, name=opts.name(base), description=_DESCRIPTION)
        names.append(opts.name(base))
    return names
