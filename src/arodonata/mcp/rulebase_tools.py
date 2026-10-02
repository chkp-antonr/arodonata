"""show_*_rulebase tools: cache-backed by default, live when a live-only parameter is given."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Annotated, Any, Literal, cast

from pydantic import Field

from ..rulebase.pager import RulebaseFetchError, fetch_full_rulebase
from ..rulebase.source import AmbiguousLayerName, PackageRulebase, RulebaseCacheNotReady, RulebaseNotFound
from ._sdk import MCPServer
from .common import (
    ReadCacheMode,
    ToolFailure,
    add_guarded_tool,
    dump_json,
    list_envelope,
    resolve_mgmt_name,
    to_api_payload,
    truncate_json,
)
from .projection import cache_age_seconds
from .rulebase_format import (
    RuleRow,
    drop_disabled,
    package_layers,
    raw_entries,
    raw_package_entries,
    render_markdown,
    render_model_friendly,
    rows_from_entries,
    rows_from_live,
    rows_from_package,
)

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..rulebase.model import RulebaseType
    from ..rulebase.source import LayerRulebase
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

_SPECS: dict[str, tuple[str, bool]] = {
    # tool base name -> (api command, requires package instead of name/uid)
    "show_access_rulebase": ("show-access-rulebase", False),
    "show_nat_rulebase": ("show-nat-rulebase", True),
    "show_https_rulebase": ("show-https-rulebase", False),
    "show_threat_rulebase": ("show-threat-rulebase", False),
}

_NOT_READY_HINT = (
    "pass domain, run refresh_rulebases for it, or pass a live-only parameter (e.g. filter) to query the "
    "management server"
)


def _footer(source: str, age: int | None, offset: int, shown: int, total: int) -> str:
    age_txt = f" (age {age}s)" if age is not None else ""
    first = offset + 1 if shown else 0
    return f"\n\nSource: {source}{age_txt} | rows {first}-{offset + shown} of {total}"


def _slice(rows: Sequence[RuleRow], offset: int, limit: int) -> list[RuleRow]:
    return list(rows[offset:] if limit == 0 else rows[offset : offset + limit])


async def _live_rulebase(
    client: ArodonataClient,
    command: str,
    rulebase_type: RulebaseType,
    mgmt: str,
    domain: str | None,
    payload: dict[str, Any],
    format: Format,
    offset: int,
    limit: int,
    opts: ToolOptions,
) -> tuple[list[RuleRow], str, int | None, Any]:
    """Run the live path: page the layer completely with the shared pager, then build rows.

    The tool's ``limit``/``offset`` never reach CP: they slice the rendered rows (``_slice``), so footer totals
    always describe the whole layer. Returns ``(rows, source, age, raw_result_or_none)``; ``raw_result_or_none``
    is the already-truncated JSON text to return immediately when ``format == "raw"``, ``None`` otherwise.
    """
    try:
        data = await fetch_full_rulebase(client, mgmt, domain or "", command, {**payload, "details-level": "full"})
    except RulebaseFetchError as exc:
        raise ToolFailure(f"{exc.code or 'error'}: {exc.message or command + ' failed'}") from exc
    rows = rows_from_live(data, rulebase_type)
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


def _ambiguous(exc: AmbiguousLayerName, by_package: bool) -> ToolFailure:
    listed = ", ".join(f"{domain}/{uid}" for domain, uid in exc.candidates)
    if by_package:
        # Package names are unique within a domain, and show_nat_rulebase has no uid: domain is the way out.
        return ToolFailure(f"package {exc.name!r} matches several packages ({listed}); pass domain")
    domains = {domain for domain, _ in exc.candidates}
    if all(uid == exc.name for _, uid in exc.candidates):
        ask = "pass domain"  # already a uid, held by several domains (a Global layer is cached in each)
    else:
        ask = "pass uid" if len(domains) == 1 else "pass domain (or uid)"
    return ToolFailure(f"{exc.name!r} matches several layers ({listed}); {ask}")


async def _read_cached(
    client: ArodonataClient,
    rulebase_type: RulebaseType,
    layer: str | None,
    package: str | None,
    mgmt: str,
    domain: str | None,
    cache_mode: str | None,
) -> PackageRulebase | LayerRulebase:
    """One facade read (the package when ``package`` is given, else the layer), its errors as ``ToolFailure``s."""
    try:
        if package:
            return await client.get_package_rulebase(
                mgmt, domain or None, package, rulebase_type, cache_mode=cache_mode
            )
        return await client.get_layer_rulebase(mgmt, domain or None, str(layer), rulebase_type, cache_mode=cache_mode)
    except AmbiguousLayerName as exc:
        raise _ambiguous(exc, by_package=bool(package)) from exc
    except (RulebaseCacheNotReady, RulebaseNotFound) as exc:
        raise ToolFailure(f"{exc}; {_NOT_READY_HINT}") from exc


async def _cached_rulebase(
    client: ArodonataClient,
    rulebase_type: RulebaseType,
    layer: str | None,
    package: str | None,
    mgmt: str,
    domain: str | None,
    enabled_only: bool | None,
    cache_mode: str | None,
    details_level: str,
    format: Format,
    offset: int,
    limit: int,
) -> tuple[list[RuleRow], str, int | None, Any, str, str]:
    """The cache path on the rulebase facade. Returns ``(rows, source, age, raw_envelope_or_none, title, note)``.

    Without ``package`` one layer is numbered layer-relative (``get_layer_rulebase``); with it (always for NAT) the
    package's SmartConsole numbering is shown (``get_package_rulebase``), narrowed to one ordered layer when
    ``layer`` is given. ``note`` is non-empty when the domain's last rulebase refresh failed.
    """
    result = await _read_cached(client, rulebase_type, layer, package, mgmt, domain, cache_mode)
    raw = format == "raw"
    records: list[dict[str, Any]] = []
    rows: list[RuleRow] = []
    if isinstance(result, PackageRulebase):
        try:
            layers = package_layers(result, layer, enabled_only=bool(enabled_only))
        except LookupError as exc:
            raise ToolFailure(str(exc)) from exc
        title = layers[0][0].layer_name if layer is not None else result.package_name
        if raw:
            records = raw_package_entries(layers, details_level)
        else:
            rows = rows_from_package(result, layers)
    else:
        entries = drop_disabled(result.entries) if enabled_only else result.entries
        title = result.layer_name
        if raw:
            records = raw_entries(entries, details_level)
        else:
            rows = rows_from_entries(entries, result.layer_names, result.layer_dictionaries)
    age = cache_age_seconds(result.snapshot_refreshed_at)
    note = (
        f"\nNote: the last rulebase refresh of {result.domain_name} failed ({result.last_error}); "
        "showing the last good snapshot"
        if result.status == "failed"
        else ""
    )
    if raw:
        env = list_envelope(
            records,
            offset=offset,
            limit=limit,
            total=len(records),
            source="cache",
            cache_age_seconds=age,
            key="rulebase",
        )
        env["objects-dictionary"] = list({o["uid"]: o for d in result.layer_dictionaries.values() for o in d}.values())
        env["status"], env["last_error"] = result.status, result.last_error
        return [], "cache", age, env, title, note
    return rows, "cache", age, None, title, note


def _build_run(
    base: str, command: str, nat: bool, client: ArodonataClient, opts: ToolOptions
) -> Callable[..., Awaitable[Any]]:
    """The shared tool body, parameterised over which rulebase kind it serves.

    Kept separate from the per-kind public signatures below (``_wrap_nat_tool``/``_wrap_named_tool``) so that
    ``show_nat_rulebase``'s published input schema can omit ``name``/``uid`` (NAT addresses its rulebase by policy
    package, not name/uid) while the other three tools keep them, without duplicating this body.
    """
    rulebase_type = cast("RulebaseType", base.removeprefix("show_").removesuffix("_rulebase"))

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
        live = any(v is not None for v in live_args.values())
        if nat and not package:
            raise ToolFailure(f"{base} requires package")
        if not nat and not layer and (live or not package):
            # The cache path can show a whole package; the live show-*-rulebase commands need a layer.
            raise ToolFailure(f"{base} requires name or uid" + ("" if live else " (or package)"))
        if live:
            payload = to_api_payload({"name": name, "uid": uid, "package": package, **live_args})
            payload.setdefault("use-object-dictionary", True)
            rows, source, age, raw = await _live_rulebase(
                client, command, rulebase_type, mgmt, domain, payload, format, offset, limit, opts
            )
            title, note = str(layer), ""
        else:
            # get_layer_rulebase resolves a uid or a name itself; package selects SmartConsole numbering.
            rows, source, age, raw, title, note = await _cached_rulebase(
                client,
                rulebase_type,
                None if nat else layer,
                package,
                mgmt,
                domain,
                enabled_only,
                cache_mode,
                details_level,
                format,
                offset,
                limit,
            )
        if raw is not None:
            return raw
        shown = _slice(rows, offset, limit)
        body = render_markdown(shown, title) if format == "markdown" else render_model_friendly(shown, title)
        body += _footer(source, age, offset, len(shown), len(rows)) + note
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
    API forwards it in the payload). On the cache path it selects the package's SmartConsole numbering (global
    layer, parent rule, ``2.x``); ``name``/``uid`` then picks one ordered layer of it. Without ``package`` the layer
    is numbered layer-relative.
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
    for base, (command, nat) in _SPECS.items():
        run = _build_run(base, command, nat, client, opts)
        tool = _wrap_nat_tool(run, opts) if nat else _wrap_named_tool(run, opts)
        tool.__name__ = base
        add_guarded_tool(server, tool, name=opts.name(base), description=_DESCRIPTION)
        names.append(opts.name(base))
    return names
