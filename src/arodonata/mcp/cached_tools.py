"""Reference-named ``show_*`` tools answered from the Arodonata cache."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any, Literal

from ..models.common import BaseModelWithRaw
from ._sdk import MCPServer
from .common import ReadCacheMode, ToolFailure, add_guarded_tool, list_envelope, resolve_mgmt_name
from .projection import cache_age_seconds, project

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from .registry import ToolOptions

DetailsLevel = Literal["uid", "standard", "full"]
_CACHE_NOTE = " Cache-backed: answers from the local Arodonata cache; pass cache_mode='smart' to re-sync stale data or cache_mode='force' to reload from the management server first."


async def _envelope(
    client: ArodonataClient,
    models: Sequence[BaseModelWithRaw],
    *,
    mgmt_name: str,
    domain: str | None,
    details_level: str,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    objects = [project(m.raw_data, details_level) for m in models]
    last = await client.cache.get_objects_last_update(mgmt_names=[mgmt_name], domain_names=[domain] if domain else None)
    return list_envelope(
        objects,
        offset=offset,
        limit=limit,
        total=len(models),
        source="cache",
        cache_age_seconds=cache_age_seconds(last),
    )


def _domain_record(domain: Any) -> dict[str, Any]:
    """The cached domains table stores no API payload (raw_data is empty), so build the record from its fields.

    The record keeps the model's field names (``active_ip``, ``is_mdm``, ...), not Check Point's kebab-case keys.
    """
    if domain.raw_data:
        return dict(domain.raw_data)
    return {"type": "domain", **domain.model_dump(exclude={"raw_data"})}


def register_cached_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    names: list[str] = []

    def _add(fn: Callable[..., Awaitable[dict[str, Any]]], base: str, description: str) -> None:
        add_guarded_tool(server, fn, name=opts.name(base), description=description + _CACHE_NOTE)
        names.append(opts.name(base))

    def _list_tool(
        base: str,
        getter_name: str,
        description: str,
        *,
        filter_kwarg: str = "name_filter",
    ) -> None:
        async def tool(
            mgmt_name: str | None = None,
            domain: str | None = None,
            filter: str | None = None,
            details_level: DetailsLevel = "standard",
            limit: int = opts.default_limit,
            offset: int = 0,
            cache_mode: ReadCacheMode = None,
        ) -> dict[str, Any]:
            mgmt = resolve_mgmt_name(client, mgmt_name)
            getter = getattr(client, getter_name)
            kwargs: dict[str, Any] = {
                filter_kwarg: filter,
                "mgmt_names": [mgmt],
                "domain_names": [domain] if domain else None,
                "cache_mode": cache_mode,
            }
            models = await getter(**kwargs)
            return await _envelope(
                client, models, mgmt_name=mgmt, domain=domain, details_level=details_level, limit=limit, offset=offset
            )

        tool.__name__ = base
        _add(tool, base, description)

    _list_tool("show_hosts", "get_hosts", "List host objects. filter matches the object name (wildcards allowed).")
    _list_tool(
        "show_networks",
        "get_networks",
        "List network objects. filter matches the subnet in CIDR notation (e.g. '10.0.0.0/24').",
        filter_kwarg="subnet",
    )
    _list_tool(
        "show_groups",
        "get_groups",
        "List group objects with member UIDs. filter matches the group name (wildcards allowed).",
    )

    async def show_gateways_and_servers(
        mgmt_name: str | None = None,
        details_level: DetailsLevel = "standard",
        limit: int = opts.default_limit,
        offset: int = 0,
        cache_mode: ReadCacheMode = None,
    ) -> dict[str, Any]:
        # Gateways live in the separate asset cache (see get_gateways docstring), not the object
        # cache that client.cache.get_objects_last_update() answers from, and that cache has no
        # per-domain scoping either, so there is no meaningful cache_age_seconds to report here.
        mgmt = resolve_mgmt_name(client, mgmt_name)
        models = await client.get_gateways(mgmt_names=[mgmt], cache_mode=cache_mode)
        objects = [project(m.raw_data, details_level) for m in models]
        return list_envelope(
            objects, offset=offset, limit=limit, total=len(models), source="cache", cache_age_seconds=None
        )

    _add(
        show_gateways_and_servers,
        "show_gateways_and_servers",
        "List gateways, clusters, cluster members and management servers. details_level='full' includes installed policy and interfaces.",
    )

    async def show_domains(
        mgmt_name: str | None = None,
        details_level: DetailsLevel = "standard",
        limit: int = opts.default_limit,
        offset: int = 0,
        cache_mode: ReadCacheMode = None,
        include_global: bool = False,
    ) -> dict[str, Any]:
        # The domains table has no timestamp column, and the object cache's age says nothing about when the domain
        # list was last synced, so there is no meaningful cache_age_seconds to report here.
        mgmt = resolve_mgmt_name(client, mgmt_name)
        models = await client.get_domains(mgmt_names=[mgmt], cache_mode=cache_mode, include_global=include_global)
        objects = [project(_domain_record(m), details_level) for m in models]
        return list_envelope(
            objects, offset=offset, limit=limit, total=len(models), source="cache", cache_age_seconds=None
        )

    _add(
        show_domains,
        "show_domains",
        "List domains of a Multi-Domain server. include_global adds the synthetic Global domain.",
    )

    async def show_object(
        uid: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        details_level: DetailsLevel = "standard",
    ) -> dict[str, Any]:
        mgmt = resolve_mgmt_name(client, mgmt_name)
        obj = await client.get_object_by_uid(uid=uid, mgmt_name=mgmt, domain_name=domain or "")
        if obj is None:
            raise ToolFailure(
                f"object '{uid}' not found in cache for {mgmt}/{domain or 'system domain'}; try refresh_objects, or show_objects / api_call to query the management server"
            )
        raw = obj.raw_data if isinstance(obj.raw_data, dict) else {}
        last = await client.cache.get_objects_last_update(mgmt_names=[mgmt], domain_names=[domain] if domain else None)
        return {"object": project(raw, details_level), "source": "cache", "cache_age_seconds": cache_age_seconds(last)}

    _add(show_object, "show_object", "Get any object by UID.")
    return names
