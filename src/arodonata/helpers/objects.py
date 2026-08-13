"""Helper functions for network object operations.

Provides cache-first queries with SMART/CACHE/FORCE modes.
Wraps ObjectService and CacheOrchestrationService.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, Literal

from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..cache.models import CPObject
    from ._context import UserContext

log = lazy_logger("arodonata.helpers.objects")


async def find_object(
    client: ArodonataClient,
    search: str,
    object_type: str | None = None,
    cache_mode: Literal["smart", "cache", "force"] = "smart",
    user_context: UserContext | None = None,
) -> CPObject | None:
    """Find object by name, IP address, or UID.

    Args:
        client: ArodonataClient instance.
        search: Object name, IP address, or UID to search for.
        object_type: Optional filter by object type.
        cache_mode: Cache mode - "smart" (default), "cache", or "force".
        user_context: Optional user context for logging.

    Returns:
        CPObject if found, None otherwise.
    """
    from ..cache.object_service import classify_input

    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) searching for object: {search}")

    # Classify input to determine search type
    search_type, cleaned = classify_input(search)

    # Get object service
    obj_service = client._object_service

    # For "cache" mode, search DB only
    if cache_mode == "cache":
        results = await obj_service._fetch_objects_from_db(
            search_type=search_type,
            cleaned=cleaned,
            mgmt_names=None,
            domain_names=None,
        )
        if object_type:
            results = [r for r in results if r.type == object_type]
        return results[0] if results else None

    # For "smart" and "force" modes, use ObjectService.search_objects
    # which handles API fallback and refresh
    search_results = []
    async for search_result in obj_service.search_objects(
        search_input=search,
        mgmt_names=None,
        domain_names=None,
    ):
        search_results = search_result.objects
        break  # Only process first result

    if cache_mode == "force" and search_results:
        # Force refresh after finding
        # Use refresh_objects with force mode
        async for _ in obj_service.refresh_objects(
            mgmt_names=None,
            domain_names=None,
            mode="force",
        ):
            pass  # Consume progress events

        # Re-fetch after refresh
        async for search_result in obj_service.search_objects(
            search_input=search,
            mgmt_names=None,
            domain_names=None,
        ):
            search_results = search_result.objects
            break

    if object_type:
        search_results = [obj for obj in search_results if obj.type == object_type]

    return search_results[0] if search_results else None


async def get_objects(
    client: ArodonataClient,
    object_type: str,
    filters: dict[str, Any] | None = None,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    cache_mode: Literal["smart", "cache", "force"] = "smart",
    user_context: UserContext | None = None,
) -> list[CPObject]:
    """Get objects by type with optional filters.

    Args:
        client: ArodonataClient instance.
        object_type: Object type (host, network, group, etc.).
        filters: Optional field filters.
        mgmt_name: Optional management server filter.
        domain_name: Optional domain filter.
        cache_mode: Cache mode - "smart" (default), "cache", or "force".
        user_context: Optional user context for logging.

    Returns:
        List of CPObject instances.
    """
    mgmt_names = [mgmt_name] if mgmt_name else None
    domain_names = [domain_name] if domain_name else None

    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting {object_type} objects")

    # Get object service for cache access
    obj_service = client._object_service

    if cache_mode == "cache":
        # Direct cache query
        result = await obj_service._cache.get_objects(
            object_type=object_type,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=filters,
        )
        return result

    # For "force" mode, refresh first
    if cache_mode == "force":
        async for _ in obj_service.refresh_objects(
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            mode="force",
        ):
            pass  # Consume progress events

    # Get objects from cache
    result = await obj_service._cache.get_objects(
        object_type=object_type,
        mgmt_names=mgmt_names,
        domain_names=domain_names,
        filters=filters,
    )
    return result


async def get_group_members(
    client: ArodonataClient,
    group_uid: str,
    mgmt_name: str,
    domain_name: str,
    cache_mode: Literal["smart", "cache", "force"] = "smart",
    user_context: UserContext | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Get group membership tree as async iterator.

    Args:
        client: ArodonataClient instance.
        group_uid: Group UID to resolve.
        mgmt_name: Management server name.
        domain_name: Domain name.
        cache_mode: Cache mode - "smart" (default), "cache", or "force".
        user_context: Optional user context for logging.

    Yields:
        Group membership nodes as dicts.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) resolving group: {group_uid}")

    obj_service = client._object_service

    if cache_mode == "force":
        # Refresh group objects
        async for _ in obj_service.refresh_objects(
            mgmt_names=[mgmt_name],
            domain_names=[domain_name],
            mode="force",
        ):
            pass  # Consume progress events

    # Resolve group memberships
    tree = await obj_service._resolve_group_memberships(
        obj_uid=group_uid,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
    )

    for node in tree:
        yield {
            "uid": node.uid,
            "name": node.name,
            "domain": node.domain,
            "depth": node.depth,
        }
