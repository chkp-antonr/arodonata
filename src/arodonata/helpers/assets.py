"""Helper functions for asset (gateway/server) operations.

Provides cache-first asset queries with SMART/CACHE/FORCE modes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..models import Gateway
    from ._context import UserContext

log = lazy_logger("arodonata.helpers.assets")


async def get_gateways(
    client: ArodonataClient,
    mgmt_names: list[str] | None = None,
    cache_mode: Literal["smart", "cache", "force"] = "smart",
    user_context: UserContext | None = None,
) -> list[Gateway]:
    """Get gateways and servers.

    Args:
        client: ArodonataClient instance.
        mgmt_names: Optional list of management servers to filter.
        cache_mode: Cache mode - "smart" (default), "cache", or "force".
        user_context: Optional user context for logging.

    Returns:
        List of Gateway Pydantic models.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting gateways")

    orchestration = client._orchestration

    # Handle force refresh
    if cache_mode == "force":
        async for _ in client.build_refresh_assets_cache(
            mgmt_names=mgmt_names or "",
        ):
            pass

    # Get gateways from cache. Always pass cache_mode="cache": gateways live in
    # the assets table (not OBJECT_TYPES), so the object-cache coordinator can
    # only do useless (and very expensive) host/network reloads here. Asset
    # freshness is handled by build_refresh_assets_cache above/below.
    gateways = await orchestration.get_gateways(mgmt_names=mgmt_names, cache_mode="cache")

    # In smart mode, if cache is empty, populate it
    if not gateways and cache_mode == "smart":
        async for _ in client.build_refresh_assets_cache(
            mgmt_names=mgmt_names or "",
            cache_mode="auto",
        ):
            pass
        gateways = await orchestration.get_gateways(mgmt_names=mgmt_names, cache_mode="cache")

    return gateways


async def refresh_assets(
    client: ArodonataClient,
    mgmt_names: list[str],
    cache_mode: Literal["smart", "force"] = "force",
    user_context: UserContext | None = None,
) -> dict[str, Any]:
    """Refresh asset cache.

    Args:
        client: ArodonataClient instance.
        mgmt_names: Management servers to refresh.
        cache_mode: "force" (default) = refresh, "smart" = check freshness first.
        user_context: Optional user context for logging.

    Returns:
        RefreshResult with statistics.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) refreshing assets for {mgmt_names}")

    orchestration = client._orchestration
    results = []

    for mgmt_name in mgmt_names:
        if cache_mode == "smart":
            # Check freshness first
            is_fresh = await orchestration._is_cache_fresh(table="assets", mgmt_name=mgmt_name, domain="")
            if is_fresh:
                results.append({"mgmt_name": mgmt_name, "status": "skipped", "reason": "fresh"})
                continue

        # Force refresh
        async for _ in client.build_refresh_assets_cache(
            mgmt_names=[mgmt_name],
        ):
            pass
        results.append({"mgmt_name": mgmt_name, "status": "refreshed"})

    return {
        "total": len(mgmt_names),
        "refreshed": sum(1 for r in results if r["status"] == "refreshed"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "details": results,
    }
