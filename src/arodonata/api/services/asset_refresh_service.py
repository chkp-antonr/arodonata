"""Asset collection and cache refresh service.

Handles asset collection, transformation, and relationship processing.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from typing import TYPE_CHECKING, Any

from arodonata.api.schemas import SSEEvent, SSEEventType
from arodonata.cache.lock_manager import distributed_lock, get_current_lock_context
from arodonata.utils.helpers import normalize_input_to_list

from ...logger import lazy_logger

if TYPE_CHECKING:
    from arodonata.api.services.domain_service import DomainService
    from arodonata.asdk import AMgmtClient
    from arodonata.cache import CacheRepository
    from arodonata.cache.models import Asset
    from arodonata.config import ArodonataSettings

log = lazy_logger("arodonata.api.services.asset_refresh_service")


class AssetRefreshService:
    """Asset collection and cache refresh service.

    Orchestrates asset collection from Check Point management servers,
    handles transformation and caching, and processes relationships.
    """

    def __init__(
        self,
        mgmt_client: AMgmtClient,
        cache: CacheRepository,
        domain_service: DomainService,
        cluster_manager: Any,
        vsx_manager: Any,
        settings: ArodonataSettings,
        api_query_method: Callable[..., Any],
    ) -> None:
        """Initialize asset refresh service.

        Args:
            mgmt_client: ASDK management client.
            cache: Cache repository instance.
            domain_service: Domain discovery service.
            cluster_manager: Cluster relationship manager instance.
            vsx_manager: VSX relationship manager instance.
            settings: Configuration settings.
            api_query_method: Reference to ArodonataClient.api_query method.
        """
        self._mgmt = mgmt_client
        self._cache = cache
        self._domain_service = domain_service
        self._cluster_manager_class = cluster_manager.__class__
        self._vsx_manager_class = vsx_manager.__class__
        self._settings = settings
        self._api_query = api_query_method
        log().trace("AssetRefreshService initialized")

    @staticmethod
    def _build_local_fields_snapshot(assets: list[Asset]) -> dict[str, dict[str, str]]:
        """Capture path/ip_address/ssh_ip before a raw refresh wipes them.

        AssetTransformer never populates these - they're written out-of-band
        by the consuming application's own disk-sync. A raw refresh (delete +
        recreate from live API data) always writes them blank, so any asset
        that currently has a non-blank value needs it captured here and
        restored after the refresh via CacheRepository.restore_asset_local_fields().
        """
        snapshot: dict[str, dict[str, str]] = {}
        for asset in assets:
            if asset.path or asset.ip_address or asset.ssh_ip:
                snapshot[asset.asset_id] = {
                    "path": asset.path or "",
                    "ip_address": asset.ip_address or "",
                    "ssh_ip": asset.ssh_ip or "",
                }
        return snapshot

    @distributed_lock("asset_refresh:{mgmt_names}:{domains}", timeout=300, ttl=300)
    async def build_refresh_assets_cache(
        self,
        mgmt_names: str | list[str] = "",
        domains: str | list[str] = "",
        cache_mode: str = "auto",
        client_wrapper: Any = None,
    ) -> AsyncGenerator[SSEEvent]:
        """Build and refresh the assets cache with comprehensive asset collection.

        Collects gateways, servers, clusters, VSX, and VS objects from specified
        management servers and domains, stores them in the cache with proper
        relationship mapping, and streams progress updates.

        Args:
            mgmt_names: Server names as comma-separated string or list (empty = all).
            domains: Domains as comma-separated string or list (empty = all).
            client_wrapper: ArodonataClient wrapper for relationship managers.

        Yields:
            SSEEvent objects for progress, results, and completion.
        """
        normalized_mgmt_names = normalize_input_to_list(mgmt_names)
        normalized_domains = normalize_input_to_list(domains)
        target_names = normalized_mgmt_names or self._mgmt.get_mgmt_names()

        target_servers_and_domains: dict[str, list[str]] = {}
        all_domains_to_delete: set[str] | None = set() if normalized_domains else None

        async for event in self._prepare_scope(
            target_names,
            normalized_domains,
            cache_mode,
            target_servers_and_domains,
            all_domains_to_delete,
        ):
            yield event

        # Snapshot locally-owned fields (path/ip_address/ssh_ip) before the
        # delete+recollect below wipes them - see _build_local_fields_snapshot().
        # Scoped identically to the delete call just below, so the restore
        # after only touches assets that were actually in the refreshed scope.
        delete_scope_mgmt_names = target_names if normalized_mgmt_names else None
        delete_scope_domain_names = list(all_domains_to_delete) if all_domains_to_delete else None
        existing_assets = await self._cache.get_assets(
            mgmt_names=delete_scope_mgmt_names,
            domain_names=delete_scope_domain_names,
        )
        local_fields_snapshot = self._build_local_fields_snapshot(existing_assets)

        try:
            delete_error = await self._delete_existing_assets(
                target_names, normalized_mgmt_names, all_domains_to_delete
            )
            if delete_error:
                yield delete_error
                return

            stats: dict[str, Any] = {
                "total_collected": 0,
                "errors": [],
                "aborted": False,
                "cluster_relationships_count": 0,
                "vsx_relationships_count": 0,
            }

            async for event in self._collect_mds_phase(target_names, cache_mode, stats):
                yield event

            async for event in self._collect_domain_phase(target_servers_and_domains, cache_mode, stats):
                yield event
            if stats["aborted"]:
                return

            async for event in self._process_relationships_phase(target_servers_and_domains, client_wrapper, stats):
                yield event

            async for event in self._generate_summary(
                target_servers_and_domains,
                stats["cluster_relationships_count"],
                stats["vsx_relationships_count"],
                stats["total_collected"],
                stats["errors"],
            ):
                yield event
        finally:
            # Restore whatever local fields survived the delete+recreate
            # above, even if collection failed or a lock was lost partway
            # through - otherwise they stay blank until the next full
            # disk-sync.
            await self._cache.restore_asset_local_fields(local_fields_snapshot)

    async def _prepare_scope(
        self,
        target_names: list[str],
        normalized_domains: list[str],
        cache_mode: str,
        target_servers_and_domains: dict[str, list[str]],
        all_domains_to_delete: set[str] | None,
    ) -> AsyncGenerator[SSEEvent]:
        """Populate domain cache per management server and apply domain filtering.

        Mutates target_servers_and_domains and all_domains_to_delete in place
        (both created empty by the caller) so later phases can read the
        accumulated scope after this generator is exhausted.

        Yields:
            SSEEvent objects for progress, warnings, and errors.
        """
        for mgmt_name in target_names:
            try:
                domain_names = await self._domain_service.populate_domain_cache(mgmt_name, cache_mode=cache_mode)

                if normalized_domains:
                    missing_domains = [d for d in normalized_domains if d and d not in domain_names]
                    if missing_domains:
                        yield SSEEvent(
                            event_type=SSEEventType.WARNING,
                            mgmt_name=mgmt_name,
                            data={
                                "message": f"Domains not found on {mgmt_name}: {', '.join(missing_domains)}",
                                "missing_domains": missing_domains,
                                "available_domains": domain_names,
                            },
                        )

                    domain_names = [d for d in domain_names if d in normalized_domains]

                target_servers_and_domains[mgmt_name] = domain_names

                if all_domains_to_delete is not None:
                    all_domains_to_delete.update(domain_names)

                yield SSEEvent(
                    event_type=SSEEventType.LOG,
                    mgmt_name=mgmt_name,
                    data={
                        "message": f"Populated domains for {mgmt_name}: {len(domain_names)}",
                        "phase": "preparation",
                        "domains_count": len(domain_names),
                    },
                )

            except Exception as e:
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    data={"error_message": f"Failed to populate domains: {e}"},
                )
                continue

    async def _delete_existing_assets(
        self,
        target_names: list[str],
        normalized_mgmt_names: list[str],
        all_domains_to_delete: set[str] | None,
    ) -> SSEEvent | None:
        """Delete existing assets for the target scope before re-collecting.

        Returns an SSEEvent (rather than being a generator) because at most one
        ERROR event is ever produced; a plain return value lets the coordinator
        decide with a simple `if` whether to yield it and stop.

        Logic:
        - No filters: delete everything (full update).
        - Only mgmt_name specified: delete everything for that server.
        - Domains specified: delete and refresh for those domains.

        Returns:
            None on success, or the ERROR SSEEvent to yield on failure.
        """
        try:
            domains_deleted = await self._cache.delete_assets(
                mgmt_names=target_names if normalized_mgmt_names else None,
                domain_names=list(all_domains_to_delete) if all_domains_to_delete else None,
            )
            log().debug(f"Deleted {domains_deleted} existing assets")
        except Exception as e:
            return SSEEvent(
                event_type=SSEEventType.ERROR,
                data={"error_message": f"Failed to delete existing assets: {e}"},
            )
        return None

    async def _collect_mds_phase(
        self,
        target_names: list[str],
        cache_mode: str,
        stats: dict[str, Any],
    ) -> AsyncGenerator[SSEEvent]:
        """Collect MDS assets for every MDM server in scope.

        Accumulates into the caller-owned `stats` dict (`total_collected`,
        `errors`) in place.

        Yields:
            SSEEvent objects for progress, results, and errors.
        """
        for mgmt_name in target_names:
            try:
                server = await self._mgmt.get_server(mgmt_name)
                if server and server.is_mdm:
                    async for event in self._collect_mds_assets(mgmt_name, cache_mode=cache_mode):
                        if event.event_type == SSEEventType.RESULT:
                            stats["total_collected"] += event.data.get("count", 0)
                        yield event
            except Exception as e:
                stats["errors"].append(f"{mgmt_name} MDS collection - {str(e)}")
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    data={"error_message": f"Failed to collect MDS assets: {e}"},
                )

    async def _collect_domain_phase(
        self,
        target_servers_and_domains: dict[str, list[str]],
        cache_mode: str,
        stats: dict[str, Any],
    ) -> AsyncGenerator[SSEEvent]:
        """Collect assets per domain, renewing the distributed lock as needed.

        Renews the lock before each management server and before each domain;
        if renewal fails (lock lost), yields an ERROR, sets
        `stats["aborted"] = True`, and stops iteration immediately.

        Yields:
            SSEEvent objects for progress, results, and errors.
        """
        for mgmt_name, domain_names in target_servers_and_domains.items():
            lock_context = get_current_lock_context()

            if lock_context:
                try:
                    await lock_context.renew_if_needed()
                except Exception as e:
                    log().warning(f"Failed to renew lock: {e}")
                    yield SSEEvent(
                        event_type=SSEEventType.ERROR,
                        mgmt_name=mgmt_name,
                        data={"error_message": f"Lock lost during operation: {e}"},
                    )
                    stats["aborted"] = True
                    return

            actual_domains = [d for d in domain_names if d]

            for domain_name in actual_domains:
                if lock_context:
                    try:
                        await lock_context.renew_if_needed()
                    except Exception as e:
                        log().warning(f"Failed to renew lock: {e}")
                        yield SSEEvent(
                            event_type=SSEEventType.ERROR,
                            mgmt_name=mgmt_name,
                            domain=domain_name,
                            data={"error_message": f"Lock lost during operation: {e}"},
                        )
                        stats["aborted"] = True
                        return

                async for event in self._refresh_domain_assets_impl(mgmt_name, domain_name, cache_mode=cache_mode):
                    if event.event_type == SSEEventType.ERROR:
                        stats["errors"].append(f"{mgmt_name}:{domain_name} - {event.data.get('error_message', '')}")
                    elif event.event_type == SSEEventType.RESULT:
                        stats["total_collected"] += event.data.get("count", 0)
                    yield event

    async def _process_relationships_phase(
        self,
        target_servers_and_domains: dict[str, list[str]],
        client_wrapper: Any,
        stats: dict[str, Any],
    ) -> AsyncGenerator[SSEEvent]:
        """Run cluster and VSX relationship processing in sequence.

        Delegates to the existing `_process_cluster_relationships` and
        `_process_vsx_relationships` generators, forwarding every event and
        accumulating their `relationships_updated` counts into `stats`.

        Yields:
            SSEEvent objects for progress and errors from both sub-phases.
        """
        async for event in self._process_cluster_relationships(target_servers_and_domains, client_wrapper):
            yield event
            if event.event_type == SSEEventType.LOG and event.data.get("relationships_updated"):
                stats["cluster_relationships_count"] += event.data["relationships_updated"]

        async for event in self._process_vsx_relationships(target_servers_and_domains, client_wrapper):
            yield event
            if event.event_type == SSEEventType.LOG and event.data.get("relationships_updated"):
                stats["vsx_relationships_count"] += event.data["relationships_updated"]

    async def _refresh_domain_assets_impl(
        self,
        mgmt_name: str,
        domain_name: str,
        cache_mode: str = "auto",
    ) -> AsyncGenerator[SSEEvent]:
        """Refresh cached assets for a single domain (unlocked implementation).

        Callers that already hold a broader asset_refresh lock (e.g.
        build_refresh_assets_cache's own per-domain loop) should call this
        directly instead of refresh_domain_assets, to avoid re-acquiring a
        lock whose key can collide with the one they already hold when the
        outer call was scoped to a single mgmt_name/domain_name.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            cache_mode: Cache mode passed through to the underlying API query.

        Yields:
            SSEEvent objects for progress, results, and errors.
        """
        from ..asset_transformer import AssetTransformer

        try:
            yield SSEEvent(
                event_type=SSEEventType.LOG,
                mgmt_name=mgmt_name,
                domain=domain_name,
                data={
                    "message": f"Processing {mgmt_name}:{domain_name}",
                    "phase": "collecting",
                },
            )

            result = await self._api_query(
                mgmt_name=mgmt_name,
                command="show-gateways-and-servers",
                domain=domain_name,
                details_level="full",
                cache_mode=cache_mode,
            )

            if not result.success:
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    domain=domain_name,
                    data={
                        "error_message": result.message,
                        "error_code": result.code,
                    },
                )
                return

            # Get domain UID from cache
            domain_uid = await self._domain_service.get_domain_uid(mgmt_name, domain_name)

            # Cache assets in batch to avoid N+1 queries
            assets_to_cache = []
            for obj in result.objects or []:
                asset = AssetTransformer.transform_to_asset(
                    obj=obj,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    domain_uid=domain_uid,
                )
                if asset:
                    assets_to_cache.append(asset)

            collected_count = 0
            if assets_to_cache:
                await self._cache.upsert_assets(assets_to_cache)
                collected_count = len(assets_to_cache)

            yield SSEEvent(
                event_type=SSEEventType.RESULT,
                mgmt_name=mgmt_name,
                domain=domain_name,
                data={
                    "result_type": "assets",
                    "count": collected_count,
                },
            )

        except Exception as e:
            yield SSEEvent(
                event_type=SSEEventType.ERROR,
                mgmt_name=mgmt_name,
                domain=domain_name,
                data={"error_message": str(e)},
            )

    @distributed_lock("asset_refresh:{mgmt_name}:{domain_name}", timeout=60, ttl=60)
    async def refresh_domain_assets(
        self,
        mgmt_name: str,
        domain_name: str,
        cache_mode: str = "auto",
    ) -> AsyncGenerator[SSEEvent]:
        """Refresh cached assets for a single domain.

        Unlike build_refresh_assets_cache, this does not delete existing
        assets first, does not touch any other domain, and does not run
        cluster/VSX relationship processing. Intended for callers that only
        need fresh policy/status data for a small, known set of domains
        without paying for a full multi-domain refresh.

        Acquires its own per-domain lock — do not call this from a context
        that already holds an asset_refresh lock covering the same
        mgmt_name/domain_name (use _refresh_domain_assets_impl instead in
        that case, e.g. build_refresh_assets_cache's own per-domain loop).

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            cache_mode: Cache mode passed through to the underlying API query.

        Yields:
            SSEEvent objects for progress, results, and errors.
        """
        async for event in self._refresh_domain_assets_impl(mgmt_name, domain_name, cache_mode):
            yield event

    async def _process_cluster_relationships(
        self,
        target_servers_and_domains: dict[str, list[str]],
        client_wrapper: Any,
    ) -> AsyncGenerator[SSEEvent]:
        """Process cluster relationships for all target servers.

        Args:
            target_servers_and_domains: Mapping of mgmt names to their domain lists.
            client_wrapper: ArodonataClient wrapper for relationship managers.

        Yields:
            SSEvent objects for progress and errors.
        """
        for mgmt_name in target_servers_and_domains:
            try:
                yield SSEEvent(
                    event_type=SSEEventType.LOG,
                    mgmt_name=mgmt_name,
                    data={
                        "message": f"Processing cluster relationships for {mgmt_name}",
                        "phase": "cluster_processing",
                    },
                )

                cluster_manager = self._cluster_manager_class(client=client_wrapper)
                cluster_member_mappings = await cluster_manager.build_cluster_member_mappings(mgmt_name=mgmt_name)

                if cluster_member_mappings:
                    updated = await cluster_manager.update_cluster_member_parent_asset_ids(
                        mgmt_name=mgmt_name,
                        cluster_member_mappings=cluster_member_mappings,
                    )

                    yield SSEEvent(
                        event_type=SSEEventType.LOG,
                        mgmt_name=mgmt_name,
                        data={
                            "message": f"Cluster relationships updated for {mgmt_name}",
                            "phase": "cluster_processing",
                            "relationships_updated": updated,
                        },
                    )

            except Exception as e:
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    data={"error_message": f"Cluster processing failed: {e}"},
                )

    async def _process_vsx_relationships(
        self,
        target_servers_and_domains: dict[str, list[str]],
        client_wrapper: Any,
    ) -> AsyncGenerator[SSEEvent]:
        """Process VSX/VS relationships for all target servers.

        Args:
            target_servers_and_domains: Mapping of mgmt names to their domain lists.
            client_wrapper: ArodonataClient wrapper for relationship managers.

        Yields:
            SSEvent objects for progress and errors.
        """
        for mgmt_name in target_servers_and_domains:
            try:
                yield SSEEvent(
                    event_type=SSEEventType.LOG,
                    mgmt_name=mgmt_name,
                    data={
                        "message": f"Processing VSX relationships for {mgmt_name}",
                        "phase": "vsx_processing",
                    },
                )

                # Get ALL domains from cache (not just filtered ones)
                cached_domains = await self._cache.get_domains(mgmt_name=mgmt_name)
                all_domain_names = [d.domain_name or "" for d in cached_domains]

                vsx_manager = self._vsx_manager_class(client=client_wrapper)

                # Build cross-domain VSX/VS mappings
                vsx_vs_mappings = await vsx_manager.build_cross_domain_vsx_vs_mapping(
                    mgmt_name=mgmt_name,
                    domains=all_domain_names,
                )

                if vsx_vs_mappings:
                    updated = await vsx_manager.update_vs_parent_asset_ids(
                        mgmt_name=mgmt_name,
                        vsx_vs_mappings=vsx_vs_mappings,
                    )

                    yield SSEEvent(
                        event_type=SSEEventType.LOG,
                        mgmt_name=mgmt_name,
                        data={
                            "message": f"VSX relationships updated for {mgmt_name}",
                            "phase": "vsx_processing",
                            "relationships_updated": updated,
                        },
                    )

            except Exception as e:
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    data={"error_message": f"VSX processing failed: {e}"},
                )

    async def _generate_summary(
        self,
        target_servers_and_domains: dict[str, list[str]],
        cluster_relationships_count: int,
        vsx_relationships_count: int,
        total_collected: int,
        errors: list[str],
    ) -> AsyncGenerator[SSEEvent]:
        """Generate and yield summary event with final statistics.

        Args:
            target_servers_and_domains: Mapping of mgmt names to their domain lists.
            cluster_relationships_count: Number of cluster relationships established.
            vsx_relationships_count: Number of VSX relationships established.
            errors: List of error messages encountered.

        Yields:
            SSEvent with summary statistics or error event if summary fails.
        """
        try:
            yield SSEEvent(
                event_type=SSEEventType.COMPLETE,
                data={
                    "total_results": total_collected,
                    "servers_processed": len(target_servers_and_domains),
                    "domains_processed": sum(len(domains) for domains in target_servers_and_domains.values()),
                    "cluster_relationships_established": cluster_relationships_count,
                    "vsx_relationships_established": vsx_relationships_count,
                    "errors": errors,
                },
            )

            log().debug(
                f"Asset refresh complete: {total_collected} assets, "
                f"{cluster_relationships_count} cluster relationships, "
                f"{vsx_relationships_count} VSX relationships, {len(errors)} errors"
            )
        except Exception as e:
            yield SSEEvent(
                event_type=SSEEventType.ERROR,
                data={"error_message": f"Failed to generate summary: {e}"},
            )

    async def _collect_mds_assets(self, mgmt_name: str, cache_mode: str = "auto") -> AsyncGenerator[SSEEvent]:
        """Collect MDS assets from a management server.

        Args:
            mgmt_name: Management server name.

        Yields:
            SSEEvent objects for progress and results.
        """
        from ..asset_transformer import AssetTransformer

        yield SSEEvent(
            event_type=SSEEventType.LOG,
            mgmt_name=mgmt_name,
            data={
                "message": f"Collecting MDS assets for {mgmt_name}",
                "phase": "collecting_mds",
            },
        )

        try:
            result = await self._api_query(
                mgmt_name=mgmt_name,
                command="show-mdss",
                details_level="full",
                payload={"show-domains": False},
                cache_mode=cache_mode,
            )

            if not result.success:
                yield SSEEvent(
                    event_type=SSEEventType.ERROR,
                    mgmt_name=mgmt_name,
                    data={
                        "error_message": result.message,
                        "error_code": result.code,
                    },
                )
                return

            assets_to_cache = []
            for obj in result.objects or []:
                # Extract domain from API response (for MDS it's usually "System Data")
                domain_info = obj.get("domain", {})
                if isinstance(domain_info, dict):
                    mds_domain_name = domain_info.get("name", "System Data")
                    mds_domain_uid = domain_info.get("uid", "")
                else:
                    log().warning(f"Unexpected domain format for MDS asset: {type(domain_info)}, using default")
                    mds_domain_name = "System Data"
                    mds_domain_uid = ""

                asset = AssetTransformer.transform_to_asset(
                    obj=obj,
                    mgmt_name=mgmt_name,
                    domain_name=mds_domain_name,
                    domain_uid=mds_domain_uid,
                )

                if asset:
                    assets_to_cache.append(asset)

            collected_count = 0
            if assets_to_cache:
                await self._cache.upsert_assets(assets_to_cache)
                collected_count = len(assets_to_cache)

            yield SSEEvent(
                event_type=SSEEventType.RESULT,
                mgmt_name=mgmt_name,
                data={
                    "result_type": "mds_assets",
                    "count": collected_count,
                },
            )

        except Exception as e:
            yield SSEEvent(
                event_type=SSEEventType.ERROR,
                mgmt_name=mgmt_name,
                data={"error_message": f"MDS collection failed: {e}"},
            )


__all__ = ["AssetRefreshService"]
