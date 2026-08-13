"""Cluster/cluster-member relationship management for Check Point API objects.

This module provides methods to handle cluster and cluster-member object relationships,
including building parent-child mappings and parent asset ID updates.
"""

from __future__ import annotations

from ..api.client import ArodonataClient
from ..logger import lazy_logger

log = lazy_logger("arodonata.cluster_relationship_manager")


class ClusterRelationshipManager:
    """Manages cluster/cluster-member relationships for Check Point objects."""

    def __init__(self, client: ArodonataClient) -> None:
        """Initialize with ArodonataClient instance.

        Args:
            client: ArodonataClient instance for cache access.
        """
        self._client = client
        log().trace("ClusterRelationshipManager initialized")

    async def build_cluster_member_mappings(self, mgmt_name: str) -> dict[str, str]:
        """Build mapping from cluster member names to cluster asset IDs.

        Queries the cache for all assets of a management server and extracts
        cluster-to-cluster-member relationships from raw_data.

        Args:
            mgmt_name: Management server name.

        Returns:
            Dictionary mapping cluster member names to cluster asset IDs.
        """
        # Get all assets for this management server
        all_assets = await self._client.cache.get_assets(mgmt_names=[mgmt_name])

        cluster_member_mappings = {}
        cluster_count = 0
        member_count = 0

        for asset in all_assets:
            # Only process cluster objects
            if asset.asset_type == "CpmiGatewayCluster":
                cluster_asset_id = asset.asset_id

                # Extract cluster member names from raw_data
                raw_data = asset.raw_data
                if isinstance(raw_data, dict):
                    member_names = raw_data.get("cluster-member-names", [])

                    if isinstance(member_names, list):
                        cluster_count += 1
                        for member_name in member_names:
                            if member_name:
                                cluster_member_mappings[member_name] = cluster_asset_id
                                member_count += 1

        log().debug(
            f"Built cluster mappings for {mgmt_name}: {cluster_count} clusters with {member_count} total members"
        )

        return cluster_member_mappings

    async def update_cluster_member_parent_asset_ids(
        self, mgmt_name: str, cluster_member_mappings: dict[str, str]
    ) -> int:
        """Update parent_asset_id for cluster member objects in the cache.

        Args:
            mgmt_name: Management server name.
            cluster_member_mappings: Mapping from cluster member names to cluster asset IDs.

        Returns:
            Number of relationships updated.
        """
        updated_count = 0

        try:
            # Get all assets for this management server
            all_assets = await self._client.cache.get_assets(mgmt_names=[mgmt_name])

            # Filter for cluster member assets
            cluster_member_assets = [asset for asset in all_assets if asset.asset_type == "cluster-member"]

            log().debug(f"Found {len(cluster_member_assets)} cluster member assets for {mgmt_name}")

            if not cluster_member_assets:
                log().debug(f"No cluster member assets found for {mgmt_name}")
                return 0

            assets_to_update = []
            for asset in cluster_member_assets:
                # Check if this cluster member has a mapping
                if asset.name in cluster_member_mappings:
                    cluster_asset_id = cluster_member_mappings[asset.name]

                    if asset.parent_asset_id != cluster_asset_id:
                        # Update the asset in cache
                        asset.parent_asset_id = cluster_asset_id
                        assets_to_update.append(asset)
                        updated_count += 1
                        log().trace(f"Marked cluster member {asset.asset_id} for update to parent {cluster_asset_id}")
                    else:
                        log().trace(f"Cluster member {asset.asset_id} already has correct parent {cluster_asset_id}")

            if assets_to_update:
                log().debug(f"Bulk updating {len(assets_to_update)} cluster member relationships for {mgmt_name}")
                await self._client.cache.upsert_assets(assets_to_update)

        except Exception as e:
            log().error(f"Error updating cluster member parent_asset_ids for {mgmt_name}: {e}")

        return updated_count


__all__ = ["ClusterRelationshipManager"]
