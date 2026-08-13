"""VSX/VS relationship management for Check Point API objects.

This module provides methods to handle VSX and VS object relationships,
including cross-domain relationship building and parent asset ID updates.
"""

from __future__ import annotations

from typing import Any

from ..api.client import ArodonataClient
from ..logger import lazy_logger

log = lazy_logger("arodonata.vsx_relationship_manager")


class VSXRelationshipManager:
    """Manages VSX/VS relationships for Check Point objects."""

    def __init__(self, client: ArodonataClient) -> None:
        """Initialize with ArodonataClient instance.

        Args:
            client: ArodonataClient instance for API calls.
        """
        self._client = client
        log().trace("VSXRelationshipManager initialized")

    async def get_vsx_objects(self, mgmt_name: str, domain: str) -> list[dict[str, Any]]:
        """Get VSX objects from a management server and domain.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            List of VSX objects with their details.
        """
        try:
            response = await self._client.api_query(
                mgmt_name=mgmt_name,
                command="show-generic-objects",
                domain=domain,
                details_level="full",
                payload={"class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj"},
            )

            if not response.success:
                return []

            objects_list = response.objects or []
            # Filter for VSX objects (vsx_slot_obj type with vsid = 0)
            return [
                obj
                for obj in objects_list
                if isinstance(obj, dict) and obj.get("type") == "vsx_slot_obj" and obj.get("vsid") == 0
            ]

        except Exception as e:
            log().warning(f"Failed to get VSX objects for {mgmt_name}:{domain}: {e}")
            return []

    async def get_vs_objects(self, mgmt_name: str, domain: str) -> list[dict[str, Any]]:
        """Get VS (Virtual System) objects from a management server and domain.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            List of VS objects with their details.
        """
        try:
            response = await self._client.api_query(
                mgmt_name=mgmt_name,
                command="show-generic-objects",
                domain=domain,
                details_level="full",
                payload={"class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj"},
            )

            if not response.success:
                return []

            objects_list = response.objects or []
            # Filter for VS objects (vs_slot_obj type with vsid > 0)
            return [
                obj
                for obj in objects_list
                if isinstance(obj, dict) and obj.get("type") == "vs_slot_obj" and obj.get("vsid", 0) > 0
            ]

        except Exception as e:
            log().warning(f"Failed to get VS objects for {mgmt_name}:{domain}: {e}")
            return []

    async def _collect_vsx_and_vs_objects(
        self, mgmt_name: str, domains: list[str]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Collect VSX and VS objects from all domains, tagging each with its domain.

        A domain that fails to collect (e.g. an API error) is logged and
        skipped rather than raised — collection continues with the remaining
        domains.

        Args:
            mgmt_name: Management server name.
            domains: List of domain names to process.

        Returns:
            Tuple of (all VSX objects, all VS objects), each tagged with "_domain".
        """
        all_vsx_objects: list[dict[str, Any]] = []
        all_vs_objects: list[dict[str, Any]] = []

        for domain in domains:
            try:
                vsx_objects = await self.get_vsx_objects(mgmt_name, domain)
                vs_objects = await self.get_vs_objects(mgmt_name, domain)

                # Add domain information to each object
                for vsx_obj in vsx_objects:
                    if isinstance(vsx_obj, dict):
                        vsx_obj["_domain"] = domain
                        all_vsx_objects.append(vsx_obj)

                for vs_obj in vs_objects:
                    if isinstance(vs_obj, dict):
                        vs_obj["_domain"] = domain
                        all_vs_objects.append(vs_obj)

            except Exception as e:
                # Failed to collect from this domain, log error and continue
                log().error(f"Failed to collect VSX/VS objects from domain {domain} on {mgmt_name}: {e}")
                continue

        return all_vsx_objects, all_vs_objects

    def _build_vsx_uid_index(self, all_vsx_objects: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
        """Build a VSX UID to (name, domain) index covering both slot and gateway UIDs.

        Objects missing a "uid" or "name" are silently skipped.

        Args:
            all_vsx_objects: VSX objects collected across all domains.

        Returns:
            Mapping from VSX slot UID and gateway UID to {"name": ..., "domain": ...}.
        """
        vsx_uid_to_info: dict[str, dict[str, str]] = {}

        for vsx_obj in all_vsx_objects:
            if isinstance(vsx_obj, dict) and vsx_obj.get("uid") and vsx_obj.get("name"):
                vsx_uid = vsx_obj["uid"]
                vsx_name = vsx_obj["name"]
                vsx_domain = vsx_obj.get("_domain", "")
                vsx_gateway_uid = vsx_obj.get("vsxGateway")

                # Map both the slot UID and the gateway UID to the same VSX info
                vsx_uid_to_info[vsx_uid] = {"name": vsx_name, "domain": vsx_domain}
                if vsx_gateway_uid:
                    vsx_uid_to_info[vsx_gateway_uid] = {
                        "name": vsx_name,
                        "domain": vsx_domain,
                    }

        return vsx_uid_to_info

    def _build_vs_to_vsx_mapping(
        self,
        all_vs_objects: list[dict[str, Any]],
        vsx_uid_to_info: dict[str, dict[str, str]],
        mgmt_name: str,
    ) -> dict[str, str]:
        """Build the VS UID/domain:name to VSX asset ID mapping.

        VS objects missing a "uid" or "vsxGateway", or whose "vsxGateway"
        doesn't resolve in vsx_uid_to_info, are silently skipped.

        Args:
            all_vs_objects: VS objects collected across all domains.
            vsx_uid_to_info: Index from _build_vsx_uid_index.
            mgmt_name: Management server name, used to build VSX asset IDs.

        Returns:
            Dictionary mapping VS UIDs and domain:name to VSX asset IDs.
        """
        vs_to_vsx_mapping: dict[str, str] = {}

        for vs_obj in all_vs_objects:
            if isinstance(vs_obj, dict) and vs_obj.get("uid") and vs_obj.get("vsxGateway"):
                vs_uid = vs_obj["uid"]
                vsx_gateway_uid = vs_obj["vsxGateway"]
                vs_domain = vs_obj.get("_domain", "")
                vs_name = vs_obj.get("name", "unknown")

                # Find the VSX info for this gateway UID (could be in any domain)
                vsx_info = vsx_uid_to_info.get(vsx_gateway_uid)
                if vsx_info:
                    # Create asset_id format for the VSX using its actual domain
                    vsx_asset_id = f"{mgmt_name}:{vsx_info['domain']}:{vsx_info['name']}"

                    # Map using both the VS UID and the VS name (with domain for name-based lookup)
                    vs_to_vsx_mapping[vs_uid] = vsx_asset_id
                    vs_to_vsx_mapping[f"{vs_domain}:{vs_name}"] = vsx_asset_id

        return vs_to_vsx_mapping

    async def build_cross_domain_vsx_vs_mapping(self, mgmt_name: str, domains: list[str]) -> dict[str, str]:
        """Build mapping from VS objects to their parent VSX objects across all domains.

        Args:
            mgmt_name: Management server name.
            domains: List of domain names to process.

        Returns:
            Dictionary mapping VS UIDs and domain:name to VSX asset IDs.
        """
        all_vsx_objects, all_vs_objects = await self._collect_vsx_and_vs_objects(mgmt_name, domains)
        vsx_uid_to_info = self._build_vsx_uid_index(all_vsx_objects)
        vs_to_vsx_mapping = self._build_vs_to_vsx_mapping(all_vs_objects, vsx_uid_to_info, mgmt_name)

        log().debug(f"Built VSX/VS mapping with {len(vs_to_vsx_mapping)} entries")
        return vs_to_vsx_mapping

    def _find_vsx_asset_id(self, asset: Any, vsx_vs_mappings: dict[str, str]) -> str | None:
        """Find VSX asset ID for a VS asset using UID or domain:name lookup.

        Args:
            asset: VS asset to find parent for.
            vsx_vs_mappings: Mapping from VS UIDs/names to VSX asset IDs.

        Returns:
            VSX asset ID or None if not found.
        """
        # Try UID-based lookup
        if asset.asset_uid in vsx_vs_mappings:
            return vsx_vs_mappings[asset.asset_uid]

        # Try domain:name-based lookup if UID not found
        if asset.domain_name:
            name_key = f"{asset.domain_name}:{asset.name}"
            if name_key in vsx_vs_mappings:
                return vsx_vs_mappings[name_key]

        return None

    async def update_vs_parent_asset_ids(self, mgmt_name: str, vsx_vs_mappings: dict[str, str]) -> int:
        """Update parent_asset_id for VS objects in the cache.

        Args:
            mgmt_name: Management server name.
            vsx_vs_mappings: Mapping from VS UIDs to VSX asset IDs.

        Returns:
            Number of relationships updated.
        """
        updated_count = 0

        try:
            # Get all assets for this management server (across all domains)
            all_assets = await self._client.cache.get_assets(mgmt_names=[mgmt_name])

            # Debug: Log total assets found and VS assets specifically
            vs_assets = [asset for asset in all_assets if asset.asset_type in ["CpmiVsNetobj", "vs_slot_obj"]]

            log().debug(f"Found {len(all_assets)} total assets for {mgmt_name}, {len(vs_assets)} VS assets")

            if not vs_assets:
                log().debug(f"No VS assets found for {mgmt_name}")
                return 0

            assets_to_update = []
            for asset in all_assets:
                # Check if this is a VS object that needs parent_asset_id update
                if asset.asset_type in ["CpmiVsNetobj", "vs_slot_obj"]:
                    vsx_asset_id = self._find_vsx_asset_id(asset, vsx_vs_mappings)

                    if vsx_asset_id and asset.parent_asset_id != vsx_asset_id:
                        # Update the asset in cache
                        old_parent_asset_id = asset.parent_asset_id
                        asset.parent_asset_id = vsx_asset_id
                        assets_to_update.append(asset)
                        updated_count += 1
                        log().debug(
                            f"Marked VS {asset.asset_id} for update from {old_parent_asset_id} to {vsx_asset_id}"
                        )
                    elif vsx_asset_id:
                        log().trace(f"VS {asset.asset_id} already has correct parent {vsx_asset_id}")

            if assets_to_update:
                log().debug(f"Bulk updating {len(assets_to_update)} VS relationships for {mgmt_name}")
                await self._client.cache.upsert_assets(assets_to_update)

        except Exception as e:
            log().error(f"Error updating VS parent_asset_ids for {mgmt_name}: {e}")

        return updated_count


__all__ = ["VSXRelationshipManager"]
