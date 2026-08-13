"""Asset transformation utilities for Check Point API objects.

This module provides methods to transform API response objects into Asset models
with proper validation and relationship handling.
"""

from __future__ import annotations

from typing import Any

from ..cache.models import Asset
from ..logger import lazy_logger

log = lazy_logger("arodonata.api.asset_transformer")


class AssetTransformer:
    """Handles transformation of API objects to Asset models."""

    @staticmethod
    def transform_to_asset(
        obj: Any,
        mgmt_name: str,
        domain_name: str,
        domain_uid: str,
    ) -> Asset | None:
        """Transform API object to Asset model.

        Args:
            obj: API response object.
            mgmt_name: Management server name.
            domain_name: Domain name.
            domain_uid: Domain UID.

        Returns:
            Asset object or None if transformation fails.
        """
        # Validate input type
        if not isinstance(obj, dict):
            return None

        # Extract and validate required fields
        required_fields = AssetTransformer._extract_required_fields(obj)
        if not required_fields:
            return None

        try:
            name, obj_type, obj_uid = required_fields

            # Correction: checkpoint-host in SMC User domain is an SMS
            # SMC and Domain server are both "checkpoint-host".
            # But SMC need to have a special type to be processed as clish-enabled.
            if obj_type == "checkpoint-host" and domain_name == "SMC User":
                obj_type = "sms"

            # Create asset with validation
            return AssetTransformer._create_asset_object(
                name=name,
                obj_type=obj_type,
                obj_uid=obj_uid,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                domain_uid=domain_uid,
                raw_object=obj,
            )

        except (ValueError, KeyError, TypeError) as e:
            # Predictable transformation errors
            log().warning(
                f"Transformation failed for object {obj.get('name', 'unknown')} on {mgmt_name}:{domain_name}: {e}"
            )
            return None
        except Exception as e:
            # Unexpected errors
            log().error(
                f"Unexpected error transforming object {obj.get('name', 'unknown')} on {mgmt_name}:{domain_name}: {e}"
            )
            raise

    @staticmethod
    def _extract_required_fields(obj: dict[str, Any]) -> tuple[str, str, str] | None:
        """Extract and validate required fields from API object.

        Args:
            obj: API response object.

        Returns:
            Tuple of (name, type, uid) or None if validation fails.
        """
        name = obj.get("name", "").strip()
        obj_type = obj.get("type", "").strip()
        obj_uid = obj.get("uid", "").strip()

        if not all([name, obj_type, obj_uid]):
            return None

        return name, obj_type, obj_uid

    @staticmethod
    def _create_asset_object(
        name: str,
        obj_type: str,
        obj_uid: str,
        mgmt_name: str,
        domain_name: str,
        domain_uid: str,
        raw_object: dict[str, Any],
        parent_asset_id: str | None = None,
    ) -> Asset:
        """Create Asset object with validated parameters.

        Args:
            name: Asset name.
            obj_type: Asset type.
            obj_uid: Asset UID.
            mgmt_name: Management server name.
            domain_name: Domain name.
            domain_uid: Domain UID.
            raw_object: Original API object for additional fields.
            parent_asset_id: Optional parent asset ID.

        Returns:
            Created Asset object.
        """
        # Create asset_id with proper formatting
        # Standardize: For system/MDS assets, domain_name is empty string in the DB/Logic
        # Ensure we don't have leading/trailing colons
        clean_domain = domain_name.strip()
        asset_id = f"{mgmt_name}:{clean_domain}:{name}"

        # Extract optional fields with defaults
        hardware_val = raw_object.get("hardware")
        if isinstance(hardware_val, dict):
            hardware = hardware_val.get("name", "").strip()
        else:
            hardware = str(hardware_val or "").strip()

        # Extract comments with fallback to nested structure
        comments_val = raw_object.get("comments", "")
        if not isinstance(comments_val, str):
            comments_val = ""
        comments = comments_val.strip()

        # Extract tags as list of {name, color} dicts
        raw_tags = raw_object.get("tags", [])
        tag_dicts: list[dict[str, Any]] = []
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, str):
                    tag_dicts.append({"name": t, "color": ""})
                elif isinstance(t, dict):
                    tn = t.get("name", "")
                    if tn:
                        tag_dicts.append({"name": tn, "color": t.get("color", "") or ""})

        return Asset(
            asset_id=asset_id,
            name=name,
            asset_type=obj_type,
            asset_hardware=hardware,
            asset_uid=obj_uid,
            domain_name=domain_name or "",
            domain_uid=domain_uid.strip() if domain_uid else "",
            mgmt_name=mgmt_name,
            parent_asset_id=parent_asset_id or "",
            path="",
            comments=comments,
            tags=tag_dicts,
            raw_data=raw_object,
        )

    @staticmethod
    def build_cluster_member_mappings(objects_list: list[dict[str, Any]]) -> dict[str, str]:
        """Build mapping from cluster member names to cluster asset IDs.

        Args:
            objects_list: List of objects from show-gateways-and-servers.

        Returns:
            Dictionary mapping member names to cluster names.
        """

        cluster_member_mappings = {}
        cluster_count = 0
        member_count = 0

        for obj in objects_list:
            if isinstance(obj, dict):
                obj_type = obj.get("type", "")
                obj_name = obj.get("name", "")

                # Find cluster objects and map their members
                if obj_type == "CpmiGatewayCluster" and obj_name:
                    cluster_name = obj_name
                    member_names = obj.get("cluster-member-names", [])

                    if isinstance(member_names, list):
                        cluster_count += 1
                        for member_name in member_names:
                            if member_name:
                                cluster_member_mappings[member_name] = cluster_name
                                member_count += 1

        log().debug(
            f"Built cluster mappings: {cluster_count} clusters with {member_count} total members. "
            f"Mappings: {cluster_member_mappings}"
        )
        return cluster_member_mappings

    @staticmethod
    def transform_to_asset_with_cluster_relationships(
        obj: Any,
        mgmt_name: str,
        domain_name: str,
        domain_uid: str,
        cluster_member_mappings: dict[str, str],
    ) -> Asset | None:
        """Transform API object to Asset with cluster relationship handling.

        Args:
            obj: API response object.
            mgmt_name: Management server name.
            domain_name: Domain name.
            domain_uid: Domain UID.
            cluster_member_mappings: Mapping from member names to cluster names.

        Returns:
            Asset object or None if transformation fails.
        """
        # Validate input type
        if not isinstance(obj, dict):
            return None

        # Extract and validate required fields
        required_fields = AssetTransformer._extract_required_fields(obj)
        if not required_fields:
            return None

        try:
            name, obj_type, obj_uid = required_fields

            # Determine parent_asset_id for cluster relationships only
            # VSX/VS relationships will be handled later
            parent_asset_id = AssetTransformer._extract_cluster_parent_asset_id(
                obj, mgmt_name, domain_name, cluster_member_mappings
            )

            # Create asset with validation
            return AssetTransformer._create_asset_object(
                name=name,
                obj_type=obj_type,
                obj_uid=obj_uid,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                domain_uid=domain_uid,
                raw_object=obj,
                parent_asset_id=parent_asset_id,
            )

        except (ValueError, KeyError, TypeError) as e:
            # Predictable transformation errors
            log().warning(
                f"Transformation with clusters failed for object {obj.get('name', 'unknown')} on {mgmt_name}:{domain_name}: {e}"
            )
            return None
        except Exception as e:
            # Unexpected errors
            log().error(
                f"Unexpected error transforming object {obj.get('name', 'unknown')} with clusters on {mgmt_name}:{domain_name}: {e}"
            )
            raise

    @staticmethod
    def _extract_cluster_parent_asset_id(
        obj: dict[str, Any],
        mgmt_name: str,
        domain_name: str,
        cluster_member_mappings: dict[str, str],
    ) -> str | None:
        """Extract parent asset ID for cluster relationships only.

        Args:
            obj: API response object.
            mgmt_name: Management server name.
            domain_name: Domain name.
            cluster_member_mappings: Mapping from member names to cluster names.

        Returns:
            Parent asset ID or None if not found.
        """
        obj_name = obj.get("name", "")
        obj_type = obj.get("type", "")

        # For VS objects, don't set parent_asset_id here - will be handled later
        # Handled by VSXRelationshipManager.build_cross_domain_vsx_vs_mapping()
        if obj_type in ["CpmiVsNetobj", "vs_slot_obj"]:
            return None

        # Check for cluster member relationship
        if obj_name in cluster_member_mappings:
            cluster_name = cluster_member_mappings[obj_name]
            parent_asset_id = f"{mgmt_name}:{domain_name}:{cluster_name}"
            log().debug(
                f"Cluster member {obj_name} mapped to parent {parent_asset_id} "
                f"(cluster: {cluster_name}, domain: {domain_name})"
            )
            return parent_asset_id

        # Handle other parent relationship types
        parent_fields = ["cluster-uid", "parent-uid"]

        for field in parent_fields:
            if field in obj and obj[field]:
                parent_id = str(obj[field]).strip()
                if parent_id:
                    log().debug(f"Found parent {field} for {obj_name}: {parent_id}")
                    return parent_id

        return None


__all__ = ["AssetTransformer"]
