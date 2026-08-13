"""Object extractor for network objects."""

from typing import Any

from .base import BaseExtractor, ExtractionContext


class ObjectExtractor(BaseExtractor):
    """Extractor for network objects (hosts, networks, groups, etc.)."""

    def extract(self, raw_data: dict[str, Any], context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from raw API response.

        Args:
            raw_data: Raw API response data.
            context: Extraction context with mgmt/domain info.

        Returns:
            Dictionary with extracted fields suitable for CPObject model.
        """
        obj_type = raw_data.get("type", "")

        return {
            # Common fields
            "uid": raw_data.get("uid", ""),
            "name": raw_data.get("name", ""),
            "type": obj_type,
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            # Type-specific fields
            **self._extract_type_fields(raw_data, obj_type),
            # Raw data (full response)
            "raw_data": raw_data,
        }

    def _extract_type_fields(self, raw_data: dict[str, Any], obj_type: str) -> dict[str, Any]:
        """Extract type-specific fields from raw data.

        Args:
            raw_data: Raw API response data.
            obj_type: Object type (host, network, group, etc.).

        Returns:
            Dictionary with type-specific fields.
        """
        extractor = self._TYPE_EXTRACTORS.get(obj_type)
        fields = extractor(self, raw_data) if extractor else {}
        fields.update(self._extract_common_optional_fields(raw_data))
        return fields

    def _extract_host_fields(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Extract host-specific fields."""
        return {"ipv4_address": raw_data.get("ipv4-address", "")}

    def _extract_network_fields(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Extract network-specific fields."""
        return {
            "subnet4": raw_data.get("subnet4", ""),
            "subnet_mask": raw_data.get("subnet-mask", ""),
        }

    def _extract_group_fields(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Extract member UIDs for group/service-group types."""
        fields: dict[str, Any] = {}
        members = raw_data.get("members", {})
        if isinstance(members, dict):
            member_objs = members.get("objects", [])
            member_uids = [m.get("uid", "") for m in member_objs if isinstance(m, dict)]
            fields["members"] = ",".join(filter(None, member_uids))
        elif isinstance(members, list):
            member_uids = [m.get("uid", "") for m in members if isinstance(m, dict)]
            fields["members"] = ",".join(filter(None, member_uids))
        return fields

    def _extract_address_range_fields(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Extract address-range-specific fields."""
        return {
            "ipv4_address_first": raw_data.get("ipv4-address-first", ""),
            "ipv4_address_last": raw_data.get("ipv4-address-last", ""),
        }

    # Dispatch table: obj_type -> unbound extractor method. Looked up in
    # _extract_type_fields, which passes `self` explicitly.
    _TYPE_EXTRACTORS: dict[str, Any] = {
        "host": _extract_host_fields,
        "network": _extract_network_fields,
        "group": _extract_group_fields,
        "service-group": _extract_group_fields,
        "address-range": _extract_address_range_fields,
    }

    def _extract_common_optional_fields(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Extract optional fields that may exist on any object type.

        Args:
            raw_data: Raw API response data.

        Returns:
            Dictionary with any of comments/color/tags present in raw_data.
        """
        fields: dict[str, Any] = {}

        if "comments" in raw_data:
            fields["comments"] = raw_data["comments"]

        if "color" in raw_data:
            fields["color"] = raw_data["color"]

        if "tags" in raw_data:
            tags = raw_data["tags"]
            if isinstance(tags, list):
                fields["tags"] = ",".join(tags)
            else:
                fields["tags"] = str(tags) if tags else ""

        return fields
