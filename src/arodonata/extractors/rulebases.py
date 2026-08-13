"""Rulebase extractors for access, NAT, HTTPS, and threat rules."""

from typing import Any

from .base import BaseExtractor, ExtractionContext


class AccessRuleExtractor(BaseExtractor):
    """Extractor for access control rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from access rule API response.

        Args:
            raw_data: Raw API response data.
            context: Extraction context with mgmt/domain info.

        Returns:
            Dictionary with extracted fields suitable for AccessRule model.
        """
        # Extract source names/UIDs (convert list to comma-separated string)
        sources = ",".join(self._extract_names_or_uids(raw_data.get("source", []), context))

        # Extract destination names/UIDs (convert list to comma-separated string)
        destinations = ",".join(self._extract_names_or_uids(raw_data.get("destination", []), context))

        # Extract service names/UIDs (convert list to comma-separated string)
        services = ",".join(self._extract_names_or_uids(raw_data.get("service", []), context))

        # Extract action (e.g., {"accept": true} -> "accept")
        action = self._extract_action(raw_data.get("action", {}))

        # Extract track type (e.g., {"type": "Log"} -> "Log")
        track = self._extract_track(raw_data.get("track", {}))

        # Extract layer name
        layer = raw_data.get("layer", {})
        if isinstance(layer, str):
            layer_name = layer
        elif isinstance(layer, dict):
            layer_name = layer.get("name", "")
        else:
            layer_name = ""

        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "sources": sources,
            "destinations": destinations,
            "services": services,
            "action": action,
            "track": track,
            "layer_name": layer_name,
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }

    def _extract_names_or_uids(self, items: list | dict, context: ExtractionContext | None = None) -> list[str]:
        """Extract Names or UIDs from a list of objects.

        Args:
            items: List of objects with name/uid field, or dict with 'objects' key.
            context: Optional extraction context for resolution.

        Returns:
            List of Name/UID strings.
        """
        if isinstance(items, dict):
            items = items.get("objects", [])

        if not isinstance(items, list):
            return []

        result = []
        for item in items:
            if isinstance(item, dict):
                result.append(item.get("uid") or item.get("name", ""))
            else:
                uid = str(item)
                # Look up name in context objects_map if available
                objects_map = getattr(context, "objects_map", None) if context else None
                name = objects_map.get(uid) if objects_map else None
                result.append(name or uid)
        return result

    def _extract_action(self, action: dict | str) -> str:
        """Extract action type from action dict or string.

        Args:
            action: Action dict (e.g., {"accept": true}) or string (e.g., "accept").

        Returns:
            Action string (e.g., "accept").
        """
        # Common Action UIDs to map if we see them
        action_map = {
            "6c488338-8eec-4103-ad21-cd461ac2c472": "Accept",
            "6c488338-8eec-4103-ad21-cd461ac2c473": "Drop",
        }

        # Handle string format
        if isinstance(action, str):
            if action in action_map:
                return action_map[action]
            return action.lower() if action else "accept"

        # Handle dict format
        if isinstance(action, dict):
            # If inlined name is available
            name = action.get("name")
            if name:
                return name

            for key in ("accept", "drop", "reject", "ask"):
                if action.get(key):
                    return key

            # Check UID
            uid = action.get("uid")
            if uid in action_map:
                return action_map[uid]

        return "accept"  # Default

    def _extract_track(self, track: dict | str) -> str:
        """Extract track type from track dict or string.

        Args:
            track: Track dict (e.g., {"type": "Log"}) or string (e.g., "Log").

        Returns:
            Track string (e.g., "Log").
        """
        # Handle string format
        if isinstance(track, str):
            return track

        # Handle dict format
        if isinstance(track, dict):
            return track.get("type", "")

        return ""


class NATRuleExtractor(BaseExtractor):
    """Extractor for NAT rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from NAT rule API response.

        Args:
            raw_data: Raw API response data.
            context: Extraction context with mgmt/domain info.

        Returns:
            Dictionary with extracted fields suitable for NATRule model.
        """
        # Extract layer name
        layer = raw_data.get("layer", {})
        if isinstance(layer, str):
            layer_name = layer
        elif isinstance(layer, dict):
            layer_name = layer.get("name", "")
        else:
            layer_name = ""

        # Helper to extract name or UID from value which could be a dict or string
        def _to_str(val: Any) -> str:
            if isinstance(val, dict):
                return val.get("name") or val.get("uid") or str(val)
            return str(val) if val is not None else ""

        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "original_source": _to_str(raw_data.get("original-source")),
            "original_destination": _to_str(raw_data.get("original-destination")),
            "original_service": _to_str(raw_data.get("original-service")),
            "translated_source": _to_str(raw_data.get("translated-source")),
            "translated_destination": _to_str(raw_data.get("translated-destination")),
            "translated_service": _to_str(raw_data.get("translated-service")),
            "layer_name": layer_name,
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }


class HTTPSRuleExtractor(BaseExtractor):
    """Extractor for HTTPS inspection rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from HTTPS rule API response.

        Args:
            raw_data: Raw API response data.
            context: Extraction context with mgmt/domain info.

        Returns:
            Dictionary with extracted fields suitable for HTTPSRule model.
        """
        # Reuse AccessRuleExtractor methods for common fields
        access_extractor = AccessRuleExtractor()

        # Extract source names/UIDs (convert list to comma-separated string)
        sources = ",".join(access_extractor._extract_names_or_uids(raw_data.get("source", []), context))

        # Extract destination names/UIDs (convert list to comma-separated string)
        destinations = ",".join(access_extractor._extract_names_or_uids(raw_data.get("destination", []), context))

        # Extract track type
        track = access_extractor._extract_track(raw_data.get("track", {}))

        # Extract layer name
        layer = raw_data.get("layer", {})
        if isinstance(layer, str):
            layer_name = layer
        elif isinstance(layer, dict):
            layer_name = layer.get("name", "")
        else:
            layer_name = ""

        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "sources": sources,
            "destinations": destinations,
            "track": track,
            "layer_name": layer_name,
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }


class ThreatRuleExtractor(BaseExtractor):
    """Extractor for threat prevention rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from threat rule API response.

        Args:
            raw_data: Raw API response data.
            context: Extraction context with mgmt/domain info.

        Returns:
            Dictionary with extracted fields suitable for ThreatRule model.
        """
        # Reuse AccessRuleExtractor for track extraction
        access_extractor = AccessRuleExtractor()

        # Extract track type
        track = access_extractor._extract_track(raw_data.get("track", {}))

        # Extract protection names (convert list to comma-separated string)
        protections_list = self._extract_protections(raw_data.get("protections", []))
        protections = ",".join(protections_list) if protections_list else ""

        # Extract layer name
        layer = raw_data.get("layer", {})
        if isinstance(layer, str):
            layer_name = layer
        elif isinstance(layer, dict):
            layer_name = layer.get("name", "")
        else:
            layer_name = ""

        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "track": track,
            "protections": protections,
            "layer_name": layer_name,
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }

    def _extract_protections(self, protections: list) -> list[str]:
        """Extract protection names from protections list.

        Args:
            protections: List of protection objects with name field.

        Returns:
            List of protection names.
        """
        if not isinstance(protections, list):
            return []

        return [p.get("name", "") for p in protections if isinstance(p, dict)]
