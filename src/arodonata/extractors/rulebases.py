"""Rulebase extractors for access, NAT, HTTPS, and threat rules.

Every reference field resolves through ``context.objects_map`` ({uid: name}, built from the response's
``objects-dictionary``) and falls back to the uid when unresolved. ``layer_name`` is not extracted: rules do not
carry their layer; the caller sets it from the response's top-level ``name`` (NAT: the package name).
"""

from typing import Any

from .base import BaseExtractor, ExtractionContext


def resolve_ref(value: Any, objects_map: dict[str, str] | None) -> str:
    """One reference as a name: a uid string via ``objects_map``; a dict by its ``name``, else its resolved ``uid``."""
    names = objects_map or {}
    if isinstance(value, dict):
        name = value.get("name")
        if name:
            return str(name)
        uid = value.get("uid")
        return names.get(str(uid), str(uid)) if uid else ""
    if value is None:
        return ""
    return names.get(str(value), str(value))


def _map(context: ExtractionContext | None) -> dict[str, str] | None:
    return getattr(context, "objects_map", None) if context else None


class AccessRuleExtractor(BaseExtractor):
    """Extractor for access control rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from an access rule.

        Args:
            raw_data: One rule from a ``show-access-rulebase`` response.
            context: Extraction context with mgmt/domain info and the layer's objects map.

        Returns:
            Fields for ``RulebaseAccess`` except ``id`` and ``layer_name``.
        """
        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "sources": ",".join(self._extract_names_or_uids(raw_data.get("source", []), context)),
            "destinations": ",".join(self._extract_names_or_uids(raw_data.get("destination", []), context)),
            "services": ",".join(self._extract_names_or_uids(raw_data.get("service", []), context)),
            "action": self._extract_action(raw_data.get("action", ""), context),
            "track": self._extract_track(raw_data.get("track", {}), context),
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
                result.append(resolve_ref(item, _map(context)))
        return result

    def _extract_action(self, action: Any, context: ExtractionContext | None = None) -> str:
        """The action's CP name (``Accept``, ``Drop``, ``Inner Layer``...), the uid when unresolved.

        A missing or empty action is treated as accept (``Accept``).
        """
        return resolve_ref(action, _map(context)) or "Accept"

    def _extract_track(self, track: Any, context: ExtractionContext | None = None) -> str:
        """The track type's CP name (``Log``, ``None``...): ``track.type`` (uid string or dict), or a bare track value."""
        if isinstance(track, dict):
            return resolve_ref(track.get("type"), _map(context))
        return resolve_ref(track, _map(context)) if track else ""


class NATRuleExtractor(BaseExtractor):
    """Extractor for NAT rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from a NAT rule (fields for ``RulebaseNAT`` except ``id`` and ``layer_name``)."""
        names = _map(context)

        def _to_str(val: Any) -> str:
            if isinstance(val, dict):
                return resolve_ref(val, names) or str(val)
            return resolve_ref(val, names)

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
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }


class HTTPSRuleExtractor(BaseExtractor):
    """Extractor for HTTPS inspection rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from an HTTPS rule (fields for ``RulebaseHTTPS`` except ``id`` and ``layer_name``)."""
        access_extractor = AccessRuleExtractor()
        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "sources": ",".join(access_extractor._extract_names_or_uids(raw_data.get("source", []), context)),
            "destinations": ",".join(access_extractor._extract_names_or_uids(raw_data.get("destination", []), context)),
            "track": access_extractor._extract_track(raw_data.get("track", {}), context),
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }


class ThreatRuleExtractor(BaseExtractor):
    """Extractor for threat prevention rules."""

    def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]:
        """Extract model fields from a threat rule (fields for ``RulebaseThreat`` except ``id`` and ``layer_name``)."""
        track = AccessRuleExtractor()._extract_track(raw_data.get("track", {}), context)
        protections = self._extract_protections(raw_data.get("protections", []), context)
        return {
            "uid": raw_data.get("uid", ""),
            "rule_number": raw_data.get("rule-number", 0),
            "name": raw_data.get("name", ""),
            "enabled": raw_data.get("enabled", True),
            "track": track,
            "protections": ",".join(protections),
            "mgmt_name": context.mgmt_name,
            "domain_name": context.domain_name,
            "raw_data": raw_data,
        }

    def _extract_protections(self, protections: Any, context: ExtractionContext | None = None) -> list[str]:
        """Protection names: dict entries by ``name``, uid strings through the objects map (uid when unresolved).

        Gate L (L3): ``show-threat-rulebase`` rules carry no protections field, so this yields nothing on real data
        and the column stays empty (decision 9); the threat profile is the rule's ``action``.
        """
        if not isinstance(protections, list):
            return []
        return [resolve_ref(p, _map(context)) for p in protections if isinstance(p, (dict, str))]
