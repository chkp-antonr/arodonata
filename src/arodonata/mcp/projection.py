"""Project a cached raw API object to the requested ``details-level``."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

UID_KEYS: frozenset[str] = frozenset({"uid", "name", "type"})

# Keys the Management API returns at details-level "standard" for network objects, rules, domains and gateways.
STANDARD_KEYS: frozenset[str] = UID_KEYS | frozenset(
    {
        "domain",
        "color",
        "comments",
        "tags",
        "groups",
        "icon",
        "ipv4-address",
        "ipv6-address",
        "subnet4",
        "subnet6",
        "mask-length4",
        "mask-length6",
        "subnet-mask",
        "ipv4-address-first",
        "ipv4-address-last",
        "ipv6-address-first",
        "ipv6-address-last",
        "members",
        "port",
        "protocol",
        "match-for-any",
        "session-timeout",
        "rule-number",
        "enabled",
        "source",
        "destination",
        "service",
        "action",
        "track",
        "install-on",
        "time",
        "inline-layer",
        "layer",
        "vpn",
        "content",
        "custom-fields",
        "position",
        "domain-type",
        "servers",
        "global-domain-assignments",
        "cluster-member-names",
        "interfaces",
        "version",
        "os-name",
        "hardware",
        "policy",
        "network-security-blades",
        "management-blades",
        "sic-status",
        "trust-state",
    }
)


def project(raw: dict[str, Any], details_level: str) -> dict[str, Any]:
    if not raw:
        return {}
    if details_level == "full":
        return copy.deepcopy(raw)
    keys = UID_KEYS if details_level == "uid" else STANDARD_KEYS
    return {k: copy.deepcopy(v) for k, v in raw.items() if k in keys}


def cache_age_seconds(last_update: datetime | None, now: datetime | None = None) -> int | None:
    if last_update is None:
        return None
    current = now or datetime.now(UTC)
    if last_update.tzinfo is None and current.tzinfo is not None:
        current = current.replace(tzinfo=None)
    elif last_update.tzinfo is not None and current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return max(0, int((current - last_update).total_seconds()))
