"""Constant tables and normalization helpers shared across CPCRUD state readers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from arodonata.core.errors import ArodonataError
from arodonata.core.errors import is_not_found_error as is_not_found_error
from arodonata.core.models.common import to_naive_utc
from arodonata.core.models.domains import DomainSyncState
from arodonata.cpcrud.models import DomainStamp

OBJECT_ITEM_TYPES: frozenset[str] = frozenset(
    {
        "host",
        "network",
        "address-range",
        "dns-domain",
        "group",
        "application-site",
    }
)

SERVICE_ITEM_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-group",
    }
)

TYPE_TO_SHOW_SINGLE_CMD: dict[str, str] = {
    "host": "show-host",
    "network": "show-network",
    "address-range": "show-address-range",
    "dns-domain": "show-dns-domain",
    "group": "show-group",
    "application-site": "show-application-site",
    "service-tcp": "show-service-tcp",
    "service-udp": "show-service-udp",
    "service-icmp": "show-service-icmp",
    "service-icmp6": "show-service-icmp6",
    "service-other": "show-service-other",
    "service-group": "show-service-group",
}

TYPE_TO_SHOW_PLURAL_CMD: dict[str, str] = {
    "host": "show-hosts",
    "network": "show-networks",
    "address-range": "show-address-ranges",
    "dns-domain": "show-dns-domains",
    "group": "show-groups",
    "application-site": "show-application-sites",
    "service-tcp": "show-services-tcp",
    "service-udp": "show-services-udp",
    "service-icmp": "show-services-icmp",
    "service-icmp6": "show-services-icmp6",
    "service-other": "show-services-other",
    "service-group": "show-service-groups",
}


class StateLookupError(ArodonataError):
    """Raised when a cache or live API state lookup fails during planning."""


def normalize_app_site_url_key(url: str, *, is_regex: bool) -> str:
    """Return canonical comparison key for an `application-site` URL entry (case-folded when `is_regex=False`)."""
    clean = str(url).strip()
    return clean if is_regex else clean.lower()


def _is_command_not_recognized(code: str | None, error_message: str | None) -> bool:
    """Return `True` when an adapter reports Check Point `generic_err_command_not_recognized`."""
    haystack = f"{code or ''} {error_message or ''}".lower()
    return "command_not_recognized" in haystack


def match_deleted_entity_overlay(
    *,
    uid: str | None,
    name: str | None,
    entity_type: str | None,
    virt_objects: Mapping[str, Any],
    virt_services: Mapping[str, Any],
    del_objects: set[str],
    del_services: set[str],
    rule_buckets: Sequence[tuple[set[str], Mapping[str, Any]]],
) -> bool:
    """Return `True` when `(uid, name, entity_type)` resolves as virtually deleted in overlay state."""
    if uid:
        uid_key = f"uid:{uid}"
        if uid_key in del_objects or uid_key in del_services or any(uid_key in r_del for r_del, _ in rule_buckets):
            return True
        if uid_key in virt_objects or uid_key in virt_services or any(uid_key in r_virt for _, r_virt in rule_buckets):
            return False
    if not name:
        return False
    if entity_type:
        typed_key = f"name:{entity_type}:{name}"
        if typed_key in del_objects or typed_key in del_services:
            return True
    elif any(k.startswith("name:") and k.rsplit(":", 1)[-1] == name for k in del_objects | del_services):
        return True
    rule_name_key = f"name:{name}"
    return any(rule_name_key in r_del for r_del, _ in rule_buckets)


def _sync_state_matches_stamp(
    sync_state: DomainSyncState | None,
    stamp: DomainStamp | None,
) -> bool:
    """Return `True` iff `sync_state` is `"ok"` and matches `stamp`'s session UID and publish timestamp."""
    if sync_state is None or sync_state.status != "ok":
        return False
    if stamp is None or not stamp.readable:
        return False

    # Both last_published_at and last_session_uid must match when present on the stamp
    if stamp.last_session_uid is not None:
        if sync_state.last_session_uid != stamp.last_session_uid:
            return False
    elif sync_state.last_session_uid is not None:
        return False

    if stamp.last_published_at is not None:
        if to_naive_utc(sync_state.last_published_at) != to_naive_utc(stamp.last_published_at):
            return False
    elif sync_state.last_published_at is not None:
        return False

    # Require at least one non-None identifier on the stamp to trust the cache
    return stamp.last_session_uid is not None or stamp.last_published_at is not None
