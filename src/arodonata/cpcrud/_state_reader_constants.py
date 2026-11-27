"""Constant tables and normalization helpers shared across CPCRUD state readers."""

from __future__ import annotations

from arodonata.core.errors import ArodonataError

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


def is_not_found_error(
    status_code: int,
    error_code: str | None,
    error_message: str | None,
) -> bool:
    """Return `True` if a Check Point API response specifically indicates 'object not found'."""
    if status_code == 404:
        return True
    code_low = (error_code or "").strip().lower()
    msg_low = (error_message or "").strip().lower()
    if "not_found" in code_low or "not found" in msg_low:
        return True
    return "requested object" in msg_low and "not found" in msg_low
