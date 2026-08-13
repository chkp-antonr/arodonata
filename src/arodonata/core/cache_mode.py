from enum import StrEnum


class CacheMode(StrEnum):
    """Cache read/refresh modes for read helpers.

    CACHE:      Read cache as-is, never call the API.
    SMART:      TTL-throttled staleness check; full domain reload if stale.
    SMART_FAST: Same check; incremental show-changes apply, falling back to SMART.
    FORCE:      Unconditional full reload of every in-scope domain (ignores TTL).
    """

    CACHE = "cache"
    SMART = "smart"
    SMART_FAST = "smart-fast"
    FORCE = "force"
