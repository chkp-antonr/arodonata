"""Shared TTL bookkeeping for opportunistic domain-list re-fetches.

A management server's *domain list itself* (as opposed to any one domain's
objects/rulebases) used to only ever get re-fetched from the API when the
local domains table came back completely empty. That meant a domain created
in SmartConsole after the table was first seeded stayed invisible to every
refresh forever - both `arodonata.cache.object_service.ObjectService` and
`arodonata.api.services.rulebase_refresh_service.RulebaseRefreshService` had
this exact gap independently.

The fix is the same shape in both places: a force/full refresh always
re-fetches the domain list unconditionally, while a check/smart refresh
re-fetches it at most once per `DOMAIN_LIST_REFRESH_TTL_SECONDS` so repeated
smart-refresh ticks don't hammer `show-domains`. `DomainListRefreshTracker`
holds the per-mgmt "last re-fetched at" memo each service needs to make that
decision, mirroring `CacheRefreshCoordinator`'s `_ttl_fresh`/`_mark_checked`
pattern (inverted to "is stale" instead of "is fresh") but scoped to
mgmt-server domain discovery rather than per-(mgmt, domain) object staleness.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from arodonata.core.cache_policy import SystemClock

if TYPE_CHECKING:
    from arodonata.core.cache_policy import Clock

DOMAIN_LIST_REFRESH_TTL_SECONDS = 3600
"""Default seconds between opportunistic (check/smart-mode) re-fetches of a management
server's domain list. Force/full refreshes ignore this and always re-fetch."""


class DomainListRefreshTracker:
    """Per-mgmt-name "when was the domain list last re-fetched" memo with a TTL."""

    def __init__(self, ttl_seconds: int = DOMAIN_LIST_REFRESH_TTL_SECONDS, clock: Clock | None = None) -> None:
        self._ttl = ttl_seconds
        self._clock: Clock = clock or SystemClock()
        self._checked_at: dict[str, datetime] = {}

    def is_stale(self, mgmt_name: str) -> bool:
        """True when `mgmt_name`'s domain list has never been re-fetched, or the TTL has
        elapsed since it last was - i.e. an opportunistic re-fetch is due."""
        checked = self._checked_at.get(mgmt_name)
        if checked is None:
            return True
        age = (self._clock.now() - checked).total_seconds()
        return age >= self._ttl

    def mark_checked(self, mgmt_name: str) -> None:
        """Record that `mgmt_name`'s domain list was just re-fetched."""
        self._checked_at[mgmt_name] = self._clock.now()
