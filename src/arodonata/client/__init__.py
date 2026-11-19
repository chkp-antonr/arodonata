"""Primary composition root and unified developer facade (`ArodonataClient`).

Wires `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`)
into core domain services (`DomainService`, `DomainSyncCoordinator`, `ObjectService`,
`ServiceCacheService`, `AssetRefreshService`, `SearchService`), defaulting `engine=None` to an
auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`).
"""

from __future__ import annotations

from arodonata.client._base import (
    TrustPolicy as TrustPolicy,
)
from arodonata.client._base import (
    build_validated_trust_policy as build_validated_trust_policy,
)
from arodonata.client._base import logger as logger
from arodonata.client.inventory import ClientInventoryMixin
from arodonata.client.lifecycle import ClientLifecycleMixin
from arodonata.client.rulebase_reports import ClientRulebaseReportsMixin
from arodonata.client.topology import ClientTopologyMixin


class ArodonataClient(
    ClientTopologyMixin,
    ClientRulebaseReportsMixin,
    ClientInventoryMixin,
    ClientLifecycleMixin,
):
    """Unified composition root and async facade for Check Point Management & MDSM."""


__all__ = [
    "ArodonataClient",
    "TrustPolicy",
    "build_validated_trust_policy",
]
