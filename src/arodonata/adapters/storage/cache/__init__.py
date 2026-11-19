"""SQL cache adapter package (`SqlCacheAdapter`) implementing `CachePort` over SQLite and PostgreSQL."""

from __future__ import annotations

from arodonata.adapters.storage.cache.control import ControlCacheMixin
from arodonata.adapters.storage.cache.inventory import InventoryCacheMixin
from arodonata.adapters.storage.cache.rulebase import RulebaseCacheMixin
from arodonata.adapters.storage.cache.topology import TopologyCacheMixin
from arodonata.core.models.common import SyncStatus
from arodonata.core.models.rulebase import RulebaseType


class SqlCacheAdapter(
    ControlCacheMixin,
    InventoryCacheMixin,
    TopologyCacheMixin,
    RulebaseCacheMixin,
):
    """SQLAlchemy/SQLModel cache adapter implementing `CachePort`."""


__all__ = ["RulebaseType", "SqlCacheAdapter", "SyncStatus"]
