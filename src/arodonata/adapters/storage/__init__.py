"""SQL storage adapters (`DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`, and SQLModel tables)."""

from arodonata.adapters.storage.cache_adapter import SqlCacheAdapter
from arodonata.adapters.storage.database import (
    DEFAULT_MEMORY_SQLITE_URL,
    DatabaseManager,
    compute_schema_hash,
)
from arodonata.adapters.storage.lock_adapter import DatabaseLockManager, SqlLockAdapter
from arodonata.adapters.storage.tables import (
    ARODONATA_TABLE_NAMES,
    AccessRuleRecord,
    AssetRecord,
    CPObjectRecord,
    CPServiceRecord,
    DistributedLockRecord,
    DomainRecord,
    DomainSyncStateRecord,
    HttpsRuleRecord,
    NatRuleRecord,
    RulebaseLayerRecord,
    RulebasePackageLayerRecord,
    RulebaseSectionRecord,
    SchemaVersionRecord,
    SIDCacheRecord,
    ThreatRuleRecord,
)

__all__ = [
    "ARODONATA_TABLE_NAMES",
    "AccessRuleRecord",
    "AssetRecord",
    "CPObjectRecord",
    "CPServiceRecord",
    "DEFAULT_MEMORY_SQLITE_URL",
    "DatabaseLockManager",
    "DatabaseManager",
    "DistributedLockRecord",
    "DomainRecord",
    "DomainSyncStateRecord",
    "HttpsRuleRecord",
    "NatRuleRecord",
    "RulebaseLayerRecord",
    "RulebasePackageLayerRecord",
    "RulebaseSectionRecord",
    "SIDCacheRecord",
    "SchemaVersionRecord",
    "SqlCacheAdapter",
    "SqlLockAdapter",
    "ThreatRuleRecord",
    "compute_schema_hash",
]
