"""Centralized cache module - the ONLY database access point.

All database operations go through this module. Other modules MUST NOT
access PostgreSQL directly.

Usage:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata.cache import CacheRepository, DatabaseManager

    # Main app creates engine from its own config
    engine = create_async_engine("postgresql+asyncpg://...")

    # Initialize database manager and cache
    db = DatabaseManager(engine)
    await db.initialize()
    cache = CacheRepository(db)

    # All DB operations through cache
    sid = await cache.get_sid("mgmt1", "domain1")
    assets = await cache.get_assets(mgmt_names=["mgmt1"])

    # Main app disposes engine
    await engine.dispose()
"""

from .database import DatabaseManager
from .json_column import JSONColumn
from .lock_manager import (
    DatabaseLockManager,
    LockAcquisitionError,
    LockContext,
    LockOwnershipError,
    _get_global_lock_manager,
    distributed_lock,
    generate_owner_id,
    get_current_lock_context,
    set_global_lock_manager,
)
from .models import Asset, CPObject, DistributedLock, Domain, SIDCache
from .repository import CacheRepository

__all__ = [
    "DatabaseManager",
    "DatabaseLockManager",
    "CacheRepository",
    "SIDCache",
    "Asset",
    "CPObject",
    "Domain",
    "DistributedLock",
    "JSONColumn",
    "LockContext",
    "LockAcquisitionError",
    "LockOwnershipError",
    "_get_global_lock_manager",
    "distributed_lock",
    "generate_owner_id",
    "get_current_lock_context",
    "set_global_lock_manager",
]
