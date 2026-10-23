"""Unit and integration tests for DatabaseManager, SqlLockAdapter, and SqlCacheAdapter on SQLite."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, select, text

from arodonata.adapters.storage import (
    DatabaseLockManager,
    DatabaseManager,
    DistributedLockRecord,
    SchemaVersionRecord,
    SIDCacheRecord,
    SqlCacheAdapter,
    SqlLockAdapter,
    compute_schema_hash,
)
from arodonata.core.errors import REDACTED_PLACEHOLDER, LockAcquisitionError
from arodonata.core.models import (
    AccessRuleEntry,
    Asset,
    CPObject,
    CPService,
    DomainInfo,
    DomainRulebaseSnapshot,
    DomainSyncState,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    SIDCacheEntry,
    utc_now,
)
from arodonata.core.ports import CachePort, LockPort


async def test_database_manager_default_memory_sqlite_and_busy_timeout() -> None:
    """Verify engine=None creates an auto-owned in-memory SQLite engine with 30s busy timeout."""
    db = DatabaseManager(engine=None)
    try:
        assert db.owns_engine is True
        assert db.is_initialized is False

        schema_hash = await db.initialize()
        assert db.is_initialized is True
        assert len(schema_hash) == 64
        assert db.migration_inspection_count == 1

        # Second initialize() with unchanged schema hash must skip per-table inspection
        schema_hash_2 = await db.initialize()
        assert schema_hash_2 == schema_hash
        assert db.migration_inspection_count == 1

        # Check SQLite busy_timeout PRAGMA (30000 ms)
        async with db.session() as session:
            pragma_val = (await session.execute(text("PRAGMA busy_timeout"))).scalar_one()
            assert int(pragma_val) == 30000

            rows = (await session.execute(select(SchemaVersionRecord))).scalars().all()
            assert len(rows) == 1
            assert rows[0].schema_hash == schema_hash
    finally:
        await db.close()


async def test_database_manager_schema_evolution_adds_missing_columns(tmp_path: Path) -> None:
    """Verify schema evolution detects a new metadata hash, adds missing columns, and records the new hash."""
    db_file = tmp_path / "evolution.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    meta_v1 = MetaData()
    Table(
        "custom_items",
        meta_v1,
        Column("id", String, primary_key=True),
        Column("name", String, nullable=False),
    )

    db_v1 = DatabaseManager(engine=url, metadata=meta_v1)
    try:
        hash_v1 = await db_v1.initialize()
        assert db_v1.migration_inspection_count == 1
    finally:
        await db_v1.close()

    # Evolve metadata by adding a new column 'count'
    meta_v2 = MetaData()
    Table(
        "custom_items",
        meta_v2,
        Column("id", String, primary_key=True),
        Column("name", String, nullable=False),
        Column("count", Integer, nullable=True),
    )
    assert compute_schema_hash(meta_v2) != hash_v1

    db_v2 = DatabaseManager(engine=url, metadata=meta_v2)
    try:
        hash_v2 = await db_v2.initialize()
        assert hash_v2 != hash_v1
        assert db_v2.migration_inspection_count == 1

        async with db_v2.engine.begin() as conn:
            cols = await conn.run_sync(
                lambda sync_conn: [c["name"] for c in inspect(sync_conn).get_columns("custom_items")]
            )
            assert "count" in cols

            versions = (await conn.execute(select(SchemaVersionRecord.schema_hash))).scalars().all()
            assert set(versions) == {hash_v1, hash_v2}
    finally:
        await db_v2.close()


async def test_sql_lock_adapter_and_expired_lock_reclamation() -> None:
    """Verify DatabaseLockManager coordinates locks and atomically reclaims expired locks."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        lock_mgr = DatabaseLockManager(db, default_owner_id="worker-a")
        assert isinstance(lock_mgr, LockPort)
        assert isinstance(lock_mgr, SqlLockAdapter)

        # Acquire lock with worker-a
        acquired_a = await lock_mgr.acquire("sync:mds1:CMA1:objects", ttl_seconds=30.0, owner_id="worker-a")
        assert acquired_a is True

        # Contending worker-b cannot acquire while unexpired
        acquired_b = await lock_mgr.acquire("sync:mds1:CMA1:objects", ttl_seconds=30.0, owner_id="worker-b")
        assert acquired_b is False

        # Backdate expires_at to the past to simulate crashed worker-a
        past_time = utc_now() - timedelta(seconds=10)
        async with db.session() as session:
            rec = await session.get(DistributedLockRecord, "sync:mds1:CMA1:objects")
            assert rec is not None
            rec.expires_at = past_time
            await session.commit()

        # Worker-b must now atomically reclaim the expired lock
        reclaimed_b = await lock_mgr.acquire("sync:mds1:CMA1:objects", ttl_seconds=30.0, owner_id="worker-b")
        assert reclaimed_b is True

        async with db.session() as session:
            rec_after = await session.get(DistributedLockRecord, "sync:mds1:CMA1:objects")
            assert rec_after is not None
            assert rec_after.owner_id == "worker-b"

        released = await lock_mgr.release("sync:mds1:CMA1:objects", owner_id="worker-b")
        assert released is True

        # Context manager test and contention error
        async with lock_mgr.lock("sync:mds1:CMA1:rulebase", ttl_seconds=30.0, owner_id="worker-1"):
            with pytest.raises(LockAcquisitionError):
                async with lock_mgr.lock("sync:mds1:CMA1:rulebase", ttl_seconds=30.0, owner_id="worker-2"):
                    pass
    finally:
        await db.close()


async def test_sql_cache_adapter_domains_sids_and_sync_state() -> None:
    """Verify domains (Global filtering), sid_cache (repr hygiene), and domain_sync_state operations."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        assert isinstance(cache, CachePort)

        # 1. Domains with Global opt-in
        await cache.upsert_domains(
            [
                DomainInfo(
                    mgmt_name="mds1", uid="u-cma1", name="CMA1", active_ip="10.0.0.11", active_mds_ip="10.0.0.1"
                ),
                DomainInfo(
                    mgmt_name="mds1",
                    uid="u-global",
                    name="Global",
                    domain_type="global domain",
                    is_global=True,
                ),
            ]
        )
        regular_domains = await cache.get_domains("mds1", include_global=False)
        assert [d.name for d in regular_domains] == ["CMA1"]

        all_domains = await cache.get_domains("mds1", include_global=True)
        assert {d.name for d in all_domains} == {"CMA1", "Global"}
        cma1 = await cache.get_domain("mds1", "CMA1")
        assert cma1 is not None and cma1.active_ip == "10.0.0.11"

        # 2. SID cache and strict SID repr hygiene
        sid_entry = SIDCacheEntry(
            mgmt_name="mds1",
            domain_name="CMA1",
            sid="sensitive_sid_998877",
            server_ip="10.0.0.11",
            session_uid="sess-1",
        )
        await cache.upsert_sid(sid_entry)
        loaded_sid = await cache.get_sid("mds1", "CMA1")
        assert loaded_sid is not None
        assert loaded_sid.sid == "sensitive_sid_998877"
        assert "sensitive_sid_998877" not in repr(loaded_sid)

        async with db.session() as session:
            raw_rec = await session.get(SIDCacheRecord, "mds1:CMA1")
            assert raw_rec is not None
            assert "sensitive_sid_998877" not in repr(raw_rec)
            assert "sensitive_sid_998877" not in str(raw_rec)
            assert REDACTED_PLACEHOLDER in repr(raw_rec)

        assert len(await cache.list_sids("mds1")) == 1
        assert await cache.evict_sid("mds1", "CMA1") is True
        assert await cache.get_sid("mds1", "CMA1") is None

        # 3. Unified domain_sync_state
        pub_time = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
        sync_time = datetime(2026, 10, 23, 12, 5, tzinfo=UTC)
        state = DomainSyncState(
            mgmt_name="mds1",
            domain_name="CMA1",
            scope="objects",
            item_type="host",
            last_published_at=pub_time,
            last_session_uid="pub-sess-42",
            synced_at=sync_time,
            status="ok",
            object_count=15,
        )
        await cache.upsert_sync_state(state)
        loaded_state = await cache.get_sync_state("mds1", "CMA1", "objects", "host")
        assert loaded_state is not None
        assert loaded_state.id == "mds1:CMA1:objects:host"
        assert loaded_state.last_published_at == pub_time
        assert loaded_state.last_session_uid == "pub-sess-42"
        assert loaded_state.synced_at == sync_time
        assert loaded_state.status == "ok"
        assert loaded_state.object_count == 15
    finally:
        await db.close()


async def test_sql_cache_adapter_selective_objects_services_assets_and_rulebase() -> None:
    """Verify type-scoped replacement for objects and services, asset storage, and atomic rulebase snapshot."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)

        # 1. Selective object replacement: refreshing 'network' must preserve 'host'
        host_obj = CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "h-1", "name": "host-1", "type": "host", "ipv4-address": "10.1.1.1"},
        )
        net_obj = CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "n-1", "name": "net-1", "type": "network", "subnet4": "10.1.0.0", "mask-length4": 16},
        )
        await cache.replace_domain_objects("mds1", "CMA1", [host_obj], types=["host"])
        await cache.replace_domain_objects("mds1", "CMA1", [net_obj], types=["network"])

        all_objs = await cache.get_objects("mds1", "CMA1")
        assert {o.uid for o in all_objs} == {"h-1", "n-1"}
        assert (await cache.get_object_by_uid("mds1", "CMA1", "h-1")) is not None

        # Incremental upsert & delete
        host_obj_2 = CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "h-2", "name": "host-2", "type": "host", "ipv4-address": "10.1.1.2"},
        )
        await cache.upsert_objects([host_obj_2])
        assert len(await cache.get_objects("mds1", "CMA1", types=["host"])) == 2
        deleted_count = await cache.delete_objects_by_uids("mds1", "CMA1", ["h-1"])
        assert deleted_count == 1
        assert [o.uid for o in await cache.get_objects("mds1", "CMA1", types=["host"])] == ["h-2"]

        # 2. Selective service replacement: refreshing 'service-other' preserves 'service-tcp'
        tcp_svc = CPService.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "s-tcp-443", "name": "https", "type": "service-tcp", "port": "443"},
        )
        other_svc = CPService.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "s-other-gre", "name": "gre-proto", "type": "service-other", "ip-protocol": "47"},
        )
        await cache.replace_domain_services("mds1", "CMA1", [tcp_svc], types=["service-tcp"])
        await cache.replace_domain_services("mds1", "CMA1", [other_svc], types=["service-other"])

        cached_services = await cache.get_services("mds1", "CMA1")
        assert {s.uid for s in cached_services} == {"s-tcp-443", "s-other-gre"}
        assert (await cache.get_service_by_uid("mds1", "CMA1", "s-tcp-443")) is not None

        # 3. Assets replacement
        gw = Asset.from_cp_dict(
            "mds1",
            "CMA1",
            {
                "uid": "gw-1",
                "name": "cluster-1",
                "type": "CpmiGatewayCluster",
                "ipv4-address": "172.16.0.1",
                "member_uids": ["m-1", "m-2"],
            },
        )
        await cache.replace_domain_assets("mds1", "CMA1", [gw])
        assets = await cache.get_assets("mds1", "CMA1")
        assert len(assets) == 1
        assert assets[0].member_uids == ["m-1", "m-2"]

        # 4. Atomic rulebase snapshot replacement
        snapshot = DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="CMA1",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="CMA1",
                    package_uid="pkg-1",
                    package_name="Standard",
                    rulebase_type="access",
                    layer_uid="layer-1",
                    layer_name="Network",
                    position=1,
                )
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="CMA1",
                    uid="layer-1",
                    name="Network",
                    rulebase_type="access",
                )
            ],
            sections=[
                RulebaseSectionEntry(
                    mgmt_name="mds1",
                    domain_name="CMA1",
                    layer_uid="layer-1",
                    layer_name="Network",
                    rulebase_type="access",
                    uid="sec-1",
                    name="Core Rules",
                    position=1,
                    from_rule=1,
                    to_rule=1,
                    rule_uids=["rule-1"],
                )
            ],
            access_rules=[
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="CMA1",
                    layer_uid="layer-1",
                    layer_name="Network",
                    section_uid="sec-1",
                    section_name="Core Rules",
                    uid="rule-1",
                    name="Allow HTTPS",
                    position=1,
                    rule_number="1",
                    action="Accept",
                    source=["h-2"],
                    destination=["n-1"],
                    service=["s-tcp-443"],
                )
            ],
            nat_rules=[
                NatRuleEntry(
                    mgmt_name="mds1",
                    domain_name="CMA1",
                    package_uid="pkg-1",
                    package_name="Standard",
                    uid="nat-1",
                    name="Hide NAT",
                    position=1,
                    rule_number="1",
                    method="hide",
                )
            ],
        )
        await cache.replace_domain_rulebase(snapshot)
        loaded_rb = await cache.get_domain_rulebase("mds1", "CMA1")
        assert len(loaded_rb.package_layers) == 1
        assert len(loaded_rb.layers) == 1
        assert len(loaded_rb.sections) == 1
        assert len(loaded_rb.access_rules) == 1
        assert loaded_rb.access_rules[0].name == "Allow HTTPS"
        assert len(loaded_rb.nat_rules) == 1
        assert loaded_rb.nat_rules[0].method == "hide"
    finally:
        await db.close()
