"""Unit and integration tests for DatabaseManager, SqlLockAdapter, and SqlCacheAdapter on SQLite."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, select, text

from arodonata.adapters.storage import (
    ARODONATA_TABLE_NAMES,
    AssetRecord,
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
    to_naive_utc,
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
        pub_time = datetime(2026, 10, 23, 12, 0)
        sync_time = datetime(2026, 10, 23, 12, 5)
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


async def test_arodonata_assets_table_name_and_naive_utc_columns() -> None:
    """Verify every table in `ARODONATA_TABLE_NAMES` starts with `arodonata_` and all DateTime columns use `timezone=False` (`C5`, `I15`)."""
    from datetime import UTC as _UTC

    from sqlalchemy import DateTime
    from sqlmodel import SQLModel

    assert AssetRecord.__tablename__ == "arodonata_assets"
    assert "arodonata_assets" in ARODONATA_TABLE_NAMES
    assert "assets" not in ARODONATA_TABLE_NAMES
    assert len(ARODONATA_TABLE_NAMES) == 15

    for table_name in ARODONATA_TABLE_NAMES:
        assert table_name.startswith("arodonata_"), f"Table {table_name!r} must start with 'arodonata_'"

    now = utc_now()
    assert now.tzinfo is None
    aware = datetime(2026, 10, 25, 12, 0, 0, tzinfo=_UTC)
    assert to_naive_utc(aware) == datetime(2026, 10, 25, 12, 0, 0)
    assert to_naive_utc(aware).tzinfo is None  # type: ignore[union-attr]

    for table_name in ARODONATA_TABLE_NAMES:
        table = SQLModel.metadata.tables[table_name]
        for col in table.columns:
            if isinstance(col.type, DateTime):
                assert col.type.timezone is False, f"{table_name}.{col.name} must have DateTime(timezone=False)"


async def test_database_manager_ignores_foreign_tables_and_recovers_legacy_v1_tables(tmp_path: Path) -> None:
    """Verify foreign tables in `SQLModel.metadata` are ignored and legacy v1 `domains`/`sid_cache` tables are dropped while `arodonata_*` tables are created (`C5`)."""
    from sqlmodel import SQLModel

    db_file = tmp_path / "legacy_upgrade.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    # 1. Register a foreign host-application table in SQLModel.metadata (e.g. a host "assets" table)
    hash_before = compute_schema_hash(SQLModel.metadata)
    foreign_table = Table(
        "host_app_custom_inventory",
        SQLModel.metadata,
        Column("asset_id", String, primary_key=True),
        Column("hostname", String, nullable=False),
    )
    try:
        # Foreign table must not affect Arodonata's schema hash
        assert compute_schema_hash(SQLModel.metadata) == hash_before

        db = DatabaseManager(engine=url)
        try:
            # Seed incompatible legacy v1 tables (`domains` with PK `mdm_dmn`, `sid_cache` with PK `mgmt_dmn_key`,
            # and `arodonata_schema_version` with integer `id` PK) before running initialize()
            async with db.engine.begin() as conn:
                await conn.execute(
                    text("CREATE TABLE arodonata_schema_version (id INTEGER PRIMARY KEY, version_hash TEXT NOT NULL)")
                )
                await conn.execute(
                    text("CREATE TABLE domains (mdm_dmn TEXT PRIMARY KEY, ip TEXT NOT NULL, domain_type TEXT NOT NULL)")
                )
                await conn.execute(
                    text("CREATE TABLE sid_cache (mgmt_dmn_key TEXT PRIMARY KEY, sid TEXT NOT NULL, ip TEXT NOT NULL)")
                )

            await db.initialize()

            async with db.engine.begin() as conn:
                table_names = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
                # Foreign host table was NOT created by Arodonata DatabaseManager
                assert "host_app_custom_inventory" not in table_names
                assert "arodonata_assets" in table_names
                assert "arodonata_domains" in table_names
                assert "arodonata_sid_cache" in table_names
                # Legacy v1 fingerprinted tables were dropped
                assert "domains" not in table_names
                assert "sid_cache" not in table_names

                domains_pk = await conn.run_sync(
                    lambda sc: inspect(sc).get_pk_constraint("arodonata_domains").get("constrained_columns")
                )
                sid_pk = await conn.run_sync(
                    lambda sc: inspect(sc).get_pk_constraint("arodonata_sid_cache").get("constrained_columns")
                )
                assert domains_pk == ["id"]
                assert sid_pk == ["id"]

            # Verify SqlCacheAdapter can now write and read domains and SIDs without NotNullViolation
            cache = SqlCacheAdapter(db)
            await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="u1", name="CMA1", active_ip="10.0.0.11")])
            await cache.upsert_sid(
                SIDCacheEntry(mgmt_name="mds1", domain_name="CMA1", sid="s-123", server_ip="10.0.0.11")
            )
            assert len(await cache.get_domains("mds1")) == 1
            assert (await cache.get_sid("mds1", "CMA1")) is not None
        finally:
            await db.close()
    finally:
        SQLModel.metadata.remove(foreign_table)


async def test_colliding_host_unprefixed_tables_are_never_dropped_or_altered(tmp_path: Path) -> None:
    """Verify host application tables named `domains`, `sid_cache`, `distributed_locks`, `domain_sync_state` without v1 fingerprints are NEVER dropped or altered (`C5`)."""
    db_file = tmp_path / "host_collision.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    db = DatabaseManager(engine=url)
    try:
        async with db.engine.begin() as conn:
            await conn.execute(text("CREATE TABLE domains (tenant_id INTEGER PRIMARY KEY, fqdn TEXT NOT NULL)"))
            await conn.execute(text("INSERT INTO domains (tenant_id, fqdn) VALUES (1, 'corp.example.com')"))
            await conn.execute(text("CREATE TABLE sid_cache (token_id TEXT PRIMARY KEY, owner TEXT NOT NULL)"))
            await conn.execute(text("INSERT INTO sid_cache (token_id, owner) VALUES ('t1', 'alice')"))
            await conn.execute(text("CREATE TABLE distributed_locks (resource TEXT PRIMARY KEY, holder TEXT NOT NULL)"))
            await conn.execute(text("INSERT INTO distributed_locks (resource, holder) VALUES ('r1', 'node-1')"))
            await conn.execute(text("CREATE TABLE domain_sync_state (job_id INTEGER PRIMARY KEY, state TEXT NOT NULL)"))
            await conn.execute(text("INSERT INTO domain_sync_state (job_id, state) VALUES (42, 'running')"))

        await db.initialize()

        async with db.engine.begin() as conn:
            # All 4 host tables and their rows must remain intact!
            dom_row = (await conn.execute(text("SELECT tenant_id, fqdn FROM domains"))).one()
            assert tuple(dom_row) == (1, "corp.example.com")
            sid_row = (await conn.execute(text("SELECT token_id, owner FROM sid_cache"))).one()
            assert tuple(sid_row) == ("t1", "alice")
            lock_row = (await conn.execute(text("SELECT resource, holder FROM distributed_locks"))).one()
            assert tuple(lock_row) == ("r1", "node-1")
            sync_row = (await conn.execute(text("SELECT job_id, state FROM domain_sync_state"))).one()
            assert tuple(sync_row) == (42, "running")

            # And Arodonata's prefixed tables must also exist
            table_names = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
            assert ARODONATA_TABLE_NAMES <= table_names
    finally:
        await db.close()


async def test_concurrent_initialize_and_out_of_band_dropped_table_recovery(tmp_path: Path) -> None:
    """Verify concurrent `DatabaseManager.initialize()` calls serialize cleanly (`C6`), out-of-band dropped tables are recreated even when `schema_hash` matches (`I2`), and incompatible column types/NOT NULL changes trigger table recreation (`I1`)."""
    import asyncio

    db_file = tmp_path / "concurrent_init.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    managers = [DatabaseManager(engine=url) for _ in range(4)]
    try:
        hashes = await asyncio.gather(*(m.initialize() for m in managers))
        assert len(set(hashes)) == 1

        # Simulate out-of-band table drop while arodonata_schema_version still holds the current hash (I2)
        async with managers[0].engine.begin() as conn:
            await conn.execute(text("DROP TABLE arodonata_objects"))

        # Re-initializing must detect the missing managed table and recreate it even though schema_hash matched
        await managers[1].initialize()
        async with managers[1].engine.begin() as conn:
            table_names = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
            assert "arodonata_objects" in table_names

        # Simulate column type incompatibility on arodonata_domains (updated_at as INTEGER instead of DATETIME) (I1)
        async with managers[0].engine.begin() as conn:
            await conn.execute(text("DELETE FROM arodonata_schema_version"))
            await conn.execute(text("DROP TABLE arodonata_domains"))
            await conn.execute(
                text("CREATE TABLE arodonata_domains (id TEXT PRIMARY KEY, mgmt_name TEXT, updated_at INTEGER)")
            )

        await managers[2].initialize()
        cache = SqlCacheAdapter(managers[2])
        await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="u1", name="CMA1", active_ip="10.0.0.11")])
        assert len(await cache.get_domains("mds1")) == 1
    finally:
        for m in managers:
            await m.close()


async def test_in_memory_sqlite_concurrent_session_isolation_and_dialect_on_conflict_upsert() -> None:
    """Verify in-memory SQLite concurrent sessions do not cross-rollback (`W17`) and `SqlCacheAdapter` uses atomic `ON CONFLICT` upserts (`W21`)."""
    import asyncio

    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)

        # Concurrent first-insert and update upserts for the same primary key must never raise IntegrityError (W21)
        async def _upsert_worker(idx: int) -> None:
            await cache.upsert_domains(
                [DomainInfo(mgmt_name="mds1", uid="u-cma1", name="CMA1", active_ip=f"10.0.0.{idx}")]
            )
            await cache.upsert_objects(
                [
                    CPObject.from_cp_dict(
                        "mds1",
                        "CMA1",
                        {"uid": "h-shared", "name": f"host-{idx}", "type": "host", "ipv4-address": f"10.1.1.{idx}"},
                    )
                ]
            )
            await cache.upsert_services(
                [
                    CPService.from_cp_dict(
                        "mds1",
                        "CMA1",
                        {"uid": "s-shared", "name": f"svc-{idx}", "type": "service-tcp", "port": str(8000 + idx)},
                    )
                ]
            )

        await asyncio.gather(*(_upsert_worker(i) for i in range(1, 9)))

        dom = await cache.get_domain("mds1", "CMA1")
        assert dom is not None
        obj = await cache.get_object_by_uid("mds1", "CMA1", "h-shared")
        assert obj is not None
        svc = await cache.get_service_by_uid("mds1", "CMA1", "s-shared")
        assert svc is not None
    finally:
        await db.close()


async def test_database_manager_tolerates_duplicate_column_and_index_errors_in_savepoints(tmp_path: Path) -> None:
    """Verify `_is_benign_concurrent_ddl_error` and savepoint-wrapped `ALTER TABLE` tolerate duplicate column errors."""
    from sqlalchemy.exc import OperationalError

    from arodonata.adapters.storage.database import _is_benign_concurrent_ddl_error

    assert _is_benign_concurrent_ddl_error(OperationalError("ALTER TABLE", {}, Exception("duplicate column name: x")))
    assert _is_benign_concurrent_ddl_error(
        OperationalError("CREATE INDEX", {}, Exception("relation 'idx_x' already exists"))
    )
    assert not _is_benign_concurrent_ddl_error(OperationalError("ALTER TABLE", {}, Exception("syntax error near FROM")))


async def test_duplicate_named_objects_and_services_with_distinct_uids_and_human_readable_ids() -> None:
    """Verify duplicate-named objects/services (`email`) with distinct UIDs coexist in DB and expose human-readable composite IDs."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)

        # Two objects sharing the exact name "email" in the same domain with distinct UIDs
        obj_email_1 = CPObject.from_cp_dict(
            "mds1",
            "General",
            {"uid": "uid-email-1", "name": "email", "type": "application-site"},
        )
        obj_email_2 = CPObject.from_cp_dict(
            "mds1",
            "General",
            {"uid": "uid-email-2", "name": "email", "type": "application-site"},
        )
        await cache.replace_domain_objects(
            "mds1",
            "General",
            [obj_email_1, obj_email_2],
            types=["application-site"],
        )
        objs = await cache.get_objects("mds1", "General", names=["email"])
        assert len(objs) == 2
        assert {o.uid for o in objs} == {"uid-email-1", "uid-email-2"}
        assert {o.id for o in objs} == {"mds1:General:uid-email-1", "mds1:General:uid-email-2"}
        assert [o.object_id for o in objs] == ["mds1:General:email", "mds1:General:email"]

        # Two services sharing the exact name "email" in the same domain with distinct UIDs
        svc_email_1 = CPService.from_cp_dict(
            "mds1",
            "General",
            {"uid": "uid-svc-email-1", "name": "email", "type": "service-other"},
        )
        svc_email_2 = CPService.from_cp_dict(
            "mds1",
            "General",
            {"uid": "uid-svc-email-2", "name": "email", "type": "service-other"},
        )
        await cache.replace_domain_services(
            "mds1",
            "General",
            [svc_email_1, svc_email_2],
            types=["service-other"],
        )
        svcs = await cache.get_services("mds1", "General", names=["email"])
        assert len(svcs) == 2
        assert {s.uid for s in svcs} == {"uid-svc-email-1", "uid-svc-email-2"}
        assert {s.id for s in svcs} == {"mds1:General:uid-svc-email-1", "mds1:General:uid-svc-email-2"}
        assert [s.service_id for s in svcs] == ["mds1:General:email", "mds1:General:email"]

        # Assets with asset_id, parent_id, parent_asset_id, member_asset_ids, virtual_system_asset_ids, and upsert_assets
        cluster = Asset(
            uid="c-1",
            name="gw-cluster",
            type="CpmiGatewayCluster",
            mgmt_name="mds1",
            domain_name="General",
            member_uids=["m-1"],
            member_asset_ids=["mds1:General:gw-m1"],
        )
        member = Asset(
            uid="m-1",
            name="gw-m1",
            type="CpmiClusterMember",
            mgmt_name="mds1",
            domain_name="General",
            parent_uid="c-1",
            parent_name="gw-cluster",
        )
        await cache.replace_domain_assets("mds1", "General", [cluster, member])
        loaded_assets = {a.uid: a for a in await cache.get_assets("mds1", "General")}
        assert loaded_assets["c-1"].asset_id == "mds1:General:gw-cluster"
        assert loaded_assets["c-1"].member_asset_ids == ["mds1:General:gw-m1"]
        assert loaded_assets["m-1"].asset_id == "mds1:General:gw-m1"
        assert loaded_assets["m-1"].parent_id == "mds1:General:c-1"
        assert loaded_assets["m-1"].parent_asset_id == "mds1:General:gw-cluster"

        # Test upsert_assets updating cross-domain parent_asset_id
        vs = Asset(
            uid="vs-1",
            name="vs-tenant-1",
            type="virtual-system",
            mgmt_name="mds1",
            domain_name="Tenant",
            parent_uid="vsx-1",
            parent_name="vsx-core",
            parent_id="mds1:Infra:vsx-1",
            parent_asset_id="mds1:Infra:vsx-core",
        )
        await cache.upsert_assets([vs])
        tenant_assets = await cache.get_assets("mds1", "Tenant")
        assert len(tenant_assets) == 1
        assert tenant_assets[0].asset_id == "mds1:Tenant:vs-tenant-1"
        assert tenant_assets[0].parent_id == "mds1:Infra:vsx-1"
        assert tenant_assets[0].parent_asset_id == "mds1:Infra:vsx-core"
    finally:
        await db.close()
