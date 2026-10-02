"""ArodonataClient rulebase facade: domain resolution, refresh before read, results from the rulebase cache."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import Domain, RulebaseSyncState
from arodonata.cache.repository import CacheRepository
from arodonata.cache.rulebase_rows import build_rulebase_rows
from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy
from arodonata.rulebase.source import AmbiguousLayerName, RulebaseCacheNotReady
from tests.unit.rulebase.fakes import domain4_snapshot
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize

from .client_test_helpers import make_client

NETWORK = "FPCR_UAT_Active Network"


class RecordingCoordinator:
    def __init__(self):
        self.default_policy = CachePolicy(mode=CacheMode.SMART, ttl=300)
        self.ensured: list[tuple[list[str] | None, list[str] | None, CacheMode]] = []

    async def ensure(self, scope, policy):
        self.ensured.append((scope.mgmt_names, scope.domain_names, policy.mode))

    def invalidate(self, mgmt_name, domain_name):
        pass


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield CacheRepository(DatabaseManager(engine))
    await engine.dispose()


def facade_client(repo):
    client = make_client(cache=repo, mgmt=AsyncMock())
    client.get_mgmt_names = lambda: ["m1", "m2"]  # type: ignore[method-assign]
    client._rulebase_coordinator = RecordingCoordinator()  # type: ignore[assignment]
    return client


async def store(repo, domain):
    snap = domain4_snapshot("m1", domain)
    state = RulebaseSyncState(
        id=f"m1:{domain}", mgmt_name="m1", domain_name=domain, format_version=2, status="ok", session_uid="sess-1"
    )
    await repo.replace_domain_rulebases("m1", domain, build_rulebase_rows(snap), state)


async def add_domain(repo, name):
    await repo.upsert_domain(Domain.build(mgmt_name="m1", domain_name=name, active_ip="10.0.0.1"))


async def test_package_rulebase_named_domain_refreshes_then_reads(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    result = await client.get_package_rulebase("m1", "Domain4", "FPCR_UAT_Active", "access", cache_mode="smart")
    assert summarize(result.layers[0][1]) == FPCR_UAT_ACTIVE_ACCESS
    assert client._rulebase_coordinator.ensured == [(["m1"], ["Domain4"], CacheMode.SMART)]


async def test_domainless_layer_read_sms_resolves_smc_user_and_refreshes_it(repo):
    await add_domain(repo, "SMC User")
    client = facade_client(repo)
    with pytest.raises(RulebaseCacheNotReady):  # first read after upgrade: resolved, refreshed (fake), not cached yet
        await client.get_layer_rulebase("m1", None, NETWORK)
    assert client._rulebase_coordinator.ensured == [(["m1"], ["SMC User"], CacheMode.SMART)]
    await store(repo, "SMC User")
    result = await client.get_layer_rulebase("m1", "", NETWORK)
    assert result.domain_name == "SMC User"


async def test_domainless_layer_read_mds_single_match_uses_that_domain(repo):
    for name in ("Domain4", "Domain5"):
        await add_domain(repo, name)
    await store(repo, "Domain4")
    client = facade_client(repo)
    result = await client.get_layer_rulebase("m1", None, NETWORK)
    assert result.domain_name == "Domain4"
    assert client._rulebase_coordinator.ensured == [(["m1"], ["Domain4"], CacheMode.SMART)]


async def test_domainless_layer_read_mds_name_in_two_domains_raises_ambiguous(repo):
    await store(repo, "Domain4")
    await store(repo, "Domain5")
    client = facade_client(repo)
    with pytest.raises(AmbiguousLayerName) as err:
        await client.get_layer_rulebase("m1", None, NETWORK)
    assert sorted(d for d, _ in err.value.candidates) == ["Domain4", "Domain5"]
    assert client._rulebase_coordinator.ensured == []


async def test_domainless_layer_read_mds_no_match_not_ready(repo):
    for name in ("Domain4", "Domain5"):
        await add_domain(repo, name)
    client = facade_client(repo)
    with pytest.raises(RulebaseCacheNotReady, match="pass domain"):
        await client.get_layer_rulebase("m1", None, NETWORK)
    assert client._rulebase_coordinator.ensured == []


async def test_domainless_package_read_resolves_through_packages(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    result = await client.get_package_rulebase("m1", None, "FPCR_UAT_Active", "nat")
    assert result.domain_name == "Domain4" and result.layers[0][0].rulebase_type == "nat"


async def test_empty_domain_is_never_refreshed(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    await client.get_layer_rulebase("m1", "", NETWORK)
    assert client._rulebase_coordinator.ensured == [(["m1"], ["Domain4"], CacheMode.SMART)]


async def test_no_mgmt_uses_first_configured_server(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    await client.get_layer_rulebase(None, "Domain4", NETWORK)
    assert client._rulebase_coordinator.ensured == [(["m1"], ["Domain4"], CacheMode.SMART)]


async def test_policy_packages_and_locate_rules_require_domain(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    assert [p.package_name for p in await client.get_policy_packages("m1", "Domain4")] == ["FPCR_UAT_Active"]
    with pytest.raises(ValueError, match="domain_name"):
        await client.get_policy_packages("m1", "")
    snap = domain4_snapshot()
    allow = next(i.uid for lyr in snap.layers for i in lyr.items if i.name == "fpcr_uat_inline_FPCR_UAT_Active_allow")
    inline = next(lyr.layer_uid for lyr in snap.layers if lyr.layer_name == "FPCR_UAT_Active Inline")
    located = await client.locate_rules("m1", "Domain4", [allow], layer_uids=[inline])
    assert [p.number for p in located.rules[allow]] == ["2.2.1"] and [p.prefix for p in located.layers[inline]] == [
        "2.2."
    ]
    assert located.status == "ok" and located.snapshot_session_uid == "sess-1"
    with pytest.raises(ValueError, match="domain_name"):
        await client.locate_rules("m1", None, [allow])  # type: ignore[arg-type]


async def test_locate_rules_layer_uids_and_cache_options_are_keyword_only(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    with pytest.raises(TypeError):
        await client.locate_rules("m1", "Domain4", ["r"], None, (), "cache")  # type: ignore[misc]
    assert client._rulebase_coordinator.ensured == []


@pytest.mark.parametrize("kwargs", [{"rule_uids": "abc"}, {"layer_uids": "abc"}])
async def test_locate_rules_rejects_a_bare_string(repo, kwargs):
    await store(repo, "Domain4")
    client = facade_client(repo)
    with pytest.raises(TypeError, match="str"):
        await client.locate_rules("m1", "Domain4", **kwargs)
    assert client._rulebase_coordinator.ensured == []


async def test_cache_mode_cache_passes_through(repo):
    await store(repo, "Domain4")
    client = facade_client(repo)
    await client.get_layer_rulebase("m1", "Domain4", NETWORK, cache_mode="cache")
    assert client._rulebase_coordinator.ensured == [(["m1"], ["Domain4"], CacheMode.CACHE)]
