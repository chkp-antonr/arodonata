"""Unit tests for RulebaseRefreshService.

refresh_domain flows against a real in-memory SQLite repository and Gate L recordings; refresh_all domain-list tests keep their mocks.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.api.services.rulebase_refresh_service import RulebaseRefreshService
from arodonata.cache import models as _models  # noqa: F401  (registers tables)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import RulebaseAccess, RulebaseHTTPS, RulebaseNAT, RulebaseSyncState, RulebaseThreat
from arodonata.cache.repository import CacheRepository
from arodonata.core.exceptions import InvalidCredentialsError, PublishedHeadError
from arodonata.rulebase.numbering import number_package
from tests.unit.rulebase.fakes import (
    ACCESS,
    FakeHeadService,
    FakeRulebaseClient,
    domain4_fake,
    load_fixture,
    make_layer,
)
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize


class FakeClock:
    """Deterministic, advanceable time source implementing the Clock protocol."""

    def __init__(self, start: datetime) -> None:
        self._t = start

    def now(self) -> datetime:
        return self._t

    def advance(self, seconds: int) -> None:
        self._t = self._t + timedelta(seconds=seconds)


def make_service(**kwargs):
    client = MagicMock()
    cache = AsyncMock()
    service = RulebaseRefreshService(client=client, cache=cache, **kwargs)
    return service, client, cache


def _stub_domain_refresh(service, events=None):
    """Stub refresh_domain and the staleness check for refresh_all tests that only care about domain-list resolution."""
    calls: list[tuple[str, str, bool]] = []

    async def fake_refresh_domain(mgmt_name, domain, *, force=False):
        calls.append((mgmt_name, domain, force))
        for event in events or []:
            yield event

    async def stale(mgmt_name, domain):
        return True, None

    service.refresh_domain = fake_refresh_domain
    service._staleness = stale
    return calls


async def collect(agen):
    return [event async for event in agen]


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield CacheRepository(DatabaseManager(engine))
    await engine.dispose()


def service_for(repo, client=None, head=None):
    client = client or domain4_fake()
    head = head or FakeHeadService(client)
    return RulebaseRefreshService(client=client, cache=repo, object_service=head), client, head  # type: ignore[arg-type]


async def refresh(service, domain="Domain4", force=False):
    return await collect(service.refresh_domain("m1", domain, force=force))


async def rules(repo, model=RulebaseAccess, layer=None, domain="Domain4"):
    return await repo.get_rulebase(model, ["m1"], [domain], {"layer_name": layer} if layer else None)


# --------------------------------------------------------------------------- #
# refresh_domain
# --------------------------------------------------------------------------- #


async def test_refresh_domain_reads_packages_layers_links_and_nat(repo):
    service, client, _ = service_for(repo)
    events = await refresh(service)
    final = events[-1]
    assert final["status"] == "domain_refreshed" and final["result"].status == "ok"
    assert [c["command"] for c in client.query_calls] == [
        "show-packages",
        "show-access-layers",
        "show-https-layers",
        "show-threat-layers",
    ]
    assert client.query_calls[0]["container_key"] == "packages" and client.query_calls[0]["details_level"] == "full"
    glb = load_fixture("global_layer_no_package.json")["uid"]
    assert (
        ACCESS,
        {"uid": glb, "package": "FPCR_UAT_Active", "details-level": "standard", "limit": 100, "offset": 0},
    ) in client.calls
    assert (
        "show-nat-rulebase",
        {
            "package": "FPCR_UAT_Active",
            "details-level": "full",
            "use-object-dictionary": True,
            "limit": 100,
            "offset": 0,
        },
    ) in client.calls


async def test_head_captured_before_fetch(repo):
    service, client, _ = service_for(repo)
    await refresh(service)
    assert [c for c, _ in client.calls[:2]] == ["show-last-published-session", "show-session"]


async def test_loaded_snapshot_numbers_match_smartconsole(repo):
    service, _, _ = service_for(repo)
    await refresh(service)
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    layout = next(p for p in snapshot.packages if p.package_name == "FPCR_UAT_Active")
    layers = {layer.layer_uid: layer for layer in snapshot.layers}
    numbered = number_package(layout, "access", layers)
    assert summarize(numbered[0]) == FPCR_UAT_ACTIVE_ACCESS
    assert [o.layer_name for o in layout.layers if o.rulebase_type == "access"] == [
        "arod-global-pkg Network",
        "FPCR_UAT_Active AppControl",
    ]
    assert [e.number for e in numbered[1]] == ["1", "2"]


async def test_sync_state_ok_with_head_uid(repo):
    service, _, _ = service_for(repo)
    events = await refresh(service)
    state = await repo.get_rulebase_sync_state("m1", "Domain4")
    assert (state.status, state.session_uid, state.format_version, state.last_error) == ("ok", "sess-1", 2, None)
    assert state.refreshed_at is not None and state.session_published_time is not None
    assert events[-1]["result"].counts == {"access": 12, "nat": 2, "https": 2, "threat": 1}


async def test_legacy_getters_after_refresh(repo):
    service, _, _ = service_for(repo)
    await refresh(service)
    network = await rules(repo, layer="FPCR_UAT_Active Network")
    assert [r.action for r in network] == ["Accept", "Inner Layer", "Accept", "Accept", "Accept", "Drop"]
    assert [r.rule_number for r in await rules(repo, layer="arod-global-pkg Network")] == [
        1,
        3,
    ]  # place-holder excluded
    nat = await rules(repo, model=RulebaseNAT, layer="FPCR_UAT_Active")
    assert [r.rule_number for r in nat] == [1, 2] and nat[0].layer_uid.startswith("25d7c8f1")


async def test_shared_ips_layer_fetched_once(repo):
    client = domain4_fake()
    second = {**client.listings["show-packages"][0], "uid": "pkg-2", "name": "Second", "nat-policy": False}
    client.listings["show-packages"].append(second)
    client.add_layer(ACCESS, load_fixture("global_layer_with_package.json"), package="Second")
    service, _, _ = service_for(repo, client)
    await refresh(service)
    ips = load_fixture("threat_ips_empty.json")["uid"]
    assert (
        sum(1 for c, p in client.calls if c == "show-threat-rulebase" and p.get("uid") == ips and p["offset"] == 0) == 1
    )


async def test_layer_deleted_in_cp_is_removed(repo):
    client = domain4_fake()
    service, _, _ = service_for(repo, client)
    await refresh(service)
    pkg = client.listings["show-packages"][0]
    app_uid = next(e["uid"] for e in pkg["access-layers"] if e["name"].endswith("AppControl"))
    pkg["access-layers"] = [e for e in pkg["access-layers"] if e["uid"] != app_uid]
    client.listings["show-access-layers"] = [e for e in client.listings["show-access-layers"] if e["uid"] != app_uid]
    await refresh(service)
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    assert app_uid not in {layer.layer_uid for layer in snapshot.layers}
    assert await rules(repo, layer="FPCR_UAT_Active AppControl") == []


async def test_package_deleted_in_cp_is_removed(repo):
    client = domain4_fake()
    service, _, _ = service_for(repo, client)
    await refresh(service)
    client.listings["show-packages"] = []
    await refresh(service)
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    assert snapshot.packages == ()
    assert await rules(repo, model=RulebaseNAT) == []


async def test_first_v2_refresh_purges_old_format_rows(repo):
    await repo.upsert_rulebases(
        [
            RulebaseAccess(
                id="m1:Domain4:Network:old",
                uid="old",
                rule_number=1,
                name="old",
                enabled=True,
                layer_name="Network",
                mgmt_name="m1",
                domain_name="Domain4",
            )
        ]
    )
    service, _, _ = service_for(repo)
    await refresh(service)
    assert "old" not in {r.uid for r in await rules(repo)}


async def test_global_domain_refresh_skips_placeholder_link(repo):
    service, client, _ = service_for(repo)
    await refresh(service, domain="Global")
    assert not any("package" in p and c == ACCESS for c, p in client.calls)
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Global")
    glb = next(o for p in snapshot.packages for o in p.layers if o.layer_domain_type == "global domain")
    assert glb.placeholder_uid is None and glb.domain_layer_uid is None


async def test_layer_with_120_rules_is_cached_completely(repo):
    client = FakeRulebaseClient()
    client.add_layer(ACCESS, make_layer("BIG", "Big", 120, rules_per_section=40))
    client.listings["show-access-layers"] = [{"uid": "BIG", "name": "Big"}]
    service, _, _ = service_for(repo, client)
    await refresh(service)
    assert [r.rule_number for r in await rules(repo, layer="Big")] == list(range(1, 121))


async def test_listing_60_layers_two_pages(repo):
    client = FakeRulebaseClient()
    for i in range(60):
        layer = make_layer(f"L{i:02}", f"Layer {i:02}", 1)
        client.add_layer(ACCESS, layer)
        client.listings.setdefault("show-access-layers", []).append({"uid": layer["uid"], "name": layer["name"]})
    service, _, _ = service_for(repo, client)
    await refresh(service)
    assert len({r.layer_uid for r in await rules(repo)}) == 60


async def test_layers_with_duplicate_names_are_fetched_by_uid(repo):
    client = FakeRulebaseClient()
    client.add_layer(ACCESS, make_layer("g-net", "Network", 2))
    client.add_layer(ACCESS, make_layer("d-net", "Network", 3))
    client.listings["show-access-layers"] = [
        {"uid": "g-net", "name": "Network", "domain": {"name": "Global", "domain-type": "global domain"}},
        {"uid": "d-net", "name": "Network", "domain": {"name": "Domain4", "domain-type": "domain"}},
    ]
    service, _, _ = service_for(repo, client)
    await refresh(service)
    assert {r.layer_uid for r in await rules(repo, layer="Network")} == {"g-net", "d-net"}
    assert all("uid" in p and "name" not in p for c, p in client.calls if c == ACCESS)


async def test_listing_entry_without_uid_is_fetched_by_name(repo):
    client = FakeRulebaseClient()
    client.add_layer(ACCESS, make_layer("big", "Big", 2))
    client.listings["show-access-layers"] = [{"name": "Big"}]
    service, _, _ = service_for(repo, client)
    await refresh(service)
    assert len(await rules(repo, layer="Big")) == 2


async def test_inline_layer_not_listed_is_fetched_through_closure(repo):
    client = domain4_fake()
    inline = load_fixture("inline_layer_fpcr_uat_active_inline.json")["uid"]
    client.listings["show-access-layers"] = [e for e in client.listings["show-access-layers"] if e["uid"] != inline]
    service, _, _ = service_for(repo, client)
    await refresh(service)
    assert [r.rule_number for r in await rules(repo, layer="FPCR_UAT_Active Inline")] == [1, 2]


async def test_failed_refresh_yields_domain_failed_even_when_state_store_fails(repo, monkeypatch):
    async def db_down(*_args, **_kwargs):
        raise RuntimeError("database unavailable")

    for method in ("replace_domain_rulebases", "mark_rulebase_sync_failed", "get_rulebase_sync_state"):
        monkeypatch.setattr(repo, method, db_down)
    service, _, _ = service_for(repo)
    final = (await refresh(service))[-1]
    assert final["status"] == "domain_failed" and "database unavailable" in final["error"]
    assert (final["result"].status, final["result"].session_uid) == ("failed", None)


# --------------------------------------------------------------------------- #
# refresh_all
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_all_skip_mode_yields_single_event_and_short_circuits():
    service, client, _ = make_service()

    events = await collect(service.refresh_all(mode="skip"))

    assert events == [{"message": "Rulebase refresh skipped", "status": "skipped"}]
    client.get_mgmt_names.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_all_uses_client_mgmt_names_and_domains_by_default():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    client.get_domains = AsyncMock(return_value=[MagicMock(name="domainA")])
    # Use simple stand-ins with a `.name` attribute for domains.
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])

    calls = _stub_domain_refresh(service)

    events = await collect(service.refresh_all())

    client.get_mgmt_names.assert_called_once_with()
    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=False)
    assert events == []
    assert calls == [("mgmt1", "domainA", True)]


@pytest.mark.asyncio
async def test_refresh_all_includes_global_when_requested():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "Global"
    client.get_domains = AsyncMock(return_value=[domain_obj])

    calls = _stub_domain_refresh(service)

    events = await collect(service.refresh_all(include_global=True))

    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=True)
    assert events == []
    assert calls == [("mgmt1", "Global", True)]


@pytest.mark.asyncio
async def test_refresh_all_respects_explicit_mgmt_and_domain_filters():
    service, client, _ = make_service()
    domain_a = MagicMock()
    domain_a.name = "domainA"
    domain_b = MagicMock()
    domain_b.name = "domainB"
    client.get_domains = AsyncMock(return_value=[domain_a, domain_b])

    calls = _stub_domain_refresh(service)

    events = await collect(service.refresh_all(mgmt_names=["mgmt1"], domain_names=["domainB"]))

    client.get_mgmt_names.assert_not_called()
    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=False)
    assert events == []
    assert calls == [("mgmt1", "domainB", True)]


@pytest.mark.asyncio
async def test_refresh_all_forwards_events_from_each_sub_refresh():
    service, client, _ = make_service()
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    stub_event = {"message": "refresh-event", "status": "domain_refreshed", "result": object()}
    _stub_domain_refresh(service, events=[stub_event])

    events = await collect(service.refresh_all())

    assert events == [{"message": "refresh-event", "status": "domain_refreshed"}]  # result stripped


# --------------------------------------------------------------------------- #
# refresh_all - domain-list re-fetch (a domain created in SmartConsole after
# the domains table was first seeded must not stay invisible forever)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_all_force_mode_always_refetches_domain_list():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="force"))

    client._domain_service.populate_domain_cache.assert_awaited_once_with("mgmt1")


@pytest.mark.asyncio
async def test_refresh_all_force_mode_refetches_on_every_call_no_ttl():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="force"))
    await collect(service.refresh_all(mode="force"))

    assert client._domain_service.populate_domain_cache.await_count == 2


@pytest.mark.asyncio
async def test_refresh_all_check_mode_refetches_domain_list_on_first_call():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="check"))

    client._domain_service.populate_domain_cache.assert_awaited_once_with("mgmt1")


@pytest.mark.asyncio
async def test_refresh_all_check_mode_does_not_refetch_within_ttl_window():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    service, client, _ = make_service(clock=clock)
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="check"))
    clock.advance(60)  # 1 minute later, well inside the 1h TTL
    await collect(service.refresh_all(mode="check"))

    client._domain_service.populate_domain_cache.assert_awaited_once_with("mgmt1")


@pytest.mark.asyncio
async def test_refresh_all_check_mode_refetches_domain_list_after_ttl_expires():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    service, client, _ = make_service(clock=clock)
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="check"))
    clock.advance(3601)  # just past the 1h TTL
    await collect(service.refresh_all(mode="check"))

    assert client._domain_service.populate_domain_cache.await_count == 2


@pytest.mark.asyncio
async def test_refresh_all_domain_list_ttl_is_configurable():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    service, client, _ = make_service(clock=clock, domain_list_refresh_ttl=30)
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()
    _stub_domain_refresh(service)

    await collect(service.refresh_all(mode="check"))
    clock.advance(31)
    await collect(service.refresh_all(mode="check"))

    assert client._domain_service.populate_domain_cache.await_count == 2


@pytest.mark.asyncio
async def test_refresh_all_domain_list_refetch_failure_does_not_abort_refresh():
    """A failed opportunistic re-fetch must not prevent refresh_all from proceeding
    with whatever `client.get_domains()` already has cached - this is purely a
    freshening step, not a precondition."""
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=RuntimeError("boom"))
    calls = _stub_domain_refresh(service)

    events = await collect(service.refresh_all(mode="force"))

    assert events == []
    assert calls == [("mgmt1", "domainA", True)]


@pytest.mark.asyncio
async def test_refresh_all_skip_mode_does_not_touch_domain_list_refresh():
    service, client, _ = make_service()
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()

    await collect(service.refresh_all(mode="skip"))

    client._domain_service.populate_domain_cache.assert_not_awaited()


# --------------------------------------------------------------------------- #
# refresh_domain failure taxonomy
# --------------------------------------------------------------------------- #


async def snapshot_rows(repo):
    return sorted(r.id for r in await rules(repo)) + sorted(r.id for r in await rules(repo, model=RulebaseNAT))


async def refreshed_then(repo, mutate):
    """Refresh once (good snapshot sess-1), apply ``mutate(client, head)``, refresh again; return (events, before)."""
    service, client, head = service_for(repo)
    await refresh(service)
    before = await snapshot_rows(repo)
    mutate(client, head)
    return await refresh(service), before, service


async def test_refresh_refuses_dirty_session_changes(repo):
    events, before, _ = await refreshed_then(repo, lambda c, h: c.session.update(changes=1))
    assert events[-1]["status"] == "domain_failed" and events[-1]["error"] == "dirty session"
    assert await snapshot_rows(repo) == before


async def test_refresh_refuses_dirty_session_locks(repo):
    events, _, _ = await refreshed_then(repo, lambda c, h: c.session.update(locks=2))
    assert events[-1]["error"] == "dirty session"


async def test_dirty_session_keeps_snapshot_and_session_uid(repo):
    def dirty(client, head):
        head.uid = "sess-2"
        client.session = load_fixture("show_session_dirty.json")

    events, before, _ = await refreshed_then(repo, dirty)
    state = await repo.get_rulebase_sync_state("m1", "Domain4")
    assert (state.status, state.last_error, state.session_uid) == ("failed", "dirty session", "sess-1")
    assert events[-1]["result"].session_uid == "sess-1" and await snapshot_rows(repo) == before


async def test_clean_session_proceeds(repo):
    client = domain4_fake()
    client.session = load_fixture("show_session_clean.json")
    service, _, _ = service_for(repo, client)
    assert (await refresh(service))[-1]["status"] == "domain_refreshed"


async def test_failed_refresh_keeps_old_snapshot_and_session_uid(repo):
    def broken(client, head):
        head.uid = "sess-2"
        client.call_failures[(ACCESS, "FPCR_UAT_Active Network")] = ApiCallResult(
            success=False, code="generic_error", message="boom"
        )

    events, before, _ = await refreshed_then(repo, broken)
    assert events[-1]["status"] == "domain_failed" and "boom" in events[-1]["error"]
    assert (await repo.get_rulebase_sync_state("m1", "Domain4")).session_uid == "sess-1"
    assert await snapshot_rows(repo) == before


async def test_other_layer_error_fails_domain(repo):
    events, _, _ = await refreshed_then(
        repo,
        lambda c, h: c.call_failures.update(
            {
                (ACCESS, "FPCR_UAT_Active AppControl"): ApiCallResult(
                    success=False, code="generic_err_object_not_found", message="gone"
                )
            }
        ),
    )
    assert events[-1]["status"] == "domain_failed" and "generic_err_object_not_found" in events[-1]["error"]


async def test_unsupported_https_command_yields_empty_type_not_failure(repo):
    client = domain4_fake()
    client.query_failures["show-https-layers"] = ApiQueryResult(
        success=False,
        code="generic_err_command_not_found",
        message="Requested API command: [show-https-layers] not found",
    )
    service, _, _ = service_for(repo, client)
    events = await refresh(service)
    assert events[-1]["status"] == "domain_refreshed"
    assert await rules(repo, model=RulebaseHTTPS) == []
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    assert not any(o.rulebase_type == "https" for p in snapshot.packages for o in p.layers)


async def test_unsupported_layer_read_yields_empty_type(repo):
    client = domain4_fake()
    client.call_failures[("show-threat-rulebase", "IPS")] = ApiCallResult(
        success=False, code="generic_err_command_not_found", message="not found"
    )
    service, _, _ = service_for(repo, client)
    assert (await refresh(service))[-1]["status"] == "domain_refreshed"
    assert await rules(repo, model=RulebaseThreat) == []


async def test_listing_failure_fails_domain_keeps_rows(repo):
    events, before, _ = await refreshed_then(
        repo,
        lambda c, h: c.query_failures.update(
            {"show-threat-layers": ApiQueryResult(success=False, code="generic_error", message="denied")}
        ),
    )
    assert events[-1]["status"] == "domain_failed" and "show-threat-layers" in events[-1]["error"]
    assert await snapshot_rows(repo) == before


async def test_invalid_listing_entry_fails_domain(repo):
    events, _, _ = await refreshed_then(repo, lambda c, h: c.listings["show-access-layers"].append({"color": "red"}))
    assert events[-1]["status"] == "domain_failed" and "invalid access layer listing entry" in events[-1]["error"]


async def test_check_head_failure_keeps_snapshot_marks_failed(repo):
    events, before, _ = await refreshed_then(repo, lambda c, h: setattr(h, "error", PublishedHeadError("no timestamp")))
    assert events[-1]["status"] == "domain_failed" and "no timestamp" in events[-1]["error"]
    state = await repo.get_rulebase_sync_state("m1", "Domain4")
    assert (state.status, state.session_uid) == ("failed", "sess-1") and await snapshot_rows(repo) == before


async def test_force_with_head_failure_stores_unversioned_snapshot(repo):
    service, _, head = service_for(repo)
    head.error = PublishedHeadError("no timestamp")
    events = await refresh(service, force=True)
    assert events[-1]["status"] == "domain_refreshed" and events[-1]["result"].status == "unversioned"
    assert any(e.get("status") == "warning" for e in events)
    state = await repo.get_rulebase_sync_state("m1", "Domain4")
    assert (state.status, state.session_uid) == ("unversioned", None)


async def test_invalid_credentials_fails_domain(repo):
    for force in (False, True):
        service, _, head = service_for(repo)
        head.error = InvalidCredentialsError("bad key")
        events = await refresh(service, force=force)
        assert events[-1]["status"] == "domain_failed" and "bad key" in events[-1]["error"]


async def test_cancelled_refresh_leaves_snapshot_and_state(repo):
    service, client, _ = service_for(repo)
    await refresh(service)
    before, state_before = await snapshot_rows(repo), await repo.get_rulebase_sync_state("m1", "Domain4")
    real = client.api_call

    async def cancelled(*args, **kwargs):
        if kwargs.get("command") == "show-nat-rulebase":
            raise asyncio.CancelledError
        return await real(*args, **kwargs)

    client.api_call = cancelled  # type: ignore[method-assign]
    with pytest.raises(asyncio.CancelledError):
        await refresh(service)
    state = await repo.get_rulebase_sync_state("m1", "Domain4")
    assert await snapshot_rows(repo) == before
    assert (state.status, state.session_uid, state.update_time) == (
        state_before.status,
        state_before.session_uid,
        state_before.update_time,
    )


async def test_failed_link_is_warning_not_failure(repo):
    client = domain4_fake()
    glb = load_fixture("global_layer_no_package.json")["uid"]
    client.call_failures[(ACCESS, f"{glb}@FPCR_UAT_Active")] = ApiCallResult(
        success=False, code="generic_error", message="x"
    )
    service, _, _ = service_for(repo, client)
    events = await refresh(service)
    assert events[-1]["status"] == "domain_refreshed"
    assert [e for e in events if e.get("status") == "warning" and "place-holder link" in e["message"]]
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    layout = snapshot.packages[0]
    entries = number_package(layout, "access", {lay.layer_uid: lay for lay in snapshot.layers})[0]
    assert [(e.number, e.kind) for e in entries] == [("1", "rule"), ("2", "place-holder"), ("3", "rule")]


def _link_read_raises(client, exc):
    glb = load_fixture("global_layer_no_package.json")["uid"]
    real = client.api_call

    async def wrapper(*args, **kwargs):
        payload = kwargs.get("payload") or {}
        if payload.get("uid") == glb and payload.get("package"):
            raise exc
        return await real(*args, **kwargs)

    client.api_call = wrapper  # type: ignore[method-assign]


async def test_link_read_transport_error_is_warning(repo):
    client = domain4_fake()
    _link_read_raises(client, TimeoutError("read timed out"))
    service, _, _ = service_for(repo, client)
    events = await refresh(service)
    assert events[-1]["status"] == "domain_refreshed"
    assert [e for e in events if e.get("status") == "warning" and "place-holder link" in e["message"]]
    snapshot = await repo.load_domain_rulebase_snapshot("m1", "Domain4")
    entries = number_package(snapshot.packages[0], "access", {lay.layer_uid: lay for lay in snapshot.layers})[0]
    assert [(e.number, e.kind) for e in entries] == [("1", "rule"), ("2", "place-holder"), ("3", "rule")]


async def test_link_read_invalid_credentials_fails_domain(repo):
    client = domain4_fake()
    _link_read_raises(client, InvalidCredentialsError("bad key"))
    service, _, _ = service_for(repo, client)
    events = await refresh(service)
    assert events[-1]["status"] == "domain_failed" and "bad key" in events[-1]["error"]


async def test_refresh_refuses_dirty_session_with_force(repo):
    service, client, _ = service_for(repo)
    await refresh(service)
    before = await snapshot_rows(repo)
    client.session.update(changes=1)
    events = await refresh(service, force=True)
    assert events[-1]["status"] == "domain_failed" and events[-1]["error"] == "dirty session"
    assert await snapshot_rows(repo) == before


async def test_check_mode_staleness_error_still_refreshes_and_continues(repo):
    service, client, _ = service_for(repo)
    client.domains = ["Domain3", "Domain4"]
    real = service._staleness

    async def flaky(mgmt_name, domain):
        if domain == "Domain3":
            raise RuntimeError("db down")
        return await real(mgmt_name, domain)

    service._staleness = flaky  # type: ignore[method-assign]
    events = await collect(service.refresh_all(mgmt_names=["m1"], mode="check"))
    by_domain = {e["domain_name"]: e["status"] for e in events if str(e.get("status", "")).startswith("domain_")}
    # the failed check counts as stale: Domain3 is refreshed anyway and Domain4 is still processed
    assert by_domain == {"Domain3": "domain_refreshed", "Domain4": "domain_refreshed"}
    assert events[-1]["status"] == "domain_refreshed"


async def test_extraction_error_fails_domain(repo, monkeypatch):
    from arodonata.api.services import rulebase_refresh_service as module

    def boom(snapshot):
        raise TypeError("bad rule")

    monkeypatch.setattr(module, "build_rulebase_rows", boom)
    service, _, _ = service_for(repo)
    events = await refresh(service)
    assert events[-1]["status"] == "domain_failed" and "bad rule" in events[-1]["error"]


async def test_refresh_service_without_object_service_raises_on_refresh_domain(repo):
    service = RulebaseRefreshService(client=domain4_fake(), cache=repo)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="object_service"):
        await refresh(service)


# --------------------------------------------------------------------------- #
# refresh_all modes, staleness, deprecated wrappers
# --------------------------------------------------------------------------- #


async def test_check_mode_skips_domain_with_same_session_uid(repo):
    service, client, _ = service_for(repo)
    await refresh(service)
    client.calls.clear()
    events = await collect(service.refresh_all(mgmt_names=["m1"], domain_names=["Domain4"], mode="check"))
    assert [e["status"] for e in events if "status" in e] == ["domain_fresh"]
    assert [c for c, _ in client.calls] == ["show-last-published-session"]


async def test_check_mode_refreshes_after_rules_only_publish(repo):
    from arodonata.cache.models import LastPublishedSession

    service, _, head = service_for(repo)
    await refresh(service)
    head.uid = "sess-2"  # a rules-only publish: the object baseline may already be at sess-2, the rulebase one is not
    await repo.upsert_last_published_session(
        LastPublishedSession(id="m1:Domain4", mgmt_name="m1", domain_name="Domain4", uid="sess-2")
    )
    events = await collect(service.refresh_all(mgmt_names=["m1"], domain_names=["Domain4"], mode="check"))
    assert events[-1]["status"] == "domain_refreshed" and "result" not in events[-1]
    assert (await repo.get_rulebase_sync_state("m1", "Domain4")).session_uid == "sess-2"


async def test_force_refreshes_regardless(repo):
    service, _, _ = service_for(repo)
    await refresh(service)
    events = await collect(service.refresh_all(mgmt_names=["m1"], domain_names=["Domain4"], mode="force"))
    assert events[-1]["status"] == "domain_refreshed"


async def test_check_invalid_credentials_is_stale(repo):
    service, _, head = service_for(repo)
    await refresh(service)
    head.error = InvalidCredentialsError("bad key")
    assert await service.is_rulebase_stale("m1", "Domain4") is True


async def test_check_head_error_is_fresh_with_warning(repo):
    service, _, head = service_for(repo)
    await refresh(service)
    head.error = PublishedHeadError("timeout")
    assert await service.is_rulebase_stale("m1", "Domain4") is False
    events = await collect(service.refresh_all(mgmt_names=["m1"], domain_names=["Domain4"], mode="check"))
    assert [e["status"] for e in events if "status" in e] == ["warning", "domain_fresh"]


@pytest.mark.parametrize(
    "state_kw",
    [
        None,
        {"format_version": 1, "status": "ok"},
        {"format_version": 2, "status": "failed"},
        {"format_version": 2, "status": "unversioned"},
    ],
)
async def test_is_stale_without_usable_sync_state(repo, state_kw):
    service, client, _ = service_for(repo)
    if state_kw is not None:
        await repo.replace_domain_rulebases(
            "m1",
            "Domain4",
            [],
            RulebaseSyncState(id="m1:Domain4", mgmt_name="m1", domain_name="Domain4", session_uid="sess-1", **state_kw),
        )
    assert await service.is_rulebase_stale("m1", "Domain4") is True
    assert client.calls == []  # no API call


async def test_is_stale_falls_back_to_publish_time_without_uid(repo):
    service, _, head = service_for(repo)
    await refresh(service)
    head.uid = ""
    assert await service.is_rulebase_stale("m1", "Domain4") is False
    head.published = head.published + timedelta(minutes=1)
    assert await service.is_rulebase_stale("m1", "Domain4") is True


@pytest.mark.parametrize("name", ["access", "nat", "https", "threat"])
async def test_per_type_wrapper_warns_and_refreshes_domain(repo, name):
    service, _, _ = service_for(repo)
    with pytest.warns(DeprecationWarning, match=f"refresh_{name}_rulebases is deprecated"):
        events = await collect(getattr(service, f"refresh_{name}_rulebases")("m1", "Domain4"))
    assert events[-1]["status"] == "domain_refreshed"
    assert all("result" not in e for e in events)  # JSON-safe, like refresh_all
    assert await rules(repo) and await rules(repo, model=RulebaseNAT)  # every type, not only NAT
