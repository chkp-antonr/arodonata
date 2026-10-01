"""Unit tests for RulebaseRefreshService.

Fixture-driven: recorded Domain4 layers served by a paging fake into a real in-memory SQLite repository for the refresh flows; refresh_all domain-list tests keep their mocks.
"""

from __future__ import annotations

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
from arodonata.cache.models import RulebaseAccess, RulebaseHTTPS, RulebaseNAT, RulebaseThreat
from arodonata.cache.repository import CacheRepository
from arodonata.extractors.base import ExtractionContext
from arodonata.extractors.rulebases import AccessRuleExtractor
from tests.unit.rulebase.fakes import FakeRulebaseClient, load_fixture, make_layer


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
    cache.replace_domain_rulebase_type = AsyncMock(side_effect=lambda model, m, d, rows: len(rows))
    service = RulebaseRefreshService(client=client, cache=cache, **kwargs)
    return service, client, cache


def _no_op_domain_generators(service):
    """Stub out the four per-domain rulebase generators for refresh_all tests that
    only care about domain-list resolution, not rulebase content."""
    for attr in (
        "refresh_access_rulebases",
        "refresh_nat_rulebases",
        "refresh_https_rulebases",
        "refresh_threat_rulebases",
    ):

        async def _empty_gen(*_args, **_kwargs):
            return
            yield  # pragma: no cover - unreachable, makes this an async generator

        setattr(service, attr, _empty_gen)


def access_rule(uid="uid-1", rule_number=1, name="Rule 1", extra=None):
    rule = {
        "type": "access-rule",
        "uid": uid,
        "rule-number": rule_number,
        "name": name,
        "enabled": True,
        "source": [],
        "destination": [],
        "service": [],
        "action": {"accept": True},
        "track": {"type": "Log"},
    }
    if extra:
        rule.update(extra)
    return rule


async def collect(agen):
    return [event async for event in agen]


# --------------------------------------------------------------------------- #
# _validate_and_get_layer_name
# --------------------------------------------------------------------------- #


def test_validate_layer_name_returns_name_for_valid_layer():
    service, _, _ = make_service()
    assert service._validate_and_get_layer_name({"name": "Network"}) == "Network"


def test_validate_layer_name_returns_none_for_non_dict():
    service, _, _ = make_service()
    assert service._validate_and_get_layer_name("not-a-dict") is None


def test_validate_layer_name_returns_none_when_name_missing():
    service, _, _ = make_service()
    assert service._validate_and_get_layer_name({"uid": "x"}) is None


def test_validate_layer_name_returns_none_when_name_empty():
    service, _, _ = make_service()
    assert service._validate_and_get_layer_name({"name": ""}) is None


# --------------------------------------------------------------------------- #
# _extract_rules_recursive
# --------------------------------------------------------------------------- #


def test_extract_rules_recursive_extracts_flat_rules():
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    rules_data = [access_rule(uid="r1"), access_rule(uid="r2")]

    extracted = service._extract_rules_recursive(
        rules_data, AccessRuleExtractor(), context, RulebaseAccess, "mgmt1", "", "Network"
    )

    assert [r.uid for r in extracted] == ["r1", "r2"]
    assert all(r.layer_name == "Network" for r in extracted)
    assert extracted[0].id == "mgmt1::Network:r1"
    assert isinstance(extracted[0], RulebaseAccess)


def test_extract_rules_recursive_recurses_into_sections():
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    rules_data = [
        {"type": "access-section", "uid": "sec1", "rulebase": [access_rule(uid="r1"), access_rule(uid="r2")]},
        access_rule(uid="r3"),
    ]

    extracted = service._extract_rules_recursive(
        rules_data, AccessRuleExtractor(), context, RulebaseAccess, "mgmt1", "", "Network"
    )

    assert sorted(r.uid for r in extracted) == ["r1", "r2", "r3"]


def test_extract_rules_recursive_recurses_via_generic_rulebase_key():
    # Even without an explicit "access-section" type, the presence of a
    # "rulebase" key triggers recursion.
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    rules_data = [{"type": "something-else", "rulebase": [access_rule(uid="nested")]}]

    extracted = service._extract_rules_recursive(
        rules_data, AccessRuleExtractor(), context, RulebaseAccess, "mgmt1", "", "Network"
    )

    assert [r.uid for r in extracted] == ["nested"]


def test_extract_rules_recursive_skips_non_dict_items():
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    rules_data = ["not-a-dict", access_rule(uid="r1")]

    extracted = service._extract_rules_recursive(
        rules_data, AccessRuleExtractor(), context, RulebaseAccess, "mgmt1", "", "Network"
    )

    assert [r.uid for r in extracted] == ["r1"]


def test_extract_rules_recursive_skips_unmatched_type_for_extractor():
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    nat_rule = {
        "type": "nat-rule",
        "uid": "n1",
        "rule-number": 1,
        "name": "NAT 1",
        "enabled": True,
    }
    # A NAT rule fed into the access extractor should be silently ignored.
    extracted = service._extract_rules_recursive(
        [nat_rule], AccessRuleExtractor(), context, RulebaseAccess, "mgmt1", "", "Network"
    )
    assert extracted == []


NETWORK = "FPCR_UAT_Active Network"
INLINE = "FPCR_UAT_Active Inline"
ACCESS = "show-access-rulebase"


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield CacheRepository(DatabaseManager(engine))
    await engine.dispose()


def lab_client(*layer_fixtures: str) -> FakeRulebaseClient:
    """Domain4-shaped fake: an access listing of the given recorded layers, each served by name."""
    client = FakeRulebaseClient()
    for name in layer_fixtures:
        layer = load_fixture(name)
        client.add_layer(ACCESS, layer)
        client.listings.setdefault("show-access-layers", []).append({"uid": layer["uid"], "name": layer["name"]})
    return client


def domain4(repo, client) -> RulebaseRefreshService:
    return RulebaseRefreshService(client=client, cache=repo)  # type: ignore[arg-type]


async def cached(repo, model=RulebaseAccess, layer=None):
    filters = {"layer_name": layer} if layer else None
    return await repo.get_rulebase(model, ["m1"], ["Domain4"], filters)


# ---- 1.2 complete layer listings -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "command", "key"),
    [
        ("refresh_access_rulebases", "show-access-layers", "access-layers"),
        ("refresh_https_rulebases", "show-https-layers", "https-layers"),
        ("refresh_threat_rulebases", "show-threat-layers", "threat-layers"),
    ],
)
async def test_layer_listing_passes_container_key(repo, method, command, key):
    client = FakeRulebaseClient()
    await collect(getattr(domain4(repo, client), method)("m1", "Domain4"))
    assert client.query_calls == [
        {"mgmt_name": "m1", "command": command, "domain": "Domain4", "details_level": "standard", "container_key": key}
    ]


async def test_layer_listing_60_layers_two_pages(repo):
    client = FakeRulebaseClient()
    for i in range(60):
        layer = make_layer(f"L{i:02}", f"Layer {i:02}", 1)
        client.add_layer(ACCESS, layer)
        client.listings.setdefault("show-access-layers", []).append({"uid": layer["uid"], "name": layer["name"]})
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    assert len({r.layer_name for r in await cached(repo)}) == 60


# ---- 1.3 names from objects-dictionary -----------------------------------------------------------------


async def test_process_layer_uses_objects_dictionary_key(repo):
    client = lab_client("domain_layer_fpcr_uat_active_network.json")
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    rules = {r.rule_number: r for r in await cached(repo)}
    assert (rules[1].sources, rules[1].destinations, rules[1].services) == ("hostA_8", "hostA_0", "https")


async def test_action_and_track_resolved_to_names(repo):
    client = lab_client("domain_layer_fpcr_uat_active_network.json")
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    rules = {r.rule_number: r for r in await cached(repo)}
    assert (rules[1].action, rules[1].track) == ("Accept", "Log")
    assert (rules[2].action, rules[2].track) == ("Inner Layer", "None")
    assert (rules[6].action, rules[6].track) == ("Drop", "None")


async def test_refresh_does_not_upsert_objects(repo, monkeypatch):
    spy = AsyncMock()
    monkeypatch.setattr(repo, "upsert_objects", spy)
    client = lab_client("domain_layer_fpcr_uat_active_network.json")
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    spy.assert_not_awaited()


@pytest.mark.parametrize(
    "fixture",
    [
        "domain_layer_fpcr_uat_active_network.json",
        "inline_layer_fpcr_uat_active_inline.json",
        "global_layer_no_package.json",
        "global_layer_with_package.json",
    ],
)
async def test_extracted_values_fit_column_lengths(repo, fixture):
    """Every string bound for a length-limited column fits (SQLite ignores VARCHAR(n); PostgreSQL does not)."""
    data = load_fixture(fixture)
    rows = domain4(repo, FakeRulebaseClient())._rows_from_layer_response(
        data, "access", "m1", "Domain4", layer_name=data["name"]
    )
    assert rows
    for row in rows:
        for col in type(row).__table__.columns:
            length = getattr(col.type, "length", None)
            value = getattr(row, col.name)
            if isinstance(length, int) and isinstance(value, str):
                assert len(value) <= length, f"{fixture}: {col.name}={value!r} exceeds {length}"


# ---- 1.4 layer_name from the response; atomic per-type replace -----------------------------------------


async def test_extracted_rules_carry_layer_name_from_response(repo):
    data = load_fixture("domain_layer_fpcr_uat_active_network.json")
    assert all("layer" not in r for section in data["rulebase"] for r in section["rulebase"])  # CP sends no layer key
    client = lab_client("domain_layer_fpcr_uat_active_network.json")
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    rows = await cached(repo, layer=NETWORK)
    assert len(rows) == 6 and {r.layer_name for r in rows} == {NETWORK}
    assert rows[0].id == f"m1:Domain4:{NETWORK}:{rows[0].uid}"


async def test_rule_deleted_in_cp_is_removed_from_cache(repo):
    client = lab_client("domain_layer_fpcr_uat_active_network.json")
    service = domain4(repo, client)
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    client.layers[(ACCESS, NETWORK)]["rulebase"][-1]["rulebase"] = []  # Cleanup rule deleted in CP
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert [r.rule_number for r in await cached(repo)] == [1, 2, 3, 4, 5]


async def test_emptied_layer_is_cleared(repo):
    client = lab_client("inline_layer_fpcr_uat_active_inline.json")
    service = domain4(repo, client)
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert len(await cached(repo)) == 2
    client.layers[(ACCESS, INLINE)] = {
        "uid": "dbfa273a",
        "name": INLINE,
        "rulebase": [],
        "objects-dictionary": [],
        "from": 0,
        "to": 0,
        "total": 0,
    }
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert await cached(repo) == []
    assert events[-1]["count"] == 0


async def test_layer_deleted_in_cp_is_removed(repo):
    client = lab_client("domain_layer_fpcr_uat_active_network.json", "inline_layer_fpcr_uat_active_inline.json")
    service = domain4(repo, client)
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    client.listings["show-access-layers"] = [{"name": NETWORK}]  # inline layer deleted in CP
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert {r.layer_name for r in await cached(repo)} == {NETWORK}


async def _seeded(repo):
    client = lab_client("domain_layer_fpcr_uat_active_network.json", "inline_layer_fpcr_uat_active_inline.json")
    service = domain4(repo, client)
    await collect(service.refresh_access_rulebases("m1", "Domain4"))
    before = sorted(r.id for r in await cached(repo))
    assert len(before) == 8
    return client, service, before


async def test_layer_fetch_failure_keeps_type_rows_and_yields_domain_failed(repo):
    client, service, before = await _seeded(repo)
    client.call_failures[(ACCESS, INLINE)] = ApiCallResult(success=False, code="generic_error", message="boom")
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert sorted(r.id for r in await cached(repo)) == before
    failed = [e for e in events if e.get("status") == "domain_failed"]
    assert len(failed) == 1 and failed[0]["rulebase_type"] == "access" and "boom" in failed[0]["error"]


async def test_invalid_listing_entry_keeps_type_rows(repo):
    client, service, before = await _seeded(repo)
    client.listings["show-access-layers"].append({"uid": "no-name"})
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert sorted(r.id for r in await cached(repo)) == before
    assert [e["status"] for e in events if "status" in e] == ["domain_failed"]


async def test_extraction_error_keeps_type_rows(repo, monkeypatch):
    client, service, before = await _seeded(repo)

    def boom(raw, context):
        raise TypeError("bad rule shape")

    monkeypatch.setattr(service._extractors["access"], "extract", boom)
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert sorted(r.id for r in await cached(repo)) == before
    assert [e["status"] for e in events if "status" in e] == ["domain_failed"]


async def test_listing_failure_keeps_rows_and_yields_warning(repo):
    client, service, before = await _seeded(repo)
    client.query_failures["show-access-layers"] = ApiQueryResult(success=False, message="no access")
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert sorted(r.id for r in await cached(repo)) == before
    assert [e["status"] for e in events] == ["warning"]


async def test_unexpected_exception_keeps_rows_and_yields_error(repo):
    client, service, before = await _seeded(repo)
    client.api_call = AsyncMock(side_effect=RuntimeError("kaboom"))  # type: ignore[method-assign]
    events = await collect(service.refresh_access_rulebases("m1", "Domain4"))
    assert sorted(r.id for r in await cached(repo)) == before
    assert events[-1]["status"] == "error" and "kaboom" in events[-1]["message"]


async def test_layer_with_120_rules_is_cached_completely(repo):
    client = FakeRulebaseClient()
    client.add_layer(ACCESS, make_layer("BIG", "Big", 120, rules_per_section=40))
    client.listings["show-access-layers"] = [{"uid": "BIG", "name": "Big"}]
    await collect(domain4(repo, client).refresh_access_rulebases("m1", "Domain4"))
    assert [r.rule_number for r in await cached(repo)] == list(range(1, 121))


@pytest.mark.parametrize(
    ("method", "listing", "command", "rule_type", "model"),
    [
        ("refresh_https_rulebases", "show-https-layers", "show-https-rulebase", "https-rule", RulebaseHTTPS),
        ("refresh_threat_rulebases", "show-threat-layers", "show-threat-rulebase", "threat-rule", RulebaseThreat),
    ],
)
async def test_https_and_threat_use_the_same_flow(repo, method, listing, command, rule_type, model):
    client = FakeRulebaseClient()
    client.add_layer(command, make_layer("X", "X layer", 3, rule_type=rule_type))
    client.listings[listing] = [{"uid": "X", "name": "X layer"}]
    events = await collect(getattr(domain4(repo, client), method)("m1", "Domain4"))
    rows = await cached(repo, model=model)
    assert [r.rule_number for r in rows] == [1, 2, 3] and {r.layer_name for r in rows} == {"X layer"}
    assert events[-1]["count"] == 3
    assert client.calls[0] == (
        command,
        {"name": "X layer", "details-level": "full", "use-object-dictionary": True, "limit": 100, "offset": 0},
    )


# ---- 1.5 NAT refresh per package with nat-policy -------------------------------------------------------


NAT = "show-nat-rulebase"


def nat_client() -> FakeRulebaseClient:
    client = FakeRulebaseClient()
    client.listings["show-packages"] = [
        {"uid": "p1", "name": "FPCR_UAT_Active", "nat-policy": True},
        {"uid": "p2", "name": "Standard", "nat-policy": True},
        {"uid": "p3", "name": "NoNat", "nat-policy": False},
    ]
    for package, n in (("FPCR_UAT_Active", 2), ("Standard", 1)):
        client.add_layer(NAT, make_layer(f"nat-{package}", f"{package} NAT", n, rule_type="nat-rule"), key=package)
    return client


async def test_nat_fetched_for_each_package_with_nat_policy(repo):
    client = nat_client()
    await collect(domain4(repo, client).refresh_nat_rulebases("m1", "Domain4"))
    assert client.query_calls[0]["command"] == "show-packages"
    assert client.query_calls[0]["container_key"] == "packages" and client.query_calls[0]["details_level"] == "full"
    assert [(cmd, p["package"]) for cmd, p in client.calls] == [(NAT, "FPCR_UAT_Active"), (NAT, "Standard")]
    assert all(p["details-level"] == "full" and p["use-object-dictionary"] is True for _, p in client.calls)


async def test_nat_rows_keyed_by_package(repo):
    await collect(domain4(repo, nat_client()).refresh_nat_rulebases("m1", "Domain4"))
    rows = await cached(repo, model=RulebaseNAT, layer="FPCR_UAT_Active")
    assert [r.rule_number for r in rows] == [1, 2]
    assert rows[0].id == f"m1:Domain4:FPCR_UAT_Active:{rows[0].uid}"
    assert await cached(repo, model=RulebaseNAT, layer="NAT") == []


async def test_nat_package_listing_failure_keeps_rows_and_yields_warning(repo):
    client = nat_client()
    service = domain4(repo, client)
    await collect(service.refresh_nat_rulebases("m1", "Domain4"))
    client.query_failures["show-packages"] = ApiQueryResult(success=False, message="denied")
    events = await collect(service.refresh_nat_rulebases("m1", "Domain4"))
    assert [e["status"] for e in events] == ["warning"]
    assert len(await cached(repo, model=RulebaseNAT)) == 3


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

    for attr in (
        "refresh_access_rulebases",
        "refresh_nat_rulebases",
        "refresh_https_rulebases",
        "refresh_threat_rulebases",
    ):

        async def _empty_gen(*_args, **_kwargs):
            return
            yield  # pragma: no cover - unreachable, makes this an async generator

        setattr(service, attr, _empty_gen)

    events = await collect(service.refresh_all())

    client.get_mgmt_names.assert_called_once_with()
    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=False)
    assert events == [
        {
            "message": "Refreshing rulebases for mgmt1:domainA",
            "mgmt_name": "mgmt1",
            "domain_name": "domainA",
        }
    ]


@pytest.mark.asyncio
async def test_refresh_all_includes_global_when_requested():
    service, client, _ = make_service()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    domain_obj = MagicMock()
    domain_obj.name = "Global"
    client.get_domains = AsyncMock(return_value=[domain_obj])

    for attr in (
        "refresh_access_rulebases",
        "refresh_nat_rulebases",
        "refresh_https_rulebases",
        "refresh_threat_rulebases",
    ):

        async def _empty_gen(*_args, **_kwargs):
            return
            yield  # pragma: no cover

        setattr(service, attr, _empty_gen)

    events = await collect(service.refresh_all(include_global=True))

    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=True)
    assert events == [
        {
            "message": "Refreshing rulebases for mgmt1:Global",
            "mgmt_name": "mgmt1",
            "domain_name": "Global",
        }
    ]


@pytest.mark.asyncio
async def test_refresh_all_respects_explicit_mgmt_and_domain_filters():
    service, client, _ = make_service()
    domain_a = MagicMock()
    domain_a.name = "domainA"
    domain_b = MagicMock()
    domain_b.name = "domainB"
    client.get_domains = AsyncMock(return_value=[domain_a, domain_b])

    for attr in (
        "refresh_access_rulebases",
        "refresh_nat_rulebases",
        "refresh_https_rulebases",
        "refresh_threat_rulebases",
    ):

        async def _empty_gen(*_args, **_kwargs):
            return
            yield  # pragma: no cover

        setattr(service, attr, _empty_gen)

    events = await collect(service.refresh_all(mgmt_names=["mgmt1"], domain_names=["domainB"]))

    client.get_mgmt_names.assert_not_called()
    client.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"], include_global=False)
    assert events == [
        {
            "message": "Refreshing rulebases for mgmt1:domainB",
            "mgmt_name": "mgmt1",
            "domain_name": "domainB",
        }
    ]


@pytest.mark.asyncio
async def test_refresh_all_forwards_events_from_each_sub_refresh():
    service, client, _ = make_service()
    domain_obj = MagicMock()
    domain_obj.name = "domainA"
    client.get_domains = AsyncMock(return_value=[domain_obj])
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])

    async def make_gen(tag):
        async def _gen(*_args, **_kwargs):
            yield {"message": tag}

        return _gen

    service.refresh_access_rulebases = await make_gen("access-event")
    service.refresh_nat_rulebases = await make_gen("nat-event")
    service.refresh_https_rulebases = await make_gen("https-event")
    service.refresh_threat_rulebases = await make_gen("threat-event")

    events = await collect(service.refresh_all())

    messages = [e["message"] for e in events]
    assert messages == [
        "Refreshing rulebases for mgmt1:domainA",
        "access-event",
        "nat-event",
        "https-event",
        "threat-event",
    ]


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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

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
    _no_op_domain_generators(service)

    events = await collect(service.refresh_all(mode="force"))

    assert events == [
        {
            "message": "Refreshing rulebases for mgmt1:domainA",
            "mgmt_name": "mgmt1",
            "domain_name": "domainA",
        }
    ]


@pytest.mark.asyncio
async def test_refresh_all_skip_mode_does_not_touch_domain_list_refresh():
    service, client, _ = make_service()
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()

    await collect(service.refresh_all(mode="skip"))

    client._domain_service.populate_domain_cache.assert_not_awaited()
