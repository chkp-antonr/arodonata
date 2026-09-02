"""Unit tests for RulebaseRefreshService.

Covers layer discovery, access/NAT/HTTPS/threat rulebase collection and
persistence (including nested-section recursion), referenced-object saving,
per-domain scoping via refresh_all, and error paths. The ArodonataClient and
CacheRepository seams are mocked; no network or database is touched.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.api.services.rulebase_refresh_service import RulebaseRefreshService
from arodonata.cache.models import RulebaseAccess, RulebaseNAT
from arodonata.extractors.base import ExtractionContext
from arodonata.extractors.rulebases import AccessRuleExtractor, NATRuleExtractor


def make_service():
    client = MagicMock()
    client._object_service = MagicMock()
    client._object_service._api_object_to_cpobject = MagicMock(return_value=None)
    cache = AsyncMock()
    cache.delete_rulebase = AsyncMock(return_value=0)
    cache.upsert_rulebases = AsyncMock(side_effect=lambda rules, **_: len(rules))
    cache.upsert_objects = AsyncMock(return_value=0)
    service = RulebaseRefreshService(client=client, cache=cache)
    return service, client, cache


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
        "layer": {"name": "Network"},
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


def test_extract_rules_recursive_builds_nat_rule_id_with_nat_layer():
    service, _, _ = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="dom1")
    nat_rule = {
        "type": "nat-rule",
        "uid": "n1",
        "rule-number": 1,
        "name": "NAT 1",
        "enabled": True,
        "original-source": "any",
        "original-destination": "any",
        "original-service": "any",
        "translated-source": "original",
        "translated-destination": "original",
        "translated-service": "original",
        "layer": "NAT",
    }
    extracted = service._extract_rules_recursive(
        [nat_rule], NATRuleExtractor(), context, RulebaseNAT, "mgmt1", "dom1", "NAT"
    )
    assert len(extracted) == 1
    assert extracted[0].id == "mgmt1:dom1:NAT:n1"


# --------------------------------------------------------------------------- #
# _fetch_layer_rulebase
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_fetch_layer_rulebase_success():
    service, client, _ = make_service()
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"rulebase": []}))

    success, data = await service._fetch_layer_rulebase("mgmt1", "", "Network", "show-access-rulebase", {})

    assert success is True
    assert data == {"rulebase": []}


@pytest.mark.asyncio
async def test_fetch_layer_rulebase_returns_false_on_unsuccessful_response():
    service, client, _ = make_service()
    client.api_call = AsyncMock(return_value=ApiCallResult(success=False))

    success, data = await service._fetch_layer_rulebase("mgmt1", "", "Network", "show-access-rulebase", {})

    assert (success, data) == (False, None)


@pytest.mark.asyncio
async def test_fetch_layer_rulebase_returns_false_when_data_missing():
    service, client, _ = make_service()
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data=None))

    success, data = await service._fetch_layer_rulebase("mgmt1", "", "Network", "show-access-rulebase", {})

    assert (success, data) == (False, None)


@pytest.mark.asyncio
async def test_fetch_layer_rulebase_catches_exception():
    service, client, _ = make_service()
    client.api_call = AsyncMock(side_effect=RuntimeError("boom"))

    success, data = await service._fetch_layer_rulebase("mgmt1", "", "Network", "show-access-rulebase", {})

    assert (success, data) == (False, None)


# --------------------------------------------------------------------------- #
# _save_referenced_objects
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_save_referenced_objects_noop_on_empty_list():
    service, client, cache = make_service()

    await service._save_referenced_objects([], "mgmt1", "", "Network")

    cache.upsert_objects.assert_not_awaited()


@pytest.mark.asyncio
async def test_save_referenced_objects_converts_and_upserts():
    service, client, cache = make_service()
    cp_obj_sentinel = object()
    client._object_service._api_object_to_cpobject = MagicMock(side_effect=[cp_obj_sentinel, None])

    await service._save_referenced_objects(
        [{"uid": "o1", "name": "obj1"}, {"uid": "o2", "name": "obj2"}], "mgmt1", "", "Network"
    )

    cache.upsert_objects.assert_awaited_once_with([cp_obj_sentinel])


# --------------------------------------------------------------------------- #
# _process_layer_rules
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_process_layer_rules_returns_zero_when_no_rules_found():
    service, client, cache = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    data = {"objects": [], "rulebase": []}

    processed = await service._process_layer_rules(
        "mgmt1", "", "Network", data, service._access_extractor, RulebaseAccess, context
    )

    assert processed == 0
    cache.delete_rulebase.assert_not_awaited()
    cache.upsert_rulebases.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_layer_rules_saves_rules_and_clears_old_ones():
    service, client, cache = make_service()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="")
    data = {
        "objects": [{"uid": "o1", "name": "obj1"}],
        "rulebase": [access_rule(uid="r1")],
    }

    processed = await service._process_layer_rules(
        "mgmt1", "", "Network", data, service._access_extractor, RulebaseAccess, context
    )

    assert processed == 1
    cache.delete_rulebase.assert_awaited_once_with(RulebaseAccess, "mgmt1", "", "Network")
    cache.upsert_rulebases.assert_awaited_once()
    assert context.objects_map == {"o1": "obj1"}


# --------------------------------------------------------------------------- #
# refresh_access_rulebases
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_access_rulebases_full_success_flow():
    service, client, cache = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "Network"}]))
    client.api_call = AsyncMock(
        return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": [access_rule(uid="r1")]})
    )

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert any("Fetching access rules for layer: Network" in m for m in messages)
    assert any("Saved 1 access rules for Network" in m for m in messages)
    cache.upsert_rulebases.assert_awaited_once()


@pytest.mark.asyncio
async def test_refresh_access_rulebases_layers_query_failure_yields_nothing():
    service, client, _ = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=False, message="no access"))

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    assert events == []


@pytest.mark.asyncio
async def test_refresh_access_rulebases_skips_invalid_layer():
    service, client, cache = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"uid": "no-name"}]))
    client.api_call = AsyncMock()

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    assert events == []
    client.api_call.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_access_rulebases_no_rules_in_layer_yields_only_fetching_message():
    service, client, cache = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "Empty"}]))
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": []}))

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching access rules for layer: Empty"]


@pytest.mark.asyncio
async def test_refresh_access_rulebases_fetch_failure_is_skipped():
    service, client, cache = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "Network"}]))
    client.api_call = AsyncMock(return_value=ApiCallResult(success=False))

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching access rules for layer: Network"]
    cache.upsert_rulebases.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_access_rulebases_process_layer_type_error_is_caught_and_continues():
    service, client, cache = make_service()
    client.api_query = AsyncMock(
        return_value=ApiQueryResult(success=True, objects=[{"name": "Network"}, {"name": "Second"}])
    )
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": []}))
    service._process_layer_rules = AsyncMock(side_effect=TypeError("bad data"))

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == [
        "Fetching access rules for layer: Network",
        "Fetching access rules for layer: Second",
    ]


@pytest.mark.asyncio
async def test_refresh_access_rulebases_generic_exception_yields_error_event():
    service, client, _ = make_service()
    client.api_query = AsyncMock(side_effect=RuntimeError("kaboom"))

    events = await collect(service.refresh_access_rulebases("mgmt1", ""))

    assert len(events) == 1
    assert events[0]["status"] == "error"
    assert "kaboom" in events[0]["message"]


# --------------------------------------------------------------------------- #
# refresh_nat_rulebases
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_nat_rulebases_success_with_standard_package():
    service, client, cache = make_service()
    nat_rule = {
        "type": "nat-rule",
        "uid": "n1",
        "rule-number": 1,
        "name": "NAT rule",
        "enabled": True,
        "layer": "NAT",
    }
    client.api_call = AsyncMock(
        return_value=ApiCallResult(
            success=True, data={"objects": [{"uid": "o1", "name": "obj1"}], "rulebase": [nat_rule]}
        )
    )

    events = await collect(service.refresh_nat_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert "Fetching NAT rulebase" in messages
    assert any("Saved 1 NAT rules" in m for m in messages)
    cache.upsert_rulebases.assert_awaited_once()
    cache.delete_rulebase.assert_awaited_once_with(RulebaseNAT, "mgmt1", "", "NAT")
    client.api_call.assert_awaited_once()


@pytest.mark.asyncio
async def test_refresh_nat_rulebases_falls_back_without_package_on_first_failure():
    service, client, cache = make_service()
    nat_rule = {"type": "nat-rule", "uid": "n1", "rule-number": 1, "name": "NAT rule", "enabled": True}
    responses = [
        ApiCallResult(success=False),
        ApiCallResult(success=True, data={"objects": [], "rulebase": [nat_rule]}),
    ]
    client.api_call = AsyncMock(side_effect=responses)

    events = await collect(service.refresh_nat_rulebases("mgmt1", ""))

    assert client.api_call.await_count == 2
    second_call_kwargs = client.api_call.await_args_list[1].kwargs
    assert "package" not in second_call_kwargs["payload"]
    messages = [e["message"] for e in events]
    assert any("Saved 1 NAT rules" in m for m in messages)


@pytest.mark.asyncio
async def test_refresh_nat_rulebases_both_calls_fail_yields_only_fetching_message():
    service, client, _ = make_service()
    client.api_call = AsyncMock(return_value=ApiCallResult(success=False))

    events = await collect(service.refresh_nat_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching NAT rulebase"]


@pytest.mark.asyncio
async def test_refresh_nat_rulebases_no_rules_found_yields_only_fetching_message():
    service, client, cache = make_service()
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": []}))

    events = await collect(service.refresh_nat_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching NAT rulebase"]
    cache.upsert_rulebases.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_nat_rulebases_generic_exception_yields_error_event():
    service, client, _ = make_service()
    client.api_call = AsyncMock(side_effect=RuntimeError("nat-boom"))

    events = await collect(service.refresh_nat_rulebases("mgmt1", ""))

    assert events[-1]["status"] == "error"
    assert "nat-boom" in events[-1]["message"]


# --------------------------------------------------------------------------- #
# refresh_https_rulebases
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_https_rulebases_success_flow():
    service, client, cache = make_service()
    https_rule = {
        "type": "https-rule",
        "uid": "h1",
        "rule-number": 1,
        "name": "Inspect",
        "enabled": True,
        "source": [],
        "destination": [],
        "track": {"type": "Inspect"},
        "layer": {"name": "CVD"},
    }
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "CVD"}]))
    client.api_call = AsyncMock(
        return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": [https_rule]})
    )

    events = await collect(service.refresh_https_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert any("Saved 1 HTTPS rules for CVD" in m for m in messages)


@pytest.mark.asyncio
async def test_refresh_https_rulebases_layers_failure_yields_nothing():
    service, client, _ = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))

    events = await collect(service.refresh_https_rulebases("mgmt1", ""))

    assert events == []


@pytest.mark.asyncio
async def test_refresh_https_rulebases_type_error_is_caught_and_continues():
    service, client, _ = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "CVD"}]))
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": []}))
    service._process_layer_rules = AsyncMock(side_effect=AttributeError("bad"))

    events = await collect(service.refresh_https_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching HTTPS rules for layer: CVD"]


@pytest.mark.asyncio
async def test_refresh_https_rulebases_generic_exception_yields_error_event():
    service, client, _ = make_service()
    client.api_query = AsyncMock(side_effect=RuntimeError("https-boom"))

    events = await collect(service.refresh_https_rulebases("mgmt1", ""))

    assert events[-1]["status"] == "error"
    assert "https-boom" in events[-1]["message"]


# --------------------------------------------------------------------------- #
# refresh_threat_rulebases
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_threat_rulebases_success_flow():
    service, client, cache = make_service()
    threat_rule = {
        "type": "threat-rule",
        "uid": "t1",
        "rule-number": 1,
        "name": "Block",
        "enabled": True,
        "track": {"type": "Alert"},
        "protections": [{"name": "SQLi"}],
        "layer": {"name": "Threat"},
    }
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "Threat"}]))
    client.api_call = AsyncMock(
        return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": [threat_rule]})
    )

    events = await collect(service.refresh_threat_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert any("Saved 1 Threat rules for Threat" in m for m in messages)


@pytest.mark.asyncio
async def test_refresh_threat_rulebases_layers_failure_yields_nothing():
    service, client, _ = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))

    events = await collect(service.refresh_threat_rulebases("mgmt1", ""))

    assert events == []


@pytest.mark.asyncio
async def test_refresh_threat_rulebases_type_error_is_caught_and_continues():
    service, client, _ = make_service()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[{"name": "Threat"}]))
    client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data={"objects": [], "rulebase": []}))
    service._process_layer_rules = AsyncMock(side_effect=TypeError("bad"))

    events = await collect(service.refresh_threat_rulebases("mgmt1", ""))

    messages = [e["message"] for e in events]
    assert messages == ["Fetching Threat rules for layer: Threat"]


@pytest.mark.asyncio
async def test_refresh_threat_rulebases_generic_exception_yields_error_event():
    service, client, _ = make_service()
    client.api_query = AsyncMock(side_effect=RuntimeError("threat-boom"))

    events = await collect(service.refresh_threat_rulebases("mgmt1", ""))

    assert events[-1]["status"] == "error"
    assert "threat-boom" in events[-1]["message"]


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
