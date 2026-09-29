from __future__ import annotations

import inspect

import pytest

from arodonata.api.client import ArodonataClient
from arodonata.cpcrud.service import CPCRUDService

from .fake_client import FakeArodonataClient, FakeCPCRUD, rule

FACADE_METHODS = [
    "get_domains",
    "get_gateways",
    "get_hosts",
    "get_networks",
    "get_groups",
    "get_object_by_uid",
    "get_access_rules",
    "get_nat_rules",
    "get_https_rules",
    "get_threat_rules",
    "api_call",
    "api_query",
    "search_objects",
    "refresh_objects",
    "refresh_rulebases",
]


@pytest.mark.parametrize("name", FACADE_METHODS)
def test_fake_signature_is_subset_of_real(name: str) -> None:
    """The fake must not accept a keyword the real ArodonataClient method would reject.

    A fake that accepted arbitrary ``**kw`` previously masked two real signature mismatches
    (``get_networks`` has no ``name_filter``; ``get_gateways`` has no ``domain_names``) because
    the fake happily recorded whatever keywords the tool code passed. Pinning every facade
    method to the real parameter names catches that class of bug at test time.
    """
    fake_params = set(inspect.signature(getattr(FakeArodonataClient, name)).parameters) - {"self"}
    real_params = set(inspect.signature(getattr(ArodonataClient, name)).parameters) - {"self"}
    assert fake_params <= real_params


CPCRUD_METHODS = ["validate", "plan", "apply", "inverse"]


@pytest.mark.parametrize("name", CPCRUD_METHODS)
def test_fake_cpcrud_signature_is_subset_of_real(name: str) -> None:
    """Same guarantee as ``test_fake_signature_is_subset_of_real``, but for ``client.cpcrud``."""
    fake_params = set(inspect.signature(getattr(FakeCPCRUD, name)).parameters) - {"self"}
    real_params = set(inspect.signature(getattr(CPCRUDService, name)).parameters) - {"self"}
    assert fake_params <= real_params


async def test_get_access_rules_canned_list_response_ignores_layer_name():
    client = FakeArodonataClient()
    client.responses["get_access_rules"] = [rule(1, "r1")]
    rules = await client.get_access_rules(mgmt_names=["mgmt1"], layer_name="Network")
    assert [r.name for r in rules] == ["r1"]


async def test_get_access_rules_dict_keyed_by_layer_name_unwraps():
    client = FakeArodonataClient()
    client.responses["get_access_rules"] = {
        "Network": [rule(1, "top")],
        "Inline-1": [rule(2, "nested")],
    }
    top = await client.get_access_rules(mgmt_names=["mgmt1"], layer_name="Network")
    nested = await client.get_access_rules(mgmt_names=["mgmt1"], layer_name="Inline-1")
    missing = await client.get_access_rules(mgmt_names=["mgmt1"], layer_name="Other")
    assert [r.name for r in top] == ["top"]
    assert [r.name for r in nested] == ["nested"]
    assert missing == []


async def test_get_nat_rules_dict_keyed_by_layer_name_unwraps():
    client = FakeArodonataClient()
    client.responses["get_nat_rules"] = {"NAT": ["nat-rule"]}
    assert await client.get_nat_rules(mgmt_names=["mgmt1"], layer_name="NAT") == ["nat-rule"]
    assert await client.get_nat_rules(mgmt_names=["mgmt1"], layer_name="Missing") == []


async def test_get_https_and_threat_rules_dict_keyed_by_layer_name_unwraps():
    client = FakeArodonataClient()
    client.responses["get_https_rules"] = {"HTTPS": ["https-rule"]}
    client.responses["get_threat_rules"] = {"Threat": ["threat-rule"]}
    assert await client.get_https_rules(mgmt_names=["mgmt1"], layer_name="HTTPS") == ["https-rule"]
    assert await client.get_threat_rules(mgmt_names=["mgmt1"], layer_name="Threat") == ["threat-rule"]


async def test_get_access_rules_records_calls():
    client = FakeArodonataClient()
    await client.get_access_rules(mgmt_names=["mgmt1"], layer_name="Network")
    assert client.calls == [
        (
            "get_access_rules",
            {
                "layer_name": "Network",
                "mgmt_names": ["mgmt1"],
                "domain_names": None,
                "enabled_only": None,
                "cache_mode": None,
                "cache_ttl": None,
            },
        )
    ]
