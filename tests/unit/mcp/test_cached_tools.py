from __future__ import annotations

import pytest

from arodonata.core.cache_mode import CacheMode
from arodonata.models import Domain, Gateway, Network

from .fake_client import FakeArodonataClient, host
from .helpers import cache_mode_enum, call_tool, make_server, payload, text, tool_input_schema


def _fake_with_hosts(n: int = 3, names=("mgmt1",)) -> FakeArodonataClient:
    fake = FakeArodonataClient(list(names))
    fake.responses["get_hosts"] = [host(f"h{i}", f"10.0.0.{i}") for i in range(n)]
    return fake


def _network(name: str, subnet: str, mgmt: str = "mgmt1") -> Network:
    raw = {"uid": f"uid-{name}", "name": name, "type": "network", "subnet4": subnet}
    return Network(uid=raw["uid"], name=name, subnet4=subnet, mgmt_name=mgmt, raw_data=raw)


def _gateway(name: str, ip: str, mgmt: str = "mgmt1") -> Gateway:
    raw = {"uid": f"uid-{name}", "name": name, "type": "simple-gateway", "ipv4-address": ip}
    return Gateway(uid=raw["uid"], name=name, type="simple-gateway", ip_address=ip, mgmt_name=mgmt, raw_data=raw)


async def test_show_hosts_maps_filter_and_domain_and_returns_envelope():
    fake = _fake_with_hosts()
    res = await call_tool(make_server(fake), "show_hosts", {"filter": "h*", "domain": "General", "limit": 2})
    assert res.is_error is False
    out = payload(res)
    assert [o["name"] for o in out["objects"]] == ["h0", "h1"]
    assert out["total"] == 3 and out["from"] == 1 and out["to"] == 2
    assert out["source"] == "cache" and out["cache_age_seconds"] == 90
    assert fake.calls == [
        (
            "get_hosts",
            {
                "name_filter": "h*",
                "mgmt_names": ["mgmt1"],
                "domain_names": ["General"],
                "cache_mode": None,
                "cache_ttl": None,
            },
        )
    ]


async def test_show_networks_maps_filter_to_subnet_and_domain():
    fake = FakeArodonataClient()
    fake.responses["get_networks"] = [_network("net1", "10.0.0.0/24")]
    res = await call_tool(make_server(fake), "show_networks", {"filter": "10.0.0.0/24", "domain": "General"})
    assert res.is_error is False
    out = payload(res)
    assert out["objects"][0]["name"] == "net1"
    assert fake.calls == [
        (
            "get_networks",
            {
                "subnet": "10.0.0.0/24",
                "mgmt_names": ["mgmt1"],
                "domain_names": ["General"],
                "cache_mode": None,
                "cache_ttl": None,
            },
        )
    ]


async def test_show_gateways_and_servers_has_no_domain_and_no_cache_age():
    fake = FakeArodonataClient()
    fake.responses["get_gateways"] = [_gateway("gw1", "10.0.0.1")]
    res = await call_tool(make_server(fake), "show_gateways_and_servers", {})
    assert res.is_error is False
    out = payload(res)
    assert out["objects"][0]["name"] == "gw1"
    assert out["source"] == "cache" and out["cache_age_seconds"] is None
    assert fake.calls == [("get_gateways", {"mgmt_names": ["mgmt1"], "cache_mode": None, "cache_ttl": None})]


async def test_show_hosts_standard_projection_hides_meta_info():
    out = payload(await call_tool(make_server(_fake_with_hosts(1)), "show_hosts", {}))
    obj = out["objects"][0]
    assert obj["ipv4-address"] == "10.0.0.0" and "meta-info" not in obj


async def test_show_hosts_uid_level():
    out = payload(await call_tool(make_server(_fake_with_hosts(1)), "show_hosts", {"details_level": "uid"}))
    assert set(out["objects"][0]) == {"uid", "name", "type"}


_CACHED_TOOLS = {
    # tool -> fake getter it delegates to
    "show_hosts": "get_hosts",
    "show_networks": "get_networks",
    "show_groups": "get_groups",
    "show_domains": "get_domains",
    "show_gateways_and_servers": "get_gateways",
}


@pytest.mark.parametrize(("tool", "getter"), _CACHED_TOOLS.items())
async def test_cached_tool_default_cache_mode_is_none(tool, getter):
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, {})
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == getter and fake.calls[0][1]["cache_mode"] is None


@pytest.mark.parametrize(("tool", "getter"), _CACHED_TOOLS.items())
async def test_cached_tool_forwards_force_cache_mode(tool, getter):
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake), tool, {"cache_mode": "force"})
    assert res.is_error is False, text(res)
    assert fake.calls[0][0] == getter and fake.calls[0][1]["cache_mode"] == "force"


@pytest.mark.parametrize("tool", _CACHED_TOOLS)
async def test_cached_tool_schema_publishes_read_cache_vocabulary(tool):
    schema = await tool_input_schema(make_server(FakeArodonataClient()), tool)
    assert cache_mode_enum(schema) == [m.value for m in CacheMode]
    assert schema["properties"]["cache_mode"].get("default") is None


@pytest.mark.parametrize("tool", _CACHED_TOOLS)
async def test_cached_tool_rejects_session_cache_vocabulary(tool):
    res = await call_tool(make_server(FakeArodonataClient()), tool, {"cache_mode": "auto"})
    assert res.is_error is True


async def test_show_hosts_requires_mgmt_name_when_ambiguous():
    fake = _fake_with_hosts(1, names=("mgmt1", "mgmt2"))
    res = await call_tool(make_server(fake), "show_hosts", {})
    assert res.is_error is True and "mgmt1, mgmt2" in text(res)


async def test_show_domains_include_global_and_no_domain_param():
    fake = FakeArodonataClient()
    fake.responses["get_domains"] = [
        Domain(
            uid="d",
            name="General",
            active_mds="m",
            active_ip="1.1.1.1",
            active_server="m",
            mgmt_name="mgmt1",
            raw_data={"uid": "d", "name": "General", "type": "domain"},
        )
    ]
    out = payload(await call_tool(make_server(fake), "show_domains", {"include_global": True}))
    assert out["objects"][0]["name"] == "General"
    # The domains table has no timestamp column; the object cache's age would be misleading here.
    assert out["cache_age_seconds"] is None
    assert fake.calls[0] == (
        "get_domains",
        {"mgmt_names": ["mgmt1"], "cache_mode": None, "cache_ttl": None, "include_global": True},
    )


async def test_show_domains_records_without_raw_data_are_not_empty():
    """The domains cache table stores no API payload, so real Domain models carry an empty raw_data."""
    fake = FakeArodonataClient()
    fake.responses["get_domains"] = [
        Domain(
            uid="d4",
            name="Domain4",
            active_mds="mdsH5b",
            active_ip="192.0.2.5",
            active_server="mdsH5b",
            mgmt_name="mgmt1",
            is_mdm=True,
        )
    ]
    standard = payload(await call_tool(make_server(fake), "show_domains", {}))["objects"][0]
    assert standard == {"uid": "d4", "name": "Domain4", "type": "domain"}
    full = payload(await call_tool(make_server(fake), "show_domains", {"details_level": "full"}))["objects"][0]
    assert full["active_mds"] == "mdsH5b" and full["active_ip"] == "192.0.2.5" and full["is_mdm"] is True


async def test_show_object_found_and_not_found():
    fake = FakeArodonataClient()
    fake.responses["get_object_by_uid"] = host("h1", "10.0.0.1")
    out = payload(await call_tool(make_server(fake), "show_object", {"uid": "uid-h1", "details_level": "full"}))
    assert out["object"]["name"] == "h1" and out["source"] == "cache"
    assert fake.calls[0] == ("get_object_by_uid", {"uid": "uid-h1", "mgmt_name": "mgmt1", "domain_name": ""})
    fake.responses["get_object_by_uid"] = None
    res = await call_tool(make_server(fake), "show_object", {"uid": "missing"})
    assert res.is_error is True and "not found in cache" in text(res)


async def test_all_cached_tools_registered():
    from .helpers import tool_names

    names = await tool_names(make_server(FakeArodonataClient()))
    assert {
        "show_hosts",
        "show_networks",
        "show_groups",
        "show_domains",
        "show_gateways_and_servers",
        "show_object",
    } <= names
