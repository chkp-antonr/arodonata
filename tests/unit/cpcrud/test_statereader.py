# tests/unit/cpcrud/test_statereader.py
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import ApiCallResult
from arodonata.cpcrud.services import ServiceSpec
from arodonata.cpcrud.statereader import HybridStateReader, LiveStateReader


class FakeClient:
    def __init__(self, responses):
        # command -> ApiCallResult, or a list[ApiCallResult] consumed in sequence across
        # successive calls to the SAME command (for testing pagination: page 1, page 2, ...).
        # Once exhausted, the last entry repeats.
        self._responses = responses
        self._page_index = {}
        self.calls = []
        self.query_calls = []

    def _next_response(self, command):
        entry = self._responses.get(command, ApiCallResult(success=False, message="not found", code="generic_err"))
        if isinstance(entry, list):
            idx = self._page_index.get(command, 0)
            self._page_index[command] = idx + 1
            return entry[min(idx, len(entry) - 1)]
        return entry

    async def api_call(self, mgmt_name, command, domain="", details_level=None, payload=None, **kw):
        self.calls.append((command, payload))
        return self._next_response(command)

    async def api_query(
        self, mgmt_name, command, domain="", details_level="standard", payload=None, container_key="objects", **kw
    ):
        self.query_calls.append((command, payload, container_key))
        return self._next_response(command)


@pytest.mark.asyncio
async def test_get_by_name_exact_hit():
    client = FakeClient(
        {
            "show-host": ApiCallResult(
                success=True, data={"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1"}, message="OK"
            )
        }
    )
    reader = LiveStateReader(client)
    state = await reader.get_by_name("host", "h1", mgmt="m", domain="d")
    assert state is not None and state.uid == "u1"
    assert client.calls[0][0] == "show-host"
    assert client.calls[0][1] == {"name": "h1", "details-level": "full"}


@pytest.mark.asyncio
async def test_get_by_name_miss_returns_none():
    client = FakeClient({})
    reader = LiveStateReader(client)
    assert await reader.get_by_name("host", "missing", mgmt="m", domain="d") is None


@pytest.mark.asyncio
async def test_get_by_name_uid_shaped_key_resolves_by_uid_not_name():
    """resolve_update/resolve_delete/resolve_show collapse a template's key: {name|uid} into a
    single string before calling get_by_name -- the ops schema explicitly permits {"uid": ...}
    alone (host_key/network_key, minProperties: 1). A uid-only key must route through "uid", not
    "name", or a legitimate uid-addressed object would always report "not found" -- for delete,
    that means silently NOT deleting an object that actually exists."""
    obj_uid = "b9c8206c-1234-4abc-9def-0090272ccb30"
    client = FakeClient(
        {
            "show-host": ApiCallResult(
                success=True, data={"uid": obj_uid, "name": "h1", "ipv4-address": "10.0.0.1"}, message="OK"
            )
        }
    )
    reader = LiveStateReader(client)
    state = await reader.get_by_name("host", obj_uid, mgmt="m", domain="d")
    assert state is not None and state.uid == obj_uid
    assert state.name == "h1"  # real name from the API response, not the raw uid string
    assert client.calls[0][1] == {"uid": obj_uid, "details-level": "full"}


@pytest.mark.asyncio
async def test_hybrid_get_by_name_uid_shaped_key_falls_through_to_fixed_live_path():
    """A uid-shaped key can never match the cache's exact-name filter (`r.name == name`), so it
    must fall through to the live path -- which now correctly resolves it by uid (not name)."""
    obj_uid = "b9c8206c-1234-4abc-9def-0090272ccb30"
    client = AsyncMock()
    client.cache.get_objects_by_name.return_value = []
    client.api_call.return_value = SimpleNamespace(
        success=True, data={"uid": obj_uid, "name": "h1"}, message="", code=""
    )
    reader = HybridStateReader(client)
    state = await reader.get_by_name("host", obj_uid, mgmt="m", domain="d")
    assert state is not None and state.uid == obj_uid
    client.api_call.assert_awaited_once_with(
        "m",
        "show-host",
        "d",
        payload={"uid": obj_uid, "details-level": "full"},
    )


@pytest.mark.asyncio
async def test_find_by_ip_post_filters_exact():
    # show-objects returns a partial match (different IP) plus an exact match
    client = FakeClient(
        {
            "show-objects": ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {"uid": "u-exact", "name": "exact", "type": "host", "ipv4-address": "10.0.0.5"},
                        {"uid": "u-partial", "name": "partial", "type": "host", "ipv4-address": "10.0.0.50"},
                    ]
                },
                message="OK",
            )
        }
    )
    reader = LiveStateReader(client)
    found = await reader.find_by_ip(type="host", ip_value={"ip-address": "10.0.0.5"}, mgmt="m", domain="d")
    assert [o.name for o in found] == ["exact"]


@pytest.mark.asyncio
async def test_where_used_total():
    client = FakeClient(
        {"where-used": ApiCallResult(success=True, data={"total": 7, "used-directly": []}, message="OK")}
    )
    reader = LiveStateReader(client)
    assert await reader.where_used("u1", mgmt="m", domain="d") == 7


@pytest.mark.asyncio
async def test_live_reader_last_publish_session_uses_client_refresh():
    class FakeLPS:
        uid = "sess-uid-42"

    client = AsyncMock()
    client.refresh_last_published_session.return_value = FakeLPS()
    reader = LiveStateReader(client)
    assert await reader.get_last_publish_session(mgmt="m", domain="d") == "sess-uid-42"
    client.refresh_last_published_session.assert_awaited_once_with("m", "d")


@pytest.mark.asyncio
async def test_live_reader_last_publish_session_empty_on_none():
    client = AsyncMock()
    client.refresh_last_published_session.return_value = None
    reader = LiveStateReader(client)
    assert await reader.get_last_publish_session(mgmt="m", domain="d") == ""


def _cpobject(**kw):
    """Minimal stand-in for cache CPObject rows."""
    from types import SimpleNamespace

    defaults = dict(
        uid="u1",
        name="h1",
        type="host",
        ipv4_address="",
        subnet4="",
        subnet_mask="",
        ipv4_address_first="",
        ipv4_address_last="",
        raw_data={"uid": "u1", "name": "h1"},
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


@pytest.mark.asyncio
async def test_hybrid_get_by_name_hits_cache_first():
    client = AsyncMock()
    client.cache.get_objects_by_name.return_value = [_cpobject()]
    reader = HybridStateReader(client)
    state = await reader.get_by_name("host", "h1", mgmt="m", domain="d")
    assert state is not None and state.uid == "u1"
    client.api_call.assert_not_awaited()  # no live fallback needed
    client.cache.get_objects_by_name.assert_awaited_once_with("h1", mgmt_names=["m"], domain_names=["d"])


@pytest.mark.asyncio
async def test_hybrid_get_by_name_falls_back_to_live_on_miss():
    client = AsyncMock()
    client.cache.get_objects_by_name.return_value = []
    client.api_call.return_value = SimpleNamespace(success=True, data={"uid": "u9", "name": "h9"}, message="", code="")
    reader = HybridStateReader(client)
    state = await reader.get_by_name("host", "h9", mgmt="m", domain="d")
    assert state is not None and state.uid == "u9"
    client.api_call.assert_awaited()  # live fallback used


@pytest.mark.asyncio
async def test_hybrid_maps_network_group_to_cache_type_group():
    client = AsyncMock()
    client.cache.get_objects_by_name.return_value = [_cpobject(type="group", name="g1", uid="ug")]
    reader = HybridStateReader(client)
    state = await reader.get_by_name("network-group", "g1", mgmt="m", domain="d")
    assert state is not None and state.type == "network-group"


@pytest.mark.asyncio
async def test_hybrid_find_by_ip_uses_cache_ip_index():
    client = AsyncMock()
    client.cache.get_objects_by_ip.return_value = [_cpobject(ipv4_address="10.0.0.5")]
    reader = HybridStateReader(client)
    matches = await reader.find_by_ip(type="host", ip_value={"ip-address": "10.0.0.5"}, mgmt="m", domain="d")
    assert [m.uid for m in matches] == ["u1"]


@pytest.mark.asyncio
async def test_hybrid_find_by_ip_network_mask_mismatch_falls_back_to_live():
    # cache row shares the subnet4 base address but is a /16, not the requested /24 --
    # get_objects_by_subnet only filters on subnet4, so without the mask check this would
    # incorrectly be treated as a cache hit.
    client = AsyncMock()
    client.cache.get_objects_by_subnet.return_value = [
        _cpobject(type="network", name="net-16", subnet4="10.0.0.0", subnet_mask="255.255.0.0"),
    ]
    client.api_query.return_value = SimpleNamespace(
        success=True,
        data={
            "objects": [
                {"uid": "live-u", "name": "net-24", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 24}
            ]
        },
        objects=[{"uid": "live-u", "name": "net-24", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 24}],
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    matches = await reader.find_by_ip(
        type="network",
        ip_value={"subnet": "10.0.0.0", "mask-length": 24},
        mgmt="m",
        domain="d",
    )
    client.api_query.assert_awaited()  # cache row rejected -> fell through to live (show-objects paginates)
    assert [m.uid for m in matches] == ["live-u"]


@pytest.mark.asyncio
async def test_hybrid_find_by_ip_network_mask_match_uses_cache():
    client = AsyncMock()
    client.cache.get_objects_by_subnet.return_value = [
        _cpobject(uid="u-net24", type="network", name="net-24", subnet4="10.0.0.0", subnet_mask="255.255.255.0"),
    ]
    reader = HybridStateReader(client)
    matches = await reader.find_by_ip(
        type="network",
        ip_value={"subnet": "10.0.0.0", "mask-length": 24},
        mgmt="m",
        domain="d",
    )
    client.api_call.assert_not_awaited()  # exact mask match -> no live fallback needed
    assert [m.uid for m in matches] == ["u-net24"]


@pytest.mark.asyncio
async def test_hybrid_find_by_ip_network_missing_mask_falls_back_to_live():
    # no mask-length supplied at all -- can't verify against the cache row, so don't guess;
    # fall through to live rather than blindly returning the (possibly wrong) cache hit.
    client = AsyncMock()
    client.cache.get_objects_by_subnet.return_value = [
        _cpobject(uid="u-cache", type="network", name="net-24", subnet4="10.0.0.0", subnet_mask="255.255.255.0"),
    ]
    client.api_query.return_value = SimpleNamespace(
        success=True,
        data={"objects": []},
        objects=[],
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    matches = await reader.find_by_ip(type="network", ip_value={"subnet": "10.0.0.0"}, mgmt="m", domain="d")
    client.api_query.assert_awaited()  # cache row not trusted without a mask-length to verify
    assert matches == []


@pytest.mark.asyncio
async def test_hybrid_where_used_is_always_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True, data={"used-directly": {"total": 7}, "total": 7}, message="", code=""
    )
    reader = HybridStateReader(client)
    assert await reader.where_used("u1", mgmt="m", domain="d") == 7


@pytest.mark.asyncio
async def test_live_reader_get_by_name_tcp_service_uses_show_service_tcp():
    client = FakeClient(
        {
            "show-service-tcp": ApiCallResult(
                success=True, data={"uid": "u1", "name": "TCP_8080", "port": "8080"}, message="", code=""
            )
        }
    )
    reader = LiveStateReader(client)
    state = await reader.get_by_name("tcp-service", "TCP_8080", mgmt="m", domain="d")
    assert state is not None and state.uid == "u1"
    assert client.calls[0][0] == "show-service-tcp"


@pytest.mark.asyncio
async def test_live_reader_get_by_name_service_group_uses_show_service_group():
    client = FakeClient(
        {
            "show-service-group": ApiCallResult(
                success=True, data={"uid": "u1", "name": "Web-Services"}, message="", code=""
            )
        }
    )
    reader = LiveStateReader(client)
    state = await reader.get_by_name("service-group", "Web-Services", mgmt="m", domain="d")
    assert state is not None and state.uid == "u1"
    assert client.calls[0][0] == "show-service-group"


async def test_hybrid_get_by_name_service_always_live_never_cached():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True, data={"uid": "u9", "name": "TCP_8080"}, message="", code=""
    )
    reader = HybridStateReader(client)
    state = await reader.get_by_name("tcp-service", "TCP_8080", mgmt="m", domain="d")
    assert state is not None and state.uid == "u9"
    client.cache.get_objects_by_name.assert_not_awaited()  # never even queried — services aren't cached


@pytest.mark.asyncio
async def test_get_service_exact_name_hit_on_first_probe():
    client = FakeClient(
        {
            "show-service-tcp": ApiCallResult(
                success=True, data={"uid": "u1", "name": "my_custom_svc", "port": "22"}, message="", code=""
            ),
        }
    )
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="named", name="my_custom_svc")
    state = await reader.get_service(spec, "my_custom_svc", mgmt="m", domain="d")
    assert state is not None and state.uid == "u1" and state.type == "tcp-service"
    assert client.calls[0] == ("show-service-tcp", {"name": "my_custom_svc", "details-level": "full"})


@pytest.mark.asyncio
async def test_get_service_probes_in_order_tcp_udp_other_icmp():
    client = FakeClient(
        {
            "show-service-icmp": ApiCallResult(
                success=True, data={"uid": "u4", "name": "my_icmp_svc"}, message="", code=""
            ),
        }
    )
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="named", name="my_icmp_svc")
    state = await reader.get_service(spec, "my_icmp_svc", mgmt="m", domain="d")
    assert state is not None and state.uid == "u4" and state.type == "icmp-service"
    assert [c[0] for c in client.calls] == [
        "show-service-tcp",
        "show-service-udp",
        "show-service-other",
        "show-service-icmp",
    ]


@pytest.mark.asyncio
async def test_get_service_named_not_found_returns_none():
    client = FakeClient({})  # every probe fails
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="named", name="totally_unknown")
    state = await reader.get_service(spec, "totally_unknown", mgmt="m", domain="d")
    assert state is None
    assert len(client.calls) == 4  # all four probes attempted


@pytest.mark.asyncio
async def test_get_service_tcp_spec_falls_back_to_port_lookup_when_name_probe_misses():
    client = FakeClient(
        {
            "show-services-tcp": ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {"uid": "u5", "name": "TCP_22", "port": "22"},
                        {"uid": "u6", "name": "TCP_80", "port": "80"},
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="tcp", port="22")
    state = await reader.get_service(spec, "22", mgmt="m", domain="d")
    assert state is not None and state.uid == "u5" and state.name == "TCP_22"
    # show-services-tcp is a listing endpoint (default page limit 50) -- must go through
    # api_query, not a single non-paginating api_call (Task 14's original bug: 219 existing
    # services on the live lab meant a freshly created one wasn't on page 1).
    assert client.query_calls and client.query_calls[-1][0] == "show-services-tcp"


@pytest.mark.asyncio
async def test_get_service_tcp_spec_no_port_match_returns_none():
    client = FakeClient(
        {
            "show-services-tcp": ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {"uid": "u6", "name": "TCP_80", "port": "80"},
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="tcp", port="22")
    state = await reader.get_service(spec, "22", mgmt="m", domain="d")
    assert state is None


@pytest.mark.asyncio
async def test_get_service_icmp_spec_is_name_probe_only_no_port_fallback():
    """ICMP has no PAGINATED port-list fallback (no show-services-icmp command exists) -- but it
    does get a canonical-name probe (Task 14 fix: `original_text` like "icmp/8" is never a real
    object's name for a bare spec, only `auto_service_name`'s "ICMP_8" ever is)."""
    client = FakeClient({})
    reader = LiveStateReader(client)
    spec = ServiceSpec(kind="icmp", icmp_type=8)
    state = await reader.get_service(spec, "icmp/8", mgmt="m", domain="d")
    assert state is None
    assert len(client.calls) == 5  # 4 name-probe commands + 1 canonical-name probe, no port-list fallback


async def test_hybrid_get_service_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True, data={"uid": "u1", "name": "TCP_22"}, message="", code=""
    )
    reader = HybridStateReader(client)
    spec = ServiceSpec(kind="tcp", port="22")
    state = await reader.get_service(spec, "22", mgmt="m", domain="d")
    assert state is not None
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_layer_access_type():
    client = FakeClient(
        {
            "show-access-layer": ApiCallResult(
                success=True, data={"uid": "u1", "name": "Network", "type": "access-layer"}, message="", code=""
            ),
        }
    )
    reader = LiveStateReader(client)
    layer = await reader.get_layer("Network", "access", mgmt="m", domain="d")
    assert layer is not None and layer.uid == "u1" and layer.name == "Network" and layer.type == "access"
    assert client.calls[0] == ("show-access-layer", {"name": "Network", "details-level": "full"})


@pytest.mark.asyncio
async def test_get_layer_uid_shaped_ref_resolves_by_uid_not_name():
    """A layer name can collide across domains in an MDS environment (a domain-local layer and
    a Global-assigned layer sharing the same name -- a real, Check-Point-recognized issue:
    SK180759/SK183697 document "More than one object named X exists" during Global assignment).
    A template author who already knows the exact layer's uid must be able to put it directly in
    the `layer` field to disambiguate (confirmed valid per Check Point's own add-access-rule.j.md:
    "Layer that the rule belongs to identified by the name or UID") -- this must resolve via
    `uid`, not `name`, or the disambiguation escape hatch wouldn't actually work."""
    layer_uid = "b9c8206c-1234-4abc-9def-0090272ccb30"
    client = FakeClient(
        {
            "show-access-layer": ApiCallResult(
                success=True, data={"uid": layer_uid, "name": "Network", "type": "access-layer"}, message="", code=""
            ),
        }
    )
    reader = LiveStateReader(client)
    layer = await reader.get_layer(layer_uid, "access", mgmt="m", domain="d")
    assert layer is not None and layer.uid == layer_uid
    assert client.calls[0] == ("show-access-layer", {"uid": layer_uid, "details-level": "full"})


@pytest.mark.asyncio
async def test_get_layer_name_that_merely_contains_hyphens_still_resolves_by_name():
    """A guard against false positives: an ordinary layer name with hyphens (but not shaped like
    a UUID) must still resolve by name, not be misclassified as a uid."""
    client = FakeClient(
        {
            "show-access-layer": ApiCallResult(
                success=True,
                data={"uid": "u1", "name": "FPCR-UAT-Active-Network", "type": "access-layer"},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    layer = await reader.get_layer("FPCR-UAT-Active-Network", "access", mgmt="m", domain="d")
    assert layer is not None and layer.uid == "u1"
    assert client.calls[0] == ("show-access-layer", {"name": "FPCR-UAT-Active-Network", "details-level": "full"})


@pytest.mark.asyncio
async def test_get_layer_inline_resolves_parent_one_level():
    client = FakeClient(
        {
            "show-access-layer": ApiCallResult(
                success=True,
                data={
                    "uid": "u2",
                    "name": "AppControl",
                    "type": "access-layer",
                    "parent-layer": {"uid": "u1", "name": "Network"},
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    layer = await reader.get_layer("AppControl", "access", mgmt="m", domain="d")
    assert layer is not None and layer.parent_layer_uid == "u1"


@pytest.mark.asyncio
async def test_get_layer_inline_parent_layer_is_bare_uid_string():
    """Task 4's caveat, live-verified in Task 14: the real API returns "parent-layer" as a bare
    UID string (e.g. "u1"), not the nested {"uid": ...} object the plan-time sketch assumed --
    confirmed against a real inline (Application Control) sub-layer on the live lab."""
    client = FakeClient(
        {
            "show-access-layer": ApiCallResult(
                success=True,
                data={"uid": "u2", "name": "Inline", "type": "access-layer", "parent-layer": "u1"},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    layer = await reader.get_layer("Inline", "access", mgmt="m", domain="d")
    assert layer is not None and layer.parent_layer_uid == "u1"


@pytest.mark.asyncio
async def test_get_layer_not_found_returns_none():
    client = FakeClient({})
    reader = LiveStateReader(client)
    layer = await reader.get_layer("NoSuchLayer", "https", mgmt="m", domain="d")
    assert layer is None
    assert client.calls[0][0] == "show-https-layer"


async def test_hybrid_get_layer_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True, data={"uid": "u1", "name": "Network", "type": "access-layer"}, message="", code=""
    )
    reader = HybridStateReader(client)
    layer = await reader.get_layer("Network", "access", mgmt="m", domain="d")
    assert layer is not None
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_section_found_in_rulebase():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {"type": "access-section", "uid": "s1", "name": "Web Section", "rulebase": []},
                        {"type": "access-rule", "uid": "r1", "name": "some-rule"},
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    section = await reader.get_section("Web Section", "layer-u1", "access", mgmt="m", domain="d")
    assert section is not None and section.uid == "s1" and section.layer_uid == "layer-u1"


@pytest.mark.asyncio
async def test_get_section_not_found_returns_none():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(success=True, data={"rulebase": []}, message="", code=""),
        }
    )
    reader = LiveStateReader(client)
    section = await reader.get_section("No Such Section", "layer-u1", "access", mgmt="m", domain="d")
    assert section is None


@pytest.mark.asyncio
async def test_get_section_matches_by_uid_too():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={"rulebase": [{"type": "access-section", "uid": "s1", "name": "Web Section", "rulebase": []}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    section = await reader.get_section("s1", "layer-u1", "access", mgmt="m", domain="d")
    assert section is not None and section.name == "Web Section"


async def test_hybrid_get_section_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(success=True, data={"rulebase": []}, message="", code="")
    reader = HybridStateReader(client)
    section = await reader.get_section("X", "layer-u1", "access", mgmt="m", domain="d")
    assert section is None
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_last_rule_returns_highest_rule_number():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "first",
                            "rule-number": 1,
                            "source": [],
                            "destination": [],
                            "service": [],
                        },
                        {
                            "type": "access-rule",
                            "uid": "r2",
                            "name": "last",
                            "rule-number": 2,
                            "source": [],
                            "destination": [],
                            "service": [],
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is not None and last.uid == "r2" and last.rule_number == 2


@pytest.mark.asyncio
async def test_get_last_rule_empty_scope_returns_none():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(success=True, data={"rulebase": []}, message="", code=""),
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is None


@pytest.mark.asyncio
async def test_get_last_rule_descends_into_sections():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "before-section",
                            "rule-number": 1,
                            "source": [],
                            "destination": [],
                            "service": [],
                        },
                        {
                            "type": "access-section",
                            "uid": "s1",
                            "name": "Sec",
                            "rulebase": [
                                {
                                    "type": "access-rule",
                                    "uid": "r2",
                                    "name": "in-section",
                                    "rule-number": 2,
                                    "source": [],
                                    "destination": [],
                                    "service": [],
                                },
                            ],
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is not None and last.uid == "r2"  # last rule overall, even nested in a section


@pytest.mark.asyncio
async def test_hybrid_get_last_rule_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={
            "rulebase": [
                {
                    "type": "access-rule",
                    "uid": "r1",
                    "name": "only",
                    "rule-number": 1,
                    "source": [],
                    "destination": [],
                    "service": [],
                },
            ]
        },
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is not None and last.uid == "r1"
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_rules_by_traffic_matches_order_independent():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "match",
                            "rule-number": 1,
                            "source": ["u2", "u1"],
                            "destination": ["u3"],
                            "service": ["u4"],
                        },
                        {
                            "type": "access-rule",
                            "uid": "r2",
                            "name": "no-match",
                            "rule-number": 2,
                            "source": ["u9"],
                            "destination": ["u3"],
                            "service": ["u4"],
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic(
        "layer-u1", "access", ["u1", "u2"], ["u3"], ["u4"], mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["r1"]


@pytest.mark.asyncio
async def test_find_rules_by_traffic_no_match_returns_empty():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "x",
                            "rule-number": 1,
                            "source": ["u9"],
                            "destination": ["u3"],
                            "service": ["u4"],
                        }
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic("layer-u1", "access", ["u1"], ["u3"], ["u4"], mgmt="m", domain="d")
    assert matches == []


@pytest.mark.asyncio
async def test_find_rules_by_traffic_multiple_matches_all_returned():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "a",
                            "rule-number": 1,
                            "source": ["u1"],
                            "destination": ["u3"],
                            "service": ["u4"],
                        },
                        {
                            "type": "access-rule",
                            "uid": "r2",
                            "name": "b",
                            "rule-number": 2,
                            "source": ["u1"],
                            "destination": ["u3"],
                            "service": ["u4"],
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic("layer-u1", "access", ["u1"], ["u3"], ["u4"], mgmt="m", domain="d")
    assert {m.uid for m in matches} == {"r1", "r2"}  # tie-break happens in resolve_rule (Task 11), not here


@pytest.mark.asyncio
async def test_find_rules_by_traffic_dereferences_uids_via_objects_dictionary():
    """Task 14's core live-verified fix: a real `show-access-rulebase` read returns bare UIDs
    for source/destination/service, never names -- comparing those UIDs directly against a
    template's declared names (the shape `resolve_rule` actually passes in) never matches,
    silently breaking idempotency. `use-object-dictionary: true` returns an `objects-dictionary`
    alongside the rulebase; `_uid_to_name_map`/`_dereference_rule` must translate the rule's raw
    UIDs to names using it before the traffic-tuple comparison runs."""
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "match",
                            "rule-number": 1,
                            "source": ["uid-host-a"],
                            "destination": ["uid-Any"],
                            "service": ["uid-Any"],
                        },
                    ],
                    "objects-dictionary": [
                        {"uid": "uid-host-a", "name": "Host_10.0.0.5"},
                        {"uid": "uid-Any", "name": "Any"},
                    ],
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    # Target refs are NAMES (matching resolve_rule's actual call shape after the Task 14 fix --
    # resolve_ip_reference/resolve_service_reference now return names, not uids, for matches).
    matches = await reader.find_rules_by_traffic(
        "layer-u1", "access", ["Host_10.0.0.5"], ["Any"], ["Any"], mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["r1"]
    assert matches[0].raw["source"] == ["Host_10.0.0.5"]  # dereferenced in the returned RuleMatch too


@pytest.mark.asyncio
async def test_find_rules_by_traffic_action_field_dereferenced_case_insensitively():
    """`action` (a plain string, not a list) must also be dereferenced -- CP's canonical action
    names are capitalized ("Accept") while templates commonly declare lowercase ("accept");
    `_rule_field_equal`'s case-fold (not this dereferencing step) is what makes the two compare
    equal, but the dereferencing must still happen first for a bare `action` uid to become a name
    at all."""
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-rule",
                            "uid": "r1",
                            "name": "match",
                            "rule-number": 1,
                            "source": ["uid-Any"],
                            "destination": ["uid-Any"],
                            "service": ["uid-Any"],
                            "action": "uid-accept",
                        },
                    ],
                    "objects-dictionary": [
                        {"uid": "uid-Any", "name": "Any"},
                        {"uid": "uid-accept", "name": "Accept"},
                    ],
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic("layer-u1", "access", ["Any"], ["Any"], ["Any"], mgmt="m", domain="d")
    assert matches[0].raw["action"] == "Accept"


@pytest.mark.asyncio
async def test_find_nat_rules_by_tuple_dereferences_uids_via_objects_dictionary():
    """NAT counterpart: `_dereference_nat_rule` must translate the 6 original/translated fields
    (singular strings, not lists) using the same objects-dictionary mechanism."""
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "nat-rule",
                            "uid": "n1",
                            "name": "hide",
                            "rule-number": 1,
                            "original-source": "uid-host-a",
                            "original-destination": "uid-Any",
                            "original-service": "uid-Any",
                            "translated-source": "uid-gw",
                            "translated-destination": "uid-Any",
                            "translated-service": "uid-Any",
                        },
                    ],
                    "objects-dictionary": [
                        {"uid": "uid-host-a", "name": "Host_10.0.0.5"},
                        {"uid": "uid-Any", "name": "Any"},
                        {"uid": "uid-gw", "name": "gw-01"},
                    ],
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_nat_rules_by_tuple(
        "Standard",
        ("Host_10.0.0.5", "Any", "Any", "gw-01", "Any", "Any"),
        mgmt="m",
        domain="d",
    )
    assert [m.uid for m in matches] == ["n1"]


@pytest.mark.asyncio
async def test_find_rules_by_traffic_accumulates_across_pages():
    """`show-access-rulebase`'s default page limit is 50 (confirmed via Check Point's own API
    reference) -- a rule beyond the first page must still be found, not silently missed. Page 1
    reports total=3/to=1 (more to come); page 2 reports total=3/to=3 (done) and carries the rule
    that actually matches, plus its own objects-dictionary entry (proving dictionaries merge
    across pages too, not just rulebase items)."""
    client = FakeClient(
        {
            "show-access-rulebase": [
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [
                            {
                                "type": "access-rule",
                                "uid": "r1",
                                "name": "other",
                                "rule-number": 1,
                                "source": ["uid-other"],
                                "destination": ["uid-Any"],
                                "service": ["uid-Any"],
                            }
                        ],
                        "objects-dictionary": [
                            {"uid": "uid-other", "name": "Other"},
                            {"uid": "uid-Any", "name": "Any"},
                        ],
                        "total": 3,
                        "to": 1,
                    },
                    message="",
                    code="",
                ),
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [
                            {
                                "type": "access-rule",
                                "uid": "r2",
                                "name": "match",
                                "rule-number": 2,
                                "source": ["uid-host-a"],
                                "destination": ["uid-Any"],
                                "service": ["uid-Any"],
                            }
                        ],
                        "objects-dictionary": [{"uid": "uid-host-a", "name": "Host_10.0.0.5"}],
                        "total": 3,
                        "to": 3,
                    },
                    message="",
                    code="",
                ),
            ],
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic(
        "layer-u1", "access", ["Host_10.0.0.5"], ["Any"], ["Any"], mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["r2"]
    assert matches[0].raw["source"] == ["Host_10.0.0.5"]  # dereferenced via page 2's own dictionary entry
    assert len(client.calls) == 2
    assert client.calls[0][1]["offset"] == 0
    assert client.calls[1][1]["offset"] == 50


@pytest.mark.asyncio
async def test_get_last_rule_accumulates_across_pages():
    """The true "last" rule can live on a later page -- get_last_rule must not stop at page 1."""
    client = FakeClient(
        {
            "show-access-rulebase": [
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [{"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 1}],
                        "total": 2,
                        "to": 1,
                    },
                    message="",
                    code="",
                ),
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [{"type": "access-rule", "uid": "r2", "name": "b", "rule-number": 2}],
                        "total": 2,
                        "to": 2,
                    },
                    message="",
                    code="",
                ),
            ],
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is not None and last.uid == "r2"
    assert [c[1]["offset"] for c in client.calls] == [0, 50]


@pytest.mark.asyncio
async def test_get_rule_by_key_finds_rule_beyond_first_page():
    """A real rule beyond page 1 must be found by key -- not wrongly reported "not found" (which
    would turn a delete into a silent no-op instead of actually deleting an existing rule)."""
    client = FakeClient(
        {
            "show-access-rulebase": [
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [{"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 1}],
                        "total": 2,
                        "to": 1,
                    },
                    message="",
                    code="",
                ),
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [{"type": "access-rule", "uid": "r2", "name": "target", "rule-number": 2}],
                        "total": 2,
                        "to": 2,
                    },
                    message="",
                    code="",
                ),
            ],
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"name": "target"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r2"
    assert [c[1]["offset"] for c in client.calls] == [0, 50]


@pytest.mark.asyncio
async def test_find_nat_rules_by_tuple_accumulates_across_pages():
    client = FakeClient(
        {
            "show-nat-rulebase": [
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [
                            {
                                "type": "nat-rule",
                                "uid": "n1",
                                "name": "other",
                                "rule-number": 1,
                                "original-source": "sX",
                                "original-destination": "d1",
                                "original-service": "svc1",
                                "translated-source": "s2",
                                "translated-destination": "d2",
                                "translated-service": "svc2",
                            }
                        ],
                        "total": 2,
                        "to": 1,
                    },
                    message="",
                    code="",
                ),
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [
                            {
                                "type": "nat-rule",
                                "uid": "n2",
                                "name": "match",
                                "rule-number": 2,
                                "original-source": "s1",
                                "original-destination": "d1",
                                "original-service": "svc1",
                                "translated-source": "s2",
                                "translated-destination": "d2",
                                "translated-service": "svc2",
                            }
                        ],
                        "total": 2,
                        "to": 2,
                    },
                    message="",
                    code="",
                ),
            ],
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_nat_rules_by_tuple(
        "Standard", ("s1", "d1", "svc1", "s2", "d2", "svc2"), mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["n2"]
    assert [c[1]["offset"] for c in client.calls] == [0, 50]


@pytest.mark.asyncio
async def test_paginate_rulebase_returns_partial_accumulation_when_a_later_page_fails():
    """A failure on page 2+ must not discard page 1's already-accumulated data -- return what
    was gathered so far rather than nothing at all."""
    client = FakeClient(
        {
            "show-access-rulebase": [
                ApiCallResult(
                    success=True,
                    data={
                        "rulebase": [{"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 1}],
                        "total": 2,
                        "to": 1,
                    },
                    message="",
                    code="",
                ),
                ApiCallResult(success=False, message="timeout", code="generic_err"),
            ],
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_rule("layer-u1", "access", mgmt="m", domain="d")
    assert last is not None and last.uid == "r1"


@pytest.mark.asyncio
async def test_find_by_ip_uses_api_query_for_pagination():
    """show-objects is a listing endpoint (default page limit 50) -- must go through api_query
    (which auto-paginates), not a single api_call that would silently miss matches past page 1."""
    client = FakeClient(
        {
            "show-objects": ApiCallResult(
                success=True,
                data={"objects": [{"uid": "u-exact", "name": "exact", "type": "host", "ipv4-address": "10.0.0.5"}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    found = await reader.find_by_ip(type="host", ip_value={"ip-address": "10.0.0.5"}, mgmt="m", domain="d")
    assert [o.name for o in found] == ["exact"]
    assert client.calls == []  # must not go through the non-paginating api_call
    assert client.query_calls[0][0] == "show-objects"
    assert client.query_calls[0][2] == "objects"  # container_key


@pytest.mark.asyncio
async def test_find_rules_by_traffic_api_failure_returns_empty():
    client = FakeClient({})  # api_call falls through to the default failing ApiCallResult
    reader = LiveStateReader(client)
    matches = await reader.find_rules_by_traffic("layer-u1", "access", ["u1"], ["u3"], ["u4"], mgmt="m", domain="d")
    assert matches == []


@pytest.mark.asyncio
async def test_hybrid_find_rules_by_traffic_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={
            "rulebase": [
                {
                    "type": "access-rule",
                    "uid": "r1",
                    "name": "only",
                    "rule-number": 1,
                    "source": ["u1"],
                    "destination": ["u3"],
                    "service": ["u4"],
                },
            ]
        },
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    matches = await reader.find_rules_by_traffic("layer-u1", "access", ["u1"], ["u3"], ["u4"], mgmt="m", domain="d")
    assert [m.uid for m in matches] == ["r1"]
    client.cache.get_objects_by_name.assert_not_awaited()  # never touches the cache


# ---------------------------------------------------------------------------
# nat-rule -- package-scoped rulebase read (no layer concept)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_nat_rules_by_tuple_positional_match():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "nat-rule",
                            "uid": "n1",
                            "name": "",
                            "rule-number": 1,
                            "original-source": "s1",
                            "original-destination": "d1",
                            "original-service": "svc1",
                            "translated-source": "s2",
                            "translated-destination": "d2",
                            "translated-service": "svc2",
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_nat_rules_by_tuple(
        "Standard", ("s1", "d1", "svc1", "s2", "d2", "svc2"), mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["n1"]
    # limit/offset are added by _paginate_rulebase (default page size 50, per Check Point's own
    # API reference) -- a single page always covers this fixture, but the payload always carries
    # them since real rulebases may need more than one page.
    assert client.calls[0] == (
        "show-nat-rulebase",
        {"package": "Standard", "details-level": "full", "use-object-dictionary": True, "limit": 50, "offset": 0},
    )


@pytest.mark.asyncio
async def test_find_nat_rules_by_tuple_no_match():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "nat-rule",
                            "uid": "n1",
                            "name": "",
                            "rule-number": 1,
                            "original-source": "sX",
                            "original-destination": "d1",
                            "original-service": "svc1",
                            "translated-source": "s2",
                            "translated-destination": "d2",
                            "translated-service": "svc2",
                        }
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    matches = await reader.find_nat_rules_by_tuple(
        "Standard", ("s1", "d1", "svc1", "s2", "d2", "svc2"), mgmt="m", domain="d"
    )
    assert matches == []


@pytest.mark.asyncio
async def test_get_last_nat_rule():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {"type": "nat-rule", "uid": "n1", "name": "", "rule-number": 1},
                        {"type": "nat-rule", "uid": "n2", "name": "", "rule-number": 2},
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_nat_rule("Standard", mgmt="m", domain="d")
    assert last is not None and last.uid == "n2"


@pytest.mark.asyncio
async def test_get_last_nat_rule_empty_returns_none():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(success=True, data={"rulebase": []}, message="", code=""),
        }
    )
    reader = LiveStateReader(client)
    last = await reader.get_last_nat_rule("Standard", mgmt="m", domain="d")
    assert last is None


@pytest.mark.asyncio
async def test_hybrid_find_nat_rules_by_tuple_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={
            "rulebase": [
                {
                    "type": "nat-rule",
                    "uid": "n1",
                    "name": "",
                    "rule-number": 1,
                    "original-source": "s1",
                    "original-destination": "d1",
                    "original-service": "svc1",
                    "translated-source": "s2",
                    "translated-destination": "d2",
                    "translated-service": "svc2",
                },
            ]
        },
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    matches = await reader.find_nat_rules_by_tuple(
        "Standard", ("s1", "d1", "svc1", "s2", "d2", "svc2"), mgmt="m", domain="d"
    )
    assert [m.uid for m in matches] == ["n1"]
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_hybrid_get_last_nat_rule_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={"rulebase": [{"type": "nat-rule", "uid": "n1", "name": "", "rule-number": 1}]},
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    last = await reader.get_last_nat_rule("Standard", mgmt="m", domain="d")
    assert last is not None and last.uid == "n1"
    client.cache.get_objects_by_name.assert_not_awaited()


# ---------------------------------------------------------------------------
# get_rule_by_key / get_nat_rule_by_key (Task 13) -- key-based lookup for update/delete/show,
# reusing the same rulebase-fetch machinery as find_rules_by_traffic/find_nat_rules_by_tuple.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_rule_by_key_matches_by_uid():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 1},
                        {"type": "access-rule", "uid": "r2", "name": "b", "rule-number": 2},
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"uid": "r2"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r2"
    assert client.calls[0] == (
        "show-access-rulebase",
        {"uid": "layer-u1", "details-level": "full", "use-object-dictionary": True, "limit": 50, "offset": 0},
    )


@pytest.mark.asyncio
async def test_get_rule_by_key_matches_by_name():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={"rulebase": [{"type": "access-rule", "uid": "r1", "name": "Allow-Web", "rule-number": 1}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"name": "Allow-Web"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r1"


@pytest.mark.asyncio
async def test_get_rule_by_key_matches_by_rule_number():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={"rulebase": [{"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 7}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"rule-number": 7}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r1"


@pytest.mark.asyncio
async def test_get_rule_by_key_descends_into_sections():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(
                success=True,
                data={
                    "rulebase": [
                        {
                            "type": "access-section",
                            "uid": "s1",
                            "name": "Sec",
                            "rulebase": [
                                {"type": "access-rule", "uid": "r2", "name": "in-section", "rule-number": 1},
                            ],
                        },
                    ]
                },
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"name": "in-section"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r2"


@pytest.mark.asyncio
async def test_get_rule_by_key_not_found_returns_none():
    client = FakeClient(
        {
            "show-access-rulebase": ApiCallResult(success=True, data={"rulebase": []}, message="", code=""),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"name": "gone"}, mgmt="m", domain="d")
    assert rule is None


@pytest.mark.asyncio
async def test_get_rule_by_key_api_failure_returns_none():
    client = FakeClient({})
    reader = LiveStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"name": "x"}, mgmt="m", domain="d")
    assert rule is None


@pytest.mark.asyncio
async def test_hybrid_get_rule_by_key_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={"rulebase": [{"type": "access-rule", "uid": "r1", "name": "a", "rule-number": 1}]},
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    rule = await reader.get_rule_by_key("layer-u1", "access", {"uid": "r1"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "r1"
    client.cache.get_objects_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_nat_rule_by_key_matches_by_name():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={"rulebase": [{"type": "nat-rule", "uid": "n1", "name": "hide-nat", "rule-number": 1}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_nat_rule_by_key("Standard", {"name": "hide-nat"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "n1"
    assert client.calls[0] == (
        "show-nat-rulebase",
        {"package": "Standard", "details-level": "full", "use-object-dictionary": True, "limit": 50, "offset": 0},
    )


@pytest.mark.asyncio
async def test_get_nat_rule_by_key_matches_by_rule_number():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(
                success=True,
                data={"rulebase": [{"type": "nat-rule", "uid": "n1", "name": "", "rule-number": 3}]},
                message="",
                code="",
            ),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_nat_rule_by_key("Standard", {"rule-number": 3}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "n1"


@pytest.mark.asyncio
async def test_get_nat_rule_by_key_not_found_returns_none():
    client = FakeClient(
        {
            "show-nat-rulebase": ApiCallResult(success=True, data={"rulebase": []}, message="", code=""),
        }
    )
    reader = LiveStateReader(client)
    rule = await reader.get_nat_rule_by_key("Standard", {"name": "gone"}, mgmt="m", domain="d")
    assert rule is None


@pytest.mark.asyncio
async def test_hybrid_get_nat_rule_by_key_always_delegates_to_live():
    client = AsyncMock()
    client.api_call.return_value = SimpleNamespace(
        success=True,
        data={"rulebase": [{"type": "nat-rule", "uid": "n1", "name": "hide-nat", "rule-number": 1}]},
        message="",
        code="",
    )
    reader = HybridStateReader(client)
    rule = await reader.get_nat_rule_by_key("Standard", {"name": "hide-nat"}, mgmt="m", domain="d")
    assert rule is not None and rule.uid == "n1"
    client.cache.get_objects_by_name.assert_not_awaited()
