"""Unit tests for :class:`arodonata.core.orchestration.CacheOrchestrationService`.

Offline-only: exercises the read-helper conversion paths, the cache-mode
dispatch to an injected coordinator, freshness checks, the publish ->
reconcile-from-server-truth flow, and discard. Uses the shared protocol
doubles from ``tests/unit/doubles.py`` where possible.
"""

from datetime import UTC, datetime, timedelta

import pytest

from arodonata.cache.models import (
    Asset,
    CPObject,
    LastPublishedSession,
    RulebaseAccess,
    RulebaseHTTPS,
    RulebaseNAT,
    RulebaseThreat,
)
from arodonata.cache.models import Domain as CacheDomain
from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshOutcome
from arodonata.core.orchestration import CacheOrchestrationService
from arodonata.core.session_tracker import SessionChange, SessionChangeTracker

from ..doubles import FakeApi, FakeCache

# ---------------------------------------------------------------------------
# Local doubles built on top of the shared ones
# ---------------------------------------------------------------------------


class ConfiguredCache(FakeCache):
    """FakeCache that returns pre-seeded rows and records read filters."""

    def __init__(
        self,
        *,
        objects=None,
        domains=None,
        gateways=None,
        rulebase=None,
        last_session=None,
        object_by_uid=None,
    ):
        self._objects = objects or []
        self._domains = domains or []
        self._gateways = gateways or []
        self._rulebase = rulebase or []
        self._last_session = last_session
        self._object_by_uid = object_by_uid
        self.get_objects_calls = []
        self.get_rulebase_calls = []

    async def get_objects(self, object_type=None, mgmt_names=None, domain_names=None, filters=None):
        self.get_objects_calls.append(
            {
                "object_type": object_type,
                "mgmt_names": mgmt_names,
                "domain_names": domain_names,
                "filters": filters,
            }
        )
        return self._objects

    async def get_domains(self, mgmt_names=None):
        return self._domains

    async def get_gateways(self, mgmt_names=None):
        return self._gateways

    async def get_rulebase(
        self,
        rulebase_type,
        layer_name=None,
        mgmt_names=None,
        domain_names=None,
        enabled_only=None,
    ):
        self.get_rulebase_calls.append(
            {
                "rulebase_type": rulebase_type,
                "layer_name": layer_name,
                "mgmt_names": mgmt_names,
                "domain_names": domain_names,
                "enabled_only": enabled_only,
            }
        )
        return self._rulebase

    async def get_last_published_session(self, mgmt_name, domain_name):
        return self._last_session

    async def get_object_by_uid(self, uid, mgmt_name, domain_name):
        return self._object_by_uid


class RecordingCoordinator:
    """Coordinator double recording ensure()/invalidate() calls."""

    def __init__(self, default_mode=CacheMode.SMART, default_ttl=300):
        self.default_policy = CachePolicy(default_mode, default_ttl)
        self.ensure_calls = []
        self.invalidated = []

    async def ensure(self, scope, policy):
        self.ensure_calls.append((scope, policy))
        return RefreshOutcome(mode_used=policy.mode)

    def invalidate(self, mgmt_name, domain_name):
        self.invalidated.append((mgmt_name, domain_name))


class SuccessAttrResponse:
    """Publish response exposing a ``.success`` attribute."""

    def __init__(self, success):
        self.success = success


def _svc(cache=None, api=None, session_tracker=None, coordinator=None):
    return CacheOrchestrationService(
        cache=cache if cache is not None else FakeCache(),
        api=api if api is not None else FakeApi(),
        session_tracker=session_tracker,
        coordinator=coordinator,
    )


# ---------------------------------------------------------------------------
# get_domains / get_gateways
# ---------------------------------------------------------------------------


async def test_get_domains_converts_and_splits_standby_lists():
    cache = ConfiguredCache(
        domains=[
            CacheDomain(
                mdm_dmn="mgmt1:dmn1",
                domain_name="dmn1",
                domain_uid="d-uid",
                active_mds="mgmt1",
                active_ip="10.0.0.1",
                active_server="mgmt1",
                standby_ips="10.0.0.2,10.0.0.3",
                standby_servers="s2,s3",
                mgmt_name="mgmt1",
                is_mdm=True,
            )
        ]
    )
    [domain] = await _svc(cache=cache).get_domains(mgmt_names=["mgmt1"])
    assert domain.uid == "d-uid"
    assert domain.name == "dmn1"
    assert domain.standby_ips == ["10.0.0.2", "10.0.0.3"]
    assert domain.standby_servers == ["s2", "s3"]
    assert domain.is_mdm is True


async def test_get_domains_empty_standby_lists_default_to_empty():
    cache = ConfiguredCache(
        domains=[
            CacheDomain(
                mdm_dmn="mgmt1:dmn1",
                domain_name="dmn1",
                active_mds="mgmt1",
                active_ip="10.0.0.1",
                active_server="mgmt1",
                mgmt_name="mgmt1",
            )
        ]
    )
    [domain] = await _svc(cache=cache).get_domains()
    assert domain.standby_ips == []
    assert domain.standby_servers == []


async def test_get_gateways_converts_assets():
    cache = ConfiguredCache(
        gateways=[
            Asset(
                asset_id="mgmt1::gw1",
                name="gw1",
                asset_type="simple-gateway",
                asset_uid="gw-uid",
                ip_address="10.0.0.5",
                ssh_ip="10.0.0.6",
                domain_name="dmn1",
                mgmt_name="mgmt1",
                parent_asset_id=None,
                raw_data={"k": "v"},
            )
        ]
    )
    [gw] = await _svc(cache=cache).get_gateways(mgmt_names=["mgmt1"])
    assert gw.uid == "gw-uid"
    assert gw.type == "simple-gateway"
    assert gw.ssh_ip == "10.0.0.6"
    assert gw.raw_data == {"k": "v"}


# ---------------------------------------------------------------------------
# get_hosts / get_networks / get_groups
# ---------------------------------------------------------------------------


def _host_obj(uid="uid-1", name="web", ip="10.0.0.10"):
    return CPObject(
        id=f"mgmt1::{uid}",
        uid=uid,
        name=name,
        type="host",
        ipv4_address=ip,
        mgmt_name="mgmt1",
        domain_name="",
        raw_data={"uid": uid},
    )


async def test_get_hosts_converts_objects_no_filter():
    cache = ConfiguredCache(objects=[_host_obj()])
    [host] = await _svc(cache=cache).get_hosts()
    assert host.name == "web"
    assert host.ip_address == "10.0.0.10"
    # No name filter -> filters passed as None.
    assert cache.get_objects_calls[0]["filters"] is None
    assert cache.get_objects_calls[0]["object_type"] == "host"


async def test_get_hosts_passes_name_filter():
    cache = ConfiguredCache(objects=[_host_obj()])
    await _svc(cache=cache).get_hosts(name_filter="web*", mgmt_names=["mgmt1"])
    assert cache.get_objects_calls[0]["filters"] == {"name": "web*"}
    assert cache.get_objects_calls[0]["mgmt_names"] == ["mgmt1"]


async def test_get_networks_converts_and_filters_by_subnet():
    objs = [
        CPObject(
            id="mgmt1::n1",
            uid="n1",
            name="net-a",
            type="network",
            subnet4="10.0.0.0",
            subnet_mask="255.255.255.0",
            mgmt_name="mgmt1",
            raw_data={},
        ),
        CPObject(
            id="mgmt1::n2",
            uid="n2",
            name="net-b",
            type="network",
            subnet4="10.1.0.0",
            subnet_mask="255.255.255.0",
            mgmt_name="mgmt1",
            raw_data={},
        ),
    ]
    svc = _svc(cache=ConfiguredCache(objects=objs))
    matched = await svc.get_networks(subnet="10.1.0.0")
    assert [n.name for n in matched] == ["net-b"]


async def test_get_networks_without_subnet_returns_all():
    objs = [
        CPObject(
            id="mgmt1::n1",
            uid="n1",
            name="net-a",
            type="network",
            subnet4="10.0.0.0",
            mgmt_name="mgmt1",
            raw_data={},
        )
    ]
    nets = await _svc(cache=ConfiguredCache(objects=objs)).get_networks()
    assert len(nets) == 1


async def test_get_groups_splits_members():
    obj = CPObject(
        id="mgmt1::g1",
        uid="g1",
        name="grp",
        type="group",
        members="m1,m2,m3",
        mgmt_name="mgmt1",
        raw_data={},
    )
    [group] = await _svc(cache=ConfiguredCache(objects=[obj])).get_groups(name_filter="grp")
    assert group.member_uids == ["m1", "m2", "m3"]


async def test_get_groups_empty_members_default_empty_list():
    obj = CPObject(
        id="mgmt1::g1",
        uid="g1",
        name="grp",
        type="group",
        members="",
        mgmt_name="mgmt1",
        raw_data={},
    )
    [group] = await _svc(cache=ConfiguredCache(objects=[obj])).get_groups()
    assert group.member_uids == []


async def test_get_object_by_uid_delegates_to_cache():
    obj = _host_obj(uid="uid-x")
    svc = _svc(cache=ConfiguredCache(object_by_uid=obj))
    result = await svc.get_object_by_uid("uid-x", "mgmt1", "dmn1")
    assert result is obj


# ---------------------------------------------------------------------------
# Rulebase helpers
# ---------------------------------------------------------------------------


async def test_get_access_rules_converts_and_splits():
    rule = RulebaseAccess(
        id="mgmt1:dmn1:Network:r1",
        uid="r1",
        rule_number=1,
        name="allow-web",
        enabled=True,
        layer_name="Network",
        mgmt_name="mgmt1",
        domain_name="dmn1",
        sources="s1,s2",
        destinations="d1",
        services="svc1",
        action="accept",
        track="Log",
        raw_data={},
    )
    cache = ConfiguredCache(rulebase=[rule])
    [ar] = await _svc(cache=cache).get_access_rules(layer_name="Network", enabled_only=True)
    assert ar.sources == ["s1", "s2"]
    assert ar.destinations == ["d1"]
    assert ar.services == ["svc1"]
    assert cache.get_rulebase_calls[0]["rulebase_type"] == "access"
    assert cache.get_rulebase_calls[0]["enabled_only"] is True


async def test_get_nat_rules_converts():
    rule = RulebaseNAT(
        id="mgmt1:dmn1:NAT:r1",
        uid="r1",
        rule_number=1,
        name="nat-1",
        enabled=True,
        layer_name="NAT",
        mgmt_name="mgmt1",
        original_source="orig-src",
        original_destination="orig-dst",
        original_service="orig-svc",
        translated_source="t-src",
        translated_destination="t-dst",
        translated_service="t-svc",
        raw_data={},
    )
    [nat] = await _svc(cache=ConfiguredCache(rulebase=[rule])).get_nat_rules()
    assert nat.original_source == "orig-src"
    assert nat.translated_service == "t-svc"


async def test_get_https_rules_converts_and_splits():
    rule = RulebaseHTTPS(
        id="mgmt1:dmn1:CVD:r1",
        uid="r1",
        rule_number=1,
        name="https-1",
        enabled=False,
        layer_name="CVD",
        mgmt_name="mgmt1",
        sources="s1,s2",
        destinations="d1,d2",
        track="Log",
        raw_data={},
    )
    [https] = await _svc(cache=ConfiguredCache(rulebase=[rule])).get_https_rules()
    assert https.sources == ["s1", "s2"]
    assert https.destinations == ["d1", "d2"]
    assert https.enabled is False


async def test_get_threat_rules_converts_and_splits():
    rule = RulebaseThreat(
        id="mgmt1:dmn1:Threat:r1",
        uid="r1",
        rule_number=1,
        name="threat-1",
        enabled=True,
        layer_name="Threat",
        mgmt_name="mgmt1",
        track="Log",
        protections="p1,p2",
        raw_data={},
    )
    [threat] = await _svc(cache=ConfiguredCache(rulebase=[rule])).get_threat_rules()
    assert threat.protections == ["p1", "p2"]


# ---------------------------------------------------------------------------
# _ensure / cache-mode dispatch to coordinator
# ---------------------------------------------------------------------------


async def test_read_helper_calls_coordinator_with_resolved_policy():
    coord = RecordingCoordinator()
    svc = _svc(cache=FakeCache(), coordinator=coord)
    await svc.get_hosts(mgmt_names=["m1"], domain_names=["d1"], cache_mode="cache")
    assert len(coord.ensure_calls) == 1
    scope, policy = coord.ensure_calls[0]
    assert policy.mode == CacheMode.CACHE
    assert scope.mgmt_names == ["m1"]
    assert scope.domain_names == ["d1"]


async def test_read_helper_defaults_to_coordinator_default_policy():
    coord = RecordingCoordinator(default_mode=CacheMode.SMART)
    svc = _svc(cache=FakeCache(), coordinator=coord)
    await svc.get_hosts(mgmt_names=["m1"], domain_names=["d1"])
    _, policy = coord.ensure_calls[0]
    assert policy.mode == CacheMode.SMART


async def test_read_helper_per_call_ttl_override_reaches_coordinator():
    coord = RecordingCoordinator(default_ttl=300)
    svc = _svc(cache=FakeCache(), coordinator=coord)
    await svc.get_networks(mgmt_names=["m1"], domain_names=["d1"], cache_ttl=999)
    _, policy = coord.ensure_calls[0]
    assert policy.ttl == 999


async def test_ensure_is_noop_without_coordinator():
    # No coordinator -> read helpers must not raise and must serve cache.
    svc = _svc(cache=ConfiguredCache(objects=[_host_obj()]))
    hosts = await svc.get_hosts(mgmt_names=["m1"], domain_names=["d1"], cache_mode="force")
    assert len(hosts) == 1


async def test_rulebase_helper_also_dispatches_to_coordinator():
    coord = RecordingCoordinator()
    svc = _svc(cache=FakeCache(), coordinator=coord)
    await svc.get_access_rules(mgmt_names=["m1"], domain_names=["d1"], cache_mode="force")
    _, policy = coord.ensure_calls[0]
    assert policy.mode == CacheMode.FORCE


# ---------------------------------------------------------------------------
# _is_cache_fresh
# ---------------------------------------------------------------------------


class _Tracker:
    def __init__(self, has=False):
        self._has = has

    def has_changes(self, mgmt_name, domain):
        return self._has


async def test_is_cache_fresh_false_when_unpublished_changes():
    svc = _svc(cache=FakeCache(), session_tracker=_Tracker(has=True))
    assert await svc._is_cache_fresh("objects", "m1", "d1") is False


async def test_is_cache_fresh_false_when_no_publish_history():
    svc = _svc(cache=ConfiguredCache(last_session=None))
    assert await svc._is_cache_fresh("objects", "m1", "d1") is False


async def test_is_cache_fresh_false_when_published_time_not_datetime():
    session = LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1")
    session.published_time = "not-a-datetime"  # type: ignore[assignment]
    svc = _svc(cache=ConfiguredCache(last_session=session))
    assert await svc._is_cache_fresh("objects", "m1", "d1") is False


async def test_is_cache_fresh_true_when_recent():
    recent = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=10)
    session = LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1", published_time=recent)
    svc = _svc(cache=ConfiguredCache(last_session=session))
    assert await svc._is_cache_fresh("objects", "m1", "d1") is True


async def test_is_cache_fresh_false_when_stale():
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=5000)
    session = LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1", published_time=old)
    svc = _svc(cache=ConfiguredCache(last_session=session))
    # "objects" freshness is 900s; 5000s old -> stale.
    assert await svc._is_cache_fresh("objects", "m1", "d1") is False


async def test_is_cache_fresh_uses_default_freshness_for_unknown_table():
    recent = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=10)
    session = LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1", published_time=recent)
    svc = _svc(cache=ConfiguredCache(last_session=session))
    assert await svc._is_cache_fresh("unknown-table", "m1", "d1") is True


# ---------------------------------------------------------------------------
# publish -> reconcile-from-server-truth
# ---------------------------------------------------------------------------


class RecordingApi(FakeApi):
    def __init__(self, response=None):
        self._response = response
        self.published = []

    async def publish(self, mgmt_name, domain=""):
        self.published.append((mgmt_name, domain))
        return self._response


async def test_publish_invalidates_and_reconciles_via_smart_fast():
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    coord = RecordingCoordinator()
    api = RecordingApi(response=None)
    svc = _svc(cache=FakeCache(), api=api, session_tracker=tracker, coordinator=coord)

    await svc.publish("m1", "d1")

    assert api.published == [("m1", "d1")]
    assert coord.invalidated == [("m1", "d1")]
    assert len(coord.ensure_calls) == 1
    scope, policy = coord.ensure_calls[0]
    assert scope.mgmt_names == ["m1"]
    assert scope.domain_names == ["d1"]
    assert policy.mode == CacheMode.SMART_FAST
    # Tracker cleared only after a successful reconcile.
    assert tracker.has_changes("m1", "d1") is False


async def test_publish_without_coordinator_skips_reconcile_but_clears_tracker():
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    api = RecordingApi(response={"success": True})
    svc = _svc(cache=FakeCache(), api=api, session_tracker=tracker)

    await svc.publish("m1", "d1")

    assert api.published == [("m1", "d1")]
    assert tracker.has_changes("m1", "d1") is False


async def test_publish_without_session_tracker_still_reconciles():
    coord = RecordingCoordinator()
    api = RecordingApi(response=None)
    svc = _svc(cache=FakeCache(), api=api, session_tracker=None, coordinator=coord)

    await svc.publish("m1", "d1")

    assert coord.invalidated == [("m1", "d1")]
    assert len(coord.ensure_calls) == 1


async def test_publish_uses_success_attribute_response():
    api = RecordingApi(response=SuccessAttrResponse(success=True))
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    svc = _svc(cache=FakeCache(), api=api, session_tracker=tracker)
    await svc.publish("m1", "d1")
    assert tracker.has_changes("m1", "d1") is False


async def test_publish_dict_without_success_key_assumes_ok():
    api = RecordingApi(response={"message": "done"})
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    svc = _svc(cache=FakeCache(), api=api, session_tracker=tracker)
    await svc.publish("m1", "d1")
    assert tracker.has_changes("m1", "d1") is False


async def test_publish_failure_raises_and_does_not_clear_tracker():
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    coord = RecordingCoordinator()
    api = RecordingApi(response={"success": False, "errors": ["nope"]})
    svc = _svc(cache=FakeCache(), api=api, session_tracker=tracker, coordinator=coord)

    with pytest.raises(RuntimeError):
        await svc.publish("m1", "d1")

    assert tracker.has_changes("m1", "d1") is True
    assert coord.invalidated == []
    assert coord.ensure_calls == []


async def test_publish_failure_via_success_attribute_raises():
    api = RecordingApi(response=SuccessAttrResponse(success=False))
    svc = _svc(cache=FakeCache(), api=api, session_tracker=None)
    with pytest.raises(RuntimeError):
        await svc.publish("m1", "d1")


# ---------------------------------------------------------------------------
# discard
# ---------------------------------------------------------------------------


async def test_discard_without_tracker_is_noop():
    svc = _svc(cache=FakeCache(), session_tracker=None)
    # Should simply return without error.
    assert await svc.discard("m1", "d1") is None


async def test_discard_with_no_changes_is_noop():
    tracker = SessionChangeTracker()
    svc = _svc(cache=FakeCache(), session_tracker=tracker)
    await svc.discard("m1", "d1")
    assert tracker.has_changes("m1", "d1") is False


async def test_discard_clears_tracked_changes():
    tracker = SessionChangeTracker()
    tracker.add_change("m1", "d1", SessionChange(operation="add", object_type="host", uid="tmp", name="h"))
    svc = _svc(cache=FakeCache(), session_tracker=tracker)
    await svc.discard("m1", "d1")
    assert tracker.has_changes("m1", "d1") is False
