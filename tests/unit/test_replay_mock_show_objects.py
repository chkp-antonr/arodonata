"""Unit tests for Check Point `show-objects` support in `FileReplayApiMock`."""

from __future__ import annotations

from typing import Any

import pytest

from arodonata.testing.replay_mock import FileReplayApiMock


@pytest.mark.spec("SCN-ITEST-007-1", "SCN-ITEST-007-2")
@pytest.mark.asyncio
async def test_file_replay_mock_show_objects_ip_subnet_range_port_and_pagination() -> None:
    """`show-objects` supports `type`, `filter`, `ip-only`, pagination, and `details-level` projection."""
    mock = FileReplayApiMock()
    branch_files = mock._domain_data["Branch"]

    branch_files["show-hosts"] = {
        "objects": [
            {
                "uid": "h-ip-match",
                "name": "Host_Prod_App",
                "type": "host",
                "ipv4-address": "10.20.30.40",
                "comments": "prod host",
                "custom-secret-field": "extra-full-only",
            },
            {
                "uid": "h-comment-only",
                "name": "Host_Ref_10.20.30.40_Note",
                "type": "host",
                "ipv4-address": "192.0.2.99",
                "comments": "references 10.20.30.40 in name/comments only",
            },
            {
                "uid": "h-v6",
                "name": "Host_IPv6_Core",
                "type": "host",
                "ipv6-address": "2001:db8:cafe::42",
            },
        ]
    }
    branch_files["show-networks"] = {
        "objects": [
            {
                "uid": "net-24",
                "name": "Net_10_10_0_0_24",
                "type": "network",
                "subnet4": "10.10.0.0",
                "mask-length4": 24,
            },
            {
                "uid": "net-16",
                "name": "Net_10_10_0_0_16",
                "type": "network",
                "subnet4": "10.10.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "net-other",
                "name": "Net_172_16_0_0_24",
                "type": "network",
                "subnet4": "172.16.0.0",
                "mask-length4": 24,
            },
        ]
    }
    branch_files["show-address-ranges"] = {
        "objects": [
            {
                "uid": "rng-1",
                "name": "Range_Pool_A",
                "type": "address-range",
                "ipv4-address-first": "10.50.0.10",
                "ipv4-address-last": "10.50.0.20",
            },
            {
                "uid": "rng-2",
                "name": "Range_Pool_B",
                "type": "address-range",
                "ipv4-address-first": "10.50.0.100",
                "ipv4-address-last": "10.50.0.120",
            },
        ]
    }
    branch_files["show-services-tcp"] = {
        "objects": [
            {
                "uid": "svc-80",
                "name": "TCP_80",
                "type": "service-tcp",
                "port": "80",
            },
            {
                "uid": "svc-8080",
                "name": "TCP_8080",
                "type": "service-tcp",
                "port": "8080",
                "protocol": "HTTP_PROXY",
            },
            {
                "uid": "svc-443",
                "name": "TCP_443",
                "type": "service-tcp",
                "port": "443",
            },
        ]
    }
    branch_files["show-services-icmp"] = {
        "objects": [
            {
                "uid": "icmp-echo",
                "name": "ICMP_Echo_Req",
                "type": "service-icmp",
                "icmp-type": 8,
                "icmp-code": 0,
            }
        ]
    }

    # 1. IP filter with ip-only=True ignores name/comment matches; ip-only=False includes them
    ip_only_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "host", "filter": "10.20.30.40", "ip-only": True},
    )
    assert ip_only_res.success
    assert [o["uid"] for o in ip_only_res.objects] == ["h-ip-match"]
    assert ip_only_res.objects[0]["ipv4-address"] == "10.20.30.40"
    assert "custom-secret-field" not in ip_only_res.objects[0]

    text_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="full",
        payload={"type": "host", "filter": "10.20.30.40", "ip-only": False},
    )
    assert [o["uid"] for o in text_res.objects] == ["h-ip-match", "h-comment-only"]
    assert text_res.objects[0]["custom-secret-field"] == "extra-full-only"

    v6_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "host", "filter": "2001:db8:cafe::42", "ip-only": True},
    )
    assert [o["uid"] for o in v6_res.objects] == ["h-v6"]
    assert v6_res.objects[0]["ipv6-address"] == "2001:db8:cafe::42"

    # 2. Subnet and address-range substring filtering with ip-only=True
    net_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "network", "filter": "10.10.0.0", "ip-only": True},
    )
    assert [o["uid"] for o in net_res.objects] == ["net-24", "net-16"]

    rng_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "address-range", "filter": "10.50.0.10", "ip-only": True},
    )
    assert [o["uid"] for o in rng_res.objects] == ["rng-1", "rng-2"]

    # 3. Port and ICMP substring filtering + pagination + details-level="uid"
    port_page1 = await mock.api_call(
        "mds1",
        "show-objects",
        {"type": "service-tcp", "filter": "80", "limit": 1, "offset": 0, "details-level": "uid"},
        domain="Branch",
    )
    assert port_page1.success
    assert port_page1.data["total"] == 2
    assert port_page1.data["from"] == 1
    assert port_page1.data["to"] == 1
    assert port_page1.data["objects"] == [{"uid": "svc-80"}]

    port_page2 = await mock.api_call(
        "mds1",
        "show-objects",
        {"type": "service-tcp", "filter": "80", "limit": 1, "offset": 1, "details-level": "standard"},
        domain="Branch",
    )
    assert port_page2.success
    assert port_page2.data["objects"][0]["uid"] == "svc-8080"
    assert port_page2.data["objects"][0]["port"] == "8080"
    assert port_page2.data["objects"][0]["protocol"] == "HTTP_PROXY"

    icmp_name_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "service-icmp", "filter": "Echo"},
    )
    assert [o["uid"] for o in icmp_name_res.objects] == ["icmp-echo"]
    assert icmp_name_res.objects[0]["icmp-type"] == 8
    assert icmp_name_res.objects[0]["icmp-code"] == 0

    # Real Check Point `show-objects` `filter` does not match numeric `icmp-type`
    icmp_num_res = await mock.api_query(
        "mds1",
        "show-objects",
        domain="Branch",
        details_level="standard",
        payload={"type": "service-icmp", "filter": "8"},
    )
    assert icmp_num_res.objects == []


@pytest.mark.spec("SCN-ITEST-020-1")
@pytest.mark.asyncio
async def test_unused_objects_single_pass_reference_collection_and_cascade(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `find_unused_objects` and `delete_unused_objects` use single-pass `collect_referenced_uids` with cascading passes."""
    from arodonata.testing import _emulator_lookup as lookup_mod
    from arodonata.testing.replay_mock import FileReplayApiMock

    def _forbid_per_object_scan(*args: Any, **kwargs: Any) -> list[str]:
        raise AssertionError(
            "collect_blocking_references must not be called in find_unused_objects / delete_unused_objects"
        )

    monkeypatch.setattr(lookup_mod, "collect_blocking_references", _forbid_per_object_scan)

    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch", session_name="unused-scan")
    h_leaf = (
        await api.api_call(
            "mds", "add-host", {"name": "H_Cascade_Leaf", "ipv4-address": "10.241.0.1"}, domain="Branch", sid=sid
        )
    ).data["uid"]
    await api.api_call("mds", "add-group", {"name": "G_Cascade_Parent", "members": [h_leaf]}, domain="Branch", sid=sid)

    unused = await api.api_call("mds", "show-unused-objects", {"filter": "Cascade"}, domain="Branch", sid=sid)
    assert unused.success
    unused_names = {o["name"] for o in unused.data["objects"]}
    assert "G_Cascade_Parent" in unused_names
    assert "H_Cascade_Leaf" not in unused_names

    deleted = await api.api_call("mds", "delete-unused-objects", {"filter": "Cascade"}, domain="Branch", sid=sid)
    assert deleted.success
    assert deleted.data["deleted-count"] == 2
    assert not (await api.api_call("mds", "show-host", {"name": "H_Cascade_Leaf"}, domain="Branch", sid=sid)).success


async def test_delete_unused_group_filter_locks_and_gateway_topology_name_refs() -> None:
    """DA-012/DA-016/DA-020: Group filter deletes group+members, enforces locks, detects named GW topology."""
    api = FileReplayApiMock()

    # 1. DA-012: delete-unused-objects with groups filter removes unreferenced group AND its members
    sid1, _ = await api.create_dedicated_session("mds", "Branch", session_name="grp-del")
    h1 = (
        await api.api_call(
            "mds", "add-host", {"name": "H_Grp_Only", "ipv4-address": "10.242.0.1"}, domain="Branch", sid=sid1
        )
    ).data["uid"]
    await api.api_call("mds", "add-group", {"name": "G_Unused_Target", "members": [h1]}, domain="Branch", sid=sid1)
    del_grp = await api.api_call(
        "mds",
        "delete-unused-objects",
        {"groups": ["G_Unused_Target"]},
        domain="Branch",
        sid=sid1,
    )
    assert del_grp.success
    assert del_grp.data["deleted-count"] == 2

    # 2. DA-020: leads-to-specific-network by object name inside show-simple-gateway detail map blocks deletion
    api._domain_data["Branch"].setdefault("show-simple-gateway", {})["gw-detail-1"] = {
        "uid": "gw-detail-1",
        "name": "gw-detail-1",
        "interfaces": [
            {
                "name": "eth1",
                "topology": {"leads-to-specific-network": "N_GW_Detail_Ref"},
            }
        ],
    }
    sid_gw, _ = await api.create_dedicated_session("mds", "Branch", session_name="gw-ref")
    net_res = await api.api_call(
        "mds",
        "add-network",
        {"name": "N_GW_Detail_Ref", "subnet4": "10.243.0.0", "mask-length4": 24},
        domain="Branch",
        sid=sid_gw,
    )
    assert net_res.success
    unused = await api.api_call(
        "mds", "show-unused-objects", {"filter": "N_GW_Detail_Ref"}, domain="Branch", sid=sid_gw
    )
    assert unused.success
    assert not any(o["name"] == "N_GW_Detail_Ref" for o in unused.data["objects"])
    del_blocked = await api.api_call("mds", "delete-network", {"name": "N_GW_Detail_Ref"}, domain="Branch", sid=sid_gw)
    assert not del_blocked.success
    assert del_blocked.error_code == "generic_err_object_cannot_be_deleted"

    # 3. DA-016: delete-unused-objects rejects candidates locked by another open session
    sid_lock, _ = await api.create_dedicated_session("mds", "Branch", session_name="holder")
    h_locked = (
        await api.api_call(
            "mds", "add-host", {"name": "H_Pre_Locked", "ipv4-address": "10.242.0.9"}, domain="Branch", sid=sid_lock
        )
    ).data["uid"]
    await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_lock)
    await api.api_call("mds", "set-host", {"uid": h_locked, "comments": "locked now"}, domain="Branch", sid=sid_lock)

    sid2, _ = await api.create_dedicated_session("mds", "Branch", session_name="deleter")
    lock_err = await api.api_call(
        "mds",
        "delete-unused-objects",
        {"objects": ["H_Pre_Locked"]},
        domain="Branch",
        sid=sid2,
    )
    assert not lock_err.success
    assert lock_err.error_code == "generic_err_object_locked"
