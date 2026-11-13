"""Unit tests for Check Point `show-objects` support in `FileReplayApiMock`."""

from __future__ import annotations

import pytest

from arodonata.testing.replay_mock import FileReplayApiMock


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
