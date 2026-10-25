"""Unit tests for contextvars propagation, SessionOverlay, domain models, and ports."""

from __future__ import annotations

import pytest

from arodonata.core.context import (
    AuthContext,
    WriteSession,
    auth_context,
    get_auth_context,
    get_user_context,
    get_write_session,
    user_context,
    write_session_context,
)
from arodonata.core.errors import REDACTED_PLACEHOLDER, MissingConfigurationError
from arodonata.core.models import (
    Asset,
    CPObject,
    CPService,
    DomainInfo,
    DomainSyncState,
    SIDCacheEntry,
)


def test_auth_and_user_context_propagation_and_secret_hygiene() -> None:
    """Verify AuthContext and UserContext bind to contextvars and never expose secrets in repr."""
    assert get_auth_context() is None
    assert get_user_context() is None

    with pytest.raises(MissingConfigurationError):
        AuthContext(username="admin")

    with (
        auth_context(username="admin", password="super_secret_password", user_id="u-1") as auth,
        user_context(user_id="u-1", username="admin", session_name="chg-101") as uctx,
    ):
        assert get_auth_context() == auth
        assert get_user_context() == uctx
        assert auth.identity_key.startswith("u-1:")
        assert len(auth.identity_key) == len("u-1:") + 24
        # Different password under same user_id produces a distinct HMAC identity_key (C7)
        other_auth = AuthContext(username="admin", password="wrong_password", user_id="u-1")
        assert other_auth.identity_key != auth.identity_key
        assert "super_secret_password" not in repr(auth)
        assert "super_secret_password" not in str(auth)
        assert REDACTED_PLACEHOLDER in repr(auth)

    assert get_auth_context() is None
    assert get_user_context() is None


def test_write_session_and_session_overlay_read_your_own_writes() -> None:
    """Verify WriteSession binds to contextvars and SessionOverlay merges creations/updates/deletions."""
    cached_hosts = [
        CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-h1", "name": "h-existing-1", "type": "host", "ipv4-address": "10.0.0.1"},
        ),
        CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-h2", "name": "h-existing-2", "type": "host", "ipv4-address": "10.0.0.2"},
        ),
    ]
    cached_services = [
        CPService.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-s1", "name": "tcp-8080", "type": "service-tcp", "port": "8080"},
        ),
    ]

    ws = WriteSession(
        mgmt_name="mds1",
        domain_name="CMA1",
        sid="live_write_sid_token",
        server_ip="10.0.0.10",
        session_uid="sess-uid-1",
    )
    assert "live_write_sid_token" not in repr(ws)
    assert "live_write_sid_token" not in str(ws)

    with write_session_context(ws):
        assert get_write_session("mds1", "CMA1") is ws
        assert get_write_session("mds1", "OTHER_DOMAIN") is None

        # 1. Update h-existing-1 IP
        updated_h1 = CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-h1", "name": "h-existing-1", "type": "host", "ipv4-address": "10.0.0.111"},
        )
        ws.overlay.record_object_upsert(updated_h1)

        # 2. Delete h-existing-2 by name
        ws.overlay.record_object_delete(name="h-existing-2", obj_type="host")

        # 3. Create new host h-new-3
        new_h3 = CPObject.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-h3", "name": "h-new-3", "type": "host", "ipv4-address": "10.0.0.3"},
        )
        ws.overlay.record_object_upsert(new_h3)

        # 4. Create new service and delete existing service
        ws.overlay.record_service_delete(uid="uid-s1")
        new_svc = CPService.from_cp_dict(
            "mds1",
            "CMA1",
            {"uid": "uid-s2", "name": "tcp-8443", "type": "service-tcp", "port": "8443"},
        )
        ws.overlay.record_service_upsert(new_svc)

        merged_hosts = ws.overlay.apply_to_objects(cached_hosts, types=["host"])
        assert [h.name for h in merged_hosts] == ["h-existing-1", "h-new-3"]
        assert merged_hosts[0].ipv4_address == "10.0.0.111"

        handled_h1, obj_h1 = ws.overlay.lookup_object_by_uid("uid-h1")
        assert handled_h1 is True and obj_h1 is not None and obj_h1.ipv4_address == "10.0.0.111"

        merged_services = ws.overlay.apply_to_services(cached_services, types=["service-tcp"])
        assert [s.name for s in merged_services] == ["tcp-8443"]

        handled_s1, svc_s1 = ws.overlay.lookup_service_by_uid("uid-s1")
        assert handled_s1 is True and svc_s1 is None

    assert get_write_session("mds1", "CMA1") is None


def test_domain_models_and_sid_cache_entry_hygiene() -> None:
    """Verify DomainInfo, SIDCacheEntry, DomainSyncState, CPObject, CPService, and Asset models."""
    dom = DomainInfo(mgmt_name="mds1", uid="d-1", name="CMA1", active_ip="10.0.0.11", active_mds_ip="10.0.0.1")
    assert dom.id == "mds1:CMA1"

    sid_entry = SIDCacheEntry(
        mgmt_name="mds1",
        domain_name="CMA1",
        sid="super_secret_sid_value",
        server_ip="10.0.0.11",
    )
    assert sid_entry.id == "mds1:CMA1"
    assert "super_secret_sid_value" not in repr(sid_entry)
    assert "super_secret_sid_value" not in str(sid_entry)

    sync = DomainSyncState(mgmt_name="mds1", domain_name="CMA1", scope="objects", item_type="host")
    assert sync.id == "mds1:CMA1:objects:host"

    dns_obj = CPObject.from_cp_dict(
        "mds1",
        "CMA1",
        {
            "uid": "uid-dns1",
            "name": ".example.com",
            "type": "dns-domain",
            "is-sub-domain": True,
            "domain": {"name": "Global", "uid": "g-uid"},
            "tags": [{"name": "prod"}],
        },
    )
    assert dns_obj.id == "mds1:CMA1:uid-dns1"
    assert dns_obj.fqdn == "example.com"
    assert dns_obj.is_sub_domain is True
    assert dns_obj.original_domain == "Global"
    assert dns_obj.tags == ["prod"]

    asset = Asset.from_cp_dict(
        "mds1",
        "CMA1",
        {
            "uid": "gw-1",
            "name": "gw-cluster-1",
            "type": "CpmiGatewayCluster",
            "ipv4-address": "192.0.2.1",
            "version": "R81.20",
            "interfaces": {"objects": [{"name": "eth0", "ipv4-address": "192.0.2.1"}]},
        },
    )
    assert asset.id == "mds1:CMA1:gw-1"
    assert asset.ipv4_address == "192.0.2.1"
    assert len(asset.interfaces) == 1
