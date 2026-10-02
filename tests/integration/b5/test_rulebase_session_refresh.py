"""Full tier: refresh_rulebases(mode='check') follows publishes (rulebase cache v2, phase 2).

Mutating (cp_mutates) in TEST_DOMAIN_A (home lab: Domain4): adds a rule to FPCR_UAT_Active Network through a dedicated
session and publishes, checks, deletes it and publishes, checks, then reverts Domain4 to the Global-assignment revision.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata.api.schemas import SSEEventType
from arodonata.rulebase.numbering import number_package

from ..cp_revision import last_published_session, revert_domain_to

pytestmark = pytest.mark.cp_mutates

DOMAIN4_REVERT_POINT = "3250a85f-9765-44ac-8355-432be83da916"
LAYER = "FPCR_UAT_Active Network"


async def _ok(client, mgmt_name, sid, server_ip, command, payload):
    r = await client.api_call_with_sid(
        mgmt_name=mgmt_name, sid=sid, server_ip=server_ip, command=command, payload=payload
    )
    assert r.success, f"{command} failed: {r.code} {r.message}"
    return r


async def _publish(client, mgmt_name, domain, name, command, payload):
    sid, server_ip = await client.create_dedicated_session(mgmt_name, domain, session_name=name)
    try:
        await _ok(client, mgmt_name, sid, server_ip, command, payload)
        await _ok(client, mgmt_name, sid, server_ip, "publish", {})
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)


async def _check(client, mgmt_name, domain):
    events = [e async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[domain], mode="check")]
    assert not [e.message for e in events if e.event_type == SSEEventType.ERROR]
    return {(e.data or {}).get("status") for e in events}


async def _numbers_by_name(client, mgmt_name, domain):
    snapshot = await client.cache.load_domain_rulebase_snapshot(mgmt_name, domain)
    layout = next(p for p in snapshot.packages if p.package_name == "FPCR_UAT_Active")
    entries = number_package(layout, "access", {layer.layer_uid: layer for layer in snapshot.layers})[0]
    return {e.name: e.number for e in entries if e.kind == "rule"}


async def test_check_mode_follows_publishes(apikey_client, test_domain_a):
    if test_domain_a != "Domain4":
        pytest.skip("runs only against the home-lab Domain4")
    client, mgmt_name = apikey_client
    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"] == DOMAIN4_REVERT_POINT, (
        f"Domain4 is at {pre['uid']}, not the recorded revert point; restore it first"
    )
    rule = f"arodonata-p2-{uuid.uuid4().hex[:8]}"
    try:
        baseline = [
            e
            async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force")
        ]
        assert not [e.message for e in baseline if e.event_type == SSEEventType.ERROR]
        assert "domain_fresh" in await _check(client, mgmt_name, test_domain_a)
        await _publish(
            client,
            mgmt_name,
            test_domain_a,
            f"{rule}-add",
            "add-access-rule",
            {"layer": LAYER, "name": rule, "position": "top", "action": "Accept"},
        )
        assert "domain_refreshed" in await _check(client, mgmt_name, test_domain_a)
        state = await client.cache.get_rulebase_sync_state(mgmt_name, test_domain_a)
        assert state.session_uid != pre["uid"]
        numbers = await _numbers_by_name(client, mgmt_name, test_domain_a)
        assert numbers[rule] == "2.1" and numbers["fpcr_uat_FPCR_UAT_Active_4"] == "2.2"
        assert "domain_fresh" in await _check(client, mgmt_name, test_domain_a)
        await _publish(
            client,
            mgmt_name,
            test_domain_a,
            f"{rule}-del",
            "delete-access-rule",
            {"layer": LAYER, "name": rule},
        )
        assert "domain_refreshed" in await _check(client, mgmt_name, test_domain_a)
        assert rule not in await _numbers_by_name(client, mgmt_name, test_domain_a)
    finally:
        await revert_domain_to(client, mgmt_name, test_domain_a, DOMAIN4_REVERT_POINT, context="p2 session refresh")
        after = await last_published_session(client, mgmt_name, test_domain_a)
        assert after["uid"] == DOMAIN4_REVERT_POINT
