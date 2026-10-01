"""Full tier: a layer longer than one CP page (120 rules, 3 sections) is cached completely.

Mutating (cp_mutates) in TEST_DOMAIN_B (home lab: Domain5): creates an unattached access layer through a dedicated
session, publishes, force-refreshes the domain's rulebases, asserts, then reverts the domain to the revision
recorded before the test.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata.api.schemas import SSEEventType

from ..cp_revision import last_published_session, revert_domain_to

pytestmark = pytest.mark.cp_mutates

SECTIONS = 3
RULES_PER_SECTION = 40


async def _ok(client, mgmt_name, sid, server_ip, command, payload):
    r = await client.api_call_with_sid(
        mgmt_name=mgmt_name, sid=sid, server_ip=server_ip, command=command, payload=payload
    )
    assert r.success, f"{command} failed: {r.code} {r.message}"
    return r


async def test_layer_with_120_rules_cached_completely(apikey_client, test_domain_b):
    if test_domain_b != "Domain5":
        pytest.skip("runs only against the home-lab Domain5")
    client, mgmt_name = apikey_client
    pre = await last_published_session(client, mgmt_name, test_domain_b)
    assert pre["uid"]
    layer = f"arodonata-p1-big-{uuid.uuid4().hex[:8]}"
    try:
        sid, server_ip = await client.create_dedicated_session(mgmt_name, test_domain_b, session_name=f"{layer}-seed")
        try:
            await _ok(client, mgmt_name, sid, server_ip, "add-access-layer", {"name": layer, "add-default-rule": False})
            for s in range(SECTIONS):
                section = f"{layer}-s{s}"
                await _ok(
                    client,
                    mgmt_name,
                    sid,
                    server_ip,
                    "add-access-section",
                    {"layer": layer, "name": section, "position": "bottom"},
                )
                for n in range(RULES_PER_SECTION):
                    await _ok(
                        client,
                        mgmt_name,
                        sid,
                        server_ip,
                        "add-access-rule",
                        {"layer": layer, "name": f"r{s}-{n}", "position": {"bottom": section}, "action": "Accept"},
                    )
            await _ok(client, mgmt_name, sid, server_ip, "publish", {})
        finally:
            await client.logout_sid(sid, server_ip, mgmt_name)

        events = [
            e
            async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[test_domain_b], mode="force")
        ]
        errors = [e.message for e in events if e.event_type == SSEEventType.ERROR]
        assert not errors, errors
        rules = await client.get_access_rules(
            layer_name=layer, mgmt_names=[mgmt_name], domain_names=[test_domain_b], cache_mode="cache"
        )
        assert len(rules) == SECTIONS * RULES_PER_SECTION
        assert [r.rule_number for r in rules] == list(range(1, SECTIONS * RULES_PER_SECTION + 1))
        assert {r.layer_name for r in rules} == {layer}
    finally:
        await revert_domain_to(client, mgmt_name, test_domain_b, pre["uid"], context="p1 large layer")
