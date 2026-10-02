"""Change report for an app-owned Domain5 session: pending numbered live through its SID, provisional without it,
published from the cache within the smart TTL (D16). Reverts Domain5 to its last published session."""

from __future__ import annotations

import uuid

import pytest
from pydantic import SecretStr

from arodonata.reports.changes import OwnedSession, SessionScope, render_change_report

from ..cp_revision import last_published_session, revert_domain_to

pytestmark = pytest.mark.cp_mutates

DOMAIN = "Domain5"
LAYER = "FPCR_UAT_Active Network"  # Task 1 findings: Domain5 baseline layout
PREFIX_NUMBER = ""  # R1 (findings.md): Domain5's FPCR_UAT_Active has no Global layer
INLINE_PARENT = "4"  # R1: FPCR_UAT_Active_InlineJump is 2 at baseline, 4 after the two insertions at the top


def _numbers(report):
    s = report.servers[0].domains[0].sessions[0]
    rules = {r.uid: r for r in s.rules}
    return s, {
        rules[row.rule_uid].name: (row.number, row.basis)
        for b in s.rulebases
        for p in b.packages
        for layer in p.layers
        for row in layer.rows
        if row.kind == "rule"
    }


async def test_change_report_session_live_provisional_published(apikey_client, test_domain_b):
    client, mgmt = apikey_client
    assert test_domain_b == DOMAIN
    pre = await last_published_session(client, mgmt, DOMAIN)
    name = f"pytest-change-report-{uuid.uuid4().hex[:8]}"
    sid = server_ip = ""
    try:
        sid, server_ip = await client.create_dedicated_session(mgmt, DOMAIN, session_name=name)

        async def call(command, payload):
            result = await client.api_call_with_sid(mgmt, sid, server_ip, command, payload=payload)
            assert result.success, f"{command}: {result.code}"
            return result.data or {}

        uid = (await call("show-session", {}))["uid"]
        await call("add-host", {"name": f"{name}-h1", "ip-address": "198.51.100.21"})
        await call("add-group", {"name": f"{name}-g", "members": [f"{name}-h1"]})
        await call(
            "add-access-rule",
            {"layer": LAYER, "position": "top", "name": f"{name}-top", "source": f"{name}-g", "action": "Accept"},
        )
        await call(
            "add-access-rule",
            {
                "layer": LAYER,
                "position": {"below": f"{name}-top"},
                "name": f"{name}-second",
                "source": f"{name}-h1",
                "action": "Accept",
            },
        )
        rulebase = await call("show-access-rulebase", {"name": LAYER, "details-level": "standard", "limit": 500})
        inline = next(
            str(r["inline-layer"])
            for item in rulebase["rulebase"]
            for r in item.get("rulebase", [item])
            if r.get("name") == "FPCR_UAT_Active_InlineJump" and r.get("inline-layer")
        )
        await call(
            "add-access-rule",
            {"layer": inline, "position": "top", "name": f"{name}-inline", "source": f"{name}-h1", "action": "Accept"},
        )
        expected = {
            f"{name}-top": f"{PREFIX_NUMBER}1",
            f"{name}-second": f"{PREFIX_NUMBER}2",
            f"{name}-inline": f"{INLINE_PARENT}.1",
        }
        owned = OwnedSession(sid=SecretStr(sid), server_ip=server_ip)

        live, numbers = _numbers(
            await client.collect_change_report([SessionScope(domain=DOMAIN, session_uids=[uid], owned_session=owned)])
        )
        assert live.numbering.source == "live" and {k: v[0] for k, v in numbers.items()} == expected

        provisional, numbers = _numbers(
            await client.collect_change_report([SessionScope(domain=DOMAIN, session_uids=[uid])])
        )
        assert provisional.numbering.provisional is True
        # D27: the layer has sections, so a provisional position is not turned into a number
        assert numbers[f"{name}-top"] == (None, "provisional")

        for rule, layer in ((f"{name}-top", LAYER), (f"{name}-second", LAYER), (f"{name}-inline", inline)):
            await call("set-access-rule", {"layer": layer, "name": rule, "enabled": False})
        await call("publish", {})  # through the SID: the smart memo is not cleared by the client

        report = await client.collect_change_report([SessionScope(domain=DOMAIN, session_uids=[uid])])
        published, numbers = _numbers(report)
        assert published.numbering.source == "cache" and published.numbering.snapshot_session_uid == uid
        assert not [w for w in report.warnings if w.code == "numbering_failed"]
        assert {k: v[0] for k, v in numbers.items()} == expected
        assert all(r.status == "added" and not r.enabled for r in published.rules)
        assert b"disabled-mark" in (render_change_report(report, ["html"]).html or b"")
    finally:
        if sid:
            await client.logout_sid(sid, server_ip, mgmt)
        await revert_domain_to(client, mgmt, DOMAIN, pre["uid"], context="b5 change report")
