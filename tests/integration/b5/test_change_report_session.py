"""Bucket 5 — Live session change report (`OwnedSession` live numbering vs cached numbering).

Mutating (`cp_mutates`) in ``TEST_DOMAIN_B``:
1. Opens a dedicated session, adds a host, group, and access rule.
2. Collects a ``ChangeReport`` with ``OwnedSession(sid=..., server_ip=...)`` while the session is
   still unpublished, verifying ``numbering_source == "owned_session"`` and live rule numbering.
3. Publishes the session, refreshes the rulebase cache, and collects a ``ChangeReport`` without
   ``OwnedSession``, verifying ``numbering_source == "cache"`` and HTML/Markdown/JSON rendering.
4. Reverts ``TEST_DOMAIN_B`` to its baseline revision.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient
from arodonata.reports import OwnedSession, SessionScope
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates


async def test_change_report_session_live_and_published(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_b: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify ``collect_change_report`` with ``OwnedSession`` before publish and from cache after publish."""
    await apikey_client.refresh_rulebases(
        mgmt_name=mgmt_name,
        domains=[test_domain_b],
        mode="force",
    )
    packages = await apikey_client.get_policy_packages(mgmt_name, test_domain_b, cache_mode="cache")
    assert packages, f"Expected policy package in {test_domain_b}"
    pkg = packages[0]
    assert pkg.access_layers, f"Expected access layer in {pkg.name}"
    layer_name = next(
        (
            lyr.layer_name
            for lyr in pkg.access_layers
            if lyr.layer_name != "Global" and not lyr.layer_name.startswith("Global")
        ),
        pkg.access_layers[-1].layer_name,
    )

    tag = uuid.uuid4().hex[:6]
    sess_name = f"it-b5-chg-{tag}"
    sess2_name = f"it-b5-mod-{tag}"
    host_name = f"{sess_name}-h1"
    host2_name = f"{sess_name}-h2"
    grp_name = f"{sess_name}-g1"
    rule_name = f"{sess_name}-r1"

    sid = ""
    server_ip = ""
    try:
        sid, server_ip = await apikey_client.create_dedicated_session(
            mgmt_name,
            test_domain_b,
            session_name=sess_name,
        )
        s_info = await apikey_client.api_call(
            mgmt_name,
            "show-session",
            {},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
        )
        assert s_info.success
        session_uid = str(s_info.data["uid"])

        assert (
            await apikey_client.api_call(
                mgmt_name,
                "add-host",
                {"name": host_name, "ipv4-address": "198.51.100.231"},
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success
        assert (
            await apikey_client.api_call(
                mgmt_name,
                "add-host",
                {"name": host2_name, "ipv4-address": "198.51.100.232"},
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success
        assert (
            await apikey_client.api_call(
                mgmt_name,
                "add-group",
                {"name": grp_name, "members": [host_name, host2_name]},
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success
        assert (
            await apikey_client.api_call(
                mgmt_name,
                "add-access-rule",
                {
                    "layer": layer_name,
                    "position": "top",
                    "name": rule_name,
                    "source": grp_name,
                    "destination": [host_name, host2_name],
                    "action": "Accept",
                },
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success
        assert (
            await apikey_client.api_call(
                mgmt_name,
                "set-access-rule",
                {
                    "layer": layer_name,
                    "name": rule_name,
                    "enabled": False,
                },
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success

        # 1. Collect while unpublished using OwnedSession
        owned = OwnedSession(
            sid=sid,
            server_ip=server_ip,
            session_uid=session_uid,
            mgmt_name=mgmt_name,
            domain=test_domain_b,
        )
        assert sid not in repr(owned)

        live_report = await apikey_client.collect_change_report(
            [
                SessionScope(
                    mgmt_name=mgmt_name,
                    domain=test_domain_b,
                    session_uids=[session_uid],
                    owned_sessions=owned,
                )
            ]
        )
        assert len(live_report.sessions) == 1
        live_sess = live_report.sessions[0]
        assert live_sess.numbering_source == "owned_session"
        assert any(rc.name == rule_name and rc.rule_number is not None for rc in live_sess.rule_changes)

        # 2. Publish the session and refresh rulebase cache
        pub_res = await apikey_client.api_call(
            mgmt_name,
            "publish",
            {},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
            wait_for_task=True,
        )
        assert pub_res.success
        await apikey_client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        sid = ""

        await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            mode="force",
        )

        # 3. Collect published session report using cached rulebase snapshot
        bundle = await apikey_client.build_change_report(
            [
                SessionScope(
                    mgmt_name=mgmt_name,
                    domain=test_domain_b,
                    session_uids=[session_uid],
                )
            ],
            formats=("html", "markdown", "json"),
        )
        pub_sess = bundle.report.sessions[0]
        assert pub_sess.numbering_source == "cache"
        assert any(rc.name == rule_name and not rc.enabled for rc in pub_sess.rule_changes)
        assert bundle.html is not None and rule_name.encode() in bundle.html
        assert bundle.markdown is not None and rule_name in bundle.markdown

        # 4. Open a second session to modify rule cell and group membership and verify snapshot diffs + inline rendering
        sid, server_ip = await apikey_client.create_dedicated_session(
            mgmt_name,
            test_domain_b,
            session_name=sess2_name,
        )
        s2_info = await apikey_client.api_call(
            mgmt_name,
            "show-session",
            {},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
        )
        assert s2_info.success
        session2_uid = str(s2_info.data["uid"])

        assert (
            await apikey_client.api_call(
                mgmt_name,
                "set-group",
                {"name": grp_name, "members": {"remove": host_name}, "comments": f"[DECOMM: {host_name}]"},
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success
        assert (
            await apikey_client.api_call(
                mgmt_name,
                "set-access-rule",
                {
                    "layer": layer_name,
                    "name": rule_name,
                    "destination": [host2_name],
                    "enabled": True,
                    "comments": f"[DECOMM: {host_name}]",
                    "ignore-warnings": True,
                },
                domain=test_domain_b,
                sid=sid,
                server_ip=server_ip,
            )
        ).success

        pub2_res = await apikey_client.api_call(
            mgmt_name,
            "publish",
            {},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
            wait_for_task=True,
        )
        assert pub2_res.success
        await apikey_client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        sid = ""

        mod_bundle = await apikey_client.build_change_report(
            [
                SessionScope(
                    mgmt_name=mgmt_name,
                    domain=test_domain_b,
                    session_uids=[session2_uid],
                )
            ],
            formats=("html", "markdown", "json"),
        )
        mod_sess = mod_bundle.report.sessions[0]
        mod_rule = next(rc for rc in mod_sess.rule_changes if rc.name == rule_name)
        rule_diffs_by_field = {d.field_name: d for d in mod_rule.field_diffs}
        assert "destination" in rule_diffs_by_field
        assert host_name in rule_diffs_by_field["destination"].removed_items
        assert "enabled" in rule_diffs_by_field
        assert rule_diffs_by_field["enabled"].old_value is False
        assert rule_diffs_by_field["enabled"].new_value is True

        mod_grp = next(oc for oc in mod_sess.object_changes if oc.name == grp_name)
        grp_diffs_by_field = {d.field_name: d for d in mod_grp.field_diffs}
        assert "members" in grp_diffs_by_field
        assert host_name in grp_diffs_by_field["members"].removed_items

        assert mod_bundle.html is not None
        assert mod_bundle.markdown is not None
        assert f"- {host_name}".encode() in mod_bundle.html
        assert b"diff-removed" in mod_bundle.html
        assert f"[-{host_name}]" in mod_bundle.markdown
    finally:
        if sid:
            await apikey_client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        base_b = cp_baseline_snapshot.domains[test_domain_b]
        await revert_domain_to(apikey_client, mgmt_name, base_b)
        await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            mode="force",
        )
