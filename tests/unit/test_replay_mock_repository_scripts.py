"""Unit tests for stateful Script Repository CRUD and permission emulation in FileReplayApiMock."""

from __future__ import annotations

import base64

import pytest

from arodonata import ArodonataClient, ArodonataSettings, RepositoryScriptNotFoundError, RepositoryScriptPermissionError
from arodonata.core.models.scripts import decode_base64_task_message
from arodonata.core.services.route_collector import build_route_collection_repository_script
from arodonata.testing import FileReplayApiMock


@pytest.mark.spec("SCN-TOPO-018-1")
async def test_replay_mock_repository_script_crud_session_isolation_and_snapshot() -> None:
    """Verify per-domain CRUD, WorkSession staging isolation until publish, discard, locks, and snapshots."""
    mock = FileReplayApiMock()

    # Open two dedicated write sessions on Branch and a read-only session on Branch
    s1_login = await mock.api_call("mds", "login", {"domain": "Branch", "user": "admin1"}, domain="Branch")
    s1 = s1_login.data["sid"]
    s2_login = await mock.api_call("mds", "login", {"domain": "Branch", "user": "admin2"}, domain="Branch")
    s2 = s2_login.data["sid"]
    ro_login = await mock.api_call(
        "mds", "login", {"domain": "Branch", "user": "reader", "read-only": True}, domain="Branch"
    )
    ro_sid = ro_login.data["sid"]

    # 1. Add script inside s1 -> visible inside s1, invisible to s2/ro_sid/run-script until publish
    add_res = await mock.api_call(
        "mds",
        "add-repository-script",
        {"name": "diag-check", "script-body": "echo v1\n", "comments": "Initial", "tags": ["ops"]},
        domain="Branch",
        sid=s1,
    )
    assert add_res.success
    script_uid = add_res.data["uid"]

    s1_show = await mock.api_call("mds", "show-repository-script", {"name": "diag-check"}, domain="Branch", sid=s1)
    assert s1_show.success
    assert s1_show.data["script-body"] == "echo v1\n"

    s2_show = await mock.api_call("mds", "show-repository-script", {"name": "diag-check"}, domain="Branch", sid=s2)
    assert not s2_show.success
    assert s2_show.error_code == "generic_err_object_not_found"

    ro_show = await mock.api_call("mds", "show-repository-script", {"name": "diag-check"}, domain="Branch", sid=ro_sid)
    assert not ro_show.success

    pre_pub_run = await mock.api_call(
        "mds",
        "run-script",
        {"script-name": "diag-check", "script-type": "repository", "targets": ["br-spb-gw-01"]},
        domain="Branch",
        sid=s2,
    )
    assert not pre_pub_run.success
    assert pre_pub_run.error_code == "generic_err_object_not_found"

    # 2. Discard s1 wipes uncommitted script
    disc_res = await mock.api_call("mds", "discard", {}, domain="Branch", sid=s1)
    assert disc_res.success
    after_disc = await mock.api_call("mds", "show-repository-script", {"name": "diag-check"}, domain="Branch", sid=s1)
    assert not after_disc.success

    # 3. Re-add and publish -> now visible across Branch sessions & run-script, still isolated from Regional
    add2 = await mock.api_call(
        "mds",
        "add-repository-script",
        {"name": "diag-check", "script-body": "echo v1\n"},
        domain="Branch",
        sid=s1,
    )
    assert add2.success
    script_uid = add2.data["uid"]
    pub_res = await mock.api_call("mds", "publish", {}, domain="Branch", sid=s1)
    assert pub_res.success

    ro_after_pub = await mock.api_call(
        "mds", "show-repository-script", {"uid": script_uid}, domain="Branch", sid=ro_sid
    )
    assert ro_after_pub.success
    assert ro_after_pub.data["name"] == "diag-check"

    regional_list = await mock.api_call("mds", "show-repository-scripts", {}, domain="Regional")
    assert regional_list.success
    assert regional_list.data["total"] == 0

    # Ensure show-objects does not expose repository scripts
    show_objs = await mock.api_call("mds", "show-objects", {"filter": "diag-check"}, domain="Branch", sid=ro_sid)
    assert show_objs.success
    assert show_objs.data["total"] == 0

    # 4. Cross-session lock contention when s1 modifies without publishing and s2 also edits same script
    snap = mock.snapshot_state()
    set_s1 = await mock.api_call(
        "mds",
        "set-repository-script",
        {"name": "diag-check", "script-body": "echo v2\n"},
        domain="Branch",
        sid=s1,
    )
    assert set_s1.success

    set_s2 = await mock.api_call(
        "mds",
        "set-repository-script",
        {"name": "diag-check", "script-body": "echo conflict\n"},
        domain="Branch",
        sid=s2,
    )
    assert not set_s2.success
    assert set_s2.error_code == "generic_err_object_locked"

    # Restore snapshot and verify delete + snapshot toggle restoration
    mock.restore_state(snap)
    del_res = await mock.api_call("mds", "delete-repository-script", {"uid": script_uid}, domain="Branch", sid=s1)
    assert del_res.success
    assert (await mock.api_call("mds", "publish", {}, domain="Branch", sid=s1)).success
    assert (await mock.api_call("mds", "show-repository-scripts", {}, domain="Branch")).data["total"] == 0


@pytest.mark.spec("SCN-CLIENT-012-3", "SCN-TOPO-018-1")
async def test_replay_mock_permissions_readonly_and_positional_args_execution() -> None:
    """Verify read_only session rejection, permission toggles, multi-target run-script, and VSX positional args."""
    mock = FileReplayApiMock()
    settings = ArodonataSettings(
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        api_key="mock-key",
        database_url="sqlite+aiosqlite:///:memory:",
    )

    async with ArodonataClient(settings=settings, api=mock) as client:
        # Provision canonical route script in Branch and DC_Spine (which hosts VSX VS) and custom script in Branch
        route_script = build_route_collection_repository_script()
        await client.ensure_repository_script("mds", "arodonata-collect-routes-v1", route_script, domain="Branch")
        await client.ensure_repository_script("mds", "arodonata-collect-routes-v1", route_script, domain="DC_Spine")
        await client.ensure_repository_script(
            "mds", "custom-health", '#!/bin/bash\necho custom "$@"\n', domain="Branch"
        )

        # 1. Read-only session rejects both one-time and repository run-script
        ro_login = await mock.api_call(
            "mds", "login", {"domain": "Branch", "user": "ro", "read-only": True}, domain="Branch"
        )
        ro_sid = ro_login.data["sid"]
        ro_repo = await mock.api_call(
            "mds",
            "run-script",
            {"script-name": "custom-health", "script-type": "repository", "targets": ["br-spb-gw-01"]},
            domain="Branch",
            sid=ro_sid,
        )
        assert not ro_repo.success
        assert "read only" in (ro_repo.error_message or "").lower()

        # 2. Restrict permissions: allow_one_time_script=False, allow_repository_script=True, manage_repository_scripts="read"
        mock.allow_one_time_script = False
        mock.allow_repository_script = True
        mock.manage_repository_scripts = "read"

        rw_login = await mock.api_call("mds", "login", {"domain": "Branch", "user": "restricted"}, domain="Branch")
        rw_sid = rw_login.data["sid"]

        # Inline one-time denied
        inline_denied = await mock.api_call(
            "mds",
            "run-script",
            {"script-name": "ad-hoc", "script": "ip route show", "targets": ["br-spb-gw-01"]},
            domain="Branch",
            sid=rw_sid,
        )
        assert not inline_denied.success
        assert inline_denied.error_code == "generic_err_no_permissions"

        # Managing repository scripts denied when manage_repository_scripts="read"
        with pytest.raises(RepositoryScriptPermissionError):
            await client.ensure_repository_script("mds", "forbidden-new", "echo x\n", domain="Branch")

        # Reading repository script still allowed
        fetched = await client.get_repository_script("mds", "custom-health", domain="Branch")
        assert fetched.name == "custom-health"

        # When manage_repository_scripts="none", even reading is denied
        mock.manage_repository_scripts = "none"
        with pytest.raises(RepositoryScriptPermissionError):
            await client.get_repository_script("mds", "custom-health", domain="Branch")
        mock.manage_repository_scripts = "read"

        # 3. Repository multi-target execution succeeds without args under restricted permissions
        multi = await client.run_repository_script(
            "mds",
            "custom-health",
            ["br-spb-gw-01", "br-reg-gw-002"],
            domain="Branch",
        )
        assert multi.success is True
        assert len(multi.targets) == 2
        assert "br-spb-gw-01" in multi.targets[0].stdout
        assert "br-reg-gw-002" in multi.targets[1].stdout

        # Under allow_one_time_script=False, passing arguments is rejected by Check Point
        with pytest.raises(RepositoryScriptPermissionError):
            await client.run_repository_script(
                "mds",
                "custom-health",
                ["br-spb-gw-01"],
                domain="Branch",
                args=["--fast", "10"],
            )

        # 4. Route-collection script positional args with allow_one_time_script=True
        mock.allow_one_time_script = True
        res_gw = await mock.api_call(
            "mds",
            "run-script",
            {
                "script-name": "arodonata-collect-routes-v1",
                "script-type": "repository",
                "targets": ["br-spb-gw-01"],
                "args": "50000 0",
            },
            domain="Branch",
            sid=rw_sid,
        )
        assert res_gw.success
        decoded_gw = decode_base64_task_message(res_gw.data["tasks"][0]["task-details"][0]["responseMessage"])
        assert "===ARODONATA_IP_ROUTE_START===" in decoded_gw

        res_vs_name = await mock.api_call(
            "mds",
            "run-script",
            {
                "script-name": "arodonata-collect-routes-v1",
                "script-type": "repository",
                "targets": ["dc-vsx-chassis-01"],
                "args": "50000 0 dc-vs-tier2-app",
            },
            domain="DC_Spine",
            sid=rw_sid,
        )
        assert res_vs_name.success
        decoded_vs = decode_base64_task_message(res_vs_name.data["tasks"][0]["task-details"][0]["responseMessage"])
        assert "===ARODONATA_VSID_RESOLVED=12===" in decoded_vs

        bad_args = await mock.api_call(
            "mds",
            "run-script",
            {
                "script-name": "arodonata-collect-routes-v1",
                "script-type": "repository",
                "targets": ["br-spb-gw-01"],
                "args": "notanumber 0",
            },
            domain="Branch",
            sid=rw_sid,
        )
        assert not bad_args.success
        decoded_err = base64.b64decode(bad_args.data["tasks"][0]["task-details"][0]["responseMessage"]).decode("utf-8")
        assert "_vs_error=" in decoded_err

        # 5. Disable allow_repository_script -> RepositoryScriptPermissionError
        mock.allow_repository_script = False
        with pytest.raises(RepositoryScriptPermissionError):
            await client.run_repository_script("mds", "custom-health", ["br-spb-gw-01"], domain="Branch")

        # 6. Missing script -> RepositoryScriptNotFoundError
        mock.allow_repository_script = True
        with pytest.raises(RepositoryScriptNotFoundError):
            await client.run_repository_script("mds", "does-not-exist", ["br-spb-gw-01"], domain="Branch")


@pytest.mark.spec("SCN-TOPO-018-2")
async def test_replay_mock_r82_parity_base64_and_zero_arg_bundle_and_args_rejection() -> None:
    """Verify SCN-TOPO-018-2: args rejection under allow_one_time_script=False, zero-arg VSX bundle, Base64 script-body."""
    mock = FileReplayApiMock(
        allow_one_time_script=False,
        allow_repository_script=True,
        encode_repository_script_body_base64=True,
    )
    settings = ArodonataSettings(
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        api_key="mock-key",
        database_url="sqlite+aiosqlite:///:memory:",
    )

    async with ArodonataClient(settings=settings, api=mock) as client:
        # Provision canonical route script on DC_Spine (VSX domain)
        route_script = build_route_collection_repository_script()
        ensured = await client.ensure_repository_script(
            "mds",
            "arodonata-collect-routes-v1",
            route_script,
            domain="DC_Spine",
        )
        assert ensured.action == "created"
        assert ensured.published is True

        # 1. show-repository-script returns Base64-encoded script-body, cleanly decoded by check_repository_script
        raw_show = await mock.api_call(
            "mds",
            "show-repository-script",
            {"name": "arodonata-collect-routes-v1"},
            domain="DC_Spine",
        )
        assert raw_show.success is True
        raw_body_b64 = raw_show.data["script-body"]
        assert "\n" not in raw_body_b64
        # Verify it really is a valid base64 string
        decoded_raw = base64.b64decode(raw_body_b64).decode("utf-8")
        assert "===ARODONATA_VSX_BUNDLE_START===" in decoded_raw

        status = await client.check_repository_script(
            "mds",
            "arodonata-collect-routes-v1",
            domain="DC_Spine",
            expected_body=route_script,
        )
        assert status.exists is True
        assert status.matches_expected is True

        # 2. run-script with non-empty args returns HTTP 400 err_validation_failed
        rejected_args = await mock.api_call(
            "mds",
            "run-script",
            {
                "script-name": "arodonata-collect-routes-v1",
                "script-type": "repository",
                "targets": ["dc-vsx-chassis-01"],
                "args": "50000 0",
            },
            domain="DC_Spine",
        )
        assert rejected_args.success is False
        assert rejected_args.status_code == 400
        assert rejected_args.error_code == "err_validation_failed"
        assert "Insufficient permissions to run this script with arguments." in (rejected_args.error_message or "")

        # 3. run-script without args succeeds and emits zero-arg VSX bundle
        zero_arg_run = await mock.api_call(
            "mds",
            "run-script",
            {
                "script-name": "arodonata-collect-routes-v1",
                "script-type": "repository",
                "targets": ["dc-vsx-chassis-01"],
            },
            domain="DC_Spine",
        )
        assert zero_arg_run.success is True
        task_detail = zero_arg_run.data["tasks"][0]["task-details"][0]
        assert task_detail["statusCode"] == "succeeded"
        bundle_out = decode_base64_task_message(task_detail["responseMessage"])
        assert "===ARODONATA_VSX_BUNDLE_START===" in bundle_out
        assert "===ARODONATA_VS_START vsid=1 name=dc-vsx-spine-vs01===" in bundle_out
        assert "===ARODONATA_IP_ROUTE_START===" in bundle_out
        assert "===ARODONATA_VSX_BUNDLE_END===" in bundle_out
