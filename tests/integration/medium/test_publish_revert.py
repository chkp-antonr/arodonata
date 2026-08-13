"""Medium tier: light create->publish->verify->revert cycles in TEST_DOMAIN_A.

First cp_mutates tests. Each test cleans up after itself (revert to the
pre-test revision), so the session-level baseline safety net stays a backstop.

The main cycle uses the dedicated-session client API directly;
test_write_helpers_work_on_mdm_domain covers the same flow through the
policy helpers (regression for the fixed MDM server-IP bug).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from arodonata.core.change_processor import ChangeProcessor, ChangeType
from arodonata.helpers import add_object, create_session, discard_session
from arodonata.helpers._context import UserContext

from ..cp_revision import discard_open_sessions, last_published_session

pytestmark = pytest.mark.cp_mutates

_CTX = UserContext(username="admin", source="test")


def _unique_host() -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:8]
    return f"arodonata-test-{suffix}", f"10.255.254.{int(suffix[:2], 16) % 254 + 1}"


async def _host_visible_via_api(client, mgmt_name: str, domain: str, name: str) -> bool:
    result = await client.api_call(mgmt_name, "show-host", domain, payload={"name": name})
    return bool(result.success)


async def _revert_domain_to(client, mgmt_name: str, domain: str, target_uid: str) -> None:
    await discard_open_sessions(client, mgmt_name, domain)
    result = await client.api_call(
        mgmt_name,
        "revert-to-revision",
        domain,
        payload={"to-session": target_uid},
        wait_for_task=True,
    )
    assert result.success, f"revert-to-revision failed: {result.message}"


async def test_create_publish_verify_revert_cycle(admin_client, test_domain_a):
    """Full light mutation cycle with smart-fast incremental cache pickup."""
    client, mgmt_name = admin_client
    host_name, host_ip = _unique_host()

    # 0. Capture the pre-test revision — the revert target.
    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"], f"{test_domain_a} must have a published revision to revert to"

    # 1. Baseline the cache so smart-fast has a from-revision to diff against.
    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass

    # 2. Create + publish a uniquely named host via a dedicated session.
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, test_domain_a, session_name="arodonata-medium-publish-cycle"
    )
    published = False
    try:
        add_result = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": host_name, "ip-address": host_ip},
        )
        assert add_result.success, f"add-host failed: {add_result.message}"

        publish_result = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="publish",
            wait_for_task=True,
        )
        assert publish_result.success, f"publish failed: {publish_result.message}"
        published = True
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)

    try:
        # 3. Server truth: the host exists.
        assert await _host_visible_via_api(client, mgmt_name, test_domain_a, host_name)

        # 4a. ChangeProcessor parses the real task-wrapped show-changes shape
        # (tasks[].task-details[].changes[].operations.added-objects[...]):
        # our published host appears in the parsed diff as an ADD.
        post_pub = await last_published_session(client, mgmt_name, test_domain_a)
        sc = await client.api_call(
            mgmt_name,
            "show-changes",
            test_domain_a,
            payload={"from-session": pre["uid"], "to-session": post_pub["uid"]},
        )
        assert sc.success, f"show-changes failed: {sc.message}"
        parsed = ChangeProcessor().parse_changes({"data": sc.data})
        added = [c for c in parsed if c.name == host_name]
        assert added and added[0].change_type == ChangeType.ADD, (
            f"Published host must appear as an ADD in the parsed diff; got {[(c.name, c.change_type) for c in parsed]}"
        )

        # 4b. smart-fast applies the diff incrementally — objects come from
        # the show-changes payload itself, so this is immune to CP's lagging
        # listing index. Staleness compares session uids (not the
        # minute-resolution publish-times), so the fresh publish is detected
        # immediately; a short retry covers server-side propagation only.
        hosts = []
        for _ in range(3):
            hosts = await client.get_hosts(
                name_filter=host_name,
                mgmt_names=[mgmt_name],
                domain_names=[test_domain_a],
                cache_mode="smart-fast",
                cache_ttl=0,
            )
            if hosts:
                break
            await asyncio.sleep(5)
        assert any(h.name == host_name for h in hosts), (
            "smart-fast must apply the published host incrementally near-immediately"
        )
    finally:
        # 5. Revert the domain to the pre-test revision.
        if published:
            await _revert_domain_to(client, mgmt_name, test_domain_a, pre["uid"])

    # 6. Server truth: the host is gone again.
    assert not await _host_visible_via_api(client, mgmt_name, test_domain_a, host_name)

    # 7. And a forced cache rebuild agrees.
    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass
    hosts = await client.get_hosts(
        name_filter=host_name,
        mgmt_names=[mgmt_name],
        domain_names=[test_domain_a],
        cache_mode="cache",
    )
    assert not hosts, "Reverted host must not survive a forced cache rebuild"

    post = await last_published_session(client, mgmt_name, test_domain_a)
    assert post["uid"], "Domain must end the test with a published revision"


async def test_discarded_session_publishes_nothing(admin_client, test_domain_a):
    """create -> add -> discard leaves no trace on the server."""
    client, mgmt_name = admin_client
    host_name, host_ip = _unique_host()

    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, test_domain_a, session_name="arodonata-medium-discard-cycle"
    )
    try:
        add_result = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": host_name, "ip-address": host_ip},
        )
        assert add_result.success, f"add-host failed: {add_result.message}"

        discard_result = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="discard",
        )
        assert discard_result.success, f"discard failed: {discard_result.message}"
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)

    assert not await _host_visible_via_api(client, mgmt_name, test_domain_a, host_name), (
        "A discarded session must not publish its objects"
    )


async def test_write_helpers_work_on_mdm_domain(admin_client, test_domain_a):
    """The policy write helpers operate on an MDM domain session.

    Regression test for the fixed MDM bug: create_session() now tracks the
    domain server IP returned by create_dedicated_session, and
    add_object()/discard_session() send the SID to that server (not the
    registry's MDS IP). Nothing is published — the session is discarded.
    """
    client, mgmt_name = admin_client
    host_name, host_ip = _unique_host()

    session_id = await create_session(client, mgmt_name, test_domain_a, _CTX, description="helper mdm cycle")
    try:
        created = await add_object(
            client,
            mgmt_name,
            test_domain_a,
            "host",
            {"name": host_name, "ip-address": host_ip},
            session_id,
            _CTX,
        )
        assert created.name == host_name
    finally:
        await discard_session(client, mgmt_name, test_domain_a, session_id, _CTX)

    assert not await _host_visible_via_api(client, mgmt_name, test_domain_a, host_name)
