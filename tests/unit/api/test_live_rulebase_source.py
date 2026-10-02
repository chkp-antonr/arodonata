from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, call

import pytest
from pydantic import SecretStr

from arodonata.api.schemas import ApiCallResult
from arodonata.api.services.live_rulebase_source import LiveRulebaseSource, SidCaller, SidCallError
from tests.unit.reports.fakes import FakeReportClient, live_responder
from tests.unit.rulebase.fakes import ACCESS, domain4_fake, domain4_snapshot
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize

SID = "SIDSENTINEL-0123456789abcdef"


def caller(client=None):
    client = client or AsyncMock()
    return SidCaller(client, "m1", SecretStr(SID), "192.0.2.1"), client


async def test_sid_caller_forwards_to_api_call_with_sid_without_domain():
    sc, client = caller()
    client.api_call_with_sid.return_value = ApiCallResult(success=True, data={"uid": "u1"})
    result = await sc.api_call(mgmt_name="m1", domain="Domain5", command="show-session", payload={})
    assert result.data == {"uid": "u1"}
    assert client.api_call_with_sid.await_args == call("m1", SID, "192.0.2.1", "show-session", payload={})
    assert SID not in repr(sc)


async def test_sid_caller_payload_has_details_level_limit_offset():
    sc, client = caller()
    client.api_call_with_sid.return_value = ApiCallResult(success=True, data={"packages": [], "total": 0})
    await sc.api_query(
        mgmt_name="m1", domain="Domain5", command="show-packages", details_level="full", container_key="packages"
    )
    assert client.api_call_with_sid.await_args.kwargs["payload"] == {
        "details-level": "full",
        "limit": 500,
        "offset": 0,
    }


@pytest.mark.parametrize(
    "command",
    [
        "publish",
        "discard",
        "logout",
        "set-access-rule",
        "add-host",
        "delete-access-rule",
        "revert-to-revision",
        "show-objects",
    ],
)
async def test_sid_caller_refuses_write_commands(command):
    sc, client = caller()
    with pytest.raises(ValueError, match="not allowed"):
        await sc.api_call(mgmt_name="m1", domain="", command=command, payload={})
    client.api_call_with_sid.assert_not_called()


async def test_sid_caller_api_query_pages_until_total():
    sc, client = caller()
    client.api_call_with_sid.side_effect = [
        ApiCallResult(success=True, data={"packages": [{"uid": "a"}, {"uid": "b"}], "total": 3}),
        ApiCallResult(success=True, data={"packages": [{"uid": "c"}], "total": 3}),
    ]
    result = await sc.api_query(
        mgmt_name="m1", domain="", command="show-packages", details_level="full", container_key="packages"
    )
    assert [o["uid"] for o in result.objects] == ["a", "b", "c"] and result.success
    assert [c.kwargs["payload"]["offset"] for c in client.api_call_with_sid.await_args_list] == [0, 2]
    client.api_call_with_sid.side_effect = [
        ApiCallResult(success=True, data={"packages": [{"uid": "a"}], "total": 2}),
        ApiCallResult(success=False, code="err_x", message=f"page failed for {SID}"),
    ]
    failed = await sc.api_query(
        mgmt_name="m1", domain="", command="show-packages", details_level="full", container_key="packages"
    )
    assert (failed.success, failed.code) == (False, "err_x") and SID[:8] not in failed.message


async def test_sid_caller_scrubs_sid_from_messages_and_exceptions():
    sc, client = caller()
    client.api_call_with_sid.return_value = ApiCallResult(
        success=False, code="generic_err_wrong_session_id", message=f"session {SID} expired; was {SID[:10]}"
    )
    result = await sc.api_call(mgmt_name="m1", domain="", command="show-session", payload={})
    assert SID[:8] not in result.message and result.code == "generic_err_wrong_session_id"
    client.api_call_with_sid.side_effect = RuntimeError(f"transport echoed {SID[:9]}")
    with pytest.raises(SidCallError) as err:
        await sc.api_call(mgmt_name="m1", domain="", command="show-session", payload={})
    assert SID[:8] not in str(err.value) and "RuntimeError" in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__


CLOCK = datetime(2026, 10, 2, 9, 0)


def live(rulebase=None, **kw):
    fake = FakeReportClient()
    fake.sid_responder = live_responder(rulebase or domain4_fake())
    kw.setdefault("packages", None)
    return LiveRulebaseSource(
        fake, "m1", "Domain4", SecretStr(SID), "192.0.2.1", session_uid="u1", clock=lambda: CLOCK, **kw
    ), fake


async def test_live_source_numbers_match_domain4_golden():
    source, _ = live()
    pkg = await source.package_rulebase("m1", "Domain4", "FPCR_UAT_Active", "access")
    assert summarize(pkg.layers[0][1]) == FPCR_UAT_ACTIVE_ACCESS and pkg.status == "live"


async def test_live_source_reports_live_status_and_snapshot_fields():
    source, _ = live(packages={"FPCR_UAT_Active"})
    located = await source.locate_rules("m1", "Domain4", ["x"])
    assert (
        located.status,
        located.snapshot_session_uid,
        located.snapshot_published_at,
        located.snapshot_refreshed_at,
        located.last_error,
    ) == ("live", "u1", None, CLOCK, None)


async def test_live_source_snapshot_datetimes_naive_utc():
    fake = FakeReportClient()
    fake.sid_responder = live_responder(domain4_fake())
    source = LiveRulebaseSource(fake, "m1", "Domain4", SecretStr(SID), "192.0.2.1", session_uid="u1", packages=None)
    refreshed = (await source.locate_rules("m1", "Domain4")).snapshot_refreshed_at
    assert refreshed is not None and refreshed.tzinfo is None
    assert abs(refreshed - datetime.now(UTC).replace(tzinfo=None)) < timedelta(minutes=1)


async def test_live_source_failing_placeholder_fetch_is_degraded():
    rulebase = domain4_fake()
    glb = next(o.layer_uid for o in domain4_snapshot().packages[0].layers if o.layer_domain_type == "global domain")
    rulebase.call_failures[(ACCESS, f"{glb}@FPCR_UAT_Active")] = ApiCallResult(
        success=False, code="err_link", message=f"link failed in session {SID}"
    )
    source, _ = live(rulebase)
    await source.locate_rules("m1", "Domain4")
    assert source.warnings and all(SID[:8] not in w for w in source.warnings)


async def test_live_source_reads_once():
    source, fake = live()
    await source.locate_rules("m1", "Domain4")
    await source.package_rulebase("m1", "Domain4", "FPCR_UAT_Active", "access")
    assert [c for _, c, _ in fake.sid_calls].count("show-packages") == 1


async def test_live_source_rejects_other_domain():
    source, _ = live()
    with pytest.raises(ValueError, match="Domain5"):
        await source.locate_rules("m1", "Domain5")
