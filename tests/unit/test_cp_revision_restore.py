"""Lab-free tests for the integration suite's revert helpers.

`revert-to-revision` on a real MDS routinely runs for minutes — longer with
100 ms+ regional latency — so every revert must use the generous explicit
timeout, not the client's 120 s default. A client-side timeout there does not
stop the server-side revert; it leaves the server mid-revert, refusing every
login with "Database revision is in progress".

The 2026-09-13 b3 failure happened because the timeout was applied to
`restore_to_baseline` only, while five integration test modules each carried
their own copy-pasted revert. `revert_domain_to` is the single implementation
they all share now, and `test_integration_tests_never_call_revert_directly`
fails the build if a copy comes back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from tests.integration.cp_revision import (
    REVERT_TIMEOUT_SECONDS,
    restore_to_baseline,
    revert_domain_to,
    snapshot_baseline,
)


@dataclass
class _Result:
    success: bool = True
    data: dict[str, Any] | None = None
    message: str = ""
    code: str = ""


@dataclass
class _FakeClient:
    """Records every api_call; answers show-last-published-session with a drifted uid."""

    revert_result: _Result = field(default_factory=_Result)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def api_call(self, mgmt_name: str, command: str, domain: str = "", **kwargs: Any) -> _Result:
        self.calls.append((command, kwargs))
        if command == "show-last-published-session":
            return _Result(data={"uid": "current-uid", "name": "drifted", "publish-time": ""})
        if command == "show-sessions":
            return _Result(data={"objects": []})
        if command == "show-domains":
            return _Result(data={"objects": [{"name": "dom-a"}, {"name": "dom-b"}]})
        if command == "revert-to-revision":
            return self.revert_result
        return _Result()

    @property
    def commands(self) -> list[str]:
        return [c for c, _ in self.calls]


class _RecordingSleep:
    """Stand-in for asyncio.sleep: records each requested pause and returns at once.

    The revert helpers wait for CPM to settle (10 s after a revert, 15 s while
    tasks block one). Real sleeps made each revert test take 10 s; recording
    them keeps the tests instant and still pins the production pauses.
    """

    def __init__(self) -> None:
        self.slept: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.slept.append(seconds)


# ---------------------------------------------------------------------------
# revert_domain_to
# ---------------------------------------------------------------------------


async def test_revert_domain_to_uses_the_generous_timeout():
    client = _FakeClient()

    reverted = await revert_domain_to(client, "mgmt", "Domain4", "target-uid", sleep=_RecordingSleep())

    revert_calls = [kw for cmd, kw in client.calls if cmd == "revert-to-revision"]
    assert reverted is True
    assert len(revert_calls) == 1
    assert revert_calls[0].get("wait_for_task") is True
    assert revert_calls[0].get("timeout") == REVERT_TIMEOUT_SECONDS


async def test_revert_domain_to_discards_open_sessions_before_reverting():
    """An open session holding locks blocks the revert, so discard must come first."""
    client = _FakeClient()

    await revert_domain_to(client, "mgmt", "Domain4", "target-uid", sleep=_RecordingSleep())

    assert client.commands.index("show-sessions") < client.commands.index("revert-to-revision")


async def test_revert_domain_to_returns_false_when_already_at_target_revision():
    """CP aborts a revert to the current revision — the desired state, not a failure."""
    client = _FakeClient(
        revert_result=_Result(
            success=False,
            code="err_validation_failed",
            message="Cannot revert to the current revision",
        )
    )

    assert await revert_domain_to(client, "mgmt", "Domain4", "target-uid", sleep=_RecordingSleep()) is False


async def test_revert_domain_to_raises_naming_domain_and_context_on_real_failure():
    client = _FakeClient(revert_result=_Result(success=False, code="err_boom", message="exploded"))

    with pytest.raises(RuntimeError, match="Domain4.*cycle 3|cycle 3.*Domain4"):
        await revert_domain_to(client, "mgmt", "Domain4", "target-uid", context="cycle 3", sleep=_RecordingSleep())


async def test_a_successful_revert_pauses_ten_seconds_for_cpm_to_settle():
    sleep = _RecordingSleep()

    await revert_domain_to(_FakeClient(), "mgmt", "Domain4", "target-uid", sleep=sleep)

    assert sleep.slept == [10]


async def test_a_revert_blocked_by_running_tasks_waits_fifteen_seconds_and_retries():
    blocked = _Result(success=False, code="err_generic", message="Some tasks are currently running")
    outcomes = iter([blocked, _Result()])

    class _Sequenced(_FakeClient):
        """Answers the first revert with "tasks running", the second with success."""

        async def api_call(self, mgmt_name, command, domain="", **kwargs):
            if command == "revert-to-revision":
                self.calls.append((command, kwargs))
                return next(outcomes)
            return await super().api_call(mgmt_name, command, domain, **kwargs)

    sequenced = _Sequenced()
    sleep = _RecordingSleep()

    assert await revert_domain_to(sequenced, "mgmt", "Domain4", "target-uid", sleep=sleep) is True
    assert sequenced.commands.count("revert-to-revision") == 2
    assert sleep.slept == [15, 10]


async def test_a_successful_revert_of_the_mds_level_logs_it_as_global(caplog):
    """Older baseline files carry the MDS level as ""; the log must not print "[]"."""
    caplog.set_level("INFO", logger="tests.integration.cp_revision")

    await revert_domain_to(_FakeClient(), "mgmt", "", "target-uid", sleep=_RecordingSleep())

    assert any(r.getMessage().startswith("[global] revert successful") for r in caplog.records)


# ---------------------------------------------------------------------------
# restore_to_baseline (shares the helper)
# ---------------------------------------------------------------------------


async def test_restore_to_baseline_reverts_drifted_domain_with_the_same_timeout():
    client = _FakeClient()
    baseline = {"": {"uid": "baseline-uid", "name": "baseline", "publish_time": ""}}
    sleep = _RecordingSleep()

    reverted = await restore_to_baseline(client, "mgmt", baseline, sleep=sleep)

    revert_calls = [kw for cmd, kw in client.calls if cmd == "revert-to-revision"]
    assert reverted == [""]
    assert len(revert_calls) == 1
    assert revert_calls[0].get("timeout") == REVERT_TIMEOUT_SECONDS
    assert sleep.slept == [10]  # the settle pause is passed through, not skipped


def test_revert_timeout_is_at_least_ten_minutes():
    """Guard against someone tuning this back down to a fast-lab value."""
    assert REVERT_TIMEOUT_SECONDS >= 600


# ---------------------------------------------------------------------------
# Regression guard: no copy-pasted reverts
# ---------------------------------------------------------------------------


def test_integration_tests_never_call_revert_directly():
    """Bucket tests must go through revert_domain_to, which carries the timeout.

    A raw api_call("revert-to-revision", ...) inherits the client's 120 s
    default and dies mid-revert on a real MDS. This guard exists because that
    is exactly how the b3 failure on 2026-09-13 happened: the timeout fix
    reached restore_to_baseline but not the five copies in the bucket tests.
    """
    bucket_tests = sorted(Path(__file__).parent.parent.glob("integration/b*/test_*.py"))
    assert bucket_tests, "no bucket tests found — check the glob after a restructure"

    offenders = [
        f"{path.relative_to(Path(__file__).parent.parent.parent)}:{i}"
        for path in bucket_tests
        for i, line in enumerate(path.read_text().splitlines(), start=1)
        if re.search(r'["\']revert-to-revision["\']', line)
    ]

    assert not offenders, (
        "call cp_revision.revert_domain_to() instead of api_call('revert-to-revision', ...) "
        f"— it carries the {REVERT_TIMEOUT_SECONDS}s timeout. Offenders: {offenders}"
    )


# ---------------------------------------------------------------------------
# snapshot_baseline: exactly the domains the mutating tests write to
# ---------------------------------------------------------------------------
#
# Only TEST_DOMAIN_A and TEST_DOMAIN_B are ever mutated, and the teardown
# revert walks the snapshot. Capturing anything else -- every domain on the
# server, or the MDS level -- would let a revert undo changes the suite did not
# make (another project's publish, a standby server the user added mid-run).
# Each domain still gets a progress line: a login can wait out the throttle.


async def _no_sleep(_seconds: float) -> None:
    return None


async def test_snapshot_captures_exactly_the_given_domains():
    client = _FakeClient()

    baseline = await snapshot_baseline(client, "mgmt", ["dom-a", "dom-b"], sleep=_no_sleep)

    assert set(baseline) == {"dom-a", "dom-b"}
    assert "show-domains" not in client.commands  # nothing is discovered: the list is the scope


async def test_snapshot_never_captures_the_mds_level():
    """ "" is the MDS level; reverting it would undo MDS-wide changes (domains, servers, admins)."""
    baseline = await snapshot_baseline(_FakeClient(), "mgmt", ["dom-a"], sleep=_no_sleep)

    assert "" not in baseline


async def test_snapshot_ignores_duplicates_and_blanks():
    """TEST_DOMAIN_A == TEST_DOMAIN_B, or an unset B, must not log in twice or capture ""."""
    client = _FakeClient()

    baseline = await snapshot_baseline(client, "mgmt", ["dom-a", "", "dom-a"], sleep=_no_sleep)

    assert list(baseline) == ["dom-a"]
    assert client.commands.count("show-last-published-session") == 1


async def test_snapshot_logs_count_then_a_line_per_domain_then_the_total(caplog):
    caplog.set_level("INFO", logger="tests.integration.cp_revision")

    await snapshot_baseline(_FakeClient(), "mgmt", ["dom-a", "dom-b"], sleep=_no_sleep)

    messages = [r.getMessage() for r in caplog.records]
    assert re.search(r"2 domains.*2 logins", messages[0]), messages
    assert any(re.search(r"dom-a.*1/2.*took \d+\.\d s", m) for m in messages), messages
    assert any(re.search(r"dom-b.*2/2.*took \d+\.\d s", m) for m in messages), messages
    assert re.search(r"snapshot complete.*\d+\.\d s", messages[-1]), messages


async def test_restore_to_baseline_logs_a_verdict_for_every_checked_domain(caplog):
    """Drifted or not, each domain gets one line: silence is what made restores look hung."""
    caplog.set_level("INFO", logger="tests.integration.cp_revision")
    client = _FakeClient()  # answers every show-last-published-session with "current-uid"
    baseline = {
        "": {"uid": "baseline-uid", "name": "baseline", "publish_time": ""},  # drifted -> revert
        "dom-a": {"uid": "current-uid", "name": "same", "publish_time": ""},  # at baseline
    }

    await restore_to_baseline(client, "mgmt", baseline, sleep=_RecordingSleep())

    messages = [r.getMessage() for r in caplog.records]
    assert any(re.search(r"global.*1/2.*drifted", m) for m in messages), messages
    assert any(re.search(r"dom-a.*2/2.*at baseline", m) for m in messages), messages
