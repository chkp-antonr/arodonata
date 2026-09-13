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
        if command == "revert-to-revision":
            return self.revert_result
        return _Result()

    @property
    def commands(self) -> list[str]:
        return [c for c, _ in self.calls]


# ---------------------------------------------------------------------------
# revert_domain_to
# ---------------------------------------------------------------------------


async def test_revert_domain_to_uses_the_generous_timeout():
    client = _FakeClient()

    reverted = await revert_domain_to(client, "mgmt", "Domain4", "target-uid")

    revert_calls = [kw for cmd, kw in client.calls if cmd == "revert-to-revision"]
    assert reverted is True
    assert len(revert_calls) == 1
    assert revert_calls[0].get("wait_for_task") is True
    assert revert_calls[0].get("timeout") == REVERT_TIMEOUT_SECONDS


async def test_revert_domain_to_discards_open_sessions_before_reverting():
    """An open session holding locks blocks the revert, so discard must come first."""
    client = _FakeClient()

    await revert_domain_to(client, "mgmt", "Domain4", "target-uid")

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

    assert await revert_domain_to(client, "mgmt", "Domain4", "target-uid") is False


async def test_revert_domain_to_raises_naming_domain_and_context_on_real_failure():
    client = _FakeClient(revert_result=_Result(success=False, code="err_boom", message="exploded"))

    with pytest.raises(RuntimeError, match="Domain4.*cycle 3|cycle 3.*Domain4"):
        await revert_domain_to(client, "mgmt", "Domain4", "target-uid", context="cycle 3")


# ---------------------------------------------------------------------------
# restore_to_baseline (shares the helper)
# ---------------------------------------------------------------------------


async def test_restore_to_baseline_reverts_drifted_domain_with_the_same_timeout():
    client = _FakeClient()
    baseline = {"": {"uid": "baseline-uid", "name": "baseline", "publish_time": ""}}

    reverted = await restore_to_baseline(client, "mgmt", baseline)

    revert_calls = [kw for cmd, kw in client.calls if cmd == "revert-to-revision"]
    assert reverted == [""]
    assert len(revert_calls) == 1
    assert revert_calls[0].get("timeout") == REVERT_TIMEOUT_SECONDS


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
