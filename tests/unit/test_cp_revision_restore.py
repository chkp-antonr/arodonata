"""Lab-free tests for the integration suite's baseline restore helper.

`revert-to-revision` on a real MDS routinely runs for minutes — longer with
100 ms+ regional latency — so the restore must not inherit the client's
default API timeout. A client-side timeout there leaves the server
mid-revert, refusing every login with "Database revision is in progress".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests.integration.cp_revision import REVERT_TIMEOUT_SECONDS, restore_to_baseline


@dataclass
class _Result:
    success: bool = True
    data: dict[str, Any] | None = None
    message: str = ""
    code: str = ""


@dataclass
class _FakeClient:
    """Records every api_call; answers show-last-published-session with a drifted uid."""

    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def api_call(self, mgmt_name: str, command: str, domain: str = "", **kwargs: Any) -> _Result:
        self.calls.append((command, kwargs))
        if command == "show-last-published-session":
            return _Result(data={"uid": "current-uid", "name": "drifted", "publish-time": ""})
        if command == "show-sessions":
            return _Result(data={"objects": []})
        return _Result()


async def test_revert_uses_a_generous_explicit_timeout():
    client = _FakeClient()
    baseline = {"": {"uid": "baseline-uid", "name": "baseline", "publish_time": ""}}

    reverted = await restore_to_baseline(client, "mgmt", baseline)

    revert_calls = [kw for cmd, kw in client.calls if cmd == "revert-to-revision"]
    assert reverted == [""]
    assert len(revert_calls) == 1
    assert revert_calls[0].get("wait_for_task") is True
    assert revert_calls[0].get("timeout") == REVERT_TIMEOUT_SECONDS


def test_revert_timeout_is_at_least_ten_minutes():
    """Guard against someone tuning this back down to a fast-lab value."""
    assert REVERT_TIMEOUT_SECONDS >= 600
