"""Unit tests for the live integration test harness utilities (lab_env, run_lock, lab_ready, cp_revision)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from arodonata.core.models.common import ApiCallResult
from tests.integration.cp_revision import (
    REVERT_TIMEOUT_SECONDS,
    DomainBaseline,
    discard_open_sessions,
    revert_domain_to,
    snapshot_baseline,
    write_baseline_file,
)
from tests.integration.lab_env import (
    LabProfileMissing,
    allowed_test_domains,
    is_test_domain,
    load_lab_env,
)
from tests.integration.lab_ready import (
    LabNotReady,
    answered_by_api,
    wait_until_ready,
)
from tests.integration.run_lock import IntegrationRunLock, IntegrationRunLocked


class TestLabEnv:
    """Tests for ``tests.integration.lab_env``."""

    def test_load_lab_env_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ARODONATA_LAB", raising=False)
        monkeypatch.delenv("API_MGMT", raising=False)
        monkeypatch.delenv("APIKEY", raising=False)
        monkeypatch.delenv("CPMDSH5_API_KEY", raising=False)
        monkeypatch.delenv("TEST_DOMAIN_A", raising=False)

        (tmp_path / ".env.test").write_text(
            "API_MGMT=10.0.0.1\nTEST_DOMAIN_A=DomA\nARODONATA_LAB=home\n",
            encoding="utf-8",
        )
        (tmp_path / ".env.secrets").write_text(
            "CPMDSH5_API_KEY=secret-home-key\nAPIKEY=default-key\n",
            encoding="utf-8",
        )
        (tmp_path / ".env.lab.home").write_text(
            "API_MGMT=192.168.5.140\nAPIKEY=${CPMDSH5_API_KEY}\n",
            encoding="utf-8",
        )

        active = load_lab_env(repo_root=tmp_path)
        assert active == "home"
        assert os.environ["API_MGMT"] == "192.168.5.140"
        assert os.environ["APIKEY"] == "secret-home-key"
        assert os.environ["TEST_DOMAIN_A"] == "DomA"

    def test_load_lab_env_missing_profile_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARODONATA_LAB", "nonexistent")
        (tmp_path / ".env.test").write_text("API_MGMT=10.0.0.1\n", encoding="utf-8")

        with pytest.raises(LabProfileMissing, match="nonexistent"):
            load_lab_env(repo_root=tmp_path)

    def test_allowed_and_is_test_domain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ARODONATA_TEST_DOMAINS", raising=False)
        assert allowed_test_domains() is None
        assert is_test_domain("Domain4") is True
        assert is_test_domain("Global") is False

        monkeypatch.setenv("ARODONATA_TEST_DOMAINS", "General, Domain4, Domain5")
        assert allowed_test_domains() == {"General", "Domain4", "Domain5"}
        assert is_test_domain("Domain4") is True
        assert is_test_domain("T-Other") is False
        assert is_test_domain("Global") is False


class TestRunLock:
    """Tests for ``tests.integration.run_lock``."""

    def test_run_lock_contention(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "integration.lock"
        lock1 = IntegrationRunLock(lock_file)
        lock2 = IntegrationRunLock(lock_file)

        lock1.acquire()
        try:
            with pytest.raises(IntegrationRunLocked, match="Another integration run holds"):
                lock2.acquire()
        finally:
            lock1.release()

        # After release, second lock can acquire cleanly
        lock2.acquire()
        lock2.release()


class TestLabReady:
    """Tests for ``tests.integration.lab_ready``."""

    def test_answered_by_api(self) -> None:
        assert answered_by_api(None) is False
        assert answered_by_api({}) is False
        assert answered_by_api({"raw_text": "<html>503</html>", "code": "http_503"}) is False
        assert answered_by_api({"current-version": "2.0"}) is True
        assert answered_by_api({"code": "generic_err_missing_required_header", "message": "Missing header"}) is True

    async def test_wait_until_ready_succeeds_after_retries(self) -> None:
        responses: list[dict[str, Any] | None] = [
            None,
            {"raw_text": "503"},
            {"code": "generic_err_unauthorized"},
        ]
        clock = [0.0]

        async def fake_probe(_ip: str) -> dict[str, Any] | None:
            return responses.pop(0)

        async def fake_sleep(dt: float) -> None:
            clock[0] += dt

        elapsed = await wait_until_ready(
            "192.0.2.1",
            timeout=30.0,
            interval=5.0,
            probe=fake_probe,
            monotonic=lambda: clock[0],
            sleep=fake_sleep,
        )
        assert elapsed == 10.0

    async def test_wait_until_ready_timeout_raises(self) -> None:
        clock = [0.0]

        async def fake_probe(_ip: str) -> dict[str, Any] | None:
            return None

        async def fake_sleep(dt: float) -> None:
            clock[0] += dt

        with pytest.raises(LabNotReady, match="not ready after 10s"):
            await wait_until_ready(
                "192.0.2.1",
                timeout=10.0,
                interval=5.0,
                probe=fake_probe,
                monotonic=lambda: clock[0],
                sleep=fake_sleep,
            )


class TestCpRevision:
    """Tests for ``tests.integration.cp_revision``."""

    async def test_snapshot_and_write_baseline(self, tmp_path: Path) -> None:
        client = AsyncMock()
        client.api_call.return_value = ApiCallResult(
            success=True,
            data={
                "objects": [
                    {
                        "uid": "sess-uid-123",
                        "name": "baseline-sess",
                        "publish-time": {"iso-8601": "2026-10-24T12:00:00Z"},
                    }
                ]
            },
        )
        snap = await snapshot_baseline(client, "mgmt1", "10.0.0.1", ["Domain4"])
        assert "Domain4" in snap.domains
        assert snap.domains["Domain4"].session_uid == "sess-uid-123"

        out_file = tmp_path / "cp_baseline.json"
        write_baseline_file(snap, out_file)
        assert out_file.exists()

    async def test_discard_open_sessions_only_dirty(self) -> None:
        client = AsyncMock()
        client.create_dedicated_session.return_value = ("ded-sid-1", "10.0.0.1")
        client.logout_sid.return_value = True
        client.api_call.side_effect = [
            ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {"uid": "clean-sess", "changes": 0, "locks": 0},
                        {"uid": "dirty-sess", "changes": 2, "locks": 1},
                    ]
                },
            ),
            ApiCallResult(success=True, data={}),
        ]
        count = await discard_open_sessions(client, "mgmt1", "Domain4")
        assert count == 1
        assert client.api_call.call_count == 2
        client.create_dedicated_session.assert_awaited_once()
        client.logout_sid.assert_awaited_once_with("mgmt1", "ded-sid-1", server_ip="10.0.0.1")

    async def test_revert_domain_to_noop_when_unchanged(self) -> None:
        client = AsyncMock()
        client.api_call.side_effect = [
            # show-sessions (open)
            ApiCallResult(success=True, data={"objects": []}),
            # show-sessions (published) -> matches baseline
            ApiCallResult(
                success=True,
                data={"objects": [{"uid": "sess-uid-123", "name": "base"}]},
            ),
        ]
        base = DomainBaseline(domain="Domain4", session_uid="sess-uid-123")
        reverted = await revert_domain_to(client, "mgmt1", base, force=False)
        assert reverted is False

    async def test_revert_domain_to_retries_on_lock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import MagicMock

        import tests.integration.cp_revision as cp_rev

        monkeypatch.setattr(cp_rev, "REVERT_LOCK_BACKOFF_SECONDS", 0.01)
        client = AsyncMock()
        client.invalidate_domain = MagicMock()
        client.create_dedicated_session.side_effect = [
            ("rev-sid-1", "10.0.0.1"),
            ("rev-sid-2", "10.0.0.1"),
        ]
        client.logout_sid.return_value = True
        client.api_call.side_effect = [
            # 1. discard_open_sessions -> show-sessions (open)
            ApiCallResult(success=True, data={"objects": []}),
            # 2. last_published_session -> show-sessions (published) -> head changed
            ApiCallResult(success=True, data={"objects": [{"uid": "new-head-456"}]}),
            # 3. revert-to-revision attempt 1 -> fails with lock
            ApiCallResult(
                success=False,
                status_code=400,
                error_code="generic_err_object_locked",
                error_message="Database is locked by another session",
                data={},
            ),
            # 4. discard_open_sessions inside retry -> show-sessions (open)
            ApiCallResult(success=True, data={"objects": []}),
            # 5. revert-to-revision attempt 2 -> succeeds
            ApiCallResult(success=True, data={"task-id": "task-1"}),
        ]
        base = DomainBaseline(domain="Domain4", session_uid="sess-uid-123")
        reverted = await revert_domain_to(client, "mgmt1", base, force=False)
        assert reverted is True
        assert client.api_call.call_count == 5
        assert client.create_dedicated_session.await_count == 2
        assert client.logout_sid.await_count == 2
        client.invalidate_domain.assert_called_once_with("mgmt1", "Domain4")
        assert REVERT_TIMEOUT_SECONDS == 900.0


def test_pytest_sh_and_conftest_spec_alignment() -> None:
    """Verify `pytest.sh`, `tests/integration/conftest.py`, and `examples/12_mcp_embedded.py`
    align with the `integration-testing-and-examples` specification (`W29`, `W30`, `I18`).
    """
    repo_root = Path(__file__).resolve().parents[2]
    pytest_sh = (repo_root / "pytest.sh").read_text(encoding="utf-8")
    assert "ARODONATA_TEST_BUCKET_PAUSE:-90" in pytest_sh
    assert "-o log_cli=true --log-cli-level=INFO" in pytest_sh

    conftest_src = (repo_root / "tests" / "integration" / "conftest.py").read_text(encoding="utf-8")
    assert "EXIT_LOCK_CONTENTION = 3" in conftest_src
    assert "EXIT_LAB_NOT_READY = 4" in conftest_src
    assert "EXIT_BASELINE_FAILURE = 5" in conftest_src
    assert "ARODONATA_TEST_READY_WAIT" in conftest_src
    assert "baseline-" in conftest_src

    ex12_src = (repo_root / "examples" / "12_mcp_embedded.py").read_text(encoding="utf-8")
    assert "host_authentication_middleware" in ex12_src
    assert "Authorization" in ex12_src
