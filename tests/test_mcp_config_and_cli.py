"""Unit tests for `ArodonataMCPSettings` and standalone CLI `arodonata-mcp` startup validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import REDACTED_PLACEHOLDER, ConfigurationError, TrustStoreError
from arodonata.mcp import (
    EXIT_CONFIG_ERROR,
    ArodonataMCPSettings,
    main,
    run_cli,
)


def test_mcp_settings_defaults_and_token_redaction() -> None:
    """`ArodonataMCPSettings` parses defaults and redacts `tokens` in `repr()`."""
    settings = ArodonataMCPSettings(
        host="0.0.0.0",
        port=8443,
        path="mcp",
        token_vars="TEAM_A_TOKEN,TEAM_B_TOKEN",
        tokens="super-secret-token-value",
    )
    assert settings.host == "0.0.0.0"
    assert settings.port == 8443
    assert settings.path == "/mcp"
    assert settings.token_vars == ["TEAM_A_TOKEN", "TEAM_B_TOKEN"]
    assert settings.tokens == ["super-secret-token-value"]

    rep = repr(settings)
    assert "super-secret-token-value" not in rep
    assert REDACTED_PLACEHOLDER in rep


def test_mcp_settings_resolve_static_tokens() -> None:
    """`resolve_static_tokens` maps env var names in `ARODONATA_MCP_TOKEN_VARS` to `client_id`."""
    settings = ArodonataMCPSettings(
        token_vars=["TEAM_A_TOKEN", "TEAM_B_TOKEN"],
        tokens=["ops_cli=ops-token-999", "bare-token-123"],
    )
    env = {
        "TEAM_A_TOKEN": "tok-alpha-secret",
        "TEAM_B_TOKEN": "tok-beta-secret",
    }
    pairs = settings.resolve_static_tokens(environ=env)
    assert pairs == [
        ("TEAM_A_TOKEN", "tok-alpha-secret"),
        ("TEAM_B_TOKEN", "tok-beta-secret"),
        ("ops_cli", "ops-token-999"),
        ("static_token_2", "bare-token-123"),
    ]


def test_mcp_settings_missing_token_var_raises() -> None:
    """Referencing an unset or empty variable in `ARODONATA_MCP_TOKEN_VARS` raises `ConfigurationError`."""
    settings = ArodonataMCPSettings(token_vars=["MISSING_TEAM_TOKEN"])
    with pytest.raises(ConfigurationError, match="MISSING_TEAM_TOKEN"):
        settings.resolve_static_tokens(environ={})


@pytest.mark.parametrize("invalid_mode", ["host", "jwt"])
def test_standalone_cli_rejects_host_and_jwt_auth_modes_with_exit_code_2(
    invalid_mode: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Scenario: Standalone startup refuses `ARODONATA_MCP_AUTH_MODE=host` or `jwt` with exit code `2`."""
    code = run_cli(["--auth-mode", invalid_mode], environ={})
    assert code == EXIT_CONFIG_ERROR == 2
    captured = capsys.readouterr()
    assert "configuration error" in captured.err
    assert invalid_mode in captured.err

    # Also verify `main(..., raise_system_exit=True)` raises SystemExit(2)
    with pytest.raises(SystemExit) as exc_info:
        main(["--auth-mode", invalid_mode], environ={}, raise_system_exit=True)
    assert exc_info.value.code == 2


def test_standalone_cli_validates_tls_trust_store_on_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Scenario: Standalone startup validates TLS trust store configuration and exits 2 on corrupted/unconfigured store."""
    corrupted_store = tmp_path / "corrupted_known_hosts.json"
    corrupted_store.write_text("{not-valid-json", encoding="utf-8")

    monkeypatch.setenv("ARODONATA_TLS_TRUST", "tofu")
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(corrupted_store))

    env = {"TEAM_A_TOKEN": "tok-a"}
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "TEAM_A_TOKEN")

    code = run_cli([], environ=env)
    assert code == 2
    err_out = capsys.readouterr().err
    assert "Failed to read TLS trust store" in err_out

    # Pinned mode without any pins or known hosts also fails with exit code 2
    empty_store = tmp_path / "empty_known_hosts.json"
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "pinned")
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(empty_store))
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", "")
    code_pinned = run_cli([], environ=env)
    assert code_pinned == 2
    err_pinned = capsys.readouterr().err
    assert "pinned" in err_pinned

    # Valid pinned fingerprint starts cleanly with injected uvicorn_runner
    valid_fp = "AA:" * 31 + "BB"
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", f"10.0.0.1:443={valid_fp}")
    started: list[tuple[Any, str, int]] = []

    def fake_uvicorn_run(app: Any, *, host: str, port: int) -> None:
        started.append((app, host, port))

    code_ok = main(
        ["--host", "127.0.0.1", "--port", "9100"],
        environ=env,
        uvicorn_runner=fake_uvicorn_run,
    )
    assert code_ok == 0
    assert len(started) == 1
    assert started[0][1] == "127.0.0.1"
    assert started[0][2] == 9100


def test_validate_standalone_startup_method(tmp_path: Path) -> None:
    """`validate_standalone_startup` checks both `auth_mode` and `TrustPolicy` directly."""
    mcp_settings = ArodonataMCPSettings(auth_mode="static", token_vars=["TEAM_A_TOKEN"])
    core_settings = ArodonataSettings(
        tls_trust="pinned",
        tls_known_hosts_path=str(tmp_path / "missing.json"),
        tls_fingerprints="",
    )
    with pytest.raises(TrustStoreError, match="pinned"):
        mcp_settings.validate_standalone_startup(core_settings, environ={"TEAM_A_TOKEN": "sec"})
