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
    is_loopback_host,
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


@pytest.mark.spec("SCN-MCP-001-2")
def test_mcp_settings_resolve_static_tokens() -> None:
    """`resolve_static_tokens` maps env var names in `ARODONATA_MCP_TOKEN_VARS` to `client_id`
    and preserves base64 tokens with `=` padding under generated non-secret `token_<idx>` IDs (`C3`, `W26`).
    """
    b64_token = "c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy=="
    settings = ArodonataMCPSettings(
        token_vars=["TEAM_A_TOKEN", "TEAM_B_TOKEN"],
        tokens=[
            "ops_cli=ops-token-999-0123456789abcdefghijk",
            b64_token,
            f"team_c={b64_token}",
        ],
    )
    env = {
        "TEAM_A_TOKEN": "tok-alpha-secret-0123456789abcdefgh",
        "TEAM_B_TOKEN": "tok-beta-secret-0123456789abcdefghi",
    }
    pairs = settings.resolve_static_tokens(environ=env)
    assert pairs == [
        ("TEAM_A_TOKEN", "tok-alpha-secret-0123456789abcdefgh"),
        ("TEAM_B_TOKEN", "tok-beta-secret-0123456789abcdefghi"),
        ("ops_cli", "ops-token-999-0123456789abcdefghijk"),
        ("token_2", b64_token),
        ("team_c", b64_token),
    ]

    # Tokens shorter than 32 chars raise ConfigurationError
    short_settings = ArodonataMCPSettings(tokens=["short-token"])
    with pytest.raises(ConfigurationError, match="minimum length is 32"):
        short_settings.resolve_static_tokens(environ={})


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

    env = {"TEAM_A_TOKEN": "tok-a-0123456789abcdefghijklmnopqrstuv"}
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
        mcp_settings.validate_standalone_startup(
            core_settings,
            environ={"TEAM_A_TOKEN": "sec-0123456789abcdefghijklmnopqrstuv"},
        )


@pytest.mark.spec("SCN-MCP-001-6")
def test_unified_security_policy_cli_and_settings_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SCN-MCP-001-6: Fail-closed `validate_security_policy()` across CLI and `ArodonataMCPSettings`."""
    # Loopback detection handles IPv4, localhost, and bracketed/canonical IPv6 loopback strictly
    for valid_lb in ("127.0.0.1", "localhost", "::1", "[::1]", "0:0:0:0:0:0:0:1"):
        assert is_loopback_host(valid_lb) is True
    for non_lb in ("0.0.0.0", "::", "10.0.0.1", "127.0.0.2", "0.0.0.0:8000", ""):
        assert is_loopback_host(non_lb) is False

    # Setup valid TLS trust store so CLI checks security policy cleanly
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "pinned")
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(tmp_path / "kh.json"))
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", f"10.0.0.1:443={'AA:' * 31 + 'BB'}")

    # 1. Safe loopback read-only auth_mode="none" succeeds
    started_hosts: list[str] = []
    for lb in ("127.0.0.1", "localhost", "::1"):
        rc_ok = run_cli(
            ["--auth-mode", "none", "--host", lb],
            uvicorn_runner=lambda _app, *, host, port: started_hosts.append(host),
        )
        assert rc_ok == 0
    assert started_hosts == ["127.0.0.1", "localhost", "::1"]

    # 2. Unsafe auth_mode="none" combinations fail with EXIT_CONFIG_ERROR (2)
    for cli_args in (
        ["--auth-mode", "none", "--host", "0.0.0.0"],
        ["--auth-mode", "none", "--host", "::"],
        ["--auth-mode", "none", "--allow-write-api"],
        ["--auth-mode", "none", "--cpcrud"],
    ):
        rc_bad = run_cli(cli_args, uvicorn_runner=lambda *_a, **_kw: None)
        assert rc_bad == EXIT_CONFIG_ERROR
        assert "configuration error" in capsys.readouterr().err.lower()

    # 3. Opt-in via --allow-insecure-unauthenticated succeeds with allow_write_api / non-loopback
    rc_opt = run_cli(
        ["--auth-mode", "none", "--host", "0.0.0.0", "--allow-write-api", "--allow-insecure-unauthenticated"],
        uvicorn_runner=lambda *_a, **_kw: None,
    )
    assert rc_opt == 0

    # 4. Wildcard allowed_hosts or allowed_origins with DNS rebinding enabled fails even in static mode
    monkeypatch.setenv("TEAM_A_TOKEN", "tok-a-0123456789abcdefghijklmnopqrstuv")
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "TEAM_A_TOKEN")
    monkeypatch.setenv("ARODONATA_MCP_ALLOWED_HOSTS", "*")
    rc_wild = run_cli([], uvicorn_runner=lambda *_a, **_kw: None)
    assert rc_wild == EXIT_CONFIG_ERROR
    assert "Wildcard" in capsys.readouterr().err

    monkeypatch.delenv("ARODONATA_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("ARODONATA_MCP_ALLOWED_ORIGINS", "https://*")
    rc_wild_orig = run_cli([], uvicorn_runner=lambda *_a, **_kw: None)
    assert rc_wild_orig == EXIT_CONFIG_ERROR
    assert "Wildcard" in capsys.readouterr().err
