from __future__ import annotations

import os
from pathlib import Path

from arodonata.mcp.__main__ import build_settings, load_env_files, main, parse_args


def test_parse_args_defaults_and_overrides():
    args = parse_args([])
    assert args.env_file == [".env.lib", ".env.secrets"] and args.host is None and args.port is None
    args = parse_args(
        [
            "--env-file",
            "a.env",
            "--env-file",
            "b.env",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--ssl-certfile",
            "c.pem",
            "--ssl-keyfile",
            "k.pem",
        ]
    )
    assert (
        args.env_file == ["a.env", "b.env"]
        and args.host == "0.0.0.0"
        and args.port == 9000
        and args.ssl_certfile == "c.pem"
    )


def test_load_env_files_in_order_with_override_and_skips_missing(tmp_path: Path, monkeypatch):
    a = tmp_path / "a.env"
    a.write_text("X_VAL=first\nONLY_A=1\n")
    b = tmp_path / "b.env"
    b.write_text("X_VAL=second\n")
    monkeypatch.delenv("X_VAL", raising=False)
    monkeypatch.delenv("ONLY_A", raising=False)
    loaded = load_env_files([str(a), str(tmp_path / "missing.env"), str(b)])
    assert loaded == [str(a), str(b)] and os.environ["X_VAL"] == "second" and os.environ["ONLY_A"] == "1"


def test_build_settings_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("ARODONATA_MCP_PORT", "1111")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    mcp_settings, lib_settings = build_settings(parse_args(["--port", "2222", "--host", "0.0.0.0"]))
    assert mcp_settings.port == 2222 and mcp_settings.host == "0.0.0.0" and lib_settings.mgmt_names_list == ["m1"]


def test_main_returns_2_on_config_error(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)  # no .env files present
    for var in ("ARODONATA_MCP_TOKEN_VARS", "MGMT_NAMES", "MGMT_SERVERS", "API_KEYS", "API_KEY_VARS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    assert main([]) == 2
    assert "ARODONATA_MCP_TOKEN_VARS" in capsys.readouterr().err


def _no_engine(monkeypatch) -> None:
    """Fail the test if ``serve`` gets far enough to create a database engine (and thus a client)."""
    import sqlalchemy.ext.asyncio as sa_asyncio

    def _fail(*_a, **_kw):
        raise AssertionError("create_async_engine should not be called")

    monkeypatch.setattr(sa_asyncio, "create_async_engine", _fail)


def test_main_returns_2_for_host_auth_mode_with_no_engine_created(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARODONATA_MCP_AUTH_MODE", "host")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    _no_engine(monkeypatch)
    assert main([]) == 2
    assert "host" in capsys.readouterr().err.lower()


def test_main_returns_2_for_jwt_auth_mode_with_no_engine_created(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARODONATA_MCP_AUTH_MODE", "jwt")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    _no_engine(monkeypatch)
    assert main([]) == 2
    assert "jwt" in capsys.readouterr().err.lower()


def test_build_settings_resolves_api_key_vars_indirection_in_order(monkeypatch):
    monkeypatch.delenv("API_KEYS", raising=False)
    monkeypatch.setenv("API_KEY_VARS", "A_KEY,B_KEY")
    monkeypatch.setenv("A_KEY", "val-a")
    monkeypatch.setenv("B_KEY", "val-b")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    _, lib_settings = build_settings(parse_args([]))
    assert lib_settings.api_keys_list == ["val-a", "val-b"]


def test_build_settings_direct_api_keys_without_api_key_vars_still_works(monkeypatch):
    monkeypatch.delenv("API_KEY_VARS", raising=False)
    monkeypatch.setenv("API_KEYS", "direct")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    _, lib_settings = build_settings(parse_args([]))
    assert lib_settings.api_keys_list == ["direct"]


def test_build_settings_drops_empty_entry_for_a_named_var_left_unset(monkeypatch):
    """An API_KEY_VARS name with no matching env var resolves to "" for that slot; joining it in
    still produces a valid comma-separated string, and ArodonataSettings._parse_comma_separated
    drops the resulting empty entry -- the same as it would for any other empty entry, e.g.
    "a,,b" -> ["a", "b"]. So the unset name is silently skipped rather than raising or including
    a literal empty-string key."""
    monkeypatch.delenv("API_KEYS", raising=False)
    monkeypatch.delenv("B_KEY", raising=False)
    monkeypatch.setenv("API_KEY_VARS", "A_KEY,B_KEY")
    monkeypatch.setenv("A_KEY", "val-a")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    _, lib_settings = build_settings(parse_args([]))
    assert lib_settings.api_keys_list == ["val-a"]


def test_main_returns_2_on_pydantic_validation_error(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARODONATA_MCP_PATH", "mcp")  # missing leading slash -> pydantic.ValidationError
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "T")
    monkeypatch.setenv("T", "x")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    assert main([]) == 2
    assert "path" in capsys.readouterr().err.lower()


def test_main_returns_2_with_one_line_for_invalid_log_level(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert main(["--log-level", "loud"]) == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and err[0].startswith("arodonata-mcp: configuration error:") and "loud" in err[0]
    assert "Traceback" not in "\n".join(err)


def test_parse_args_accepts_log_level_case_insensitively():
    assert parse_args(["--log-level", "DEBUG"]).log_level == "debug"


def test_main_returns_2_with_one_line_for_server_registry_count_mismatch(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("API_KEY_VARS", raising=False)
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "T")
    monkeypatch.setenv("T", "x")
    monkeypatch.setenv("MGMT_NAMES", "m1,m2")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main([]) == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and err[0].startswith("arodonata-mcp: configuration error:") and "mismatch" in err[0]


def test_value_error_during_server_run_is_not_reported_as_configuration_error(monkeypatch, tmp_path):
    import pytest

    async def boom(_args):
        raise ValueError("runtime failure")

    monkeypatch.chdir(tmp_path)
    # Patch the globals ``main`` actually resolves ``serve`` from: other tests re-import arodonata.mcp modules, so
    # ``import arodonata.mcp.__main__`` here may return a different module object than the one ``main`` came from.
    monkeypatch.setitem(main.__globals__, "serve", boom)
    with pytest.raises(ValueError, match="runtime failure"):
        main([])
