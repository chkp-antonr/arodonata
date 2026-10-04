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


def test_shutdown_timeout_defaults_to_5_and_the_cli_overrides_it(monkeypatch):
    monkeypatch.delenv("ARODONATA_MCP_SHUTDOWN_TIMEOUT", raising=False)
    assert parse_args([]).shutdown_timeout is None
    mcp_settings, _ = build_settings(parse_args([]))
    assert mcp_settings.shutdown_timeout == 5
    mcp_settings, _ = build_settings(parse_args(["--shutdown-timeout", "2"]))
    assert mcp_settings.shutdown_timeout == 2


def _fake_server_stack(monkeypatch, tmp_path, server_serve):
    """Run the real ``main``/``serve`` with the client, MCP app and uvicorn server replaced by fakes.

    ``server_serve(config)`` stands in for ``uvicorn.Server(config).serve()``; nothing touches the network.
    """
    import uvicorn

    import arodonata.api.client as client_module
    import arodonata.mcp.app as app_module

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def close(self):
            return None

    class FakeServer:
        def __init__(self, config):
            self.config = config

        async def serve(self):
            await server_serve(self.config)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(client_module, "ArodonataClient", FakeClient)
    monkeypatch.setattr(app_module, "create_mcp_server", lambda client, settings: object())
    monkeypatch.setattr(app_module, "create_asgi_app", lambda client, settings, server: object())
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setitem(main.__globals__, "_server_class", lambda: FakeServer)


def test_uvicorn_gets_the_shutdown_timeout_so_an_open_client_connection_cannot_block_ctrl_c(monkeypatch, tmp_path):
    """Claude Code keeps its connection open; without a graceful-shutdown timeout uvicorn waits for it forever."""
    seen = {}

    async def record(config):
        seen["timeout"] = config.timeout_graceful_shutdown

    _fake_server_stack(monkeypatch, tmp_path, record)
    assert main(["--shutdown-timeout", "3"]) == 0
    assert seen["timeout"] == 3


def test_a_thread_stuck_in_network_io_does_not_hold_up_exit(monkeypatch, tmp_path):
    """cpapi connects without a socket timeout; a blocked worker thread must not keep the process alive.

    Without the fix asyncio.run joins the pool for up to 300 s and the interpreter then joins it without limit.
    """
    import threading
    import time

    import pytest

    release = threading.Event()
    threading.Timer(3, release.set).start()  # a safety net: the stuck thread always ends eventually

    async def leave_a_blocked_thread(_config):
        import asyncio

        asyncio.get_running_loop().run_in_executor(None, release.wait)
        await asyncio.sleep(0.1)  # the worker has picked the call up

    class Exited(Exception):
        pass

    def fake_exit(code):
        raise Exited(code)

    _fake_server_stack(monkeypatch, tmp_path, leave_a_blocked_thread)
    monkeypatch.setitem(main.__globals__, "_hard_exit", fake_exit)
    started = time.monotonic()
    try:
        with pytest.raises(Exited) as exited:
            main(["--shutdown-timeout", "0"])
        assert exited.value.args == (0,)
        assert time.monotonic() - started < 2
    finally:
        release.set()


def test_a_clean_shutdown_returns_normally_without_a_hard_exit(monkeypatch, tmp_path):
    async def quick_call(_config):
        import asyncio

        await asyncio.to_thread(lambda: None)

    def fail_exit(code):
        raise AssertionError(f"hard exit {code} with no blocked thread")

    _fake_server_stack(monkeypatch, tmp_path, quick_call)
    monkeypatch.setitem(main.__globals__, "_hard_exit", fail_exit)
    assert main(["--shutdown-timeout", "1"]) == 0


async def test_the_server_does_not_re_raise_the_caught_sigint_after_a_clean_shutdown(monkeypatch):
    """uvicorn re-raises the signals it caught once serve() returns, for its host's sake. We are the host: re-raised,
    the SIGINT makes asyncio.run cancel the main task mid-cleanup, and SQLAlchemy logs a CancelledError traceback
    for the aiosqlite connection it was closing."""
    import signal

    import uvicorn

    server = main.__globals__["_server_class"]()(uvicorn.Config(app=None))

    async def stop_on_ctrl_c(sockets=None):
        server.handle_exit(signal.SIGINT, None)

    raised: list[int] = []
    monkeypatch.setattr(server, "_serve", stop_on_ctrl_c)
    monkeypatch.setattr(signal, "raise_signal", raised.append)
    await server.serve()
    assert raised == []
    assert server.should_exit is True


def _sdk_session_logger():
    import logging

    return logging.getLogger("mcp.server.streamable_http")


def test_info_log_level_quiets_the_sdk_per_request_session_log(monkeypatch):
    """In stateless mode the SDK logs "Terminating session: None" at INFO on every request."""
    from arodonata.mcp.__main__ import configure_logging

    monkeypatch.setattr(_sdk_session_logger(), "level", 0)
    configure_logging("info")
    assert _sdk_session_logger().level == 30  # WARNING: warnings and errors still shown


def test_debug_log_level_keeps_the_sdk_session_log(monkeypatch):
    from arodonata.mcp.__main__ import configure_logging

    monkeypatch.setattr(_sdk_session_logger(), "level", 0)
    configure_logging("debug")
    assert _sdk_session_logger().level == 0


def test_main_exits_2_when_the_tofu_store_cannot_be_created(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    blocker = tmp_path / "file"
    blocker.write_text("x")  # a parent that is a file: the store can never be created (also under root)
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(blocker / "sub" / "t.json"))
    monkeypatch.delenv("ARODONATA_TLS_TRUST", raising=False)
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "T")
    monkeypatch.setenv("T", "x")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    assert main(["--env-file", str(tmp_path / "none.env")]) == 2
    assert "configuration error" in capsys.readouterr().err


def test_main_exits_2_for_an_invalid_tls_trust_mode(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "bogus")
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "T")
    monkeypatch.setenv("T", "x")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    assert main(["--env-file", str(tmp_path / "none.env")]) == 2
    assert "configuration error" in capsys.readouterr().err


def test_main_exits_2_for_lab_memory_without_arodonata_lab(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "lab-memory")
    monkeypatch.delenv("ARODONATA_LAB", raising=False)
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "T")
    monkeypatch.setenv("T", "x")
    monkeypatch.setenv("MGMT_NAMES", "m1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "k")
    assert main(["--env-file", str(tmp_path / "none.env")]) == 2
    assert "ARODONATA_LAB" in capsys.readouterr().err
