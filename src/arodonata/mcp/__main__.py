"""``arodonata-mcp``: serve Arodonata as a streamable-HTTP MCP server for a team."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import NoReturn

DEFAULT_ENV_FILES = [".env.lib", ".env.secrets"]
# Levels understood by both ``logging.basicConfig`` and uvicorn (uvicorn's extra "trace" is unknown to logging).
LOG_LEVELS = ("critical", "error", "warning", "info", "debug")
log = logging.getLogger("arodonata.mcp")
# SDK loggers that only add noise at INFO: in stateless mode streamable_http logs "Terminating session: None" for
# every request. Raised to WARNING unless --log-level debug, so their warnings and errors still show.
QUIET_SDK_LOGGERS = ("mcp.server.streamable_http",)
# Name prefix of the worker threads that run the synchronous Check Point SDK (``asyncio.to_thread``).
SDK_THREAD_PREFIX = "arodonata-mcp-sdk"


class CLIArgumentError(Exception):
    """A command-line usage error, reported by ``main`` as a single configuration-error line."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CLIArgumentError(message)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = _ArgumentParser(prog="arodonata-mcp", description="Serve Arodonata as an MCP server over streamable HTTP.")
    p.add_argument(
        "--env-file",
        action="append",
        default=None,
        help="dotenv file to load (repeatable, later files override). Default: .env.lib then .env.secrets",
    )
    p.add_argument("--host", default=None, help="Bind address (overrides ARODONATA_MCP_HOST)")
    p.add_argument("--port", type=int, default=None, help="Bind port (overrides ARODONATA_MCP_PORT)")
    p.add_argument("--ssl-certfile", default=None)
    p.add_argument("--ssl-keyfile", default=None)
    p.add_argument("--log-level", default="info", type=str.lower, choices=LOG_LEVELS)
    p.add_argument(
        "--shutdown-timeout",
        type=int,
        default=None,
        help="Seconds to wait on shutdown for open connections and stuck SDK calls (overrides ARODONATA_MCP_SHUTDOWN_TIMEOUT)",
    )
    args = p.parse_args(argv)
    if args.env_file is None:
        args.env_file = list(DEFAULT_ENV_FILES)
    return args


def load_env_files(paths: list[str]) -> list[str]:
    from dotenv import load_dotenv

    loaded: list[str] = []
    for path in paths:
        if Path(path).is_file():
            load_dotenv(path, override=True)
            loaded.append(path)
    return loaded


def build_settings(args: argparse.Namespace):  # -> tuple[ArodonataMCPSettings, ArodonataSettings]
    from ..config import ArodonataSettings
    from .settings import ArodonataMCPSettings

    overrides = {
        k: v
        for k, v in (("host", args.host), ("port", args.port), ("shutdown_timeout", args.shutdown_timeout))
        if v is not None
    }

    # ArodonataSettings.api_keys has no validation_alias, so pydantic-settings only ever populates it from a
    # bare (case-insensitive) "API_KEYS" env var or an explicit constructor kwarg -- never from API_KEY_VARS,
    # because its own before-validator (which does know about API_KEY_VARS) only runs when the field is given
    # some value. Resolve the indirection ourselves, the way examples/05_rulebase_queries.py does, and only pass
    # api_keys= when API_KEY_VARS is actually set; otherwise pass nothing so a bare API_KEYS env var (or
    # credential-mode login, which does not need api_keys at all) keeps working exactly as it does today. Never
    # log the resolved key values.
    lib_overrides: dict[str, str] = {}
    api_key_vars = os.getenv("API_KEY_VARS", "")
    if api_key_vars.strip():
        var_names = [name.strip() for name in api_key_vars.split(",")]
        lib_overrides["api_keys"] = ",".join(os.environ.get(name, "") for name in var_names)

    return ArodonataMCPSettings(**overrides), ArodonataSettings(**lib_overrides)


async def serve(args: argparse.Namespace) -> None:
    import uvicorn
    from sqlalchemy.ext.asyncio import create_async_engine

    from ..api.client import ArodonataClient
    from ..asdk.tls import TrustPolicy
    from .app import create_asgi_app, create_mcp_server
    from .settings import ArodonataMCPConfigError

    mcp_settings, lib_settings = build_settings(args)
    TrustPolicy.from_settings(lib_settings).preflight()  # tofu + unusable store -> exit 2 now, not at first host
    if mcp_settings.auth_mode == "host":
        raise ArodonataMCPConfigError(
            "auth_mode=host is only for embedding create_asgi_app behind an authenticating ASGI host; the "
            "standalone arodonata-mcp executable has no such host and would serve every request anonymously"
        )
    if mcp_settings.auth_mode == "jwt":
        raise ArodonataMCPConfigError("auth_mode=jwt is reserved and not implemented")

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        log.warning("DATABASE_URL not set; using an in-memory SQLite cache that is lost on exit")
        database_url = "sqlite+aiosqlite:///:memory:"
    if mcp_settings.host not in ("127.0.0.1", "localhost", "::1") and not args.ssl_certfile:
        log.warning(
            "binding to %s without TLS; put a TLS-terminating proxy in front (org policy requires TLS 1.2+)",
            mcp_settings.host,
        )
    engine = create_async_engine(database_url)
    client: ArodonataClient | None = None
    sdk_pool = ThreadPoolExecutor(thread_name_prefix=SDK_THREAD_PREFIX)
    asyncio.get_running_loop().set_default_executor(sdk_pool)
    try:
        try:
            client = ArodonataClient(engine=engine, settings=lib_settings)
        except ValueError as exc:
            # e.g. the server registry's MGMT_NAMES / MGMT_SERVERS / API_KEYS count mismatch. Only construction is
            # translated: a ValueError raised while serving is a bug, not a configuration problem.
            raise ArodonataMCPConfigError(str(exc)) from exc
        server = create_mcp_server(client, mcp_settings)  # fails fast on auth misconfiguration, before any network I/O
        async with client:  # __aenter__ initializes the db and schedules startup session cleanup
            app = create_asgi_app(client, mcp_settings, server=server)
            config = uvicorn.Config(
                app,
                host=mcp_settings.host,
                port=mcp_settings.port,
                log_level=args.log_level,
                ssl_certfile=args.ssl_certfile,
                ssl_keyfile=args.ssl_keyfile,
                # Claude Code keeps its connection open: without a limit, Ctrl+C waits for it forever.
                timeout_graceful_shutdown=mcp_settings.shutdown_timeout,
            )
            log.info("arodonata-mcp listening on %s:%s%s", mcp_settings.host, mcp_settings.port, mcp_settings.path)
            await _server_class()(config).serve()
    finally:
        # ``client.close()`` is idempotent (checks ``_closed``), so this is a no-op when the ``async with`` block
        # above already ran __aexit__; it is the only cleanup when construction failed before entering that block.
        if client is not None:
            await client.close()
        await engine.dispose()
        await _release_sdk_pool(sdk_pool, mcp_settings.shutdown_timeout)


@functools.cache
def _server_class() -> type:  # -> type[uvicorn.Server]; uvicorn is imported lazily, like the rest of the SDK
    import uvicorn

    class _Server(uvicorn.Server):
        """uvicorn.Server that does not re-raise the signal it stopped on.

        uvicorn re-raises a caught SIGINT once `serve()` returns, so that its host stops too. Here the host is
        `serve()` itself, which stops anyway; re-raised, the SIGINT makes `asyncio.run` cancel the main task in
        the middle of its cleanup (client close, engine dispose), and SQLAlchemy logs a CancelledError traceback
        for the connection it was closing.
        """

        @contextlib.contextmanager
        def capture_signals(self):  # type: ignore[no-untyped-def]
            with super().capture_signals():
                yield
                self._captured_signals.clear()

    return _Server


def _blocked_sdk_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith(SDK_THREAD_PREFIX) and t.is_alive()]


async def _release_sdk_pool(pool: ThreadPoolExecutor, timeout: float) -> None:
    """Stop the SDK worker pool without letting a call stuck in network I/O hold up the exit.

    The Check Point SDK connects without a socket timeout, and a thread cannot be cancelled: a call to an
    unreachable server keeps its worker blocked after its task was cancelled. Give such calls ``timeout`` seconds,
    then hand ``asyncio.run`` an unused pool so it does not join the old one for up to 300 s; ``main`` exits past
    whatever is still blocked.
    """
    pool.shutdown(wait=False, cancel_futures=True)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while _blocked_sdk_threads() and loop.time() < deadline:
        await asyncio.sleep(0.1)
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))


def _hard_exit(code: int) -> NoReturn:
    os._exit(code)


def _exit_past_blocked_sdk_threads(code: int) -> None:
    """The interpreter joins every pool thread at exit, without a limit: leave at once if any is still blocked."""
    blocked = _blocked_sdk_threads()
    if not blocked:
        return
    log.warning("exiting with %d Check Point SDK call(s) still blocked in network I/O", len(blocked))
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()
    _hard_exit(code)


def configure_logging(level: str) -> None:
    """Root logging at ``level``; the SDK loggers in QUIET_SDK_LOGGERS at WARNING unless ``level`` is debug."""
    logging.basicConfig(level=level.upper())
    if level != "debug":
        for name in QUIET_SDK_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    try:
        from . import _sdk  # noqa: F401
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        args = parse_args(argv)
    except CLIArgumentError as exc:
        print(f"arodonata-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    configure_logging(args.log_level)
    loaded = load_env_files(args.env_file)
    log.info("loaded env files: %s", ", ".join(loaded) or "none")
    from pydantic import ValidationError

    from ..core.exceptions import ConfigurationError, MissingConfigurationError
    from .settings import ArodonataMCPConfigError

    try:
        asyncio.run(serve(args))
    except (ArodonataMCPConfigError, MissingConfigurationError, ConfigurationError, ValidationError) as exc:
        print(f"arodonata-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        pass
    _exit_past_blocked_sdk_threads(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
