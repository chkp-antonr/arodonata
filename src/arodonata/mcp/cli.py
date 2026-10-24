"""Standalone CLI entry point (`arodonata-mcp`) for the Arodonata Streamable-HTTP MCP server."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from typing import Any

import arlogi
from pydantic import ValidationError

from arodonata.client import ArodonataClient
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ArodonataError, redact_sid
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.server import create_asgi_app

logger = arlogi.get_logger(__name__)

EXIT_CONFIG_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arodonata-mcp",
        description="Arodonata Check Point Security Management & MDSM Streamable-HTTP MCP Server",
    )
    parser.add_argument("--host", type=str, default=None, help="Bind host (overrides ARODONATA_MCP_HOST)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (overrides ARODONATA_MCP_PORT)")
    parser.add_argument("--path", type=str, default=None, help="MCP HTTP path (overrides ARODONATA_MCP_PATH)")
    parser.add_argument(
        "--auth-mode",
        type=str,
        default=None,
        help="Authentication mode (overrides ARODONATA_MCP_AUTH_MODE; 'host' and 'jwt' are rejected in standalone CLI)",
    )
    parser.add_argument(
        "--allow-write-api",
        action="store_true",
        default=None,
        help="Allow non-show-* commands in api_call",
    )
    parser.add_argument(
        "--live-compat",
        action="store_true",
        default=None,
        help="Enable live-compatibility MCP tools",
    )
    parser.add_argument(
        "--cpcrud",
        action="store_true",
        default=None,
        help="Enable declarative CPCRUD MCP tools",
    )
    return parser


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    environ: dict[str, str] | None = None,
    uvicorn_runner: Callable[..., Any] | None = None,
) -> int:
    """Run the standalone `arodonata-mcp` Streamable-HTTP server and return an integer exit code.

    Validates TLS trust store configuration and authentication mode at startup.
    Refuses `ARODONATA_MCP_AUTH_MODE=host` or `jwt` with exit code `2` and a clear
    configuration error message written to `stderr`.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_CONFIG_ERROR

    try:
        mcp_kwargs: dict[str, Any] = {}
        if args.host is not None:
            mcp_kwargs["host"] = args.host
        if args.port is not None:
            mcp_kwargs["port"] = args.port
        if args.path is not None:
            mcp_kwargs["path"] = args.path
        if args.auth_mode is not None:
            mcp_kwargs["auth_mode"] = args.auth_mode
        if args.allow_write_api is True:
            mcp_kwargs["allow_write_api"] = True
        if args.live_compat is True:
            mcp_kwargs["live_compat"] = True
        if args.cpcrud is True:
            mcp_kwargs["cpcrud"] = True

        mcp_settings = ArodonataMCPSettings(**mcp_kwargs)
        core_settings = ArodonataSettings()
        trust_policy = mcp_settings.validate_standalone_startup(core_settings, environ=environ)
    except (ArodonataError, ValidationError, ValueError) as exc:
        err_msg = redact_sid(str(exc))
        sys.stderr.write(f"arodonata-mcp configuration error: {err_msg}\n")
        sys.stderr.flush()
        logger.error("arodonata-mcp startup validation failed", error=err_msg)
        return EXIT_CONFIG_ERROR

    client = ArodonataClient(settings=core_settings, trust_policy=trust_policy)
    asgi_app = create_asgi_app(
        client,
        settings=core_settings,
        mcp_settings=mcp_settings,
        environ=environ,
    )

    if uvicorn_runner is not None:
        uvicorn_runner(asgi_app, host=mcp_settings.host, port=mcp_settings.port)
        return 0

    import uvicorn

    uvicorn.run(asgi_app, host=mcp_settings.host, port=mcp_settings.port)
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: dict[str, str] | None = None,
    uvicorn_runner: Callable[..., Any] | None = None,
    raise_system_exit: bool | None = None,
) -> int:
    """Console script entry point for `arodonata-mcp`.

    When invoked with no arguments (`argv is None` and `uvicorn_runner is None`, as in the console
    script entry point) or `raise_system_exit=True`, raises `SystemExit(code)` on non-zero exit code.
    Otherwise returns `code` directly for programmatic callers and tests.
    """
    code = run_cli(argv, environ=environ, uvicorn_runner=uvicorn_runner)
    should_raise = (argv is None and uvicorn_runner is None) if raise_system_exit is None else raise_system_exit
    if should_raise and code != 0:
        raise SystemExit(code)
    return code


__all__ = [
    "EXIT_CONFIG_ERROR",
    "main",
    "run_cli",
]
