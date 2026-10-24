"""MCP server and embeddable ASGI application factories (`create_mcp_server`, `create_asgi_app`)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.types import ASGIApp, Receive, Scope, Send

from arodonata import __version__
from arodonata.client import ArodonataClient
from arodonata.core.config import ArodonataSettings
from arodonata.mcp.config import ArodonataMCPSettings, MCPAuthMode
from arodonata.mcp.prompts import register_mcp_prompts
from arodonata.mcp.security import (
    MCPBearerAuthMiddleware,
    MCPOriginHostGuardMiddleware,
    StaticTokenVerifier,
)
from arodonata.mcp.tools import register_mcp_tools


def _resolve_mcp_settings(
    mcp_settings: ArodonataMCPSettings | None = None,
    *,
    auth_mode: MCPAuthMode | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    allow_write_api: bool | None = None,
    live_compat: bool | None = None,
    cpcrud: bool | None = None,
    path: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> ArodonataMCPSettings:
    base = mcp_settings.model_copy(deep=True) if mcp_settings is not None else ArodonataMCPSettings()
    if auth_mode is not None:
        base.auth_mode = auth_mode
    if allowed_hosts is not None:
        base.allowed_hosts = list(allowed_hosts)
    if allowed_origins is not None:
        base.allowed_origins = list(allowed_origins)
    if allow_write_api is not None:
        base.allow_write_api = allow_write_api
    if live_compat is not None:
        base.live_compat = live_compat
    if cpcrud is not None:
        base.cpcrud = cpcrud
    if path is not None:
        base.path = path if path.startswith("/") else f"/{path}"
    if host is not None:
        base.host = host
    if port is not None:
        base.port = port
    return base


class ArodonataASGIApp:
    """ASGI wrapper combining `MCPOriginHostGuardMiddleware`, optional `MCPBearerAuthMiddleware`,
    and the underlying `Starlette` Streamable-HTTP MCP application (preserving its `router.lifespan_context`).
    """

    def __init__(
        self,
        *,
        starlette_app: Any,
        guarded_app: ASGIApp,
        mcp_server: MCPServer,
        client: ArodonataClient,
        mcp_settings: ArodonataMCPSettings,
        token_verifier: TokenVerifier | None,
    ) -> None:
        self.starlette_app = starlette_app
        self.app = guarded_app
        self.mcp_server = mcp_server
        self.client = client
        self.mcp_settings = mcp_settings
        self.token_verifier = token_verifier
        self.router = starlette_app.router

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)


def create_mcp_server(
    client: ArodonataClient | None = None,
    *,
    settings: ArodonataSettings | None = None,
    mcp_settings: ArodonataMCPSettings | None = None,
    auth_mode: MCPAuthMode | None = None,
    token_verifier: TokenVerifier | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    allow_write_api: bool | None = None,
    live_compat: bool | None = None,
    cpcrud: bool | None = None,
    environ: dict[str, str] | None = None,
) -> MCPServer:
    """Create and configure an `MCPServer` instance wired to `ArodonataClient`.

    When `auth_mode="host"` is specified for embedding inside an authenticating ASGI host,
    Arodonata disables its internal token verifier (`token_verifier=None`) and relies on the
    enclosing ASGI host middleware for request authentication.
    """
    eff_mcp = _resolve_mcp_settings(
        mcp_settings,
        auth_mode=auth_mode,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        allow_write_api=allow_write_api,
        live_compat=live_compat,
        cpcrud=cpcrud,
    )

    owns_client = client is None
    eff_client = client if client is not None else ArodonataClient(settings=settings)

    eff_verifier: TokenVerifier | None = None
    eff_auth_settings: AuthSettings | None = None

    if eff_mcp.auth_mode in ("host", "none"):
        eff_verifier = None
        eff_auth_settings = None
    elif eff_mcp.auth_mode == "static":
        eff_verifier = (
            token_verifier
            if token_verifier is not None
            else StaticTokenVerifier.from_settings(eff_mcp, environ=environ)
        )
        eff_auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(f"http://{eff_mcp.host}:{eff_mcp.port}"),
            resource_server_url=None,
            required_scopes=["mcp"],
        )
    elif token_verifier is not None:
        eff_verifier = token_verifier
        eff_auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(f"http://{eff_mcp.host}:{eff_mcp.port}"),
            resource_server_url=None,
            required_scopes=["mcp"],
        )

    @asynccontextmanager
    async def _server_lifespan(_srv: MCPServer[Any]) -> AsyncIterator[dict[str, Any]]:
        if not eff_client.db.is_initialized:
            await eff_client.initialize(run_startup_cleanup=False)
        try:
            yield {"client": eff_client}
        finally:
            if owns_client:
                await eff_client.close()

    server = MCPServer(
        name=eff_mcp.server_name,
        title="Arodonata Check Point MCP Server",
        description="Async-first Check Point Security Management & MDSM Model Context Protocol Server",
        version=__version__,
        lifespan=_server_lifespan,
        auth=eff_auth_settings,
        token_verifier=eff_verifier,
    )

    register_mcp_tools(server, lambda: eff_client, eff_mcp)
    register_mcp_prompts(server)

    # Attach metadata for inspection and create_asgi_app reuse
    server._arodonata_client = eff_client  # type: ignore[attr-defined]
    server._arodonata_mcp_settings = eff_mcp  # type: ignore[attr-defined]
    server._arodonata_token_verifier = eff_verifier  # type: ignore[attr-defined]
    server._arodonata_owns_client = owns_client  # type: ignore[attr-defined]
    return server


def create_asgi_app(
    client: ArodonataClient | None = None,
    *,
    mcp_server: MCPServer | None = None,
    settings: ArodonataSettings | None = None,
    mcp_settings: ArodonataMCPSettings | None = None,
    auth_mode: MCPAuthMode | None = None,
    token_verifier: TokenVerifier | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    allow_write_api: bool | None = None,
    live_compat: bool | None = None,
    cpcrud: bool | None = None,
    path: str | None = None,
    json_response: bool | None = None,
    stateless_http: bool | None = None,
    environ: dict[str, str] | None = None,
) -> ArodonataASGIApp:
    """Create a Streamable-HTTP ASGI application ready for `uvicorn` or Starlette/FastAPI mounting.

    Enforces:
    - DNS rebinding protection (`Host` not in `allowed_hosts` -> HTTP `421`).
    - Browser `Origin` header validation (`Origin` not in `allowed_origins` -> HTTP `403`).
    - Static bearer token verification (`auth_mode="static"`) mapping matched env var names to `client_id`
      and binding `UserContext(client_id=...)` in `contextvars`, or pass-through in `auth_mode="host"`.
    """
    if mcp_server is not None:
        base_mcp: ArodonataMCPSettings = getattr(
            mcp_server,
            "_arodonata_mcp_settings",
            mcp_settings or ArodonataMCPSettings(),
        )
        eff_mcp = _resolve_mcp_settings(
            base_mcp,
            auth_mode=auth_mode,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            allow_write_api=allow_write_api,
            live_compat=live_compat,
            cpcrud=cpcrud,
            path=path,
        )
        eff_client: ArodonataClient = getattr(mcp_server, "_arodonata_client", None) or (
            client if client is not None else ArodonataClient(settings=settings)
        )
        eff_verifier: TokenVerifier | None = (
            None
            if eff_mcp.auth_mode in ("host", "none")
            else (token_verifier or getattr(mcp_server, "_arodonata_token_verifier", None))
        )
        srv = mcp_server
    else:
        eff_mcp = _resolve_mcp_settings(
            mcp_settings,
            auth_mode=auth_mode,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            allow_write_api=allow_write_api,
            live_compat=live_compat,
            cpcrud=cpcrud,
            path=path,
        )
        srv = create_mcp_server(
            client,
            settings=settings,
            mcp_settings=eff_mcp,
            token_verifier=token_verifier,
            environ=environ,
        )
        eff_client = srv._arodonata_client  # type: ignore[attr-defined]
        eff_verifier = srv._arodonata_token_verifier  # type: ignore[attr-defined]

    if json_response is not None:
        eff_mcp.json_response = json_response
    if stateless_http is not None:
        eff_mcp.stateless_http = stateless_http

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=eff_mcp.enable_dns_rebinding_protection,
        allowed_hosts=list(eff_mcp.allowed_hosts),
        allowed_origins=list(eff_mcp.allowed_origins),
    )

    starlette_app = srv.streamable_http_app(
        streamable_http_path=eff_mcp.path,
        json_response=eff_mcp.json_response,
        stateless_http=eff_mcp.stateless_http,
        transport_security=transport_security,
        host=eff_mcp.host,
    )

    inner_app: ASGIApp = starlette_app
    if eff_mcp.auth_mode == "static" and eff_verifier is not None:
        inner_app = MCPBearerAuthMiddleware(inner_app, verifier=eff_verifier)

    guarded_app: ASGIApp = MCPOriginHostGuardMiddleware(
        inner_app,
        allowed_hosts=eff_mcp.allowed_hosts,
        allowed_origins=eff_mcp.allowed_origins,
        enabled=eff_mcp.enable_dns_rebinding_protection,
    )

    return ArodonataASGIApp(
        starlette_app=starlette_app,
        guarded_app=guarded_app,
        mcp_server=srv,
        client=eff_client,
        mcp_settings=eff_mcp,
        token_verifier=eff_verifier,
    )


__all__ = [
    "ArodonataASGIApp",
    "create_asgi_app",
    "create_mcp_server",
]
