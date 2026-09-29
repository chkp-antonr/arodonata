"""Factories: a configured MCPServer and a mountable Starlette app."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.routing import Mount

from ._sdk import AuthSettings, MCPServer, TransportSecuritySettings
from .auth import build_token_verifier
from .registry import register_arodonata_tools
from .settings import ArodonataMCPConfigError, ArodonataMCPSettings

if TYPE_CHECKING:
    from ..api.client import ArodonataClient

INSTRUCTIONS = (
    "Check Point Security Management via Arodonata. Call arodonata_init first. Tools named show_* mirror the Check Point "
    "Management API; cache-backed ones answer from a local cache (pass cache_mode='smart' to re-sync stale data, 'force' to reload). Use search_objects "
    "to find objects across servers and domains, and api_call for any show-* command without a dedicated tool."
)


def create_mcp_server(
    client: ArodonataClient,
    settings: ArodonataMCPSettings | None = None,
    *,
    name: str = "arodonata",
    environ: Mapping[str, str] | None = None,
) -> MCPServer:
    """Build an MCPServer with Arodonata tools and the configured bearer-token verifier.

    ``auth_mode="jwt"`` is reserved but not implemented (see ``JwtTokenVerifier``): it is rejected here rather than
    left to fail at request time, since the stub verifier raises ``NotImplementedError`` on every call.
    """
    cfg = settings or ArodonataMCPSettings()
    if cfg.auth_mode == "jwt":
        raise ArodonataMCPConfigError("auth_mode=jwt is reserved and not implemented")
    verifier = build_token_verifier(cfg, environ)
    auth = None
    if verifier is not None:
        auth = AuthSettings(
            issuer_url=AnyHttpUrl(cfg.public_url),
            resource_server_url=AnyHttpUrl(cfg.public_url),
            # Static tokens carry no resource/audience claim to check; the verifier itself is the authority.
            validate_token_resource=False,
        )
    server = MCPServer(name, instructions=INSTRUCTIONS, token_verifier=verifier, auth=auth)
    register_arodonata_tools(
        server,
        client,
        live_compat=cfg.live_compat,
        cpcrud=cfg.cpcrud,
        allow_write_api=cfg.allow_write_api,
        default_limit=cfg.default_limit,
        max_result_chars=cfg.max_result_chars,
    )
    return server


def create_asgi_app(
    client: ArodonataClient,
    settings: ArodonataMCPSettings | None = None,
    *,
    server: MCPServer | None = None,
) -> Starlette:
    """Starlette app serving streamable HTTP at ``settings.path``; mount it in a host app or run it with uvicorn.

    The returned app's lifespan runs the MCP session manager only. The caller owns ``client`` (open it before serving,
    close it after) and the database engine.
    """
    cfg = settings or ArodonataMCPSettings()
    mcp = server or create_mcp_server(client, cfg)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=cfg.allowed_hosts_list,
        allowed_origins=cfg.allowed_origins_list,
    )
    inner = mcp.streamable_http_app(
        streamable_http_path=cfg.path,
        stateless_http=cfg.stateless,
        json_response=cfg.json_response,
        transport_security=security,
        host=cfg.host,
    )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    return Starlette(routes=[Mount("/", app=inner)], lifespan=lifespan)
