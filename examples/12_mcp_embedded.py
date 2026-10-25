"""Example 12 — Embedding Arodonata's MCP server inside a FastAPI application (`create_asgi_app`).

Run:
    uv run examples/12_mcp_embedded.py

Then connect an MCP client to `http://127.0.0.1:8000/mcp`.
Demonstrates:
1. Creating an `ArodonataClient` and wiring it into `create_mcp_server(client, auth_mode="host")`.
2. Registering custom application-specific tools alongside Arodonata's built-in Check Point tools.
3. Wrapping the MCP server in `create_asgi_app` and mounting it inside a FastAPI lifespan.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request, Response  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings, user_context  # noqa: E402
from arodonata.mcp import ArodonataMCPSettings, create_asgi_app, create_mcp_server  # noqa: E402

settings = ArodonataSettings()
client = ArodonataClient(settings=settings)
mcp_settings = ArodonataMCPSettings(
    server_name="acme-firewall-assistant",
    auth_mode="host",
    port=8000,
    path="/mcp",
    live_compat=True,
    cpcrud=True,
)

mcp_server = create_mcp_server(client, mcp_settings=mcp_settings)


@mcp_server.tool(
    name="acme_change_ticket",
    description="Look up the ACME change ticket that introduced a firewall rule (demo stub).",
)
async def acme_change_ticket(rule_uid: str) -> dict[str, str]:
    """Return a demo change ticket reference for `rule_uid`."""
    return {"rule_uid": rule_uid, "ticket": "CHG-2026-0001"}


mcp_app = create_asgi_app(client, mcp_server=mcp_server, mcp_settings=mcp_settings)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize ArodonataClient and the Streamable-HTTP MCP router lifespan."""
    async with client, mcp_app.router.lifespan_context(mcp_app.starlette_app):
        yield


app = FastAPI(title="ACME Firewall Assistant (Arodonata v2 MCP)", lifespan=lifespan)

EXPECTED_HOST_API_KEY = os.environ.get("ACME_HOST_API_KEY", "acme-host-demo-token-0123456789abcdef")


@app.middleware("http")
async def host_authentication_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Enclosing ASGI host authentication middleware required when `auth_mode='host'` (`I18`)."""
    if request.url.path == "/healthz":
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {EXPECTED_HOST_API_KEY}":
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    caller_id = request.headers.get("X-Client-ID", "acme-portal-user")
    with user_context(user_id=caller_id, client_id=caller_id):
        return await call_next(request)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


app.mount("/", mcp_app)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
