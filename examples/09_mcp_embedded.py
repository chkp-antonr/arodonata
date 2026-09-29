"""Serve Arodonata as an MCP endpoint inside your own FastAPI application.

Run: uv run examples/09_mcp_embedded.py
Then point an MCP client at http://127.0.0.1:8000/mcp with header "Authorization: Bearer <value of DEMO_MCP_TOKEN>".

Environment (examples/.env.lib and .env.secrets):
    DATABASE_URL=postgresql+asyncpg://...      # or sqlite+aiosqlite:///./_tmp/arodonata.db
    MGMT_NAMES=mgmt1
    MGMT_SERVERS=10.0.0.1
    API_KEY_VARS=MY_API_KEY_VAR
    ARODONATA_MCP_TOKEN_VARS=DEMO_MCP_TOKEN
    ARODONATA_MCP_PUBLIC_URL=http://127.0.0.1:8000/mcp
    DEMO_MCP_TOKEN=change-me
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import uvicorn
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.mcp import ArodonataMCPSettings, create_asgi_app, create_mcp_server


def _settings_from_env() -> ArodonataSettings:
    # ArodonataSettings() only auto-reads plain env vars; API_KEY_VARS indirection (like
    # examples/04_smart_refresh.py) must be resolved by the caller before construction.
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
client = ArodonataClient(engine=engine, settings=_settings_from_env())
mcp_settings = ArodonataMCPSettings(port=8000, path="/mcp")

# Build the server yourself so you can add application-specific tools next to the Arodonata ones.
mcp_server = create_mcp_server(client, mcp_settings, name="acme-firewall-assistant")


@mcp_server.tool()
async def acme_change_ticket(rule_uid: str) -> dict[str, str]:
    """Look up the ACME change ticket that introduced a rule (demo stub)."""
    return {"rule_uid": rule_uid, "ticket": "CHG-0001"}


mcp_app = create_asgi_app(client, mcp_settings, server=mcp_server)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # ``client.__aenter__`` already initializes the cache database and schedules the startup
    # session cleanup; do not call ``client.schedule_startup_cleanup()`` again here.
    async with client:
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
    await engine.dispose()


app = FastAPI(title="ACME firewall assistant", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


# Mount the MCP app last: it only serves its own path, but a root mount registered before
# your own routes would shadow all of them, since Starlette matches mounts in registration order.
app.mount("/", mcp_app)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
