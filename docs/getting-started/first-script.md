# Your First Script

This walks through the minimal script needed to connect to a management
server and query its hosts.

```python
import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


async def main() -> None:
    # 1. Create the database engine — Arodonata manages the engine's lifecycle
    #    for you, but the calling app owns creating and disposing it.
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)

    settings = ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=os.getenv("PRIMARY_MGMT_KEY", "mock-key"),
    )

    client = ArodonataClient(engine=engine, settings=settings)

    try:
        # 3. The async context manager owns session lifecycle (login,
        #    keepalive, cleanup on exit).
        async with client:
            for server_name in client.get_mgmt_names():
                hosts = await client.get_hosts(mgmt_names=[server_name])
                print(f"{server_name}: {len(hosts)} hosts")
                for host in hosts[:5]:
                    print(f"  {host.name} -> {host.ip_address}")
    finally:
        # 4. The engine is yours to dispose.
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
```

This queries `get_hosts()` straight from the cache — nothing is populated in
it yet on a fresh database, so the first run against an empty cache returns
an empty list. See
[`build_refresh_assets_cache`](../api/arodonata/api/client.md) and the
[Examples](../examples/index.md) section for how to populate it.

## First run against a server

The first time the script connects to a management server, Arodonata trusts the certificate that server presents and records its SHA-256 fingerprint in a trust store, `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json` by default (set `ARODONATA_TLS_KNOWN_HOSTS_PATH` to put it elsewhere, for example in a container with a read-only home).
You will see one WARNING per server, `TLS <host>:<port>: first contact, certificate <fingerprint> trusted and recorded in <path>`.
From then on a different certificate at that address is refused before anything is sent.
To pin fingerprints you took from the server yourself instead of trusting the first contact, see [TLS Verification](../configuration/tls-verification.md).
