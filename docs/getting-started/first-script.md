# Your First Script

This walks through the minimal script needed to connect to a management
server and query its hosts.

```python
import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


async def main() -> None:
    # 1. Create the database engine — the calling app owns its lifecycle:
    #    it creates the engine here and disposes it at the end.
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)

    # 2. Read MGMT_NAMES, MGMT_SERVERS and API_KEY_VARS from the process
    #    environment (load your .env first, e.g. with python-dotenv); each
    #    variable named in API_KEY_VARS holds one server's API key.
    settings = ArodonataSettings()

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

`get_hosts()` reads through the cache in the client's default `cache_mode="smart"`: a domain with nothing cached yet is loaded in full from the management server on first use, and a cached domain is reloaded only when it has been published since it was cached (checked at most once per TTL window). So the first run against a fresh database returns the server's hosts, it just takes longer. Pass `cache_mode="cache"` (to the call or to `ArodonataClient`) to read only what is already cached, without calling the API. To populate or refresh the cache up front, see [`refresh_objects`](../api/arodonata/api/client.md) and [Smart Refresh](../examples/04-smart-refresh.md).

## First run against a server

The first time the script connects to a management server, Arodonata trusts the certificate that server presents and records its SHA-256 fingerprint in a trust store, `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json` by default (set `ARODONATA_TLS_KNOWN_HOSTS_PATH` to put it elsewhere, for example in a container with a read-only home).
You will see one WARNING per server, `TLS <host>:<port>: first contact, certificate <fingerprint> trusted and recorded in <path>`.
From then on a different certificate at that address is refused before anything is sent.
To pin fingerprints you took from the server yourself instead of trusting the first contact, see [TLS Verification](../configuration/tls-verification.md).
