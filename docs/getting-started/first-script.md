# Your First Script

Every interaction in Arodonata v2 goes through [`ArodonataClient`](../architecture/ports-and-adapters.md). It manages the database schema, connection pools, session lifecycle, rate limiting, and domain cache synchronization.

## 1. Read-Only Queries & Smart Caching

When you enter `async with ArodonataClient() as client:`, Arodonata automatically:

1. Verifies and migrates the 15 `arodonata_*` tables in your SQLite or PostgreSQL database (`DatabaseManager.initialize()`).
2. Schedules non-blocking cleanup of any orphaned idle Arodonata read sessions (`changes == 0` and `locks == 0`).
3. Disposes owned connections cleanly on exit (preserving persistent `arodonata_sid_cache` rows across CLI runs when using a file-backed SQLite or PostgreSQL database).

```python
import asyncio
from dotenv import load_dotenv
from arodonata import ArodonataClient


async def main() -> None:
    load_dotenv(".env")

    async with ArodonataClient() as client:
        # 1. Discover domains on all configured management servers
        domains = await client.get_domains(include_global=True)
        for dom in domains:
            print(f"{dom.mgmt_name} / {dom.name} (active IP: {dom.active_ip}, global: {dom.is_global})")

        # 2. Fetch hosts, networks, and services using smart cache synchronization
        hosts = await client.get_hosts(domain="Domain4", cache_mode="smart")
        networks = await client.get_networks(domain="Domain4", cache_mode="smart")
        services = await client.get_services(domain="Domain4", types=["tcp", "udp"], cache_mode="smart")

        print(f"Loaded {len(hosts)} hosts, {len(networks)} networks, {len(services)} services")

        # 3. Inspect gateways, clusters, and VSX topology (with human-readable asset_id & parent_asset_id)
        gateways = await client.get_gateways(domain="Domain4", cache_mode="smart")
        for gw in gateways:
            print(
                f"Asset: {gw.asset_id} ({gw.type}) IP={gw.ipv4_address} "
                f"parent={gw.parent_asset_id} members={gw.member_asset_ids}"
            )


if __name__ == "__main__":
    asyncio.run(main())
```

## 2. Understanding `cache_mode`

All read and refresh methods accept a `CacheMode`:

- `"cache"`: Read strictly from the local SQL database (`0` network calls).
- `"smart"` (default): Probes `show-last-published-session` when the domain TTL (`cache_ttl`, default `300s`) expires; reloads from the API only if a newer publish occurred.
- `"smart-fast"`: Like `"smart"`, but fetches only incremental deltas via `show-changes` (preferring `from-session` over UTC `from-date`), falling back to a full type reload if changes exceed `max_incremental_changes` (`500`).
- `"force"`: Unconditionally reloads the requested scope from the Check Point API and atomically updates the SQL cache.

## 3. Isolated Writes & Read-Your-Own-Writes (`SessionOverlay`)

Never mutate objects on the shared read-only session. Instead, open an isolated `client.write_session(mgmt_name, domain)` or call high-level mutation helpers (`add_object`, `set_object`, `delete_object`):

```python
async with ArodonataClient() as client:
    mgmt = client.settings.mgmt_names[0]

    # Opens a dedicated Check Point session outside arodonata_sid_cache
    async with client.write_session(mgmt, "Domain4", publish_on_exit=False) as ws:
        await client.add_object(
            mgmt,
            "host",
            {"name": "h-temp-app", "ipv4-address": "198.51.100.42"},
            domain="Domain4",
        )

        # SessionOverlay automatically merges uncommitted creates/updates/deletes into cache reads!
        found = await client.find_object(mgmt, "Domain4", "h-temp-app")
        assert found is not None and found.ipv4_address == "198.51.100.42"

        # Explicitly discard so nothing is published to Domain4
        await client.api_call(mgmt, "discard", {}, domain="Domain4", sid=ws.sid, server_ip=ws.server_ip)
        ws.discarded = True
```
