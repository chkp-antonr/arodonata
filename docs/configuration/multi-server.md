# Multi-Server Topology & Authentication Modes

Arodonata v2 natively manages multiple Check Point Security Management Servers (SMS) and Multi-Domain Security Management (MDSM) clusters within a single `ArodonataClient` instance.

## 1. Positional Multi-Server Configuration

Configure multiple servers by providing comma-separated lists (or JSON arrays) in `ARODONATA_MGMT_NAMES` and `ARODONATA_MGMT_SERVERS`:

```ini
ARODONATA_MGMT_NAMES=mdsm-eu,mdsm-us,sms-dmz
ARODONATA_MGMT_SERVERS=10.10.1.10:443,10.20.1.10:443,[2001:db8::10]:443
ARODONATA_API_KEY_VARS=MDSM_EU_KEY,MDSM_US_KEY,SMS_DMZ_KEY

MDSM_EU_KEY=secret-api-key-eu
MDSM_US_KEY=secret-api-key-us
SMS_DMZ_KEY=secret-api-key-dmz
```

### Indirect Secret References (`ARODONATA_API_KEY_VARS`)

Using `ARODONATA_API_KEY_VARS` is recommended for production deployments so each server's secret key resides in its own dedicated secret environment variable rather than a combined comma-separated string.

## 2. Authentication Modes (`AuthMode`)

`ArodonataSettings` automatically determines `auth_mode` using strict precedence:

1. **`"api_key"` Mode**: Active when `api_keys`, `api_key`, or `api_key_vars` are provided. Counts of `mgmt_names`, `mgmt_servers`, and `api_keys` must match exactly.
2. **`"credential"` Mode**: Active when `username` and `password` are provided (and no explicit `api_keys` are set).
3. **`"dynamic"` Mode**: Active when no static credentials or API keys are configured in `ArodonataSettings`. Callers supply per-request credentials at runtime via `with client.auth_context(username=..., password=...):` or an injected `AuthProvider` port.

## 3. Runtime Credential & Attribution Contexts

In multi-tenant web backends (such as FPCR v2), a single long-lived `ArodonataClient` can execute operations under the logged-in administrator's identity using Python `contextvars`:

```python
with (
    client.auth_context(api_key=user_api_key),
    client.user_context(
        user_id="u-1042",
        username="alice@corp.example",
        session_name="fpcr-ticket-9812",
        session_description="Automated firewall rule provisioning",
    ),
):
    async with client.write_session("mdsm-eu", "Domain4") as ws:
        await client.add_object("mdsm-eu", "host", {"name": "h-srv-99", "ipv4-address": "10.10.99.1"}, domain="Domain4")
```

- **Credential Isolation in `arodonata_sid_cache`**: Shared read-only session keys incorporate an HMAC-SHA256 digest of the active credential (`auth_identity`), ensuring two different dynamic credentials never share a cached `sid`.
