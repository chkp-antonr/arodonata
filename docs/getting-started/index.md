# Getting Started

## Requirements

- Python 3.13+
- A PostgreSQL 12+ database for the cache layer

## Install

=== "uv (recommended)"

    ```bash
    uv pip install arodonata
    ```

=== "pip"

    ```bash
    pip install arodonata
    ```

For local development against a clone of this repo:

```bash
uv sync --dev
```

## Configure your environment

Arodonata does not read `.env` files itself — the calling application resolves
configuration (e.g. via `python-dotenv`) and passes explicit values into
[`ArodonataSettings`](../api/arodonata/config/settings.md).
The calling app owns the database engine lifecycle and passes the engine directly to
`ArodonataClient`. Typical `.env` for local development:

```bash
# Database cache
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache

# Management server details (comma-separated, matched by position)
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

# Secrets — the actual key values, referenced by the variable names above
PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

See the [Configuration Guide](../configuration/index.md) for every setting.

## Next step

Continue to [Your First Script](first-script.md) for a minimal end-to-end
example, or jump to [Examples](../examples/index.md) for more complete
scripts.
