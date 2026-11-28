# CLI Architecture & `arlogi` Bootstrap Guide

Conventions for packaging, configuring, logging, and securing Check Point automation scripts built on **Arodonata v2** (`Python >= 3.13`, `uv`) and **`arlogi`**.

## 1. Choosing Single-File PEP 723 vs. Multi-File `uv` Project

- **Single-File PEP 723 (`templates/cli_script_pep723.py`)**:
  - Best for focused operational tools (inventory audits, hotfix compliance checks, single-domain reports, scheduled cron jobs).
  - Runs directly with `uv run path/to/script.py` without creating a separate virtualenv or `pyproject.toml`.
  - Keep `# /// script` minimal (`requires-python = ">=3.13"`, `"arodonata>=2.6.7"`, `"arlogi>=0.1.0"`).
- **Multi-File `uv` Project (`templates/cli_project_pyproject.toml`)**:
  - Best when a script grows helper modules, Jinja2/HTML renderers, custom CPCRUD planners, or a multi-module test suite.
  - Exposes an entry point under `[project.scripts]` and ships dev tooling (`pytest`, `pytest-asyncio`, `ruff`, `mypy`) in `[dependency-groups]`.

## 2. `ArodonataSettings` Configuration & SQLite Cache Lifecycle

Load settings from environment variables (`ARODONATA_*`) or pass explicit CLI overrides into `ArodonataSettings(...)`:

- **Credentials & Servers**:
  - Single server: `ARODONATA_MGMT_NAME`, `ARODONATA_MGMT_IP`, `ARODONATA_API_KEY` (or `ARODONATA_USERNAME` / `ARODONATA_PASSWORD`).
  - Multi-server MDSM: `ARODONATA_MGMT_NAMES`, `ARODONATA_MGMT_SERVERS`, `ARODONATA_API_KEY_VARS` (names of env vars holding each key).
- **TLS Verification**:
  - Default `tls_trust="tofu"` verifies against `tls_known_hosts_path`; for strict CI/CD or production automation, use `tls_trust="pinned"` with `tls_fingerprints`.
- **SQLite Cache Mode**:
  - **Single-shot read/inventory scripts**: omit `database_url` (defaults to `sqlite+aiosqlite:///:memory:`).
  - **Multi-step workflows (`plan` -> operator review -> `apply`)**: set `database_url="sqlite+aiosqlite:///./state/arodonata_cache.db"` so cached objects, rulebases, and sync checkpoints survive across CLI invocations.
- **Session Hygiene**:
  - Always open `ArodonataClient` with `async with ArodonataClient(settings=settings) as client:` so `await client.close(logout=True)` runs automatically even on exceptions.

## 3. Idiomatic `arlogi` Logging

Initialize `arlogi` once at CLI entry before running async workflows:

```python
import arlogi

arlogi.setup_logging(
    level="INFO",
    json_file_name="logs/checkpoint_cli.jsonl",
    json_file_only=False,
)
logger = arlogi.get_logger(__name__)
logger.info("gateway inventory loaded", mgmt_name="prod-mds", domain="Branch", count=42)
```

- Keep `json_file_only=False` for interactive CLI scripts so operators see readable console output while JSONL audit logs persist to disk.
- Pass structured context fields via keyword arguments (`mgmt_name=`, `domain=`, `dry_run=`, `count=`) instead of formatting sensitive payloads into message strings.

## 4. `--dry-run` Contract & Secret Hygiene

- Every script that can mutate Check Point state (objects, rules, repository scripts, `clish` config, policy install) MUST expose `--dry-run` (or default to read-only plan mode and require `--apply` / `--execute`).
- Under `--dry-run`, compute the `Plan` (`client.cpcrud.plan(...)`) or print the exact intended targets (`asset.name`, `asset.asset_role`, `asset.platform_family`), then exit `0` without opening mutating write calls or publishing changes.
- **Secret & Session Redaction**:
  - **Never** print, log, or serialize `api_key`, `password`, raw Check Point session IDs (`sid`), authentication headers, or private key material into stdout, `arlogi` logs, OpenTelemetry attributes, or generated reports.
  - When referencing session ownership in logs or reports, log only non-secret `session_uid`, `session_name`, `mgmt_name`, and `domain_name`.
