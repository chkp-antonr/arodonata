---
name: arodonata-aibuilder
description: Author, secure, and replay-test lightweight Check Point Security Management and MDSM automation scripts on top of Arodonata v2, arlogi, CPCRUD, ScriptRepositoryService, native Asset classification, and FileReplayApiMock.
---

# Arodonata AI Builder

Build concise, production-safe Python 3.13 (`uv`) automation scripts and CLI tools for Check Point Security Management (SMS) and Multi-Domain Security Management (MDSM) using **Arodonata v2** and **`arlogi`**.

## Core Principle: Delegate, Never Duplicate

Treat `arodonata` as the single authoritative engine for Check Point operations:

- **Transport, Auth, & Sessions**: Always use `ArodonataClient` (`async with ArodonataClient(...) as client:`) — never roll custom `aiohttp`/`requests` clients, manual login cooldowns, or raw `show-task` polling loops.
- **Inventory & Asset Classification**: Use `client.get_gateways(roles=..., platforms=...)`, `client.query_objects(...)`, and native `Asset` fields (`asset_role`, `platform_family`, `is_policy_target`, `is_execution_target`) — never write ad-hoc regexes on `Asset.name`, `comments`, or `tags`.
- **Policy Mutations & Reporting**: Use `client.cpcrud` (`validate`/`plan`/`apply`/`inverse`) or `client.write_session(...)` with `client.collect_change_report(...)` / `build_change_report_from_plan(...)`.
- **On-Box Execution**: Use `ScriptRepositoryService` (`client.ensure_repository_script` + `client.run_repository_script`) instead of inline one-time scripts when RBAC restricts them.

## 3-Tier Check Point API Lookup Ladder

Always verify Check Point Management API commands and payloads before writing code:

1. **Tier 1 (`arodonata.api_reference`)**: Query the bundled offline Check Point API index first (`search_api_commands()`, `describe_api_command()`, `validate_api_payload()`).
2. **Tier 2 (Bundled Quirks & MCP Docs)**: Consult [checkpoint-api-quirks.md](references/checkpoint-api-quirks.md), [checkpoint-ops-quirks.md](references/checkpoint-ops-quirks.md), or `context7` / `cp-documentation` MCP servers for MDSM Global/Local nuances, Gaia `clish`, CDT, and hotfix behavior.
3. **Tier 3 (Explicit Verification Gate)**: For undocumented commands or R81.x/R82+ nuances unconfirmed by Tiers 1–2, add an explicit `# VERIFY:` comment and validate read-only against a lab or `FileReplayApiMock` before mutating production.

## 5-Step Script Authoring Workflow

1. **Clarify Scope & Target Classification**:
   - Determine SMS (`domain=None`) vs. MDSM (`domains` / `include_global=False`), read-only vs. mutating (`--dry-run` mandatory for mutations), and single-file PEP 723 script vs. multi-file `uv` project.
   - Separate policy installation targets (`asset.is_policy_target`) from OS/CLI execution hosts (`asset.is_execution_target`) and inspect `asset.platform_family` (`gaia`, `gaia_embedded`, `maestro`, `cloudguard`, `open_server`).
2. **Verify Exact SDK & API Signatures**:
   - Check [sdk-quickref.md](references/sdk-quickref.md) before emitting any `ArodonataClient`, `ArodonataSettings`, `CPCRUDService`, `ScriptRepositoryService`, or `arodonata.testing` call.
3. **Scaffold with `arlogi` & Lifecycle Guards**:
   - Follow [cli-architecture-and-arlogi.md](references/cli-architecture-and-arlogi.md): initialize `arlogi.setup_logging(..., json_file_only=False)`, support `--dry-run`, use `:memory:` SQLite for single-shot reads or a file-backed `sqlite+aiosqlite:///...` URL for multi-step `plan`/`apply` workflows, and wrap `ArodonataClient` in `async with`.
4. **Enforce Security & Operational Quirks**:
   - **Never** log, `repr()`, or export `sid`, `api_key`, `password`, private keys, or raw auth headers.
   - Always `discard` or `publish` dirty sessions before `logout`; never sweep-discard foreign sessions on a shared MDSM (`show-session(uid=...)` -> targeted `take-over-session(uid=...)`).
   - On MDSM, never target `"Network"` ambiguously by bare name if Global Policy collides with a local layer; post-filter `show-networks` by exact `subnet4` + `mask_length4`; check `RefreshOutcome.failed_domains` before treating empty inventory as zero assets.
   - On Gaia boxes, run `cpinfo -y all` in a single pass; run `clish -c "<cmd>" < /dev/null` with `lock database override` (aborting on `CLINFR0771`); use stdlib `python3` on Gaia (`gaia` / `maestro`) and pure POSIX `sh` on Quantum Spark (`gaia_embedded`).
5. **Write & Run Offline Replay Tests First**:
   - Follow [replay-testing-guide.md](references/replay-testing-guide.md) and start from [test_script_replay.py](templates/test_script_replay.py) using `FileReplayApiMock` and `FileReplayCliMock` with zero network access.

## References (Progressive Disclosure)

- [SDK & CLI Quick-Reference](references/sdk-quickref.md) — AST-extracted `ArodonataClient`, `ArodonataSettings`, models, `CPCRUDService`, `ScriptRepositoryService`, `ChangeReport`, and `arodonata.testing` signatures.
- [Check Point Management API Quirks](references/checkpoint-api-quirks.md) — Login throttling, dirty logout locks, `show-changes`, `Any`/`Original` sentinels, `show-networks` post-filtering, and MDSM `Global` domain boundaries.
- [Check Point Operational & CLI Quirks](references/checkpoint-ops-quirks.md) — `Asset` role/platform rules, Maestro/SMB nuances, `ScriptRepositoryService`, `clish`, `cpinfo -y all`, `cplp`, `autoupdatercli`, and CDT constraints.
- [CLI Architecture & `arlogi` Bootstrap](references/cli-architecture-and-arlogi.md) — PEP 723 vs. project layout, `ArodonataSettings` env vars, SQLite lifecycle, `--dry-run`, and `arlogi` logging rules.
- [Offline Replay & Mock Testing Guide](references/replay-testing-guide.md) — `FileReplayApiMock`, `FileReplayCliMock`, `CheckPointReplayHttpServer`, `snapshot_state()`/`restore_state()`, and call-log assertions.

## Starter Templates

- [Single-File PEP 723 `uv` Script](templates/cli_script_pep723.py) — Runnable Python 3.13 CLI with `arlogi`, `--dry-run`, `ArodonataClient`, and native `Asset` filtering.
- [Multi-File `uv` Project Manifest](templates/cli_project_pyproject.toml) — `pyproject.toml` starter with `arodonata`, `arlogi`, `pytest-asyncio`, `ruff`, and `mypy`.
- [Offline Replay Test Template](templates/test_script_replay.py) — Ready-to-run `pytest` suite exercising `ArodonataClient` + `Asset` classification against `FileReplayApiMock`.
