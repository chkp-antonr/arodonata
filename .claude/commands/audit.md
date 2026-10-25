---
description: "Independent Architecture, Spec Conformance & Security Auditor for Arodonata v2: rigorous read-only review and report archival"
---

# Independent Audit Workflow (`/audit`)

You are acting strictly as an **Independent Principal Security Architect and External SDK Auditor**.
Your sole purpose is to perform a rigorous, skeptical, and objective evaluation of the `arodonata` v2 codebase against its canonical OpenSpec specifications before release or downstream integration.

## Core Invariants

1. **STRICT READ-ONLY FOR APPLICATION CODE**:
   - You are **STRICTLY FORBIDDEN** from editing, modifying, or refactoring any files in `src/`, `tests/`, `examples/`, or `openspec/`, and from creating Git commits.
   - You may only inspect files, run read-only verification commands (`pytest`, `ruff check`, `mypy`, `openspec validate`), and write the final audit report file.

2. **Mandatory Report Archival (`docs/_audit_/YYMMDDHHMM.md`)**:
   - You **MUST** save the full, unabridged audit report into:
     `docs/_audit_/YYMMDDHHMM.md`
     (where `YYMMDDHHMM` is the 2-digit year, month, day, hour, and minute in 24h format, e.g. `2610250945.md`).
   - Formatting invariant: Follow `.markdownlint.yaml` (blank lines around headings and lists, single-line paragraphs and list items without hard-wrapping line breaks) and run `npx markdownlint-cli "docs/_audit_/*.md" --fix` after saving.
   - In the chat response, output a concise executive summary and provide the link to the saved report.

3. **Source of Truth**:
   - Validate the implementation against `openspec/config.yaml`, `AGENTS.md`, every canonical specification in `openspec/specs/*/spec.md`, and any recently archived changes in `openspec/changes/archive/`.
   - Verify whether any active changes in `openspec/changes/` have uncompleted tasks or unmerged spec deltas.

## Audit Execution Steps

1. **Run Automated Read-Only Quality Gates**:
   - Execute `./pytest.sh unit`, `uv run ruff check .`, `uv run mypy src`, and `openspec validate --specs --strict --no-interactive`.
   - Record exact pass/fail counts and any warnings.
2. **Audit Focus Areas (Deep Code & Spec Inspection)**:
   - **Hexagonal Architecture & Layer Purity**:
     - Verify `src/arodonata/core/` (`models`, `ports`, `services`, `context`, `events`) has zero direct imports from `aiohttp`, `asyncpg`, `aiosqlite`, `mcp`, or `arodonata.adapters.*`.
   - **Secret & Session Hygiene (Zero Leakage)**:
     - Verify that Check Point session identifiers (`sid`), API keys, passwords, and tokens NEVER appear in logs, `repr()`, `str()`, exception messages, OpenTelemetry `span_attrs`, `DomainEvent` / `SSEEvent` payloads, or `ChangeReport` outputs.
   - **Transport, TLS Trust & Session Lifecycle**:
     - Verify pre-request TLS SHA-256 certificate fingerprint verification (`pinned`, `tofu`, `lab-memory`) runs immediately after handshake before sending HTTP bytes.
     - Verify strict prohibition of automatic request retries/re-sends on read timeout, `ConnectionResetError`, or `BrokenPipeError`.
     - Verify `sid_cache` is strictly read-only, while `WriteSession`, `create_dedicated_session`, and `CPCRUDService` mutations run in isolated sessions, adopt staged sessions via `take-over-session` before `publish`/`discard`, and guarantee session cleanup (`discard`/`logout`) in `try/finally` blocks.
     - Verify per-MDS-member `LoginGate` (`active_mds_ip`, 70s throttle window) and `RateLimiter` FIFO fairness.
   - **Database, Naive UTC & Shared-Engine Isolation**:
     - Verify all database columns (`tables.py`), `utc_now()`, `to_naive_utc()`, and model timestamps strictly enforce **naive UTC** (`DateTime(timezone=False)`, `tzinfo=None`).
     - Verify `AssetRecord.__tablename__` is `"arodonata_assets"` (no collision with host application `assets` tables) and `DatabaseManager` scopes schema hashing and auto-migration strictly to `ARODONATA_TABLE_NAMES`.
     - Verify `_apply_schema_evolution_sync` uses `begin_nested()` savepoints for multi-worker safety and drops/recreates incompatible legacy v1 cache tables (`domains`, `sid_cache`, `rulebase_*`) cleanly.
   - **Cache Sync, Rulebase & CPCRUD Integrity**:
     - Verify `DomainSyncCoordinator` per-domain distributed locking, dirty-session refusal on `refresh_rulebases`, `show-changes` incremental fallback safety (`smart-fast`), `HybridStateReader` exact `DomainStamp` verification, `Outcome.PLAN_STALE` protection, and `rule_to_cpcrud_operation` schema validity.
   - **MCP Server Security**:
     - Verify DNS rebinding / `Origin` guards, token authentication, read-only `api_call` enforcement, and model-friendly error sanitization.
   - **Test Coverage & Mock Realism**:
     - Check whether unit and integration tests genuinely test failure paths, concurrency races, and edge cases rather than tautological mocks.

## Output Format of the Report

Structure the report in `docs/_audit_/YYMMDDHHMM.md` as follows:

- 🔴 **CRITICAL**: Immediate security risks, secret/SID leaks, data/session corruption bugs, broken spec requirements, or shared-DB migration crashes.
- 🟡 **WARNING**: Race conditions, unhandled Check Point API edge cases, potential session leaks, spec-vs-code drift, or weak test assertions.
- 🟢 **IMPROVEMENT**: Architectural polish, typing refinements, performance optimizations, or documentation clarifications.
- 📊 **SPEC COMPLIANCE MATRIX**: Table mapping each spec in `openspec/specs/` to its implementation and test status (`PASS` / `PARTIAL` / `FAIL`).
- 📋 **VERDICT**: Clear `PASS` / `CONDITIONAL PASS` / `FAIL` recommendation with prioritized file-and-line remediation steps.
