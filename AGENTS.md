# Arodonata v2 — AI Agent Guidelines & Engineering Standards

## 1. Spec-Driven Development (SDD) & OpenSpec

This repository strictly adheres to **Spec-Driven Development** powered by **OpenSpec**.

- **Single Source of Truth**: All capabilities, architecture decisions, requirements, and business rules are recorded in `openspec/` (`openspec/specs/`, `openspec/changes/`, `openspec/config.yaml`).
- **No Parallel Specs**: Do NOT create ad-hoc spec folders (e.g. `docs/internal/features/`). When designing or modifying features, use OpenSpec commands (`openspec change new`, `openspec validate`).
- **Language**: All specifications, code comments, documentation, and commit messages MUST be written in **English**.

---

## 2. Documentation Architecture

```text
arodonata-v2/
├── openspec/                 # [TRACKED] Canonical specs, changes, and system invariants
│   ├── config.yaml           # OpenSpec project configuration
│   └── specs/                # Deployed library capabilities
├── docs/
│   ├── guides/               # [TRACKED] Architecture, usage, and integration guides
│   ├── troubleshooting/      # [TRACKED] Post-mortems, Check Point API quirks, knowledge base
│   └── _notes/               # [IGNORED] Scratchpads, raw LLM transcripts, and temporary notes
└── README.md                 # [TRACKED] Project entry point
```

### Session Notes, Plan Archival & Task Finalization (`docs/_notes/`)

- **Task Finalizer (`/archive-task`)**: Use `/archive-task <topic>` (`.agents/workflows/archive-task.md`, `.claude/commands/archive-task.md`) as the primary finalizer to aggregate session achievements, save the note, update `CHANGELOG.md`, run all quality gates, commit to the working branch, and prepare a PR.
- **Save Plan Workflow (`/save-plan`)**: Use `/save-plan <topic>` (`.agents/workflows/save-plan.md`, `.claude/commands/save-plan.md`) to persist intermediate implementation plans or scratch notes.
- **Naming Convention**: `docs/_notes/YYMMDDHHMM-<topic>.md`:
  - `YYMMDDHHMM`: 2-digit year, month, day, hour, and minute in 24h format (e.g. `2610222230`).
  - `<topic>`: Short descriptive Latin slug with hyphens (e.g. `milestone-1-core-ports`).
  - **Single-Line Formatting**: In note files, write each paragraph and list item as a single line without hard-wrapping line breaks.
- **Git Status**: Files in `docs/_notes/` are gitignored to prevent cluttering version history while maintaining local session records.

---

## 3. Technology Stack & Architectural Invariants

- **Python Runtime**: Python 3.13 (`.python-version` specifies `3.13.5`).
- **Package Management**: `uv`. Run `uv sync` to install dependencies.
- **Hexagonal Architecture (Ports & Adapters)**:
  - Business logic in `core` depends strictly on `ApiPort` and `CachePort` protocols, never directly on HTTP transport (`aiohttp`/`cpapi`) or database drivers (`asyncpg`/`aiosqlite`).
- **Database-Backed Cache**:
  - SQLAlchemy 2.0+ async + SQLModel on PostgreSQL or SQLite with schema hash auto-migration (`arodonata_schema_version`) and distributed locks (`distributed_locks`).
- **Security Hygiene**:
  - Session identifiers (`sid`) and API keys/passwords MUST NEVER appear in logs, `repr()`, OpenTelemetry spans, error messages, or reports.
- **Observability & Logging**:
  - Provider-agnostic OpenTelemetry instrumentation (`opentelemetry-api` + `arlogi.otel.traced`); never owns or configures a global `TracerProvider`.
  - Structured logging via `arlogi`.

---

## 4. Quality Gates & Linting Standards

Always run quality checks before finishing a task or after modifying files:

```bash
# Python lint and format
uv run ruff check .
uv run ruff format --check .

# Markdown lint and auto-format (MUST run on any markdown change)
npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix

# Type checking
uv run mypy src

# Tests
uv run pytest

# OpenSpec specification validation
openspec validate --specs --no-interactive
```

### Markdown Standards & Mandatory Linting on Save

Whenever creating or modifying any Markdown file (`.md` in `openspec/`, `docs/`, `README.md`, `AGENTS.md`, etc.):

- **Mandatory Check**: Agents MUST validate and format Markdown files using `markdownlint-cli` immediately after saving or before marking a task/step as complete:

  ```bash
  npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix
  ```

- **Configuration**: Governed strictly by `.markdownlint.yaml`.
- **Key Invariants**:
  - Always leave a blank line before and after headings (`MD022`).
  - Always surround lists with blank lines (`MD032`).
  - Never allow multiple consecutive blank lines (`MD012`).
  - Keep line endings clean without trailing whitespace (`MD009`).

### Python Code Style

Configured in `.ruff.toml`:

- Line length limit: 120 characters.
- Double quotes for strings.
- Known third-party imports: `arlogi`.
- Strict typing with `mypy`.

---

## 5. Git Branching, Commit Discipline & PR Workflow

- **Git Workflow Command (`/git-workflow`)**:
  - Use `/git-workflow <pr|pr nomerge|merge|cleanup|release>` (`.agents/workflows/git-workflow.md`, `.claude/commands/git-workflow.md`) to push topic branches to `chkpar`, open Pull Requests targeting `master`, squash-merge (`gh pr merge --squash --delete-branch`), fast-forward sync `master`, and prune merged local branches.
- **Dedicated Branches Only**:
  - All operations, bug fixes, refactoring, and feature work MUST be performed in dedicated branches (e.g. `feat/<topic>`, `fix/<topic>`, `chore/<topic>`).
  - Direct commits and direct pushes to `master` are strictly prohibited.
- **Commits to Working Branch**:
  - All task commits MUST be made onto the active working branch adhering to Conventional Commits: `<type>(<scope>): <description>`.
- **Integration to `master` via PR & Squash Merge Only**:
  - Merging into `master` is executed strictly through a GitHub Pull Request (PR) with **Squash and Merge**.
  - Direct local fast-forward or non-squash merges into `master` are forbidden.
- **Ask Before Commits**:
  - Never run `git commit` or `git push` without user alignment or explicit workflow step execution.
