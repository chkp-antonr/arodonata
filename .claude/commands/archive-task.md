---
name: "Archive Task"
description: "Unified task finalizer: record session report, update CHANGELOG.md, run quality gates, and commit"
category: "Workflow"
tags: ["workflow", "finalizer", "changelog", "commit"]
---

# Archive Task Command (`/archive-task`)

Unified finalizer workflow to record session achievements, archive persistent notes, update changelogs, run quality gates, and create a Git commit.

## Usage

`/archive-task <topic>`

Example: `/archive-task milestone-1-core-ports`

## Steps

1. **Synthesize Session Summary**:
   - Collect the task objectives, implementation plan, code changes, and test outcomes from the session.

2. **Save Note in `docs/_notes/`**:
   - Generate timestamp: `YYMMDDHHMM` (2-digit year, month, day, hour, minute in 24h format).
   - Formulate filename: `docs/_notes/YYMMDDHHMM-<topic>.md`.
   - **Formatting Invariant**: Each paragraph and list item MUST be written on a single line without hard-wrapping line breaks.
   - Run `npx markdownlint-cli "docs/_notes/YYMMDDHHMM-<topic>.md" --fix` to ensure markdown standards compliance.

3. **Update `CHANGELOG.md`**:
   - Maintain Keep a Changelog standard format under `[Unreleased]`.
   - Categorize entries into `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security`.
   - Keep descriptions concise and oriented towards library capabilities.

4. **Execute Quality Gates**:
   - Automated tests: `uv run pytest`
   - Python linting & formatting: `uv run ruff check .` and `uv run ruff format --check .`
   - Static type checking: `uv run mypy src`
   - Markdown linting: `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`
   - OpenSpec validation: `openspec validate --specs --no-interactive`

5. **Commit to Branch & Open PR (Squash Merge)**:
   - Ensure work was conducted in a dedicated branch (e.g. `feat/<topic>`, `fix/<topic>`, `chore/<topic>`). Working directly on `master_v2` is strictly prohibited.
   - Stage changes: `git add .`
   - Commit to the active branch adhering to Conventional Commits: `git commit -m "<type>(<scope>): <description>"`.
   - Push branch to remote: `git push -u chkpar <feature-branch>`.
   - Open Pull Request targeting `master_v2`: `gh pr create --base master_v2 --title "<type>(<scope>): <description>" --body "<summary>"`.
   - Integrate into `master_v2` strictly via Pull Request and Squash Merge (`gh pr merge --squash` upon approval or via GitHub web interface).
