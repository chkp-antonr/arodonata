# AI Working Instructions

Always review the following documents before starting work:

- **[.internal/CONTEXT.md](.internal/CONTEXT.md)** - Project context map with chronological research and feature history
- **[.internal/AI_WORKING_MODEL.md](.internal/AI_WORKING_MODEL.md)** - How to organize artifacts and documentation for AI-human collaboration

## Commit discipline

Never run `git commit` (or `git add -A` / `git push`) without the user
explicitly asking for that specific commit first — no exceptions for
"minor" or routine-looking changes (archive-task updates, changelog
entries, formatting, etc. included). Ask before every commit, individually.

## Conventional Commits

Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `perf:`, `test:`, `ci:`,
`build:`) — enforced by a `commitizen` pre-commit hook. `CHANGELOG.md` is
generated from these messages; don't hand-edit it except inside an
`## [Unreleased]` section.

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:

- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `uv run graphify update .` to keep the graph current
