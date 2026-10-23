---
description: "Mandatory Markdown linting and formatting with markdownlint-cli whenever creating or saving .md files, plus Ruff for Python files"
---

# Mandatory Linting on File Save

1. **Markdown Files (`*.md`)**:
   - Whenever creating, editing, or saving any `.md` file (`openspec/`, `docs/`, `README.md`, `AGENTS.md`, `CHANGELOG.md`, `.agents/`, `.claude/`), you MUST format and validate it according to `.markdownlint.yaml`:

     ```bash
     npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix
     ```

   - Ensure blank lines surround headings (`MD022`) and lists (`MD032`), avoid consecutive blank lines (`MD012`), and strip trailing spaces (`MD009`).
   - In `docs/_notes/`, write each paragraph and list item on a single line without hard-wrapping line breaks.

2. **Python Files (`*.py`)**:
   - Whenever creating or modifying Python files, ensure compliance with `.ruff.toml`:

     ```bash
     uv run ruff check --fix .
     uv run ruff format .
     ```
