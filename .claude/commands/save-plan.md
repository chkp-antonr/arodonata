---
name: "Save Plan"
description: "Save the current implementation plan or session notes to docs/_notes/YYMMDDHHMM-<topic>.md"
category: "Documentation"
tags: ["plan", "notes", "workflow"]
---

# Save Plan & Session Notes Command

Save the active `implementation_plan.md` or current session plan to `docs/_notes/`.

## Input

- **`<topic>`**: Short descriptive topic slug (Latin lowercase, hyphen-separated, e.g. `milestone-1-core-ports`, `session-pool`, `cpcrud-engine`).
- **Content**: Either the active `implementation_plan.md` artifact from the session, or user-provided notes/plan text.

## File Naming Convention

All persistent planning notes MUST be stored under:

`docs/_notes/YYMMDDHHMM-<topic>.md`

Where:

- `YY`: 2-digit year (e.g., `26` for 2026)
- `MM`: 2-digit month (`01`-`12`)
- `DD`: 2-digit day of month (`01`-`31`)
- `HH`: 2-digit hour in 24-hour format (`00`-`23`)
- `MM`: 2-digit minute (`00`-`59`)
- `<topic>`: Short Latin slug with hyphens (e.g., `milestone-1-core-ports`)

## Execution Steps

1. **Resolve Timestamp & Target Path**:
   - Determine local date and time: `YYMMDDHHMM`.
   - Infer or extract `<topic>` from user argument or session context.
   - Construct target path: `docs/_notes/YYMMDDHHMM-<topic>.md`.

2. **Retrieve Plan Content**:
   - Read the current `implementation_plan.md` artifact from the Antigravity session directory (or context).
   - If user provided custom text in the command, use that content.

3. **Write File**:
   - Ensure `docs/_notes/` directory exists.
   - Write the markdown content to `docs/_notes/YYMMDDHHMM-<topic>.md`.

4. **Verify Markdown Quality**:
   - Run `npx markdownlint-cli "docs/_notes/YYMMDDHHMM-<topic>.md" --fix`.

5. **Report Result**:
   - Output the relative path to the saved note so the user can easily reference it.
