---
description: "Strict git branching rule: all work in separate branches, commit there, merge to master only via PR and squash merge"
---

# Git Branching & PR Invariant

1. **Dedicated Branches Only**:
   - Every operation, code modification, feature addition, refactor, and documentation task MUST be carried out in a separate branch (e.g. `feat/<topic>`, `fix/<topic>`, `chore/<topic>`).
   - Direct work and direct commits on `master` are strictly prohibited.

2. **Branch Commits**:
   - Commit all changes into the active working branch adhering to Conventional Commits format (`feat:`, `fix:`, `docs:`, `chore:`, etc.).
   - Never push directly to `master`.

3. **Master Integration via PR & Squash Merge**:
   - Integration into `master` is performed exclusively via Pull Request (PR) with **Squash and Merge** (`gh pr create` -> `gh pr merge --squash` or via GitHub web interface).
   - Never fast-forward merge into `master` locally without a squash PR.
