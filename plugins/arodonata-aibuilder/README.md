# Arodonata AI Builder (`arodonata-aibuilder`)

Repository-hosted multi-agent plugin bundle for authoring, securing, and replay-testing lightweight Check Point Security Management and MDSM automation scripts on top of **Arodonata v2** and **`arlogi`**.

## What Is Included

- **Manifests**:
  - `plugin.json`: Antigravity plugin manifest (strictly supported top-level fields and 3 `suggestedPrompts`).
  - `.claude-plugin/plugin.json`: Claude Code plugin manifest.
- **Portable Skill (`skills/arodonata-aibuilder/`)**:
  - `SKILL.md`: Primary skill encoding "Delegate, Never Duplicate", the 3-Tier Check Point API Lookup Ladder, a 5-step script-authoring workflow, and strict SID/secret hygiene.
  - `references/sdk-quickref.md`: Deterministic AST-derived Arodonata v2 & `arlogi` signature cheat sheet (synced).
  - `references/checkpoint-api-quirks.md`: Check Point Management API & MDSM pitfalls (synced).
  - `references/checkpoint-ops-quirks.md`: Asset classification, Gaia `python3` vs. Gaia Embedded `sh`, `cpinfo`, `clish`, and CDT rules (synced).
  - `references/cli-architecture-and-arlogi.md`: Standalone PEP 723 vs. project layout, `ArodonataSettings`, `arlogi`, and `--dry-run` patterns.
  - `references/replay-testing-guide.md`: Zero-socket offline testing with `FileReplayApiMock`, `FileReplayCliMock`, and `CheckPointReplayHttpServer`.
  - `templates/`: Verified Python 3.13 / `uv` starters (`cli_script_pep723.py`, `cli_project_pyproject.toml`, `test_script_replay.py`).

## Why `mcp_config.json` Is Omitted

This plugin intentionally does **not** bundle an `mcp_config.json` file because Check Point Management hostnames, MDSM credentials, API keys, and TLS trust stores (`tofu` / pinned SHA-256 fingerprints) differ per operator environment. Configure `arodonata-mcp` in your local client configuration when needed.

## Multi-Agent Installation

### Antigravity

Symlink or copy `plugins/arodonata-aibuilder` into your Antigravity plugins directory:

```bash
ln -s /path/to/arodonata_v2/plugins/arodonata-aibuilder ~/.gemini/config/plugins/arodonata-aibuilder
```

### Claude Code

Register or install the plugin directory containing `.claude-plugin/plugin.json` using Claude Code's local plugin marketplace/directory workflow:

```bash
claude plugin add /path/to/arodonata_v2/plugins/arodonata-aibuilder
```

### Codex CLI, Cursor, and Gemini CLI

Point your agent's skills loader to (or copy) the self-contained skill directory:

```bash
ln -s /path/to/arodonata_v2/plugins/arodonata-aibuilder/skills/arodonata-aibuilder ~/.agents/skills/arodonata-aibuilder
```

## Reference Synchronization

`sdk-quickref.md`, `checkpoint-api-quirks.md`, and `checkpoint-ops-quirks.md` inside `skills/arodonata-aibuilder/references/` are generated deterministically from `src/arodonata` and `docs/troubleshooting/`. Whenever SDK signatures or quirk guides change, run:

```bash
uv run python docs/scripts/build_notebooklm_docs.py
```

Hand-authored guides (`cli-architecture-and-arlogi.md` and `replay-testing-guide.md`) are preserved across synchronization runs.
