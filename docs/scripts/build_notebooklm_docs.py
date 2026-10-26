"""Regenerate docs-notebooklm/*.md and prepare docs/arodonata-v2-complete.md for build-docs.

Run after documentation or API changes:

    uv run python docs/scripts/build_notebooklm_docs.py

Produces four self-contained Markdown knowledge bundles in `docs-notebooklm/` sized for
Google NotebookLM / Claude Projects / Gemini Gems:

  01-guide-and-concepts.md                    - Complete narrative documentation (overview,
                                                getting started, architecture, 15-table DB
                                                schema, caching/sync, sessions/overlays,
                                                CPCRUD, MCP server & consolidated tools,
                                                configuration, change reports, testing)
  02-api-reference.md                         - Every public class, SQLModel table, function,
                                                and method in `src/arodonata`, extracted
                                                directly from source via `ast`
  03-examples-and-recipes.md                  - All 12 progressive examples (`01`..`12`) with
                                                resolved `--8<--` snippets and helper scripts
  04-capabilities-db-mcp-and-openspec.md      - Downstream integration guide (`CAPABILITIES.md`),
                                                exact SQLModel table definitions (`tables.py`),
                                                MCP tool registrations, and all 10 OpenSpec
                                                system specifications (`openspec/specs/*/spec.md`)

Also writes `docs/_build_bundle/arodonata-v2-docs/` so running:

    node ~/.claude/docs-build/build-docs.js docs/_build_bundle/arodonata-v2-docs --out docs/_html

generates a single portable HTML documentation suite at `docs/_html/arodonata-v2-docs.html`.
"""

from __future__ import annotations

import ast
import re
import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent.parent
DOCS = REPO / "docs"
SRC = REPO / "src" / "arodonata"
EXAMPLES = REPO / "examples"
OPENSPEC_SPECS = REPO / "openspec" / "specs"
OUT = REPO / "docs-notebooklm"
BUNDLE_DIR = DOCS / "_build_bundle" / "arodonata-v2-docs"

SNIPPET_RE = re.compile(r'^--8<-- "(.+?)"\s*$', re.MULTILINE)


def _resolve_snippets(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        full = REPO / m.group(1)
        if full.exists():
            return full.read_text(encoding="utf-8").rstrip("\n")
        return f"[MISSING SNIPPET: {m.group(1)}]"

    return SNIPPET_RE.sub(repl, text)


def _code_block(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text.rstrip()}\n```"


# ---------------------------------------------------------------------------
# AST extraction: pull public classes/functions/methods straight from source
# ---------------------------------------------------------------------------


def _get_docstring(node: ast.AsyncFunctionDef | ast.ClassDef | ast.FunctionDef | ast.Module) -> str:
    ds = ast.get_docstring(node)
    return ds.strip() if ds else ""


def _decorators(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
    out: list[str] = []
    for d in node.decorator_list:
        with suppress(Exception):
            out.append("@" + ast.unparse(d))
    return out


def _format_arg(a: ast.arg, defaults_map: dict[str, str]) -> str:
    ann = ""
    if a.annotation is not None:
        try:
            ann = f": {ast.unparse(a.annotation)}"
        except Exception:
            ann = ""
    return f"{a.arg}{ann}{defaults_map.get(a.arg, '')}"


def _format_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    parts: list[str] = []
    posonly = list(getattr(args, "posonlyargs", []))
    all_pos = posonly + list(args.args)
    n_no_default = len(all_pos) - len(args.defaults)
    defaults_map: dict[str, str] = {}
    for i, d in enumerate(args.defaults):
        arg = all_pos[n_no_default + i]
        try:
            defaults_map[arg.arg] = f" = {ast.unparse(d)}"
        except Exception:
            defaults_map[arg.arg] = " = ..."

    for i, a in enumerate(all_pos):
        parts.append(_format_arg(a, defaults_map))
        if posonly and i == len(posonly) - 1:
            parts.append("/")

    if args.vararg:
        parts.append(f"*{_format_arg(args.vararg, {})}")
    elif args.kwonlyargs:
        parts.append("*")

    for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=False):
        dm: dict[str, str] = {}
        if d is not None:
            try:
                dm[a.arg] = f" = {ast.unparse(d)}"
            except Exception:
                dm[a.arg] = " = ..."
        parts.append(_format_arg(a, dm))

    if args.kwarg:
        parts.append(f"**{_format_arg(args.kwarg, {})}")

    ret = ""
    if node.returns is not None:
        try:
            ret = f" -> {ast.unparse(node.returns)}"
        except Exception:
            ret = ""

    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({', '.join(parts)}){ret}"


def _process_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    return {
        "signature": _format_signature(node),
        "docstring": _get_docstring(node),
        "decorators": _decorators(node),
    }


def _process_class(node: ast.ClassDef) -> dict[str, Any]:
    bases: list[str] = []
    for b in node.bases:
        with suppress(Exception):
            bases.append(ast.unparse(b))

    class_vars: list[str] = []
    methods: list[dict[str, Any]] = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if item.name.startswith("_") and item.name != "__init__":
                continue
            methods.append(_process_function(item))
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            try:
                ann = ast.unparse(item.annotation)
            except Exception:
                ann = ""
            default = ""
            if item.value is not None:
                with suppress(Exception):
                    default = f" = {ast.unparse(item.value)}"
            class_vars.append(f"{item.target.id}: {ann}{default}")

    return {
        "name": node.name,
        "bases": bases,
        "decorators": _decorators(node),
        "docstring": _get_docstring(node),
        "methods": methods,
        "class_vars": class_vars,
    }


def _process_module(path: Path, relpath: str) -> dict[str, Any]:
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return {"path": relpath, "error": str(e)}

    mod: dict[str, Any] = {
        "path": relpath,
        "docstring": _get_docstring(tree),
        "classes": [],
        "functions": [],
    }
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            mod["classes"].append(_process_class(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            mod["functions"].append(_process_function(node))
    return mod


def extract_modules() -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    for path in sorted(SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(SRC.parent).as_posix()
        modules.append(_process_module(path, rel))
    return modules


GROUP_TITLES: dict[str, str] = {
    "(root)": "Top-Level Package & ArodonataClient Facade (`arodonata`, `arodonata.client`)",
    "core": "core — Configuration, Contexts, Models, Hexagonal Ports, Sync & Search Services",
    "adapters": "adapters — Check Point Transport (`AMgmtClient`), SQL Storage (15 Tables) & SSE",
    "rulebase": "rulebase — Cached Rulebase Source, SmartConsole Numbering & Local Filtering",
    "cpcrud": "cpcrud — Declarative Policy-as-Code Engine (Validator, Planner, Executor, Inverse)",
    "reports": "reports — Auditable Session Change Report Collector & Multi-Format Renderer",
    "mcp": "mcp — Streamable-HTTP Model Context Protocol Server & Consolidated Tools",
}
GROUP_ORDER = list(GROUP_TITLES.keys())


def _render_docstring(ds: str) -> str:
    return (ds if ds else "_No docstring._") + "\n"


def _render_function(fn: dict[str, Any], level: int) -> str:
    h = "#" * level
    out = [f"{h} `{fn['signature']}`\n"]
    if fn.get("decorators"):
        out.append(_code_block("\n".join(fn["decorators"]), "python"))
    out.append(_render_docstring(fn["docstring"]))
    return "\n".join(out)


def _render_class(cls: dict[str, Any], level: int) -> str:
    h = "#" * level
    bases = f"({', '.join(cls['bases'])})" if cls["bases"] else ""
    out = [f"{h} class `{cls['name']}{bases}`\n"]
    if cls.get("decorators"):
        out.append(_code_block("\n".join(cls["decorators"]), "python"))
    out.append(_render_docstring(cls["docstring"]))
    if cls["class_vars"]:
        out.append(f"{h}# Fields / Class Variables\n")
        out.append(_code_block("\n".join(cls["class_vars"]), "python"))
    if cls["methods"]:
        out.append(f"{h}# Methods\n")
        for meth in cls["methods"]:
            out.append(_render_function(meth, level + 2))
    return "\n".join(out)


def _render_module(mod: dict[str, Any], level: int) -> str:
    h = "#" * level
    out = [f"{h} `{mod['path']}`\n"]
    if mod.get("error"):
        out.append(f"_Parse error: {mod['error']}_\n")
        return "\n".join(out)
    if mod.get("docstring"):
        out.append(_render_docstring(mod["docstring"]))
    if not mod.get("classes") and not mod.get("functions"):
        out.append("_No public classes or functions in this module._\n")
        return "\n".join(out)
    if mod.get("functions"):
        out.append(f"{h}# Module-Level Functions\n")
        for fn in mod["functions"]:
            out.append(_render_function(fn, level + 2))
    for cls in mod.get("classes", []):
        out.append(_render_class(cls, level + 1))
    return "\n".join(out)


def build_api_reference() -> str:
    modules = extract_modules()
    groups: dict[str, list[dict[str, Any]]] = {}
    for m in modules:
        parts = m["path"].split("/")
        group = "(root)" if len(parts) == 2 else parts[1]
        groups.setdefault(group, []).append(m)

    order = [g for g in GROUP_ORDER if g in groups] + [g for g in groups if g not in GROUP_ORDER]

    parts = [
        "# Arodonata v2 — Full API Reference\n",
        "Complete, auto-generated reference of every public class, SQLModel table, function, and "
        "method in the `arodonata` v2.0.0 package, extracted directly from `src/arodonata` via AST.\n",
        "## Package Map\n",
    ]
    for g in order:
        parts.append(f"- **{GROUP_TITLES.get(g, g)}** — {len(groups[g])} module(s)")
    parts.append("")

    for g in order:
        parts.append(f"\n---\n\n## {GROUP_TITLES.get(g, g)}\n")
        for mod in sorted(groups[g], key=lambda m: m["path"]):
            parts.append(_render_module(mod, 3))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Build: guide & concepts (file 1)
# ---------------------------------------------------------------------------

GUIDE_SOURCES: list[tuple[str, str, str]] = [
    ("00-index.md", "Overview & Quickstart", "index.md"),
    ("01-getting-started.md", "Getting Started — Installation & Setup", "getting-started/index.md"),
    ("02-first-script.md", "Getting Started — Your First Script", "getting-started/first-script.md"),
    ("03-cpcrud-quickstart.md", "Getting Started — CPCRUD Quickstart", "getting-started/cpcrud.md"),
    ("04-capabilities.md", "Capabilities & Downstream Integration Guide", "CAPABILITIES.md"),
    ("05-architecture-overview.md", "Architecture — Overview", "architecture/index.md"),
    ("06-ports-and-adapters.md", "Architecture — Hexagonal Ports & Adapters", "architecture/ports-and-adapters.md"),
    ("07-database-schema.md", "Architecture — Database Schema (15 Tables)", "architecture/database-schema.md"),
    ("08-caching-and-sync.md", "Architecture — Caching, Incremental Sync & Search", "architecture/caching-and-sync.md"),
    ("09-sessions-and-mdm.md", "Architecture — Sessions, MDSM & SessionOverlay", "architecture/sessions-and-mdm.md"),
    ("10-cpcrud-architecture.md", "Architecture — CPCRUD Engine Internals", "architecture/cpcrud.md"),
    ("11-mcp-server.md", "MCP Server & Consolidated Tool Surface", "mcp/index.md"),
    ("12-user-guide-cpcrud.md", "User Guide — Declarative CPCRUD Operations", "user-guide/cpcrud.md"),
    ("13-change-report.md", "User Guide — Auditable Change Reports", "user-guide/change-report.md"),
    ("14-configuration.md", "Configuration — Environment & Settings", "configuration/index.md"),
    ("15-multi-server.md", "Configuration — Multi-Server Topology & Auth", "configuration/multi-server.md"),
    ("16-tls-verification.md", "Configuration — TLS Certificate Verification", "configuration/tls-verification.md"),
    ("17-testing.md", "Development — Testing & Quality Gates", "development/testing.md"),
    ("18-changelog.md", "Project Changelog (v2.0.0)", "CHANGELOG.md"),
]


def build_guide() -> str:
    parts = [
        "# Arodonata v2 — Concepts, Architecture & User Guide\n",
        "This document is the consolidated narrative guide to **Arodonata v2 (`2.0.0`)**: "
        "hexagonal architecture, the 15 `arodonata_*` SQLModel cache tables, incremental sync, "
        "isolated write sessions with `SessionOverlay`, the declarative `CPCRUD` engine, "
        "auditable change reports, and the consolidated Model Context Protocol (MCP) server.\n",
    ]
    for _, title, relpath in GUIDE_SOURCES:
        parts.append(f"\n---\n\n## {title}\n")
        parts.append(f"*(source: `docs/{relpath}`)*\n")
        raw = (DOCS / relpath).read_text(encoding="utf-8")
        parts.append(_resolve_snippets(raw))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Build: examples & recipes (file 3)
# ---------------------------------------------------------------------------

EXAMPLE_MD_FILES: list[tuple[str, str]] = [
    ("20-examples-catalog.md", "examples/index.md"),
    ("21-example-01-basic-queries.md", "examples/01-basic-queries.md"),
    ("22-example-02-search-and-query.md", "examples/02-search-and-query.md"),
    ("23-example-03-gateway-relationships.md", "examples/03-gateway-relationships.md"),
    ("24-example-04-smart-refresh.md", "examples/04-smart-refresh.md"),
    ("25-example-05-rulebase-queries.md", "examples/05-rulebase-queries.md"),
    ("26-example-06-session-basics.md", "examples/06-session-basics.md"),
    ("27-example-07-context-and-overlay.md", "examples/07-context-and-overlay.md"),
    ("28-example-08-cpcrud-operations.md", "examples/08-cpcrud-operations.md"),
    ("29-example-09-cpcrud-inverse.md", "examples/09-cpcrud-inverse.md"),
    ("30-example-10-change-report-evidence.md", "examples/10-change-report-evidence.md"),
    ("31-example-11-otel-tracing.md", "examples/11-otel-tracing.md"),
    ("32-example-12-mcp-embedded.md", "examples/12-mcp-embedded.md"),
]


def build_examples() -> str:
    parts = [
        "# Arodonata v2 — Runnable Examples & Recipes (01..12)\n",
        "Worked examples showing common tasks with Arodonata v2: basic queries, multi-term search "
        "and structured cross-domain aggregation (`query_objects`), gateway/cluster/VSX relationships, "
        "paired streaming and batch smart refresh, rulebase queries and local filtering, session "
        "lifecycle, `WriteSession` + `SessionOverlay` read-your-own-writes isolation, declarative "
        "CPCRUD (`plan`/`apply`/`inverse`), auditable change reports (`OwnedSession` live numbering "
        "vs published cached numbering), OpenTelemetry tracing, and embedded FastAPI MCP servers.\n",
    ]
    for _, relpath in EXAMPLE_MD_FILES:
        text = (DOCS / relpath).read_text(encoding="utf-8")
        parts.append(f"\n---\n\n*(source: `docs/{relpath}`)*\n")
        parts.append(_resolve_snippets(text))

    guard = EXAMPLES / "_session_guard.py"
    if guard.exists():
        parts.append("\n---\n\n### Helper used by mutating lab examples: `examples/_session_guard.py`\n")
        parts.append(_code_block(guard.read_text(encoding="utf-8"), "python"))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Build: Capabilities, DB Schema, MCP Tool Specs & Canonical OpenSpec (file 4)
# ---------------------------------------------------------------------------


def build_capabilities_and_specs() -> str:
    parts = [
        "# Arodonata v2 — Capabilities, DB Schema, MCP Surface & Canonical OpenSpec Specifications\n",
        "This bundle combines the Downstream Integration Guide (`docs/CAPABILITIES.md`), "
        "the complete 15-table SQLModel database schema (`docs/architecture/database-schema.md` + "
        "`src/arodonata/adapters/storage/tables.py`), the consolidated MCP Server specification "
        "(`docs/mcp/index.md`), and all 10 canonical OpenSpec capability specifications "
        "(`openspec/specs/*/spec.md`).\n",
        "\n---\n\n## Part 1: Downstream Integration Guide (`docs/CAPABILITIES.md`)\n",
        _resolve_snippets((DOCS / "CAPABILITIES.md").read_text(encoding="utf-8")),
        "\n---\n\n## Part 2: 15-Table Database Schema (`docs/architecture/database-schema.md`)\n",
        _resolve_snippets((DOCS / "architecture/database-schema.md").read_text(encoding="utf-8")),
        "\n---\n\n### Canonical SQLModel Table Definitions (`src/arodonata/adapters/storage/tables.py`)\n",
        _code_block((SRC / "adapters" / "storage" / "tables.py").read_text(encoding="utf-8"), "python"),
        "\n---\n\n## Part 3: Consolidated MCP Server & Tools (`docs/mcp/index.md`)\n",
        _resolve_snippets((DOCS / "mcp/index.md").read_text(encoding="utf-8")),
        "\n---\n\n## Part 4: Canonical OpenSpec System Specifications (`openspec/specs/`)\n",
    ]

    for spec_path in sorted(OPENSPEC_SPECS.glob("*/spec.md")):
        cap_name = spec_path.parent.name
        parts.append(f"\n---\n\n### OpenSpec Capability: `{cap_name}` (`openspec/specs/{cap_name}/spec.md`)\n")
        parts.append(spec_path.read_text(encoding="utf-8"))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Prepare flat ordered directory for `~/.claude/docs-build/build-docs.js`
# ---------------------------------------------------------------------------


def prepare_build_docs_bundle() -> None:
    if BUNDLE_DIR.exists():
        shutil.rmtree(BUNDLE_DIR)
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Start here (index.md)
    index_text = _resolve_snippets((DOCS / "index.md").read_text(encoding="utf-8"))
    (BUNDLE_DIR / "index.md").write_text(index_text, encoding="utf-8")

    # 2. Guides (unnumbered top-level guides: CAPABILITIES, DATABASE_SCHEMA, MCP_SERVER)
    (BUNDLE_DIR / "CAPABILITIES.md").write_text(
        _resolve_snippets((DOCS / "CAPABILITIES.md").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (BUNDLE_DIR / "DATABASE_SCHEMA.md").write_text(
        _resolve_snippets((DOCS / "architecture/database-schema.md").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (BUNDLE_DIR / "MCP_SERVER.md").write_text(
        _resolve_snippets((DOCS / "mcp/index.md").read_text(encoding="utf-8")),
        encoding="utf-8",
    )

    # 3. Details (numbered 01..32 in exact reading order)
    for bundle_name, _, relpath in GUIDE_SOURCES:
        if relpath in ("index.md", "CAPABILITIES.md", "architecture/database-schema.md", "mcp/index.md"):
            continue
        content = _resolve_snippets((DOCS / relpath).read_text(encoding="utf-8"))
        (BUNDLE_DIR / bundle_name).write_text(content, encoding="utf-8")

    for bundle_name, relpath in EXAMPLE_MD_FILES:
        content = _resolve_snippets((DOCS / relpath).read_text(encoding="utf-8"))
        (BUNDLE_DIR / bundle_name).write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    OUT.mkdir(exist_ok=True)

    files = {
        "01-guide-and-concepts.md": build_guide(),
        "02-api-reference.md": build_api_reference(),
        "03-examples-and-recipes.md": build_examples(),
        "04-capabilities-db-mcp-and-openspec.md": build_capabilities_and_specs(),
    }

    for name, content in files.items():
        p = OUT / name
        p.write_text(content, encoding="utf-8")
        print(f"Wrote {p.relative_to(REPO)}: {p.stat().st_size:,} bytes")

    prepare_build_docs_bundle()
    print(f"Prepared build-docs bundle in {BUNDLE_DIR.relative_to(REPO)}")


if __name__ == "__main__":
    main()
