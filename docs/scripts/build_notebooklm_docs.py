"""Regenerate docs-notebooklm/*.md for upload to Google's NotebookLM.

Run by hand after doc or API changes:

    uv run python docs/scripts/build_notebooklm_docs.py

Produces three self-contained markdown files sized for NotebookLM (which
caps the number of sources per notebook but allows large individual files):

  01-guide-and-concepts.md   - narrative docs (overview, getting started,
                                architecture, configuration, user guide,
                                development/testing)
  02-api-reference.md        - every public class/function/method in
                                src/arodonata, extracted directly from
                                source via `ast` (signature + docstring),
                                so it can't drift out of sync with the code
  03-examples-and-recipes.md - docs/examples/*.md with their pymdownx
                                `--8<--` snippets resolved inline against
                                the real examples/*.py scripts

Output directory (docs-notebooklm/, repo root) is gitignored - it's a
generation artifact, not something to hand-edit or commit.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DOCS = REPO / "docs"
SRC = REPO / "src" / "arodonata"
EXAMPLES = REPO / "examples"
OUT = REPO / "docs-notebooklm"


# ---------------------------------------------------------------------------
# AST extraction: pull public classes/functions/methods straight from source
# ---------------------------------------------------------------------------


def _get_docstring(node: ast.AST) -> str:
    ds = ast.get_docstring(node)
    return ds.strip() if ds else ""


def _decorators(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
    out = []
    for d in node.decorator_list:
        try:
            out.append("@" + ast.unparse(d))
        except Exception:
            pass
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
    parts = []
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

    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        dm = {}
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


def _process_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    return {
        "signature": _format_signature(node),
        "docstring": _get_docstring(node),
        "decorators": _decorators(node),
    }


def _process_class(node: ast.ClassDef) -> dict:
    bases = []
    for b in node.bases:
        try:
            bases.append(ast.unparse(b))
        except Exception:
            pass

    class_vars = []
    methods = []
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
                try:
                    default = f" = {ast.unparse(item.value)}"
                except Exception:
                    pass
            class_vars.append(f"{item.target.id}: {ann}{default}")

    return {
        "name": node.name,
        "bases": bases,
        "decorators": _decorators(node),
        "docstring": _get_docstring(node),
        "methods": methods,
        "class_vars": class_vars,
    }


def _process_module(path: Path, relpath: str) -> dict:
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return {"path": relpath, "error": str(e)}

    mod = {"path": relpath, "docstring": _get_docstring(tree), "classes": [], "functions": []}
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


def extract_modules() -> list[dict]:
    modules = []
    for path in sorted(SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(SRC.parent).as_posix()
        modules.append(_process_module(path, rel))
    return modules


# ---------------------------------------------------------------------------
# Rendering: API reference (file 2)
# ---------------------------------------------------------------------------

GROUP_TITLES = {
    "(root)": "Top-Level Package",
    "api": "api — High-Level Client & Services",
    "adapters": "adapters — External Integrations (API transport, cache backend)",
    "asdk": "asdk — Low-Level Check Point Management API SDK",
    "cache": "cache — Database-Backed Caching Layer",
    "config": "config — Settings & Constants",
    "core": "core — Core Domain Logic, Protocols & Exceptions",
    "cpcrud": "cpcrud — Declarative CRUD / Rule Engine",
    "extractors": "extractors — Bulk Data Extraction",
    "helpers": "helpers — Convenience Helper Functions",
    "models": "models — Data Models",
    "ports": "ports — Abstract Interfaces (Hexagonal Architecture Ports)",
    "utils": "utils — Utility Functions",
    "services": "services — (reserved)",
}
GROUP_ORDER = list(GROUP_TITLES.keys())


def _code_block(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text}\n```"


def _render_docstring(ds: str) -> str:
    return (ds if ds else "_No docstring._") + "\n"


def _render_function(fn: dict, level: int) -> str:
    h = "#" * level
    out = [f"{h} `{fn['signature']}`\n"]
    if fn.get("decorators"):
        out.append(_code_block("\n".join(fn["decorators"]), "python"))
    out.append(_render_docstring(fn["docstring"]))
    return "\n".join(out)


def _render_class(cls: dict, level: int) -> str:
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


def _render_module(mod: dict, level: int) -> str:
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
    groups: dict[str, list[dict]] = {}
    for m in modules:
        parts = m["path"].split("/")
        group = "(root)" if len(parts) == 2 else parts[1]
        groups.setdefault(group, []).append(m)

    order = [g for g in GROUP_ORDER if g in groups] + [g for g in groups if g not in GROUP_ORDER]

    parts = [
        "# Arodonata — Full API Reference\n",
        "Complete, auto-generated reference of every public class, function, and "
        "method in the `arodonata` package, grouped by subpackage. Each entry shows "
        "the exact signature (as written in source) and its docstring. This is the "
        "third companion document alongside the Guide and the Examples — use it to "
        "look up exact function names, parameters, and return types.\n",
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

GUIDE_SOURCES = [
    ("Overview", "index.md"),
    ("Getting Started — Overview", "getting-started/index.md"),
    ("Getting Started — Your First Script", "getting-started/first-script.md"),
    ("Getting Started — CRUD Quickstart", "getting-started/cpcrud.md"),
    ("Architecture — Overview", "architecture/index.md"),
    ("Architecture — Ports & Adapters", "architecture/ports-and-adapters.md"),
    ("Architecture — Caching & Sync", "architecture/caching-and-sync.md"),
    ("Architecture — Sessions & Multi-Domain Management", "architecture/sessions-and-mdm.md"),
    ("Architecture — CRUD Engine", "architecture/cpcrud.md"),
    ("Configuration — Overview", "configuration/index.md"),
    ("Configuration — Multi-Server Setup", "configuration/multi-server.md"),
    ("User Guide — CRUD Operations", "user-guide/cpcrud.md"),
    ("Development — Testing", "development/testing.md"),
]


def build_guide() -> str:
    parts = [
        "# Arodonata — Concepts & Guide\n",
        "This document is a consolidated guide to the Arodonata library: what it does, "
        "how it's built, how to configure it, and how to use its main features. "
        "It's one of three companion documents (Guide, API Reference, Examples) meant "
        "to be uploaded together to an AI document-chat tool so you can ask questions "
        "like \"which function do I use to fetch a host object?\" or \"how do I set up "
        "multi-server config?\" and get grounded answers.\n",
    ]
    for title, relpath in GUIDE_SOURCES:
        parts.append(f"\n---\n\n## {title}\n")
        parts.append(f"*(source: `docs/{relpath}`)*\n")
        parts.append((DOCS / relpath).read_text(encoding="utf-8"))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Build: examples & recipes (file 3)
# ---------------------------------------------------------------------------

EXAMPLE_MD_FILES = [
    "examples/index.md",
    "examples/01-basic-queries.md",
    "examples/02-search.md",
    "examples/03-gateway-relationships.md",
    "examples/04-smart-refresh.md",
    "examples/05-rulebase-queries.md",
    "examples/06-crud-operations.md",
    "examples/07-crud-inverse.md",
    "examples/07-session-basics.md",
    "examples/08-otel-smart-refresh.md",
]

SNIPPET_RE = re.compile(r'^--8<-- "(.+?)"\s*$', re.MULTILINE)


def _resolve_snippets(text: str) -> str:
    def repl(m: re.Match) -> str:
        full = REPO / m.group(1)
        if full.exists():
            return full.read_text(encoding="utf-8").rstrip("\n")
        return f"[MISSING SNIPPET: {m.group(1)}]"

    return SNIPPET_RE.sub(repl, text)


def build_examples() -> str:
    parts = [
        "# Arodonata — Examples & Recipes\n",
        "Worked examples showing common tasks with Arodonata: basic queries, search, "
        "gateway relationships, smart refresh, rulebase queries, CRUD operations "
        "(including inverse/rollback), session basics, and OpenTelemetry tracing. "
        "Each section pairs the explanation with the full, runnable example script "
        "(snippets resolved inline, matching what the docs site renders). "
        "Companion document to the Guide and the full API Reference.\n",
    ]
    for relpath in EXAMPLE_MD_FILES:
        text = (DOCS / relpath).read_text(encoding="utf-8")
        parts.append(f"\n---\n\n*(source: `docs/{relpath}`)*\n")
        parts.append(_resolve_snippets(text))

    guard = EXAMPLES / "_session_guard.py"
    if guard.exists():
        parts.append("\n---\n\n### Helper used by the session example: `examples/_session_guard.py`\n")
        parts.append(_code_block(guard.read_text(encoding="utf-8"), "python"))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    OUT.mkdir(exist_ok=True)

    (OUT / "01-guide-and-concepts.md").write_text(build_guide(), encoding="utf-8")
    (OUT / "02-api-reference.md").write_text(build_api_reference(), encoding="utf-8")
    (OUT / "03-examples-and-recipes.md").write_text(build_examples(), encoding="utf-8")

    for name in ("01-guide-and-concepts.md", "02-api-reference.md", "03-examples-and-recipes.md"):
        p = OUT / name
        print(f"{name}: {p.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
