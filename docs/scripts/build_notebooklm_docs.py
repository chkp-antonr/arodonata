"""Regenerate docs-notebooklm/*.md, sync plugin skill references, and prepare docs/_build_bundle/arodonata-v2-docs for build-docs.

Run after documentation or API changes:

    uv run python docs/scripts/build_notebooklm_docs.py

Produces five self-contained Markdown knowledge bundles in `docs-notebooklm/` sized for
Google NotebookLM / Claude Projects / Gemini Gems / AI coding skills:

  01-guide-and-concepts.md                    - Complete narrative documentation (overview,
                                                getting started, architecture, SQLModel DB
                                                schema, caching/sync, sessions/overlays,
                                                CPCRUD, MCP server & consolidated tools,
                                                configuration, mock guides, troubleshooting,
                                                testing)
  02-api-reference.md                         - Every public class, SQLModel table, function,
                                                and method in `src/arodonata`, extracted
                                                directly from source via `ast`
  03-examples-and-recipes.md                  - All tracked progressive examples (`01`..`N`) with
                                                resolved `--8<--` snippets and helper scripts
  04-capabilities-db-mcp-and-openspec.md      - Downstream integration guide (`CAPABILITIES.md`),
                                                exact SQLModel table definitions (`tables.py`),
                                                MCP tool registrations, and all canonical OpenSpec
                                                system specifications (`openspec/specs/*/spec.md`)
  05-sdk-quickref.md                          - Compact AST-derived SDK & CLI quick-reference
                                                for AI coding agents

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
PLUGIN_REFS_DIR = REPO / "plugins" / "arodonata-aibuilder" / "skills" / "arodonata-aibuilder" / "references"

SNIPPET_RE = re.compile(r'^--8<-- "(.+?)"\s*$', re.MULTILINE)


def _read_package_version() -> str:
    """Read `arodonata.__version__` directly from `src/arodonata/__init__.py` via AST."""
    init_path = SRC / "__init__.py"
    tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    return "0.0.0"


def _count_sqlmodel_tables() -> int:
    """Count `SQLModel` table classes (`table=True`) in `adapters/storage/tables.py` via AST."""
    tables_path = SRC / "adapters" / "storage" / "tables.py"
    tree = ast.parse(tables_path.read_text(encoding="utf-8"), filename=str(tables_path))
    count = 0
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(
            isinstance(kw, ast.keyword)
            and kw.arg == "table"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        ):
            count += 1
    return count


def _count_openspec_specs() -> int:
    """Count canonical OpenSpec capability specifications under `openspec/specs/`."""
    return len(list(OPENSPEC_SPECS.glob("*/spec.md")))


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
    "adapters": "adapters — Check Point Transport (`AMgmtClient`), SQL Storage & SSE",
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
    pkg_version = _read_package_version()
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
        f"method in the `arodonata` v{pkg_version} package, extracted directly from `src/arodonata` via AST.\n",
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

_TABLE_COUNT = _count_sqlmodel_tables()
_PKG_VERSION = _read_package_version()

GUIDE_SOURCES: list[tuple[str, str, str]] = [
    ("00-index.md", "Overview & Quickstart", "index.md"),
    ("01-getting-started.md", "Getting Started — Installation & Setup", "getting-started/index.md"),
    ("02-first-script.md", "Getting Started — Your First Script", "getting-started/first-script.md"),
    ("03-cpcrud-quickstart.md", "Getting Started — CPCRUD Quickstart", "getting-started/cpcrud.md"),
    ("04-capabilities.md", "Capabilities & Downstream Integration Guide", "CAPABILITIES.md"),
    ("05-architecture-overview.md", "Architecture — Overview", "architecture/index.md"),
    ("06-ports-and-adapters.md", "Architecture — Hexagonal Ports & Adapters", "architecture/ports-and-adapters.md"),
    (
        "07-database-schema.md",
        f"Architecture — Database Schema ({_TABLE_COUNT} Tables)",
        "architecture/database-schema.md",
    ),
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
    (
        "17a-enterprise-replay-mock-server.md",
        "Guides — Enterprise Replay Mock Server",
        "guides/enterprise-replay-mock-server.md",
    ),
    ("17b-mock-testing-scenarios.md", "Guides — Mock Testing Scenarios", "guides/mock-testing-scenarios.md"),
    (
        "17c-checkpoint-api-quirks.md",
        "Troubleshooting — Check Point API Quirks",
        "troubleshooting/checkpoint-api-quirks.md",
    ),
    (
        "17d-checkpoint-ops-quirks.md",
        "Troubleshooting — Check Point Operations & CLI Quirks",
        "troubleshooting/checkpoint-ops-quirks.md",
    ),
    ("18-changelog.md", f"Project Changelog (v{_PKG_VERSION})", "CHANGELOG.md"),
]


def build_guide() -> str:
    pkg_version = _read_package_version()
    table_count = _count_sqlmodel_tables()
    parts = [
        "# Arodonata v2 — Concepts, Architecture & User Guide\n",
        f"This document is the consolidated narrative guide to **Arodonata v2 (`{pkg_version}`)**: "
        f"hexagonal architecture, the {table_count} `arodonata_*` SQLModel cache tables, incremental sync, "
        "isolated write sessions with `SessionOverlay`, the declarative `CPCRUD` engine, "
        "auditable change reports, mock/replay testing, Check Point API & operational quirks, "
        "and the consolidated Model Context Protocol (MCP) server.\n",
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


def discover_example_md_files() -> list[tuple[str, str]]:
    """Discover the examples catalog and all numbered `docs/examples/[0-9][0-9]-*.md` guides."""
    discovered: list[tuple[str, str]] = [("20-examples-catalog.md", "examples/index.md")]
    example_paths = sorted((DOCS / "examples").glob("[0-9][0-9]-*.md"))
    for idx, example_path in enumerate(example_paths, start=21):
        discovered.append((f"{idx:02d}-example-{example_path.name}", f"examples/{example_path.name}"))
    return discovered


EXAMPLE_MD_FILES: list[tuple[str, str]] = discover_example_md_files()


def build_examples() -> str:
    example_files = discover_example_md_files()
    numbered_count = len(example_files) - 1
    parts = [
        f"# Arodonata v2 — Runnable Examples & Recipes (01..{numbered_count:02d})\n",
        "Worked examples showing common tasks with Arodonata v2: basic queries, multi-term search "
        "and structured cross-domain aggregation (`query_objects`), gateway/cluster/VSX relationships, "
        "paired streaming and batch smart refresh, rulebase queries and local filtering, session "
        "lifecycle, `WriteSession` + `SessionOverlay` read-your-own-writes isolation, declarative "
        "CPCRUD (`plan`/`apply`/`inverse`), auditable change reports (`OwnedSession` live numbering "
        "vs published cached numbering), OpenTelemetry tracing, embedded FastAPI MCP servers, and "
        "gateway topology matching (`examples/13_gateway_topology_matching.py`).\n",
    ]
    for _, relpath in example_files:
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
    table_count = _count_sqlmodel_tables()
    spec_count = _count_openspec_specs()
    parts = [
        "# Arodonata v2 — Capabilities, DB Schema, MCP Surface & Canonical OpenSpec Specifications\n",
        "This bundle combines the Downstream Integration Guide (`docs/CAPABILITIES.md`), "
        f"the complete {table_count}-table SQLModel database schema (`docs/architecture/database-schema.md` + "
        "`src/arodonata/adapters/storage/tables.py`), the consolidated MCP Server specification "
        f"(`docs/mcp/index.md`), and all {spec_count} canonical OpenSpec capability specifications "
        "(`openspec/specs/*/spec.md`).\n",
        "\n---\n\n## Part 1: Downstream Integration Guide (`docs/CAPABILITIES.md`)\n",
        _resolve_snippets((DOCS / "CAPABILITIES.md").read_text(encoding="utf-8")),
        f"\n---\n\n## Part 2: {table_count}-Table Database Schema (`docs/architecture/database-schema.md`)\n",
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
# Build: Compact Agent SDK Quick-Reference (file 5)
# ---------------------------------------------------------------------------


def _parse_src_tree(relpath: str) -> ast.Module:
    path = SRC / relpath
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _find_class_node(tree: ast.Module, class_name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node
    raise ValueError(f"Class {class_name!r} not found in AST")


def _compact_field_default(value_node: ast.expr | None) -> str:
    """Format a compact default suffix for quickref model fields, omitting `AliasChoices`/constraints."""
    if value_node is None:
        return ""
    if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name) and value_node.func.id == "Field":
        for kw in value_node.keywords:
            if kw.arg == "default":
                with suppress(Exception):
                    return f" = {ast.unparse(kw.value)}"
            if kw.arg == "default_factory":
                with suppress(Exception):
                    if isinstance(kw.value, ast.Lambda):
                        return f" = {ast.unparse(kw.value.body)}"
                    factory = ast.unparse(kw.value)
                    if factory == "list":
                        return " = []"
                    if factory == "dict":
                        return " = {}"
                    return f" = {factory}()"
        return ""
    with suppress(Exception):
        return f" = {ast.unparse(value_node)}"
    return ""


def _extract_class_fields(relpath: str, class_name: str, *, compact: bool = True) -> list[str]:
    cls_node = _find_class_node(_parse_src_tree(relpath), class_name)
    fields: list[str] = []
    for item in cls_node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and not item.target.id.startswith("_"):
            if item.target.id == "model_config":
                continue
            ann = ast.unparse(item.annotation)
            default = _compact_field_default(item.value) if compact else ""
            if not compact and item.value is not None:
                with suppress(Exception):
                    default = f" = {ast.unparse(item.value)}"
            fields.append(f"{item.target.id}: {ann}{default}")
    return fields


def _extract_class_method_sigs(
    relpath: str,
    class_name: str,
    *,
    include_dunder: tuple[str, ...] = ("__init__",),
    include_properties: bool = True,
    exclude_prefixes: tuple[str, ...] = (),
) -> list[str]:
    cls_node = _find_class_node(_parse_src_tree(relpath), class_name)
    sigs: list[str] = []
    for item in cls_node.body:
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if item.name.startswith("_") and item.name not in include_dunder:
            continue
        if exclude_prefixes and item.name.startswith(exclude_prefixes):
            continue
        decs = _decorators(item)
        if not include_properties and "@property" in decs:
            continue
        sig = _format_signature(item)
        if "@property" in decs:
            sigs.append(f"@property {sig}")
        elif "@classmethod" in decs:
            sigs.append(f"@classmethod {sig}")
        else:
            sigs.append(sig)
    return sigs


def _extract_module_func_sigs(relpath: str, func_names: tuple[str, ...]) -> list[str]:
    tree = _parse_src_tree(relpath)
    by_name: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in func_names:
            by_name[node.name] = _format_signature(node)
    return [by_name[name] for name in func_names if name in by_name]


def _extract_all_exports(relpath: str) -> list[str]:
    tree = _parse_src_tree(relpath)
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
            and isinstance(node.value, (ast.List, ast.Tuple))
        ):
            return [
                elt.value for elt in node.value.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
    return []


def build_sdk_quickref() -> str:
    """Build deterministic compact SDK & CLI quick-reference extracted from `src/arodonata` via AST."""
    pkg_version = _read_package_version()

    client_init = _extract_class_method_sigs(
        "client/_base.py", "ClientBase", include_properties=False, exclude_prefixes=("write_session",)
    )
    client_lifecycle = _extract_class_method_sigs(
        "client/lifecycle.py", "ClientLifecycleMixin", exclude_prefixes=("stream_",)
    )
    client_inventory = _extract_class_method_sigs(
        "client/inventory.py", "ClientInventoryMixin", exclude_prefixes=("stream_",)
    )
    client_rulebase = _extract_class_method_sigs(
        "client/rulebase_reports.py", "ClientRulebaseReportsMixin", exclude_prefixes=("stream_",)
    )
    client_topology = _extract_class_method_sigs(
        "client/topology.py", "ClientTopologyMixin", exclude_prefixes=("stream_",)
    )

    settings_fields = _extract_class_fields("core/config.py", "ArodonataSettings")

    asset_fields = _extract_class_fields("core/models/assets.py", "Asset")
    asset_methods = _extract_class_method_sigs("core/models/assets.py", "Asset", include_dunder=())
    asset_helpers = _extract_module_func_sigs(
        "core/models/assets.py",
        ("classify_asset_role", "classify_asset_platform", "classify_asset"),
    )
    cpobject_fields = _extract_class_fields("core/models/objects.py", "CPObject")
    cpobject_methods = _extract_class_method_sigs("core/models/objects.py", "CPObject", include_dunder=())
    cpservice_fields = _extract_class_fields("core/models/services.py", "CPService")
    cpservice_methods = _extract_class_method_sigs("core/models/services.py", "CPService", include_dunder=())
    domain_fields = _extract_class_fields("core/models/domains.py", "DomainInfo")
    domain_helpers = _extract_module_func_sigs("core/models/domains.py", ("parse_domain_entry", "parse_domain_dict"))

    script_sigs = _extract_class_method_sigs("core/services/script_service.py", "ScriptRepositoryService")
    cpcrud_sigs = _extract_class_method_sigs("cpcrud/service.py", "CPCRUDService")
    apiref_sigs = _extract_class_method_sigs("api_reference/engine.py", "ApiReferenceEngine")
    apiref_funcs = _extract_module_func_sigs(
        "api_reference/engine.py",
        (
            "normalize_api_version",
            "get_api_reference",
            "search_api_commands",
            "describe_api_command",
            "validate_api_payload",
        ),
    )

    change_report_fields = _extract_class_fields("reports/models.py", "ChangeReport")
    session_report_fields = _extract_class_fields("reports/models.py", "SessionChangeReport")
    session_scope_fields = _extract_class_fields("reports/models.py", "SessionScope")
    range_scope_fields = _extract_class_fields("reports/models.py", "RangeScope")
    owned_session_fields = _extract_class_fields("reports/models.py", "OwnedSession")
    render_options_fields = _extract_class_fields("reports/models.py", "RenderOptions")
    report_funcs = [
        *_extract_module_func_sigs("reports/collector.py", ("collect_change_report",)),
        *_extract_module_func_sigs("reports/plan_report.py", ("build_change_report_from_plan",)),
        *_extract_module_func_sigs("reports/renderer.py", ("build_change_report", "render_change_report")),
    ]

    testing_exports = _extract_all_exports("testing/__init__.py")
    replay_api_sigs = _extract_class_method_sigs("testing/replay_mock.py", "FileReplayApiMock")
    replay_cli_sigs = _extract_class_method_sigs("testing/_replay_cli.py", "FileReplayCliMock")
    mock_http_sigs = _extract_class_method_sigs("testing/mock_server.py", "CheckPointReplayHttpServer")
    snapshot_fields = _extract_class_fields("testing/_emulator_models.py", "ReplayStateSnapshot")
    dataset_funcs = _extract_module_func_sigs(
        "testing/dataset_generator.py",
        ("generate_enterprise_raw_dataset", "ensure_enterprise_raw_dataset"),
    )

    sections = [
        f"# Arodonata v2 (`{pkg_version}`) — SDK & CLI Quick-Reference",
        "",
        f"Auto-generated deterministic cheat sheet from `src/arodonata` (`arodonata=={pkg_version}`). "
        "Use this quick-reference to verify exact symbols, method signatures, and model fields without "
        "loading the full multi-megabyte `02-api-reference.md` bundle.",
        "",
        "## 1. `ArodonataClient` (`arodonata.ArodonataClient`)",
        "",
        "Async-first facade (`ClientTopologyMixin`, `ClientRulebaseReportsMixin`, `ClientInventoryMixin`, `ClientLifecycleMixin`, `ClientBase`).",
        "Properties: `settings`, `db`, `owns_engine`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `api_reference`, `script_service`, `topology_service`.",
        "Streaming variants (`AsyncIterator[SyncProgressEvent | CPCRUDEvent]`): `stream_refresh_objects`, `stream_refresh_services`, `stream_refresh_assets`, `stream_refresh_rulebases`, `stream_refresh_policy_packages`, `stream_refresh_topology`, `stream_publish_staged_session`.",
        "",
        "### Initialization & Lifecycle",
        "",
        _code_block("\n".join([*client_init, *client_lifecycle]), "python"),
        "",
        "### Inventory, Cache, Search & CRUD",
        "",
        _code_block("\n".join(client_inventory), "python"),
        "",
        "### Rulebases, Change Reports, API Reference & Repository Scripts",
        "",
        _code_block("\n".join(client_rulebase), "python"),
        "",
        "### Gateway Topology & Route Collection",
        "",
        _code_block("\n".join(client_topology), "python"),
        "",
        "## 2. `ArodonataSettings` (`arodonata.ArodonataSettings`)",
        "",
        _code_block("\n".join(settings_fields), "python"),
        "",
        "## 3. Core Models (`Asset`, `CPObject`, `CPService`, `DomainInfo`)",
        "",
        "### `Asset`",
        "",
        _code_block("\n".join([*asset_fields, "", *asset_methods, "", *asset_helpers]), "python"),
        "",
        "### `CPObject`",
        "",
        _code_block("\n".join([*cpobject_fields, "", *cpobject_methods]), "python"),
        "",
        "### `CPService`",
        "",
        _code_block("\n".join([*cpservice_fields, "", *cpservice_methods]), "python"),
        "",
        "### `DomainInfo`",
        "",
        _code_block("\n".join([*domain_fields, "", *domain_helpers]), "python"),
        "",
        "## 4. `ScriptRepositoryService` (`arodonata.ScriptRepositoryService`)",
        "",
        _code_block("\n".join(script_sigs), "python"),
        "",
        "## 5. `CPCRUDService` (`arodonata.CPCRUDService`)",
        "",
        _code_block("\n".join(cpcrud_sigs), "python"),
        "",
        "## 6. `ApiReferenceEngine` & Offline Reference (`arodonata.api_reference`)",
        "",
        _code_block("\n".join([*apiref_sigs, "", *apiref_funcs]), "python"),
        "",
        "## 7. `ChangeReport` & Audit Helpers (`arodonata.reports`)",
        "",
        _code_block(
            "\n".join(
                [
                    "# ChangeReport",
                    *change_report_fields,
                    "",
                    "# SessionChangeReport",
                    *session_report_fields,
                    "",
                    "# Scopes & Options",
                    *[f"SessionScope.{f}" for f in session_scope_fields],
                    *[f"RangeScope.{f}" for f in range_scope_fields],
                    *[f"OwnedSession.{f}" for f in owned_session_fields],
                    *[f"RenderOptions.{f}" for f in render_options_fields],
                    "",
                    "# Report Functions",
                    *report_funcs,
                ]
            ),
            "python",
        ),
        "",
        "## 8. `arodonata.testing` Replay & Mock Helpers",
        "",
        f"Exports (`__all__`): `{', '.join(testing_exports)}`.",
        "",
        _code_block(
            "\n".join(
                [
                    "# FileReplayApiMock",
                    *replay_api_sigs,
                    "",
                    "# FileReplayCliMock",
                    *replay_cli_sigs,
                    "",
                    "# CheckPointReplayHttpServer",
                    *mock_http_sigs,
                    "",
                    "# ReplayStateSnapshot",
                    *snapshot_fields,
                    "",
                    "# Dataset Generators",
                    *dataset_funcs,
                ]
            ),
            "python",
        ),
        "",
        "## 9. Idiomatic `arlogi` CLI Bootstrap",
        "",
        _code_block(
            "\n".join(
                [
                    "import arlogi",
                    "",
                    'arlogi.setup_logging(level="INFO", json_file_name="logs/cli.jsonl", json_file_only=False)',
                    "logger = arlogi.get_logger(__name__)",
                    'logger.info("inventory sync finished", mgmt_name="prod-mds", count=42)',
                ]
            ),
            "python",
        ),
        "",
        "- Keep `json_file_only=False` for interactive CLI scripts so operators see console logs while JSONL audit logs persist on disk.",
        "- Never pass `sid`, `api_key`, `password`, or raw auth headers in log messages or `extra` kwargs.",
        "",
        "## 10. 3-Tier Check Point API Lookup Ladder",
        "",
        "1. **Tier 1 (`arodonata.api_reference`)**: Query the bundled offline Check Point API index first via `search_api_commands()`, `describe_api_command()`, and `validate_api_payload()` (or `client.search_api_commands()` / `client.describe_api_command()` / `client.validate_api_payload()`).",
        "2. **Tier 2 (`context7` / `cp-documentation` MCP)**: When deeper vendor semantics, MDSM edge cases, or Gaia/CDT behavior are needed, consult `docs/troubleshooting/checkpoint-api-quirks.md`, `docs/troubleshooting/checkpoint-ops-quirks.md`, or the documentation MCP servers.",
        "3. **Tier 3 (Explicit Verification Flag)**: For undocumented commands or site-specific R81.x/R82+ nuances not verified by Tiers 1–2, emit an explicit `# VERIFY:` note and confirm against a read-only lab/replay check before mutating production state.",
    ]
    return "\n".join(sections).rstrip() + "\n"


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

    # 3. Details (ordered guides + dynamically discovered examples)
    for bundle_name, _, relpath in GUIDE_SOURCES:
        if relpath in ("index.md", "CAPABILITIES.md", "architecture/database-schema.md", "mcp/index.md"):
            continue
        content = _resolve_snippets((DOCS / relpath).read_text(encoding="utf-8"))
        (BUNDLE_DIR / bundle_name).write_text(content, encoding="utf-8")

    for bundle_name, relpath in discover_example_md_files():
        content = _resolve_snippets((DOCS / relpath).read_text(encoding="utf-8"))
        (BUNDLE_DIR / bundle_name).write_text(content, encoding="utf-8")


def sync_plugin_references(target_dir: Path | None = None, *, sdk_quickref_content: str | None = None) -> list[Path]:
    """Deterministically sync SDK quick-reference and Check Point quirk docs into the plugin skill references."""
    dest = target_dir or PLUGIN_REFS_DIR
    dest.mkdir(parents=True, exist_ok=True)

    synced_payloads: dict[str, str] = {
        "sdk-quickref.md": sdk_quickref_content if sdk_quickref_content is not None else build_sdk_quickref(),
        "checkpoint-api-quirks.md": _resolve_snippets(
            (DOCS / "troubleshooting" / "checkpoint-api-quirks.md").read_text(encoding="utf-8")
        ),
        "checkpoint-ops-quirks.md": _resolve_snippets(
            (DOCS / "troubleshooting" / "checkpoint-ops-quirks.md").read_text(encoding="utf-8")
        ),
    }

    written: list[Path] = []
    for filename, content in synced_payloads.items():
        path = dest / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


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
        "05-sdk-quickref.md": build_sdk_quickref(),
    }

    for name, content in files.items():
        p = OUT / name
        p.write_text(content, encoding="utf-8")
        print(f"Wrote {p.relative_to(REPO)}: {p.stat().st_size:,} bytes")

    synced_paths = sync_plugin_references(sdk_quickref_content=files["05-sdk-quickref.md"])
    print(f"Synced {len(synced_paths)} plugin reference(s) into {PLUGIN_REFS_DIR.relative_to(REPO)}")

    prepare_build_docs_bundle()
    print(f"Prepared build-docs bundle in {BUNDLE_DIR.relative_to(REPO)}")


if __name__ == "__main__":
    main()
