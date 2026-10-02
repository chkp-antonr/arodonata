from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src" / "arodonata"
_REPORT = (
    "from datetime import UTC, datetime\n"
    "from arodonata.reports.changes import ChangeReport, render_change_report\n"
    "r = ChangeReport(generated_at=datetime(2026, 10, 2, tzinfo=UTC), arodonata_version='x', requested=[], "
    "servers=[])\n"
    "out = render_change_report(r, ['markdown', 'json'])\n"
    "assert out.markdown and out.json\n"
)


def _run(code: str) -> None:
    subprocess.run([sys.executable, "-c", code], check=True)


def test_reports_never_import_mcp():
    pattern = re.compile(r"^\s*(from\s+(arodonata\.mcp|\.\.\.?mcp)\b|import\s+arodonata\.mcp\b)", re.M)
    offenders = [str(p.relative_to(SRC)) for p in (SRC / "reports").rglob("*.py") if pattern.search(p.read_text())]
    assert offenders == []


def test_import_does_not_load_jinja2_or_markupsafe():
    _run(
        "import sys\n" + _REPORT + "bad = [m for m in ('jinja2', 'markupsafe') if m in sys.modules]\n"
        "assert not bad, bad\n"
    )


def test_markdown_and_json_work_with_markupsafe_blocked():
    _run(
        "import sys\nsys.modules['markupsafe'] = None\nsys.modules['jinja2'] = None\n"
        + _REPORT
        + "try:\n    render_change_report(r, ['html'])\nexcept ImportError as e:\n"
        "    assert \"arodonata[report]\" in str(e)\nelse:\n    raise AssertionError('html without jinja2')\n"
    )


def test_rulebase_import_loads_no_reports_or_live_reader():
    _run(
        "import sys\nimport arodonata.rulebase\n"
        "bad = [m for m in sys.modules if m == 'arodonata.reports' or m.startswith('arodonata.reports.') or m in "
        "('arodonata.api.services.rulebase_reader', 'arodonata.api.services.live_rulebase_source')]\n"
        "assert not bad, bad\n"
    )


def test_rulebase_sources_import_no_api_or_reports():
    offenders = []
    for path in (SRC / "rulebase").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom):
                names = [("." * node.level) + (node.module or "")]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            for name in names:
                if name.startswith(("arodonata.api", "arodonata.reports", "..api", "..reports")):
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []
