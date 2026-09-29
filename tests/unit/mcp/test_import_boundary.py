from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[3] / "src" / "arodonata"
IMPORT_RE = re.compile(r"^\s*(from\s+mcp[\s.]|import\s+mcp\b)", re.M)


def test_no_mcp_imports_outside_subpackage():
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if "mcp" not in p.relative_to(SRC).parts[:1] and IMPORT_RE.search(p.read_text())
    ]
    assert offenders == []


def test_sdk_module_is_the_only_importer():
    pkg = SRC / "mcp"
    offenders = [p.name for p in pkg.glob("*.py") if p.name != "_sdk.py" and IMPORT_RE.search(p.read_text())]
    assert offenders == []


def test_missing_extra_message_is_actionable(monkeypatch):
    import builtins
    import importlib
    import sys

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "mcp" or name.startswith("mcp."):
            raise ModuleNotFoundError("No module named 'mcp'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules.pop("arodonata.mcp._sdk", None)
    with pytest.raises(ImportError, match=r"uv pip install 'arodonata\[mcp\]'"):
        importlib.import_module("arodonata.mcp._sdk")
    sys.modules.pop("arodonata.mcp._sdk", None)


def test_entry_point_reports_hint_and_settings_still_import_without_sdk(monkeypatch, capsys):
    """`arodonata.mcp.__init__` must not import the SDK eagerly.

    Regression guard: the package `__init__` used to do `from ._sdk import
    MISSING_EXTRA_MESSAGE`, so merely importing `arodonata.mcp.__main__` (as the console
    script entry point does) or `arodonata.mcp.settings` raised an uncaught ImportError
    when the `mcp` extra was missing, instead of the entry point printing the hint and
    exiting 2.
    """
    import builtins
    import importlib
    import sys

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "mcp" or name.startswith("mcp."):
            raise ModuleNotFoundError("No module named 'mcp'")
        return real_import(name, *a, **k)

    saved = {
        name: module
        for name, module in sys.modules.items()
        if name == "arodonata.mcp" or name.startswith("arodonata.mcp.")
    }
    for name in saved:
        sys.modules.pop(name, None)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        main_module = importlib.import_module("arodonata.mcp.__main__")
        rc = main_module.main([])
        captured = capsys.readouterr()
        assert rc == 2
        assert "uv pip install 'arodonata[mcp]'" in captured.err

        sys.modules.pop("arodonata.mcp.settings", None)
        settings_module = importlib.import_module("arodonata.mcp.settings")
        assert settings_module.ArodonataMCPSettings().port == 8765
    finally:
        for name in list(sys.modules):
            if name == "arodonata.mcp" or name.startswith("arodonata.mcp."):
                sys.modules.pop(name, None)
        sys.modules.update(saved)
