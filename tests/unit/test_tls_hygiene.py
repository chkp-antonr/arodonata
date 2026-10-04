"""TLS hygiene (Backlog #1, spec D24): no verification opt-out anywhere; TLS primitives only in asdk/tls.py."""

from __future__ import annotations

import ast
import http.client
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN = [ROOT / "src", ROOT / "tests" / "integration", ROOT / "examples", ROOT / "docs" / "scripts"]
TLS_MODULE = ROOT / "src" / "arodonata" / "asdk" / "tls.py"
BANNED_KWARGS = {"unsafe", "unsafe_auto_accept", "debug_file", "http_debug_level", "fingerprint"}
FALSE_KWARGS = {"verify", "ssl", "verify_ssl"}
BANNED_EVERYWHERE = {"_create_unverified_context", "setdefaulttimeout"}
TLS_ONLY_CALLS = {"SSLContext", "APIClient", "APIClientArgs", "HTTPSConnection"}


def _files() -> list[Path]:
    return [p for base in SCAN if base.exists() for p in sorted(base.rglob("*.py"))]


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def everywhere_hits(tree: ast.AST) -> list[str]:
    """Constructs banned in every scanned file, as ``line what`` strings."""
    found = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in BANNED_KWARGS:
                    found.append(f"{line} {kw.arg}=")
                if kw.arg in FALSE_KWARGS and _is_false(kw.value):
                    found.append(f"{line} {kw.arg}=False")
        if _name(node) in BANNED_EVERYWHERE:
            found.append(f"{line} {_name(node)}")
    return found


def outside_tls_hits(tree: ast.AST) -> list[str]:
    """Constructs banned in every scanned file except asdk/tls.py."""
    found = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if _name(node) == "CERT_NONE":
            found.append(f"{line} CERT_NONE")
        if isinstance(node, ast.Call) and _name(node.func) in TLS_ONLY_CALLS:
            found.append(f"{line} {_name(node.func)}(")
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "check_fingerprint":
            found.append(f"{line} def check_fingerprint")
        if (
            isinstance(node, ast.Assign)
            and _is_false(node.value)
            and any(_name(t) == "check_hostname" for t in node.targets)
        ):
            found.append(f"{line} check_hostname = False")
    return found


def test_no_verification_opt_out_anywhere():
    found = [f"{p.relative_to(ROOT)}:{h}" for p in _files() for h in everywhere_hits(ast.parse(p.read_text()))]
    assert not found, found


def test_tls_primitives_only_in_tls_module():
    found = [
        f"{p.relative_to(ROOT)}:{h}"
        for p in _files()
        if p != TLS_MODULE
        for h in outside_tls_hits(ast.parse(p.read_text()))
    ]
    assert not found, found


def test_cert_none_only_inside_probe_certificate():
    tree = ast.parse(TLS_MODULE.read_text())
    total = sum(1 for n in ast.walk(tree) if _name(n) == "CERT_NONE")
    inside = 0
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) and fn.name == "probe_certificate":
            inside = sum(1 for n in ast.walk(fn) if _name(n) == "CERT_NONE")
    assert total == inside == 1


def test_checker_detects_synthetic_violations():
    """The guard is not vacuous: each banned construct is reported."""
    everywhere = ast.parse(
        "APIClientArgs(unsafe=True, unsafe_auto_accept=True, fingerprint='x', debug_file='f', http_debug_level=1)\n"
        "requests.get(u, verify=False)\nf(ssl=False)\nf(verify_ssl=False)\n"
        "ssl._create_unverified_context()\nsocket.setdefaulttimeout(5)\n"
    )
    hits = " ".join(everywhere_hits(everywhere))
    for expected in (
        "unsafe=",
        "unsafe_auto_accept=",
        "fingerprint=",
        "debug_file=",
        "http_debug_level=",
        "verify=False",
        "ssl=False",
        "verify_ssl=False",
        "_create_unverified_context",
        "setdefaulttimeout",
    ):
        assert expected in hits, expected
    outside = ast.parse(
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.verify_mode = ssl.CERT_NONE\nctx.check_hostname = False\n"
        "APIClient(a)\nHTTPSConnection(h)\nclass C:\n    def check_fingerprint(self): ...\n"
    )
    hits = " ".join(outside_tls_hits(outside))
    for expected in (
        "SSLContext(",
        "CERT_NONE",
        "check_hostname = False",
        "APIClient(",
        "HTTPSConnection(",
        "def check_fingerprint",
    ):
        assert expected in hits, expected
    assert not everywhere_hits(ast.parse("f(verify=True, timeout=5)")) and not outside_tls_hits(ast.parse("x = 1"))


def test_cpapi_contract():
    from cpapi import APIClient
    from cpapi.mgmt_api import HTTPSConnection

    for name in (
        "check_fingerprint",
        "create_https_connection",
        "get_https_connection",
        "api_call",
        "get_port",
        "close_connection",
    ):
        assert callable(getattr(APIClient, name)), name
    assert issubclass(HTTPSConnection, http.client.HTTPSConnection)
    client = APIClient()  # default args: no I/O at construction
    assert hasattr(client, "conn")
    assert hasattr(client, "single_conn")
    assert client.single_conn is True  # the re-send guard depends on it


def test_pyproject_bounds_cpapi():
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    assert "cp-mgmt-api-sdk>=1.9.0,<1.10" in deps
