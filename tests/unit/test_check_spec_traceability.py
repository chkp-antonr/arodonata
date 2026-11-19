"""Unit tests for `scripts/check_spec_traceability.py`."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_spec_traceability.py"


def _load_traceability_module() -> ModuleType:
    module_name = "arodonata_check_spec_traceability"
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_MOD = _load_traceability_module()

_VALID_SPEC = """\
# CPCRUD Declarative Spec

## Purpose

Defines declarative validation and execution contracts for Check Point policy templates.

## Requirements

### Requirement: Alpha Validation

**ID**: REQ-CPCRUD-001\\
**Intent**: Reject malformed templates offline.\\
**Non-goals**: Live state planning.

The engine SHALL validate templates offline.

#### Scenario: SCN-CPCRUD-001-1 — Invalid template fails offline

- **GIVEN** a malformed template
- **WHEN** `validate(template)` is called
- **THEN** it SHALL return validation errors
"""


def _write_repo(
    root: Path,
    *,
    spec_text: str = _VALID_SPEC,
    test_text: str = "",
    baseline: list[str] | None = None,
    delta_text: str | None = None,
) -> Path:
    spec_file = root / "openspec" / "specs" / "cpcrud" / "spec.md"
    spec_file.parent.mkdir(parents=True, exist_ok=True)
    spec_file.write_text(spec_text, encoding="utf-8")

    if delta_text is not None:
        delta_file = root / "openspec" / "changes" / "demo-change" / "specs" / "cpcrud" / "spec.md"
        delta_file.parent.mkdir(parents=True, exist_ok=True)
        delta_file.write_text(delta_text, encoding="utf-8")

    if test_text:
        test_file = root / "tests" / "unit" / "test_sample.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(test_text, encoding="utf-8")

    baseline_path = root / "scripts" / "spec_traceability_baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps({"schema_version": 1, "untested_scenarios": baseline or []}, indent=2) + "\n",
        encoding="utf-8",
    )
    return baseline_path


def test_valid_spec_and_covered_test_passes(tmp_path: Path) -> None:
    """Valid specs with covered `@pytest.mark.spec` scenarios and clean baseline pass."""
    test_src = 'import pytest\n\n@pytest.mark.spec("SCN-CPCRUD-001-1")\ndef test_alpha() -> None:\n    pass\n'
    baseline = _write_repo(tmp_path, test_text=test_src, baseline=[])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert report.errors == []
    assert report.requirement_count == 1
    assert report.scenario_count == 1
    assert report.covered_count == 1
    assert _MOD.main(["--root", str(tmp_path), "--baseline", str(baseline)]) == 0


def test_write_baseline_populates_only_untested_scenarios(tmp_path: Path) -> None:
    """`--write-baseline` writes only scenarios not yet covered by `@pytest.mark.spec`."""
    two_scn_spec = (
        _VALID_SPEC
        + "\n#### Scenario: SCN-CPCRUD-001-2 — Valid template passes offline\n\n"
        + "- **WHEN** a valid template is checked\n"
        + "- **THEN** it SHALL return zero errors\n"
    )
    test_src = 'import pytest\n\n@pytest.mark.spec("SCN-CPCRUD-001-1")\ndef test_alpha() -> None:\n    pass\n'
    baseline = _write_repo(tmp_path, spec_text=two_scn_spec, test_text=test_src)

    assert _MOD.main(["--root", str(tmp_path), "--baseline", str(baseline), "--write-baseline"]) == 0
    saved = json.loads(baseline.read_text(encoding="utf-8"))
    assert saved["untested_scenarios"] == ["SCN-CPCRUD-001-2"]
    assert _MOD.main(["--root", str(tmp_path), "--baseline", str(baseline)]) == 0


@pytest.mark.parametrize(
    ("bad_meta", "expected_substr"),
    [
        ("**ID**: REQ-CPCRUD-001\\\n**Non-goals**: Live state planning.", "missing required '**Intent**:'"),
        (
            "**ID**: REQ-CPCRUD-001\\\n**Intent**:\\\n**Non-goals**: Live state planning.",
            "'**Intent**:' metadata cannot be empty",
        ),
        (
            "**ID**: REQ-CPCRUD-001\\\n**Intent**: Reject malformed templates offline.",
            "missing required '**Non-goals**:'",
        ),
        (
            "**ID**: REQ-CPCRUD-001\\\n**Intent**: Reject malformed templates offline.\\\n**Non-goals**:",
            "'**Non-goals**:' metadata cannot be empty",
        ),
    ],
)
def test_missing_or_empty_intent_and_non_goals_rejected(
    tmp_path: Path,
    bad_meta: str,
    expected_substr: str,
) -> None:
    """Missing or empty `**Intent**:` or `**Non-goals**:` fails validation."""
    old_meta = "**ID**: REQ-CPCRUD-001\\\n**Intent**: Reject malformed templates offline.\\\n**Non-goals**: Live state planning."
    spec_text = _VALID_SPEC.replace(old_meta, bad_meta)
    baseline = _write_repo(tmp_path, spec_text=spec_text, baseline=["SCN-CPCRUD-001-1"])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any(expected_substr in err for err in report.errors), report.errors


def test_dangling_req_and_scn_cross_references_rejected(tmp_path: Path) -> None:
    """Any cross-reference to an undefined `REQ-*` or `SCN-*` in spec prose or metadata fails."""
    spec_text = _VALID_SPEC.replace(
        "Live state planning.",
        "Live state planning (`REQ-CPCRUD-999`, `SCN-CPCRUD-999-1`).",
    )
    baseline = _write_repo(tmp_path, spec_text=spec_text, baseline=["SCN-CPCRUD-001-1"])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any("cross-reference 'REQ-CPCRUD-999' does not exist" in err for err in report.errors), report.errors
    assert any("cross-reference 'SCN-CPCRUD-999-1' does not exist" in err for err in report.errors), report.errors


def test_new_uncovered_scenario_not_in_baseline_rejected(tmp_path: Path) -> None:
    """A new scenario absent from both `@pytest.mark.spec` and baseline is rejected."""
    two_scn_spec = (
        _VALID_SPEC
        + "\n#### Scenario: SCN-CPCRUD-001-2 — Brand new scenario\n\n"
        + "- **WHEN** a new rule runs\n"
        + "- **THEN** it SHALL require a test\n"
    )
    baseline = _write_repo(tmp_path, spec_text=two_scn_spec, baseline=["SCN-CPCRUD-001-1"])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any(
        "uncovered scenario SCN-CPCRUD-001-2 requires a @pytest.mark.spec test" in err for err in report.errors
    ), report.errors


def test_covered_scenario_still_in_baseline_rejected_with_update_hint(tmp_path: Path) -> None:
    """Covered scenarios still listed in `spec_traceability_baseline.json` fail with `--write-baseline` hint."""
    test_src = 'import pytest\n\n@pytest.mark.spec("SCN-CPCRUD-001-1")\ndef test_alpha() -> None:\n    pass\n'
    baseline = _write_repo(tmp_path, test_text=test_src, baseline=["SCN-CPCRUD-001-1"])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any(
        "already-covered scenario 'SCN-CPCRUD-001-1'" in err and "--write-baseline" in err for err in report.errors
    ), report.errors


def test_modified_delta_changing_req_id_rejected(tmp_path: Path) -> None:
    """`MODIFIED` deltas changing an existing requirement's `REQ-*` ID are rejected."""
    delta = """\
## MODIFIED Requirements

### Requirement: Alpha Validation

**ID**: REQ-CPCRUD-002\\
**Intent**: Reject malformed templates offline.\\
**Non-goals**: Live state planning.

The engine SHALL validate templates offline.

#### Scenario: SCN-CPCRUD-002-1 — Invalid template fails offline

- **GIVEN** a malformed template
- **WHEN** `validate(template)` is called
- **THEN** it SHALL return validation errors
"""
    baseline = _write_repo(tmp_path, baseline=["SCN-CPCRUD-001-1"], delta_text=delta)

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any("changed ID from REQ-CPCRUD-001 to REQ-CPCRUD-002" in err for err in report.errors), report.errors


def test_modified_delta_dropping_existing_scn_rejected_unless_explicit(tmp_path: Path) -> None:
    """`MODIFIED` deltas cannot silently drop existing `SCN-*` IDs unless explicitly declared."""
    two_scn_spec = (
        _VALID_SPEC
        + "\n#### Scenario: SCN-CPCRUD-001-2 — Valid template passes offline\n\n"
        + "- **WHEN** a valid template is checked\n"
        + "- **THEN** it SHALL return zero errors\n"
    )
    delta_dropping = """\
## MODIFIED Requirements

### Requirement: Alpha Validation

**ID**: REQ-CPCRUD-001\\
**Intent**: Reject malformed templates offline.\\
**Non-goals**: Live state planning.

The engine SHALL validate templates offline.

#### Scenario: SCN-CPCRUD-001-1 — Invalid template fails offline

- **GIVEN** a malformed template
- **WHEN** `validate(template)` is called
- **THEN** it SHALL return validation errors
"""
    baseline = _write_repo(
        tmp_path,
        spec_text=two_scn_spec,
        baseline=["SCN-CPCRUD-001-1"],
        delta_text=delta_dropping,
    )
    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any("dropped existing scenario ID(s): SCN-CPCRUD-001-2" in err for err in report.errors), report.errors

    delta_explicit = delta_dropping + "\n<!-- removed-scenarios: SCN-CPCRUD-001-2 -->\n"
    baseline = _write_repo(
        tmp_path,
        spec_text=two_scn_spec,
        baseline=["SCN-CPCRUD-001-1"],
        delta_text=delta_explicit,
    )
    report_explicit = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert report_explicit.errors == [], report_explicit.errors


def test_unknown_or_bare_pytest_spec_marker_rejected(tmp_path: Path) -> None:
    """Unknown scenario IDs or bare `@pytest.mark.spec` decorators fail validation."""
    test_src = (
        "import pytest\n\n"
        '@pytest.mark.spec("SCN-CPCRUD-999-1")\n'
        "def test_unknown() -> None:\n"
        "    pass\n\n"
        "@pytest.mark.spec\n"
        "def test_bare() -> None:\n"
        "    pass\n"
    )
    baseline = _write_repo(tmp_path, test_text=test_src, baseline=["SCN-CPCRUD-001-1"])

    report = _MOD.run_check(root=tmp_path, baseline_path=baseline)
    assert any("unknown scenario ID 'SCN-CPCRUD-999-1'" in err for err in report.errors), report.errors
    assert any("bare '@pytest.mark.spec' requires a scenario ID" in err for err in report.errors), report.errors
