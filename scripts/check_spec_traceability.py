"""OpenSpec requirement/scenario format and pytest traceability gate."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

CAPABILITY_PREFIXES: dict[str, str] = {
    "ai-builder": "AIBUILD",
    "api-reference": "APIREF",
    "cache-and-sync": "CACHE",
    "change-reports": "REPORT",
    "client-and-facade": "CLIENT",
    "configuration": "CONFIG",
    "cpcrud": "CPCRUD",
    "gateway-topology": "TOPO",
    "integration-testing-and-examples": "ITEST",
    "mcp-server": "MCP",
    "rulebase-and-numbering": "RULE",
    "sessions-and-mdm": "SESS",
    "transport-and-tls": "TRANS",
}

MAX_REQUIREMENT_BODY_LENGTH = 500

_REQ_HEADER_RE = re.compile(r"^###\s+Requirement:\s*(.+?)\s*(?:#+\s*)?$", re.IGNORECASE)
_SCENARIO_HEADER_RE = re.compile(r"^####\s+Scenario:\s*(SCN-([A-Z][A-Z0-9]*)-(\d{3})-(\d+))\s+—\s+(\S.*)$")
_ANY_LEVEL4_RE = re.compile(r"^####\s+")
_LEVEL2_RE = re.compile(r"^##\s+")
_DELTA_SECTION_RE = re.compile(r"^##\s+(ADDED|MODIFIED|REMOVED|RENAMED)\s+Requirements\s*$", re.IGNORECASE)
_REQUIREMENTS_SECTION_RE = re.compile(r"^##\s+Requirements\s*$", re.IGNORECASE)
_METADATA_RE = re.compile(r"^\*\*([^*]+)\*\*:(.*)$")
_REQ_ID_RE = re.compile(r"^REQ-([A-Z][A-Z0-9]*)-(\d{3})$")
_SCN_ID_RE = re.compile(r"^SCN-([A-Z][A-Z0-9]*)-(\d{3})-(\d+)$")
_SHALL_OR_MUST_RE = re.compile(r"\b(SHALL|MUST)\b")
_REF_TOKEN_RE = re.compile(r"\b(REQ-[A-Z][A-Z0-9]*-\d+|SCN-[A-Z][A-Z0-9]*-\d+-\d+)\b")
_REMOVED_BULLET_RE = re.compile(r"^\s*[-*+]\s*`?###\s*Requirement:\s*(.+?)`?\s*$")
_RENAMED_FROM_RE = re.compile(r"^\s*[-*+]?\s*FROM:\s*`?###\s*Requirement:\s*(.+?)`?\s*$")
_RENAMED_TO_RE = re.compile(r"^\s*[-*+]?\s*TO:\s*`?###\s*Requirement:\s*(.+?)`?\s*$")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_REMOVED_SCENARIOS_COMMENT_RE = re.compile(r"<!--\s*removed-scenarios:\s*([^>]+?)-->", re.IGNORECASE | re.DOTALL)
_FENCE_OPEN_RE = re.compile(r"^\s*(`{3,}|~{3,})")


@dataclass(frozen=True, slots=True)
class ParsedScenario:
    """Single scenario parsed from a requirement block."""

    scn_id: str
    dom: str
    req_num: str
    seq: int
    title: str
    line: int
    has_body: bool


@dataclass(frozen=True, slots=True)
class ParsedRequirement:
    """Single requirement block parsed from a main spec or delta spec."""

    name: str
    normalized_name: str
    line: int
    req_id: str | None
    dom: str | None
    num: str | None
    scenarios: tuple[ParsedScenario, ...]
    file_path: Path
    capability: str
    explicitly_removed_scns: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class DeltaSpecResult:
    """Parsed delta sections from an active change spec file."""

    added: tuple[ParsedRequirement, ...]
    modified: tuple[ParsedRequirement, ...]
    removed: tuple[tuple[str, int], ...]
    renamed: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True, slots=True)
class SpecMarkerUsage:
    """Single `@pytest.mark.spec(...)` invocation found by AST scan."""

    scn_id: str | None
    file_path: Path
    line: int
    error: str | None = None


@dataclass(slots=True)
class TraceabilityReport:
    """Result summary and collected validation errors."""

    requirement_count: int = 0
    scenario_count: int = 0
    covered_count: int = 0
    baseline_count: int = 0
    marker_count: int = 0
    errors: list[str] = field(default_factory=list)
    untested_scenarios: list[str] = field(default_factory=list)


def _normalize_req_name(name: str) -> str:
    return " ".join(name.strip().split()).lower()


def _build_fence_mask(lines: list[str]) -> list[bool]:
    mask: list[bool] = []
    fence_char = ""
    fence_len = 0
    for line in lines:
        if not fence_char:
            match = _FENCE_OPEN_RE.match(line)
            if match:
                token = match.group(1)
                fence_char = token[0]
                fence_len = len(token)
                mask.append(True)
                continue
            mask.append(False)
        else:
            mask.append(True)
            stripped = line.strip()
            if stripped and set(stripped) == {fence_char} and len(stripped) >= fence_len:
                fence_char = ""
                fence_len = 0
    return mask


def _format_loc(root: Path, file_path: Path, line: int) -> str:
    try:
        rel = file_path.relative_to(root).as_posix()
    except ValueError:
        rel = file_path.as_posix()
    return f"{rel}:{line}"


def _capability_from_spec_path(base_specs_dir: Path, spec_file: Path) -> str:
    rel = spec_file.relative_to(base_specs_dir)
    return rel.parent.as_posix()


def _parse_requirement_block(
    *,
    root: Path,
    file_path: Path,
    capability: str,
    header_line_no: int,
    raw_name: str,
    block_lines: list[str],
    block_mask: list[bool],
    errors: list[str],
) -> ParsedRequirement:
    loc = _format_loc(root, file_path, header_line_no)
    expected_prefix = CAPABILITY_PREFIXES.get(capability)

    first_scn_rel = next(
        (i for i, ln in enumerate(block_lines) if not block_mask[i] and _ANY_LEVEL4_RE.match(ln)),
        len(block_lines),
    )
    pre_scn_lines = block_lines[:first_scn_rel]
    pre_scn_mask = block_mask[:first_scn_rel]

    metadata_items: list[tuple[int, str, str]] = []
    norm_lines: list[str] = []
    saw_norm_text = False
    for idx, line in enumerate(pre_scn_lines):
        if pre_scn_mask[idx]:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        meta_match = _METADATA_RE.match(stripped)
        if meta_match and not saw_norm_text:
            key = meta_match.group(1).strip()
            val = meta_match.group(2).strip()
            metadata_items.append((header_line_no + 1 + idx, key, val))
        else:
            saw_norm_text = True
            norm_lines.append(stripped)

    req_id: str | None = None
    dom: str | None = None
    num: str | None = None
    has_intent = False
    has_non_goals = False
    for meta_idx, (m_line, m_key, m_val) in enumerate(metadata_items):
        m_loc = _format_loc(root, file_path, m_line)
        is_last = meta_idx == len(metadata_items) - 1
        raw_line = pre_scn_lines[m_line - header_line_no - 1].rstrip("\r\n")
        if not is_last and not raw_line.endswith("\\"):
            errors.append(f"{m_loc}: metadata line '**{m_key}**:' must end with '\\' for clean Markdown line breaks")
        if is_last and raw_line.endswith("\\"):
            errors.append(f"{m_loc}: final metadata line '**{m_key}**:' must not end with a trailing '\\'")

        clean_val = m_val[:-1].strip() if m_val.endswith("\\") else m_val
        key_lower = m_key.lower()
        if key_lower == "acceptance":
            errors.append(f"{m_loc}: forbidden '**Acceptance**:' metadata field")
        elif key_lower == "id":
            id_match = _REQ_ID_RE.fullmatch(clean_val)
            if not id_match:
                errors.append(f"{m_loc}: invalid requirement ID {clean_val!r}; expected REQ-<DOM>-<NNN>")
            else:
                req_id = clean_val
                dom, num = id_match.group(1), id_match.group(2)
                if expected_prefix is not None and dom != expected_prefix:
                    errors.append(
                        f"{m_loc}: requirement ID {req_id} uses prefix {dom!r}, "
                        f"expected {expected_prefix!r} for capability {capability!r}"
                    )
        elif key_lower == "intent":
            if not clean_val:
                errors.append(f"{m_loc}: '**Intent**:' metadata cannot be empty")
            else:
                has_intent = True
        elif key_lower == "non-goals":
            if not clean_val:
                errors.append(f"{m_loc}: '**Non-goals**:' metadata cannot be empty")
            else:
                has_non_goals = True

    if req_id is None and not any(k.lower() == "id" for _, k, _ in metadata_items):
        errors.append(f"{loc}: requirement '{raw_name}' is missing required '**ID**: REQ-<DOM>-<NNN>' metadata")
    if not has_intent and not any(k.lower() == "intent" for _, k, _ in metadata_items):
        errors.append(f"{loc}: requirement '{raw_name}' is missing required '**Intent**:' metadata")
    if not has_non_goals and not any(k.lower() == "non-goals" for _, k, _ in metadata_items):
        errors.append(f"{loc}: requirement '{raw_name}' is missing required '**Non-goals**:' metadata")

    norm_body = "\n".join(norm_lines)
    if not norm_body:
        errors.append(f"{loc}: requirement '{raw_name}' is missing normative requirement text")
    else:
        if not _SHALL_OR_MUST_RE.search(norm_body):
            errors.append(f"{loc}: requirement '{raw_name}' normative text must contain SHALL or MUST")
        if len(norm_body) > MAX_REQUIREMENT_BODY_LENGTH:
            errors.append(
                f"{loc}: requirement '{raw_name}' normative text is {len(norm_body)} chars "
                f"(max {MAX_REQUIREMENT_BODY_LENGTH})"
            )

    scenarios: list[ParsedScenario] = []
    seen_seqs: set[int] = set()
    i = first_scn_rel
    while i < len(block_lines):
        if block_mask[i] or not _ANY_LEVEL4_RE.match(block_lines[i]):
            i += 1
            continue
        scn_line_no = header_line_no + 1 + i
        scn_loc = _format_loc(root, file_path, scn_line_no)
        scn_header = block_lines[i].strip()
        j = i + 1
        while j < len(block_lines) and (block_mask[j] or not _ANY_LEVEL4_RE.match(block_lines[j])):
            j += 1
        scn_body = "\n".join(block_lines[i + 1 : j]).strip()
        has_body = bool(scn_body)
        if not has_body:
            errors.append(f"{scn_loc}: scenario header has an empty body")

        scn_match = _SCENARIO_HEADER_RE.fullmatch(scn_header)
        if not scn_match:
            errors.append(
                f"{scn_loc}: invalid level-4 header {scn_header!r}; expected '#### Scenario: SCN-<DOM>-<NNN>-<K> — <Title>'"
            )
        else:
            scn_id, s_dom, s_num, s_seq_raw, title = (
                scn_match.group(1),
                scn_match.group(2),
                scn_match.group(3),
                scn_match.group(4),
                scn_match.group(5).strip(),
            )
            seq = int(s_seq_raw)
            if seq <= 0:
                errors.append(f"{scn_loc}: scenario sequence number must be >= 1 in {scn_id}")
            if seq in seen_seqs:
                errors.append(f"{scn_loc}: duplicate scenario index {seq} within requirement {req_id or raw_name}")
            seen_seqs.add(seq)
            if dom is not None and num is not None and (s_dom != dom or s_num != num):
                errors.append(f"{scn_loc}: scenario ID {scn_id} does not match parent requirement {req_id}")
            elif expected_prefix is not None and s_dom != expected_prefix:
                errors.append(f"{scn_loc}: scenario ID {scn_id} uses prefix {s_dom!r}, expected {expected_prefix!r}")
            scenarios.append(
                ParsedScenario(
                    scn_id=scn_id,
                    dom=s_dom,
                    req_num=s_num,
                    seq=seq,
                    title=title,
                    line=scn_line_no,
                    has_body=has_body,
                )
            )
        i = j

    if not scenarios:
        errors.append(f"{loc}: requirement '{raw_name}' must contain at least one valid scenario")

    non_fenced_text = "\n".join(ln for idx, ln in enumerate(block_lines) if not block_mask[idx])
    explicitly_removed: set[str] = set()
    for cm in _REMOVED_SCENARIOS_COMMENT_RE.finditer(non_fenced_text):
        for tok in _REF_TOKEN_RE.findall(cm.group(1)):
            if tok.startswith("SCN-"):
                explicitly_removed.add(tok)

    return ParsedRequirement(
        name=raw_name.strip(),
        normalized_name=_normalize_req_name(raw_name),
        line=header_line_no,
        req_id=req_id,
        dom=dom,
        num=num,
        scenarios=tuple(scenarios),
        file_path=file_path,
        capability=capability,
        explicitly_removed_scns=frozenset(explicitly_removed),
    )


def _parse_main_spec(
    *,
    root: Path,
    specs_dir: Path,
    spec_file: Path,
    errors: list[str],
) -> list[ParsedRequirement]:
    capability = _capability_from_spec_path(specs_dir, spec_file)
    lines = spec_file.read_text(encoding="utf-8").splitlines()
    mask = _build_fence_mask(lines)

    req_sec_idx = next(
        (i for i, ln in enumerate(lines) if not mask[i] and _REQUIREMENTS_SECTION_RE.match(ln)),
        -1,
    )
    if req_sec_idx == -1:
        errors.append(f"{_format_loc(root, spec_file, 1)}: missing '## Requirements' section")
        return []

    req_end_idx = len(lines)
    for i in range(req_sec_idx + 1, len(lines)):
        if not mask[i] and _LEVEL2_RE.match(lines[i]):
            req_end_idx = i
            errors.append(
                f"{_format_loc(root, spec_file, i + 1)}: unexpected level-2 heading inside/after "
                f"'## Requirements': {lines[i].strip()!r}"
            )
            break

    for i in range(len(lines)):
        if mask[i]:
            continue
        if i <= req_sec_idx and _REQ_HEADER_RE.match(lines[i]):
            errors.append(f"{_format_loc(root, spec_file, i + 1)}: requirement appears outside '## Requirements'")

    req_starts: list[tuple[int, str]] = []
    for i in range(req_sec_idx + 1, req_end_idx):
        if mask[i]:
            continue
        match = _REQ_HEADER_RE.match(lines[i])
        if match:
            req_starts.append((i, match.group(1).strip()))

    parsed: list[ParsedRequirement] = []
    for idx, (start_i, raw_name) in enumerate(req_starts):
        end_i = req_starts[idx + 1][0] if idx + 1 < len(req_starts) else req_end_idx
        parsed.append(
            _parse_requirement_block(
                root=root,
                file_path=spec_file,
                capability=capability,
                header_line_no=start_i + 1,
                raw_name=raw_name,
                block_lines=lines[start_i + 1 : end_i],
                block_mask=mask[start_i + 1 : end_i],
                errors=errors,
            )
        )
    return parsed


def _parse_delta_spec(
    *,
    root: Path,
    change_specs_dir: Path,
    spec_file: Path,
    errors: list[str],
) -> DeltaSpecResult:
    capability = _capability_from_spec_path(change_specs_dir, spec_file)
    lines = spec_file.read_text(encoding="utf-8").splitlines()
    mask = _build_fence_mask(lines)

    sections: list[tuple[str, int, int]] = []
    for i, ln in enumerate(lines):
        if mask[i]:
            continue
        m = _DELTA_SECTION_RE.match(ln)
        if m:
            sections.append((m.group(1).upper(), i, len(lines)))

    for idx in range(len(sections) - 1):
        kind, start_i, _ = sections[idx]
        sections[idx] = (kind, start_i, sections[idx + 1][1])

    added: list[ParsedRequirement] = []
    modified: list[ParsedRequirement] = []
    removed: list[tuple[str, int]] = []
    renamed: list[tuple[str, str, int]] = []

    for kind, start_i, end_i in sections:
        if kind in {"ADDED", "MODIFIED"}:
            req_starts: list[tuple[int, str]] = []
            for i in range(start_i + 1, end_i):
                if mask[i]:
                    continue
                m = _REQ_HEADER_RE.match(lines[i])
                if m:
                    req_starts.append((i, m.group(1).strip()))
            for r_idx, (r_start, r_name) in enumerate(req_starts):
                r_end = req_starts[r_idx + 1][0] if r_idx + 1 < len(req_starts) else end_i
                req_obj = _parse_requirement_block(
                    root=root,
                    file_path=spec_file,
                    capability=capability,
                    header_line_no=r_start + 1,
                    raw_name=r_name,
                    block_lines=lines[r_start + 1 : r_end],
                    block_mask=mask[r_start + 1 : r_end],
                    errors=errors,
                )
                if kind == "ADDED":
                    added.append(req_obj)
                else:
                    modified.append(req_obj)
        elif kind == "REMOVED":
            for i in range(start_i + 1, end_i):
                if mask[i]:
                    continue
                hm = _REQ_HEADER_RE.match(lines[i])
                bm = _REMOVED_BULLET_RE.match(lines[i])
                if hm:
                    removed.append((hm.group(1).strip(), i + 1))
                elif bm:
                    removed.append((bm.group(1).strip(), i + 1))
        elif kind == "RENAMED":
            pending_from: tuple[str, int] | None = None
            for i in range(start_i + 1, end_i):
                if mask[i]:
                    continue
                fm = _RENAMED_FROM_RE.match(lines[i])
                if fm:
                    pending_from = (fm.group(1).strip(), i + 1)
                    continue
                tm = _RENAMED_TO_RE.match(lines[i])
                if tm and pending_from is not None:
                    renamed.append((pending_from[0], tm.group(1).strip(), pending_from[1]))
                    pending_from = None

    return DeltaSpecResult(
        added=tuple(added),
        modified=tuple(modified),
        removed=tuple(removed),
        renamed=tuple(renamed),
    )


def _extract_spec_id_from_expr(node: ast.AST) -> list[str | None]:
    """Extract literal scenario IDs from `@pytest.mark.spec(...)` or `pytest.mark.spec(...)`."""
    if not isinstance(node, ast.Call):
        return [None]
    ids: list[str | None] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            ids.append(arg.value)
        else:
            ids.append(None)
    for kw in node.keywords:
        if kw.arg == "id":
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                ids.append(kw.value.value)
            else:
                ids.append(None)
    return ids or [None]


def _is_spec_mark_expr(node: ast.AST) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    if not isinstance(target, ast.Attribute) or target.attr != "spec":
        return False
    val = target.value
    if isinstance(val, ast.Attribute) and val.attr == "mark":
        return True
    return isinstance(val, ast.Name) and val.id == "mark"


def _collect_markers_from_node(node: ast.expr, file_path: Path, out: list[SpecMarkerUsage]) -> None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            _collect_markers_from_node(elt, file_path, out)
        return
    if _is_spec_mark_expr(node):
        if not isinstance(node, ast.Call):
            out.append(SpecMarkerUsage(None, file_path, node.lineno, "bare '@pytest.mark.spec' requires a scenario ID"))
            return
        for scn_id in _extract_spec_id_from_expr(node):
            if scn_id is None:
                out.append(
                    SpecMarkerUsage(
                        None,
                        file_path,
                        node.lineno,
                        "@pytest.mark.spec(...) requires string literal 'SCN-<DOM>-<NNN>-<K>' argument(s)",
                    )
                )
            else:
                out.append(SpecMarkerUsage(scn_id, file_path, node.lineno))


def _scan_test_markers(root: Path, errors: list[str]) -> list[SpecMarkerUsage]:
    tests_dir = root / "tests"
    if not tests_dir.exists():
        return []
    usages: list[SpecMarkerUsage] = []
    for py_file in sorted(tests_dir.rglob("*.py")):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as exc:
            errors.append(f"{_format_loc(root, py_file, exc.lineno or 1)}: failed to parse Python test: {exc.msg}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for dec in node.decorator_list:
                    _collect_markers_from_node(dec, py_file, usages)
            elif isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
                    _collect_markers_from_node(node.value, py_file, usages)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "param":
                for kw in node.keywords:
                    if kw.arg == "marks":
                        _collect_markers_from_node(kw.value, py_file, usages)
    for usage in usages:
        if usage.error is not None:
            errors.append(f"{_format_loc(root, usage.file_path, usage.line)}: {usage.error}")
    return usages


def _scan_cross_references(
    *,
    root: Path,
    spec_files: list[Path],
    effective_reqs: set[str],
    effective_scns: set[str],
    errors: list[str],
) -> None:
    for spec_file in spec_files:
        raw_text = spec_file.read_text(encoding="utf-8")
        # Preserve line numbers while blanking out multi-line HTML comments.
        cleaned = _HTML_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), raw_text)
        lines = cleaned.splitlines()
        mask = _build_fence_mask(lines)
        in_non_target_delta = False
        for idx, line in enumerate(lines):
            if mask[idx]:
                continue
            delta_hdr = _DELTA_SECTION_RE.match(line)
            if delta_hdr:
                in_non_target_delta = delta_hdr.group(1).upper() in {"REMOVED", "RENAMED"}
                continue
            if in_non_target_delta:
                continue
            # Do not mistake a requirement's own `**ID**:` or `#### Scenario: SCN-...` header for a cross-reference.
            scan_line = line
            meta_match = _METADATA_RE.match(line.strip())
            if meta_match and meta_match.group(1).strip().lower() == "id":
                continue
            scn_match = _SCENARIO_HEADER_RE.match(line.strip())
            if scn_match:
                scan_line = scn_match.group(5)
            for ref in _REF_TOKEN_RE.findall(scan_line):
                loc = _format_loc(root, spec_file, idx + 1)
                if (ref.startswith("REQ-") and ref not in effective_reqs) or (
                    ref.startswith("SCN-") and ref not in effective_scns
                ):
                    errors.append(f"{loc}: cross-reference '{ref}' does not exist in specs")


def run_check(
    *,
    root: Path,
    baseline_path: Path,
    write_baseline: bool = False,
) -> TraceabilityReport:
    """Validate spec formatting, IDs, cross-references, and `@pytest.mark.spec` traceability."""
    report = TraceabilityReport()
    specs_dir = root / "openspec" / "specs"
    changes_dir = root / "openspec" / "changes"

    main_spec_files = sorted(specs_dir.glob("**/spec.md")) if specs_dir.exists() else []
    if not main_spec_files:
        report.errors.append(f"No OpenSpec main specification files found under {specs_dir}")
        return report

    main_reqs_by_cap: dict[str, dict[str, ParsedRequirement]] = {}
    effective_reqs: dict[str, ParsedRequirement] = {}
    effective_scns: dict[str, tuple[str, Path, int]] = {}
    seen_main_reqs: dict[str, tuple[Path, int]] = {}
    seen_main_scns: dict[str, tuple[Path, int]] = {}

    for spec_file in main_spec_files:
        cap = _capability_from_spec_path(specs_dir, spec_file)
        reqs = _parse_main_spec(root=root, specs_dir=specs_dir, spec_file=spec_file, errors=report.errors)
        cap_map = main_reqs_by_cap.setdefault(cap, {})
        for req in reqs:
            cap_map[req.normalized_name] = req
            if req.req_id is not None:
                if req.req_id in seen_main_reqs:
                    prev_path, prev_line = seen_main_reqs[req.req_id]
                    report.errors.append(
                        f"{_format_loc(root, req.file_path, req.line)}: duplicate requirement ID {req.req_id} "
                        f"(already defined at {_format_loc(root, prev_path, prev_line)})"
                    )
                else:
                    seen_main_reqs[req.req_id] = (req.file_path, req.line)
                    effective_reqs[req.req_id] = req
            for scn in req.scenarios:
                if scn.scn_id in seen_main_scns:
                    prev_path, prev_line = seen_main_scns[scn.scn_id]
                    report.errors.append(
                        f"{_format_loc(root, req.file_path, scn.line)}: duplicate scenario ID {scn.scn_id} "
                        f"(already defined at {_format_loc(root, prev_path, prev_line)})"
                    )
                else:
                    seen_main_scns[scn.scn_id] = (req.file_path, scn.line)
                    effective_scns[scn.scn_id] = (req.req_id or "", req.file_path, scn.line)

    delta_spec_files: list[Path] = []
    if changes_dir.exists():
        for change_entry in sorted(changes_dir.iterdir()):
            if not change_entry.is_dir() or change_entry.name == "archive" or change_entry.name.startswith("."):
                continue
            change_specs_dir = change_entry / "specs"
            if not change_specs_dir.exists():
                continue
            for delta_file in sorted(change_specs_dir.glob("**/spec.md")):
                delta_spec_files.append(delta_file)
                cap = _capability_from_spec_path(change_specs_dir, delta_file)
                delta = _parse_delta_spec(
                    root=root,
                    change_specs_dir=change_specs_dir,
                    spec_file=delta_file,
                    errors=report.errors,
                )
                cap_main = main_reqs_by_cap.get(cap, {})
                renamed_from_by_to = {_normalize_req_name(to): _normalize_req_name(frm) for frm, to, _ in delta.renamed}

                for rem_name, _ in delta.removed:
                    norm_rem = _normalize_req_name(rem_name)
                    old_req = cap_main.get(norm_rem)
                    if old_req and old_req.req_id is not None:
                        effective_reqs.pop(old_req.req_id, None)
                        for scn in old_req.scenarios:
                            effective_scns.pop(scn.scn_id, None)

                for mod_req in delta.modified:
                    lookup_key = renamed_from_by_to.get(mod_req.normalized_name, mod_req.normalized_name)
                    old_req = cap_main.get(lookup_key)
                    mod_loc = _format_loc(root, mod_req.file_path, mod_req.line)
                    if old_req is not None and old_req.req_id is not None:
                        if mod_req.req_id is not None and mod_req.req_id != old_req.req_id:
                            report.errors.append(
                                f"{mod_loc}: MODIFIED requirement '{mod_req.name}' changed ID from "
                                f"{old_req.req_id} to {mod_req.req_id} (must preserve existing ID for archive safety)"
                            )
                        old_scn_ids = {s.scn_id for s in old_req.scenarios}
                        mod_scn_ids = {s.scn_id for s in mod_req.scenarios}
                        dropped_scns = sorted(old_scn_ids - mod_scn_ids - mod_req.explicitly_removed_scns)
                        if dropped_scns:
                            report.errors.append(
                                f"{mod_loc}: MODIFIED requirement '{mod_req.name}' dropped existing scenario ID(s): "
                                f"{', '.join(dropped_scns)} "
                                "(preserve them or list in '<!-- removed-scenarios: ... -->')"
                            )
                        for old_scn in old_req.scenarios:
                            effective_scns.pop(old_scn.scn_id, None)
                    if mod_req.req_id is not None:
                        effective_reqs[mod_req.req_id] = mod_req
                    for scn in mod_req.scenarios:
                        if scn.scn_id in effective_scns:
                            prev_path, prev_line = effective_scns[scn.scn_id][1:]
                            report.errors.append(
                                f"{_format_loc(root, mod_req.file_path, scn.line)}: duplicate scenario ID "
                                f"{scn.scn_id} (already defined at {_format_loc(root, prev_path, prev_line)})"
                            )
                        else:
                            effective_scns[scn.scn_id] = (mod_req.req_id or "", mod_req.file_path, scn.line)

                for add_req in delta.added:
                    add_loc = _format_loc(root, add_req.file_path, add_req.line)
                    if add_req.req_id is not None:
                        if add_req.req_id in effective_reqs:
                            prev = effective_reqs[add_req.req_id]
                            report.errors.append(
                                f"{add_loc}: ADDED requirement ID {add_req.req_id} collides with "
                                f"{_format_loc(root, prev.file_path, prev.line)}"
                            )
                        else:
                            effective_reqs[add_req.req_id] = add_req
                    for scn in add_req.scenarios:
                        if scn.scn_id in effective_scns:
                            prev_path, prev_line = effective_scns[scn.scn_id][1:]
                            report.errors.append(
                                f"{_format_loc(root, add_req.file_path, scn.line)}: ADDED scenario ID {scn.scn_id} "
                                f"collides with {_format_loc(root, prev_path, prev_line)}"
                            )
                        else:
                            effective_scns[scn.scn_id] = (add_req.req_id or "", add_req.file_path, scn.line)

    effective_req_ids = set(effective_reqs)
    effective_scn_ids = set(effective_scns)

    _scan_cross_references(
        root=root,
        spec_files=[*main_spec_files, *delta_spec_files],
        effective_reqs=effective_req_ids,
        effective_scns=effective_scn_ids,
        errors=report.errors,
    )

    marker_usages = _scan_test_markers(root, report.errors)
    covered_scns: set[str] = set()
    for usage in marker_usages:
        if usage.scn_id is None:
            continue
        loc = _format_loc(root, usage.file_path, usage.line)
        if not _SCN_ID_RE.fullmatch(usage.scn_id):
            report.errors.append(f"{loc}: invalid @pytest.mark.spec ID {usage.scn_id!r}; expected SCN-<DOM>-<NNN>-<K>")
            continue
        if usage.scn_id not in effective_scn_ids:
            report.errors.append(f"{loc}: @pytest.mark.spec references unknown scenario ID {usage.scn_id!r}")
            continue
        covered_scns.add(usage.scn_id)

    untested = sorted(effective_scn_ids - covered_scns)
    report.requirement_count = len(effective_req_ids)
    report.scenario_count = len(effective_scn_ids)
    report.covered_count = len(covered_scns)
    report.marker_count = len(marker_usages)
    report.untested_scenarios = untested

    if write_baseline:
        if report.errors:
            return report
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": 1, "untested_scenarios": untested}
        baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        report.baseline_count = len(untested)
        return report

    if not baseline_path.exists():
        report.errors.append(
            f"Missing baseline file {baseline_path}; run with --write-baseline to initialize or cover all scenarios"
        )
        return report

    try:
        raw_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline_list = raw_baseline.get("untested_scenarios", [])
        if not isinstance(baseline_list, list) or not all(isinstance(item, str) for item in baseline_list):
            raise ValueError("'untested_scenarios' must be a list of strings")
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"Invalid baseline file {baseline_path}: {exc}")
        return report

    baseline_set = set(baseline_list)
    report.baseline_count = len(baseline_set)

    for stale_id in sorted(baseline_set - effective_scn_ids):
        report.errors.append(f"Baseline file contains unknown/stale scenario ID {stale_id!r}")

    for covered_id in sorted(baseline_set & covered_scns):
        report.errors.append(
            f"Baseline file still lists already-covered scenario {covered_id!r}; "
            "run 'uv run python scripts/check_spec_traceability.py --write-baseline' to update baseline"
        )

    for uncovered_id in untested:
        if uncovered_id not in baseline_set:
            _, s_path, s_line = effective_scns[uncovered_id]
            report.errors.append(
                f"{_format_loc(root, s_path, s_line)}: uncovered scenario {uncovered_id} "
                "requires a @pytest.mark.spec test (not in baseline)"
            )

    return report


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for OpenSpec traceability validation."""
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Validate OpenSpec requirement/scenario IDs and test traceability.")
    parser.add_argument("--root", type=Path, default=repo_root, help="Repository root path.")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to baseline JSON file (default: <root>/scripts/spec_traceability_baseline.json).",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write currently untested scenario IDs to the baseline file.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    baseline_path = (args.baseline or (root / "scripts" / "spec_traceability_baseline.json")).resolve()
    report = run_check(root=root, baseline_path=baseline_path, write_baseline=args.write_baseline)

    if report.errors:
        for err in report.errors:
            print(f"ERROR: {err}", file=sys.stderr)
        print(
            f"Spec traceability check FAILED with {len(report.errors)} error(s) "
            f"({report.requirement_count} requirements, {report.scenario_count} scenarios).",
            file=sys.stderr,
        )
        return 1

    action = "Wrote baseline for" if args.write_baseline else "Checked"
    print(
        f"{action} {report.requirement_count} requirements, {report.scenario_count} scenarios "
        f"({report.covered_count} covered by tests, {report.baseline_count} in baseline), "
        f"{report.marker_count} test markers: OK"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
