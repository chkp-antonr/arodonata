"""SmartConsole's numbering of package FPCR_UAT_Active, access, ordered layer 0 (Anton's screenshot, spec 2.5)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# (number, kind, name, range, depth)
FPCR_UAT_ACTIVE_ACCESS: list[tuple[str, str, str, str, int]] = [
    ("1", "rule", "arod-glb-ping", "", 0),
    ("2", "parent-rule", "Parent rule for Domain's policy", "", 0),
    ("", "section", "FPCR_UAT_Section_4", "2.1-2.2", 1),
    ("2.1", "rule", "fpcr_uat_FPCR_UAT_Active_4", "", 1),
    ("2.2", "rule", "FPCR_UAT_Active_InlineJump", "", 1),
    ("2.2.1", "rule", "fpcr_uat_inline_FPCR_UAT_Active_allow", "", 2),
    ("2.2.2", "rule", "fpcr_uat_inline_FPCR_UAT_Active_cleanup", "", 2),
    ("", "section", "FPCR_UAT_Section_3", "2.3", 1),
    ("2.3", "rule", "fpcr_uat_FPCR_UAT_Active_3", "", 1),
    ("", "section", "FPCR_UAT_Section_2", "2.4", 1),
    ("2.4", "rule", "fpcr_uat_FPCR_UAT_Active_2", "", 1),
    ("", "section", "FPCR_UAT_Section_1", "2.5", 1),
    ("2.5", "rule", "fpcr_uat_FPCR_UAT_Active_1", "", 1),
    ("", "section", "Cleanup", "2.6", 1),
    ("2.6", "rule", "Cleanup rule", "", 1),
    ("3", "rule", "arod-glb-post", "", 0),
]


def summarize(entries: Iterable[Any]) -> list[tuple[str, str, str, str, int]]:
    return [(e.number, e.kind, e.name, e.range, e.depth) for e in entries]
