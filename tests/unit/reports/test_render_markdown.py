from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path

from arodonata.reports.changes import render_change_report
from arodonata.reports.changes.render import RenderOptions
from tests.unit.reports.entries import access_rule, d4_layer, d4_rule, entry, modified, session_meta
from tests.unit.reports.fakes import FakeReportClient
from tests.unit.reports.sample import HOSTILE, OPTIONS, object_rows, rule_rows, sample_report
from tests.unit.rulebase.fakes import domain4_snapshot

GOLDEN = Path(__file__).parent / "golden" / "change_report.md"


def md(report, options=OPTIONS) -> str:
    out = render_change_report(report, ["markdown"], options).markdown
    assert out is not None
    return out


async def test_markdown_golden():
    text = md(await sample_report())
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(text)
    assert text == GOLDEN.read_text()


async def test_status_markers_and_strikethrough():
    text = md(await sample_report())
    assert any(line.startswith("| [+] [x] |") for line in text.splitlines())  # added + disabled
    deleted = next(line for line in text.splitlines() if line.startswith("| [-] |"))
    assert "~~" in deleted and "(before deletion)" in deleted
    assert any(line.startswith("| [~] [x] |") for line in text.splitlines())  # enabled -> disabled
    assert "+web-2" in text and "~~web-1~~" in text
    assert "(was 2.2.1)" in text  # the moved inline rule
    assert "| [-] | – (position 5 in its section) (before deletion) |" in text  # D27: sectioned layer, no number
    assert "- 2.3 fpcr\\_uat\\_FPCR\\_UAT\\_Active\\_3: source: -web-1 +web-2; action: Accept → Drop" in text


async def test_truncation_message_counts_remaining_rules():
    report = await sample_report()
    text = md(report, OPTIONS.model_copy(update={"markdown_max_rules": 2}))
    assert f"…and {rule_rows(report) - 2} more rules, full report via the library" in text
    assert sum(1 for line in text.splitlines() if line.startswith(("| [+]", "| [-]", "| [~]"))) == 2
    assert "#### pending \\| change" in text  # session headers are never truncated


async def test_truncation_counts_shared_inline_rule_once_per_package_row():
    snap = domain4_snapshot()
    layout = snap.packages[0]
    two = dataclasses.replace(
        snap, packages=(layout, dataclasses.replace(layout, package_uid="p2", package_name="Copy"))
    )
    inline = d4_rule("fpcr_uat_inline_FPCR_UAT_Active_allow")
    body = access_rule(inline["uid"], "allow", layer=inline["layer"], comments="a")
    fake = FakeReportClient()
    fake.changes[("m1", "Domain4")] = [
        entry(session_meta("pub-1"), modified=[modified(body, {**body, "comments": "b"})])
    ]
    fake.snapshots[("m1", "Domain4")] = two
    report = await sample_report(fake=fake)
    assert rule_rows(report) == 2
    assert "…and 1 more rules, full report via the library" in md(
        report, OPTIONS.model_copy(update={"markdown_max_rules": 1})
    )


async def test_object_truncation():
    report = await sample_report()
    text = md(report, OPTIONS.model_copy(update={"markdown_max_objects": 1}))
    assert f"…and {object_rows(report) - 1} more objects, full report via the library" in text


async def test_pipes_escaped_in_cells():
    text = md(await sample_report())
    assert "Open \\| web access" in text and "pending \\| change" in text
    width = None
    for line in text.splitlines():
        if not line.startswith("|"):
            width = None
            continue
        pipes = len(re.findall(r"(?<!\\)\|", line))  # unescaped cell separators
        width = width or pipes
        assert pipes == width, line


async def test_markdown_cp_names_with_link_and_markup_neutralised():
    text = md(await sample_report())
    assert "\\[x\\]\\(javascript:alert\\(1\\)\\) \\<img src=x\\> \\*\\*b\\*\\* \\~\\~s\\~\\~ \\+lead \\\\" in text
    assert "](javascript" not in text and "<img" not in text.replace("\\<img", "")
    assert HOSTILE not in text


async def test_markdown_has_no_raw_appendix():
    text = md(await sample_report(include_raw=True))
    assert "Raw show-changes" not in text and '"changes"' not in text


async def test_markdown_title_and_header_fields_limited_markdown():
    text = md(await sample_report(), RenderOptions(title="[x](javascript:y) **T**", header_fields={"A|B": "`c`"}))
    assert text.startswith("# \\[x\\]\\(javascript:y\\) **T**\n") and "- A\\|B: `c`" in text


async def test_code_span_newline_cannot_inject_html_block():
    evil = "T `x\n<script>alert(1)</script>`"
    text = md(await sample_report(), RenderOptions(title=evil, header_fields={"K": evil}))
    assert not any(line.startswith("<script") for line in text.splitlines())


async def test_modified_item_marker_is_escaped_star():
    text = md(await sample_report())
    assert "web-1\\*" in text


async def _secmove_report():
    layer = d4_layer("FPCR_UAT_Active Network")
    old = access_rule("mv1", "mover", layer=layer, position=1, comments="a")
    fake = FakeReportClient()
    fake.changes[("m1", "Domain4")] = [entry(session_meta("pub-1"), modified=[modified(old, {**old, "comments": "b"})])]
    fake.snapshots[("m1", "Domain4")] = domain4_snapshot()
    from arodonata.reports.changes import SessionScope, collect_change_report

    return await collect_change_report(fake, [SessionScope(domain="Domain4", session_uids=["pub-1"])])  # type: ignore[arg-type]


async def test_section_move_with_equal_positions_is_marked_moved_with_position_detail():
    report = await _secmove_report()
    [rule] = next(s for srv in report.servers for d in srv.domains for s in d.sessions).rules
    assert rule.moved and any(c.field == "position" and (c.old, c.new) == ("1", "1") for c in rule.changes)
    text = md(report)
    row = next(line for line in text.splitlines() if "mover" in line or "(moved)" in line)
    assert "(moved)" in row
    from tests.unit.reports.test_render_html import html

    page = html(report)
    assert "num-moved" in page and "(moved)" in page


async def test_was_number_case_has_no_extra_moved_suffix():
    text = md(await sample_report())
    assert "(was 2.2.1)" in text and "(was 2.2.1) (moved)" not in text
