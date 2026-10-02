from __future__ import annotations

import pytest

from arodonata.reports.changes import ChangeReport, UnsupportedFormat, render_change_report
from tests.unit.reports.sample import OPTIONS, sample_report


async def test_only_requested_formats_built():
    report = await sample_report()
    result = render_change_report(report, ["json"])
    assert result.report is report and result.json is not None
    assert (result.html, result.markdown, result.pdf) == (None, None, None)
    assert render_change_report(report).json is None


async def test_pdf_raises_unsupported_format():
    with pytest.raises(UnsupportedFormat, match="pdf"):
        render_change_report(await sample_report(), ["markdown", "pdf"])


async def test_unknown_format_and_bare_str_rejected():
    report = await sample_report()
    with pytest.raises(ValueError, match="unknown report format 'docx'"):
        render_change_report(report, ["docx"])  # type: ignore[list-item]
    with pytest.raises(TypeError, match="not a str"):
        render_change_report(report, "html")  # type: ignore[arg-type]


async def test_json_is_model_dump_json():
    report = await sample_report()
    assert render_change_report(report, ["json"]).json == report.model_dump_json().encode()


async def test_round_trip_collect_json_render_equals_direct():
    report = await sample_report()
    direct = render_change_report(report, ["json", "markdown", "html"], OPTIONS)
    assert direct.json is not None
    stored = ChangeReport.model_validate_json(direct.json)
    again = render_change_report(stored, ["markdown", "html"], OPTIONS)
    assert (again.markdown, again.html) == (direct.markdown, direct.html)


@pytest.mark.parametrize("source", ["live", "cache"])
def test_numbering_label_without_snapshot_time_drops_the_time_clause(source):
    from arodonata.reports.changes.build import build_session
    from arodonata.reports.changes.model import NumberingInfo
    from arodonata.reports.changes.view import numbering_label
    from tests.unit.reports.entries import entry, session_meta

    s = build_session(entry(session_meta("s1")))
    info = NumberingInfo(source=source, snapshot_session_uid="other", status="live" if source == "live" else "ok")
    label = numbering_label(s.model_copy(update={"numbering": info}))
    assert " at " not in label and "UTC" not in label and label
