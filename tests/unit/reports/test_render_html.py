from __future__ import annotations

import importlib.resources
import os
import re
import sys
from pathlib import Path

import pytest

from arodonata.reports.changes import render_change_report
from arodonata.reports.changes.render import RenderOptions
from tests.unit.reports.entries import entry, host, session_meta
from tests.unit.reports.fakes import FakeReportClient
from tests.unit.reports.sample import OPTIONS, sample_report

GOLDEN = Path(__file__).parent / "golden" / "change_report.html"


def html(report, options=OPTIONS) -> str:
    out = render_change_report(report, ["html"], options).html
    assert out is not None
    return out.decode()


async def test_html_golden():
    text = html(await sample_report())
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(text)
    assert text == GOLDEN.read_text()


async def test_html_ids_unique():
    text = html(await sample_report())
    ids = re.findall(r'\sid="([^"]+)"', text)
    assert len(ids) == len(set(ids))
    targets = re.findall(r'href="#([^"]+)"', text)
    assert targets and set(targets) <= set(ids)


async def test_html_self_contained_no_script_no_external_refs():
    text = html(await sample_report())
    assert not re.search(r"<(script|img|link|iframe|object|embed|style\s+src)\b", text, re.I)
    assert "url(" not in text and "@import" not in text and "@font-face" not in text
    hrefs = re.findall(r'href="([^"]*)"', text)
    assert all(h.startswith("#") or h.startswith("https://servicenow.example.com/") for h in hrefs)


async def test_names_with_amp_lt_gt_quote_escaped():
    text = html(await sample_report())
    assert "<b>&" not in text and "&lt;b&gt;&amp;&#34;&#39;" in text
    assert "&lt;img src=x&gt;" in text


async def test_title_javascript_link_not_a_link():
    text = html(await sample_report(), RenderOptions(title="[x](javascript:alert(1)) **Bold**"))
    assert 'href="javascript' not in text.lower() and "<strong>Bold</strong>" in text


async def test_disabled_row_marker_and_grey():
    text = html(await sample_report())
    assert '<tr class="row-modified row-disabled">' in text
    assert '<td class="col-enabled cell-changed"><span class="disabled-mark">✗</span></td>' in text
    assert '<tr class="row-added row-disabled">' in text


async def test_status_row_classes_and_tags():
    text = html(await sample_report())
    assert '<span class="tag tag-new">NEW</span>' in text and '<span class="tag tag-deleted">DELETED</span>' in text
    assert '<tr class="row-deleted">' in text and "num-moved" in text and "(was 2.2.1)" in text
    assert "(position 5 in its section)" in text
    assert '<td class="cell-changed">' in text


async def test_empty_sections_hidden():
    fake = FakeReportClient()
    fake.changes[("m1", "Domain4")] = [entry(session_meta("pub-1"), added=[host("h9", "only-host")])]
    text = html(await sample_report(fake=fake))
    assert "Objects" in text and "only-host" in text
    for absent in (
        "Access Control",
        "Section changes",
        "Other changes",
        "Hidden internal changes",
        "No visible changes",
    ):
        assert absent not in text


async def test_raw_appendix_in_details():
    text = html(await sample_report(include_raw=True))
    assert "Raw show-changes responses" in text and "<details><summary>m1 / Domain4 / " in text
    assert "(err_rpc)</summary>" in text
    assert "<details>" not in html(await sample_report(include_raw=False))


async def test_times_labelled_utc():
    text = html(await sample_report())
    assert "Generated 2026-10-02 09:00:00 UTC" in text and "Published 2026-10-01 05:53:00 UTC" in text
    assert "Not published" in text


def test_template_is_package_resource():
    resource = importlib.resources.files("arodonata.reports.changes") / "templates" / "change_report.html.j2"
    assert resource.is_file()


async def test_missing_jinja2_raises_actionable_import_error(monkeypatch):
    report = await sample_report()
    monkeypatch.setitem(sys.modules, "jinja2", None)
    monkeypatch.delitem(sys.modules, "arodonata.reports.changes.render_html", raising=False)
    with pytest.raises(ImportError, match=r"uv pip install 'arodonata\[report\]'"):
        render_change_report(report, ["html"])
