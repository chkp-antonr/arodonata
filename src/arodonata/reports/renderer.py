"""Multi-format offline evidence rendering (`arodonata.reports.renderer`).

Implements `render_change_report` and `build_change_report`:
- Offline rendering of `ChangeReport` into `"html"` (`bytes`), `"markdown"` (`str`), and
  `"json"` (`str`), raising `UnsupportedFormat` for `"pdf"` or unknown formats.
- Escapes all Check Point strings in every format while supporting safe inline markdown
  (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title`
  and `header_fields`.
- Produces self-contained UTF-8 HTML (`bytes`) with inline CSS, zero `<script>` tags, zero
  external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs,
  moved rule badges, disabled `✗` markers), and per-rule field diff detail tables.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.errors import UnsupportedFormat
from arodonata.core.models.common import utc_now
from arodonata.core.ports import ApiPort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports._renderer_formatting import (
    SUPPORTED_REPORT_FORMATS,
    render_safe_inline_markdown_html,
    render_safe_inline_markdown_md,
)
from arodonata.reports._renderer_html import _INLINE_CSS, _render_html_document
from arodonata.reports._renderer_markdown import _render_markdown_document
from arodonata.reports.collector import MAX_UID_LOOKUPS, _ReportCachePort, collect_change_report
from arodonata.reports.models import ChangeReport, RenderedReportBundle, RenderOptions, ReportScope


def _normalize_report_formats(formats: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for fmt in formats:
        clean = str(fmt).strip().lower()
        if clean == "md":
            clean = "markdown"
        if clean not in SUPPORTED_REPORT_FORMATS:
            raise UnsupportedFormat(f"Unsupported report format {fmt!r}. Supported formats are: html, json, markdown.")
        if clean not in normalized:
            normalized.append(clean)
    return normalized


@traced
def render_change_report(
    report: ChangeReport,
    *,
    formats: Sequence[str] = ("html", "markdown", "json"),
    options: RenderOptions | None = None,
) -> RenderedReportBundle:
    """Render `report` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`.

    Raises `UnsupportedFormat` if `'pdf'` or any unrecognized format is requested.
    """
    normalized_formats = _normalize_report_formats(formats)
    span_attrs(formats=normalized_formats, session_count=len(report.sessions))
    eff_options = options or RenderOptions(
        title=report.title,
        header_fields=dict(report.header_fields),
    )

    html_bytes = _render_html_document(report, eff_options) if "html" in normalized_formats else None
    md_text = _render_markdown_document(report, eff_options) if "markdown" in normalized_formats else None
    json_text = report.model_dump_json(indent=2) if "json" in normalized_formats else None

    return RenderedReportBundle(
        report=report,
        html=html_bytes,
        markdown=md_text,
        json_text=json_text,
    )


@traced
async def build_change_report(
    api: ApiPort,
    cache: _ReportCachePort,
    scopes: Sequence[ReportScope | dict[str, Any]],
    *,
    formats: Sequence[str] = ("html", "markdown", "json"),
    options: RenderOptions | None = None,
    max_uid_lookups: int = MAX_UID_LOOKUPS,
    now_fn: Callable[[], datetime] = utc_now,
    refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None,
) -> RenderedReportBundle:
    """Collect a `ChangeReport` and render it into `formats` in a single call."""
    # Pre-validate requested formats before making network calls
    _normalize_report_formats(formats)

    report = await collect_change_report(
        api,
        cache,
        scopes,
        options=options,
        max_uid_lookups=max_uid_lookups,
        now_fn=now_fn,
        refresh_rulebase_fn=refresh_rulebase_fn,
    )
    return render_change_report(report, formats=formats, options=options)


__all__ = [
    "SUPPORTED_REPORT_FORMATS",
    "_INLINE_CSS",
    "_render_html_document",
    "_render_markdown_document",
    "build_change_report",
    "render_change_report",
    "render_safe_inline_markdown_html",
    "render_safe_inline_markdown_md",
]
