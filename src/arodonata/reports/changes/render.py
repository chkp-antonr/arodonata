"""Render a ChangeReport into the requested formats only (spec 6.1). No Check Point access; a stored report
(``ChangeReport.model_validate_json``) re-renders identically. HTML needs the ``report`` extra (lazy import)."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Literal, get_args

from arlogi.otel.decorator import traced
from pydantic import BaseModel, ConfigDict, Field

from ...telemetry import span_attrs
from .model import ChangeReport

ReportFormat = Literal["html", "json", "markdown", "pdf"]
_KNOWN_FORMATS: tuple[str, ...] = get_args(ReportFormat)


class RenderOptions(BaseModel):
    """``title`` and ``header_fields`` accept limited markdown (bold, italic, code, http/https/mailto links)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str = "Policy change report"
    header_fields: dict[str, str] = Field(default_factory=dict)  # ordered pairs, e.g. {"RITM": "RITM0012345"}
    generated_by: str | None = None
    markdown_max_rules: int | None = None  # markdown truncation (MCP), counts rule rows
    markdown_max_objects: int | None = None  # markdown truncation (MCP), counts object/section/other rows


@dataclass(frozen=True)
class ChangeReportResult:
    report: ChangeReport
    html: bytes | None = None
    json: bytes | None = None
    markdown: str | None = None
    pdf: bytes | None = None


class UnsupportedFormat(ValueError):
    """A known but not (yet) supported format, e.g. 'pdf' (reserved)."""


def render_json(report: ChangeReport, options: RenderOptions) -> bytes:
    return report.model_dump_json().encode()


def _render_markdown(report: ChangeReport, options: RenderOptions) -> str:
    from .render_markdown import render_markdown

    return render_markdown(report, options)


def _render_html(report: ChangeReport, options: RenderOptions) -> bytes:
    # import_module (not "from . import"): a missing Jinja2 must fail here with the actionable message every time
    module = importlib.import_module(f"{__package__}.render_html")
    html: bytes = module.render_html(report, options)
    return html


RENDERERS: dict[str, Callable[[ChangeReport, RenderOptions], bytes | str]] = {
    "json": render_json,
    "markdown": _render_markdown,
    "html": _render_html,
}


def _check(formats: Collection[ReportFormat]) -> list[str]:
    if isinstance(formats, str):
        raise TypeError("formats must be a collection of format names, not a str (wrap it: ['html'])")
    requested: list[str] = list(dict.fromkeys(formats))
    for fmt in requested:
        if fmt not in _KNOWN_FORMATS:
            raise ValueError(f"unknown report format {fmt!r}; known: {', '.join(_KNOWN_FORMATS)}")
        if fmt not in RENDERERS:
            raise UnsupportedFormat(f"report format {fmt!r} is reserved and not supported yet")
    return requested


@traced
def render_change_report(
    report: ChangeReport, formats: Collection[ReportFormat] = (), options: RenderOptions | None = None
) -> ChangeReportResult:
    """Build only the requested formats; ``report`` is always returned."""
    requested = _check(formats)
    opts = options or RenderOptions()
    out = {fmt: RENDERERS[fmt](report, opts) for fmt in requested}
    span_attrs(
        **{"report.formats": ",".join(requested)},
        **{f"report.{fmt}_bytes": len(v.encode() if isinstance(v, str) else v) for fmt, v in out.items()},
    )
    html, json_, markdown = out.get("html"), out.get("json"), out.get("markdown")
    return ChangeReportResult(
        report=report,
        html=html if isinstance(html, bytes) else None,
        json=json_ if isinstance(json_, bytes) else None,
        markdown=markdown if isinstance(markdown, str) else None,
    )
