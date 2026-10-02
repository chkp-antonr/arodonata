"""HTML change report, layout A: one self-contained file, Jinja2 with autoescape on (spec 6.3). Needs the 'report'
extra; imported lazily by render.py only."""

from __future__ import annotations

import json
from typing import Any

from ._messages import MISSING_REPORT_EXTRA

try:
    import jinja2
    from markupsafe import Markup
except ImportError as exc:  # jinja2 or markupsafe missing (or blocked)
    raise ImportError(MISSING_REPORT_EXTRA) from exc

from .markup import inline_html
from .model import ChangeReport
from .render import RenderOptions
from .view import report_view

_ENV: jinja2.Environment | None = None


def _json(value: Any, *, compact: bool = False) -> str:
    if compact:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def _env() -> jinja2.Environment:
    global _ENV
    if _ENV is None:
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("arodonata.reports.changes", "templates"),
            autoescape=True,
            undefined=jinja2.StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        env.filters["inline"] = lambda text: Markup(inline_html(str(text)))
        env.filters["pretty_json"] = _json
        env.filters["compact_json"] = lambda value: _json(value, compact=True)
        _ENV = env
    return _ENV


def render_html(report: ChangeReport, options: RenderOptions) -> bytes:
    template = _env().get_template("change_report.html.j2")
    return template.render(view=report_view(report), options=options).encode("utf-8")
