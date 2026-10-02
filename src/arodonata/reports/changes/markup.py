"""Limited markdown for titles and header fields, and markdown escaping for CP-sourced strings (spec 6.2).

Allowed: ``**bold**``, ``*italic*``, `` `code` ``, ``[text](url)`` with an http, https or mailto URL without control
characters; no nesting except plain text inside bold/italic; unclosed markers are literal. Standard library only:
MarkupSafe arrives only with the ``report`` extra, so the markdown and JSON paths must not import it.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from typing import Literal
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = frozenset({"http", "https", "mailto"})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MD_SPECIALS = frozenset("\\`*_~[]()<>|#+!&")
_TOKEN = re.compile(
    r"`(?P<code>[^`]+)`"
    r"|\*\*(?P<bold>[^*]+)\*\*"
    r"|(?<!\*)\*(?P<italic>[^*]+)\*(?!\*)"
    r"|\[(?P<text>[^\]]+)\]\((?P<url>[^)\s]+)\)"
)
Kind = Literal["text", "code", "bold", "italic", "link"]


def _safe_url(url: str) -> bool:
    if _CONTROL.search(url):
        return False
    try:
        return urlsplit(url).scheme.lower() in _ALLOWED_SCHEMES
    except ValueError:
        return False


def _tokens(text: str) -> Iterator[tuple[Kind, str, str]]:
    """(kind, text, url): one left-to-right pass; a disallowed link is the whole token as literal text."""
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    pos = 0
    for m in _TOKEN.finditer(text):
        if m.start() > pos:
            yield "text", text[pos : m.start()], ""
        if m.group("code") is not None:
            yield "code", m.group("code"), ""
        elif m.group("bold") is not None:
            yield "bold", m.group("bold"), ""
        elif m.group("italic") is not None:
            yield "italic", m.group("italic"), ""
        elif _safe_url(m.group("url")):
            yield "link", m.group("text"), m.group("url")
        else:
            yield "text", m.group(0), ""
        pos = m.end()
    if pos < len(text):
        yield "text", text[pos:], ""


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def inline_html(text: str) -> str:
    """Escaped HTML built from escaped parts only; render_html.py wraps it in markupsafe.Markup."""
    out: list[str] = []
    for kind, value, url in _tokens(str(text)):
        if kind == "code":
            out.append(f"<code>{_esc(value)}</code>")
        elif kind == "bold":
            out.append(f"<strong>{_esc(value)}</strong>")
        elif kind == "italic":
            out.append(f"<em>{_esc(value)}</em>")
        elif kind == "link":
            out.append(f'<a href="{_esc(url)}">{_esc(value)}</a>')
        else:
            out.append(_esc(value))
    return "".join(out)


def escape_md(text: str) -> str:
    """Backslash-escape markdown metacharacters (backslash included) and fold newlines into spaces."""
    flat = str(text).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return "".join(f"\\{ch}" if ch in _MD_SPECIALS else ch for ch in flat)


def inline_markdown(text: str) -> str:
    """Markdown: the allowed constructs kept, everything else escaped."""
    out: list[str] = []
    for kind, value, url in _tokens(str(text)):
        if kind == "code":
            out.append(f"`{value}`")
        elif kind == "bold":
            out.append(f"**{escape_md(value)}**")
        elif kind == "italic":
            out.append(f"*{escape_md(value)}*")
        elif kind == "link":
            out.append(f"[{escape_md(value)}]({url.replace('<', '%3C').replace('>', '%3E')})")
        else:
            out.append(escape_md(value))
    return "".join(out)
