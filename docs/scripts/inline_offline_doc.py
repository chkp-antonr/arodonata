"""Bundle the print-site merged page into a single portable offline HTML file.

Run after ``uv run mkdocs build -f mkdocs-offline.yml``:

    uv run python docs/scripts/inline_offline_doc.py

site-offline/print_page/index.html has everything in one page, but it still
depends on sibling asset folders (CSS/JS/images) in site-offline/ — copying
just that file elsewhere breaks the styling. This inlines the local
stylesheets and print-site.js and base64-embeds the images directly into the
page, so the output (site-offline/arodonata-docs-offline.html) is a single file
with no dependency on the rest of the built site and can be copied anywhere.

Dropped, deliberately:
- The Google Fonts CDN link/preconnect: needs network to do anything, and
  the theme's font stack already falls back to a system font without it.
- assets/javascripts/bundle*.min.js (search, instant-nav): it lazily loads
  separate worker/lunr chunk files by relative path, which won't resolve
  once this file is moved, and none of that is needed to read the page.
"""

import base64
import mimetypes
import re
from pathlib import Path

PRINT_PAGE = Path(__file__).parent.parent.parent / "site-offline" / "print_page" / "index.html"
OUTPUT = PRINT_PAGE.parent.parent / "arodonata-docs-offline.html"

GOOGLE_FONTS_PRECONNECT = re.compile(r'<link rel="preconnect" href="https://fonts\.gstatic\.com"[^>]*>\s*')
GOOGLE_FONTS_STYLESHEET = re.compile(r'<link rel="stylesheet" href="https://fonts\.googleapis\.com[^"]*">\s*')
STYLESHEET_LINK = re.compile(r'<link rel="stylesheet" href="([^"]+)">')
ICON_LINK = re.compile(r'(<link rel="icon" href=")([^"]+)(">)')
IMG_TAG = re.compile(r'(<img [^>]*src=")([^"]+)(")')
SCRIPT_SRC_TAG = re.compile(r'<script src="([^"]+)"[^>]*></script>')


def _read_local(href: str) -> str:
    return (PRINT_PAGE.parent / href).resolve().read_text()


def _data_uri(href: str) -> str:
    path = (PRINT_PAGE.parent / href).resolve()
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def main() -> None:
    html = PRINT_PAGE.read_text()

    html = GOOGLE_FONTS_PRECONNECT.sub("", html)
    html = GOOGLE_FONTS_STYLESHEET.sub("", html)

    html = STYLESHEET_LINK.sub(
        lambda m: m.group(0) if m.group(1).startswith("http") else f"<style>{_read_local(m.group(1))}</style>",
        html,
    )
    html = ICON_LINK.sub(lambda m: f"{m.group(1)}{_data_uri(m.group(2))}{m.group(3)}", html)
    html = IMG_TAG.sub(
        lambda m: (
            m.group(0)
            if m.group(2).startswith(("http", "data:"))
            else f"{m.group(1)}{_data_uri(m.group(2))}{m.group(3)}"
        ),
        html,
    )
    html = SCRIPT_SRC_TAG.sub(
        lambda m: f"<script>{_read_local(m.group(1))}</script>" if m.group(1).endswith("print-site.js") else "",
        html,
    )

    OUTPUT.write_text(html)
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
