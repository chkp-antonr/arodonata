from __future__ import annotations

from arodonata.reports.changes.markup import escape_md, inline_html, inline_markdown


def test_bold_italic_code_and_link():
    assert inline_html("**b** *i* `c<d>` [t](https://x.example/?a=1&b=2) [m](mailto:a@b.example)") == (
        '<strong>b</strong> <em>i</em> <code>c&lt;d&gt;</code> <a href="https://x.example/?a=1&amp;b=2">t</a> '
        '<a href="mailto:a@b.example">m</a>'
    )


def test_javascript_and_data_links_not_links():
    for url in (
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,x",
        "java\tscript:x",
        "//evil.example",
        "vbscript:x",
    ):
        out = inline_html(f"[x]({url})")
        assert "<a " not in out and "href" not in out


def test_html_specials_escaped():
    assert inline_html("<script>\"&'") == "&lt;script&gt;&quot;&amp;&#x27;"
    assert inline_html("**<b>**") == "<strong>&lt;b&gt;</strong>"


def test_unclosed_markers_literal():
    assert inline_html("**bold") == "**bold"
    assert inline_html("`code") == "`code"
    assert inline_html("[t](https://x.example") == "[t](https://x.example"
    assert inline_html("*a **b") == "*a **b"


def test_markdown_variant_neutralises_disallowed_links():
    assert inline_markdown("[x](javascript:alert(1)) **b** [ok](https://x.example)") == (
        "\\[x\\]\\(javascript:alert\\(1\\)\\) **b** [ok](https://x.example)"
    )
    assert inline_markdown("<img src=x> #h") == "\\<img src=x\\> \\#h"


def test_escape_md_metacharacters_and_trailing_backslash():
    assert escape_md("a|b\\") == "a\\|b\\\\"
    assert escape_md("[x](y) <i> **~~+#!_`") == "\\[x\\]\\(y\\) \\<i\\> \\*\\*\\~\\~\\+\\#\\!\\_\\`"
    assert escape_md("line1\nline2\r\nline3") == "line1 line2 line3"


def test_newlines_folded_so_code_span_cannot_open_html_block():
    text = "T `x\n<script>alert(1)</script>`"
    md_out = inline_markdown(text)
    assert "\n" not in md_out and "\n" not in inline_html(text) and "\r" not in inline_html("a\r\nb\rc")
    assert not any(line.startswith("<") for line in md_out.splitlines())


def test_ampersand_escaped_in_markdown():
    assert escape_md("&lt;b&gt;") == "\\&lt;b\\&gt;"


def test_quote_in_link_url_cannot_break_attribute():
    out = inline_html('[x](https://a"onmouseover="alert(1))')
    assert 'href="https://a&quot;onmouseover=&quot;alert(1"' in out
    assert '"onmouseover=' not in out.replace("&quot;onmouseover=", "")
