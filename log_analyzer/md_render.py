# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Render the markdown an LLM actually emits into HTML for the log_analyzer reports.

The models already return clean markdown. The reports were throwing it away:
HTML collapses newlines, so a findings list arrived as one run-on paragraph with
literal ``**bold**``, ``1.`` and ``- `` characters in it.
"""

import html
import re

_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^[-*\u2022]\s+(.*)$")
_NUMBER = re.compile(r"^(\d+)[.)]\s+(.*)$")


def _bold(text):
    parts, last = [], 0
    for m in _BOLD.finditer(text):
        parts.append(html.escape(text[last:m.start()]))
        parts.append("<strong>" + html.escape(m.group(1)) + "</strong>")
        last = m.end()
    parts.append(html.escape(text[last:]))
    return "".join(parts)


def inline_md(text):
    """Escape *text*, then render `code` spans and **bold**."""
    parts, last = [], 0
    for m in _CODE.finditer(text):
        parts.append(_bold(text[last:m.start()]))
        parts.append("<code>" + html.escape(m.group(1)) + "</code>")
        last = m.end()
    parts.append(_bold(text[last:]))
    return "".join(parts)


def looks_like_html(text):
    stripped = (text or "").lstrip()
    return stripped.startswith("<") and re.search(r"</(p|ul|ol|li|div|h[1-6])>", text or "") is not None


_INLINE_BULLET = re.compile(r"\s+-\s+(?=\S)")


def _split_inline_bullets(line):
    """Turn ' - a - b' runs into real bullet lines.

    Requires whitespace on both sides, so 'c1->c2' and 'A-B' are untouched.
    """
    hits = _INLINE_BULLET.findall(line)
    if not hits:
        return line
    head = line[:_INLINE_BULLET.search(line).start()].rstrip()
    # One separator is only a list if it follows a label; two or more always is.
    if len(hits) < 2 and not head.endswith((":", ":**")):
        return line
    rest = _INLINE_BULLET.sub("\n- ", line[len(head):].lstrip())
    if rest.startswith("- "):
        return (head + "\n" + rest) if head else rest
    return head + "\n- " + rest


def md_to_html(text):
    """Convert an LLM reply to safe HTML: headings, bullets, numbered lists, paragraphs."""
    if not text or not text.strip():
        return ""
    if looks_like_html(text):
        return text

    # A single line often packs the whole list, e.g. "... **Specific Failures:**
    # 1. CUDA failure ... 2. Test failure ...". Break before those markers so the
    # list renderer below can see them.
    text = re.sub(r"(?<!^)(?<![\n\d])\s+(?=\d+\.\s+\*\*)", "\n", text)
    text = re.sub(r"(?<!^)\s+(?=\*\*[A-Z][^*]{2,40}:\*\*)", "\n\n", text)
    text = "\n".join(_split_inline_bullets(l) for l in text.splitlines())

    out, para, list_items, list_tag = [], [], [], None

    def flush_para():
        if para:
            out.append("<p>" + "<br>".join(inline_md(p) for p in para) + "</p>")
            para.clear()

    def flush_list():
        nonlocal list_tag
        if list_items:
            out.append(f"<{list_tag}>" + "".join(f"<li>{i}</li>" for i in list_items)
                       + f"</{list_tag}>")
            list_items.clear()
        list_tag = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush_list()
            flush_para()
            continue

        m = _HEADING.match(line)
        if m:
            flush_list()
            flush_para()
            level = min(len(m.group(1)) + 2, 6)
            out.append(f"<h{level}>{inline_md(m.group(2))}</h{level}>")
            continue

        m = _BULLET.match(line)
        if m:
            flush_para()
            if list_tag not in (None, "ul"):
                flush_list()
            list_tag = "ul"
            list_items.append(inline_md(m.group(1)))
            continue

        m = _NUMBER.match(line)
        if m:
            flush_para()
            if list_tag not in (None, "ol"):
                flush_list()
            list_tag = "ol"
            list_items.append(inline_md(m.group(2)))
            continue

        flush_list()
        para.append(line)

    flush_list()
    flush_para()
    return "".join(out)


# Drop-in <style> block; both reports already use a light card layout.
REPORT_MD_CSS = """
.md p { margin: 0 0 8px; line-height: 1.55; }
.md ul, .md ol { margin: 4px 0 10px; padding-left: 22px; }
.md li { margin: 3px 0; line-height: 1.5; }
.md h3, .md h4, .md h5 { margin: 12px 0 6px; font-size: 14px; color: #1f3a5f; }
.md code { background: #eef1f5; border: 1px solid #d8dee6; border-radius: 3px;
           padding: 1px 4px; font-family: Consolas, monospace; font-size: 12px; }
.md strong { color: #12395e; }
"""
