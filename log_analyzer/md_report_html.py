# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Render the AI deep-analysis markdown deliverables as standalone HTML.

The signature engine already emits .html, but the LLM-written reports
(copilot_deep_analysis.md, copilot_ado_match.md, ado_correlation.md,
copilot_handoff.md) stay markdown, so they cannot be opened next to the other
reports or attached to an issue without a viewer.

md_render.md_to_html() is the existing converter, but it only knows headings,
lists and inline formatting. The real reports lean on markdown **tables** for
the evidence grid and on blockquotes for cited log lines, and those degrade
into unreadable paragraphs. This module handles both, plus fenced code, and
wraps the result in a self-contained page that matches the look of the
signature reports.

Usage:
  python md_report_html.py <file.md> [<file2.md> ...]
  python md_report_html.py --scan-folder <log folder>   # all known deliverables
  python md_report_html.py --scan-folder <dir> --all    # every .md in the folder
"""
import argparse
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from md_render import REPORT_MD_CSS, inline_md  # noqa: E402

# The files the deep-analysis workflow writes as markdown. Anything else needs --all
# or an explicit path, so a stray note in the log folder is not turned into a
# report that looks official.
KNOWN_REPORTS = [
    "copilot_deep_analysis.md",
    "copilot_ado_match.md",
    "ado_correlation.md",
    "copilot_handoff.md",
    "sku_analysis.md",
]

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^\s*[-*\u2022]\s+(.*)$")
_NUMBER = re.compile(r"^\s*(\d+)[.)]\s+(.*)$")
_QUOTE = re.compile(r"^>\s?(.*)$")
_FENCE = re.compile(r"^\s*```+\s*(\w*)\s*$")
_HR = re.compile(r"^\s*([-*_])\1{2,}\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")

PAGE_CSS = """
body { font-family: "Segoe UI", Arial, sans-serif; background: #f4f6f8;
       color: #222; margin: 0; padding: 24px; }
.wrap { max-width: 1100px; margin: 0 auto; background: #fff; border: 1px solid #dde3ea;
        border-radius: 8px; padding: 24px 32px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
h1 { font-size: 22px; color: #12395e; margin: 0 0 4px; }
h2 { font-size: 17px; color: #1f3a5f; margin: 22px 0 8px;
     border-bottom: 1px solid #e3e8ee; padding-bottom: 4px; }
.meta { color: #6b7785; font-size: 12px; margin: 0 0 18px; }
table { border-collapse: collapse; margin: 10px 0 16px; width: 100%; font-size: 13px; }
th, td { border: 1px solid #d8dee6; padding: 6px 9px; text-align: left;
         vertical-align: top; }
th { background: #eef2f7; color: #12395e; font-weight: 600; }
tr:nth-child(even) td { background: #fafbfc; }
blockquote { margin: 10px 0; padding: 8px 14px; background: #f7f9fb;
             border-left: 3px solid #7aa7d0; color: #33475b; }
blockquote p { margin: 0 0 6px; }
pre { background: #1f2733; color: #e6edf3; padding: 12px 14px; border-radius: 5px;
      overflow-x: auto; font-family: Consolas, monospace; font-size: 12px;
      line-height: 1.45; }
hr { border: 0; border-top: 1px solid #e3e8ee; margin: 18px 0; }
"""


def _cells(line):
    row = line.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|"):
        row = row[:-1]
    return [c.strip() for c in row.split("|")]


def _is_table_start(lines, i):
    return ("|" in lines[i]
            and i + 1 < len(lines)
            and "|" in lines[i + 1]
            and _TABLE_SEP.match(lines[i + 1]))


def md_to_html(text):
    """Markdown -> HTML fragment, including tables, blockquotes and code fences."""
    lines = text.replace("\r\n", "\n").split("\n")
    out = []
    para = []
    items = []
    list_tag = None
    quote = []
    i = 0

    def flush_para():
        if para:
            out.append("<p>" + "<br>".join(inline_md(p) for p in para) + "</p>")
            del para[:]

    def flush_list():
        if items:
            out.append("<%s>%s</%s>" % (list_tag,
                                        "".join("<li>%s</li>" % x for x in items),
                                        list_tag))
            del items[:]

    def flush_quote():
        if quote:
            out.append("<blockquote>%s</blockquote>"
                       % "".join("<p>%s</p>" % inline_md(q) for q in quote if q.strip()))
            del quote[:]

    def flush_all():
        flush_list()
        flush_para()
        flush_quote()

    while i < len(lines):
        raw = lines[i]
        line = raw.strip()

        m = _FENCE.match(raw)
        if m:
            flush_all()
            body = []
            i += 1
            while i < len(lines) and not _FENCE.match(lines[i]):
                body.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>%s</code></pre>"
                       % html.escape("\n".join(body)))
            continue

        if _is_table_start(lines, i):
            flush_all()
            head = _cells(lines[i])
            i += 2
            rows = []
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_cells(lines[i]))
                i += 1
            thead = "".join("<th>%s</th>" % inline_md(c) for c in head)
            tbody = "".join(
                "<tr>%s</tr>" % "".join("<td>%s</td>" % inline_md(c) for c in r)
                for r in rows)
            out.append("<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>"
                       % (thead, tbody))
            continue

        if not line:
            flush_all()
            i += 1
            continue

        if _HR.match(line):
            flush_all()
            out.append("<hr>")
            i += 1
            continue

        m = _QUOTE.match(line)
        if m:
            flush_list()
            flush_para()
            quote.append(m.group(1))
            i += 1
            continue
        flush_quote()

        m = _HEADING.match(line)
        if m:
            flush_all()
            level = min(len(m.group(1)), 6)
            out.append("<h%d>%s</h%d>" % (level, inline_md(m.group(2)), level))
            i += 1
            continue

        m = _BULLET.match(line)
        if m:
            flush_para()
            if list_tag not in (None, "ul"):
                flush_list()
            list_tag = "ul"
            items.append(inline_md(m.group(1)))
            i += 1
            continue

        m = _NUMBER.match(line)
        if m:
            flush_para()
            if list_tag not in (None, "ol"):
                flush_list()
            list_tag = "ol"
            items.append(inline_md(m.group(2)))
            i += 1
            continue

        flush_list()
        para.append(line)
        i += 1

    flush_all()
    return "".join(out)


AI_NOTICE = "AI-generated, may be inaccurate, verify against the log evidence."


def render_page(md_text, title, source_path="", ai_generated=False):
    body = md_to_html(md_text)
    # The first H1 becomes the page title; keep the document itself unchanged.
    meta = "generated by md_report_html.py"
    if source_path:
        meta += " from " + html.escape(os.path.basename(source_path))
    notice = ("<p class='ai-notice' role='note' style='padding:8px 12px;border-radius:6px;"
              "border:1px solid #e0b252;background:#fff8e6;color:#5c4400;font-weight:600'>"
              "&#9888; %s</p>" % html.escape(AI_NOTICE)) if ai_generated else ""
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>%s</title><style>%s%s</style></head>"
            "<body><div class='wrap md'><h1>%s</h1>"
            "<p class='meta'>%s</p>%s%s</div></body></html>"
            % (html.escape(title), PAGE_CSS, REPORT_MD_CSS,
               html.escape(title), meta, notice, body))


def convert(md_path, out_path=None, ai_generated=None):
    """Render one markdown file; the known deliverables are AI output by definition."""
    with open(md_path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    title = os.path.splitext(os.path.basename(md_path))[0]
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    if ai_generated is None:
        ai_generated = os.path.basename(md_path) in KNOWN_REPORTS
    out_path = out_path or os.path.splitext(md_path)[0] + ".html"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render_page(text, title, md_path, ai_generated=ai_generated))
    return out_path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="markdown file(s) to convert")
    ap.add_argument("--scan-folder", help="convert the deep-analysis deliverables in this folder")
    ap.add_argument("--all", action="store_true",
                    help="with --scan-folder, convert every .md, not just known reports")
    args = ap.parse_args(argv)

    targets = list(args.files)
    if args.scan_folder:
        folder = args.scan_folder
        if not os.path.isdir(folder):
            print("ERROR: no such folder: %s" % folder, file=sys.stderr)
            return 2
        if args.all:
            targets += [os.path.join(folder, f) for f in sorted(os.listdir(folder))
                        if f.lower().endswith(".md")]
        else:
            targets += [os.path.join(folder, f) for f in KNOWN_REPORTS
                        if os.path.isfile(os.path.join(folder, f))]

    if not targets:
        print("nothing to convert (no files given, and no known .md report found)",
              file=sys.stderr)
        return 1

    rc = 0
    for md in targets:
        if not os.path.isfile(md):
            print("SKIP (missing): %s" % md, file=sys.stderr)
            rc = 1
            continue
        try:
            out = convert(md)
        except Exception as exc:
            print("FAIL %s: %s" % (md, exc), file=sys.stderr)
            rc = 1
            continue
        print("%s -> %s (%d bytes)" % (os.path.basename(md), out,
                                       os.path.getsize(out)))
    return rc


if __name__ == "__main__":
    sys.exit(main())
