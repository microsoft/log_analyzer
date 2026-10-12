"""Neutral header/footer styling shared by every HTML report log_analyzer writes.

Stdlib-only and import-safe: report generation must never fail because the
cosmetic wrapper could not load.

Typical use::

    import brand
    page = brand.brandify(page, "Log Analysis")
"""

from __future__ import annotations

import base64
import datetime
import html
import re
from pathlib import Path

__all__ = [
    "PRODUCT", "logo_data_uri", "favicon_tag", "page_title", "version",
    "brand_css", "brand_chip", "brand_banner", "brand_footer", "head_tags",
    "brandify", "write_branded",
]

PRODUCT = "Log Analyzer"
ACCENT = "#2b5797"
ACCENT_LT = "#3a6fb8"

_ROOT = Path(__file__).resolve().parent.parent
_SVG_LOGO = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40'>"
    "<rect x='1' y='1' width='38' height='38' rx='10' fill='%s'/>"
    "<text x='20' y='26' font-family='Segoe UI,sans-serif' font-size='16' "
    "font-weight='700' fill='#fff' text-anchor='middle'>LA</text></svg>"
) % ACCENT

_cache: dict = {}


def logo_data_uri() -> str:
    if "logo" not in _cache:
        _cache["logo"] = ("data:image/svg+xml;base64,"
                          + base64.b64encode(_SVG_LOGO.encode("utf-8")).decode("ascii"))
    return _cache["logo"]


def version() -> str:
    """Tool version from ``log_analyzer/version.txt`` ("" when unavailable)."""
    if "ver" not in _cache:
        v = ""
        try:
            f = _ROOT / "log_analyzer" / "version.txt"
            if f.is_file():
                v = f.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
        except Exception:
            v = ""
        _cache["ver"] = v
    return _cache["ver"]


def favicon_tag() -> str:
    return '<link rel="icon" href="%s">' % logo_data_uri()


def page_title(tool: str = "") -> str:
    tool = (tool or "").strip()
    return "%s · %s" % (PRODUCT, tool) if tool else PRODUCT


def brand_css() -> str:
    return """
.labrand{display:inline-flex;align-items:center;gap:7px;color:#fff;
  padding:3px 11px 3px 3px;border-radius:999px;background:%(a)s;
  font:600 12px/1 "Segoe UI",system-ui,sans-serif;text-decoration:none}
.labrand img{width:19px;height:19px;border-radius:5px;display:block}
.labrand .latool{font-weight:400;padding-left:8px;border-left:1px solid rgba(255,255,255,.5)}
.labanner{display:flex;align-items:center;gap:12px;flex-wrap:wrap;
  padding:11px 16px;margin:0 0 14px;border-radius:10px;color:#fff;
  background:linear-gradient(95deg,%(a)s 0%%,%(al)s 100%%);
  font:400 13px/1.35 "Segoe UI",system-ui,sans-serif}
.labanner img{width:34px;height:34px;border-radius:8px;display:block}
.labanner .lab-txt{display:flex;flex-direction:column;gap:2px;min-width:0}
.labanner .lab-wm{font-size:16px;font-weight:700}
.labanner .lab-tool{font-size:12px;opacity:.92}
.labanner .lab-meta{margin-left:auto;text-align:right;font-size:11px;opacity:.9;white-space:nowrap}
@media print{.labanner{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
.lafoot{margin:26px 0 8px;padding:9px 4px 0;border-top:1px solid rgba(43,87,151,.4);
  display:flex;align-items:center;gap:8px;flex-wrap:wrap;
  font:400 11px/1.5 "Segoe UI",system-ui,sans-serif;opacity:.72;color:inherit}
.lafoot img{width:14px;height:14px;border-radius:4px;display:block}
.lafoot .laf-right{margin-left:auto}
""" % {"a": ACCENT, "al": ACCENT_LT}


def brand_chip(tool: str = "", href: str | None = None, title: str | None = None) -> str:
    tool_html = ('<span class="latool">%s</span>' % html.escape(tool)) if tool else ""
    inner = '<img src="%s" alt=""><span>%s</span>%s' % (logo_data_uri(), PRODUCT, tool_html)
    tip = html.escape(title or ("%s %s" % (PRODUCT, version())).strip())
    if href:
        return ('<a class="labrand" href="%s" title="%s" target="_blank" rel="noopener">%s</a>'
                % (html.escape(href), tip, inner))
    return '<span class="labrand" title="%s">%s</span>' % (tip, inner)


def brand_banner(tool: str = "", subtitle: str = "", meta: str = "") -> str:
    v = version()
    right = meta or ("%s<br>%s" % (html.escape(v) if v else "",
                                   datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
    tool_line = ('<span class="lab-tool">%s</span>' % html.escape(tool)) if tool else ""
    sub = ('<span class="lab-tool">%s</span>' % html.escape(subtitle)) if subtitle else ""
    return ('<div class="labanner"><img src="%s" alt="">'
            '<span class="lab-txt"><span class="lab-wm">%s</span>%s%s</span>'
            '<span class="lab-meta">%s</span></div>'
            % (logo_data_uri(), PRODUCT, tool_line, sub, right))


def brand_footer(tool: str = "", extra: str = "") -> str:
    bits = ["<b>%s</b>" % PRODUCT]
    if tool:
        bits.append(html.escape(tool))
    if version():
        bits.append(html.escape(version()))
    right = extra or ("generated %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return ('<div class="lafoot"><img src="%s" alt=""><span>%s</span>'
            '<span class="laf-right">%s</span></div>'
            % (logo_data_uri(), " · ".join(bits), right))


def head_tags(tool: str = "", with_css: bool = True) -> str:
    out = ["<title>%s</title>" % html.escape(page_title(tool)), favicon_tag()]
    if with_css:
        out.append("<style>%s</style>" % brand_css())
    return "\n".join(out)


_MARK = "<!--log-analyzer-branded-->"


def brandify(page: str, tool: str = "", subtitle: str = "",
             banner: bool = True, footer: bool = True) -> str:
    """Add header/footer to an already rendered HTML page (idempotent)."""
    if not page or _MARK in page or "labrand" in page:
        return page
    try:
        head = _MARK + favicon_tag() + "<style>" + brand_css() + "</style>"
        if re.search(r"</head\s*>", page, re.I):
            page = re.sub(r"</head\s*>", lambda m: head + "</head>", page, count=1, flags=re.I)
        elif re.search(r"<body[^>]*>", page, re.I):
            page = re.sub(r"(<body[^>]*>)", lambda m: head + m.group(1), page, count=1, flags=re.I)
        else:
            page = head + page
        if banner:
            b = brand_banner(tool, subtitle)
            if re.search(r"<body[^>]*>", page, re.I):
                page = re.sub(r"(<body[^>]*>)", lambda m: m.group(1) + b, page, count=1, flags=re.I)
            else:
                page = b + page
        if footer:
            f = brand_footer(tool)
            if re.search(r"</body\s*>", page, re.I):
                page = re.sub(r"</body\s*>", lambda m: f + "</body>", page, count=1, flags=re.I)
            else:
                page += f
        return page
    except Exception:
        return page


def write_branded(path, page: str, tool: str = "", subtitle: str = "",
                  banner: bool = True, footer: bool = True, encoding="utf-8"):
    out = brandify(page, tool, subtitle, banner=banner, footer=footer)
    Path(path).write_text(out, encoding=encoding)
    return out
