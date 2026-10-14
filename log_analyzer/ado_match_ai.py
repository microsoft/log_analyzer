#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Known-issue matching for error signatures, via the platform's issue source.

The error signatures of one run are handed to the configured AI CLI, which
searches the platform's ``issue_source`` knowledge source (a skill, MCP server
or tool configured in the user's own AI CLI, named in sku_registry.json) one
signature at a time and cites real issue IDs.

The platform is detected (or passed with --sku) and ``sku_router`` maps it to
its issue source. When that platform has no issue source configured, the step
writes a short report saying so and does not call the AI at all - it never
substitutes another platform's issues.

This step must never block the main report: main() always exits 0 and a
missing output file simply means "known-issue match unavailable".
"""

import argparse
import html
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
COMMON_DIR = REPO_ROOT / "common"
for _p in (str(COMMON_DIR), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Cosmetic only: report generation must never fail because branding could not
# load, so the fallback is a no-op stub rather than an ImportError.
try:
    import brand
except Exception:                                        # pragma: no cover
    class brand:                                         # noqa: N801
        brandify = staticmethod(lambda page, *a, **k: page)
        _nil = staticmethod(lambda *a, **k: "")
        brand_css = favicon_tag = head_tags = _nil
        brand_chip = brand_banner = brand_footer = _nil

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OUTPUT_HTML = "ado_match_result.html"
OUTPUT_LOG = "ado_match_result.log"
SIGNATURES_LOG = "error_signatures.log"
PROMPT_FILE = HERE / "prompts" / "ado_match.md"
TOOL_TITLE = "Known-Issue Match"

# Cap what we hand the agent: signature lines can be enormous raw dumps and the
# command-line length limit of the AI CLI is the real constraint.
MAX_SIGNATURES = 40
MAX_SIGNATURE_CHARS = 400

_PAGE_HEAD = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Known-Issue Match Result</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f7f9}}
.ok{{background:#e8f5e9;border:1px solid #a5d6a7;padding:14px;border-radius:6px}}
.warn{{background:#fff3cd;border:1px solid #ffeeba;padding:14px;border-radius:6px}}
pre{{background:#fff;border:1px solid #ddd;border-radius:6px;padding:12px;
white-space:pre-wrap;word-wrap:break-word;font-size:13px;line-height:1.5}}
</style></head><body>
<h1>Known-Issue Match Result</h1>
<p><b>System:</b> {sut}<br><b>Platform:</b> {sku}<br><b>Generated:</b> {ts}</p>
"""

EMPTY_HTML = _PAGE_HEAD + """<p class="ok">No error signatures were produced for this
run, so there was nothing to match against known issues.</p>
</body></html>
"""

NO_SOURCE_HTML = _PAGE_HEAD + """<p class="warn">{reason}</p>
<p>{count} error signature(s) were found but not matched. They are listed below
so nothing is lost; matching them requires an issue source for this platform
(see <code>knowledge.issue_source</code> in sku_registry.json).</p>
<pre>{signatures}</pre>
</body></html>
"""

FALLBACK_HTML = _PAGE_HEAD + """<p class="warn">The agent did not write a formatted
report file, so its raw response is shown below.</p>
<pre>{body}</pre>
</body></html>
"""


def _import_router():
    import sku_router
    return sku_router


def resolve_issue_source(scan_folder: Path, explicit_sku: str):
    """Pick the issue source for this folder's platform.

    Returns (sku, source_name, detection, problem). ``problem`` is a
    human-readable reason when no source can be used - the caller must surface
    it rather than falling back to another platform's issues.
    """
    sku_router = _import_router()
    det = sku_router.detect_sku(scan_folder, explicit_sku or None)
    if not det.sku:
        return None, None, det, (
            "The platform of this log folder could not be determined, so there is "
            "no way to know which issue source is the right one. Re-run with "
            "--sku <platform> to match anyway. Details: " + "; ".join(det.evidence))

    sources = {s["role"]: s for s in sku_router.resolve_sources(det.sku)}
    name = sources.get("issue_source", {}).get("source")
    if not name:
        return det.sku, None, det, (
            "Platform %s has no issue source configured (knowledge.issue_source in "
            "sku_registry.json), so known-issue matching is not available." % det.sku)
    return det.sku, name, det, None


def read_signatures(scan_folder: Path):
    """Return the trimmed, de-duplicated signature lines for this run."""
    path = scan_folder / SIGNATURES_LOG
    if not path.is_file():
        return []
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line[:MAX_SIGNATURE_CHARS])
        if len(out) >= MAX_SIGNATURES:
            break
    return out


def _write_log_summary(scan_folder: Path, payload: dict):
    """Keep ado_match_result.log present; the report index links to it."""
    try:
        (scan_folder / OUTPUT_LOG).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not write %s: %s", OUTPUT_LOG, exc)


def _link_instruction(sku_router):
    try:
        url = sku_router.issue_url_template()
    except Exception:                                     # registry issues must not crash
        url = ""
    if url:
        return "Make each issue ID a link to %s (replace <ID> with the issue ID)." % (
            url.replace("{id}", "<ID>"))
    return "Show issue IDs as plain text; no issue-tracker link is configured."


def run_ado_match(scan_folder: Path, sut: str, model: str, timeout: int,
                  sku: str = "") -> bool:
    import ai_backend

    output_path = scan_folder / OUTPUT_HTML
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if output_path.exists():
        # Never let a stale report from a previous run look fresh.
        try:
            output_path.unlink()
        except OSError as exc:
            logger.warning("Could not remove stale %s: %s", output_path, exc)

    resolved_sku, source, detection, problem = resolve_issue_source(scan_folder, sku)
    sku_label = resolved_sku or "unknown platform"
    logger.info("Platform routing: %s", detection.as_dict())
    base = {"sut": sut, "generated": ts, "sku": resolved_sku,
            "sku_detection": detection.as_dict()}

    signatures = read_signatures(scan_folder)
    if not signatures:
        logger.info("No error signatures in %s; nothing to match.", scan_folder)
        output_path.write_text(brand.brandify(
            EMPTY_HTML.format(sut=html.escape(sut), sku=html.escape(sku_label), ts=ts),
            TOOL_TITLE, sut), encoding="utf-8")
        _write_log_summary(scan_folder, dict(base, signature_count=0, matches=[]))
        return True

    if problem:
        # No issue source for this platform: report the gap, keep the signatures.
        logger.warning("Known-issue match not possible: %s", problem)
        output_path.write_text(brand.brandify(
            NO_SOURCE_HTML.format(sut=html.escape(sut), sku=html.escape(sku_label), ts=ts,
                                  reason=html.escape(problem), count=len(signatures),
                                  signatures=html.escape("\n".join(signatures))),
            TOOL_TITLE, sut), encoding="utf-8")
        _write_log_summary(scan_folder, dict(base, signature_count=len(signatures),
                                             error=problem))
        return False

    backend = ai_backend.create_cli_backend(model=model, workdir=str(REPO_ROOT))
    if backend is None:
        reason = ("No AI CLI is configured or available (%s); skipping known-issue "
                  "match." % ai_backend.cli_backend_label())
        logger.warning("%s", reason)
        _write_log_summary(scan_folder, dict(base, signature_count=len(signatures),
                                             error=reason))
        return False

    try:
        backend.preflight(timeout=min(timeout, 90))
    except Exception as exc:
        reason = "AI backend preflight failed: %s" % exc
        logger.error("%s", reason)
        _write_log_summary(scan_folder, dict(base, signature_count=len(signatures),
                                             error=reason))
        return False

    sku_router = _import_router()
    try:
        display = sku_router.load_registry()["skus"][resolved_sku].get(
            "display_name") or resolved_sku
    except Exception:                                     # registry issues must not crash
        display = resolved_sku

    numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(signatures, 1))
    prompt = PROMPT_FILE.read_text(encoding="utf-8").format(
        sut=sut, signatures=numbered, output=output_path, issue_source=source,
        platform=resolved_sku, platform_label=display,
        link_instruction=_link_instruction(sku_router))

    logger.info("Running known-issue match via %s for platform %s (model=%s, "
                "timeout=%ss, %d signature(s))", source, resolved_sku, model, timeout,
                len(signatures))

    # Knowledge-source tools stay enabled: the issue source IS the point of this step.
    text = backend.run(
        prompt,
        extra_dirs=[str(scan_folder)],
        timeout=timeout,
        on_status=lambda m: logger.info("[match] %s", str(m)[:200]),
    ) or ""

    _write_log_summary(scan_folder, dict(base, signature_count=len(signatures),
                                         source=source, report=str(output_path),
                                         agent_reply_chars=len(text),
                                         ai_notice=ai_backend.AI_NOTICE))

    if output_path.exists() and output_path.stat().st_size > 0:
        try:
            page = output_path.read_text(encoding="utf-8", errors="replace")
            output_path.write_text(brand.brandify(page, TOOL_TITLE, sut, ai_generated=True),
                                   encoding="utf-8")
        except Exception as exc:                         # cosmetic; never fail the run
            logger.warning("Could not add the AI notice to %s: %s", output_path, exc)
        logger.info("Known-issue match report written to %s (%d bytes)",
                    output_path, output_path.stat().st_size)
        return True

    if not text.strip():
        logger.error("Known-issue match produced no report and no text.")
        return False

    logger.warning("Agent did not write %s; saving its raw response instead.",
                   OUTPUT_HTML)
    output_path.write_text(brand.brandify(
        FALLBACK_HTML.format(sut=html.escape(sut), sku=html.escape(sku_label),
                             ts=ts, body=html.escape(text)),
        TOOL_TITLE, sut, ai_generated=True), encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Match error signatures against the known issues of the "
                    "platform's configured issue source")
    parser.add_argument("--scan_folder", required=True, help="Log folder")
    parser.add_argument("--sut", default="", help="System name for the report header")
    parser.add_argument("--sku", default=os.getenv("LOG_ANALYZER_PLATFORM", ""),
                        help="Platform name from sku_registry.json (env "
                             "LOG_ANALYZER_PLATFORM). Auto-detected when omitted.")
    parser.add_argument("--model",
                        default=os.getenv("LOG_ANALYZER_ADO_MATCH_MODEL", "auto"),
                        help="AI model for the match pass (env LOG_ANALYZER_ADO_MATCH_MODEL)")
    parser.add_argument("--timeout", type=int,
                        default=int(os.getenv("LOG_ANALYZER_ADO_MATCH_TIMEOUT", "1800")),
                        help="Seconds to allow the agent to run "
                             "(env LOG_ANALYZER_ADO_MATCH_TIMEOUT)")
    args = parser.parse_args()

    scan_folder = Path(args.scan_folder)
    if not scan_folder.is_dir():
        logger.error("Scan folder not found: %s", scan_folder)
        return 0

    try:
        run_ado_match(scan_folder, args.sut or scan_folder.name,
                      args.model, args.timeout, args.sku)
    except Exception as exc:  # never block the main report
        logger.error("Known-issue match failed: %s", exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
