#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deep AI analysis of one log folder.

This is deliberately the opposite of result_analyzer.py:

  result_analyzer.py -> many small, tool-free, per-finding classifications.
  deep_analysis.py   -> ONE agentic pass over the whole log folder through the
                        configured AI CLI, with real filesystem access to the
                        logs and, when configured, the platform's knowledge
                        sources (skills / MCP servers / tools) from
                        sku_registry.json.

AI is optional. When no AI CLI is configured or available the step is skipped
with a clear message. A failed run exits nonzero so the parent analyzer can
record it, while the parent still generates its deterministic reports.
"""

import argparse
import html
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

OUTPUT_NAME = "deep_analysis.html"
PROMPT_FILE = HERE / "prompts" / "deep_analysis.md"
TOOL_TITLE = "Deep Analysis"

ROLE_LABELS = {
    "issue_source": "known-issue / bug database",
    "kb": "platform documentation",
    "testplan": "test-case library",
}

FALLBACK_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Deep Analysis (raw)</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f7f9}}
pre{{background:#fff;border:1px solid #ddd;border-radius:6px;padding:16px;
white-space:pre-wrap;word-wrap:break-word;font-size:13px;line-height:1.5}}
.warn{{background:#fff3cd;border:1px solid #ffeeba;padding:12px;border-radius:6px}}
</style></head><body>
<h1>Deep Analysis</h1>
<p><b>Folder:</b> {folder}<br><b>Generated:</b> {ts}</p>
<p class="warn">The agent did not write a formatted report file, so its raw
response is shown below.</p>
<pre>{body}</pre>
</body></html>
"""


def knowledge_block(sources):
    """Prompt text listing the configured knowledge sources, if any."""
    configured = [s for s in sources if s.get("source")]
    if not configured:
        return ("No external knowledge sources are configured for this platform. "
                "Rely only on the files in the log folder and general engineering "
                "knowledge. Do not claim any finding is a known issue and do not cite "
                "issue IDs; classify real findings as UNCORRELATED.")
    lines = ["Cross-reference findings with these knowledge sources configured in your "
             "AI CLI (skills, MCP servers or tools). Use only these sources and the "
             "files in the log folder:"]
    for s in configured:
        lines.append("  - `%s` - %s" % (s["source"], ROLE_LABELS.get(s["role"], s["role"])))
    missing = [ROLE_LABELS.get(s["role"], s["role"]) for s in sources if not s.get("source")]
    if missing:
        lines.append("Not configured: %s." % ", ".join(missing))
    lines.append("If a source is unavailable or a search is incomplete, classify unmatched "
                 "findings as UNCORRELATED rather than proven NEW.")
    return "\n".join(lines)


def build_prompt(scan_folder, output_path, signature=None):
    import sku_router
    detection = sku_router.detect_sku(scan_folder, pack=signature)
    if detection.sku:
        info = sku_router.load_registry()["skus"].get(detection.sku) or {}
        platform = "%s (%s)" % (detection.sku, info.get("display_name") or detection.sku)
        sources = sku_router.resolve_sources(detection.sku)
    else:
        platform = "unknown"
        sources = []
    template = PROMPT_FILE.read_text(encoding="utf-8")
    return template.format(folder=scan_folder, output=output_path, platform=platform,
                           routing=sku_router.describe(detection),
                           knowledge_block=knowledge_block(sources))


def run_deep_analysis(scan_folder: Path, model: str, timeout: int, signature=None):
    """Run the deep pass. Returns True/False, or None when no AI CLI is available."""
    import ai_backend

    output_path = scan_folder / OUTPUT_NAME
    if output_path.exists():
        # Never let a stale report from a previous run masquerade as fresh.
        try:
            output_path.unlink()
        except OSError as exc:
            logger.warning("Could not remove stale %s: %s", output_path, exc)

    backend = ai_backend.create_cli_backend(model=model, workdir=str(REPO_ROOT))
    if backend is None:
        logger.warning("No AI CLI is configured or available (%s); skipping deep "
                       "analysis. Configure ai_cli in common/llm_config.json or set "
                       "LOG_ANALYZER_AI_CLI.", ai_backend.cli_backend_label())
        return None

    # Prove a fresh, non-interactive child can authenticate before handing it
    # the expensive analysis prompt.
    backend.preflight(timeout=min(timeout, 90))

    prompt = build_prompt(scan_folder, output_path, signature)
    logger.info("Running deep analysis via %s (model=%s, timeout=%ss) on %s",
                ai_backend.cli_backend_label(), model, timeout, scan_folder)

    # Knowledge-source tools stay enabled on purpose: those lookups are the
    # point of this step, and their start-up cost is paid once per run.
    text = backend.run(
        prompt,
        extra_dirs=[str(scan_folder)],
        timeout=timeout,
        on_status=lambda m: logger.info("[deep] %s", str(m)[:200]),
    ) or ""

    if output_path.exists() and output_path.stat().st_size > 0:
        _stamp_ai_notice(output_path)
        logger.info("Deep analysis written to %s (%d bytes)",
                    output_path, output_path.stat().st_size)
        return True

    if not text.strip():
        logger.error("Deep analysis produced no report and no text.")
        return False

    logger.warning("Agent did not write %s; saving its raw response instead.",
                   OUTPUT_NAME)
    output_path.write_text(
        brand.brandify(FALLBACK_HTML.format(
            folder=html.escape(str(scan_folder)),
            ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            body=html.escape(text),
        ), TOOL_TITLE, str(scan_folder), ai_generated=True),
        encoding="utf-8",
    )
    return True


def _stamp_ai_notice(path: Path):
    """Label an agent-written report as AI output (idempotent)."""
    try:
        page = path.read_text(encoding="utf-8", errors="replace")
        path.write_text(brand.brandify(page, TOOL_TITLE, ai_generated=True),
                        encoding="utf-8")
    except Exception as exc:                             # cosmetic; never fail the run
        logger.warning("Could not add the AI notice to %s: %s", path, exc)


def main():
    parser = argparse.ArgumentParser(description="Deep AI analysis of a test log folder")
    parser.add_argument("--scan_folder", required=True, help="Log folder to analyze")
    parser.add_argument("--signature",
                        help="Signature pack or platform name used to pick knowledge sources")
    parser.add_argument("--model",
                        default=os.getenv("LOG_ANALYZER_DEEP_MODEL", "auto"),
                        help="AI model for the deep pass (env LOG_ANALYZER_DEEP_MODEL)")
    parser.add_argument("--timeout", type=int,
                        default=int(os.getenv("LOG_ANALYZER_DEEP_TIMEOUT", "3600")),
                        help="Seconds to allow the agent to run (env LOG_ANALYZER_DEEP_TIMEOUT)")
    args = parser.parse_args()

    scan_folder = Path(args.scan_folder)
    if not scan_folder.is_dir():
        logger.error("Scan folder not found: %s", scan_folder)
        return 1

    try:
        result = run_deep_analysis(scan_folder, args.model, args.timeout, args.signature)
    except Exception as exc:  # never block the main report
        logger.error("Deep analysis failed: %s", exc)
        return 1
    return 0 if result is None or result else 1


if __name__ == "__main__":
    sys.exit(main())
