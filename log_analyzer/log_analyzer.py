# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
import sys
import logging
import argparse
import subprocess
from datetime import datetime as _dt
from pathlib import Path
import re


def convert_log_to_html(log_path):
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return None

    try:
        if log_path.lower().endswith(".log"):
            html_path = log_path[:-4] + ".html"
        else:
            html_path = log_path + ".html"

        with open(log_path, "r", encoding="utf-8", errors="replace") as log_file:
            lines = log_file.readlines()

        # Logs written from AI output carry the AI notice; surface it visibly.
        ai_notice = ""
        if any(ai_backend.AI_NOTICE in line for line in lines[:200]):
            ai_notice = getattr(brand, "ai_notice_html", lambda: "")()

        with open(html_path, "w", encoding="utf-8") as html_file:
            html_file.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Log Analyzer · {os.path.basename(log_path)}</title>
    {brand.favicon_tag()}
    <style>
{brand.brand_css()}
        body {{ font-family: monospace; white-space: pre-wrap; }}
        .error {{ color: red; font-weight: bold; }}
        .warning {{ color: orange; }}
        .info {{ color: blue; }}
        .debug {{ color: green; }}
        .default {{ color: black; }}
        a {{ color: darkcyan; text-decoration: underline; }}
    </style>
</head>
<body>
{brand.brand_banner("Log Viewer", os.path.basename(log_path))}
{ai_notice}
<pre>
""")

            for line in lines:
                safe_line = (
                    line.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                )

                # Detect file paths in the line (basic pattern: C:\... or /var/...)
                file_path_pattern = r'(?:[a-zA-Z]:\\[^\s]+|\/[^\s]+)'
                matches = re.findall(file_path_pattern, safe_line)

                for match in matches:
                    #path_as_url = f'file:///{match.replace("\\\\", "/").replace("\\", "/")}'
                    safe_path = match.replace("\\\\", "/").replace("\\", "/")
                    path_as_url = f'file:///{safe_path}'
                    hyperlink = f"<a href='{path_as_url}'>{match}</a>"
                    safe_line = safe_line.replace(match, hyperlink)

                # Apply CSS classes based on log level
                if "error" in line.lower():
                    css_class = "error"
                elif "warn" in line.lower():
                    css_class = "warning"
                elif "info" in line.lower():
                    css_class = "info"
                elif "debug" in line.lower():
                    css_class = "debug"
                else:
                    css_class = "default"

                html_file.write(f"<span class='{css_class}'>{safe_line}</span>")

            html_file.write("</pre>\n"
                            + brand.brand_footer("Log Viewer")
                            + "\n</body>\n</html>")

        print(f"HTML file created at: {html_path}")
        return html_path

    except Exception as e:
        print(f"Failed to convert {log_path} to HTML: {e}")
        return None


# Resolve the absolute path to the script directory.
script_dir = Path(__file__).resolve().parent

# The "sut" folder (signature packs) is expected in the repository root.
sut_folder = script_dir.parent / "sut"

# Append the absolute path to the ../common folder relative to this file.
common_path = script_dir.parent / "common"
sys.path.insert(0, str(common_path))

from lib_log import *
import ai_backend

# Header/footer styling for every HTML this module writes.
# Cosmetic only: a report must still be produced if branding cannot load, so
# the fallback is a no-op stub rather than an exception.
try:
    import brand
except Exception:                                        # pragma: no cover
    class brand:                                         # noqa: N801
        _nil = staticmethod(lambda *a, **k: "")
        brand_css = favicon_tag = head_tags = _nil
        brand_chip = brand_banner = brand_footer = _nil


def _bool_arg(value):
    return str(value).lower() in ("true", "1", "yes")


def create_parser():
    """Creates and returns the argument parser."""
    parser = argparse.ArgumentParser(
        description="log_analyzer: error-signature detection across nested log folders"
    )
    
    # Required arguments
    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument(
        "--scan_folder",
        help="Specify the folder to scan for logs",
        required=True
    )
    required_group.add_argument(
        "--signature",
        required=True,
        help=(
            "Signature pack(s) to load: a bare name (without the 'settings.' prefix or "
            "'.json' extension), searched recursively in the repository's sut folder, or a "
            "path to a settings JSON file. Separate several packs with commas; their "
            "signatures are combined. For example, --signature sample loads "
            "sut/settings.sample.json and --signature sample,ocp_diag adds the OCP pack."
        )
    )
    
    # Optional general arguments
    optional_group = parser.add_argument_group('optional arguments')
    optional_group.add_argument(
        "--logpath",
        help="Specify the path where logs will be saved."
    )
    optional_group.add_argument(
        "--ado_search",
        type=_bool_arg,
        default=False,
        help="Match findings against known issues through the AI CLI (default: false). Pass 'true' to enable; requires --ai."
    )
    optional_group.add_argument(
        "--to_csv",
        type=_bool_arg,
        default=False,
        help="Specify whether to convert .json and .xml files to .csv before error signature search (default: false). Pass 'true' to enable."
    )
    optional_group.add_argument(
        "--ocp_diag",
        choices=("auto", "true", "false"),
        default="auto",
        help=(
            "Normalize OCP Test and Validation (spec v2.0) diagnostic output found in "
            "*.json/*.jsonl files into *.ocptv.log/*.ocptv.csv and apply the ocp_diag "
            "signature pack (default: auto = only when such output is detected)."
        )
    )
    optional_group.add_argument(
        "--no_stop",
        type=_bool_arg,
        default=True,
        help="Specify whether to disable stopping on critical errors (default: true). Pass 'false' to stop on errors."
    )
    optional_group.add_argument(
        "--compare_good_log",
        type=_bool_arg,
        default=True,
        help="LLM-based comparison against good_log baselines declared in error signatures (default: true). Only runs with --ai. Pass 'false' to disable."
    )
    optional_group.add_argument(
        "--result_analyzer",
        type=_bool_arg,
        default=False,
        help="Run result_analyzer.py (consolidated test report) after log analysis completes (default: false). Pass 'true' to enable."
    )
    optional_group.add_argument(
        "--cycle_diff",
        type=_bool_arg,
        default=False,
        help=(
            "Compare collector output files, workload/tool folders and sensor CSVs across "
            "cycles (default: false); with --ai, changed targets are also explained by the AI backend."
        )
    )
    optional_group.add_argument(
        "--deep_analysis",
        type=_bool_arg,
        default=False,
        help=(
            "Run the agentic deep analysis (deep_analysis.py) as the last step (default: false). "
            "Pass 'true' or set LOG_ANALYZER_DEEP=1 to enable; requires --ai."
        )
    )
    optional_group.add_argument(
        "--ai",
        action="store_true",
        help=(
            "Enable AI analysis: LLM summary of findings, good-log comparison, AI explanations "
            "in the test report and cycle diff, and the opt-in deep analysis / known-issue "
            "match. Off by default; LOG_ANALYZER_AI=1 also enables it. AI output is labelled "
            "'AI-generated, may be inaccurate, verify against the log evidence.'"
        )
    )
    optional_group.add_argument(
        "--no_ai",
        action="store_true",
        help="Force AI analysis off, overriding --ai and LOG_ANALYZER_AI (AI is off by default)."
    )
    optional_group.add_argument(
        "--version",
        action="store_true",
        help="Print the version and exit."
    )
    
    return parser

def parse_args():
    parser = create_parser()
    # If no arguments are provided, print help and exit.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()

def normalize_signature(sig_input: str) -> str:
    """
    Removes any directory part, 'settings.' prefix or '.json' suffix from the provided signature.
    """
    norm_sig = Path(sig_input).name if ("/" in sig_input or "\\" in sig_input) else sig_input
    if norm_sig.startswith("settings."):
        norm_sig = norm_sig[len("settings."):]
    if norm_sig.endswith(".json"):
        norm_sig = norm_sig[:-len(".json")]
    return norm_sig

def find_signature_config(sig_input: str) -> Path:
    """
    Resolve the signature pack for --signature.

    Accepts a path to a settings JSON file, or a bare name whose file
    'settings.{name}.json' is searched recursively in the repository's sut
    folder. As a last resort a platform name/alias from sku_registry.json is
    mapped to its declared signature packs. Logs an error and exits if nothing
    is found.
    """
    explicit = Path(sig_input)
    if explicit.suffix.lower() == ".json" and explicit.is_file():
        return explicit.resolve()

    normalized_sig = normalize_signature(sig_input)
    expected_filename = f"settings.{normalized_sig}.json"
    
    if sut_folder.exists():
        for config_file in sorted(sut_folder.rglob(expected_filename)):
            return config_file
        try:
            import sku_router
            sku = sku_router.normalize_sku(normalized_sig)
            if sku:
                for filename in sku_router.load_registry()["skus"][sku]["signature_packs"]:
                    for candidate in sorted(sut_folder.rglob(filename)):
                        if candidate.is_file():
                            return candidate
        except Exception as exc:
            logging.debug(f"Platform-alias signature lookup failed: {exc}")

    logging.error(
        f"Configuration file for signature '{sig_input}' not found. Expected file name: "
        f"'{expected_filename}' in '{sut_folder}' (or pass a path to a settings JSON file)."
    )
    sys.exit(1)

def split_signatures(sig_input: str):
    """Split a comma-separated --signature value into individual pack names."""
    return [part.strip() for part in str(sig_input).split(",") if part.strip()]


def primary_signature(sig_input: str) -> str:
    """Normalized name of the first pack; used for platform routing."""
    parts = split_signatures(sig_input)
    return normalize_signature(parts[0]) if parts else ""


def _load_pack(signature_arg: str):
    config_file = find_signature_config(signature_arg)
    try:
        import json
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        logging.error(f"Error reading configuration file {config_file}: {e}")
        sys.exit(1)
    logging.info(f"Loaded configuration from {config_file}")
    return config, config_file


def merge_pack(config, extra, extra_file=None):
    """Append another pack's signatures to an already loaded configuration."""
    config.setdefault("error_signatures", [])
    config["error_signatures"].extend(extra.get("error_signatures") or [])
    if extra_file is not None:
        config.setdefault("_loaded_packs", []).append(str(extra_file))
    try:
        collect_signature_terms(config)
    except Exception as exc:
        logging.warning(f"Could not index signature terms: {exc}")
    return config


def read_config_m(signature_arg: str):
    """
    Reads the configuration for one or more comma-separated signature packs.

    The first pack provides pack-level settings (such as dedup_mode); the
    signatures of the following packs are appended.
    """
    names = split_signatures(signature_arg)
    if not names:
        logging.error("No signature pack given.")
        sys.exit(1)
    config, config_file = _load_pack(names[0])
    config["_loaded_packs"] = [str(config_file)]
    for name in names[1:]:
        extra, extra_file = _load_pack(name)
        merge_pack(config, extra, extra_file)
    # This local reader shadows lib_log.read_config_m, so the pack-level
    # hooks have to be applied here too or a pack's declared dedup_mode
    # and its term table are silently ignored on the CLI path.
    try:
        apply_pack_dedup_mode(config)
        collect_signature_terms(config)
    except Exception as exc:
        logging.warning(f"Could not apply pack dedup settings: {exc}")
    return config


def run_ocp_diag_step(args, config):
    """Normalize OCP diagnostic output and make sure its signatures are loaded.

    Returns the list of source files that were normalized.
    """
    if args.ocp_diag == "false":
        return []
    try:
        import ocptv
    except Exception as exc:
        logging.warning(f"OCP diag support unavailable: {exc}")
        return []
    converted, legacy = ocptv.convert_folder(args.scan_folder)
    if legacy:
        logging.info(f"OCP diag: {len(legacy)} legacy (pre-2.0) file(s) left as raw text.")
    if not converted:
        if args.ocp_diag == "true":
            logging.warning("OCP diag: no OCP v2.0 diagnostic output found in the scan folder.")
        return []
    loaded = [Path(p).name.lower() for p in config.get("_loaded_packs", [])]
    if "settings.ocp_diag.json" not in loaded:
        extra, extra_file = _load_pack("ocp_diag")
        merge_pack(config, extra, extra_file)
        logging.info("OCP diag: added the ocp_diag signature pack.")
    return converted

def run_result_analyzer(input_logpath):
    """
    Run result_analyzer.py with the specified input logpath.
    Output will be streamed directly to console in real-time.
    
    Args:
        input_logpath: Path to pass as --input_logpath to result_analyzer.py
        
    Returns:
        bool: True if successful, False otherwise
    """
    result_analyzer_script = script_dir / "result_analyzer.py"
    
    if not result_analyzer_script.exists():
        logging.error(f"result_analyzer.py not found at: {result_analyzer_script}")
        return False
    
    try:
        cmd = [
            sys.executable,
            str(result_analyzer_script),
            "--input_logpath", str(input_logpath)
        ]
        
        logging.info(f"Running result_analyzer.py with input_logpath: {input_logpath}")
        logging.info(f"Command: {' '.join(cmd)}")
        logging.info("-" * 80)  # Visual separator
        
        # Don't capture output - let it stream directly to console
        result = subprocess.run(
            cmd, 
            timeout=600  # 10 minute timeout, adjust as needed
        )
        
        logging.info("-" * 80)  # Visual separator
        
        if result.returncode == 0:
            logging.info("result_analyzer.py completed successfully")
            return True
        else:
            logging.error(f"result_analyzer.py failed with return code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        logging.error(f"result_analyzer.py timed out after 600 seconds")
        return False
    except Exception as e:
        logging.error(f"Error running result_analyzer.py: {e}")
        return False


# ── Cross-linking of generated reports ──────────────────────────────────────
# Every step of the pipeline drops its own standalone HTML into the scan folder,
# so users had to know each filename to find anything. We inject a shared nav bar
# into all of them and generate an index.html landing page.
NAV_START = "<!--LOG_ANALYZER_NAV_START-->"
NAV_END = "<!--LOG_ANALYZER_NAV_END-->"
INDEX_NAME = "index.html"

# Longest-prefix-ish friendly names; first matching substring wins.
_REPORT_LABELS = [
    ("analysis_report", "Test Analysis Report"),
    ("deep_analysis", "Deep Analysis"),
    ("sensor_xlsx_digest", "Sensor XLSX Digest"),
    ("cycle_diff", "Cross-Cycle Diff"),
    ("cross_cycle", "Cross-Cycle Diff"),
    ("error_signatures_summary", "Error Signatures (Summary)"),
    ("error-signatures-details", "Error Signatures (Details)"),
    ("error_signatures", "Error Signatures"),
    ("sensor", "Sensors"),
    ("log_analyzer", "Log Analyzer"),
]

# Non-HTML artifacts worth surfacing on the index so users know they exist.
# (pattern, friendly label) - matched case-insensitively against the file name;
# the label is suffixed with the file kind (workbook / raw CSV).
_ARTIFACT_LABELS = [
    ("sdr_reading", "BMC SDR sensor readings"),
    ("sensor_reading", "Sensor readings"),
    (".ocptv", "OCP diagnostic output (normalized)"),
]
_ARTIFACT_SUFFIXES = {".xlsx", ".xlsm", ".csv"}

_NAV_CSS = (
    "#la-nav{font-family:Segoe UI,Arial,sans-serif;font-size:13px;"
    "background:#1f2430;color:#e6e6e6;padding:8px 14px;margin:0 0 12px 0;"
    "border-bottom:2px solid #4a90d9;display:flex;flex-wrap:wrap;gap:6px;"
    "align-items:center}"
    "#la-nav b{margin-right:10px;color:#8ab4f8;letter-spacing:.5px}"
    "#la-nav a{color:#e6e6e6;text-decoration:none;padding:3px 9px;"
    "border-radius:4px;background:#2c3446}"
    "#la-nav a:hover{background:#4a90d9;color:#fff}"
    "#la-nav a.current{background:#4a90d9;color:#fff;font-weight:600}"
)


def _report_label(name):
    lowered = name.lower()
    for key, label in _REPORT_LABELS:
        if key in lowered:
            return label
    return Path(name).stem.replace("_", " ").replace("-", " ").title()


def _build_nav_html(entries, current_name):
    def _link(href, label):
        cls = ' class="current"' if href == current_name else ""
        return f'<a href="{href}"{cls}>{label}</a>'

    links = ["<b>Log Analyzer Reports</b>", _link(INDEX_NAME, "Index")]
    links += [_link(name, label) for name, label in entries]
    return (f"{NAV_START}<style>{_NAV_CSS}</style>"
            f'<div id="la-nav">{"".join(links)}</div>{NAV_END}')


def _inject_nav(html_path, entries):
    """Insert (or refresh) the nav bar right after <body> in an existing report."""
    try:
        text = html_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logging.warning("Could not read %s: %s", html_path, exc)
        return False

    # Re-runs must replace the old bar, not stack another one on top.
    if NAV_START in text and NAV_END in text:
        start = text.index(NAV_START)
        end = text.index(NAV_END) + len(NAV_END)
        text = text[:start] + text[end:]

    nav = _build_nav_html(entries, html_path.name)
    match = re.search(r"<body[^>]*>", text, re.IGNORECASE)
    if match:
        text = text[:match.end()] + nav + text[match.end():]
    else:
        text = nav + text

    try:
        html_path.write_text(text, encoding="utf-8")
        return True
    except OSError as exc:
        logging.warning("Could not write %s: %s", html_path, exc)
        return False


def _human_size(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0


def _collect_artifacts(scan_folder):
    """Data files (xlsx/csv) that are not reports but users still need to reach."""
    found = []
    for path in sorted(scan_folder.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_file() or path.suffix.lower() not in _ARTIFACT_SUFFIXES:
            continue
        lowered = path.name.lower()
        label = next((lab for pat, lab in _ARTIFACT_LABELS if pat in lowered), None)
        if label is None:
            continue
        label += " (workbook)" if path.suffix.lower() in (".xlsx", ".xlsm") else " (raw CSV)"
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        found.append((path.name, label, _human_size(size)))
    # xlsx first: they are the curated view, the raw csv is the fallback.
    found.sort(key=lambda item: (0 if item[0].lower().endswith(".xlsx") else 1,
                                 item[0].lower()))
    return found


def build_html_index(scan_folder):
    """Cross-link all reports in scan_folder and write an index.html landing page."""
    scan_folder = Path(scan_folder)
    if not scan_folder.is_dir():
        return

    reports = sorted((p for p in scan_folder.glob("*.html")
                      if p.name.lower() != INDEX_NAME),
                     key=lambda p: p.name.lower())
    if not reports:
        logging.info("No HTML reports found in %s; skipping index.", scan_folder)
        return

    entries = [(p.name, _report_label(p.name)) for p in reports]

    for report in reports:
        _inject_nav(report, entries)

    rows = "\n".join(
        f'<li><a href="{name}">{label}</a>'
        f'<span class="fn">{name}</span></li>'
        for name, label in entries
    )

    artifacts = _collect_artifacts(scan_folder)
    if artifacts:
        art_rows = "\n".join(
            f'<li><a href="{name}">{label}</a>'
            f'<span class="fn">{name} &middot; {size}</span></li>'
            for name, label, size in artifacts
        )
        artifacts_block = (
            '<h2 class="sec">Sensor Data Files</h2>'
            '<div class="sub">Spreadsheets/CSVs produced by sensor collection. '
            'Click to open in Excel; the workbooks summarize sensor status and '
            'sharply-changing readings.</div>'
            f'<ul>\n{art_rows}\n</ul>'
        )
    else:
        artifacts_block = ""

    index_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Log Analyzer Reports - {scan_folder.name}</title>
{brand.favicon_tag()}
<style>{brand.brand_css()}
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f7f7f9;color:#222}}
.wrap{{max-width:900px;margin:24px auto;padding:0 16px}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:#666;font-size:13px;margin-bottom:18px}}
ul{{list-style:none;padding:0;margin:0}}
li{{background:#fff;border:1px solid #ddd;border-radius:6px;margin-bottom:8px;
padding:12px 16px;display:flex;justify-content:space-between;align-items:center}}
li a{{font-size:15px;font-weight:600;color:#1a5fb4;text-decoration:none}}
li a:hover{{text-decoration:underline}}
.fn{{color:#888;font-size:12px;font-family:Consolas,monospace}}
h2.sec{{font-size:16px;margin:22px 0 8px;padding-top:14px;
border-top:1px solid #ddd;color:#333}}
</style></head><body>
{_build_nav_html(entries, INDEX_NAME)}
<div class="wrap">
{brand.brand_banner("Reports", str(scan_folder))}
<div class="sub">{scan_folder} &middot; generated {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<h2 class="sec">Reports</h2>
<ul>
{rows}
</ul>
{artifacts_block}
{brand.brand_footer("Reports")}
</div></body></html>
"""
    index_path = scan_folder / INDEX_NAME
    index_path.write_text(index_html, encoding="utf-8")
    logging.info("Wrote report index with %d links: %s", len(entries), index_path)


def organize_html_files(scan_folder, log_folder):
    """
    Organize generated HTML files by moving intermediate analysis files 
    to the log_analyzer's own log folder, keeping only key reports in scan_folder.
    
    Files to keep in scan_folder root:
    - *analysis_report_*.html (test report from result_analyzer.py)
    - error_signatures*.html (including error_signatures_summary.html, error-signatures-details.html)
    - summary_good_log_analysis.html
    
    All other HTML files will be moved to the log_analyzer's log folder.
    
    Args:
        scan_folder: The scan folder path where HTML files were generated
        log_folder: The log_analyzer's own log folder path (e.g., logs/LOG_ANALYZER-3.0.0-HOST-11301630)
    """
    import glob
    import shutil
    
    # Keep ALL analyzer HTML at the top level of scan_folder (next to
    # error_signatures.html/.log) by default. Set LOG_ANALYZER_ORGANIZE_HTML=1 to
    # move intermediate HTML into the LOG_ANALYZER-* subfolder instead.
    if os.getenv("LOG_ANALYZER_ORGANIZE_HTML", "0").strip().lower() not in ("1", "true", "yes"):
        logging.info("Keeping all HTML at top level of scan_folder (organize disabled; set LOG_ANALYZER_ORGANIZE_HTML=1 to move intermediate HTML).")
        return
    
    if not os.path.exists(log_folder):
        logging.error(f"Log folder does not exist: {log_folder}")
        return
    
    # Patterns for files to KEEP in scan_folder root
    keep_patterns = [
        "*analysis_report_*.html",
        "error_signatures*.html",  # This covers error_signatures.html, error_signatures_summary.html, error-signatures-details.html
        "summary_good_log_analysis.html"
    ]
    
    # Get all HTML files in scan_folder root (not recursive)
    all_html_files = glob.glob(os.path.join(scan_folder, "*.html"))
    
    if not all_html_files:
        logging.info("No HTML files found in scan_folder to organize")
        return
    
    # Determine which files to keep
    files_to_keep = set()
    for pattern in keep_patterns:
        matching_files = glob.glob(os.path.join(scan_folder, pattern))
        files_to_keep.update(matching_files)
    
    # Files to move = all HTML files - files to keep
    files_to_move = [f for f in all_html_files if f not in files_to_keep]
    
    if not files_to_move:
        logging.info("No HTML files need to be moved - all files are in the keep list")
        return
    
    logging.info(f"Organizing HTML files: keeping {len(files_to_keep)} files, moving {len(files_to_move)} files to {log_folder}")
    
    moved_count = 0
    failed_count = 0
    
    for file_path in files_to_move:
        try:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(log_folder, filename)
            
            # If destination file exists, add a suffix to avoid overwriting
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(log_folder, f"{base}_{counter}{ext}")
                    counter += 1
            
            shutil.move(file_path, dest_path)
            logging.info(f"Moved: {filename} -> {log_folder}")
            moved_count += 1
            
        except Exception as e:
            logging.error(f"Failed to move {file_path}: {e}")
            failed_count += 1
    
    logging.info(f"HTML file organization completed: {moved_count} moved, {failed_count} failed")
    
    # Log the files that were kept
    if files_to_keep:
        logging.info("Files kept in scan_folder:")
        for kept_file in sorted(files_to_keep):
            logging.info(f"  - {os.path.basename(kept_file)}")

def prepare_platform_analysis(args, config):
    """Detect the platform for logging and signature/knowledge-source routing.

    Detection is informational only: a failure here never stops the analysis.
    """
    try:
        import sku_router
    except Exception as exc:
        logging.info(f"Platform detection unavailable: {exc}")
        return None
    try:
        declared = config.get("sku") or config.get("SUT_SKU")
        detection = sku_router.detect_sku(
            args.scan_folder, explicit=declared, pack=primary_signature(args.signature))
        logging.info(sku_router.describe(detection))
        return detection
    except Exception as exc:
        logging.warning(f"Platform detection failed: {exc}")
        return None


def _env_flag(name):
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes")


def run_deep_analysis(args):
    """Optional agentic deep analysis (deep_analysis.py), run as the last step."""
    if not (args.deep_analysis or _env_flag("LOG_ANALYZER_DEEP")):
        logging.info("Deep analysis not requested (enable with --deep_analysis true or LOG_ANALYZER_DEEP=1).")
        return
    if args.no_ai:
        logging.info("AI analysis is off; skipping deep analysis (enable with --ai).")
        return
    deep_script = script_dir / "deep_analysis.py"
    if not deep_script.exists():
        logging.warning("deep_analysis.py not found at: %s", deep_script)
        return
    _da_to = int(os.getenv("LOG_ANALYZER_DEEP_TIMEOUT", "3600"))
    cmd = [sys.executable, str(deep_script),
           "--scan_folder", str(args.scan_folder),
           "--signature", primary_signature(args.signature),
           "--timeout", str(_da_to)]
    deep_model = os.getenv("LOG_ANALYZER_DEEP_MODEL", "").strip()
    if deep_model:
        cmd += ["--model", deep_model]
    try:
        logging.info("Starting deep analysis...")
        result = subprocess.run(cmd, timeout=_da_to + 120)
        if result.returncode != 0:
            logging.error("Deep analysis failed with return code %s", result.returncode)
    except subprocess.TimeoutExpired:
        logging.error("Deep analysis timed out after %s seconds", _da_to + 120)
    except Exception as e:
        logging.error(f"Error running deep analysis: {e}")


def main():
    banner = r'''
    +------------------------------+
    |         log_analyzer         |
    +------------------------------+
    '''
    print(banner)
    
    version = read_version()
    print(f"Version: {version}")
    
    if "--version" in sys.argv:
        sys.exit(0)
    
    args = parse_args()
    # AI is opt-in. From here on args.no_ai is the single switch every step checks.
    args.no_ai = args.no_ai or not ai_backend.ai_enabled(args.ai)
    
    result = create_testlog("LOG_ANALYZER", logpath=args.scan_folder)
    if result is None:
        print("Error creating log, exiting...")
        sys.exit(1)
    timestamp, log_file_path, log_folder, log_filename = result
    if args.no_ai:
        logging.info("AI analysis is off (default). Enable it with --ai or LOG_ANALYZER_AI=1.")
    else:
        logging.info(f"AI analysis is on. AI output is labelled: {ai_backend.AI_NOTICE}")

    config = read_config_m(args.signature)
    detection = prepare_platform_analysis(args, config)
    
    logging.info(f"Scan folder set to: {args.scan_folder}")
    display_title("LOG_ANALYZER")

    ocp_files = run_ocp_diag_step(args, config)

    if args.to_csv:
        logging.info("Converting JSON and XML files to CSV...")
        convert_files_to_csv(args.scan_folder, skip=ocp_files)

    # Perform log analysis and pass through the no_stop flag AND the new compare_good_log flag
    critical_stop, killed_processes_info, log_analyzer_log_file = log_analyzer(
        config,
        args.scan_folder,
        no_stop=args.no_stop,
        compare_good_log=args.compare_good_log and not args.no_ai
    )

    if os.path.exists(log_analyzer_log_file):
        if args.ado_search and not args.no_ai:
            logging.info("Performing ADO search...")
            categorize_matched_lines_ado(args.scan_folder)
        else:
            if args.ado_search:
                logging.info("AI analysis is off; skipping known-issue search (enable with --ai).")
            logging.info("Log analysis without ADO search...")
            categorize_matched_lines(args.scan_folder)
            
        # Always convert generated log files to HTML after analysis
        logging.info("Converting generated log files to HTML...")
        # ado_match_result.html is written directly by ado_match_ai.py;
        # converting the .log here would overwrite that real report with a
        # plain-text dump of the summary stub.
        log_files_to_convert = [
            "error-signatures-details.log",
            "error_signatures.log",
            "whitelisted-signatures.log",
            "log_analyzer_output.log",
            "stop_on_fail_result.log",
            "error_signatures_summary.log"
        ]
        base_log_folder = args.scan_folder   
        for log_file_name in log_files_to_convert:
            log_file_path = os.path.join(base_log_folder, log_file_name)
            if os.path.exists(log_file_path):
                html_path = convert_log_to_html(log_file_path)
                if html_path:
                    logging.info(f"Converted {log_file_path} to {html_path}")
                else:
                    logging.warning(f"Failed to convert {log_file_path}")
            else:
                logging.warning(f"{log_file_path} does not exist, skipping HTML conversion.")

        # Also convert any good_log analysis files to HTML
        import glob
        analysis_pattern = os.path.join(base_log_folder, "good_log_analysis_*.log")
        analysis_files = glob.glob(analysis_pattern)
        
        if analysis_files:
            logging.info(f"Found {len(analysis_files)} good_log analysis files to convert to HTML...")
            for analysis_file_path in analysis_files:
                html_path = convert_log_to_html(analysis_file_path)
                if html_path:
                    logging.info(f"Converted analysis file {analysis_file_path} to {html_path}")
                else:
                    logging.warning(f"Failed to convert analysis file {analysis_file_path}")
        else:
            logging.info("No good_log analysis files found to convert.")
                
        # Send error_signatures.log to LLM for summary analysis
        error_signatures_log_path = os.path.join(args.scan_folder, "error_signatures.log")
        details_log_path = os.path.join(args.scan_folder, "error-signatures-details.log")
        # The deduped error_signatures.log can end up empty or clobbered (e.g. the ADO
        # date-clean step overwriting it with an LLM 'no text' message). In that case
        # summarize the full details log instead so real findings are not lost.
        summary_source_path = error_signatures_log_path
        summary_skip_truncation = True
        try:
            _sig_size = os.path.getsize(error_signatures_log_path) if os.path.exists(error_signatures_log_path) else 0
            if _sig_size < 200 and os.path.exists(details_log_path) and os.path.getsize(details_log_path) > 200:
                summary_source_path = details_log_path
                summary_skip_truncation = False
                logging.warning(f"error_signatures.log is empty/near-empty ({_sig_size}B); summarizing {details_log_path} instead.")
        except Exception as _e:
            logging.warning(f"Could not evaluate summary source size: {_e}")
        if args.no_ai:
            logging.info("AI analysis is off; skipping the error-signature LLM summary.")
        elif os.path.exists(summary_source_path):
            logging.info("Sending error signatures to LLM for summary analysis...")
            summary_json_output = os.path.join(args.scan_folder, "error_signatures_summary.json")
            summary_analysis_output = os.path.join(args.scan_folder, "error_signatures_summary.log")
            
            try:
                send_summary_to_ollama(
                    log_file_path=summary_source_path,
                    model=ai_backend.http_model(),
                    api_url=ai_backend.http_api_url(),
                    json_output_path=summary_json_output,
                    analysis_output_path=summary_analysis_output,
                    timeout=int(os.getenv("LOG_ANALYZER_SUMMARY_TIMEOUT", "300")),
                    skip_context_truncation=summary_skip_truncation
                )
                logging.info(f"Error signatures summary completed. Results saved to {summary_analysis_output}")
                
                # Convert the summary log to HTML as well
                if os.path.exists(summary_analysis_output):
                    html_path = convert_log_to_html(summary_analysis_output)
                    if html_path:
                        logging.info(f"Converted summary analysis to HTML: {html_path}")
                        
            except Exception as e:
                logging.error(f"Failed to send error signatures to LLM for summary: {e}")
        else:
            logging.warning(f"Error signatures log not found at {error_signatures_log_path}, skipping LLM summary.")
        
        # Organize HTML files - move intermediate files to log_analyzer's log folder
        logging.info("Organizing HTML files...")
        organize_html_files(args.scan_folder, log_folder)

        # Run result_analyzer BEFORE cycle_diff. result_analyzer produces the
        # primary test report (consolidated pass/fail summary across all test
        # steps) and is comparatively fast; cycle_diff is the slow, best-effort
        # cross-cycle AI deep-dive. If an outer caller enforces a total time
        # budget, running result_analyzer first guarantees the pass/fail report
        # exists regardless of how long cycle_diff takes or whether it times out.
        # Without AI, result_analyzer still runs in deterministic mode
        # (--no_llm): the workload verdicts are pure parsing and cost no LLM
        # calls, so a pass/fail report exists after every run.
        if args.result_analyzer:
            logging.info("Starting result analyzer as requested...")
            logging.info("-" * 80)

            result_analyzer_script = script_dir / "result_analyzer.py"
            
            if not result_analyzer_script.exists():
                logging.error(f"result_analyzer.py not found at: {result_analyzer_script}")
            else:
                try:
                    # result_analyzer.py makes one AI CLI call per finding. Each
                    # call has a noticeable start-up cost, so a run with dozens of
                    # findings would exceed this step's timeout if serialized.
                    # The calls are stateless (own temp dir per invocation), so
                    # they are fanned out via --workers.
                    _ra_workers = os.getenv("LOG_ANALYZER_RESULT_ANALYZER_WORKERS", "6")
                    cmd = [
                        sys.executable,
                        str(result_analyzer_script),
                        "--input_logpath", str(args.scan_folder),
                        "--workers", str(_ra_workers)
                    ]
                    if args.no_ai:
                        cmd.append("--no_llm")
                        logging.info(
                            "AI off: running result_analyzer in deterministic "
                            "mode (--no_llm). Workload verdicts are still parsed."
                        )
                    else:
                        cmd.append("--ai")
                    
                    logging.info(f"Running result_analyzer.py with input_logpath: {args.scan_folder}")
                    logging.info(f"Command: {' '.join(cmd)}")
                    
                    # Don't capture output - let it stream directly to console
                    _ra_to = int(os.getenv("LOG_ANALYZER_RESULT_ANALYZER_TIMEOUT", "1800"))
                    result = subprocess.run(cmd, timeout=_ra_to)
                    
                    logging.info("-" * 80)
                    
                    if result.returncode == 0:
                        logging.info("result_analyzer.py completed successfully")
                    else:
                        logging.error(f"result_analyzer.py failed with return code {result.returncode}")
                        
                except subprocess.TimeoutExpired:
                    logging.error("result_analyzer.py timed out after %s seconds", _ra_to)
                except Exception as e:
                    logging.error(f"Error running result_analyzer.py: {e}")

        if args.cycle_diff:
            cycle_diff_script = script_dir / "cycle_diff_analyzer.py"
            cycle_diff_command = [
                sys.executable,
                str(cycle_diff_script),
                "--scan_folder", str(args.scan_folder),
            ]
            if args.no_ai:
                cycle_diff_command.append("--no_ai")
            else:
                cycle_diff_command.append("--ai")
            try:
                logging.info("Starting cross-cycle log comparison...")
                _cd_to = int(os.getenv("LOG_ANALYZER_CYCLE_DIFF_TIMEOUT", "1800"))
                result = subprocess.run(cycle_diff_command, timeout=_cd_to)
                if result.returncode != 0:
                    logging.error("Cross-cycle log comparison failed with return code %s", result.returncode)
            except subprocess.TimeoutExpired:
                logging.error("Cross-cycle log comparison timed out after %s seconds", _cd_to)
            except Exception as e:
                logging.error(f"Error running cross-cycle log comparison: {e}")

        # Deep analysis: one opt-in agentic pass, independent of the
        # per-finding classifications above. It is the slowest and least
        # essential step, so it runs last and its failure never affects the
        # test report.
        run_deep_analysis(args)

        # Turn the large sensor workbooks into a reviewable page before indexing.
        try:
            from sensor_xlsx_digest import build_digest as _build_sensor_digest
            _build_sensor_digest(Path(args.scan_folder))
        except Exception as e:
            logging.error(f"Error building sensor XLSX digest: {e}")

        # Cross-link every report in the folder so users can hop between them.
        try:
            build_html_index(Path(args.scan_folder))
        except Exception as e:
            logging.error(f"Error building HTML index: {e}")

    else:
        logging.error(f"Log_analyzer file not found: {log_analyzer_log_file}")
        
if __name__ == "__main__":
    main()
