#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test suite result analyzer.

Scans a test run folder (one sub-folder per test cycle), extracts every
result line ("Result: PASS", "| Foo Result | FAIL |", ...) and every
structured workload verdict CSV, classifies them deterministically and,
optionally, asks an AI backend to explain non-passing results. The output is
a single interactive HTML report (``test_analysis_report_<timestamp>.html``).

Folder layouts recognised (see ``CYCLE_FOLDER_RE``):

* ``<host>_<TAG>_c<N>-<version>-<timestamp>`` - one folder per test cycle.
* ``Cycle_<N>`` plus optional ``Pretest`` / ``Posttest`` phase folders,
  possibly nested one or more levels below the run root.

If a test suite driver script was copied into the run root it is used to
learn which workloads ran (see ``SUITE_SCRIPT_GLOB``).

AI is optional. The CLI backend comes from ``common/ai_backend.py``; an
OpenAI-compatible HTTP LLM endpoint is used only when explicitly configured
(``--ai_url``, ``LOG_ANALYZER_AI_URL`` or ``ai_backend: "http"`` in
``common/llm_config.json``).
"""

import argparse
import html
import os
import re
import csv
import json
import socket
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import requests
import time
import threading

os.sys.path.insert(0, str(Path(__file__).resolve().parent))
_COMMON_DIR = str(Path(__file__).resolve().parent.parent / "common")
if _COMMON_DIR not in os.sys.path:
    os.sys.path.insert(0, _COMMON_DIR)
from md_render import md_to_html, REPORT_MD_CSS
import ai_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Two cycle-folder conventions are recognised:
#   "<hostname>_<TAG>_c<N>-<version>-<timestamp>" where <TAG> is any suite tag,
#   "<unit>/Cycle_<N>/..." with sibling "Pretest" / "Posttest" phase folders.
CYCLE_FOLDER_RE = re.compile(
    r"_[A-Za-z0-9]+_c(\d+)(?:-|_|$)"          # tagged:   ..._TAG_c12-...
    r"|^Cycle[_\-\s]?(\d+)$",                  # numbered: Cycle_12
    re.IGNORECASE)

# Phase folders that carry results but have no cycle number. They are mapped
# onto sentinel indices so they sort before/after the numbered cycles.
PHASE_FOLDERS = {"pretest": 0, "posttest": 10 ** 6}

# Glob (relative to the run root) for an optional test suite driver script.
# When present it lists the workloads that ran and the output folder each one
# owns. Override with --suite_glob or LOG_ANALYZER_SUITE_SCRIPT_GLOB.
SUITE_SCRIPT_GLOB = os.getenv("LOG_ANALYZER_SUITE_SCRIPT_GLOB", "*test_suite*.py")

# Name prefixes of log-collector helpers / output folders. Their content is
# covered by the dedicated log analyzers, so they are neither treated as
# workloads nor sent to the AI here. Override with LOG_ANALYZER_COLLECTOR_PREFIXES
# (comma-separated).
COLLECTOR_PREFIXES = tuple(
    p.strip().lower() for p in os.getenv(
        "LOG_ANALYZER_COLLECTOR_PREFIXES", "collector,log_collector").split(",")
    if p.strip())

# Diagnostic dump files that never contain test results.
DUMP_FILE_SKIP_TOKENS = ('coredump', 'crashdump', 'memdump', 'supportbundle')

# Reverse map, used to render the sentinels as their phase name instead of the
# meaningless "Cycle 0" / "Cycle 1000000".
PHASE_LABELS = {0: "Pretest", 10 ** 6: "Posttest"}


def _open_text(path, **kwargs):
    """Open a log file with the encoding it actually uses.

    Many Windows tools write UTF-16LE (FF FE byte-order mark). Reading those as
    UTF-8 yields text with a NUL between every visible character, which garbles
    result rows and breaks AI CLI calls ("embedded null character"). Sniff the
    BOM and decode correctly.
    """
    try:
        with open(path, 'rb') as fh:
            bom = fh.read(4)
    except Exception:
        bom = b''
    if bom.startswith(b'\xff\xfe') or bom.startswith(b'\xfe\xff'):
        enc = 'utf-16'
    elif bom.startswith(b'\xef\xbb\xbf'):
        enc = 'utf-8-sig'
    else:
        enc = 'utf-8'
    kwargs.setdefault('errors', 'ignore')
    return open(path, 'r', encoding=enc, **kwargs)


def report_file_link(log_file, report_path) -> str:
    """href for a log file that survives copying the run folder elsewhere.

    The report is often generated on the system under test and the whole run
    folder is then copied elsewhere, so an absolute file:// link breaks there.
    A link relative to the report keeps working.
    """
    log_file = Path(log_file)
    try:
        rel = os.path.relpath(log_file, Path(report_path).parent)
    except ValueError:  # different drive on Windows
        rel = None
    if rel and not rel.replace('\\', '/').startswith('../../../'):
        return quote(rel.replace('\\', '/'))
    try:
        return log_file.resolve().as_uri()
    except ValueError:
        return 'file://' + quote(str(log_file).replace('\\', '/'))


def cycle_label(cycle_num) -> str:
    """Human label for a cycle index: a phase name for the sentinels."""
    try:
        n = int(cycle_num)
    except (TypeError, ValueError):
        return str(cycle_num)
    if n in PHASE_LABELS:
        return PHASE_LABELS[n]
    return f"Cycle {n}"


# ── Deterministic verdict classification ──────────────────────────────────
# A workload that writes "| Disk Result | PASS | (ID: 12345)" has ALREADY
# stated its verdict. Reading it needs no LLM; making the status depend on one
# leaves almost every row UNKNOWN whenever the AI is unavailable or skipped.
#
# The verdict is read from a *delimited field*, never as a substring, because
# substring matching gets both directions wrong: the literal "| pass |" misses
# the real "|   PASS   |" (padded), while a bare "error" search would mislabel
# "| PASS | No diagnostic error entries present" as a failure.
VERDICT_TOKENS = {
    "PASS": "PASS", "PASSED": "PASS", "OK": "PASS",
    "SUCCESS": "PASS", "SUCCEEDED": "PASS", "GOOD": "PASS",
    # Config-compare tools state their per-key verdict as Match / Mismatch.
    "MATCH": "PASS", "MATCHED": "PASS",
    "MISMATCH": "FAIL", "MISMATCHED": "FAIL", "NOMATCH": "FAIL",
    "FAIL": "FAIL", "FAILED": "FAIL", "FAILURE": "FAIL",
    "ERROR": "FAIL", "ABORT": "FAIL", "ABORTED": "FAIL",
    "TIMEOUT": "FAIL", "TIMEDOUT": "FAIL",
    "WARN": "WARNING", "WARNING": "WARNING", "MARGINAL": "WARNING",
}

# Explicit completion phrases used by tools that report no verdict token.
# Deliberately a short whitelist rather than sentiment matching.
_COMPLETION_PASS = (
    "terminated successfully",
    "completed successfully",
    "finished successfully",
    "ran successfully",
)

_RESULT_VALUE_RE = re.compile(r'\bresults?\b[\'"]?\s*[:=]\s*(.+)$', re.IGNORECASE)
_SEVERITY = {"FAIL": 3, "WARNING": 2, "PASS": 1, "UNKNOWN": 0}

# Column headers that the generic "| <word> Result |" pattern matches even
# though they describe a table layout, not an outcome. Config-compare tools
# print one per run; counting them as results buries the real verdict-less
# rows in UNKNOWN noise.
_HEADER_FIELDS = {
    "node[key]", "source value", "target value", "expected", "actual",
    "status", "result", "test", "name", "value", "description", "component",
}


def is_result_header_line(line: str) -> bool:
    """True when a matched line is a table header rather than a result."""
    text = str(line or "")
    if "|" not in text:
        return False
    fields = [f.strip().lower() for f in text.split("|")]
    fields = [f for f in fields if f]
    if len(fields) < 3:
        return False
    # Drop a leading timestamp / severity prefix field before judging.
    body = []
    for f in fields:
        # A prefix field may carry both, e.g. "2026-07-14t05:44:29z [information]".
        # Strip only a STANDALONE bracketed token - never one glued to a word,
        # or the real header name "node[key]" would be destroyed.
        stripped = re.sub(r'(^|\s)\[[a-z]+\](?=\s|$)', ' ', f).strip()
        if not stripped or re.match(r'^[\d\-/:t\sz\.apm]+$', stripped):
            continue
        body.append(stripped)
    if len(body) < 3:
        return False
    return all(f in _HEADER_FIELDS for f in body)


def _verdict_from_field(field: str):
    """Map one delimited field to a verdict, or None if it is not one."""
    # Strip decoration: "* FAIL *", "[PASS]", "<<OK>>", trailing punctuation.
    cleaned = re.sub(r'[\s*\[\]<>()\.:;,\'"-]+', ' ', str(field)).strip().upper()
    if not cleaned or len(cleaned) > 12:
        return None
    return VERDICT_TOKENS.get(cleaned)


def classify_result_line(line: str) -> str:
    """Deterministic PASS/FAIL/WARNING/UNKNOWN verdict for one result line.

    Returns UNKNOWN when the line states no verdict - for example a
    config-compare table header ``| Result | Node[key] | Source Value |``,
    which is a column layout, not an outcome. Guessing there would be worse
    than admitting the gap.
    """
    text = str(line or "")
    if not text.strip():
        return "UNKNOWN"

    # 1. Delimited verdict field - the authoritative signal.
    #    Severity wins so "| PASS | ... | FAIL |" can never read as a pass.
    best = "UNKNOWN"
    if "|" in text:
        for field in text.split("|"):
            v = _verdict_from_field(field)
            if v and _SEVERITY[v] > _SEVERITY[best]:
                best = v
    if best != "UNKNOWN":
        return best

    # 2. "Result: <TOKEN>" / "test result: PASSED" - token must be exact.
    m = _RESULT_VALUE_RE.search(text)
    if m:
        value = m.group(1).strip()
        first = re.split(r'[\s,;|]+', value, maxsplit=1)[0]
        v = _verdict_from_field(first)
        if v:
            return v
        # 3. Known completion phrases, whitelisted explicitly.
        low = value.lower()
        if any(p in low for p in _COMPLETION_PASS):
            return "PASS"

    return "UNKNOWN"


def cycle_number_from_name(folder_name: str):
    """Cycle index for a folder name, or None when it is not a cycle folder.

    Returns the numbered cycle for both folder conventions, and a sentinel for
    the Pretest/Posttest phases so those results are analysed rather than
    dropped.
    """
    phase = PHASE_FOLDERS.get(str(folder_name).strip().lower())
    if phase is not None:
        return phase
    m = CYCLE_FOLDER_RE.search(str(folder_name))
    if not m:
        return None
    for g in m.groups():
        if g:
            return int(g)
    return None

# Replies that mean "I never received a task/log" rather than an analysis. The
# CLI returns these with exit code 0 and non-empty text, so nothing else in the
# pipeline can tell them apart from a real finding.
_NON_ANSWER_PATTERNS = re.compile(
    r"(i'm ready|i am ready|^ready[.!,]|ready to analyze"
    r"|don't see (?:a |any )?(?:specific )?(?:task|data|log)"
    r"|do not see (?:a |any )?(?:specific )?(?:task|data|log)"
    r"|no (?:specific )?task (?:or data )?(?:to work on|provided|given)"
    r"|need (?:a |more )?(?:specific )?(?:task|data|input)"
    r"|tell me what to analyze|what would you like|point me at"
    r"|nothing to analyze|input is empty|no input|please provide)",
    re.IGNORECASE | re.MULTILINE,
)


# ── Report branding ───────────────────────────────────────────────────────
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


def _is_non_answer(text: str) -> bool:
    """True when the model replied with a capability blurb / request for input."""
    stripped = (text or "").strip()
    if not stripped:
        return True
    # Long replies that merely mention these phrases in passing ("no other
    # errors to analyze") are still real analyses, so only short ones qualify.
    return len(stripped) < 600 and bool(_NON_ANSWER_PATTERNS.search(stripped))


class LogAnalyzer:
    """Analyze the result lines of a multi-cycle test run."""
    
    def __init__(self, input_logpath: str, ai_url: Optional[str] = None, 
                max_workers: int = 1, timeout: int = 300, model: Optional[str] = None,
                debug: bool = False, suite_glob: Optional[str] = None):
        """
        Initialize the log analyzer.
        
        Args:
            input_logpath: Root path containing test cycle folders
            ai_url: Base URL of an OpenAI-compatible HTTP LLM endpoint. Passing
                one opts into the HTTP backend; otherwise the endpoint from
                common/llm_config.json (or LOG_ANALYZER_AI_URL) is used.
            max_workers: Number of concurrent workers for LLM calls (default: 1)
            timeout: Timeout in seconds for LLM API calls
            model: Model name for the HTTP endpoint (defaults to the configured
                model; "default" auto-detects it from /v1/models)
            debug: If True, log prompts and responses sent to / from LLM (truncated)
            suite_glob: Glob for an optional test suite driver script in the run
                root (defaults to SUITE_SCRIPT_GLOB)
        """
        self.input_logpath = Path(input_logpath)
        self.ai_api_base = (ai_url or ai_backend.http_api_base()).rstrip("/")
        self.ai_api_url = f"{self.ai_api_base}/v1/chat/completions"
        # CLI-first: the HTTP endpoint is used only when the operator explicitly
        # opted in (passed a URL, set LOG_ANALYZER_AI_URL or ai_backend "http").
        self._http_explicit = bool(ai_url) or ai_backend.http_opted_in()
        self.max_workers = max_workers
        self.timeout = timeout
        self.debug = debug
        self.llm_backend = "http"
        self.cli_backend = None
        self.llm_unavailable_reason = None
        self._backend_lock = threading.Lock()
        self.suite_glob = suite_glob or SUITE_SCRIPT_GLOB
        # False skips backend selection entirely (main() sets it for --no_llm).
        self.ai_enabled = True
        
        self.model = model or ai_backend.http_model()
        
        # Try to auto-detect model if using default
        if self.model == "default":
            detected_model = self._detect_available_model()
            if detected_model:
                self.model = detected_model
                logger.info(f"Auto-detected model: {self.model}")
        
        # Result patterns to search for (case-insensitive)
        self.result_patterns = [
            r'\bresult[\'"]?\s*:\s*',
            r'\bRESULT[\'"]?\s*:\s*',
            r'\bResult[\'"]?\s*:\s*',
            # Pipe-separated table formats
            r'\|\s*\*?\s*(?:FINAL\s+)?RESULT\s*\|',  # Matches | FINAL RESULT |, | * RESULT |
            r'\|\s*(?:Pre-test|Post-test|MST)\s+Result\s*\|',  # Matches | Pre-test Result |, etc.
            r'\|\s*\w+\s+Result\s*\|',  # Generic pattern for | XXX Result |
        ]
        
        # Statistics
        self.stats = {
            'total_folders': 0,
            'power_cycle_folders': 0,
            'total_log_files': 0,
            'results_found': 0,
            'files_with_results': 0,    # unique files with at least one result
            'llm_calls': 0,
            'llm_failures': 0,
            'workload_results': 0,      # structured workload verdicts (no LLM needed)
            'ai_skipped': 0,            # results deliberately not sent to the LLM
            'ai_deferred': 0,           # results over the LLM budget
            'ai_forced_fails': 0,       # FAIL/WARNING sent regardless of budget
            'ai_unavailable_skipped': 0, # queue skipped after backend preflight
        }

        # Test suite awareness. When the driver script of the run is copied
        # into the log root it is the ground truth for WHICH workloads actually
        # ran and WHERE each one wrote its output. Without it the analyzer is
        # blind to every workload that does not emit a "Result:" line into a
        # .log file (for example one whose verdict lives in a CSV).
        self.suite_workloads = self._parse_test_suite()

        # Incremental report support (set by main()); lets us flush partial HTML
        # so a timeout still leaves a readable report instead of nothing.
        self.output_path = None
        self._partial_lock = threading.Lock()
        self._all_results_ref = None
        self._last_flush = 0.0

    # ── Test suite parsing ─────────────────────────────────────────────────
    def _parse_test_suite(self) -> List[Dict]:
        """
        Parse the test suite driver script copied into the log root to learn
        which workloads ran and which output directory each one owns.

        The script is located with ``self.suite_glob`` (default
        ``SUITE_SCRIPT_GLOB`` = ``*test_suite*.py``; override with
        ``--suite_glob`` or ``LOG_ANALYZER_SUITE_SCRIPT_GLOB``). Output folders
        are recognised as ``{log_folder}/<Name>`` in command strings, or as
        helper scripts invoked with ``--logpath {log_folder}``.

        Returns a list of {'name': <human description>, 'outdir': <folder name>}.
        """
        workloads = []
        try:
            candidates = sorted(self.input_logpath.glob(self.suite_glob))
        except Exception as e:
            logger.warning(f"Cannot scan for test suite script: {e}")
            return workloads

        if not candidates:
            logger.info("No test suite script (%s) found in log root; "
                        "falling back to generic scanning.", self.suite_glob)
            return workloads

        suite = candidates[0]
        logger.info(f"Test suite script detected: {suite.name}")
        try:
            text = suite.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Cannot read test suite script {suite}: {e}")
            return workloads

        # Output roots are written as {log_folder}\<Name> or {log_folder}/<Name>
        # in the command strings; the trailing quoted string on the same
        # run_test(...) call is the human-readable workload description.
        seen = set()
        for line_no, line in enumerate(text.splitlines()):
            if line.lstrip().startswith("#"):
                continue  # commented-out / disabled workloads must not count
            for m in re.finditer(r'\{log_folder\}[\\/]+([A-Za-z0-9_\-]+)', line):
                outdir = m.group(1)
                if outdir.lower() in seen:
                    continue
                seen.add(outdir.lower())
                workloads.append({'name': outdir, 'outdir': outdir,
                                  'source_line': line_no + 1})

            # Some suites do NOT name their output dir inline; they call a
            # helper (e.g. cmds/bandwidth.py, fio_stress.py) with
            # "--logpath {log_folder}" and let the helper create its own
            # subfolder. Capturing the helper name here is what makes such
            # workloads discoverable at all.
            if '--logpath' in line and '{log_folder}' in line:
                for m in re.finditer(r'([A-Za-z0-9_\-]+)\.py', line):
                    tool = m.group(1)
                    if tool.lower().startswith(COLLECTOR_PREFIXES):
                        continue
                    if tool.lower() in seen:
                        continue
                    seen.add(tool.lower())
                    workloads.append({'name': tool, 'outdir': tool,
                                      'source_line': line_no + 1})
                # Helper referenced through a variable, e.g. {fio_stress}
                for m in re.finditer(r'\{([A-Za-z0-9_]+)\}\s+--logpath', line):
                    tool = m.group(1)
                    if tool.lower() in seen or tool == 'log_folder':
                        continue
                    seen.add(tool.lower())
                    workloads.append({'name': tool, 'outdir': tool,
                                      'source_line': line_no + 1})

        if workloads:
            logger.info("Suite workload output dirs: %s",
                        ", ".join(w['outdir'] for w in workloads))
        return workloads


    def get_folder_creation_time(self, folder_path: Path) -> float:
        """Get folder creation/modification time"""
        try:
            return folder_path.stat().st_mtime
        except Exception as e:
            logger.warning(f"Cannot get time for {folder_path}: {e}")
            return 0.0
    

    def _detect_available_model(self) -> Optional[str]:
        """
        Try to auto-detect an available model from the API.
        
        Returns:
            Model name if detected, None otherwise
        """
        try:
            # Try to get models list from /v1/models endpoint
            models_url = f"{self.ai_api_base}/v1/models"
            response = requests.get(models_url, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                
                # Handle different response formats
                if 'data' in result and len(result['data']) > 0:
                    # OpenAI-style response
                    model_id = result['data'][0].get('id')
                    if model_id:
                        logger.info(f"Detected model from API: {model_id}")
                        return model_id
                elif 'models' in result and len(result['models']) > 0:
                    # Alternative format
                    model_id = result['models'][0]
                    if isinstance(model_id, dict):
                        model_id = model_id.get('id') or model_id.get('name')
                    if model_id:
                        logger.info(f"Detected model from API: {model_id}")
                        return model_id
            
            logger.warning("Could not auto-detect model from API; keeping '%s'", self.model)
            return None
            
        except Exception as e:
            logger.debug(f"Model auto-detection failed: {e}")
            return None


    def find_power_cycle_folders(self) -> List[Tuple[Path, int]]:
        """
        Find cycle folders and extract their cycle numbers.

        Recognises "<hostname>_<TAG>_c<N>-..." (any tag) and "Cycle_<N>" plus
        Pretest/Posttest phase folders; see CYCLE_FOLDER_RE.
        
        Returns:
            List of (folder_path, cycle_number) tuples, sorted by cycle number
        """
        if not self.input_logpath.exists():
            logger.error(f"Input path does not exist: {self.input_logpath}")
            return []
        
        # Check if the input path itself is a power cycle folder
        folder_name = self.input_logpath.name
        cycle_num = cycle_number_from_name(folder_name)
        if cycle_num is not None:
            logger.info(f"Input path is a power cycle folder: {folder_name}")
            logger.info(f"Analyzing single power cycle folder ({cycle_label(cycle_num)})")
            return [(self.input_logpath, cycle_num)]
        
        # Otherwise, treat as parent folder containing multiple cycle folders
        all_folders = []
        
        # Get all subdirectories
        for item in self.input_logpath.iterdir():
            if item.is_dir():
                all_folders.append(item)
        
        if not all_folders:
            logger.warning(f"No subdirectories found in {self.input_logpath}")
            return []
        
        self.stats['total_folders'] = len(all_folders)
        
        # Sort by creation time and exclude the earliest one (only in multi-folder mode)
        all_folders.sort(key=self.get_folder_creation_time)
        
        if len(all_folders) > 1:
            excluded_folder = all_folders[0]
            logger.info(f"Excluding earliest folder: {excluded_folder.name}")
            folders_to_analyze = all_folders[1:]
        else:
            logger.warning("Only one folder found, analyzing it anyway")
            folders_to_analyze = all_folders
        
        # Filter for power cycle folders and extract cycle numbers
        power_cycle_folders = []
        
        for folder in folders_to_analyze:
            folder_name = folder.name
            
            # "<hostname>_<TAG>_c<N>-..." for any tag, or "Cycle_<N>" /
            # Pretest / Posttest.
            cycle_num = cycle_number_from_name(folder_name)
            if cycle_num is not None:
                power_cycle_folders.append((folder, cycle_num))
                logger.info(f"Found power cycle folder: {folder_name} ({cycle_label(cycle_num)})")

        # Some layouts nest cycles under per-unit folders
        # (<root>/<group>/<unit>/Cycle_7), so a flat scan of the root finds
        # nothing. Recurse rather than reporting an empty run.
        if not power_cycle_folders:
            logger.info("No cycle folders at top level - searching nested "
                        "unit folders")
            for sub in sorted(self.input_logpath.rglob("*")):
                if not sub.is_dir():
                    continue
                cycle_num = cycle_number_from_name(sub.name)
                if cycle_num is not None:
                    power_cycle_folders.append((sub, cycle_num))
            if power_cycle_folders:
                logger.info(f"Found {len(power_cycle_folders)} nested cycle "
                            f"folder(s)")
        
        self.stats['power_cycle_folders'] = len(power_cycle_folders)
        
        # Sort by cycle number, then path so units stay grouped
        power_cycle_folders.sort(key=lambda x: (x[1], str(x[0])))
        
        return power_cycle_folders
    
    def find_log_files(self, folder: Path) -> List[Path]:
        """
        Recursively find all .log files in a folder and its subfolders.
        
        Args:
            folder: Root folder to search
            
        Returns:
            List of log file paths
        """
        log_files = []
        try:
            log_files = list(folder.rglob("*.log"))
        except Exception as e:
            logger.error(f"Error searching for log files in {folder}: {e}")
        
        return log_files

    # ── Structured workload results (no LLM required) ──────────────────────
    # Some workloads never write a "Result:" line into a .log file - they emit
    # a machine-readable verdict file instead (for example a storage benchmark
    # wrapper writing spec_verdict.csv with a per-drive Verdict column). These
    # are authoritative pass/fail signals and must never be missed, so we parse
    # them directly rather than hoping an LLM stumbles across them.
    # Maps file name -> name of the verdict column.
    WORKLOAD_VERDICT_FILES = {
        'spec_verdict.csv': 'Verdict',
        'results_verdict.csv': 'Verdict',
        'task_verdict.csv': 'Verdict',
    }

    def find_workload_result_files(self, folder: Path) -> List[Path]:
        """Find structured workload verdict files (csv) under a cycle folder."""
        found = []
        try:
            for name in self.WORKLOAD_VERDICT_FILES:
                found.extend(folder.rglob(name))
        except Exception as e:
            logger.error(f"Error searching workload result files in {folder}: {e}")
        return found

    def parse_workload_verdict(self, csv_path: Path) -> List[Dict]:
        """
        Parse a structured verdict CSV into result_info dicts with a
        deterministic status - no LLM call needed.
        """
        results = []
        verdict_col = self.WORKLOAD_VERDICT_FILES.get(csv_path.name.lower(), 'Verdict')
        try:
            with open(csv_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as f:
                rows = list(csv.DictReader(f))
        except Exception as e:
            logger.warning(f"Cannot parse verdict file {csv_path}: {e}")
            return results

        if not rows:
            return results

        # Match the verdict column case-insensitively.
        col = None
        for k in rows[0].keys():
            if k and k.strip().lower() == verdict_col.lower():
                col = k
                break
        if col is None:
            return results

        for idx, row in enumerate(rows, start=2):  # header is line 1
            verdict = (row.get(col) or '').strip().upper()
            if not verdict:
                continue
            if verdict in ('FAIL', 'FAILED'):
                status = 'FAIL'
            elif verdict in ('PASS', 'PASSED', 'OK'):
                status = 'PASS'
            elif verdict in ('WARN', 'WARNING', 'MARGINAL'):
                status = 'WARNING'
            else:
                status = 'UNKNOWN'

            # Compact, human-readable one-liner of the whole row.
            detail = ", ".join(f"{k}={v}" for k, v in row.items()
                               if v not in (None, '') and k)
            results.append({
                'verdict_status': status,
                'line_content': f"[{csv_path.name}] {detail}",
                'line_number': idx,
            })
        return results

    

    def extract_result_lines(self, log_file: Path) -> List[Tuple[str, List[int]]]:
        """
        Extract UNIQUE result content from a log file, tracking all line numbers.
        Handles large files intelligently.
        
        Args:
            log_file: Path to log file
            
        Returns:
            List of (unique_content, [line_numbers]) tuples
        """
        # Dictionary to track unique content and their line numbers
        unique_results = {}
        
        # Check file size
        try:
            file_size_mb = log_file.stat().st_size / (1024 * 1024)
        except Exception as e:
            logger.warning(f"Cannot stat {log_file}: {e}")
            return []
        
        filename_lower = log_file.name.lower()
        
        # Rule 1: Skip known diagnostic dumps entirely (no test results in these)
        if any(pattern in filename_lower for pattern in DUMP_FILE_SKIP_TOKENS):
            if file_size_mb > 10:  # Only log if it's actually large
                logger.debug(f"Skipping diagnostic dump: {log_file.name} ({file_size_mb:.1f}MB)")
            return []
        
        # Rule 2: Size thresholds
        MAX_FULL_SCAN_MB = 50
        TAIL_LINES = 10000  # ~500KB-1MB of text typically
        
        use_tail_only = False
        if file_size_mb > MAX_FULL_SCAN_MB:
            # For output.log and similar, use tail sampling
            if 'output' in filename_lower or 'result' in filename_lower or 'summary' in filename_lower:
                use_tail_only = True
                logger.info(f"  Large file ({file_size_mb:.1f}MB), tail-sampling last {TAIL_LINES} lines: {log_file.name}")
            else:
                logger.warning(f"  Skipping large file ({file_size_mb:.1f}MB): {log_file.name}")
                return []
        
        try:
            if use_tail_only:
                # Efficient tail reading for large files
                lines_to_scan = self._read_tail(log_file, TAIL_LINES)
                
                for rel_line_num, line in enumerate(lines_to_scan, 1):
                    for pattern in self.result_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            content = line.strip()
                            # A column header is a table layout, not a result.
                            if is_result_header_line(content):
                                break
                            normalized_content = re.sub(r'\s+', ' ', content)
                            
                            if normalized_content not in unique_results:
                                unique_results[normalized_content] = {
                                    'original': content,
                                    'line_numbers': []
                                }
                            # Mark as "tail" line number (negative indicates from-end)
                            unique_results[normalized_content]['line_numbers'].append(-rel_line_num)
                            break
            else:
                # Full scan for normal-sized files
                with _open_text(log_file) as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in self.result_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                content = line.strip()
                                # A column header is a table layout, not a result.
                                if is_result_header_line(content):
                                    break
                                normalized_content = re.sub(r'\s+', ' ', content)
                                
                                if normalized_content not in unique_results:
                                    unique_results[normalized_content] = {
                                        'original': content,
                                        'line_numbers': []
                                    }
                                unique_results[normalized_content]['line_numbers'].append(line_num)
                                break
        
        except Exception as e:
            logger.error(f"Error reading {log_file}: {e}")
        
        # Convert to list format
        result_list = []
        for normalized, data in unique_results.items():
            result_list.append((data['original'], data['line_numbers']))
        
        # Sort by first line number occurrence (handle negative = tail lines)
        result_list.sort(key=lambda x: abs(x[1][0]) if x[1] else 0)
        
        return result_list


    def _read_tail(self, file_path: Path, num_lines: int) -> List[str]:
        """
        Efficiently read last N lines of a large file.
        Uses seek from end to avoid reading entire file.
        
        Args:
            file_path: Path to file
            num_lines: Number of lines to read from end
            
        Returns:
            List of lines (may be fewer if file is smaller)
        """
        # Estimate ~200 bytes per line, read 2x buffer for safety
        buffer_size = num_lines * 400
        
        try:
            file_size = file_path.stat().st_size
            
            with open(file_path, 'rb') as f:
                # If file is smaller than buffer, just read all
                if file_size <= buffer_size:
                    f.seek(0)
                    content = f.read().decode('utf-8', errors='ignore')
                    return content.splitlines()
                
                # Seek to near end and read
                f.seek(max(0, file_size - buffer_size))
                
                # Skip partial first line (we may have landed mid-line)
                f.readline()
                
                content = f.read().decode('utf-8', errors='ignore')
                lines = content.splitlines()
                
                # Return last num_lines
                return lines[-num_lines:] if len(lines) > num_lines else lines
                
        except Exception as e:
            logger.error(f"Error reading tail of {file_path}: {e}")
            return []

    def sanitize_text_for_ai(self, text: str) -> str:
        """
        Sanitize text before sending to AI by removing passwords and sensitive data.
        
        Args:
            text: Raw text content
            
        Returns:
            Sanitized text
        """
        # Patterns to redact
        patterns = [
            (r'password[\'"]?\s*[:=]\s*[\'"]?[\w!@#$%^&*()]+[\'"]?', 'password: [REDACTED]'),
            (r'token[\'"]?\s*[:=]\s*[\'"]?[\w-]+[\'"]?', 'token: [REDACTED]'),
            (r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?[\w-]+[\'"]?', 'api_key: [REDACTED]'),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_ADDRESS]'),  # IP addresses
            (r'user(?:name)?[\'"]?\s*[:=]\s*[\'"]?[\w]+[\'"]?', 'username: [REDACTED]'),
        ]
        
        sanitized = text
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def _activate_cli_fallback(self, reason: str) -> bool:
        """Switch this analysis run to the AI CLI backend (default, or after the
        HTTP LLM endpoint fails)."""
        with self._backend_lock:
            if self.llm_backend == "cli":
                return True
            if self.llm_backend == "unavailable":
                return False

            label = ai_backend.cli_backend_label()
            try:
                # These prompts are self-contained classifications ("reply with
                # one word", "list what failed") that never need a tool, so MCP
                # servers would be pure per-call cold-start cost. Deep analysis
                # is a separate pass.
                per_item_model = os.getenv("LOG_ANALYZER_RESULT_ANALYZER_MODEL",
                                           "auto")
                backend = ai_backend.create_cli_backend(model=per_item_model,
                                                        disable_mcp=True)
                if backend is None:
                    raise RuntimeError("AI CLI backend is disabled or not installed")
                if os.getenv("LOG_ANALYZER_AI_PREFLIGHT", "1") != "0":
                    preflight_timeout = int(
                        os.getenv("LOG_ANALYZER_AI_PREFLIGHT_TIMEOUT", "90")
                    )
                    backend.preflight(timeout=preflight_timeout)
                self.cli_backend = backend
                self.llm_backend = "cli"
                self.llm_unavailable_reason = None
                logger.info("Using %s backend (%s)", label, reason)
                return True
            except Exception as exc:
                self.llm_backend = "unavailable"
                self.llm_unavailable_reason = str(exc)
                logger.error("AI CLI backend unavailable (%s): %s", reason, exc)
                return False

    def _prepare_llm_backend(self) -> None:
        """Pick the LLM backend. CLI-FIRST: use the configured AI CLI by default
        and only use the HTTP LLM endpoint when the operator explicitly opted in
        (--ai_url / LOG_ANALYZER_AI_URL / ai_backend "http" in llm_config.json).
        This avoids waiting out an HTTP timeout on an unreachable endpoint."""
        if not self._http_explicit:
            if self._activate_cli_fallback("CLI-first (default)"):
                return
            logger.warning("AI CLI backend is unavailable; probing the HTTP "
                           "LLM endpoint instead.")
            self.llm_backend = "http"
        # Operator opted into the HTTP endpoint (or the CLI is missing): probe it
        # once so a down server does not delay every result.
        parsed = urlparse(self.ai_api_base)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with socket.create_connection((host, port), timeout=5):
                pass
            logger.info("HTTP LLM endpoint is reachable at %s:%s", host, port)
        except OSError as exc:
            if self._http_explicit:
                self._activate_cli_fallback(f"{host}:{port}: {exc}")
            else:
                self.llm_backend = "unavailable"
                self.llm_unavailable_reason = (
                    f"{self.llm_unavailable_reason or 'AI CLI unavailable'}; "
                    f"HTTP LLM endpoint {host}:{port} unreachable: {exc}")
                logger.error("No AI backend available: %s", self.llm_unavailable_reason)

    def _call_ai_cli(self, system_message: str, instruction: str,
                     content: str, analysis_type: str) -> str:
        if self.llm_backend != "cli" or self.cli_backend is None:
            return "UNKNOWN" if analysis_type == "status" else "LLM unavailable"

        label = ai_backend.cli_backend_label()
        run_kwargs = {
            "timeout": self.timeout,
            "on_status": lambda message: logger.info("[%s] %s", label, str(message)[:160]),
        }
        inline_prompt = f"{system_message}\n\n{instruction}\n\n{content}"
        # CLI backends may take the prompt as an argv entry, so a big log can
        # exceed the Windows command-line limit. Past that size the log is
        # staged as a file -- but the INSTRUCTION must stay in the prompt,
        # otherwise the model just answers "ready, what should I analyze?"
        # instead of opening the file.
        use_file = len(inline_prompt) > 6000

        def _ask(extra_pressure: str = "") -> str:
            if use_file:
                prompt = (f"{system_message}\n\n{instruction}\n\n"
                          "The log text to analyze is in session_log.txt in your "
                          "current directory. Read that file first, then answer. "
                          "Do not ask for more data and do not describe your "
                          "capabilities." + extra_pressure)
                return (self.cli_backend.run(
                    prompt, sanitized_log_text=content, **run_kwargs) or "").strip()
            return (self.cli_backend.run(
                inline_prompt + extra_pressure, **run_kwargs) or "").strip()

        try:
            text = _ask()
            if _is_non_answer(text):
                logger.warning("AI CLI returned a non-answer (%s); retrying once: %.120s",
                               analysis_type, text.replace("\n", " "))
                text = _ask("\n\nIMPORTANT: your previous reply did not answer. "
                            "Answer now using only the log text provided.")
                if _is_non_answer(text):
                    self.stats['llm_failures'] += 1
                    logger.error("AI CLI still returned a non-answer (%s); giving up.",
                                 analysis_type)
                    return "UNKNOWN" if analysis_type == "status" else \
                        "LLM returned no usable analysis (non-answer after retry)"
                logger.warning("AI CLI returned a non-answer (%s); retrying once: %.120s",
                               analysis_type, text.replace("\n", " "))
                text = _ask("\n\nIMPORTANT: your previous reply did not answer. "
                            "Answer now using only the log text provided.")
                if _is_non_answer(text):
                    self.stats['llm_failures'] += 1
                    logger.error("AI CLI still returned a non-answer (%s); giving up.",
                                 analysis_type)
                    return "UNKNOWN" if analysis_type == "status" else \
                        "LLM returned no usable analysis (non-answer after retry)"
            if analysis_type == "status":
                upper = text.upper()
                for status in ("FAIL", "PASS", "WARNING", "UNKNOWN"):
                    if status in upper:
                        return status
                return "UNKNOWN"
            return text or f"No response from {label}"
        except Exception as exc:
            # A non-zero exit is usually transient (rate limit, a cold CLI
            # session). Retry once with a short backoff before giving up, and
            # keep the diagnosable message the backend produces.
            if "exited with code" in str(exc):
                logger.warning("AI CLI failed (%s); retrying once in 5s: %.200s",
                               analysis_type, str(exc))
                time.sleep(5)
                try:
                    text = _ask()
                    if text and not _is_non_answer(text):
                        if analysis_type == "status":
                            upper = text.upper()
                            for status in ("FAIL", "PASS", "WARNING", "UNKNOWN"):
                                if status in upper:
                                    return status
                            return "UNKNOWN"
                        return text
                except Exception as exc2:
                    exc = exc2
            logger.error("AI CLI analysis failed: %s", exc)
            self.stats['llm_failures'] += 1
            return "UNKNOWN" if analysis_type == "status" else f"{label} error: {exc}"
    

    def call_llm_api(self, content: str, context: str = "", analysis_type: str = "full") -> str:
        """
        Call the LLM API to analyze test results using ChatCompletion format.
        
        Args:
            content: Test result content to analyze
            context: Additional context (file path, test name, etc.)
            analysis_type: "status" for PASS/FAIL/UNKNOWN, "findings" for key findings
            
        Returns:
            LLM analysis response
        """
        self.stats['llm_calls'] += 1

        # Sanitize content
        sanitized_content = self.sanitize_text_for_ai(content)

        # The instruction is kept separate from the log text so the CLI path
        # can stage a big log as a file while still sending a real task.
        if analysis_type == "status":
            system_message = "You are a system-test result analyzer."
            instruction = """Analyze this test result and determine its status.

    Look for these EXACT patterns (case-insensitive):
    - "Result: PASS", "Test Result: PASS", "Final Result: PASS", "result=PASS", "PASSED" = PASS
    - "Result: FAIL", "Test Result: FAIL", "Final Result: FAIL", "result=FAIL", "FAILED" = FAIL  
    - "Result: WARNING", "WARN", "Warning" = WARNING
    - "Result: ERROR", "ERROR" (but not "0 errors") = FAIL
    - "test passed", "all tests passed", "success", "succeeded" = PASS
    - "test failed", "failure", "unsuccessful" = FAIL

    Return ONLY ONE WORD: either PASS, FAIL, WARNING, or UNKNOWN

    IMPORTANT: Do NOT explain your reasoning. Return ONLY the status word."""
            payload = f"Test Result:\n{sanitized_content}"
        else:  # analysis_type == "findings"
            system_message = "You are a system-test result analyzer."
            instruction = f"""Context: {context}

    Provide ONLY the direct findings:
    - List the specific tests or components that failed
    - Include brief reason if visible"""
            payload = f"Test Result Content:\n{sanitized_content}"

        user_message = f"{instruction}\n\n{payload}"

        if self.llm_backend == "cli":
            return self._call_ai_cli(system_message, instruction, payload, analysis_type)
        if self.llm_backend == "unavailable":
            return "UNKNOWN" if analysis_type == "status" else "LLM unavailable"

        try:
            # Optional debug log for what we're about to send
            if self.debug:
                truncated_msg = user_message[:10000]
                logger.debug(
                    "[LLM DEBUG] analysis_type=%s context=%s\n"
                    "User message (truncated %d/%d chars):\n%s",
                    analysis_type,
                    context,
                    len(truncated_msg),
                    len(user_message),
                    truncated_msg
                )

            # Test connectivity first
            parsed = urlparse(self.ai_api_base)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            with socket.create_connection((host, port), timeout=5):
                pass

            # OpenAI-compatible chat/completions request
            request_body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                "max_tokens": 100 if analysis_type == "status" else 1500,
                "temperature": 0.0,  # Zero temperature for deterministic results
            }

            headers = {
                "Content-Type": "application/json"
            }

            response = requests.post(
                self.ai_api_url,
                json=request_body,
                headers=headers,
                timeout=self.timeout
            )

            if self.debug:
                raw_body = response.text
                logger.debug(
                    "[LLM DEBUG] HTTP %s from %s\nResponse body (truncated %d/%d chars):\n%s",
                    response.status_code,
                    self.ai_api_url,
                    min(len(raw_body), 2000),
                    len(raw_body),
                    raw_body[:2000]
                )

            if response.status_code != 200:
                logger.error(f"LLM API error: {response.status_code}")
                if self.debug:
                    logger.debug("[LLM DEBUG] Non-200 response body: %s", response.text[:2000])
                if self._activate_cli_fallback(f"HTTP {response.status_code}"):
                    return self._call_ai_cli(system_message, instruction, payload, analysis_type)
                self.stats['llm_failures'] += 1
                return "UNKNOWN" if analysis_type == "status" else "API Error"

            # Parse the chat/completions response
            result = response.json()
            if 'choices' in result and len(result['choices']) > 0:
                choice = result['choices'][0]
                if 'message' in choice and 'content' in choice['message']:
                    raw_text = choice['message']['content'] or ''
                else:
                    raw_text = ''
            else:
                raw_text = ''

            raw_text = raw_text.strip()

            if self.debug:
                logger.debug("[LLM DEBUG] Parsed text before cleaning: %r", raw_text)

            # Clean the response
            text = raw_text
            
            # Strip any remaining role markers (shouldn't exist in chat format, but just in case)
            for prefix in ("assistant:", "assistant ::", "ASSISTANT:", "Assistant:"):
                if text.startswith(prefix):
                    text = text[len(prefix):].lstrip()

            # Post-process depending on analysis_type
            if analysis_type == "status":
                upper = text.upper()
                status = "UNKNOWN"

                # Prefer explicit status words anywhere in the string
                if "FAIL" in upper:
                    status = "FAIL"
                elif "PASS" in upper:
                    status = "PASS"
                elif "WARNING" in upper or "WARN" in upper:
                    status = "WARNING"
                elif "UNKNOWN" in upper:
                    status = "UNKNOWN"

                text = status
            else:
                # For findings, if there is a bullet list inside the text, keep from first bullet down
                lines = text.splitlines()
                for i, line in enumerate(lines):
                    if line.strip().startswith(('-', '*')):
                        text = "\n".join(lines[i:])
                        break

            if self.debug:
                logger.debug("[LLM DEBUG] Final returned text after cleaning: %r", text)

            # In case model returns empty string
            if not text:
                return "UNKNOWN" if analysis_type == "status" else "No response from LLM"

            return text

        except socket.timeout:
            logger.error(f"Connection timeout to {host}:{port}")
            if self._activate_cli_fallback(f"connection timeout to {host}:{port}"):
                return self._call_ai_cli(system_message, instruction, payload, analysis_type)
            self.stats['llm_failures'] += 1
            return "UNKNOWN" if analysis_type == "status" else "Connection timeout"
        except Exception as e:
            logger.error(f"Error calling LLM API: {e}")
            if self._activate_cli_fallback(str(e)):
                return self._call_ai_cli(system_message, instruction, payload, analysis_type)
            self.stats['llm_failures'] += 1
            return "UNKNOWN" if analysis_type == "status" else f"Error: {str(e)}"

    def analyze_single_result_optimized(self, result_info: Dict) -> Dict:
        """
        Analyze a single deduplicated result with LLM in two stages.
        Uses all line numbers for context but makes fewer LLM calls.
        
        Args:
            result_info: Dictionary with result information
            
        Returns:
            Updated dictionary with LLM analysis
        """
        log_file = result_info['log_file']
        line_content = result_info['line_content']
        line_numbers = result_info.get('all_line_numbers', [result_info['line_number']])
        
        # Deterministic verdict first. The workload already stated its result;
        # the LLM is only allowed to escalate it, never to erase it.
        quick_status = classify_result_line(line_content)
        if quick_status == 'UNKNOWN':
            quick_status = None
        
        # Create context string
        context = f"File: {Path(log_file).name}, Lines: {result_info['line_display']}"
        
        # Read log file once
        lines = None
        try:
            with _open_text(log_file) as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Failed to read log file {log_file}: {e}")
        
        if lines is not None:
            # Build context from ALL occurrences
            context_lines = []
            for line_num in line_numbers[:3]:  # Use up to 3 occurrences for context
                start_idx = max(0, line_num - 4)
                end_idx = min(len(lines), line_num + 3)
                context_lines.extend(lines[start_idx:end_idx])
            
            status_context_lines = ''.join(context_lines[:50])  # Cap at 50 lines
        else:
            status_context_lines = line_content
        
        # Ask LLM for status (first call)
        llm_status = self.call_llm_api(
            status_context_lines,
            context,
            analysis_type="status"
        )
        
        # Normalize and validate LLM status
        llm_status = (llm_status or "").strip().upper()
        if llm_status not in ['PASS', 'FAIL', 'WARNING', 'UNKNOWN']:
            llm_status = 'UNKNOWN'
        
        # Merge statuses (prioritize safety: FAIL > WARNING > PASS > UNKNOWN)
        candidates = [c for c in [llm_status, quick_status] if c]
        
        if 'FAIL' in candidates:
            final_status = 'FAIL'
        elif 'WARNING' in candidates:
            final_status = 'WARNING'
        elif 'PASS' in candidates:
            final_status = 'PASS'
        else:
            final_status = 'UNKNOWN'
        
        result_info['status'] = final_status
        
        # If PASS, skip findings analysis
        if final_status == 'PASS':
            result_info['llm_analysis'] = None
            return result_info
        
        # Build extended findings context for non-PASS results
        if lines is not None:
            # Collect context around ALL occurrences
            all_contexts = []
            for line_num in line_numbers[:5]:  # Use up to 5 occurrences
                local_start = max(0, line_num - 6)
                local_end = min(len(lines), line_num + 5)
                all_contexts.append(''.join(lines[local_start:local_end]))
            
            local_context = '\n---\n'.join(all_contexts)
            
            # Collect error/fail lines
            error_lines = []
            for idx, line in enumerate(lines):
                ll = line.lower()
                if 'error' in ll or 'fail' in ll:
                    error_lines.append(f"[L{idx + 1}] {line.rstrip()}")
            
            # Cap size
            if len(error_lines) > 50:
                error_lines = error_lines[:25] + ["... (truncated) ..."] + error_lines[-25:]
            
            error_section = "\n".join(error_lines) if error_lines else "None found."
            
            findings_context = (
                f"Context from {len(line_numbers)} occurrence(s) of this result:\n"
                f"{local_context}\n\n"
                "Error/fail lines in log:\n"
                f"{error_section}"
            )
        else:
            findings_context = line_content
        
        # Second LLM call: findings
        llm_analysis = self.call_llm_api(
            findings_context,
            context,
            analysis_type="findings"
        )
        
        result_info['llm_analysis'] = llm_analysis or None
        return result_info

    def analyze_folder(self, folder: Path, cycle_num: int) -> Dict:
        """
        Analyze a single power cycle folder with deduplication.
        
        Args:
            folder: Folder path
            cycle_num: Cycle number
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing folder: {folder.name} ({cycle_label(cycle_num)})")
        
        folder_results = {
            'folder_name': folder.name,
            'cycle_number': cycle_num,
            'subfolders': {},
            'results': []
        }
        
        # Find all log files
        log_files = self.find_log_files(folder)
        self.stats['total_log_files'] += len(log_files)
        
        logger.info(f"Found {len(log_files)} log files in {folder.name}")
        
        # Process each log file with progress tracking
        processed = 0
        
        for log_file in log_files:
            processed += 1
            
            # Progress logging every 50 files or at milestones
            if processed % 50 == 0 or processed == len(log_files):
                logger.info(f"  Processing file {processed}/{len(log_files)} in {cycle_label(cycle_num)}")
            
            # Determine subfolder relative to main folder
            relative_path = log_file.relative_to(folder)
            subfolder = str(relative_path.parent) if relative_path.parent != Path('.') else 'root'
            
            # SKIP files in root folder entirely
            if subfolder == 'root':
                logger.debug(f"Skipping root file: {log_file.name}")
                continue
            
            # Extract UNIQUE result lines (handles large files internally with tail sampling)
            start_time = time.time()
            unique_results = self.extract_result_lines(log_file)
            elapsed = time.time() - start_time
            
            # Warn about slow files
            if elapsed > 5.0:
                file_size_mb = log_file.stat().st_size / (1024 * 1024)
                logger.warning(f"  Slow file ({elapsed:.1f}s): {log_file.name} ({file_size_mb:.1f}MB)")
            
            if unique_results:
                self.stats['files_with_results'] += 1
                self.stats['results_found'] += len(unique_results)
                
                # Process each unique result content
                for result_content, line_numbers in unique_results:
                    # Format line numbers for display
                    if len(line_numbers) == 1:
                        line_display = str(line_numbers[0])
                    else:
                        line_display = f"{line_numbers[0]} (+{len(line_numbers)-1} more)"
                    
                    result_info = {
                        'log_file': str(log_file),
                        'relative_path': str(relative_path),
                        'subfolder': subfolder,
                        'line_content': result_content,
                        'line_number': line_numbers[0],  # Use first occurrence for sorting
                        'line_display': line_display,     # Display string showing all occurrences
                        'all_line_numbers': line_numbers, # Keep all line numbers for analysis
                        # Verdict read straight from the line. Present whether
                        # or not an LLM ever runs, so --no_llm still yields a
                        # real PASS/FAIL instead of a wall of UNKNOWN.
                        'deterministic_status': classify_result_line(result_content),
                        'status': None,
                        'llm_analysis': None
                    }
                    
                    folder_results['results'].append(result_info)
                    
                    # Track subfolders
                    if subfolder not in folder_results['subfolders']:
                        folder_results['subfolders'][subfolder] = 0
                    folder_results['subfolders'][subfolder] += 1
        
        # ── Structured workload verdicts ───────────────────────────────────
        # Parse machine-readable verdict files (e.g. spec_verdict.csv) next to
        # the generic .log scan. These carry authoritative pass/fail data that
        # the "Result:" regex over .log files can never see.
        for vfile in self.find_workload_result_files(folder):
            try:
                rel = vfile.relative_to(folder)
            except ValueError:
                continue
            sub = str(rel.parent) if rel.parent != Path('.') else 'root'
            workload = rel.parts[0] if len(rel.parts) > 1 else vfile.stem
            for parsed in self.parse_workload_verdict(vfile):
                self.stats['results_found'] += 1
                self.stats['workload_results'] += 1
                folder_results['results'].append({
                    'log_file': str(vfile),
                    'relative_path': str(rel),
                    'subfolder': sub,
                    'workload': workload,
                    'line_content': parsed['line_content'],
                    'line_number': parsed['line_number'],
                    'line_display': str(parsed['line_number']),
                    'all_line_numbers': [parsed['line_number']],
                    # Deterministic status straight from the tool's own verdict.
                    'status': parsed['verdict_status'],
                    'deterministic_status': parsed['verdict_status'],
                    'structured': True,
                    'llm_analysis': None,
                })
                folder_results['subfolders'][sub] = folder_results['subfolders'].get(sub, 0) + 1

        # ── Workload coverage guarantee ────────────────────────────────────
        self._ensure_workload_coverage(folder, folder_results)

        # Summary logging
        logger.info(f"  {cycle_label(cycle_num)} complete: {len(folder_results['results'])} results found")
        
        return folder_results

    # Cycle-level folders that are infrastructure, not test workloads. Folders
    # starting with one of COLLECTOR_PREFIXES are excluded as well.
    NON_WORKLOAD_DIRS = {'logs', 'cpu_logs', 'pretest_reference'}

    def _ensure_workload_coverage(self, folder: Path, folder_results: Dict) -> None:
        """
        Guarantee that every workload the test suite actually ran produces a
        row in the report.

        The generic scan only surfaces files that contain a "Result:"-style
        line. Workloads that never print one would otherwise be absent from
        the report even though the suite ran them - the reader could not tell
        "passed" from "never analyzed".
        For any workload directory with zero findings we synthesize one entry
        seeded with that workload's most informative output file, so it always
        gets a verdict.
        """
        try:
            subdirs = [d for d in folder.iterdir() if d.is_dir()]
        except Exception as e:
            logger.warning(f"Cannot enumerate workload dirs in {folder}: {e}")
            return

        covered = set()
        for r in folder_results['results']:
            rel = str(r.get('relative_path', '')).replace('\\', '/')
            if '/' in rel:
                covered.add(rel.split('/')[0].lower())

        for sub in subdirs:
            name = sub.name
            low = name.lower()
            if low in self.NON_WORKLOAD_DIRS or low.startswith(COLLECTOR_PREFIXES):
                continue
            if low in covered:
                continue  # already has findings from the generic scan

            evidence = self._pick_workload_evidence(sub)
            if not evidence:
                continue

            ev_path, snippet = evidence
            try:
                rel = ev_path.relative_to(folder)
            except ValueError:
                continue

            self.stats['results_found'] += 1
            folder_results['results'].append({
                'log_file': str(ev_path),
                'relative_path': str(rel),
                'subfolder': name,
                'workload': name,
                'line_content': f"[workload coverage] {name}: {snippet}",
                'line_number': 1,
                'line_display': 'summary',
                'all_line_numbers': [1],
                'status': None,
                'coverage_fill': True,
                'llm_analysis': None,
            })
            folder_results['subfolders'][name] = folder_results['subfolders'].get(name, 0) + 1
            logger.info(f"  Coverage fill for workload '{name}' via {ev_path.name}")

    # Preferred evidence files per workload, most conclusive first.
    _EVIDENCE_PRIORITY = [
        'summary.csv', '_summary.csv', 'verdict.csv', 'results.csv',
        'spec_verdict.csv', '.json', '.log', '.txt',
    ]

    def _pick_workload_evidence(self, wdir: Path) -> Optional[Tuple[Path, str]]:
        """Choose the most conclusive output file in a workload dir."""
        try:
            files = [f for f in wdir.rglob('*') if f.is_file()]
        except Exception:
            return None
        if not files:
            return None

        best = None
        for token in self._EVIDENCE_PRIORITY:
            for f in files:
                if f.name.lower().endswith(token):
                    best = f
                    break
            if best:
                break
        if best is None:
            best = max(files, key=lambda f: f.stat().st_size if f.exists() else 0)

        # A short excerpt keeps the LLM prompt small while still conclusive.
        try:
            if best.stat().st_size > 200_000:
                lines = self._read_tail(best, 40)
            else:
                with open(best, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = fh.readlines()[-40:]
            snippet = ' '.join(l.strip() for l in lines if l.strip())[:600]
        except Exception as e:
            snippet = f"(could not read {best.name}: {e})"
        return best, snippet or f"(empty {best.name})"


    def analyze_all_folders(self) -> List[Dict]:
        """
        Analyze all power cycle folders with optimized deduplication.
        
        Returns:
            List of analysis results for each folder
        """
        power_cycle_folders = self.find_power_cycle_folders()
        
        if not power_cycle_folders:
            logger.warning("No power cycle folders found to analyze")
            return []
        
        all_results = []
        
        # Analyze each folder
        for folder, cycle_num in power_cycle_folders:
            folder_results = self.analyze_folder(folder, cycle_num)
            all_results.append(folder_results)
        
        # Now perform LLM analysis on all results concurrently
        logger.info(f"Starting LLM analysis with {self.max_workers} workers...")
        
        # Collect all results that need LLM analysis
        results_to_analyze = []
        for folder_result in all_results:
            for r in folder_result['results']:
                if self._should_skip_ai(r):
                    self.stats['ai_skipped'] += 1
                    if not r.get('status'):
                        r['status'] = (r.get('deterministic_status')
                                       or classify_result_line(r.get('line_content', '')))
                    if not r.get('llm_analysis'):
                        r['llm_analysis'] = r.get('skip_reason', 'AI analysis skipped.')
                    continue
                results_to_analyze.append(r)

        # ── LLM budget ────────────────────────────────────────────────────
        # A large run cannot be sent to an LLM in full: thousands of results at
        # several seconds per call would take many hours. So the budget caps the
        # run - but it must never cap the failures, which are the reason the
        # report is opened at all. FAIL and WARNING are therefore taken OUT of
        # the budget entirely; the cap applies only to the discretionary
        # remainder, where verdict-less rows rank ahead of deterministic PASSes.
        budget = int(os.getenv("LOG_ANALYZER_RESULT_ANALYZER_AI_BUDGET", "120"))
        must_send = [r for r in results_to_analyze
                     if self._known_verdict(r) in ('FAIL', 'WARNING')]
        optional = [r for r in results_to_analyze
                    if self._known_verdict(r) not in ('FAIL', 'WARNING')]
        self.stats['ai_forced_fails'] = len(must_send)

        # budget=0 means "failures only" - the fastest useful run. It must not
        # read as "unlimited", which is what `if budget > 0` alone did.
        if budget >= 0 and len(optional) > budget:
            rank = {'UNKNOWN': 0, 'PENDING': 0, 'PASS': 2}
            optional.sort(
                key=lambda r: (rank.get(self._known_verdict(r) or 'UNKNOWN', 1),
                               0 if r.get('coverage_fill') else 1))
            deferred = optional[budget:]
            optional = optional[:budget]
            for r in deferred:
                self.stats['ai_deferred'] += 1
                if not r.get('status'):
                    r['status'] = (r.get('deterministic_status')
                                   or classify_result_line(r.get('line_content', '')))
                if not r.get('llm_analysis'):
                    r['llm_analysis'] = (
                        f"Not sent to the LLM: over the {budget}-result AI budget "
                        f"(status shown is the deterministic verdict). Every FAIL and "
                        f"WARNING was sent regardless of budget; raise "
                        f"LOG_ANALYZER_RESULT_ANALYZER_AI_BUDGET to also cover these.")
            logger.info("LLM budget %d: %d FAIL/WARNING sent unconditionally, "
                        "%d of %d discretionary selected, %d deferred",
                        budget, len(must_send), len(optional),
                        len(optional) + len(deferred), len(deferred))
        results_to_analyze = must_send + optional

        logger.info("LLM queue: %d to analyze, %d skipped (structured verdict / "
                    "already covered by dedicated analyzers)",
                    len(results_to_analyze), self.stats['ai_skipped'])
        
        if results_to_analyze:
            if self.ai_enabled:
                self._prepare_llm_backend()
            if self.llm_backend == "unavailable":
                reason = self.llm_unavailable_reason or "backend preflight failed"
                self.stats['ai_unavailable_skipped'] = len(results_to_analyze)
                logger.error(
                    "AI backend preflight failed; skipping all %d queued results: %s",
                    len(results_to_analyze), reason,
                )
                for result in results_to_analyze:
                    if not result.get('status'):
                        result['status'] = (
                            result.get('deterministic_status')
                            or classify_result_line(result.get('line_content', ''))
                        )
                    result['llm_analysis'] = (
                        "AI analysis skipped before queue: AI backend "
                        f"preflight failed. {reason}"
                    )
            else:
                # Use ThreadPoolExecutor for concurrent LLM calls
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_result = {
                        executor.submit(self.analyze_single_result_optimized, result): result
                        for result in results_to_analyze
                    }

                    completed = 0
                    total = len(results_to_analyze)

                    for future in as_completed(future_to_result):
                        completed += 1
                        try:
                            result = future.result()
                            if completed % 10 == 0 or completed == total:
                                logger.info(f"LLM analysis progress: {completed}/{total}")
                        except Exception as e:
                            logger.error(f"Error in LLM analysis: {e}")
                        # Flush a partial report periodically so an outer timeout
                        # still leaves a readable HTML instead of nothing at all.
                        self._maybe_flush_partial(all_results, completed, total)
        
        return all_results

    # ── Incremental report flushing ────────────────────────────────────────
    def _maybe_flush_partial(self, all_results: List[Dict], completed: int,
                             total: int) -> None:
        """
        Write an interim HTML report while LLM analysis is still running.

        result_analyzer used to write its HTML only after every LLM call
        finished, so when the caller's timeout killed the process the
        report never existed at all. Flushing on an interval means a killed run
        still leaves a valid, partially-populated report on disk.
        """
        if not self.output_path:
            return
        interval = float(os.getenv("LOG_ANALYZER_RESULT_ANALYZER_FLUSH_SEC", "60"))
        now = time.time()
        with self._partial_lock:
            if now - self._last_flush < interval and completed != total:
                return
            self._last_flush = now
        try:
            self.generate_html_report(all_results, Path(self.output_path),
                                      partial=(completed < total),
                                      progress=(completed, total))
            logger.info(f"Interim report flushed ({completed}/{total}): {self.output_path}")
        except Exception as e:
            logger.warning(f"Interim report flush failed: {e}")

    # ── AI scope control ───────────────────────────────────────────────────
    # Log-collector dumps and BMC sensor data already have dedicated analyzers
    # in the pipeline (error signatures, sensor digest, cycle_diff).
    # Re-analyzing them here with a per-finding AI call adds hundreds of
    # redundant round-trips while adding no information. Skip them and spend
    # the budget on real workload results.
    AI_SKIP_PATH_PATTERNS = list(COLLECTOR_PREFIXES) + [
        'bmc_collect',
        'sensor_reading',
        'sensor_details',
        'bmc_sdr',
        'sel.log',
    ]

    @staticmethod
    def _known_verdict(result_info: Dict) -> str:
        """The verdict already known without the LLM, whatever built this row.

        Results are constructed in several places and they do not all set the
        same fields: the scan path sets 'deterministic_status', while the
        structured/suite path sets only 'status'. Reading one field alone would
        make the FAIL exemption below miss most failures, so resolve it from
        every deterministic source in turn.
        """
        for key in ('deterministic_status', 'status'):
            val = (result_info.get(key) or '').strip().upper()
            if val and val != 'PENDING':
                return val
        return classify_result_line(result_info.get('line_content', '') or '')

    def _should_skip_ai(self, result_info: Dict) -> bool:
        """Decide whether a finding should bypass the LLM entirely."""
        # A failure is the whole reason anyone opens this report. It must reach
        # the LLM whatever else is true - even a 'structured' verdict, which
        # tells you THAT it failed but never why. Set
        # LOG_ANALYZER_RESULT_ANALYZER_AI_FAILS=0 to opt out.
        if self._known_verdict(result_info) in ('FAIL', 'WARNING'):
            if os.getenv("LOG_ANALYZER_RESULT_ANALYZER_AI_FAILS", "1").strip().lower() \
                    not in ("0", "false", "no"):
                return False

        # Structured verdicts already carry an authoritative status.
        if result_info.get('structured'):
            result_info['skip_reason'] = (
                "Deterministic verdict read directly from the workload's own "
                "result file - no LLM interpretation required."
            )
            return True

        if os.getenv("LOG_ANALYZER_RESULT_ANALYZER_AI_ALL", "0").strip().lower() in ("1", "true", "yes"):
            return False

        # Coverage-fill entries exist precisely because nothing else reported on
        # that workload - they must always reach the LLM or the workload stays
        # verdict-less, which is the bug this whole mechanism fixes.
        if result_info.get('coverage_fill'):
            return False

        # Deterministic verdict already known -> the LLM cannot improve it, and
        # on a large run it is the difference between a feasible run and an
        # impossible one: most results are an explicit "| PASS |" that needs
        # no interpretation, and sending each one would cost seconds to
        # reconfirm what the log already states.
        # Set LOG_ANALYZER_RESULT_ANALYZER_AI_PASS=1 (or _AI_ALL=1) to override.
        if (result_info.get('deterministic_status') == 'PASS'
                and not os.getenv("LOG_ANALYZER_RESULT_ANALYZER_AI_PASS")):
            result_info['skip_reason'] = (
                "PASS was read deterministically from the log's own verdict "
                "field; no LLM interpretation required."
            )
            return True

        probe = (str(result_info.get('relative_path', '')) + ' ' +
                 str(result_info.get('log_file', ''))).lower()
        for pat in self.AI_SKIP_PATH_PATTERNS:
            if pat in probe:
                result_info['skip_reason'] = (
                    f"Skipped AI analysis: '{pat}' content is already covered by the "
                    f"dedicated collector / sensor / error-signature analyzers."
                )
                return True
        return False

    def generate_html_report(self, analysis_results: List[Dict], output_path: Path,
                             partial: bool = False, progress: Optional[Tuple[int, int]] = None):
        """
        Generate an interactive HTML report with improved formatting.
        
        Args:
            analysis_results: List of analysis results
            output_path: Path to save the HTML report
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        # Suite awareness banner: show which workloads the test suite actually
        # ran, so a reader can immediately tell whether a workload is missing
        # from the report because it passed or because it was never analyzed.
        if self.suite_workloads:
            suite_html = ("<p><strong>Suite workloads detected:</strong> "
                          + ", ".join(w['outdir'] for w in self.suite_workloads)
                          + "</p>")
        else:
            suite_html = ""

        # AI provenance banner. A reader must be able to tell WHY a row has the
        # status it has: read from the log deterministically, judged by the LLM,
        # or left unjudged because the run hit its AI budget. Without this the
        # report cannot be distinguished from one where the LLM simply failed.
        s = self.stats
        ai_sent = s.get('llm_calls', 0)
        ai_skipped = s.get('ai_skipped', 0)
        ai_deferred = s.get('ai_deferred', 0)
        ai_failed = s.get('llm_failures', 0)
        ai_unavailable = s.get('ai_unavailable_skipped', 0)
        backend = getattr(self, 'llm_backend', None) or 'none'
        budget = os.getenv("LOG_ANALYZER_RESULT_ANALYZER_AI_BUDGET", "120")
        if ai_unavailable:
            reason = html.escape(
                self.llm_unavailable_reason or "AI backend preflight failed"
            )
            ai_html = (
                "<div style='background:#fdecea;border:1px solid #c62828;"
                "padding:12px;margin:12px 0;border-radius:5px'>"
                "<strong>AI unavailable before analysis:</strong> "
                f"{reason}<br>{ai_unavailable} queued rows were not sent. "
                "Deterministic verdicts remain available; check that the AI "
                "CLI is installed and authenticated for the account running the "
                "analyzer (or configure an HTTP LLM endpoint), then rerun."
                "</div>"
            )
        elif ai_sent or ai_skipped or ai_deferred:
            ai_html = (
                "<p><strong>AI analysis:</strong> "
                f"<span style='color:#0a7'>{ai_sent} sent to LLM</span> "
                f"(backend: {backend}, budget: {budget}) &nbsp;|&nbsp; "
                f"<span style='color:#c00'>{s.get('ai_forced_fails', 0)} FAIL/WARNING "
                f"sent unconditionally (never capped by budget)</span> &nbsp;|&nbsp; "
                f"{ai_skipped} skipped (deterministic verdict / covered by a "
                f"dedicated analyzer) &nbsp;|&nbsp; "
                f"{ai_deferred} deferred (over budget) &nbsp;|&nbsp; "
                f"<span style='color:{'#c00' if ai_failed else '#666'}'>"
                f"{ai_failed} LLM failures</span>"
                "</p>"
                "<p style='font-size:12px;color:#666;margin-top:4px'>"
                "Rows not sent to the LLM still carry a real verdict when the log "
                "stated one; they show UNKNOWN only when no verdict was present. "
                "Raise <code>LOG_ANALYZER_RESULT_ANALYZER_AI_BUDGET</code> to send more."
                "</p>"
            )
        else:
            ai_html = ("<p><strong>AI analysis:</strong> off (enable with "
                       "<code>--ai</code>) &mdash; every status shown was read "
                       "deterministically from the log's own verdict field.</p>")

        if partial:
            done, total = progress if progress else (0, 0)
            partial_banner = (
                '<div style="background:#fff3cd;border:1px solid #ffc107;'
                'border-radius:6px;padding:12px 16px;margin:12px 0;color:#664d03">'
                f'<strong>⏳ PARTIAL REPORT</strong> &mdash; AI analysis still in '
                f'progress ({done}/{total} findings analyzed). This file is '
                f'refreshed periodically; if the run is killed by a timeout, this '
                f'partial content is preserved instead of being lost.</div>'
            )
        else:
            partial_banner = ""
        
        # Generate cycles content first
        cycles_html = ""
        
        for idx, folder_result in enumerate(analysis_results):
            cycle_num = folder_result['cycle_number']
            folder_name = folder_result['folder_name']
            subfolders = folder_result['subfolders']
            results = folder_result['results']
            
            cycle_id = f"cycle_{idx}"
            
            # Subfolder summary (excluding root)
            if subfolders:
                subfolder_summary = ", ".join([f"{sf}: {count} results" for sf, count in subfolders.items()])
            else:
                subfolder_summary = "No subfolders"
            
            # Count status types
            status_counts = {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'UNKNOWN': 0, 'PENDING': 0}
            for result in results:
                status = result.get('status') or 'PENDING'
                if status in status_counts:
                    status_counts[status] += 1
            
            cycles_html += f"""
            <div class="cycle-section">
                <div class="cycle-header" onclick="toggleCycle('{cycle_id}')">
                    <div>
                        <h2>{cycle_label(cycle_num)}: {folder_name}</h2>
                        <div style="font-size: 14px; margin-top: 5px;">
                            {len(results)} results | 
                            <span class="status-pass">PASS: {status_counts['PASS']}</span> | 
                            <span class="status-fail">FAIL: {status_counts['FAIL']}</span> | 
                            <span class="status-warning">WARNING: {status_counts['WARNING']}</span> | 
                            <span>UNKNOWN: {status_counts['UNKNOWN']}</span>
                        </div>
                    </div>
                    <span class="toggle-icon">▼</span>
                </div>
                <div class="cycle-content" id="{cycle_id}">
                    <div class="subfolder-info">
                        <strong>Subfolders analyzed:</strong> {subfolder_summary}
                    </div>
                    
                    <table class="result-table">
                        <thead>
                            <tr>
                                <th style="width: 3%;">#</th>
                                <th style="width: 13%;">Log File</th>
                                <th style="width: 9%;">Subfolder</th>
                                <th style="width: 4%;">Line</th>
                                <th style="width: 6%;">Result</th>
                                <th style="width: 33%;">Result Content</th>
                                <th style="width: 32%;">Key Findings</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            for result_idx, result in enumerate(results, 1):
                log_file_path = Path(result['log_file'])
                log_file_name = log_file_path.name
                subfolder = result['subfolder'] or '-'  # Show dash for root/None
                line_num = result['line_number']
                # A partial flush can hit results whose LLM stage has not run
                # yet, so status is present-but-None. Coerce here or the whole
                # interim report generation dies on status.lower().
                status = result.get('status') or 'PENDING'
                line_content = result['line_content'][:150] + '...' if len(result['line_content']) > 150 else result['line_content']
                llm_analysis = result.get('llm_analysis', '')
                
                # HTML escape
                line_content = line_content.replace('<', '&lt;').replace('>', '&gt;')
                # The model replies in markdown; md_to_html escapes and structures it.
                llm_analysis = md_to_html(llm_analysis) if llm_analysis else ''
                
                file_link = report_file_link(log_file_path, output_path)
                
                # Status styling
                status_class = f"status-{status.lower()}"
                
                # Only show analysis for non-PASS results
                analysis_cell = ""
                if status != 'PASS' and llm_analysis:
                    analysis_cell = f'<div class="llm-analysis md">{llm_analysis}</div>'
                elif status == 'PASS':
                    analysis_cell = '<span style="color: #999;">-</span>'
                else:
                    analysis_cell = '<span style="color: #999;">No analysis available</span>'
                
                cycles_html += f"""
                            <tr>
                                <td>{result_idx}</td>
                                <td><a href="{file_link}" target="_blank" title="{result['relative_path']}">{log_file_name}</a></td>
                                <td>{subfolder}</td>
                                <td>{line_num}</td>
                                <td><span class="{status_class}">{status}</span></td>
                                <td><div class="result-line">{line_content}</div></td>
                                <td>{analysis_cell}</td>
                            </tr>
                """
            
            cycles_html += """
                        </tbody>
                    </table>
                </div>
            </div>
            """
        
        # No results message
        no_results_message = ""
        if not analysis_results or not any(r['results'] for r in analysis_results):
            no_results_message = '<div class="no-results">No test results found in the analyzed folders.</div>'
        
        # Build complete HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Suite Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: none;
            width: 100%;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        
        .report-info {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        
        .report-info p {{
            margin: 5px 0;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-card h3 {{
            font-size: 14px;
            margin-bottom: 10px;
            opacity: 0.9;
        }}
        
        .stat-card .number {{
            font-size: 32px;
            font-weight: bold;
        }}
        
        .controls {{
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .search-box {{
            width: 100%;
            padding: 10px;
            font-size: 16px;
            border: 2px solid #ddd;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #3498db;
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 8px 16px;
            border: 2px solid #3498db;
            background: white;
            color: #3498db;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }}
        
        .filter-btn:hover {{
            background: #3498db;
            color: white;
        }}
        
        .filter-btn.active {{
            background: #3498db;
            color: white;
        }}
        
        .cycle-section {{
            margin: 30px 0;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .cycle-header {{
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .cycle-header:hover {{
            background: linear-gradient(135deg, #2980b9 0%, #21618c 100%);
        }}
        
        .cycle-header h2 {{
            font-size: 20px;
        }}
        
        .toggle-icon {{
            font-size: 24px;
            transition: transform 0.3s;
        }}
        
        .cycle-header.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}
        
        .cycle-content {{
            padding: 20px;
            display: block;
        }}
        
        .cycle-content.hidden {{
            display: none;
        }}
        
        .subfolder-info {{
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
        
        .result-table {{
            width: 100%;
            table-layout: fixed;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        .result-table thead {{
            background: #34495e;
            color: white;
        }}
        
        .result-table th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        
        .result-table td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
            word-break: break-word;
            overflow-wrap: anywhere;
        }}
        
        .result-table tbody tr:hover {{
            background: #f5f5f5;
        }}
        
        .result-table a {{
            color: #3498db;
            text-decoration: none;
        }}
        
        .result-table a:hover {{
            text-decoration: underline;
        }}
        
        .result-line {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 8px;
            border-radius: 3px;
            font-size: 13px;
            word-break: break-all;
        }}
        
        .llm-analysis {{
            background: #fff3cd;
            padding: 10px;
            border-left: 4px solid #ffc107;
            border-radius: 3px;
            font-size: 13px;
            line-height: 1.4;
        }}
        
        {REPORT_MD_CSS}
        
        .status-pass {{
            color: #27ae60;
            font-weight: bold;
        }}
        
        .status-fail {{
            color: #e74c3c;
            font-weight: bold;
        }}
        
        .status-warning {{
            color: #f39c12;
            font-weight: bold;
        }}
        
        .status-unknown {{
            color: #95a5a6;
            font-weight: bold;
        }}
        
        .status-pending {{
            color: #b58105;
            font-weight: bold;
        }}
        
        .no-results {{
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 18px;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
            .search-box, .filter-buttons {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🏁 Test Suite Analysis Report</h1>
        
        <div class="report-info">
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Analysis Path:</strong> {str(self.input_logpath)}</p>
            <p><strong>Total Cycles Analyzed:</strong> {len(analysis_results)}</p>
            {suite_html}
            {ai_html}
        </div>
        {partial_banner}
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Folders</h3>
                <div class="number">{self.stats['total_folders']}</div>
            </div>
            <div class="stat-card">
                <h3>Power Cycle Folders</h3>
                <div class="number">{self.stats['power_cycle_folders']}</div>
            </div>
            <div class="stat-card">
                <h3>Log Files Analyzed</h3>
                <div class="number">{self.stats['total_log_files']}</div>
            </div>
            <div class="stat-card">
                <h3>Results Found</h3>
                <div class="number">{self.stats['results_found']}</div>
            </div>
            <div class="stat-card">
                <h3>Workload Verdicts</h3>
                <div class="number">{self.stats['workload_results']}</div>
            </div>
            <div class="stat-card">
                <h3>AI Skipped</h3>
                <div class="number">{self.stats['ai_skipped']}</div>
            </div>
            <div class="stat-card">
                <h3>LLM Analyses</h3>
                <div class="number">{self.stats['llm_calls']}</div>
            </div>
            <div class="stat-card">
                <h3>LLM Failures</h3>
                <div class="number">{self.stats['llm_failures']}</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search in results, file names, or analysis..." onkeyup="filterResults()">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterByStatus('all', this)">All Results</button>
                <button class="filter-btn" onclick="filterByStatus('pass', this)">Pass Only</button>
                <button class="filter-btn" onclick="filterByStatus('fail', this)">Fail Only</button>
                <button class="filter-btn" onclick="filterByStatus('warning', this)">Warning Only</button>
                <button class="filter-btn" onclick="toggleAllCycles()">Expand/Collapse All</button>
            </div>
            <div id="filter-note" style="display:none; margin-top:12px; padding:10px 14px;
                 background:#eef7ff; border-left:4px solid #3498db; border-radius:4px;
                 font-size:14px; color:#2c3e50;"></div>
        </div>
        
        <div id="cyclesContainer">
            {cycles_html}
        </div>
        
        {no_results_message}
    </div>
    
    <script>
        let allExpanded = true;
        
        function toggleCycle(cycleId) {{
            const content = document.getElementById(cycleId);
            const header = content.previousElementSibling;
            
            if (content.classList.contains('hidden')) {{
                content.classList.remove('hidden');
                header.classList.remove('collapsed');
            }} else {{
                content.classList.add('hidden');
                header.classList.add('collapsed');
            }}
        }}
        
        function toggleAllCycles() {{
            const allContents = document.querySelectorAll('.cycle-content');
            const allHeaders = document.querySelectorAll('.cycle-header');
            
            allExpanded = !allExpanded;
            
            allContents.forEach(content => {{
                if (allExpanded) {{
                    content.classList.remove('hidden');
                }} else {{
                    content.classList.add('hidden');
                }}
            }});
            
            allHeaders.forEach(header => {{
                if (allExpanded) {{
                    header.classList.remove('collapsed');
                }} else {{
                    header.classList.add('collapsed');
                }}
            }});
        }}
        
        function filterResults() {{
            const searchValue = document.getElementById('searchBox').value.toLowerCase();
            // Same rule as filterByStatus: a cycle whose rows all fail the
            // search must disappear entirely, header and all.
            document.querySelectorAll('.cycle-section').forEach(section => {{
                let visible = 0;
                section.querySelectorAll('.result-table tbody tr').forEach(row => {{
                    const match = row.textContent.toLowerCase().includes(searchValue);
                    row.style.display = match ? '' : 'none';
                    if (match) visible++;
                }});
                section.style.display = (visible > 0 || !searchValue) ? '' : 'none';
            }});
        }}
        
        function filterByStatus(status, btn) {{
            // Update button states. The clicked button is passed explicitly -
            // the old code relied on the implicit global `event`, which is
            // non-standard and breaks when the function is called from
            // anywhere other than an inline handler.
            document.querySelectorAll('.filter-btn').forEach(b => {{
                b.classList.remove('active');
            }});
            const clicked = btn || (typeof event !== 'undefined' && event ? event.target : null);
            if (clicked && clicked.classList) clicked.classList.add('active');

            const want = String(status).toUpperCase();
            let shownCycles = 0, hiddenCycles = 0, shownRows = 0;

            // Filter per CYCLE, not per row. Hiding only the <tr> left the
            // cycle header, the subfolder bar and an empty table on screen, so
            // a 100-cycle run still meant scrolling past ~100 empty cards to
            // reach 2 failures. Hide the whole card when nothing matches.
            document.querySelectorAll('.cycle-section').forEach(section => {{
                const rows = section.querySelectorAll('.result-table tbody tr');
                let visible = 0;

                rows.forEach(row => {{
                    const cell = row.querySelector('.status-pass, .status-fail, .status-warning, .status-unknown, .status-pending');
                    const rowStatus = cell ? cell.textContent.trim().toUpperCase() : '';
                    const match = (want === 'ALL') || (rowStatus === want);
                    row.style.display = match ? '' : 'none';
                    if (match) visible++;
                }});

                if (visible > 0 || want === 'ALL') {{
                    section.style.display = '';
                    shownCycles++;
                    shownRows += visible;
                    // Auto-expand a matching cycle so the hit is on screen
                    // without a second click; collapse is still manual.
                    if (want !== 'ALL') {{
                        const body = section.querySelector('.cycle-content');
                        const head = section.querySelector('.cycle-header');
                        if (body) body.classList.remove('hidden');
                        if (head) head.classList.remove('collapsed');
                    }}
                }} else {{
                    section.style.display = 'none';
                    hiddenCycles++;
                }}
            }});

            const note = document.getElementById('filter-note');
            if (note) {{
                if (want === 'ALL') {{
                    note.style.display = 'none';
                }} else {{
                    note.style.display = 'block';
                    note.innerHTML = hiddenCycles === 0
                        ? '<strong>' + want + '</strong> filter: ' + shownRows +
                          ' result(s) across all ' + shownCycles + ' cycle(s).'
                        : '<strong>' + want + '</strong> filter: ' + shownRows +
                          ' result(s) in ' + shownCycles + ' cycle(s). ' +
                          '<span style="color:#0a7">' + hiddenCycles +
                          ' cycle(s) with no ' + want + ' hidden.</span>';
                }}
            }}
        }}
    </script>
</body>
</html>
"""
        
        # Write to file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(brand.brandify(
                    html_content, "Test Suite Analysis",
                    ai_generated=bool(ai_sent)))
            logger.info(f"HTML report generated successfully: {output_path}")
        except Exception as e:
            logger.error(f"Error writing HTML report: {e}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze the result lines of a multi-cycle test run and '
                    'generate an interactive HTML report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python result_analyzer.py --input_logpath /path/to/logs
  python result_analyzer.py --input_logpath /path/to/logs --ai --output report.html --workers 8
  python result_analyzer.py --input_logpath /path/to/logs --ai --ai_url http://localhost:11434

AI is off by default: without --ai (or LOG_ANALYZER_AI=1) the report is built
from deterministic parsing only. AI-written text in the report is labelled
"AI-generated, may be inaccurate, verify against the log evidence."

AI backends (see common/ai_backend.py and common/llm_config.json):
  With --ai the configured AI CLI is used (LOG_ANALYZER_AI_CLI=none disables it).
  An OpenAI-compatible HTTP LLM endpoint is used only when explicitly
  configured (--ai_url, LOG_ANALYZER_AI_URL, or ai_backend "http").

Environment variables:
  LOG_ANALYZER_AI                         1 enables AI analysis (same as --ai)
  LOG_ANALYZER_AI_URL                     HTTP LLM endpoint base URL (opts into HTTP)
  LOG_ANALYZER_AI_MODEL                   Model name for the HTTP LLM endpoint
  LOG_ANALYZER_AI_CLI                     AI CLI type: copilot | custom | none
  LOG_ANALYZER_AI_PREFLIGHT               0 skips the AI CLI preflight check
  LOG_ANALYZER_AI_PREFLIGHT_TIMEOUT       Preflight timeout in seconds (default 90)
  LOG_ANALYZER_RESULT_ANALYZER_MODEL      Model passed to the AI CLI (default auto)
  LOG_ANALYZER_RESULT_ANALYZER_WORKERS    Default for --workers (default 8)
  LOG_ANALYZER_RESULT_ANALYZER_AI_BUDGET  Max non-failing results sent to AI (default 120)
  LOG_ANALYZER_RESULT_ANALYZER_AI_FAILS   0 stops always sending FAIL/WARNING to AI
  LOG_ANALYZER_RESULT_ANALYZER_AI_PASS    1 also sends deterministic PASS rows to AI
  LOG_ANALYZER_RESULT_ANALYZER_AI_ALL     1 sends every row to AI (still budgeted)
  LOG_ANALYZER_RESULT_ANALYZER_FLUSH_SEC  Interim report flush interval (default 60)
  LOG_ANALYZER_SUITE_SCRIPT_GLOB          Default for --suite_glob
  LOG_ANALYZER_COLLECTOR_PREFIXES         Comma-separated log-collector folder prefixes
        """
    )
    
    parser.add_argument(
        '--input_logpath',
        type=str,
        required=True,
        help='Root path containing test cycle folders'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output HTML report path (default: test_analysis_report_TIMESTAMP.html in input_logpath)'
    )
    
    parser.add_argument(
        '--ai_url',
        type=str,
        default=None,
        help='Base URL of an OpenAI-compatible HTTP LLM endpoint; passing it '
             'opts into the HTTP backend (overrides LOG_ANALYZER_AI_URL)'
    )
    
    parser.add_argument(
        '--model',
        type=str,
        default=None,
        help='Model name for the HTTP LLM endpoint (overrides LOG_ANALYZER_AI_MODEL; '
             '"default" auto-detects it from /v1/models)'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=int(os.getenv("LOG_ANALYZER_RESULT_ANALYZER_WORKERS", "8")),
        help='Number of concurrent workers for LLM calls (default: 8). '
             'Each AI call can take tens of seconds, so serial runs are slow.'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Timeout in seconds for LLM API calls (default: 300)'
    )

    parser.add_argument(
        '--suite_glob',
        type=str,
        default=SUITE_SCRIPT_GLOB,
        help='Glob (relative to --input_logpath) of an optional test suite '
             'driver script used to learn which workloads ran '
             f'(default: {SUITE_SCRIPT_GLOB})'
    )
    
    parser.add_argument(
        '--ai',
        action='store_true',
        help='Enable LLM analysis (off by default; LOG_ANALYZER_AI=1 also enables it)'
    )

    parser.add_argument(
        '--no_llm',
        action='store_true',
        help='Force LLM analysis off, overriding --ai and LOG_ANALYZER_AI'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Log sanitized prompts and LLM responses (truncated)'
    )
    
    args = parser.parse_args()
    args.no_llm = args.no_llm or not ai_backend.ai_enabled(args.ai)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input path
    if not Path(args.input_logpath).exists():
        logger.error(f"Input path does not exist: {args.input_logpath}")
        return 1
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(args.input_logpath) / f"test_analysis_report_{timestamp}.html"
    
    logger.info("="*60)
    logger.info("Test Suite Result Analyzer")
    logger.info("="*60)
    logger.info(f"Input path: {args.input_logpath}")
    logger.info(f"Output report: {output_path}")
    logger.info(f"Workers: {args.workers}")
    logger.info(f"LLM Analysis: {'Disabled' if args.no_llm else 'Enabled'}")
    if not args.no_llm and args.model:
        logger.info(f"Model: {args.model}")
    if args.debug:
        logger.info("LLM debug logging: ENABLED")
    logger.info("="*60)
    
    # Create analyzer
    analyzer = LogAnalyzer(
        input_logpath=args.input_logpath,
        ai_url=args.ai_url,
        max_workers=args.workers if not args.no_llm else 1,
        timeout=args.timeout,
        model=args.model,
        debug=args.debug,
        suite_glob=args.suite_glob,
    )
    
    # If no_llm is set, override the call_llm_api method to return a placeholder.
    # It must NOT return a status: the deterministic classifier already produced
    # one, and returning "UNKNOWN" here would overwrite a perfectly good verdict.
    if args.no_llm:
        analyzer.ai_enabled = False
        analyzer.call_llm_api = lambda content, context, analysis_type='full': (
            "" if analysis_type == "status" else "AI analysis off (enable with --ai)"
        )
    
    # Perform analysis
    start_time = time.time()
    
    try:
        logger.info("Starting analysis...")
        # Hand the output path to the analyzer so it can flush interim reports
        # while the LLM stage runs; without this a timeout produced no file.
        analyzer.output_path = str(output_path)
        analysis_results = analyzer.analyze_all_folders()
        
        elapsed_time = time.time() - start_time
        logger.info(f"Analysis completed in {elapsed_time:.2f} seconds")
        
        # Generate report
        logger.info("Generating HTML report...")
        analyzer.generate_html_report(analysis_results, output_path)
        
        # Print summary
        logger.info("="*60)
        logger.info("ANALYSIS SUMMARY")
        logger.info("="*60)
        logger.info(f"Total folders scanned: {analyzer.stats['total_folders']}")
        logger.info(f"Power cycle folders found: {analyzer.stats['power_cycle_folders']}")
        logger.info(f"Log files analyzed: {analyzer.stats['total_log_files']}")
        logger.info(f"Results found: {analyzer.stats['results_found']}")
        logger.info(f"LLM API calls: {analyzer.stats['llm_calls']}")
        logger.info(f"LLM failures: {analyzer.stats['llm_failures']}")
        logger.info(f"AI skipped (deterministic/covered elsewhere): {analyzer.stats['ai_skipped']}")
        logger.info(f"AI deferred (over budget): {analyzer.stats['ai_deferred']}")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info("="*60)
        logger.info(f"✅ Report generated: {output_path}")
        logger.info("="*60)
        
        return 0
    
    except Exception as e:
        logger.error(f"Fatal error during analysis: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())