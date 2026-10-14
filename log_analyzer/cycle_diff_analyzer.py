#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compare same-identity log files across consecutive test-cycle folders.

For every cycle folder (see ``CYCLE_FOLDER_RE``) the tool collects:

* files directly in the cycle folder whose name matches one of the
  ``FILE_CATEGORY_PATTERNS`` (dmesg, syslog, SEL, event, sensor CSV, *.log ...),
* every text file below a log-collector folder (name starts with one of
  ``COLLECTOR_PREFIXES``), categorised by the same patterns,
* every text file below any other sub-folder ("Cycle test log", i.e. workload
  output), compared one file at a time.

Files with the same normalised identity (cycle numbers and timestamps removed)
are compared between adjacent cycles; the deterministic line-set difference is
optionally summarised by an AI backend (see ``common/ai_backend.py``).
"""

import argparse
import fnmatch
import hashlib
import html
import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from md_render import inline_md


logger = logging.getLogger(__name__)

# Cycle folders are named "<hostname>_<TAG>_c<N>-<version>-<timestamp>" (any
# tag) or "loop_<N>".
CYCLE_FOLDER_RE = re.compile(r"_[A-Za-z0-9]+_c(\d+)(?:-|_|$)", re.IGNORECASE)
TEXT_SUFFIXES = {".csv", ".json", ".log", ".out", ".txt", ".xml"}
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_SAMPLE_LINES = 12
MAX_REPORT_LINE_CHARS = 2000
# Deeper AI comparison: feed more context lines per transition so findings are not "too rough".
MAX_AI_SAMPLE_LINES = 25
MAX_AI_LINE_CHARS = 600
DEFAULT_AI_BUDGET = 50
# Groups packed into a single AI call. Batching amortizes the per-call
# cold-start cost of an AI CLI across many groups instead of paying it once
# per group.
AI_BATCH_SIZE = 10

# (category, case-insensitive basename glob) pairs; the first match wins.
# Root-level cycle files are compared only when they match one of these; files
# below a collector folder fall back to "Collector log". Override with
# --file_patterns or LOG_ANALYZER_CYCLE_DIFF_FILE_PATTERNS (comma-separated
# "Category=glob" or bare "glob" entries).
DEFAULT_FILE_CATEGORY_PATTERNS: List[Tuple[str, str]] = [
    ("Kernel log", "*dmesg*"),
    ("System log", "*syslog*"),
    ("System log", "*journal*"),
    ("SEL", "*sel*"),
    ("Events", "*event*"),
    ("PCIe", "*lspci*"),
    ("PCIe", "*pci*"),
    ("Sensors", "*sensor*.csv"),
    ("Sensors", "*sdr*.csv"),
    ("Test suite", "*test_suite*"),
    ("Test suite", "*.out"),
    ("Log", "*.log"),
]

# Name prefixes of log-collector output folders inside a cycle folder.
# Override with --collector_prefixes or LOG_ANALYZER_COLLECTOR_PREFIXES.
DEFAULT_COLLECTOR_PREFIXES = ("collector", "log_collector")

# Timestamped folder prefixes whose timestamp suffix is normalised away.
TIMESTAMPED_DIR_PREFIXES = ("pretest", "bmc_collect")


def parse_file_patterns(spec: Optional[str]) -> List[Tuple[str, str]]:
    """Parse "Category=glob,glob2,..." into (category, glob) pairs."""
    pairs = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            category, pattern = item.split("=", 1)
            category, pattern = category.strip() or "Log", pattern.strip()
        else:
            category, pattern = "Log", item
        if pattern:
            pairs.append((category, pattern.lower()))
    return pairs


def parse_prefixes(spec: Optional[str]) -> Tuple[str, ...]:
    return tuple(p.strip().lower() for p in (spec or "").split(",") if p.strip())


FILE_CATEGORY_PATTERNS = (
    parse_file_patterns(os.getenv("LOG_ANALYZER_CYCLE_DIFF_FILE_PATTERNS"))
    or list(DEFAULT_FILE_CATEGORY_PATTERNS))
COLLECTOR_PREFIXES = (
    parse_prefixes(os.getenv("LOG_ANALYZER_COLLECTOR_PREFIXES"))
    or DEFAULT_COLLECTOR_PREFIXES)


# ── Report branding ───────────────────────────────────────────────────────
# Cosmetic only: report generation must never fail because branding could not
# load, so the fallback is a no-op stub rather than an ImportError.
try:
    _common_dir = str(Path(__file__).resolve().parent.parent / "common")
    if _common_dir not in sys.path:
        sys.path.insert(0, _common_dir)
    import brand
except Exception:                                        # pragma: no cover
    class brand:                                         # noqa: N801
        brandify = staticmethod(lambda page, *a, **k: page)
        _nil = staticmethod(lambda *a, **k: "")
        brand_css = favicon_tag = head_tags = _nil
        brand_chip = brand_banner = brand_footer = _nil


def glob_to_regex(pattern: str) -> Optional["re.Pattern"]:
    """Convert a settings file glob (e.g. dmesg*serialized.log) to a basename regex."""
    pattern = (pattern or "").strip().replace("\\", "/")
    if not pattern:
        return None
    # Only the basename is matched against per-cycle files; golden absolute paths are references.
    base = pattern.rsplit("/", 1)[-1]
    if not base:
        return None
    escaped = re.escape(base).replace(r"\*", ".*").replace(r"\?", ".")
    try:
        return re.compile(rf"^{escaped}$", re.IGNORECASE)
    except re.error:
        return None


def load_interested_patterns(scan_folder: Path, settings_path: Optional[Path]) -> List["re.Pattern"]:
    """Load 'interested log file' basename patterns from the SUT settings error_signatures."""
    if settings_path is None:
        candidates = sorted(
            p for p in scan_folder.glob("*.json")
            if "settings" in p.name.lower()
        )
        for candidate in candidates:
            try:
                if "error_signatures" in candidate.read_text(encoding="utf-8-sig", errors="ignore"):
                    settings_path = candidate
                    break
            except OSError:
                continue
    if settings_path is None or not settings_path.is_file():
        logger.info("No SUT settings with error_signatures found; interested-file weighting disabled")
        return []
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8-sig", errors="ignore"))
    except (OSError, ValueError) as exc:
        logger.warning("Could not parse settings %s: %s", settings_path, exc)
        return []
    raw_patterns = []
    for signature in data.get("error_signatures", []):
        for key in ("file", "good_log"):
            value = signature.get(key)
            if isinstance(value, str) and value.strip():
                raw_patterns.append(value)
    patterns = []
    seen = set()
    for raw in raw_patterns:
        compiled = glob_to_regex(raw)
        if compiled and compiled.pattern not in seen:
            seen.add(compiled.pattern)
            patterns.append(compiled)
    logger.info("Loaded %d interested-file patterns from %s", len(patterns), settings_path.name)
    return patterns


# Wrapper/preamble lines an AI CLI backend sometimes emits instead of a real finding.
AI_JUNK_MARKERS = (
    "ready to analyze",
    "i'll inspect",
    "i\u2019ll inspect",
    "inspect the provided",
    "sanitized log",
    "base any findings solely",
    "lines read",
    "i am ready",
    "let me analyze",
    "here is my analysis",
    "here are my findings",
    "based on the provided",
    "no meaningful regression detected",
)
TRANSITION_MARKER_RE = re.compile(r"(c\d+\s*->\s*c\d+\s*:)")
SEVERITY_TAG_RE = re.compile(r"\[(CRITICAL|WARNING|INFO)\]", re.IGNORECASE)
CODE_SPAN_RE = re.compile(r"`([^`]+)`")


def split_ai_findings(raw: str) -> List[str]:
    """Split a raw AI response into clean, individual finding lines, dropping wrapper preamble."""
    text = (raw or "").strip()
    if not text:
        return []
    # Put each 'cX -> cY:' finding and each severity tag on its own line.
    text = TRANSITION_MARKER_RE.sub(r"\n\1", text)
    text = SEVERITY_TAG_RE.sub(lambda m: m.group(0).upper() + "\n", text)
    findings = []
    seen = set()
    for line in text.splitlines():
        line = line.strip().strip("-*\u2022 \t")
        if not line:
            continue
        low = line.lower()
        if any(marker in low for marker in AI_JUNK_MARKERS):
            continue
        # Drop file-read progress artifacts like "└ L241:360 (116 lines read)".
        if line.startswith("\u2514") or re.match(r"^L\d+:\d+", line):
            continue
        if line.upper() == "NO MEANINGFUL REGRESSION":
            return ["NO MEANINGFUL REGRESSION"]
        if low not in seen:
            seen.add(low)
            findings.append(line)
    return findings


BATCH_GROUP_HEADER_RE = re.compile(r"^\s*#{1,4}\s*GROUP:\s*(.+?)\s*$", re.MULTILINE)


def split_batch_response(raw: str, identities: List[str]) -> Dict[str, str]:
    """Split one batched AI response into per-group text keyed by group identity.

    The model is asked to prefix each group's findings with a '### GROUP: <identity>'
    header line, in the same order the groups were sent. Falls back to substring
    matching if the model didn't echo an identity back verbatim."""
    text = raw or ""
    matches = list(BATCH_GROUP_HEADER_RE.finditer(text))
    if not matches and len(identities) == 1:
        # Single-group batch (typically the last, partial one): tolerate the model
        # skipping the '### GROUP:' header since there is nothing to disambiguate.
        return {identities[0]: text.strip()}
    result: Dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        segment = text[start:end].strip()
        header_identity = match.group(1).strip()
        if header_identity in identities:
            result[header_identity] = segment
            continue
        for identity in identities:
            if identity in header_identity or header_identity in identity:
                result[identity] = segment
                break
    return result


def _inline_html(text: str) -> str:
    """Escape text and render `backtick` spans as <code> and **bold** as <strong>."""
    return inline_md(text)


def render_finding_html(finding: str) -> str:
    """Render one finding as an <li> with a colored severity badge and bold transition prefix."""
    if finding == "NO MEANINGFUL REGRESSION":
        return "<li class='f-ok'><span class='badge badge-ok'>STABLE</span> No meaningful regression across cycles.</li>"
    severity = "INFO"
    match = SEVERITY_TAG_RE.search(finding)
    if match:
        severity = match.group(1).upper()
        finding = SEVERITY_TAG_RE.sub("", finding).strip()
    badge = f"<span class='badge badge-{severity.lower()}'>{severity}</span>"
    transition = ""
    tmatch = TRANSITION_MARKER_RE.match(finding)
    if tmatch:
        transition = "<strong>" + html.escape(tmatch.group(1).replace(" ", "")) + "</strong> "
        finding = finding[tmatch.end():].strip()
    return f"<li class='f-{severity.lower()}'>{badge} {transition}{_inline_html(finding)}</li>"


def render_ai_cell(raw: str) -> str:
    """Turn a raw AI response into a formatted bullet list; note when only preamble came back."""
    findings = split_ai_findings(raw)
    if not findings:
        return "<span class='ai-note'>AI returned no usable finding (preamble only) - re-run recommended.</span>"
    return "<ul class='findings'>" + "".join(render_finding_html(f) for f in findings) + "</ul>"


IMPORTANT_LINE_RE = re.compile(
    r"\b(error|fail(?:ed|ure)?|warn(?:ing)?|critical|fatal|panic|aer|dpc|uncorrect|missing|timeout)\b",
    re.IGNORECASE,
)
IGNORED_TARGET_FOLDERS = {"logs", "log_analyzer"}


def find_cycle_folders(scan_folder: Path) -> List[Tuple[int, Path]]:
    """Return direct child cycle folders sorted by cycle number."""
    folders = []
    if not scan_folder.is_dir():
        return folders
    for child in scan_folder.iterdir():
        if not child.is_dir():
            continue
        match = CYCLE_FOLDER_RE.search(child.name)
        if not match:
            match = re.fullmatch(r"loop_(\d+)", child.name, re.IGNORECASE)
        if match:
            folders.append((int(match.group(1)), child))
    return sorted(folders, key=lambda item: (item[0], item[1].name.lower()))


def classify_file(path: Path, patterns: List[Tuple[str, str]]) -> Optional[str]:
    """Category of a text log file from the (category, glob) list, or None."""
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return None
    name = path.name.lower()
    for category, pattern in patterns:
        if fnmatch.fnmatchcase(name, pattern):
            return category
    return None


def normalize_target_identity(name: str) -> str:
    """Normalize a peer folder name such as ALLTOALL_PERF_<timestamp>."""
    return normalize_log_identity(Path(name))


def normalize_log_identity(relative_path: Path,
                           dir_prefixes: Tuple[str, ...] = ()) -> str:
    """Remove cycle and timestamp noise while preserving test numbers such as 'test 1'."""
    value = relative_path.as_posix().lower()
    value = re.sub(r"(?i)(cycle[_-]?|_c)\d+", r"\1<cycle>", value)
    value = re.sub(r"(?<!\d)20\d{6}[_-]?\d{6}(?!\d)", "<timestamp>", value)
    value = re.sub(r"(?<!\d)\d{8}[_-]\d{6}(?!\d)", "<timestamp>", value)
    value = re.sub(r"(?<!\d)\d{2}(?:[-_]\d{2}){4,5}(?!\d)", "<timestamp>", value)
    prefixes = tuple(dict.fromkeys(tuple(dir_prefixes or COLLECTOR_PREFIXES)
                                   + TIMESTAMPED_DIR_PREFIXES))
    if prefixes:
        alternation = "|".join(re.escape(p) for p in prefixes)
        value = re.sub(rf"(?i)({alternation})[-_][^/]*?\d{{6,14}}", r"\1-<timestamp>", value)
    value = re.sub(r"(?<=[-_])\d{8,14}(?=/|$|[._-])", "<timestamp>", value)
    value = re.sub(r"(?<!\d)\d{10,14}(?!\d)", "<timestamp>", value)
    return value


def normalize_content(text: str) -> List[str]:
    """Normalize volatile timestamps/cycle labels without hiding hardware changes."""
    normalized = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"\b20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?\b", "<timestamp>", line)
        line = re.sub(r"\b20\d{6}[_-]?\d{6}\b", "<timestamp>", line)
        line = re.sub(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b", "<time>", line)
        line = re.sub(r"(?i)\bcycle(?:[_ -]?number)?\s*[:=_-]?\s*\d+\b", "cycle <cycle>", line)
        normalized.append(re.sub(r"\s+", " ", line))
    return normalized


def read_normalized(path: Path) -> Tuple[List[str], bool]:
    """Read bounded text from both ends of a file and report whether it was truncated."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        if size <= MAX_READ_BYTES:
            data = stream.read()
            truncated = False
        else:
            half = MAX_READ_BYTES // 2
            head = stream.read(half)
            stream.seek(max(0, size - half))
            tail = stream.read(half)
            data = head + b"\n<content truncated>\n" + tail
            truncated = True
    return normalize_content(data.decode("utf-8", errors="replace")), truncated


def summarize_transition(previous: Dict, current: Dict) -> Dict:
    """Produce a bounded deterministic line-set summary for adjacent cycles."""
    previous_set = set(previous["lines"])
    current_set = set(current["lines"])
    added = sorted(current_set - previous_set)
    removed = sorted(previous_set - current_set)
    important_added = [line[:MAX_REPORT_LINE_CHARS] for line in added if IMPORTANT_LINE_RE.search(line)]
    important_removed = [line[:MAX_REPORT_LINE_CHARS] for line in removed if IMPORTANT_LINE_RE.search(line)]
    return {
        "from_cycle": previous["cycle"],
        "to_cycle": current["cycle"],
        "changed": previous["digest"] != current["digest"],
        "added_line_count": len(added),
        "removed_line_count": len(removed),
        "important_added": important_added[:MAX_SAMPLE_LINES],
        "important_removed": important_removed[:MAX_SAMPLE_LINES],
        "added_samples": [line[:MAX_REPORT_LINE_CHARS] for line in added[:MAX_SAMPLE_LINES]],
        "removed_samples": [line[:MAX_REPORT_LINE_CHARS] for line in removed[:MAX_SAMPLE_LINES]],
    }


class CycleDiffAnalyzer:
    def __init__(self, scan_folder: str, use_ai: bool = True, max_ai_groups: int = DEFAULT_AI_BUDGET,
                 settings_path: Optional[str] = None,
                 file_patterns: Optional[List[Tuple[str, str]]] = None,
                 collector_prefixes: Optional[Tuple[str, ...]] = None):
        self.scan_folder = Path(scan_folder)
        self.use_ai = use_ai
        self.max_ai_groups = max(0, max_ai_groups)
        self._llm = None
        self.file_patterns = list(file_patterns or FILE_CATEGORY_PATTERNS)
        self.collector_prefixes = tuple(collector_prefixes or COLLECTOR_PREFIXES)
        self.interested_patterns = load_interested_patterns(
            self.scan_folder, Path(settings_path) if settings_path else None
        )

    def _match_interested(self, file_names: List[str]) -> Optional[str]:
        """Return the first interested pattern (as text) matched by any file basename."""
        for name in file_names:
            base = Path(name).name
            for pattern in self.interested_patterns:
                if pattern.search(base):
                    return pattern.pattern
        return None

    def collect_groups(self) -> Tuple[List[int], Dict[str, Dict]]:
        cycle_folders = find_cycle_folders(self.scan_folder)
        cycles = sorted({cycle for cycle, _ in cycle_folders})
        groups = {}
        grouped_paths = defaultdict(lambda: defaultdict(list))

        folders_by_cycle = defaultdict(list)
        for cycle, folder in cycle_folders:
            folders_by_cycle[cycle].append(folder)

        for cycle in cycles:
            target_folders = []
            for folder in folders_by_cycle[cycle]:
                for child in folder.iterdir():
                    if child.is_file():
                        root_category = classify_file(child, self.file_patterns)
                        if root_category:
                            identity = normalize_log_identity(Path(child.name), self.collector_prefixes)
                            grouped_paths[(root_category, identity)][cycle].append(child)
                    elif child.is_dir():
                        child_name = child.name.lower()
                        if child_name.startswith(self.collector_prefixes):
                            for path in child.rglob("*"):
                                if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                                    continue
                                relative_path = path.relative_to(folder)
                                category = classify_file(relative_path, self.file_patterns) or "Collector log"
                                identity = normalize_log_identity(relative_path, self.collector_prefixes)
                                grouped_paths[(category, identity)][cycle].append(path)
                        elif child_name not in IGNORED_TARGET_FOLDERS:
                            target_folders.append(child)

            # Per-cycle test-folder logs (workload output, peers of the collector
            # folder): compare ONE log file at a time across cycles so each file
            # (e.g. bandwidth_test_*.log) gets its own row.
            per_cycle_counts = defaultdict(int)
            for target_folder in sorted(target_folders, key=lambda item: item.name.lower()):
                for path in sorted(target_folder.rglob("*"), key=lambda item: item.as_posix().lower()):
                    if not (path.is_file() and path.suffix.lower() in TEXT_SUFFIXES):
                        continue
                    file_identity = normalize_log_identity(Path(path.name))
                    per_cycle_counts[file_identity] += 1
                    identity = f"{file_identity} #{per_cycle_counts[file_identity]}"
                    grouped_paths[("Cycle test log", identity)][cycle].append(path)

        for (category, identity), by_cycle in sorted(grouped_paths.items()):
            entries = []
            for cycle in cycles:
                paths = sorted(by_cycle.get(cycle, []))
                if not paths:
                    entries.append({"cycle": cycle, "missing": True, "files": []})
                    continue
                lines = []
                truncated = False
                for path in paths:
                    file_lines, file_truncated = read_normalized(path)
                    lines.extend(file_lines)
                    truncated = truncated or file_truncated
                digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
                entries.append({
                    "cycle": cycle,
                    "missing": False,
                    "files": [str(path.relative_to(self.scan_folder)) for path in paths],
                    "file_count": len(paths),
                    "line_count": len(lines),
                    "truncated": truncated,
                    "digest": digest,
                    "lines": lines,
                })

            present = [entry for entry in entries if not entry["missing"]]
            if not present:
                continue
            transitions = [summarize_transition(present[index - 1], present[index]) for index in range(1, len(present))]
            missing_cycles = [entry["cycle"] for entry in entries if entry["missing"]]
            changed = bool(missing_cycles or any(item["changed"] for item in transitions))
            all_files = [name for entry in present for name in entry.get("files", [])]
            interested_pattern = self._match_interested(all_files)
            # Workload output logs (peers of the collector folder) are always of interest.
            is_interested = bool(interested_pattern) or category == "Cycle test log"
            key = f"{category}: {identity}"
            groups[key] = {
                "category": category,
                "identity": identity,
                "changed": changed,
                "interested": is_interested,
                "interested_pattern": interested_pattern or ("cycle test log" if category == "Cycle test log" else None),
                "missing_cycles": missing_cycles,
                "cycles": [{key: value for key, value in entry.items() if key != "lines"} for entry in entries],
                "transitions": transitions,
                "ai_analysis": None,
                "ai_compared": False,
            }
        return cycles, groups

    def _ensure_llm(self):
        if self._llm is None:
            from result_analyzer import LogAnalyzer

            # Batches of AI_BATCH_SIZE groups do proportionally more work per call
            # than the old single-group calls did, so allow more time per call.
            self._llm = LogAnalyzer(str(self.scan_folder), max_workers=1, timeout=900)
            self._llm._prepare_llm_backend()
        return self._llm

    @staticmethod
    def _ai_priority(group: Dict) -> Tuple[int, int, bool, str]:
        category_priority = {
            "Cycle test log": 0,
            "Sensors": 1,
            "Events": 2,
            "PCIe": 2,
            "SEL": 2,
            "Kernel log": 2,
            "System log": 2,
            "Test suite": 2,
            "Collector log": 3,
            "Log": 3,
        }
        has_important_lines = any(
            item["important_added"] or item["important_removed"]
            for item in group["transitions"]
        )
        return (
            0 if group.get("interested") else 1,          # interested files first
            category_priority.get(group["category"], 4),
            not has_important_lines,
            group["identity"],
        )

    def rank_ai_candidates(self, groups: Dict[str, Dict]) -> List[Dict]:
        """Return ALL changed groups ranked interested-first, distinct file families before repeats."""
        candidates = [group for group in groups.values() if group["changed"]]
        candidates.sort(key=self._ai_priority)
        selected = []
        deferred = []
        seen_families = set()
        for group in candidates:
            family = re.sub(r" #\d+$", "", group["identity"])
            # Cover distinct file families first; extra occurrences of the same file are deferred.
            if family in seen_families:
                deferred.append(group)
                continue
            seen_families.add(family)
            selected.append(group)
        selected.extend(deferred)
        return selected

    def _compact_group_payload(self, group: Dict) -> Dict:
        compact_transitions = []
        for transition in group["transitions"]:
            compact = {
                key: transition[key]
                for key in (
                    "from_cycle", "to_cycle", "changed",
                    "added_line_count", "removed_line_count",
                )
            }
            for key in ("important_added", "important_removed", "added_samples", "removed_samples"):
                compact[key] = [
                    line[:MAX_AI_LINE_CHARS]
                    for line in transition[key][:MAX_AI_SAMPLE_LINES]
                ]
            compact_transitions.append(compact)
        return {
            "identity": group["identity"],
            "log_type": group["category"],
            "interested_file": bool(group.get("interested")),
            "matched_pattern": group.get("interested_pattern"),
            "cycles_present": [c["cycle"] for c in group["cycles"] if not c.get("missing")],
            "missing_cycles": group["missing_cycles"],
            "adjacent_cycle_differences": compact_transitions,
        }

    def _build_batch_ai_request(self, batch: List[Dict]) -> Tuple[str, str]:
        payload = [self._compact_group_payload(group) for group in batch]
        prompt = json.dumps(payload, ensure_ascii=False, indent=2)
        context = (
            "You are a systems-debugging assistant comparing MULTIPLE log files across "
            "consecutive test cycles (cX -> cY), one per entry in the JSON array below. Each entry's "
            "'adjacent_cycle_differences' gives, per adjacent transition, the lines that appeared "
            "(added_samples/important_added) and disappeared (removed_samples/important_removed) "
            "after timestamp/cycle-number normalization.\n\n"
            "Process EVERY entry, in the SAME ORDER as the array. For EACH entry:\n"
            "1. Emit a line EXACTLY '### GROUP: <identity>' using that entry's 'identity' value "
            "verbatim (no quotes, nothing else on that line).\n"
            "2. Immediately after, answer with ONLY findings for that entry (no preamble, no "
            "'ready to analyze', no restating the task). Do a THOROUGH comparison, not a shallow one:\n"
            "   a. For EACH adjacent transition that has a meaningful change, emit one line starting "
            "exactly 'cX -> cY:' followed by a concise root-cause-oriented finding.\n"
            "   b. Call out new errors, hardware faults, PCIe AER, timeouts, missing or "
            "disappearing devices, test PASS<->FAIL transitions, and meaningful counter or "
            "threshold changes. Quote the specific token or device name as evidence.\n"
            "   c. Classify each finding severity as [CRITICAL], [WARNING], or [INFO] at the end of "
            "the line.\n"
            "   d. Treat pure timestamp/ordering/counter noise as not meaningful.\n"
            "   e. If that entry is genuinely stable across every transition, return exactly "
            "'NO MEANINGFUL REGRESSION' for it.\n"
            "3. Then move to the next entry's '### GROUP:' header. Do not skip any entry, and do not "
            "merge multiple entries under one header."
        )
        return prompt, context

    def analyze_with_ai(self, groups: Dict[str, Dict]) -> Dict[str, int]:
        """Analyze the top `max_ai_groups` ranked candidates, packed AI_BATCH_SIZE-per-call.

        Batching amortizes the AI CLI per-call cold-start cost across many groups
        instead of paying it once per group. A batch is retried once only if it produced ZERO
        usable findings across ALL of its groups (e.g. preamble-only or missing headers).
        """
        ranked = self.rank_ai_candidates(groups)
        selected = ranked[: self.max_ai_groups]
        usable = 0
        preamble = 0
        batch_calls = 0
        llm = self._ensure_llm()
        if getattr(llm, "llm_backend", None) == "unavailable":
            reason = (
                getattr(llm, "llm_unavailable_reason", None)
                or "AI backend preflight failed"
            )
            for group in selected:
                group["ai_analysis"] = (
                    "AI analysis skipped before queue: AI backend "
                    f"preflight failed. {reason}"
                )
                group["ai_compared"] = False
                group["ai_usable"] = False
            logger.error(
                "AI backend preflight failed; skipping all %d selected groups: %s",
                len(selected), reason,
            )
            return {
                "usable": 0,
                "attempts": 0,
                "preamble": 0,
                "ranked": len(ranked),
                "batch_calls": 0,
                "unavailable_count": len(selected),
                "unavailable_reason": reason,
            }
        for start in range(0, len(selected), AI_BATCH_SIZE):
            batch = selected[start:start + AI_BATCH_SIZE]
            identities = [group["identity"] for group in batch]
            prompt, context = self._build_batch_ai_request(batch)

            raw = llm.call_llm_api(prompt, context, analysis_type="findings")
            batch_calls += 1
            per_group = split_batch_response(raw, identities)
            if not any(split_ai_findings(per_group.get(identity, "")) for identity in identities):
                # Whole batch was unusable (preamble-only / missing headers) - retry once.
                raw_retry = llm.call_llm_api(prompt, context, analysis_type="findings")
                batch_calls += 1
                retry_per_group = split_batch_response(raw_retry, identities)
                if any(split_ai_findings(retry_per_group.get(identity, "")) for identity in identities):
                    raw = raw_retry
                    per_group = retry_per_group

            for group in batch:
                segment = per_group.get(group["identity"], "")
                findings = split_ai_findings(segment)
                group["ai_analysis"] = segment or raw
                group["ai_compared"] = True
                if findings:
                    group["ai_usable"] = True
                    usable += 1
                else:
                    group["ai_usable"] = False
                    preamble += 1
        return {"usable": usable, "attempts": len(selected), "preamble": preamble,
                "ranked": len(ranked), "batch_calls": batch_calls}

    def run(self) -> Dict:
        cycles, groups = self.collect_groups()
        ai_stats = {"usable": 0, "attempts": 0, "preamble": 0, "ranked": 0}
        if self.use_ai and len(cycles) >= 2:
            ai_stats = self.analyze_with_ai(groups)
        report = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "scan_folder": str(self.scan_folder),
            "cycles": cycles,
            "group_count": len(groups),
            "changed_group_count": sum(group["changed"] for group in groups.values()),
            "interested_group_count": sum(group.get("interested", False) for group in groups.values()),
            "ai_compared_count": sum(bool(group.get("ai_usable")) for group in groups.values()),
            "ai_attempted_count": ai_stats["attempts"],
            "ai_preamble_count": ai_stats["preamble"],
            "ai_unavailable_count": ai_stats.get("unavailable_count", 0),
            "ai_unavailable_reason": ai_stats.get("unavailable_reason"),
            "ai_enabled": self.use_ai,
            "ai_budget": self.max_ai_groups,
            "ai_candidate_count": ai_stats["ranked"],
            "interested_pattern_count": len(self.interested_patterns),
            "groups": groups,
        }
        self.write_reports(report)
        return report

    def write_reports(self, report: Dict) -> None:
        json_path = self.scan_folder / "cycle_diff_report.json"
        html_path = self.scan_folder / "cycle_diff_report.html"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        rows = []
        for group in report["groups"].values():
            transition_text = []
            for item in group["transitions"]:
                state = "changed" if item["changed"] else "same"
                transition_text.append(
                    f"c{item['from_cycle']} to c{item['to_cycle']}: {state}; "
                    f"+{item['added_line_count']} / -{item['removed_line_count']} lines"
                )
            if group["missing_cycles"]:
                transition_text.append("missing in c" + ", c".join(map(str, group["missing_cycles"])))

            ai_compared = bool(group.get("ai_compared"))
            ai_usable = bool(group.get("ai_usable"))
            if ai_compared and ai_usable and group["ai_analysis"]:
                analysis = render_ai_cell(group["ai_analysis"])
                analysis_class = ""
                analysis_is_html = True
            elif ai_compared and not ai_usable:
                analysis = render_ai_cell(group.get("ai_analysis") or "")
                analysis_class = ""
                analysis_is_html = True
            elif not report["ai_enabled"]:
                analysis = "AI disabled for this run (--no_ai)."
                analysis_class = "ai-note"
                analysis_is_html = False
            elif report.get("ai_unavailable_reason"):
                analysis = (
                    "AI unavailable before analysis: "
                    + report["ai_unavailable_reason"]
                )
                analysis_class = "ai-note"
                analysis_is_html = False
            elif not group["changed"]:
                analysis = "No deterministic change; AI not requested."
                analysis_class = "ai-note"
                analysis_is_html = False
            else:
                analysis = f"Not selected for AI assessment (budget: {report['ai_budget']} usable files)."
                analysis_class = "ai-note"
                analysis_is_html = False

            interested = bool(group.get("interested"))
            interested_cell = "yes" if interested else "no"
            interested_title = html.escape(group.get("interested_pattern") or "")
            if ai_usable:
                compared_cell, ai_flag = "YES", "1"
            elif ai_compared:
                compared_cell, ai_flag = "retry", "0"
            else:
                compared_cell, ai_flag = "no", "0"
            cycles_text = "; ".join(transition_text) or "single cycle"
            # data-* attributes drive the client-side filters.
            rows.append(
                "<tr class='{state}' data-changed='{changed}' data-interested='{intr}' data-ai='{ai}'>"
                "<td>{category}</td><td><code>{identity}</code></td>"
                "<td class='flag flag-{intr}' title='{intitle}'>{interested_cell}</td>"
                "<td class='flag flag-ai-{ai}'>{compared_cell}</td>"
                "<td>{cycles}</td><td class='{analysis_class}'>{analysis}</td></tr>".format(
                    state="changed" if group["changed"] else "same",
                    changed="1" if group["changed"] else "0",
                    intr="1" if interested else "0",
                    ai=ai_flag,
                    category=html.escape(group["category"]),
                    identity=html.escape(group["identity"]),
                    intitle=interested_title,
                    interested_cell=interested_cell,
                    compared_cell=compared_cell,
                    cycles=html.escape(cycles_text),
                    analysis_class=analysis_class,
                    analysis=analysis if analysis_is_html else html.escape(analysis).replace("\n", "<br>"),
                )
            )

        style = (
            "body{font:14px Segoe UI,sans-serif;margin:24px;color:#222}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ccc;padding:8px;vertical-align:top;text-align:left}"
            "th{position:sticky;top:0;background:#f3f3f3;cursor:default}"
            ".changed{background:#fff9f2}.same{color:#666}.ai-note{color:#888;font-style:italic}"
            "code{font-size:12px;background:#f0f0f0;padding:0 3px;border-radius:3px}"
            ".flag{text-align:center;font-weight:600}"
            ".flag-1{color:#0a7d00}.flag-0{color:#999}"
            ".flag-ai-1{color:#0a58ca}.flag-ai-0{color:#999}"
            ".controls{margin:12px 0;padding:10px;background:#f7f7f7;border:1px solid #ddd;border-radius:6px}"
            ".controls input[type=text]{padding:5px;width:280px}"
            ".controls label{margin-right:14px;user-select:none}"
            ".pill{display:inline-block;padding:2px 8px;margin-right:8px;border-radius:10px;background:#eee}"
            "ul.findings{margin:0;padding-left:2px;list-style:none}"
            "ul.findings li{margin:0 0 7px 0;padding:5px 7px;border-left:4px solid #ccc;background:#fafafa;line-height:1.45}"
            "li.f-critical{border-left-color:#c62828;background:#fdecea}"
            "li.f-warning{border-left-color:#e08600;background:#fff6e5}"
            "li.f-info{border-left-color:#0a58ca;background:#eef3fc}"
            "li.f-ok{border-left-color:#0a7d00;background:#eefaef}"
            ".badge{display:inline-block;font-size:10px;font-weight:700;color:#fff;padding:1px 6px;border-radius:9px;margin-right:6px;vertical-align:middle}"
            ".badge-critical{background:#c62828}.badge-warning{background:#e08600}"
            ".badge-info{background:#0a58ca}.badge-ok{background:#0a7d00}"
            ".flag-ai-retry{color:#e08600;font-weight:600;text-align:center}"
            # CSS-driven filtering: the browser hides whole row sets with one
            # style recalc instead of 15k per-row JS writes.
            "#tbl.f-ai tbody tr[data-ai='0']{display:none}"
            "#tbl.f-int tbody tr[data-interested='0']{display:none}"
            "#tbl.f-chg tbody tr[data-changed='0']{display:none}"
            "#tbl tbody tr.qhide{display:none}"
        )
        summary = (
            f"<p>Cycles: {html.escape(str(report['cycles']))} &nbsp;|&nbsp; "
            f"<span class='pill'>files: {report['group_count']}</span>"
            f"<span class='pill'>changed: {report['changed_group_count']}</span>"
            f"<span class='pill'>interested: {report.get('interested_group_count', 0)}</span>"
            f"<span class='pill'>AI compared (usable): {report.get('ai_compared_count', 0)}</span>"
            f"<span class='pill'>AI budget: {report['ai_budget']} usable files</span>"
            f"<span class='pill'>LLM calls: {report.get('ai_attempted_count', 0)}</span>"
            f"<span class='pill'>preamble-only skipped: {report.get('ai_preamble_count', 0)}</span>"
            f"<span class='pill'>settings patterns: {report.get('interested_pattern_count', 0)}</span>"
            f" &nbsp;AI: {'enabled' if report['ai_enabled'] else 'disabled'}</p>"
        )
        if report.get("ai_unavailable_reason"):
            summary += (
                "<div style='background:#fdecea;border:1px solid #c62828;"
                "padding:12px;margin:12px 0;border-radius:5px'>"
                "<strong>AI unavailable before analysis:</strong> "
                + html.escape(report["ai_unavailable_reason"])
                + f"<br>{report.get('ai_unavailable_count', 0)} selected files "
                "were not sent. Deterministic cross-cycle differences remain available."
                "</div>"
            )
        controls = (
            "<div class='controls'>"
            "<input type='text' id='q' placeholder='filter by file name / text...' oninput='applyFilters()'>"
            "&nbsp;&nbsp;"
            "<label><input type='checkbox' id='fAI' onclick='applyFilters()' checked> AI compared (usable) only</label>"
            "<label><input type='checkbox' id='fInt' onclick='applyFilters()'> Interested only</label>"
            "<label><input type='checkbox' id='fChg' onclick='applyFilters()'> Changed only</label>"
            "<span id='count' style='margin-left:10px;color:#555'></span>"
            "</div>"
        )
        # The three boolean filters are applied by toggling one class on the
        # table (no per-row JS). Only the free-text query walks rows, and it
        # reads textContent of the two label cells -- textContent is layout
        # free, unlike innerText which forced a reflow per row and froze the
        # browser on multi-thousand-row reports.
        script = (
            "<script>var _rows=null,_qprev='';"
            "function _index(tbl){var out=[];var nl=tbl.tBodies[0].rows;"
            "for(var i=0;i<nl.length;i++){var r=nl[i];"
            "out.push({e:r,h:false,"
            "t:(r.cells[0].textContent+' '+r.cells[1].textContent).toLowerCase(),"
            "a:r.getAttribute('data-ai')==='1',i:r.getAttribute('data-interested')==='1',"
            "c:r.getAttribute('data-changed')==='1'});}return out;}"
            "function applyFilters(){"
            "var tbl=document.getElementById('tbl');"
            "var q=document.getElementById('q').value.trim().toLowerCase();"
            "var ai=document.getElementById('fAI').checked;"
            "var it=document.getElementById('fInt').checked;"
            "var ch=document.getElementById('fChg').checked;"
            "tbl.classList.toggle('f-ai',ai);"
            "tbl.classList.toggle('f-int',it);"
            "tbl.classList.toggle('f-chg',ch);"
            "if(_rows===null)_rows=_index(tbl);"
            "if(q!==_qprev){"
            "for(var j=0;j<_rows.length;j++){var o=_rows[j];"
            "var hide=q!==''&&o.t.indexOf(q)<0;"
            "if(hide!==o.h){o.h=hide;o.e.classList.toggle('qhide',hide);}}"
            "_qprev=q;}"
            "var shown=0;"
            "for(var k=0;k<_rows.length;k++){var p=_rows[k];"
            "if(!p.h&&(!ai||p.a)&&(!it||p.i)&&(!ch||p.c))shown++;}"
            "document.getElementById('count').innerText=shown+' shown of '+_rows.length;}"
            "window.addEventListener('load',applyFilters);</script>"
        )
        html_path.write_text(
            brand.brandify(
                "<!doctype html><html><head><meta charset='utf-8'>"
                "<title>Cross-cycle Log Differences</title>"
                f"<style>{style}</style></head><body>"
                "<h1>Cross-cycle Log Differences</h1>"
                + summary + controls +
                # f-ai is baked into the initial markup so the browser never
                # lays out the non-AI rows on first paint.
                "<table id='tbl' class='f-ai'><thead><tr><th>Type</th><th>Log file (normalized)</th>"
                "<th>Interested</th><th>AI compared</th><th>Deterministic diff</th>"
                "<th>AI assessment</th></tr></thead><tbody>"
                + "".join(rows) + "</tbody></table>" + script + "</body></html>",
                "Cross-cycle Diff"),
            encoding="utf-8",
        )
        logger.info("Cross-cycle reports written to %s and %s", json_path, html_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare same-identity log files across consecutive test-cycle folders")
    parser.add_argument("--scan_folder", required=True,
                        help="Run folder containing one sub-folder per test cycle.")
    parser.add_argument("--no_ai", action="store_true",
                        help="Deterministic diff only; do not call an AI backend.")
    parser.add_argument("--max_ai_groups", type=int, default=DEFAULT_AI_BUDGET,
                        help="Total number of log files to AI-compare across cycles (budget).")
    parser.add_argument("--settings", default=None,
                        help="Path to a settings JSON providing interested error_signatures[].file patterns.")
    parser.add_argument("--file_patterns", default=None,
                        help="Comma-separated 'Category=glob' (or bare 'glob') entries that select and "
                             "categorise log files to compare; first match wins. Default: "
                             + ",".join(f"{c}={g}" for c, g in DEFAULT_FILE_CATEGORY_PATTERNS)
                             + " (env: LOG_ANALYZER_CYCLE_DIFF_FILE_PATTERNS).")
    parser.add_argument("--collector_prefixes", default=None,
                        help="Comma-separated name prefixes of log-collector folders inside a cycle "
                             "folder (default: " + ",".join(DEFAULT_COLLECTOR_PREFIXES)
                             + "; env: LOG_ANALYZER_COLLECTOR_PREFIXES).")
    parser.add_argument("--render_only", action="store_true",
                        help="Re-render the HTML report from an existing cycle_diff_report.json (no LLM calls).")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    file_patterns = parse_file_patterns(args.file_patterns) or None
    collector_prefixes = parse_prefixes(args.collector_prefixes) or None
    if args.render_only:
        analyzer = CycleDiffAnalyzer(args.scan_folder, False, args.max_ai_groups, settings_path=args.settings,
                                     file_patterns=file_patterns, collector_prefixes=collector_prefixes)
        json_path = analyzer.scan_folder / "cycle_diff_report.json"
        report = json.loads(json_path.read_text(encoding="utf-8"))
        analyzer.write_reports(report)
        logger.info("Re-rendered HTML from %s (no LLM calls)", json_path)
        return 0
    report = CycleDiffAnalyzer(
        args.scan_folder, not args.no_ai, args.max_ai_groups, settings_path=args.settings,
        file_patterns=file_patterns, collector_prefixes=collector_prefixes,
    ).run()
    if len(report["cycles"]) < 2:
        logger.warning("Need at least two cycle folders; found %s", report["cycles"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())