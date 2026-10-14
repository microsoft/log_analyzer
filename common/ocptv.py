# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Normalize OCP Test and Validation diagnostic output into line-based records.

Diagnostics that follow the OCP Test and Validation Output Specification v2.0
(https://github.com/opencomputeproject/ocp-diag-core) emit one JSON
"artifact" per event. The analyzer's signature engine is line based, so this
module turns every artifact into ONE self-contained text line that also carries
the context the raw artifact only references by id (run name, step name,
hardware name/serial, measurement series limits)::

    [OCPTV] FAIL artifact=diagnosis run=gpu_diag step=0:"mem bw" verdict=mem-bw-low ...

and a fixed-column CSV next to it for spreadsheet review.

Two file layouts are recognised:

* ``jsonl`` - JSON Lines, one artifact per line (the specification's LDJSON).
* ``indented`` - artifacts pretty-printed over several lines and separated by
  commas, as written by some test harnesses (for example the OCP accelerator
  compliance tool).

Output from pre-2.0 (legacy OCPDiag) diagnostics uses different field names and
is detected but not normalized.

Stdlib only.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from pathlib import Path

PREFIX = "[OCPTV]"
LOG_SUFFIX = ".ocptv.log"
CSV_SUFFIX = ".ocptv.csv"
SOURCE_SUFFIXES = (".json", ".jsonl", ".ndjson")
SNIFF_BYTES = 64 * 1024

CSV_COLUMNS = [
    "seq", "timestamp", "run", "step_id", "step_name", "artifact", "outcome",
    "severity", "status", "result", "verdict", "symptom", "message", "hardware",
    "name", "value", "unit", "limit", "compliant", "source",
]

_TOP_LEVEL_KEYS = ("schemaVersion", "testRunArtifact", "testStepArtifact")
# Text some emitters put in front of each JSON document (e.g. a logger tag).
_LINE_PREFIX_RE = re.compile(r"^[^{\[]*?(?=\{)")
_DECODER = json.JSONDecoder()

LEGACY = "legacy"
JSONL = "jsonl"
INDENTED = "indented"


# --------------------------------------------------------------------------- #
# Detection and reading
# --------------------------------------------------------------------------- #

def _first_document(text):
    """Return (document, consumed_text) for the first JSON object in *text*."""
    start = text.find("{")
    if start < 0:
        return None, ""
    try:
        obj, end = _DECODER.raw_decode(text, start)
    except ValueError:
        return None, ""
    return obj, text[start:end]


def _is_legacy(doc):
    """Pre-2.0 output: old field names or an explicit schema major < 2."""
    version = doc.get("schemaVersion")
    if isinstance(version, dict) and isinstance(version.get("major"), int):
        return version["major"] < 2
    for container in ("testRunArtifact", "testStepArtifact"):
        body = doc.get(container)
        if not isinstance(body, dict):
            continue
        log = body.get("log")
        if isinstance(log, dict) and "text" in log and "message" not in log:
            return True
        diag = body.get("diagnosis")
        if isinstance(diag, dict) and "verdict" not in diag and "symptom" in diag:
            return True
        meas = body.get("measurement")
        if isinstance(meas, dict) and "info" in meas and "element" in meas:
            return True
    return False


def sniff(path):
    """Return the layout of an OCP output file (jsonl/indented/legacy) or None."""
    path = Path(path)
    if path.name.endswith((LOG_SUFFIX, CSV_SUFFIX)):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(SNIFF_BYTES)
    except OSError:
        return None
    doc, raw = _first_document(head)
    if not isinstance(doc, dict) or not any(k in doc for k in _TOP_LEVEL_KEYS):
        return None
    # A file may start with the schemaVersion record; look further for the
    # first real artifact before deciding it is legacy.
    probe_docs = [doc]
    rest = head[head.find(raw) + len(raw):] if raw else ""
    for _ in range(5):
        nxt, nraw = _first_document(rest)
        if not isinstance(nxt, dict):
            break
        probe_docs.append(nxt)
        rest = rest[rest.find(nraw) + len(nraw):]
    if any(_is_legacy(d) for d in probe_docs):
        return LEGACY
    return INDENTED if "\n" in raw.strip() else JSONL


def iter_documents(path):
    """Yield ``(document, error)`` pairs from a JSONL or indented OCP file.

    Exactly one of the pair is set. Unparseable fragments are reported as
    errors instead of being skipped silently.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    pos, length = 0, len(text)
    while pos < length:
        while pos < length and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= length:
            break
        if text[pos] != "{":
            # Skip a prefix such as a logger tag up to the next object.
            line_end = text.find("\n", pos)
            line_end = length if line_end < 0 else line_end
            brace = text.find("{", pos, line_end)
            if brace < 0:
                fragment = text[pos:line_end].strip()
                if fragment and fragment not in ("[", "]"):
                    yield None, f"non-JSON text: {fragment[:120]}"
                pos = line_end + 1
                continue
            pos = brace
        try:
            doc, end = _DECODER.raw_decode(text, pos)
        except ValueError as exc:
            line_end = text.find("\n", pos)
            line_end = length if line_end < 0 else line_end
            yield None, f"invalid JSON ({exc.msg}): {text[pos:line_end].strip()[:120]}"
            pos = line_end + 1
            continue
        yield doc, None
        pos = end


# --------------------------------------------------------------------------- #
# Measurement validation
# --------------------------------------------------------------------------- #

def _as_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_list(value):
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _equal(a, b):
    na, nb = _as_number(a), _as_number(b)
    if na is not None and nb is not None:
        return na == nb
    return str(a).strip().lower() == str(b).strip().lower()


def evaluate_validator(value, validator):
    """True/False when the validator can be evaluated, None otherwise."""
    if not isinstance(validator, dict):
        return None
    kind = str(validator.get("type", "")).upper()
    limit = validator.get("value")
    try:
        if kind == "EQUAL":
            return _equal(value, limit)
        if kind == "NOT_EQUAL":
            return not _equal(value, limit)
        if kind in ("LESS_THAN", "LESS_THAN_OR_EQUAL", "GREATER_THAN", "GREATER_THAN_OR_EQUAL"):
            a, b = _as_number(value), _as_number(limit)
            if a is None or b is None:
                return None
            return {"LESS_THAN": a < b, "LESS_THAN_OR_EQUAL": a <= b,
                    "GREATER_THAN": a > b, "GREATER_THAN_OR_EQUAL": a >= b}[kind]
        if kind in ("REGEX_MATCH", "REGEX_NO_MATCH"):
            found = any(re.search(str(p), str(value)) for p in _as_list(limit))
            return found if kind == "REGEX_MATCH" else not found
        if kind in ("IN_SET", "NOT_IN_SET"):
            member = any(_equal(value, item) for item in _as_list(limit))
            return member if kind == "IN_SET" else not member
    except re.error:
        return None
    return None


def evaluate(value, validators):
    """Combine validators: False if any fails, None if none is decidable."""
    results = [evaluate_validator(value, v) for v in (validators or [])]
    decided = [r for r in results if r is not None]
    if not decided:
        return None
    return all(decided)


def describe_validators(validators):
    parts = []
    for v in validators or []:
        if isinstance(v, dict):
            value = v.get("value")
            if isinstance(value, (list, tuple)):
                value = "[" + "|".join(str(x) for x in value) + "]"
            parts.append(f"{v.get('type', '?')} {value}")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

class _RunState:
    """Context collected from earlier artifacts and reused by later ones."""

    def __init__(self):
        self.run_name = ""
        self.steps = {}
        self.hardware = {}
        self.series = {}


def _hardware_label(state, hw_id):
    if hw_id in (None, ""):
        return ""
    ids = hw_id if isinstance(hw_id, (list, tuple)) else [hw_id]
    labels = []
    for one in ids:
        info = state.hardware.get(str(one))
        if not info:
            labels.append(str(one))
            continue
        label = info.get("name") or str(one)
        extras = [info.get(k) for k in ("location", "serialNumber") if info.get(k)]
        labels.append(f"{label} ({', '.join(extras)})" if extras else label)
    return ", ".join(labels)


def _outcome_for(artifact, body):
    if artifact == "testRunEnd":
        status = str(body.get("status", "")).upper()
        result = str(body.get("result", "")).upper()
        if status == "ERROR":
            return "ERROR"
        if status == "SKIP" or result == "NOT_APPLICABLE":
            return "SKIP"
        if result == "FAIL":
            return "FAIL"
        return "PASS" if result == "PASS" else "UNKNOWN"
    if artifact == "testStepEnd":
        status = str(body.get("status", "")).upper()
        return {"ERROR": "ERROR", "SKIP": "SKIP", "COMPLETE": "PASS"}.get(status, "UNKNOWN")
    if artifact == "diagnosis":
        kind = str(body.get("type", "")).upper()
        return kind if kind in ("PASS", "FAIL", "UNKNOWN") else "UNKNOWN"
    if artifact == "error":
        return "ERROR"
    if artifact == "log":
        severity = str(body.get("severity", "")).upper()
        return "ERROR" if severity in ("ERROR", "FATAL") else (
            "WARN" if severity == "WARNING" else "INFO")
    return "INFO"


def _record(state, doc, source):
    """Turn one artifact document into a normalized record dict (or None)."""
    seq = doc.get("sequenceNumber", "")
    timestamp = doc.get("timestamp", "")
    if "schemaVersion" in doc and not any(k in doc for k in _TOP_LEVEL_KEYS[1:]):
        return None

    container = doc.get("testRunArtifact") or doc.get("testStepArtifact")
    if not isinstance(container, dict):
        return None
    step_id = str(container.get("testStepId", "")) if "testStepArtifact" in doc else ""
    artifact = next((k for k in container if k != "testStepId"), "")
    body = container.get(artifact)
    if not isinstance(body, dict):
        body = {"content": body}

    rec = {c: "" for c in CSV_COLUMNS}
    rec.update(seq=seq, timestamp=timestamp, step_id=step_id, artifact=artifact,
               source=source)

    if artifact == "testRunStart":
        state.run_name = str(body.get("name", ""))
        dut = body.get("dutInfo") or {}
        for hw in (dut.get("hardwareInfos") or []):
            if isinstance(hw, dict) and hw.get("hardwareInfoId") is not None:
                state.hardware[str(hw["hardwareInfoId"])] = hw
        rec["name"] = state.run_name
        rec["value"] = body.get("version", "")
    elif artifact == "testStepStart":
        state.steps[step_id] = str(body.get("name", ""))
        rec["name"] = state.steps[step_id]
    elif artifact in ("testRunEnd", "testStepEnd"):
        rec["status"] = body.get("status", "")
        rec["result"] = body.get("result", "")
    elif artifact == "log":
        rec["severity"] = body.get("severity", "")
        rec["message"] = body.get("message", "")
    elif artifact == "error":
        rec["symptom"] = body.get("symptom", "")
        rec["message"] = body.get("message", "")
    elif artifact == "diagnosis":
        rec["verdict"] = body.get("verdict", "")
        rec["message"] = body.get("message", "")
        rec["hardware"] = _hardware_label(state, body.get("hardwareInfoId"))
    elif artifact == "measurement":
        validators = body.get("validators") or []
        rec.update(name=body.get("name", ""), value=body.get("value", ""),
                   unit=body.get("unit", ""), limit=describe_validators(validators),
                   hardware=_hardware_label(state, body.get("hardwareInfoId")))
        rec["compliant"] = _compliance(body.get("value"), validators)
    elif artifact == "measurementSeriesStart":
        series_id = str(body.get("measurementSeriesId", ""))
        state.series[series_id] = body
        rec.update(name=body.get("name", ""), unit=body.get("unit", ""),
                   limit=describe_validators(body.get("validators")),
                   hardware=_hardware_label(state, body.get("hardwareInfoId")))
    elif artifact == "measurementSeriesElement":
        series = state.series.get(str(body.get("measurementSeriesId", ""))) or {}
        validators = series.get("validators") or []
        rec.update(name=series.get("name", ""), value=body.get("value", ""),
                   unit=series.get("unit", ""), limit=describe_validators(validators),
                   hardware=_hardware_label(state, series.get("hardwareInfoId")))
        rec["compliant"] = _compliance(body.get("value"), validators)
    elif artifact == "measurementSeriesEnd":
        series = state.series.get(str(body.get("measurementSeriesId", ""))) or {}
        rec.update(name=series.get("name", ""), value=body.get("totalCount", ""))
    elif artifact == "file":
        rec.update(name=body.get("displayName", ""), message=body.get("uri", ""))
    elif artifact == "extension":
        rec["name"] = body.get("name", "")
        rec["message"] = json.dumps(body.get("content"), separators=(",", ":"))[:500]
    else:
        rec["message"] = json.dumps(body, separators=(",", ":"))[:500]

    rec["run"] = state.run_name
    rec["step_name"] = state.steps.get(step_id, "")
    if artifact in ("measurement", "measurementSeriesElement"):
        rec["outcome"] = {"false": "FAIL", "true": "PASS"}.get(rec["compliant"], "INFO")
    else:
        rec["outcome"] = _outcome_for(artifact, body)
    return rec


def _compliance(value, validators):
    if not validators:
        return ""
    verdict = evaluate(value, validators)
    return "unknown" if verdict is None else ("true" if verdict else "false")


def _parse_error_record(message, source):
    rec = {c: "" for c in CSV_COLUMNS}
    rec.update(artifact="parse", outcome="ERROR", message=message, source=source)
    return rec


def _quote(value):
    text = str(value).replace("\r", " ").replace("\n", " ")
    if text == "" or re.search(r'[\s"=]', text):
        return '"' + text.replace('"', "'") + '"'
    return text


def format_line(rec):
    """Render a record as the fixed-order single line the signatures match.

    Order: prefix, outcome, artifact, then the state fields (severity, status,
    result) so signature terms such as ``artifact=log severity=FATAL`` are
    contiguous, then context and details.
    """
    parts = [PREFIX, rec["outcome"] or "INFO", f"artifact={rec['artifact']}"]
    for key in ("severity", "status", "result"):
        if rec.get(key) not in ("", None):
            parts.append(f"{key}={_quote(rec[key])}")
    if rec.get("run"):
        parts.append(f"run={_quote(rec['run'])}")
    if rec.get("step_id") != "":
        parts.append(f"step={rec['step_id']}:{_quote(rec.get('step_name', ''))}")
    for key, label in (("verdict", "verdict"), ("symptom", "symptom"), ("name", "name"),
                       ("value", "value"), ("unit", "unit"), ("limit", "limit"),
                       ("compliant", "compliant"), ("hardware", "hw"), ("message", "msg")):
        if rec.get(key) not in ("", None):
            parts.append(f"{label}={_quote(rec[key])}")
    parts.append(f"seq={rec.get('seq', '')}")
    if rec.get("timestamp"):
        parts.append(f"ts={rec['timestamp']}")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# Files and folders
# --------------------------------------------------------------------------- #

def output_paths(source):
    source = Path(source)
    stem = source.name
    for suffix in SOURCE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return source.with_name(stem + LOG_SUFFIX), source.with_name(stem + CSV_SUFFIX)


def convert_file(source, layout=None):
    """Normalize one OCP output file. Returns (log_path, csv_path, counts)."""
    source = Path(source)
    layout = layout or sniff(source)
    if layout not in (JSONL, INDENTED):
        raise ValueError(f"{source} is not OCP v2.0 output (layout={layout})")
    log_path, csv_path = output_paths(source)
    state = _RunState()
    counts = {}
    with open(log_path, "w", encoding="utf-8") as log_out, \
            open(csv_path, "w", encoding="utf-8", newline="") as csv_out:
        writer = csv.DictWriter(csv_out, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for doc, error in iter_documents(source):
            if error is not None:
                rec = _parse_error_record(error, source.name)
            elif isinstance(doc, dict):
                rec = _record(state, doc, source.name)
                if rec is None:
                    continue
            else:
                continue
            counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
            log_out.write(format_line(rec) + "\n")
            writer.writerow(rec)
    return log_path, csv_path, counts


def find_ocp_files(scan_folder):
    """Yield (path, layout) for every OCP output file under *scan_folder*."""
    for root, _dirs, files in os.walk(scan_folder):
        for name in sorted(files):
            if name.lower().endswith(SOURCE_SUFFIXES) and not name.startswith("settings."):
                path = Path(root) / name
                layout = sniff(path)
                if layout:
                    yield path, layout


def convert_folder(scan_folder):
    """Normalize every OCP v2.0 output file in a folder tree.

    Returns ``(converted, legacy)``: the source paths that were normalized, and
    the pre-2.0 files that were detected but skipped.
    """
    converted, legacy = [], []
    for path, layout in find_ocp_files(scan_folder):
        if layout == LEGACY:
            legacy.append(path)
            logging.info(f"OCP diag: legacy (pre-2.0) output not normalized: {path}")
            continue
        try:
            log_path, _csv_path, counts = convert_file(path, layout)
        except Exception as exc:
            logging.warning(f"OCP diag: could not normalize {path}: {exc}")
            continue
        converted.append(path)
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        logging.info(f"OCP diag: normalized {path.name} ({layout}) -> {log_path.name} [{summary}]")
    return converted, legacy
