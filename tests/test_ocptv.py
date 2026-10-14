# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OCP Test and Validation (spec v2.0) diagnostic output support."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

import ocptv  # noqa: E402
import lib_log  # noqa: E402


def _artifacts(run_result="FAIL", include_end=True):
    arts = [
        {"schemaVersion": {"major": 2, "minor": 0}, "sequenceNumber": 0, "timestamp": "2024-01-01T00:00:00Z"},
        {"testRunArtifact": {"testRunStart": {
            "name": "accel_diag", "version": "1.0", "commandLine": "", "parameters": {},
            "dutInfo": {"dutInfoId": "dut0", "hardwareInfos": [
                {"hardwareInfoId": "hw0", "name": "accelerator0", "location": "slot 1",
                 "serialNumber": "SN-EXAMPLE-0"}]}}},
         "sequenceNumber": 1, "timestamp": "2024-01-01T00:00:01Z"},
        {"testStepArtifact": {"testStepId": "0", "testStepStart": {"name": "memory bandwidth"}},
         "sequenceNumber": 2, "timestamp": "2024-01-01T00:00:02Z"},
        {"testStepArtifact": {"testStepId": "0", "measurement": {
            "name": "bandwidth", "value": 10, "unit": "GB/s", "hardwareInfoId": "hw0",
            "validators": [{"type": "GREATER_THAN", "value": 50}]}},
         "sequenceNumber": 3, "timestamp": "2024-01-01T00:00:03Z"},
        {"testStepArtifact": {"testStepId": "0", "measurement": {
            "name": "temperature", "value": 40, "unit": "C",
            "validators": [{"type": "LESS_THAN", "value": 85}]}},
         "sequenceNumber": 4, "timestamp": "2024-01-01T00:00:04Z"},
        {"testStepArtifact": {"testStepId": "0", "diagnosis": {
            "verdict": "mem-bw-low", "type": "FAIL", "message": "bandwidth below limit",
            "hardwareInfoId": "hw0"}},
         "sequenceNumber": 5, "timestamp": "2024-01-01T00:00:05Z"},
        {"testStepArtifact": {"testStepId": "0", "error": {
            "symptom": "driver-timeout", "message": "driver did not respond"}},
         "sequenceNumber": 6, "timestamp": "2024-01-01T00:00:06Z"},
        {"testStepArtifact": {"testStepId": "0", "log": {"severity": "FATAL", "message": "giving up"}},
         "sequenceNumber": 7, "timestamp": "2024-01-01T00:00:07Z"},
        {"testStepArtifact": {"testStepId": "0", "measurementSeriesStart": {
            "measurementSeriesId": "s0", "name": "fan rpm", "unit": "RPM",
            "validators": [{"type": "GREATER_THAN_OR_EQUAL", "value": 1000}]}},
         "sequenceNumber": 8, "timestamp": "2024-01-01T00:00:08Z"},
        {"testStepArtifact": {"testStepId": "0", "measurementSeriesElement": {
            "measurementSeriesId": "s0", "index": 0, "value": 400, "timestamp": "2024-01-01T00:00:09Z"}},
         "sequenceNumber": 9, "timestamp": "2024-01-01T00:00:09Z"},
        {"testStepArtifact": {"testStepId": "0", "testStepEnd": {"status": "ERROR"}},
         "sequenceNumber": 10, "timestamp": "2024-01-01T00:00:10Z"},
    ]
    if include_end:
        arts.append({"testRunArtifact": {"testRunEnd": {"status": "COMPLETE", "result": run_result}},
                     "sequenceNumber": 11, "timestamp": "2024-01-01T00:00:11Z"})
    return arts


def _passing_artifacts():
    return [
        {"schemaVersion": {"major": 2, "minor": 0}, "sequenceNumber": 0, "timestamp": "t0"},
        {"testRunArtifact": {"testRunStart": {"name": "clean_diag", "version": "1", "commandLine": "",
                                              "parameters": {}, "dutInfo": {"dutInfoId": "d"}}},
         "sequenceNumber": 1, "timestamp": "t1"},
        {"testStepArtifact": {"testStepId": "0", "testStepStart": {"name": "check"}},
         "sequenceNumber": 2, "timestamp": "t2"},
        {"testStepArtifact": {"testStepId": "0", "log": {"severity": "WARNING", "message": "minor"}},
         "sequenceNumber": 3, "timestamp": "t3"},
        {"testStepArtifact": {"testStepId": "0", "measurement": {
            "name": "voltage", "value": 12.0, "validators": [{"type": "IN_SET", "value": [12.0, 12.1]}]}},
         "sequenceNumber": 4, "timestamp": "t4"},
        {"testStepArtifact": {"testStepId": "0", "diagnosis": {"verdict": "ok", "type": "PASS"}},
         "sequenceNumber": 5, "timestamp": "t5"},
        {"testStepArtifact": {"testStepId": "0", "testStepEnd": {"status": "COMPLETE"}},
         "sequenceNumber": 6, "timestamp": "t6"},
        {"testRunArtifact": {"testRunEnd": {"status": "COMPLETE", "result": "PASS"}},
         "sequenceNumber": 7, "timestamp": "t7"},
    ]


def write_jsonl(path, arts, prefix=""):
    path.write_text("".join(prefix + json.dumps(a) + "\n" for a in arts), encoding="utf-8")
    return path


def write_indented(path, arts):
    path.write_text("".join(json.dumps(a, indent=4) + "," for a in arts), encoding="utf-8")
    return path


LEGACY_LINES = [
    {"testRunArtifact": {"testRunStart": {"name": "old", "version": "1"}}, "sequenceNumber": 0, "timestamp": "t"},
    {"testRunArtifact": {"log": {"severity": "ERROR", "text": "old style"}}, "sequenceNumber": 1, "timestamp": "t"},
]


# --------------------------------------------------------------------------- #
# Detection and parsing
# --------------------------------------------------------------------------- #

def test_sniff_layouts(tmp_path):
    assert ocptv.sniff(write_jsonl(tmp_path / "a.jsonl", _artifacts())) == ocptv.JSONL
    assert ocptv.sniff(write_jsonl(tmp_path / "p.json", _artifacts(), prefix="[pylog] ")) == ocptv.JSONL
    assert ocptv.sniff(write_indented(tmp_path / "b.json", _artifacts())) == ocptv.INDENTED
    assert ocptv.sniff(write_jsonl(tmp_path / "c.jsonl", LEGACY_LINES)) == ocptv.LEGACY
    plain = tmp_path / "d.json"
    plain.write_text('{"items": [1, 2]}', encoding="utf-8")
    assert ocptv.sniff(plain) is None


def test_indented_and_jsonl_produce_identical_records(tmp_path):
    a_log, _, _ = ocptv.convert_file(write_jsonl(tmp_path / "a.jsonl", _artifacts()))
    b_log, _, _ = ocptv.convert_file(write_indented(tmp_path / "b.json", _artifacts()))
    strip = lambda p: [line.rsplit(" seq=", 1)[0] for line in p.read_text(encoding="utf-8").splitlines()]
    assert strip(a_log) == strip(b_log)


def test_normalized_lines_carry_context(tmp_path):
    log_path, csv_path, counts = ocptv.convert_file(write_jsonl(tmp_path / "run.jsonl", _artifacts()))
    lines = log_path.read_text(encoding="utf-8").splitlines()
    diag = next(line for line in lines if "artifact=diagnosis" in line)
    assert diag.startswith("[OCPTV] FAIL artifact=diagnosis run=accel_diag step=0:\"memory bandwidth\"")
    assert "verdict=mem-bw-low" in diag and "accelerator0 (slot 1, SN-EXAMPLE-0)" in diag
    bw = next(line for line in lines if "name=bandwidth" in line)
    assert bw.startswith("[OCPTV] FAIL artifact=measurement") and "compliant=false" in bw
    temp = next(line for line in lines if "name=temperature" in line)
    assert temp.startswith("[OCPTV] PASS artifact=measurement")
    series = next(line for line in lines if "artifact=measurementSeriesElement" in line)
    assert series.startswith("[OCPTV] FAIL") and 'name="fan rpm"' in series
    assert any(line.startswith("[OCPTV] ERROR artifact=log severity=FATAL") for line in lines)
    assert any(line.startswith("[OCPTV] ERROR artifact=testStepEnd status=ERROR") for line in lines)
    assert any(line.startswith("[OCPTV] FAIL artifact=testRunEnd status=COMPLETE result=FAIL") for line in lines)
    assert csv_path.read_text(encoding="utf-8").splitlines()[0].startswith("seq,timestamp,run,step_id")
    assert counts["FAIL"] == 4


def test_corrupted_fragment_is_reported(tmp_path):
    src = write_jsonl(tmp_path / "bad.jsonl", _artifacts())
    src.write_text(src.read_text(encoding="utf-8") + '{"testRunArtifact": {"log": {"sever\n',
                   encoding="utf-8")
    log_path, _, _ = ocptv.convert_file(src)
    assert "[OCPTV] ERROR artifact=parse" in log_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("value,validator,expected", [
    (5, {"type": "EQUAL", "value": 5}, True),
    ("abc", {"type": "NOT_EQUAL", "value": "abc"}, False),
    (3, {"type": "LESS_THAN", "value": 3}, False),
    (3, {"type": "LESS_THAN_OR_EQUAL", "value": 3}, True),
    (4, {"type": "GREATER_THAN", "value": 3}, True),
    (2, {"type": "GREATER_THAN_OR_EQUAL", "value": 3}, False),
    ("link up x16", {"type": "REGEX_MATCH", "value": ["x8", "x16"]}, True),
    ("error", {"type": "REGEX_NO_MATCH", "value": "err"}, False),
    ("b", {"type": "IN_SET", "value": ["a", "b"]}, True),
    (1, {"type": "NOT_IN_SET", "value": [1, 2]}, False),
    ("n/a", {"type": "LESS_THAN", "value": 3}, None),
    (1, {"type": "SOMETHING_NEW", "value": 3}, None),
])
def test_validators(value, validator, expected):
    assert ocptv.evaluate_validator(value, validator) is expected


def test_convert_folder_skips_legacy(tmp_path):
    write_jsonl(tmp_path / "new.jsonl", _artifacts())
    write_jsonl(tmp_path / "old.jsonl", LEGACY_LINES)
    converted, legacy = ocptv.convert_folder(tmp_path)
    assert [p.name for p in converted] == ["new.jsonl"]
    assert [p.name for p in legacy] == ["old.jsonl"]
    assert not (tmp_path / "old.ocptv.log").exists()


# --------------------------------------------------------------------------- #
# JSON match_type
# --------------------------------------------------------------------------- #

def test_json_match_type_reads_json_lines(tmp_path):
    src = tmp_path / "events.jsonl"
    src.write_text('{"Severity": "OK"}\n{"Severity": "Critical", "Message": "fan"}\n', encoding="utf-8")

    class Sink:
        def write(self, _text):
            pass

    sig = {"error_text": [{"Severity": "Critical"}], "whitelist_text": []}
    matched, error = lib_log.analyze_json_file(str(src), sig, Sink())
    assert error is None and len(matched) == 1


def test_json_match_type_reports_unparseable_file(tmp_path):
    src = tmp_path / "broken.json"
    src.write_text('{"Severity": "Critical", ', encoding="utf-8")

    class Sink:
        def write(self, _text):
            pass

    matched, error = lib_log.analyze_json_file(str(src), {"error_text": [{"Severity": "x"}]}, Sink())
    assert matched == [] and error


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #

def _run_cli(scan, *extra):
    cmd = [sys.executable, str(REPO_ROOT / "log_analyzer" / "log_analyzer.py"),
           "--scan_folder", str(scan), "--no_ai", *extra]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    return (scan / "error_signatures.log").read_text(encoding="utf-8")


def test_cli_auto_detects_and_reports_ocp_failures(tmp_path):
    write_jsonl(tmp_path / "accel_diag.jsonl", _artifacts())
    write_indented(tmp_path / "harness_OCPTV.json", _artifacts(include_end=False))
    write_jsonl(tmp_path / "clean.jsonl", _passing_artifacts())
    summary = _run_cli(tmp_path, "--signature", "sample")

    assert "[OCPTV] FAIL artifact=diagnosis" in summary
    assert "[OCPTV] FAIL artifact=measurement" in summary
    assert "[OCPTV] FAIL artifact=measurementSeriesElement" in summary
    assert "[OCPTV] ERROR artifact=error" in summary
    assert "[OCPTV] FAIL artifact=testRunEnd" in summary
    assert "[OCPTV] ERROR artifact=testStepEnd" in summary
    assert "artifact=log severity=FATAL" in summary
    assert "Expect - artifact=testRunEnd - but not found" in summary
    assert "clean_diag" not in summary
    assert (tmp_path / "accel_diag.ocptv.csv").exists()
    assert not (tmp_path / "harness_OCPTV.csv").exists()


def test_cli_ocp_diag_false_skips_normalization(tmp_path):
    write_jsonl(tmp_path / "accel_diag.jsonl", _artifacts())
    summary = _run_cli(tmp_path, "--signature", "sample", "--ocp_diag", "false")
    assert "[OCPTV]" not in summary
    assert not (tmp_path / "accel_diag.ocptv.log").exists()
