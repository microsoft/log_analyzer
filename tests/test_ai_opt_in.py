# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AI analysis must be opt-in, and AI output must be labelled as such."""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))
sys.path.insert(0, str(REPO_ROOT / "log_analyzer"))

import ai_backend  # noqa: E402
import brand  # noqa: E402
import md_report_html  # noqa: E402

NOTICE = "AI-generated, may be inaccurate, verify against the log evidence."

FAKE_AI = r'''
import pathlib, re, sys
prompt = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
with open(sys.argv[2], "a", encoding="utf-8") as marker:
    marker.write("called\n")
ready = re.search(r"exactly (\w+_READY)", prompt)
print(ready.group(1) if ready else "FAKE-AI summary: kernel hardware error found.")
'''


def test_notice_text_is_shared():
    assert ai_backend.AI_NOTICE == NOTICE
    assert brand.AI_NOTICE == NOTICE
    assert md_report_html.AI_NOTICE == NOTICE


def test_ai_is_off_by_default(monkeypatch):
    monkeypatch.delenv("LOG_ANALYZER_AI", raising=False)
    assert ai_backend.ai_enabled() is False
    assert ai_backend.ai_enabled(True) is True
    monkeypatch.setenv("LOG_ANALYZER_AI", "1")
    assert ai_backend.ai_enabled() is True
    monkeypatch.setenv("LOG_ANALYZER_AI", "0")
    assert ai_backend.ai_enabled() is False


def test_custom_command_from_environment(monkeypatch):
    monkeypatch.setenv("LOG_ANALYZER_AI_CLI_COMMAND", json.dumps(["tool", "{prompt_file}"]))
    assert ai_backend.load_llm_config()["ai_cli"]["custom_command"] == ["tool", "{prompt_file}"]


def test_brandify_adds_notice_once():
    page = "<html><head><title>t</title></head><body><p>x</p></body></html>"
    plain = brand.brandify(page, "Tool")
    assert NOTICE not in plain
    labelled = brand.brandify(page, "Tool", ai_generated=True)
    assert labelled.count(NOTICE) == 1
    assert labelled.index("labanner") < labelled.index(NOTICE) < labelled.index("<p>x</p>")
    assert brand.add_ai_notice(labelled) == labelled
    # Already-branded pages (e.g. written by an agent) still get the notice.
    assert brand.brandify(plain, "Tool", ai_generated=True).count(NOTICE) == 1


def test_markdown_deliverables_are_labelled(tmp_path):
    ai_md = tmp_path / "copilot_deep_analysis.md"
    ai_md.write_text("# Deep\nsome finding\n", encoding="utf-8")
    other_md = tmp_path / "notes.md"
    other_md.write_text("# Notes\nhuman text\n", encoding="utf-8")
    assert NOTICE in Path(md_report_html.convert(str(ai_md))).read_text(encoding="utf-8")
    assert NOTICE not in Path(md_report_html.convert(str(other_md))).read_text(encoding="utf-8")


def _scan_folder(tmp_path):
    scan = tmp_path / "scan"
    (scan / "cycle_1").mkdir(parents=True)
    (scan / "cycle_2").mkdir()
    (scan / "cycle_1" / "dmesg_a.log").write_text(
        "[1.0] Severity=err Hardware Error: machine check\n", encoding="utf-8")
    (scan / "cycle_2" / "dmesg_a.log").write_text("[1.0] all good\n", encoding="utf-8")
    return scan


def _run(tmp_path, scan, *extra):
    fake = tmp_path / "fake_ai.py"
    fake.write_text(FAKE_AI, encoding="utf-8")
    marker = tmp_path / "ai_called.txt"
    env = dict(os.environ)
    env.pop("LOG_ANALYZER_AI", None)
    env.update({
        "LOG_ANALYZER_AI_CLI": "custom",
        "LOG_ANALYZER_AI_CLI_COMMAND": json.dumps([sys.executable, str(fake), "{prompt_file}",
                                                   str(marker)]),
        "LOG_ANALYZER_AI_PREFLIGHT": "0",
    })
    cmd = [sys.executable, str(REPO_ROOT / "log_analyzer" / "log_analyzer.py"),
           "--scan_folder", str(scan), "--signature", "sample", *extra]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                          timeout=600)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    return marker


def test_default_run_never_calls_ai(tmp_path):
    scan = _scan_folder(tmp_path)
    marker = _run(tmp_path, scan, "--result_analyzer", "true", "--cycle_diff", "true",
                  "--deep_analysis", "true", "--ado_search", "true")
    assert not marker.exists()
    assert not (scan / "error_signatures_summary.log").exists()
    assert "Hardware Error" in (scan / "error_signatures.log").read_text(encoding="utf-8")


def test_ai_run_labels_its_output(tmp_path):
    scan = _scan_folder(tmp_path)
    marker = _run(tmp_path, scan, "--ai")
    assert marker.exists()
    summary = (scan / "error_signatures_summary.log").read_text(encoding="utf-8")
    assert "FAKE-AI summary" in summary
    assert NOTICE in summary
    assert NOTICE in (scan / "error_signatures_summary.html").read_text(encoding="utf-8")
    assert json.loads((scan / "error_signatures_summary.json").read_text(
        encoding="utf-8"))["ai_notice"] == NOTICE


def test_no_ai_overrides_ai(tmp_path):
    scan = _scan_folder(tmp_path)
    marker = _run(tmp_path, scan, "--ai", "--no_ai")
    assert not marker.exists()


def test_test_report_is_labelled_only_when_ai_ran(tmp_path):
    import result_analyzer

    analyzer = result_analyzer.LogAnalyzer(str(tmp_path))
    plain = tmp_path / "plain.html"
    analyzer.generate_html_report([], plain)
    assert NOTICE not in plain.read_text(encoding="utf-8")

    analyzer.stats["llm_calls"] = 1
    labelled = tmp_path / "labelled.html"
    analyzer.generate_html_report([], labelled)
    assert NOTICE in labelled.read_text(encoding="utf-8")


def test_cycle_diff_is_labelled_only_when_ai_text_is_shown(tmp_path):
    import cycle_diff_analyzer

    group = {"ai_compared": True, "ai_analysis": "AI says x"}
    assert cycle_diff_analyzer._has_ai_text({"groups": {"g": group}})
    assert not cycle_diff_analyzer._has_ai_text({"groups": {"g": {"ai_compared": False}}})
    assert not cycle_diff_analyzer.CycleDiffAnalyzer(str(tmp_path)).use_ai
