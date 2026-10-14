# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Guardrails that keep private data out of this public repository."""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import check_public_release  # noqa: E402


def _labels_for(line):
    return {label for label, pattern in check_public_release.GENERIC_RULES if pattern.search(line)}


def test_repository_has_no_leaks():
    rules = check_public_release.GENERIC_RULES + check_public_release.load_local_rules()
    findings = check_public_release.scan(check_public_release.candidate_files(), rules)
    assert findings == [], "\n".join(f"{f}:{n}: [{label}] {hit}" for f, n, label, hit in findings)


def test_checker_detects_generic_leaks():
    assert "private IPv4 address" in _labels_for('server = "10.1.2.3"')  # public-release: allow
    assert "private IPv4 address" in _labels_for("http://192.168.0.10:8000/v1")  # public-release: allow
    assert "UNC share path" in _labels_for(r"copy to \\fileserver\logs")  # public-release: allow
    assert "credential value in JSON" in _labels_for('"password": "hunter2"')  # public-release: allow
    assert "e-mail address" in _labels_for("contact someone@example.com")  # public-release: allow
    assert "personal home path" in _labels_for("/home/alice/project")  # public-release: allow


def test_checker_ignores_safe_values():
    assert not _labels_for('"api_url": "http://localhost:11434/v1/chat/completions"')
    assert not _labels_for(r'"good_log": "..\\common\\good_dmesg.log"')
    assert not _labels_for('"password": ""')
    assert not _labels_for("version 10.0.20348")


def test_email_allowlist_matches_exact_domain_only():
    allowed = check_public_release.is_allowed
    assert allowed("e-mail address", "1+bot@users.noreply.github.com")  # public-release: allow
    assert not allowed("e-mail address", "x@users.noreply.github.com.example.org")  # public-release: allow
    assert not allowed("e-mail address", "x@evilusers.noreply.github.com")  # public-release: allow
    assert allowed("internal URL", "aka.ms/security")
    assert not allowed("internal URL", "aka.ms/private-link")  # public-release: allow


def test_python_files_have_copyright_header():
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],
                         cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.split()
    missing = []
    for rel in out:
        head = (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()[:3]
        if "# Copyright (c) Microsoft Corporation." not in head \
                or "# Licensed under the MIT License." not in head:
            missing.append(rel)
    assert missing == []


def test_only_public_settings_are_tracked():
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "sut"],
                         cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.split()
    settings = sorted(p for p in out if Path(p).name.startswith("settings."))
    assert settings == ["sut/settings.ocp_diag.json", "sut/settings.sample.json"]


# Copyleft packages this project has depended on before; MIT-licensed
# replacements exist (rapidfuzz, charset-normalizer).
COPYLEFT_PACKAGES = {"fuzzywuzzy", "python-levenshtein", "levenshtein", "chardet"}


def test_requirements_have_no_copyleft_packages():
    names = set()
    for line in (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(re.split(r"[<>=!~;\[ ]", line, 1)[0].strip().lower())
    assert not names & COPYLEFT_PACKAGES
