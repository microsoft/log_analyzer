#!/usr/bin/env python3
"""Pre-publish leak check for this repository.

Scans every tracked and untracked (non-ignored) text file for data that must
never reach a public repository: private IP addresses, credentials, e-mail
addresses, internal URLs, UNC shares and absolute personal paths.

Organisation-specific terms (project code names, lab names, internal key
names, ...) must NOT be listed here, because this file is public. Put them in
``tools/public_release_denylist.local.txt`` (git-ignored), one regular
expression per line; lines starting with ``#`` are comments.

Usage::

    python tools/check_public_release.py           # exit 1 when anything is found
    python tools/check_public_release.py --list    # also list scanned files

A line can be exempted with an inline ``public-release: allow`` marker.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL_DENYLIST = REPO_ROOT / "tools" / "public_release_denylist.local.txt"
ALLOW_MARKER = "public-release: allow"

BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".db", ".sqlite",
                   ".zip", ".gz", ".7z", ".xlsx", ".pyc", ".exe", ".dll", ".pdf"}

# Microsoft open-source template files legitimately carry these addresses.
ALLOWED_EMAILS = {"opencode@microsoft.com", "secure@microsoft.com", "cla@microsoft.com"}
# Public short links used by the Microsoft open-source template files.
ALLOWED_SHORT_LINKS = {"aka.ms/security", "aka.ms/onboardsupport", "aka.ms/spot",
                       "aka.ms/opensource", "aka.ms/msrc"}

GENERIC_RULES = [
    ("private IPv4 address",
     re.compile(r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.])")),
    ("link-local IPv4 address", re.compile(r"(?<![\d.])169\.254\.\d{1,3}\.\d{1,3}(?![\d.])")),
    ("e-mail address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")),
    # UNC paths in plain text or inside JSON/Python strings (escaped backslashes).
    ("UNC share path",
     re.compile(r"(?<![\w\\.:])(?:\\\\|\\\\\\\\)[A-Za-z][A-Za-z0-9_.-]+(?:\\|\\\\)[A-Za-z0-9_$.-]+")),
    ("personal home path",
     re.compile(r"(?i)(?:/home/|/Users/|C:\\{1,2}Users\\{1,2})(?!<|\{|\$|%|\*|username\b|you\b|user\b|name\b|public\b)[A-Za-z0-9._-]+")),
    ("internal URL", re.compile(r"(?i)\b(?:[a-z0-9-]+\.visualstudio\.com|[a-z0-9-]+\.sharepoint\.com|"
                                r"idweb\.microsoft\.com|aka\.ms/[A-Za-z0-9_-]+|"
                                r"vault\.azure\.net|[a-z0-9-]+\.corp\.microsoft\.com)")),
    ("Azure DevOps organisation URL", re.compile(r"(?i)dev\.azure\.com/(?!\{|<|your)[A-Za-z0-9_-]+")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("credential value in JSON",
     re.compile(r'(?i)"[A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api_key)"\s*:\s*"(?!\s*"|<|your|\$\{)[^"]+"')),
]


def load_local_rules():
    rules = []
    if LOCAL_DENYLIST.is_file():
        for raw in LOCAL_DENYLIST.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append(("local denylist term", re.compile(line, re.IGNORECASE)))
            except re.error as exc:
                print(f"warning: bad denylist pattern {line!r}: {exc}", file=sys.stderr)
    return rules


def candidate_files():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
        paths = [REPO_ROOT / p for p in out.splitlines() if p.strip()]
    except Exception:
        paths = [p for p in REPO_ROOT.rglob("*") if ".git" not in p.parts]
    return [p for p in paths
            if p.is_file() and p.suffix.lower() not in BINARY_SUFFIXES
            and p.resolve() != LOCAL_DENYLIST.resolve()]


def scan(paths, rules):
    findings = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if ALLOW_MARKER in line:
                continue
            for label, pattern in rules:
                for match in pattern.finditer(line):
                    hit = match.group(0)
                    if label == "e-mail address" and (
                            hit.lower() in ALLOWED_EMAILS or hit.lower().endswith("noreply.github.com")):
                        continue
                    if label == "internal URL" and hit.lower() in ALLOWED_SHORT_LINKS:
                        continue
                    if label == "credential value in JSON":
                        hit = hit.split(":")[0] + ': "<redacted>"'
                    findings.append((rel, lineno, label, hit))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pre-publish leak check.")
    parser.add_argument("--list", action="store_true", help="list scanned files")
    args = parser.parse_args(argv)

    rules = GENERIC_RULES + load_local_rules()
    files = candidate_files()
    if args.list:
        for f in files:
            print("scan:", f.relative_to(REPO_ROOT).as_posix())
    findings = scan(files, rules)
    for rel, lineno, label, hit in findings:
        print(f"{rel}:{lineno}: [{label}] {hit}")
    local = "with" if LOCAL_DENYLIST.is_file() else "WITHOUT"
    print(f"Scanned {len(files)} files {local} a local denylist: {len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
