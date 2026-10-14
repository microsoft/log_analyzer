#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Decide which platform a log folder belongs to, and which knowledge sources serve it.

The platform -> knowledge source mapping lives in ``sku_registry.json``
(optionally overridden by the git-ignored ``sku_registry.local.json``) and is
resolved here, so the AI steps never borrow another platform's known issues.

Detection is a three-way vote, deliberately kept auditable:

  1. explicit - ``SUT_SKU`` / ``sku`` inside ``sut.settings.*.json`` (what the
     test setup itself recorded), or a platform passed in by the caller;
  2. path     - platform tokens in the scan folder path or file names;
  3. content  - platform fingerprints inside a bounded sample of the log text.

Confidence is ``high`` when the platform was stated explicitly or two
independent votes agree, ``medium`` for a single content fingerprint and
``low`` for a single path token or an assumed default. When the votes actively
**disagree**, the result is ``None`` with the candidates listed and the caller
is expected to say so.

When the vote finds **no signal at all**, the registry's ``default_sku`` (if
set) is applied and reported as ``confidence='low', method='default'``. The
default is never used to break a tie: conflicting evidence still refuses.
"""
import json
import os
import re
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent / "sku_registry.json"
LOCAL_REGISTRY_NAME = "sku_registry.local.json"

# Signature packs live under the repository's sut/ folder. A pack may declare
# the platform it targets ("sku"), which is authoritative.
PACK_DIR = Path(__file__).resolve().parent.parent / "sut"
PACK_PATTERN = "settings.%s.json"

PLATFORM_ENV = "LOG_ANALYZER_PLATFORM"
KNOWLEDGE_ROLES = ("issue_source", "kb", "testplan")

CONTENT_EXTS = {".log", ".txt", ".json", ".csv", ".md", ".ini", ".cfg"}
CONTENT_MAX_FILES = 60
CONTENT_MAX_BYTES_PER_FILE = 256 * 1024
CONTENT_MAX_TOTAL_BYTES = 6 * 1024 * 1024

_registry_cache = {}


class SkuDetection(object):
    """Outcome of the vote. ``sku`` is None when nothing could be established."""

    def __init__(self, sku, confidence, method, evidence, candidates, votes):
        self.sku = sku
        self.confidence = confidence          # high | medium | low | none
        self.method = method                  # explicit | pack | fingerprint | content | default | none
        self.evidence = evidence              # list[str], human-checkable
        self.candidates_considered = candidates
        self.votes = votes                    # {source: sku}

    def as_dict(self):
        return {"sku": self.sku, "confidence": self.confidence, "method": self.method,
                "evidence": self.evidence, "candidates_considered": self.candidates_considered,
                "votes": self.votes}

    def __repr__(self):
        return "SkuDetection(sku=%r, confidence=%r, method=%r)" % (
            self.sku, self.confidence, self.method)


def _deep_merge(base, override):
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_registry(path=None):
    """Load and cache the platform registry (re-read when either file changes).

    ``sku_registry.local.json`` next to the registry, when present, is
    deep-merged over it.
    """
    p = Path(path) if path else REGISTRY_PATH
    local = p.with_name(LOCAL_REGISTRY_NAME)
    try:
        stamp = p.stat().st_mtime_ns
    except OSError as exc:
        raise FileNotFoundError("Platform registry not found: %s (%s)" % (p, exc))
    local_stamp = local.stat().st_mtime_ns if local.is_file() else None
    key = str(p)
    cached = _registry_cache.get(key)
    if not cached or cached[0] != (stamp, local_stamp):
        data = json.loads(p.read_text(encoding="utf-8"))
        if local_stamp is not None:
            override = json.loads(local.read_text(encoding="utf-8"))
            if not isinstance(override, dict):
                raise ValueError("%s must contain a JSON object" % local)
            data = _deep_merge(data, override)
        data.setdefault("skus", {})
        _registry_cache[key] = ((stamp, local_stamp), data)
    return _registry_cache[key][1]


def known_skus(registry=None):
    return sorted((registry or load_registry())["skus"])


def default_sku(registry=None):
    """Registry-declared platform to assume when the vote finds no signal at all.

    Returns a validated registry key, or None when no default is configured or
    it names a platform that is not in the registry.
    """
    reg = registry or load_registry()
    return normalize_sku(reg.get("default_sku"), reg)


def normalize_sku(value, registry=None):
    """Map a platform name or alias (any case) onto a registry key, else None."""
    if not value:
        return None
    reg = registry or load_registry()
    want = str(value).strip().upper()
    if want in reg["skus"]:
        return want
    for sku, info in reg["skus"].items():
        if want == sku.upper():
            return sku
        for alias in info.get("aliases") or []:
            if want == str(alias).upper():
                return sku
    return None


def _explicit_vote(scan_folder, reg):
    """Platform as recorded by the test setup itself - the strongest signal."""
    folder = Path(scan_folder)
    candidates = list(folder.glob("sut.settings.*.json"))
    for sub in sorted(p for p in folder.iterdir() if p.is_dir()) if folder.is_dir() else []:
        candidates.extend(sub.glob("sut.settings.*.json"))
    for f in candidates:
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for field in ("SUT_SKU", "sku"):
            sku = normalize_sku(data.get(field), reg)
            if sku:
                return sku, "%s=%s in %s" % (field, data.get(field), f.name)
    return None, None


def _path_vote(scan_folder, reg):
    """Platform tokens in the folder path and file names."""
    folder = Path(scan_folder)
    names = [str(folder)]
    if folder.is_dir():
        for child in list(folder.iterdir())[:400]:
            names.append(child.name)
    blob = "\n".join(names)

    hits = {}
    for sku, info in reg["skus"].items():
        for pat in (info.get("fingerprints") or {}).get("path") or []:
            m = re.search(pat, blob, re.IGNORECASE)
            if m:
                hits.setdefault(sku, "path token %r matched %r" % (m.group(0), pat))
                break
    if len(hits) == 1:
        sku = next(iter(hits))
        return sku, hits[sku]
    if len(hits) > 1:
        return None, "ambiguous path tokens: %s" % ", ".join(sorted(hits))
    return None, None


def _iter_content(folder):
    total = 0
    files = 0
    for p in sorted(Path(folder).rglob("*")):
        if files >= CONTENT_MAX_FILES or total >= CONTENT_MAX_TOTAL_BYTES:
            return
        if not p.is_file() or p.suffix.lower() not in CONTENT_EXTS:
            continue
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                chunk = fh.read(CONTENT_MAX_BYTES_PER_FILE)
        except OSError:
            continue
        files += 1
        total += len(chunk)
        yield p, chunk


def _content_vote(scan_folder, reg):
    """Platform fingerprints inside the logs themselves."""
    counts = {}
    where = {}
    for path, chunk in _iter_content(scan_folder):
        for sku, info in reg["skus"].items():
            for pat in (info.get("fingerprints") or {}).get("content") or []:
                found = re.findall(pat, chunk, re.IGNORECASE)
                if found:
                    counts[sku] = counts.get(sku, 0) + len(found)
                    where.setdefault(sku, "%s in %s" % (pat, path.name))
    if not counts:
        return None, None
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    top, top_n = ranked[0]
    if len(ranked) > 1 and ranked[1][1] * 2 > top_n:
        return None, "content fingerprints inconclusive: %s" % ", ".join(
            "%s x%d" % kv for kv in ranked[:3])
    return top, "%d content hit(s), e.g. %s" % (top_n, where[top])


def _find_pack(name, base):
    filename = PACK_PATTERN % name
    direct = base / filename
    if direct.is_file():
        return direct
    if base.is_dir():
        for candidate in base.rglob(filename):
            return candidate
    return None


def sku_from_pack(pack, registry=None, pack_dir=None):
    """Resolve the platform a signature pack targets. Returns (sku, evidence).

    Resolution order:

      1. the pack's own ``sku`` field - authoritative, set by whoever wrote it;
      2. the platform whose ``signature_packs`` list contains this pack file;
      3. the pack name read as a platform name or alias;
      4. the leading token of the pack name before ``_``, ``-`` or ``.``.

    Returns ``(None, reason)`` when nothing resolves, so the caller can say so
    instead of defaulting to another platform.
    """
    if not pack:
        return None, "no signature pack given"
    reg = registry or load_registry()
    base = Path(pack_dir) if pack_dir else PACK_DIR
    name = str(pack).strip()

    path = _find_pack(name, base)
    if path is not None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            data = None
        declared = data.get("sku") if isinstance(data, dict) else None
        if declared:
            sku = normalize_sku(declared, reg)
            if sku:
                return sku, 'pack %s declares "sku": "%s"' % (path.name, declared)
            return None, ('pack %s declares "sku": "%s" which is not in the '
                          "registry" % (path.name, declared))

    filename = PACK_PATTERN % name
    owners = [sku for sku, info in reg["skus"].items()
              if filename in (info.get("signature_packs") or [])]
    if len(owners) == 1:
        return owners[0], "pack %s is listed under platform %s" % (filename, owners[0])

    sku = normalize_sku(name, reg)
    if sku:
        return sku, "pack name %r resolves to platform %s" % (name, sku)

    head = re.split(r"[_\-.]", name)[0]
    if head and head != name:
        sku = normalize_sku(head, reg)
        if sku:
            return sku, "pack name %r leading token %r resolves to platform %s" % (
                name, head, sku)

    return None, ("pack %r declares no sku and its name does not resolve "
                  "(known: %s)" % (name, ", ".join(known_skus(reg)) or "none"))


def detect_sku(scan_folder, explicit=None, registry=None, pack=None,
               allow_default=True):
    """Run the three-way vote over a scan folder.

    Args:
        scan_folder: log folder to inspect.
        explicit: platform supplied by the caller; trusted, but still validated
            against the registry so a typo fails loudly. When absent, the
            ``LOG_ANALYZER_PLATFORM`` environment variable is honoured the same way.
        registry: pre-loaded registry, for tests.
        pack: signature pack name (``--signature``). A pack that resolves to a
            platform is enough on its own.
        allow_default: when the vote finds no signal at all, fall back to the
            registry's ``default_sku`` at ``confidence='low'``.
    """
    reg = registry or load_registry()
    evidence = []
    votes = {}

    if not explicit:
        env_sku = os.environ.get(PLATFORM_ENV, "").strip()
        if env_sku:
            explicit = env_sku
            evidence.append("[env] %s=%s" % (PLATFORM_ENV, env_sku))

    def _fallback(why, candidates=(), votes_=None):
        """No signal found - assume the configured default, but say that we did."""
        d = default_sku(reg) if allow_default else None
        if not d:
            return SkuDetection(None, "none", "none", why, list(candidates),
                                votes_ or {})
        return SkuDetection(
            d, "low", "default",
            list(why) + ["[default] no platform signal found; assuming registry "
                         "default_sku=%s (%s). Pass --sku/--signature, or set "
                         "SUT_SKU in sut.settings.*.json, to make this explicit."
                         % (d, reg["skus"][d].get("display_name", ""))],
            list(candidates) or [d], votes_ or {})

    if explicit:
        sku = normalize_sku(explicit, reg)
        if not sku:
            return SkuDetection(None, "none", "none",
                                evidence +
                                ["platform %r is not in the registry (known: %s)"
                                 % (explicit, ", ".join(known_skus(reg)) or "none")],
                                known_skus(reg), {})
        return SkuDetection(sku, "high", "explicit",
                            evidence + ["platform supplied by caller: %s" % sku],
                            [sku], {"explicit": sku})

    if pack:
        sku, why = sku_from_pack(pack, reg)
        if sku:
            return SkuDetection(sku, "high", "pack",
                                ["[pack] %s" % why], [sku], {"pack": sku})
        evidence.append("[pack] %s" % why)

    folder = Path(scan_folder)
    if not folder.is_dir():
        # A bad path is an input error, never paper over it with the default.
        return SkuDetection(None, "none", "none",
                            evidence + ["scan folder does not exist: %s" % folder],
                            [], {})

    for name, fn in (("explicit", _explicit_vote), ("path", _path_vote),
                     ("content", _content_vote)):
        try:
            sku, why = fn(folder, reg)
        except OSError as exc:
            sku, why = None, "%s vote failed: %s" % (name, exc)
        if why:
            evidence.append("[%s] %s" % (name, why))
        if sku:
            votes[name] = sku

    if not votes:
        return _fallback(evidence or ["no platform signal found in %s" % folder])

    agree = {}
    for src, sku in votes.items():
        agree.setdefault(sku, []).append(src)
    winner, sources = max(agree.items(), key=lambda kv: len(kv[1]))
    candidates = sorted(agree)

    if len(agree) > 1:
        # Conflicting evidence: say so instead of picking a favourite.
        return SkuDetection(None, "none", "none",
                            evidence + ["votes disagree: %s" % votes],
                            candidates, votes)

    if "explicit" in sources:
        confidence, method = "high", "explicit"
    elif len(sources) >= 2:
        confidence, method = "high", "fingerprint"
    elif sources == ["content"]:
        confidence, method = "medium", "content"
    else:
        confidence, method = "low", "fingerprint"

    return SkuDetection(winner, confidence, method, evidence, candidates, votes)


def resolve_sources(sku, registry=None):
    """Knowledge sources for a platform: issue_source / kb / testplan.

    Each entry is ``{"role", "source", "status"}`` where ``source`` is the name
    of a skill, MCP server or tool configured in the user's AI CLI. Roles with
    nothing configured come back as ``missing`` so the caller can report the
    gap instead of quietly falling back to another platform.
    """
    reg = registry or load_registry()
    info = reg["skus"].get(sku) or {}
    knowledge = info.get("knowledge") or {}
    out = []
    for role in KNOWLEDGE_ROLES:
        name = knowledge.get(role)
        out.append({"role": role, "source": name,
                    "status": "configured" if name else "missing"})
    return out


def issue_url_template(registry=None):
    """Issue link template with ``{id}`` still in it, or "" when not configured."""
    tracker = (registry or load_registry()).get("issue_tracker") or {}
    url = str(tracker.get("work_item_url") or "")
    for field in ("org", "project"):
        token = "{%s}" % field
        if token in url:
            value = str(tracker.get(field) or "").strip()
            if not value:
                return ""
            url = url.replace(token, value)
    return url if "{id}" in url else ""


def describe(detection, registry=None):
    """One-paragraph, human-checkable summary of a detection."""
    if not detection.sku:
        return ("Platform could not be determined (%s). Candidates considered: %s. "
                "Evidence:\n  %s"
                % (detection.confidence, ", ".join(detection.candidates_considered) or "none",
                   "\n  ".join(detection.evidence) or "none"))
    reg = registry or load_registry()
    info = reg["skus"][detection.sku]
    srcs = ", ".join("%s=%s" % (s["role"], s["source"] or "not configured")
                     for s in resolve_sources(detection.sku, reg))
    return ("Platform %s (%s), confidence=%s via %s\n  knowledge sources: %s\n"
            "  evidence:\n    %s"
            % (detection.sku, info.get("display_name", ""), detection.confidence,
               detection.method, srcs, "\n    ".join(detection.evidence) or "none"))


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Detect the platform of a log folder")
    ap.add_argument("--scan_folder", required=True)
    ap.add_argument("--sku", default="", help="Platform name; overrides detection")
    ap.add_argument("--signature", default="",
                    help="Signature pack name; the platform it targets is used")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    ap.add_argument("--no-default-sku", action="store_true",
                    help="Do not fall back to the registry default_sku when no "
                         "platform signal is found; refuse instead")
    args = ap.parse_args()

    det = detect_sku(args.scan_folder, args.sku or None,
                     pack=args.signature or None,
                     allow_default=not args.no_default_sku)
    if args.json:
        payload = det.as_dict()
        payload["sources"] = resolve_sources(det.sku) if det.sku else []
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(describe(det))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
