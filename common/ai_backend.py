# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pluggable AI backends for log_analyzer.

Two families of backend are supported:

* **CLI backends** - an agentic AI command-line tool that can read files on its
  own. The default is the GitHub Copilot CLI (``copilot``). Any other AI CLI can
  be plugged in through ``ai_cli.custom_command`` in ``llm_config.json``.
* **HTTP backend** - any OpenAI-compatible ``/v1/chat/completions`` endpoint
  (Ollama, vLLM, LM Studio, ...). The HTTP request code lives with its callers;
  this module only resolves the endpoint and model from configuration.

Configuration precedence (highest first):

1. Environment variables (``LOG_ANALYZER_AI_*``)
2. ``common/llm_config.local.json`` (git-ignored, for your private settings)
3. ``common/llm_config.json`` (committed template)
4. Built-in defaults

Every call site treats AI as optional: when no backend is available the
analysis still completes and simply omits the AI sections.
"""

from __future__ import annotations

import collections
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

_COMMON_DIR = Path(__file__).resolve().parent

DEFAULT_CONFIG = {
    "model": "your-local-model-name",
    "api_url": "http://localhost:11434/v1/chat/completions",
    "timeout": 300,
    "max_tokens": 4096,
    "max_context_tokens": 131072,
    # "cli" (agentic CLI first) or "http" (OpenAI-compatible endpoint only).
    "ai_backend": "cli",
    "ai_cli": {
        # "copilot", "custom" or "none".
        "type": "copilot",
        "model": "auto",
        # Unattended runs need tool approval up front. Tighten these if your
        # environment requires it; see README "Security considerations".
        "copilot_args": ["--allow-all-tools", "--no-ask-user"],
        # Placeholders: {prompt_file} {prompt} {workdir} {model}
        "custom_command": [],
    },
}

READY_MARKER = "LOG_ANALYZER_BACKEND_READY"


class AIBackendUnavailable(RuntimeError):
    """Raised when the configured AI backend cannot be used."""


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _read_json(path: Path) -> dict:
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception:
        pass
    return {}


def load_llm_config() -> dict:
    """Return the merged AI configuration (see module docstring)."""
    cfg = _deep_merge(DEFAULT_CONFIG, _read_json(_COMMON_DIR / "llm_config.json"))
    cfg = _deep_merge(cfg, _read_json(_COMMON_DIR / "llm_config.local.json"))

    env = os.environ
    if env.get("LOG_ANALYZER_AI_URL"):
        url = env["LOG_ANALYZER_AI_URL"].strip().rstrip("/")
        if not url.endswith("/chat/completions"):
            url = url + "/v1/chat/completions"
        cfg["api_url"] = url
    if env.get("LOG_ANALYZER_AI_MODEL"):
        cfg["model"] = env["LOG_ANALYZER_AI_MODEL"].strip()
    if env.get("LOG_ANALYZER_AI_BACKEND"):
        cfg["ai_backend"] = env["LOG_ANALYZER_AI_BACKEND"].strip().lower()
    if env.get("LOG_ANALYZER_AI_CLI"):
        cfg["ai_cli"]["type"] = env["LOG_ANALYZER_AI_CLI"].strip().lower()
    return cfg


def http_opted_in() -> bool:
    """True when the operator explicitly chose the HTTP endpoint."""
    if os.getenv("LOG_ANALYZER_AI_URL", "").strip():
        return True
    return str(load_llm_config().get("ai_backend", "cli")).lower() == "http"


def http_api_url() -> str:
    """Full chat-completions URL of the configured HTTP endpoint."""
    return str(load_llm_config()["api_url"])


def http_api_base() -> str:
    """Endpoint base URL (scheme://host:port) of the configured HTTP endpoint."""
    url = http_api_url()
    return re.sub(r"/v\d+/.*$", "", url).rstrip("/")


def http_model() -> str:
    return str(load_llm_config()["model"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _strip_control_chars(text):
    """Drop NULs and C0 controls that cannot survive an argv or a text pipe.

    UTF-16 logs decoded loosely carry a NUL after every character, and
    subprocess refuses an argv entry containing one.
    """
    if not text:
        return text
    text = text.replace("\x00", "")
    return re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def _no_window_kwargs():
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def _is_shell_shim(exe: str) -> bool:
    return os.name == "nt" and str(exe).lower().endswith((".bat", ".cmd", ".ps1"))


def _launch_argv(exe: str):
    low = str(exe).lower()
    if os.name == "nt" and low.endswith(".ps1"):
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(exe)]
    if os.name == "nt" and low.endswith((".bat", ".cmd")):
        return ["cmd", "/c", str(exe)]
    return [str(exe)]


def _configured_mcp_servers():
    """Names of the user's own MCP servers from ~/.copilot/mcp-config.json."""
    try:
        cfg = Path.home() / ".copilot" / "mcp-config.json"
        if cfg.is_file():
            data = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
            servers = data.get("mcpServers") if isinstance(data, dict) else None
            if isinstance(servers, dict):
                return [str(k) for k in servers]
    except Exception:
        pass
    return []


def _staged_prompt(prompt: str, sanitized_log_text, tmpdir: Path) -> str:
    final_prompt = _strip_control_chars(prompt)
    if sanitized_log_text is not None:
        (tmpdir / "session_log.txt").write_text(
            _strip_control_chars(sanitized_log_text), encoding="utf-8", errors="replace")
        final_prompt = (
            "The input data to analyze is in your current directory as "
            "`session_log.txt`. Read it first.\n\n" + final_prompt)
    return final_prompt


# --------------------------------------------------------------------------- #
# GitHub Copilot CLI
# --------------------------------------------------------------------------- #

def find_copilot_exe():
    """Locate the GitHub Copilot CLI launcher, or return None."""
    override = os.path.expandvars(os.path.expanduser(
        os.getenv("LOG_ANALYZER_COPILOT_EXE", "").strip().strip('"')))
    if override and os.path.isfile(override):
        return override
    for name in ("copilot.exe", "copilot"):
        exe = shutil.which(name)
        if exe:
            return exe
    candidates = []
    appdata = os.getenv("APPDATA", "")
    localappdata = os.getenv("LOCALAPPDATA", "")
    for base in (appdata, localappdata):
        if base:
            for code_dir in ("Code", "Code - Insiders"):
                candidates.append(os.path.join(base, code_dir, "User", "globalStorage",
                                               "github.copilot-chat", "copilotCli"))
    candidates += [os.path.join(appdata, "npm"), os.path.join(localappdata, "npm"),
                   str(Path.home() / ".local" / "bin"), "/usr/local/bin"]
    for folder in candidates:
        if not folder:
            continue
        for name in ("copilot.exe", "copilot.cmd", "copilot.bat", "copilot", "copilot.ps1"):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
    return None


class CopilotCLIBackend:
    """One non-interactive GitHub Copilot CLI run per request."""

    name = "copilot"

    def __init__(self, model=None, workdir=None, disable_mcp=False, extra_args=None):
        cfg = load_llm_config()["ai_cli"]
        self.exe = find_copilot_exe()
        self.model = model or cfg.get("model") or "auto"
        self.workdir = workdir or os.getcwd()
        self.disable_mcp = disable_mcp
        self.extra_args = list(extra_args if extra_args is not None
                               else cfg.get("copilot_args") or [])

    def is_available(self):
        return self.exe is not None

    def preflight(self, timeout=90):
        """Prove one real request works before a batch run."""
        response = self.run(
            "This is a non-interactive backend health check. "
            f"Reply with exactly {READY_MARKER} and nothing else.",
            timeout=timeout)
        if READY_MARKER not in (response or ""):
            sample = (response or "<empty response>").replace("\n", " ")[:200]
            raise AIBackendUnavailable("Copilot CLI preflight failed: " + sample)
        return True

    def run(self, prompt, sanitized_log_text=None, on_text=None, on_status=None,
            timeout=600, extra_dirs=None, **_ignored):
        if not self.exe:
            raise AIBackendUnavailable("Copilot CLI not found on PATH")
        on_text = on_text or (lambda s: None)
        on_status = on_status or (lambda s: None)

        tmpdir = Path(tempfile.mkdtemp(prefix="log_analyzer_ai_"))
        try:
            final_prompt = _staged_prompt(prompt, sanitized_log_text, tmpdir)
            run_cwd = str(tmpdir) if sanitized_log_text is not None else self.workdir
            # cmd.exe / PowerShell shims mangle multi-line argv; hand the prompt
            # over as a file instead.
            if _is_shell_shim(self.exe) or len(final_prompt) > 6000:
                (tmpdir / "prompt.md").write_text(final_prompt, encoding="utf-8")
                final_prompt = ("Read the file prompt.md in directory " + str(tmpdir)
                                + " and follow its instructions exactly.")
            cmd = _launch_argv(self.exe) + [
                "-p", final_prompt,
                "--output-format", "json",
                "--stream", "on",
                "--add-dir", str(tmpdir),
            ] + self.extra_args
            for extra in extra_dirs or []:
                if extra:
                    cmd += ["--add-dir", str(extra)]
            if self.model:
                cmd += ["--model", self.model]
            if self.disable_mcp:
                cmd += ["--disable-builtin-mcps"]
                for server in _configured_mcp_servers():
                    cmd += ["--disable-mcp-server", server]

            on_status(f"Launching Copilot CLI (model={self.model})...")
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            proc = subprocess.Popen(
                cmd, cwd=run_cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env,
                **_no_window_kwargs())

            messages, order, shown = {}, [], {}
            stderr_tail = collections.deque(maxlen=20)
            timed_out = [False]

            def _pump_stderr():
                for line in proc.stderr:
                    line = line.rstrip()
                    if line:
                        stderr_tail.append(line)
                        on_status(line)

            def _watchdog():
                if proc.poll() is None:
                    timed_out[0] = True
                    on_status(f"Copilot CLI timed out after {timeout}s; stopping.")
                    try:
                        proc.kill()
                    except Exception:
                        pass

            threading.Thread(target=_pump_stderr, daemon=True).start()
            timer = threading.Timer(timeout, _watchdog) if timeout else None
            if timer:
                timer.daemon = True
                timer.start()
            try:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    kind, mid, text = self._classify(line)
                    if kind in ("delta", "final") and text is not None:
                        if mid not in messages:
                            messages[mid] = ""
                            order.append(mid)
                        if kind == "delta":
                            messages[mid] += text
                        elif len(text) >= len(messages[mid]):
                            messages[mid] = text
                        prev = shown.get(mid, 0)
                        if len(messages[mid]) > prev:
                            on_text(messages[mid][prev:])
                            shown[mid] = len(messages[mid])
                    elif kind in ("status", "error") and text:
                        on_status(text)
            finally:
                if timer:
                    timer.cancel()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

            result = "\n".join(messages[m] for m in order if messages[m]).strip()
            if timed_out[0] and not result:
                result = f"[Copilot CLI timed out after {timeout}s]"
            if not result and proc.returncode not in (0, None):
                detail = " | ".join(list(stderr_tail)[-5:])
                raise RuntimeError(
                    f"Copilot CLI exited with code {proc.returncode}: {detail}")
            return result
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    def _classify(jsonl_line):
        """Classify one JSONL event of ``--output-format json``."""
        try:
            obj = json.loads(jsonl_line)
        except ValueError:
            if not jsonl_line.startswith("{"):
                return ("final", "_textmode", jsonl_line)
            return ("", None, None)
        if not isinstance(obj, dict):
            return ("", None, None)
        etype = str(obj.get("type", ""))
        data = obj.get("data") or {}
        mid = data.get("messageId") or "_msg"
        if etype == "assistant.message_delta":
            return ("delta", mid, data.get("deltaContent", "") or "")
        if etype == "assistant.message":
            return ("final", mid, data.get("content", "") or "")
        if etype == "result":
            code = obj.get("exitCode", 0)
            return ("error", None, f"[copilot exited {code}]") if code not in (0, None) \
                else ("", None, None)
        if "tool" in etype or "execution" in etype:
            name = data.get("name") or data.get("toolName") or ""
            return ("status", None, f"... {etype.split('.')[-1]} {name}".rstrip())
        if "error" in etype.lower():
            return ("error", None, str(data.get("message") or etype))
        return ("", None, None)


# --------------------------------------------------------------------------- #
# Any other AI CLI
# --------------------------------------------------------------------------- #

class CustomCLIBackend:
    """Run an arbitrary AI CLI described by ``ai_cli.custom_command``.

    Each element of the command list may contain the placeholders
    ``{prompt_file}``, ``{prompt}``, ``{workdir}`` and ``{model}``. The
    assistant's answer is read from the command's standard output.
    """

    name = "custom"

    def __init__(self, model=None, workdir=None, disable_mcp=False, command=None):
        cfg = load_llm_config()["ai_cli"]
        self.command = list(command if command is not None else cfg.get("custom_command") or [])
        self.model = model or cfg.get("model") or ""
        self.workdir = workdir or os.getcwd()

    def is_available(self):
        return bool(self.command) and shutil.which(self.command[0]) is not None

    def preflight(self, timeout=90):
        response = self.run(f"Reply with exactly {READY_MARKER} and nothing else.",
                            timeout=timeout)
        if READY_MARKER not in (response or ""):
            raise AIBackendUnavailable("Custom AI CLI preflight failed")
        return True

    def run(self, prompt, sanitized_log_text=None, on_text=None, on_status=None,
            timeout=600, extra_dirs=None, **_ignored):
        if not self.command:
            raise AIBackendUnavailable("ai_cli.custom_command is not configured")
        on_status = on_status or (lambda s: None)
        tmpdir = Path(tempfile.mkdtemp(prefix="log_analyzer_ai_"))
        try:
            final_prompt = _staged_prompt(prompt, sanitized_log_text, tmpdir)
            prompt_file = tmpdir / "prompt.md"
            prompt_file.write_text(final_prompt, encoding="utf-8")
            run_cwd = str(tmpdir) if sanitized_log_text is not None else self.workdir
            values = {"prompt_file": str(prompt_file), "prompt": final_prompt,
                      "workdir": run_cwd, "model": self.model}
            cmd = [str(part).format(**values) for part in self.command]
            on_status(f"Launching {cmd[0]}...")
            proc = subprocess.run(cmd, cwd=run_cwd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout,
                                  **_no_window_kwargs())
            out = (proc.stdout or "").strip()
            if on_text and out:
                on_text(out)
            if not out and proc.returncode != 0:
                raise RuntimeError(f"{cmd[0]} exited with code {proc.returncode}: "
                                   f"{(proc.stderr or '')[-400:]}")
            return out
        except subprocess.TimeoutExpired:
            return f"[AI CLI timed out after {timeout}s]"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def create_cli_backend(model=None, workdir=None, disable_mcp=False):
    """Return the configured CLI backend, or None when disabled/unavailable."""
    kind = str(load_llm_config()["ai_cli"].get("type", "copilot")).lower()
    if kind == "none":
        return None
    cls = CustomCLIBackend if kind == "custom" else CopilotCLIBackend
    backend = cls(model=model, workdir=workdir, disable_mcp=disable_mcp)
    return backend if backend.is_available() else None


def cli_backend_label() -> str:
    kind = str(load_llm_config()["ai_cli"].get("type", "copilot")).lower()
    return {"custom": "custom AI CLI", "none": "no AI CLI"}.get(kind, "Copilot CLI")
