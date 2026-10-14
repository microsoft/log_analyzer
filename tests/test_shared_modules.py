# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for the shared AI backend and report branding helpers."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

import ai_backend  # noqa: E402
import brand  # noqa: E402


def test_default_config_points_to_localhost(monkeypatch):
    for var in ("LOG_ANALYZER_AI_URL", "LOG_ANALYZER_AI_MODEL",
                "LOG_ANALYZER_AI_BACKEND", "LOG_ANALYZER_AI_CLI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(ai_backend, "_COMMON_DIR", Path("does-not-exist"))
    cfg = ai_backend.load_llm_config()
    assert "localhost" in cfg["api_url"]
    assert cfg["ai_cli"]["type"] == "copilot"
    assert not ai_backend.http_opted_in()


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("LOG_ANALYZER_AI_URL", "http://localhost:8000")
    monkeypatch.setenv("LOG_ANALYZER_AI_MODEL", "my-model")
    assert ai_backend.http_api_url() == "http://localhost:8000/v1/chat/completions"
    assert ai_backend.http_api_base() == "http://localhost:8000"
    assert ai_backend.http_model() == "my-model"
    assert ai_backend.http_opted_in()


def test_cli_backend_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LOG_ANALYZER_AI_CLI", "none")
    assert ai_backend.create_cli_backend() is None


def test_custom_cli_backend_runs_command(monkeypatch, tmp_path):
    script = tmp_path / "echo_ai.py"
    script.write_text("import sys; print('ANSWER:' + open(sys.argv[1]).read().strip())",
                      encoding="utf-8")
    backend = ai_backend.CustomCLIBackend(
        command=[sys.executable, str(script), "{prompt_file}"], workdir=str(tmp_path))
    assert backend.is_available()
    assert backend.run("hello") == "ANSWER:hello"
    staged = backend.run("summarize", sanitized_log_text="log line")
    assert "session_log.txt" in staged and "summarize" in staged


def test_copilot_event_classification():
    classify = ai_backend.CopilotCLIBackend._classify
    assert classify('{"type":"assistant.message_delta","data":{"messageId":"m","deltaContent":"hi"}}') \
        == ("delta", "m", "hi")
    assert classify('{"type":"assistant.message","data":{"messageId":"m","content":"done"}}') \
        == ("final", "m", "done")
    assert classify("plain text")[0] == "final"


def test_brandify_is_idempotent():
    page = "<html><head><title>x</title></head><body><p>hi</p></body></html>"
    once = brand.brandify(page, "Test")
    assert brand.PRODUCT in once
    assert brand.brandify(once, "Test") == once
