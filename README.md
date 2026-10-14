# Log Analyzer

Error-signature detection and optional AI-assisted analysis for nested server and hardware test log folders.

`log_analyzer` scans a folder of logs with configurable **error signatures** (plain-text, case-insensitive rules with
whitelists). It then writes text and HTML reports. On top of that deterministic scan it can optionally:

- compare logs against a known-good baseline,
- summarize findings with an AI model,
- build a consolidated test-result report for multi-cycle test runs,
- diff the same log file across consecutive test cycles,
- run an agentic "deep analysis" of the whole folder,
- match findings against your issue tracker through an AI CLI.

AI is **off by default**: without `--ai` (or `LOG_ANALYZER_AI=1`) the tool is fully deterministic and needs no network
access. Everything an AI backend writes into a report is labelled
**"AI-generated, may be inaccurate, verify against the log evidence."**

### Supported log formats

- Any line-oriented text log (dmesg, syslog, journal exports, exported event logs, test tool output, ...).
- JSON documents, JSON Lines and concatenated JSON objects (`match_type: JSON`).
- CSV and XML, optionally converted with `--to_csv`.
- Diagnostic output following the
  [OCP Test and Validation Output Specification](https://github.com/opencomputeproject/ocp-diag-core) v2.0, as JSON
  Lines or in the indented, comma-separated variant some test harnesses write. See
  [OCP diagnostic output](#ocp-diagnostic-output). Output from pre-2.0 (legacy) diagnostics is scanned as plain text
  only.

> **Note on decoders.** This repository contains **no** binary or vendor log decoders (for example BMC SEL, UEFI CPER
> or BIOS POST-code decoders). Convert such logs to text with your own tools before scanning them.

---

## Requirements

- Python 3.9 or newer
- `pip install -r requirements.txt`
- Optional, for AI features, either:
  - an AI command-line tool such as the [GitHub Copilot CLI](https://github.com/github/copilot-cli) (the default) or
    any other AI CLI (see [AI backends](#ai-backends)), or
  - an OpenAI-compatible HTTP endpoint (Ollama, vLLM, LM Studio, ...).

## Quick start

```bash
git clone https://github.com/microsoft/log_analyzer.git
cd log_analyzer
pip install -r requirements.txt

# Deterministic scan with the generic sample signatures (AI is off by default)
python log_analyzer/log_analyzer.py --scan_folder /path/to/logs --signature sample

# Same scan plus AI summary of the findings (needs an AI backend, see "AI backends")
python log_analyzer/log_analyzer.py --scan_folder /path/to/logs --signature sample --ai
```

Reports are written into the scanned folder:

| File | Content |
|---|---|
| `error_signatures.log` / `.html` | De-duplicated matched signatures |
| `error-signatures-details.log` / `.html` | Every matched line with file and line number |
| `whitelisted-signatures.log` / `.html` | Lines suppressed by `whitelist_text`, and why |
| `stop_on_fail_result.log` | Signatures configured to stop the run |
| `error_signatures_summary.log` | AI summary of all findings (AI enabled) |
| `good_log_analysis_*.log` | Differences against a baseline log (AI enabled) |
| `index.html` | Navigation page across all generated reports |
| `LOG_ANALYZER-*/` | The tool's own run log |

## Command line

```text
python log_analyzer/log_analyzer.py --scan_folder <folder> --signature <name|path> [options]
```

| Option | Default | Description |
|---|---|---|
| `--scan_folder` | (required) | Folder to scan recursively |
| `--signature` | (required) | `sample` loads `sut/settings.sample.json`; a bare name is searched recursively under `sut/`; a path to a JSON file also works. Combine packs with commas: `sample,ocp_diag` |
| `--logpath` | scan folder | Where the tool's own run log is written |
| `--to_csv` | `false` | Convert `.json` / `.xml` files to `.csv` before scanning |
| `--ocp_diag` | `auto` | Normalize OCP diagnostic output and apply the `ocp_diag` pack: `auto` (when detected), `true` or `false` |
| `--no_stop` | `true` | Do not stop on signatures marked `stop_on_fail_check` |
| `--compare_good_log` | `true` | AI comparison against `good_log` baselines declared in signatures (only with `--ai`) |
| `--result_analyzer` | `false` | Build the consolidated multi-cycle test report (`result_analyzer.py`) |
| `--cycle_diff` | `false` | Diff the same log files across cycle folders (`cycle_diff_analyzer.py`) |
| `--deep_analysis` | `false` | Run the agentic deep analysis (`deep_analysis.py`) as the last step (needs `--ai`) |
| `--ado_search` | `false` | Match findings against known issues through the AI CLI (`ado_match_ai.py`, needs `--ai`) |
| `--ai` | off | Enable AI analysis (also `LOG_ANALYZER_AI=1`) |
| `--no_ai` | off | Force AI off, overriding `--ai` and `LOG_ANALYZER_AI` |
| `--version` | | Print the version and exit |

## Error signatures

Signature packs live in `sut/settings.<name>.json`. Only the generic `sut/settings.sample.json` and
`sut/settings.ocp_diag.json` are committed; every other `settings.*.json` under `sut/` is git-ignored so that your own
packs stay private. Start by copying the sample:

```bash
cp sut/settings.sample.json sut/settings.myplatform.json
python log_analyzer/log_analyzer.py --scan_folder /path/to/logs --signature myplatform
```

A pack only needs an `error_signatures` list. Each entry supports:

| Field | Meaning |
|---|---|
| `description` | Name shown in the reports |
| `match_type` | `ERROR`, `PASS` or `JSON` (see below) |
| `file` | File-name glob, matched recursively under the scan folder |
| `error_text` / `pass_text` | Terms to look for (case-insensitive substring, no regex) |
| `whitelist_text` | Terms that suppress a matched line |
| `stop_on_fail_check` | `"true"` stops the run when the signature fails (unless `--no_stop`) |
| `good_log` | Optional baseline file for good-log comparison |
| `dedup_mode` | Optional per-signature summary mode (`exact`, `term`, `signature`, `fuzzy`); overrides the pack's `dedup_mode` |
| `comment` | Free text |

Match types:

- **ERROR**: a line matches when any `error_text` term is present and no `whitelist_text` term is present (OR).
- **PASS**: the signature fails when any `pass_text` term is missing from the matched file.
- **JSON**: every key/value pair in `error_text` must match the same JSON record (AND). Works on single JSON documents,
  JSON Lines and concatenated objects. A file that cannot be parsed is reported as a failed check, never as clean.

```json
{
  "description": "Linux dmesg suspected errors",
  "match_type": "ERROR",
  "file": "dmesg*.log",
  "error_text": ["Severity=err", "Hardware Error"],
  "whitelist_text": ["DEBUG"],
  "stop_on_fail_check": "false"
}
```

Use `whitelist_review.py` to tune noisy signatures interactively. It opens a local web page that lists every match per
signature and lets you add whitelist terms, which it writes back with a backup:

```bash
python log_analyzer/whitelist_review.py --scan_folder /path/to/logs --settings myplatform
```

## OCP diagnostic output

Diagnostics built on the OCP Test and Validation Output Specification v2.0 (for example with the reference
[`ocptv` Python library](https://github.com/opencomputeproject/ocp-diag-core-python)) emit one JSON artifact per event.
With `--ocp_diag auto` (the default), every `*.json` / `*.jsonl` file under the scan folder is checked. Each file that
holds v2.0 output is normalized by `common/ocptv.py` into two files next to it:

- `<name>.ocptv.log`: one self-contained line per artifact, with the run name, step name and hardware details
  resolved, for the signature engine:

  ```text
  [OCPTV] FAIL artifact=diagnosis run=accel_diag step=0:bandwidth verdict=bw-low hw="accel0 (slot 3, SN1)" msg="below 40" seq=4 ts=...
  [OCPTV] FAIL artifact=measurement run=accel_diag step=0:bandwidth name=bw value=12.5 unit=GB/s limit="GREATER_THAN_OR_EQUAL 40" compliant=false ...
  ```

- `<name>.ocptv.csv`: the same records with fixed columns, for spreadsheet review.

The `ocp_diag` signature pack (`sut/settings.ocp_diag.json`) is then added automatically. It reports:

| Severity | Finding |
|---|---|
| FAIL | `testRunEnd` result `FAIL`; run or step status `ERROR`; `diagnosis` type `FAIL`; any `error` artifact; `FATAL` log |
| FAIL | Measurement or series element that violates its validators (evaluated by log_analyzer for all 10 validator types, even when the diagnostic emitted no diagnosis) |
| FAIL | Output that is not valid JSON, or a run without `testRunEnd` (crashed, hung or truncated) |
| WARN | `ERROR` log; `diagnosis` type `UNKNOWN`; skipped run or step |

The final `testRunEnd` result is not enough on its own: a diagnostic can report `PASS` while logging errors or
out-of-limit measurements, and the pack reports those separately. To silence a known finding, add its `verdict=`,
`symptom=` or `name=` value to `whitelist_text`. Use `--ocp_diag false` to disable the step.

## Additional tools

All tools live in `log_analyzer/` and print full usage with `--help`.

| Script | Purpose |
|---|---|
| `result_analyzer.py` | Consolidated PASS/FAIL report for a run made of one folder per test cycle |
| `cycle_diff_analyzer.py` | Diff of same-identity log files across consecutive cycles; file patterns are configurable (`--file_patterns`) |
| `sensor_xlsx_digest.py` | One-page digest of sensor-analysis workbooks (`--xlsx_glob`, default `*sensor*.xlsx`) |
| `deep_analysis.py` | Agentic AI review of a whole log folder; prompt in `prompts/deep_analysis.md` |
| `ado_match_ai.py` | Matches findings against known issues of a configured issue source; prompt in `prompts/ado_match.md` |
| `whitelist_review.py` | Interactive whitelist editor (stdlib web server on `127.0.0.1`) |
| `md_report_html.py` | Converts the AI markdown deliverables into standalone HTML |

### Platforms and knowledge sources

`log_analyzer/sku_registry.json` maps a platform to its signature packs and, optionally, to knowledge sources that
your AI CLI can use, such as skills, MCP servers or knowledge bases. The committed file contains only an `EXAMPLE`
entry. Put your real platforms into the git-ignored `log_analyzer/sku_registry.local.json`; it is merged over the
committed registry. `deep_analysis.py` and `ado_match_ai.py` mention a knowledge source in their prompts only when one
is configured. Set `LOG_ANALYZER_PLATFORM` to force a platform instead of auto-detecting it.

## AI backends

AI analysis is opt-in. `log_analyzer.py`, `result_analyzer.py` and `cycle_diff_analyzer.py` call an AI backend only
when you pass `--ai` or set `LOG_ANALYZER_AI=1`. `deep_analysis.py` and `ado_match_ai.py` exist only to run an AI
pass, so running them directly is the opt-in.

When AI is on, these outputs carry the notice **"AI-generated, may be inaccurate, verify against the log evidence."**:

- the summary of findings (`error_signatures_summary.*`);
- good-log comparisons (`good_log_analysis_*`);
- AI columns in the test report and the cross-cycle diff;
- `deep_analysis.html`, `ado_match_result.*`, and the HTML rendered from the AI markdown deliverables.

Treat AI output as a lead to check, never as a verdict.

AI settings live in `common/llm_config.json`. Copy it to the git-ignored `common/llm_config.local.json` for private
values such as your own endpoint. Environment variables override both files.

| Setting | Environment variable | Meaning |
|---|---|---|
| | `LOG_ANALYZER_AI` | `1` enables AI analysis (same as `--ai`) |
| `ai_backend` | `LOG_ANALYZER_AI_BACKEND` | `cli` (default) or `http` |
| `ai_cli.type` | `LOG_ANALYZER_AI_CLI` | `copilot` (default), `custom` or `none` |
| `ai_cli.model` | | Model passed to the AI CLI (`auto` by default) |
| `ai_cli.copilot_args` | | Extra Copilot CLI arguments (default `--allow-all-tools --no-ask-user`) |
| `ai_cli.custom_command` | `LOG_ANALYZER_AI_CLI_COMMAND` | Command for any other AI CLI (env value: a JSON list), see below |
| `api_url` | `LOG_ANALYZER_AI_URL` | OpenAI-compatible endpoint; setting the variable opts into HTTP |
| `model` | `LOG_ANALYZER_AI_MODEL` | Model name for the HTTP endpoint |
| | `LOG_ANALYZER_COPILOT_EXE` | Explicit path to the Copilot CLI executable |

**Using another AI CLI.** Set `ai_cli.type` to `custom` and describe the command as a list. The placeholders
`{prompt_file}`, `{prompt}`, `{workdir}` and `{model}` are substituted, and the answer is read from standard output:

```json
"ai_cli": {
  "type": "custom",
  "custom_command": ["my-ai-cli", "--non-interactive", "--prompt-file", "{prompt_file}"]
}
```

Other per-feature variables include `LOG_ANALYZER_DEEP`, `LOG_ANALYZER_DEEP_MODEL`, `LOG_ANALYZER_DEEP_TIMEOUT`,
`LOG_ANALYZER_ADO_MATCH_MODEL`, `LOG_ANALYZER_ADO_MATCH_TIMEOUT` and `LOG_ANALYZER_RESULT_ANALYZER_*`. See each
script's `--help` for the full list.

### Security considerations

- Log content is sent to the AI backend you configure, and only when AI is enabled. Leave AI off (the default) when
  logs must not leave the machine. If you must use AI on sensitive logs, choose a local HTTP endpoint.
- `result_analyzer.py` redacts simple credential patterns before sending results. The other AI features send log
  excerpts as they are, so review what your logs contain.
- Unattended agentic runs need tool approval up front. The default Copilot arguments
  (`--allow-all-tools --no-ask-user`) let the agent run tools without asking. Access is limited to a temporary
  staging directory and the scanned folder (`--add-dir`). Tighten `ai_cli.copilot_args` if your environment requires
  it.

## Project layout

```text
log_analyzer/
├── log_analyzer/            # entry points, prompts, platform registry
│   ├── log_analyzer.py
│   ├── result_analyzer.py, cycle_diff_analyzer.py, sensor_xlsx_digest.py
│   ├── deep_analysis.py, ado_match_ai.py, sku_router.py, sku_registry.json
│   ├── whitelist_review.py, md_render.py, md_report_html.py
│   └── prompts/
├── common/
│   ├── lib_log.py           # signature engine, good-log comparison, report helpers
│   ├── ocptv.py             # OCP Test and Validation output normalizer
│   ├── ai_backend.py        # Copilot CLI / custom CLI / HTTP configuration
│   ├── brand.py             # report header and footer
│   └── llm_config.json      # AI settings template
├── sut/
│   ├── settings.sample.json   # generic example signature pack
│   └── settings.ocp_diag.json # OCP diagnostic output signatures
├── tools/check_public_release.py
└── tests/
```

## Development

```bash
python -m pytest tests
python tools/check_public_release.py
```

`tools/check_public_release.py` fails when the tree contains private IP addresses, credentials, e-mail addresses,
internal URLs, UNC shares or personal paths. Organisation-specific terms belong in the git-ignored
`tools/public_release_denylist.local.txt`, one regular expression per line. Run the check before every push.

### Dependency licenses

`tests/test_public_release.py` also fails if `requirements.txt` lists one of the copyleft (GPL/LGPL) packages this
project used to depend on. Keep new dependencies MIT, BSD or Apache-2.0
compatible, and add them to the table below.

## Third-party dependencies

This project is MIT-licensed and bundles no third-party code. Its runtime dependencies are installed separately with
`pip` and all use permissive licenses:

| Package | License | Used for |
|---|---|---|
| `rapidfuzz` | MIT | Fuzzy line similarity (de-duplication, good-log comparison) |
| `charset-normalizer` | MIT | Log file encoding detection |
| `requests` | Apache-2.0 | OpenAI-compatible HTTP endpoint calls |
| `pandas` | BSD-3-Clause | Sensor workbook digest (optional) |
| `openpyxl` | MIT | Sensor workbook digest (optional) |
| `pytest` | MIT | Tests (development only) |

External AI command-line tools such as the GitHub Copilot CLI are invoked, not redistributed, and are subject to their
own terms.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License
Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution.
For details, visit <https://cla.opensource.microsoft.com>. See [CONTRIBUTING.md](CONTRIBUTING.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## Reporting security issues

Please do not report security vulnerabilities through public GitHub issues. Follow the instructions in
[SECURITY.md](SECURITY.md) instead.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft
sponsorship. Any use of third-party trademarks or logos is subject to those third parties' policies.
