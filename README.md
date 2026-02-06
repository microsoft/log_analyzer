# Log Analyzer

A comprehensive log analysis tool designed for server and hardware debugging, featuring **AI-powered analysis**, **good-log comparison**, and **automated error-signature detection**.

```text
 _                                _                     
| | ___   __ _     __ _ _ __   __ _| |_   _ _______ _ __ 
| |/ _ \ / _` |   / _` | '_ \ / _` | | | | |_  / _ \ '__|
| | (_) | (_| |  | (_| | | | | (_| | | |_| |/ /  __/ |   
|_|\___/ \__, |___\__,_|_| |_|\__,_|_|\__, /___\___|_|   
         |___/_____|                  |___/             
```

---

## 🚀 Features

- **Multi-format Log Processing**: JSON, XML, CSV, plain text
- **AI-Powered Analysis (Local LLM)**: Designed to work with your **local LLM setup** (e.g., Ollama, vLLM, LM Studio). No external API calls are required unless you configure them.
- **Good Log Comparison**: Detect anomalies against baseline logs
- **Error Signature Detection**: Configurable patterns with whitelist support
- **Hardware Log Decoding**: Hooks for BMC SEL and CPER decoders (*implement your own – see note below*)
- **ADO Integration**: Query Azure DevOps for related issues
- **HTML Reports**: Interactive reports from analysis results
- **Log Merging & Sorting**: Timestamp correction, multi-source merge


---
## 💻 Example

Scan a folder of GPU logs using the `gpu_debug` signature:

```bash
python log_analyzer.py --scan_folder ./logs --signature gpu_debug --compare_good_log true
```

**Expected console output:**

```
[INFO] Loaded signature file: sut/settings.gpu_debug.json
[INFO] Scanning folder: ./logs
[INFO] Found file: gpu_test_01.log
[INFO] Good log comparison enabled
[DIFF] Line 103: "ECC error detected" not found in baseline
[WARNING] Matched error signature: GPU Memory Error
[INFO] Results saved to log_analyzer_output.log
```

**Generated files:**
- `log_analyzer_output.log` — full run log  
- `error_signatures.log` — list of matched error signatures  
- `good_log_analysis_gpu_test_01.log` — diff vs baseline  
- `summary_good_log_analysis.html` — interactive HTML summary  

---

## 📋 Requirements

- Python **3.7+**
- Local LLM service running (optional, for AI analysis features)
- Azure DevOps DB access (optional, for ADO search)

---

## 🛠️ Installation

```bash
# Clone the repository
git clone <repository-url>
cd log_analyzer

# Install dependencies
pip install -r requirements.txt
```

Optional LLM config at `common/llm_config.json`:

```json
{
  "model": "your-local-model-name",
  "api_url": "http://localhost:11434/v1/chat/completions",
  "timeout": 300,
  "max_tokens": 4096,
  "max_context_tokens": 262144
}
```

---

## 🎯 Usage

### Basic

```bash
python log_analyzer.py --scan_folder /path/to/logs --signature sample_signature
```

### Advanced

```bash
python log_analyzer.py \
  --scan_folder /path/to/logs \
  --signature gpu_debug \
  --ado_search true \
  --compare_good_log true \
  --decode_sel true \
  --to_csv true \
  --logpath /path/to/output
```

---

## ⚙️ Command Line Arguments

**Required**
- `--scan_folder` — Folder containing logs
- `--signature` — Loads `sut/settings.{signature}.json`

**Optional**
- `--logpath` — Output path for generated logs/reports
- `--ado_search` — Enable ADO search (`true|false`, default `false`)
- `--to_csv` — Convert JSON/XML → CSV before analysis
- `--no_stop` — Do not stop on critical errors (`true` by default)
- `--compare_good_log` — Enable baseline comparison

**Decoding (Custom Implementations Required)**
- `--decode_sel` — Hook for **BMC SEL decoding**  
  ⚠️ Decoder code not included for security reasons. Implement your own logic under `tools/SEL/`.
- `--decode_cper` — Hook for **CPER decoding**  
  ⚠️ Decoder code not included for security reasons. Implement your own logic under `tools/GB_CPER_Decoder/`.
- `--cper_file_names` — File pattern for CPER decoding (e.g. `"Baseboard_*.json"`)

---

## 📁 Project Structure

```text
log_analyzer/
├── log_analyzer.py        # Main entry point
├── signature_creator.py   # Web UI for editing signature configs
├── lib_log.py             # Core analysis engine
├── requirements.txt
├── version.txt
├── common/
│   └── llm_config.json    # Local LLM config
├── sut/
│   └── settings.*.json    # Error signature configs
└── tools/
    ├── SEL/               # (User-provided SEL decoder)
    └── GB_CPER_Decoder/   # (User-provided CPER decoder)
```

---

## ⚡ Configuration Example

Create `sut/settings.gpu_debug.json`:

```json
{
  "error_signatures": [
    {
      "description": "GPU Memory Error",
      "file": "gpu_*.log",
      "match_type": "ERROR",
      "error_text": ["memory error", "ECC error"],
      "whitelist_text": ["corrected", "info"],
      "stop_on_fail_check": "true",
      "good_log": "/path/to/baseline.log",
      "comment": "Critical GPU memory issues"
    }
  ]
}
```

---

## 🎨 Signature Creator (Web UI)

Create and edit signature configuration files using an interactive web interface!

### Quick Start

```bash
cd log_analyzer
python signature_creator.py
```

Then open http://localhost:8080 in your browser.

### Features

- **Zero Dependencies**: Uses only Python's built-in `http.server` module
- **Beautiful UI**: Modern, responsive web interface with real-time editing
- **Full Control**: Add, edit, delete, and reorder signatures
- **Smart Forms**: Dynamic forms that adapt to match_type (ERROR/PASS/JSON)
- **Network Access**: Accessible from LAN/remote via `0.0.0.0` binding

### Command Line Options

```bash
# Default: port 8080, signature 'sample'
python signature_creator.py

# Custom port and signature
python signature_creator.py --port 9000 --signature gpu_debug

# Help
python signature_creator.py --help
```

### Usage Workflow

1. **Start the server** with the signature you want to edit
2. **Open the URL** shown in the console (localhost or network IP)
3. **Edit signatures** using the web interface:
   - Add new signatures with "+ Add Signature"
   - Edit fields directly (description, match_type, file pattern, etc.)
   - Add/remove error_text, whitelist_text, or pass_text entries
   - Reorder signatures with ↑/↓ buttons
   - Delete unwanted signatures
4. **Save changes** with the "Save" button
5. **View JSON** to inspect the raw configuration

The UI will automatically show/hide fields based on the selected `match_type`:
- **ERROR**: Shows `error_text` and `whitelist_text`
- **PASS**: Shows `pass_text`
- **JSON**: Shows `error_text` (for key-value pairs) and `whitelist_text`

---

## 🧠 Code Logic Overview

**Core workflow**
1. Initialize (load signature, setup logging/output, init local LLM if enabled)
2. Pre-process (optional CSV conversion, SEL/CPER decoding hooks)
3. Analyze (apply signatures, compare good logs, generate reports)
4. Post-process (categorize, optional ADO search, generate HTML summary)

**Key components**
- `log_analyzer.py`: CLI + orchestrator
- `lib_log.py`: analysis engine, local LLM integration, good-log normalization/diff

---

## 📊 Output Files

- `log_analyzer_output.log`
- `error_signatures.log`
- `error-signatures-details.log`
- `ado_match_result.log`
- `good_log_analysis_*.log`
- `summary_good_log_analysis.html`
- `error_signatures_summary.log`
- `*.html`

---

## 🛡️ Error Handling

- Graceful fallback when optional modules fail
- Encoding detection with recovery
- Detailed logging of all operations
- Timeout handling for LLM calls

---

## 🤝 Contributing

This project welcomes contributions. You must sign a Microsoft CLA: <https://cla.opensource.microsoft.com>.  
Code of Conduct: [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

---

## 📞 Support

- Check HTML reports  
- Review `log_analyzer_output.log`  
- Ensure configs & dependencies are valid  

---

## ⚠️ Note on Decoders

The **BMC SEL** and **CPER decoding** functions are **not included** due to security restrictions.  
Users can implement their own decoder logic under:

- `tools/SEL/`
- `tools/GB_CPER_Decoder/`

The analyzer is built to call these hooks if enabled.

---

## Trademarks

This project may contain Microsoft and third-party trademarks. Usage must follow [Microsoft’s Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
