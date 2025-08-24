# Log Analyzer

A comprehensive log analysis tool designed for server and hardware debugging, featuring AI-powered analysis, good log comparison, and automated error signature detection.

```
 _                                _                     
| | ___   __ _     __ _ _ __   __ _| |_   _ _______ _ __ 
| |/ _ \ / _` |   / _` | '_ \ / _` | | | | |_  / _ \ '__|
| | (_) | (_| |  | (_| | | | | (_| | | |_| |/ /  __/ |   
|_|\___/ \__, |___\__,_|_| |_|\__,_|_|\__, /___\___|_|   
         |___/_____|                  |___/             
```

##  Features

- **Multi-format Log Processing**: Supports various log formats including JSON, XML, CSV, and plain text
- **AI-Powered Analysis**: LLM integration for intelligent log analysis and issue identification
- **Good Log Comparison**: Compare current logs against known good baselines to identify anomalies
- **Error Signature Detection**: Configurable error signatures for automated issue detection
- **Hardware Log Decoding**: Specialized decoders for BMC SEL and CPER logs
- **ADO Integration**: Search Azure DevOps database for related issues and solutions
- **HTML Reports**: Generate interactive HTML reports from analysis results
- **Log Merging & Sorting**: Intelligent timestamp-based log merging with correction capabilities

##  Requirements

- Python 3.7+
- Access to LLM API (optional, for AI analysis features)
- ADO database (optional, for ADO search features)

##  Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd log_analyzer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure LLM (Optional):**
   Create `common/llm_config.json`:
   ```json
   {
     "model": "your-model-name",
     "api_url": "http://your-llm-server:port/v1/chat/completions",
     "timeout": 300,
     "max_tokens": 4096,
     "max_context_tokens": 262144
   }
   ```

##  Usage

### Basic Usage

```bash
python log_analyzer.py --scan_folder /path/to/logs --signature sample_signature
```

### Advanced Usage

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

### Command Line Arguments

#### Required Arguments
- `--scan_folder`: Path to the folder containing logs to analyze
- `--signature`: Signature name (loads `settings.{signature}.json` from sut folder)

#### Optional Arguments
- `--logpath`: Output path for generated logs and reports
- `--ado_search`: Enable ADO database search (default: false)
- `--to_csv`: Convert JSON/XML files to CSV before analysis (default: false)
- `--no_stop`: Disable stopping on critical errors (default: true)
- `--compare_good_log`: Enable LLM-based good log comparison (default: false)

#### Decoding Options
- `--decode_sel`: Decode BMC SEL logs (default: false)
- `--decode_cper`: Decode CPER logs (default: false)
- `--cper_file_names`: File pattern for CPER decoding (e.g., "Baseboard_*.json")

##  Project Structure

```
log_analyzer/
 log_analyzer.py          # Main entry point
 lib_log.py              # Core library functions
 requirements.txt        # Python dependencies
 version.txt            # Version information
 common/
    llm_config.json    # LLM configuration
 sut/
    settings.*.json    # Error signature configurations
 tools/
     SEL/               # SEL decoder tools
     GB_CPER_Decoder/   # CPER decoder tools
```

##  Configuration

### Error Signature Configuration

Create `sut/settings.{signature}.json`:

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

### Match Types
- `ERROR`: Match error text while excluding whitelist text
- `PASS`: Verify required text is present
- `JSON`: Search within JSON structures

##  Code Logic Overview

### Core Workflow

1. **Initialization**
   - Load configuration from signature file
   - Set up logging and output directories
   - Initialize LLM connection (if enabled)

2. **Pre-processing**
   - Convert JSON/XML to CSV (if enabled)
   - Decode specialized logs (SEL, CPER)

3. **Log Analysis**
   - Scan files matching patterns
   - Apply error signatures
   - Perform good log comparison (if enabled)
   - Generate analysis reports

4. **Post-processing**
   - Categorize matched signatures
   - Search ADO database (if enabled)
   - Generate HTML reports
   - Create summary analysis

### Key Components

#### `log_analyzer.py`
- **Main entry point** with argument parsing
- **HTML conversion** for reports
- **CPER decoding** integration
- **Workflow orchestration**

#### `lib_log.py`
- **Core analysis engine** with signature matching
- **LLM integration** for intelligent analysis
- **Good log comparison** with normalization
- **Log processing utilities** (merge, sort, convert)
- **ADO database integration**
- **File format conversions**

### AI-Powered Features

#### Good Log Comparison
1. **Normalization**: Remove timestamps, IPs, and variable data
2. **Fuzzy Matching**: Compare lines with 80% similarity threshold
3. **Chunked Analysis**: Process large logs in manageable chunks
4. **Issue Classification**: Identify Critical vs Warning vs Info level issues

#### LLM Analysis
- **Error Signature Summarization**: Comprehensive analysis of all detected issues
- **Root Cause Analysis**: Hardware/firmware/software categorization
- **Debugging Recommendations**: Actionable next steps

##  Output Files

The analyzer generates several output files:

- `log_analyzer_output.log`: Detailed analysis log
- `error_signatures.log`: Categorized error signatures
- `error-signatures-details.log`: Detailed signature matches
- `ado_match_result.log`: ADO search results (if enabled)
- `good_log_analysis_*.log`: Individual good log comparisons
- `summary_good_log_analysis.html`: Interactive summary dashboard
- `error_signatures_summary.log`: LLM-generated comprehensive summary
- `*.html`: HTML versions of all log files

##  Advanced Features

### Log Merging and Sorting
- Intelligent timestamp correction for logs with incorrect dates
- Multi-file merging with source tracking
- Chronological sorting across different log sources

### Fuzzy Search and Deduplication
- Advanced similarity matching for error signatures
- Automatic deduplication of similar issues
- Configurable similarity thresholds

### Robust File Handling
- Automatic encoding detection with fallback support
- Error-tolerant file reading
- Support for various timestamp formats

##  Error Handling

The tool includes comprehensive error handling:
- Graceful degradation when optional components fail
- Detailed logging of all operations
- Fallback mechanisms for encoding issues
- Timeout handling for LLM requests

##  Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

### Development Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

##  Support

For issues and questions:
- Check the generated HTML reports for detailed analysis
- Review the `log_analyzer_output.log` for detailed execution logs
- Ensure all required dependencies are installed
- Verify configuration files are properly formatted

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.