import os
import sys
import logging
import argparse
import subprocess
from pathlib import Path
import re

def convert_log_to_html(log_path):
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return None

    try:
        if log_path.lower().endswith(".log"):
            html_path = log_path[:-4] + ".html"
        else:
            html_path = log_path + ".html"

        with open(log_path, "r", encoding="utf-8", errors="replace") as log_file:
            lines = log_file.readlines()

        with open(html_path, "w", encoding="utf-8") as html_file:
            html_file.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{os.path.basename(log_path)}</title>
    <style>
        body {{ font-family: monospace; white-space: pre-wrap; }}
        .error {{ color: red; font-weight: bold; }}
        .warning {{ color: orange; }}
        .info {{ color: blue; }}
        .debug {{ color: green; }}
        .default {{ color: black; }}
        a {{ color: darkcyan; text-decoration: underline; }}
    </style>
</head>
<body>
<pre>
""")

            for line in lines:
                safe_line = (
                    line.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                )

                # Detect file paths in the line (basic pattern: C:\... or /home/...)
                file_path_pattern = r'(?:[a-zA-Z]:\\[^\s]+|\/[^\s]+)'
                matches = re.findall(file_path_pattern, safe_line)

                for match in matches:
                    safe_path = match.replace("\\\\", "/").replace("\\", "/")
                    path_as_url = f'file:///{safe_path}'
                    hyperlink = f"<a href='{path_as_url}'>{match}</a>"
                    safe_line = safe_line.replace(match, hyperlink)

                # Apply CSS classes based on log level
                if "error" in line.lower():
                    css_class = "error"
                elif "warn" in line.lower():
                    css_class = "warning"
                elif "info" in line.lower():
                    css_class = "info"
                elif "debug" in line.lower():
                    css_class = "debug"
                else:
                    css_class = "default"

                html_file.write(f"<span class='{css_class}'>{safe_line}</span>")

            html_file.write("</pre>\n</body>\n</html>")

        print(f"HTML file created at: {html_path}")
        return html_path

    except Exception as e:
        print(f"Failed to convert {log_path} to HTML: {e}")
        return None

import fnmatch

# Resolve the absolute path to the script directory.
script_dir = Path(__file__).resolve().parent

# The "sut" folder is expected to be in the parent folder of this script.
sut_folder = script_dir.parent / "sut"

# Append the absolute path to the ../common folder relative to this file.
common_path = script_dir.parent / "common"
sys.path.append(str(common_path))

from lib_log import *

def load_llm_config():
    """Load LLM configuration from common/llm_config.json"""
    config_path = common_path / "llm_config.json"
    
    # Default configuration as fallback
    default_config = {
        "model": "your-model-name",
        "api_url": "http://your-llm-server:port/v1/chat/completions",
        "timeout": 300,
        "max_tokens": 4096,
        "max_context_tokens": 262144
    }
    
    try:
        if config_path.exists():
            import json
            with open(config_path, 'r') as f:
                config = json.load(f)
            logging.info(f"LLM configuration loaded from {config_path}")
            return config
        else:
            logging.warning(f"LLM config file not found at {config_path}, using defaults")
            # Create default config file for user convenience
            try:
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logging.info(f"Created default LLM config file at {config_path}")
            except Exception as e:
                logging.warning(f"Could not create default config file: {e}")
            return default_config
    except Exception as e:
        logging.error(f"Error loading LLM config from {config_path}: {e}, using defaults")
        return default_config

def create_parser():
    """Creates and returns the argument parser."""
    parser = argparse.ArgumentParser(
        description="Log Analyzer for error signatures detection from nested logs"
    )
    
    # Required arguments
    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument(
        "--scan_folder",
        help="Specify the folder to scan for logs",
        required=True
    )
    required_group.add_argument(
        "--signature",
        required=True,
        help=(
            "Specify the signature name (the bare signature, without the 'settings.' prefix or "
            "'.json' extension). For example, use --signature sample to load "
            "settings.sample.json located in the sut folder or its subfolders."
        )
    )
    
    # Optional general arguments
    optional_group = parser.add_argument_group('optional arguments')
    optional_group.add_argument(
        "--logpath",
        help="Specify the path where logs will be saved."
    )
    optional_group.add_argument(
        "--ado_search",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=False,
        help="Specify whether to search ADO data (default: false). Pass 'true' to enable."
    )
    optional_group.add_argument(
        "--to_csv",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=False,
        help="Specify whether to convert .json and .xml files to .csv before error signature search (default: false). Pass 'true' to enable."
    )
    optional_group.add_argument(
        "--no_stop",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=True,
        help="Specify whether to disable stopping on critical errors (default: true). Pass 'false' to stop on errors."
    )
    optional_group.add_argument(
        "--compare_good_log",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=False,
        help="Enable LLM-based good log comparison analysis when good_log paths are specified in error signatures (default: false). Pass 'true' to enable."
    )
    optional_group.add_argument(
        "--version",
        action="store_true",
        help="Print the version and exit."
    )
    
    # Decoding options
    decode_group = parser.add_argument_group('decoding options')
    decode_group.add_argument(
        "--decode_sel",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=False,
        help="Decode BMC SEL logs. Pass 'true' to enable (default: false)."
    )
    decode_group.add_argument(
        "--decode_cper",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=False,
        help="Decode CPER logs using CPER_Decoder for .json files (default: false). Pass 'true' to enable."
    )
    decode_group.add_argument(
        "--cper_file_names",
        help="Specify file pattern(s) to search for CPER decoding (e.g., Baseboard_*.json). Only used with --decode_cper."
    )
    
    return parser

def parse_args():
    parser = create_parser()
    # If no arguments are provided, print help and exit.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()

def normalize_signature(sig_input: str) -> str:
    """
    Removes any 'settings.' prefix or '.json' suffix from the provided signature.
    """
    norm_sig = sig_input
    if norm_sig.startswith("settings."):
        norm_sig = norm_sig[len("settings."):]
    if norm_sig.endswith(".json"):
        norm_sig = norm_sig[:-len(".json")]
    return norm_sig

def find_signature_config(sig_input: str) -> Path:
    """
    Searches for the configuration file based on the provided signature.
    The expected configuration file name is always 'settings.{normalized}.json'.
    This function searches for the file in the sut folder (located in the parent folder of this script)
    and its subdirectories.
    If not found, a unified error message is logged and the script exits.
    """
    normalized_sig = normalize_signature(sig_input)
    expected_filename = f"settings.{normalized_sig}.json"
    
    if sut_folder.exists():
        for config_file in sut_folder.rglob(expected_filename):
            return config_file

    logging.error(
        f"Configuration file for signature '{sig_input}' not found. Expected file name: "
        f"'{expected_filename}' in '{sut_folder}'."
    )
    sys.exit(1)

def read_config_m(signature_arg: str):
    """
    Reads the configuration based on the signature.
    """
    config_file = find_signature_config(signature_arg)
    try:
        import json
        with open(config_file, 'r') as f:
            config = json.load(f)
        logging.info(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        logging.error(f"Error reading configuration file {config_file}: {e}")
        sys.exit(1)

def decode_cper_logs(scan_folder: str, logpath: str = None, cper_file_names: str = None):
    """
    Decode CPER logs using CPER_Decoder for .json files in the scan folder.
    """
    scan_path = Path(scan_folder)
    if not scan_path.exists():
        logging.error(f"Scan folder does not exist: {scan_folder}")
        return
    
    decoder_script = script_dir.parent / "tools" / "CPER_Decoder" / "cper_decoder.py"
    if not decoder_script.exists():
        logging.warning(f"CPER_Decoder script not found at: {decoder_script}. CPER decoding will be skipped.")
        return
    
    json_files = []
    if cper_file_names:
        logging.info(f"Searching for files matching pattern: {cper_file_names}")
        for file_path in scan_path.rglob("*"):
            if file_path.is_file() and fnmatch.fnmatch(file_path.name, cper_file_names):
                json_files.append(file_path)
    else:
        for json_file in scan_path.rglob("*.json"):
            filename = json_file.name.upper()
            if not (filename.endswith("FULL.JSON") or filename.endswith("ONLY.JSON")):
                json_files.append(json_file)
    
    if not json_files:
        logging.info("No files found for CPER decoding")
        return
    
    logging.info(f"Found {len(json_files)} files for CPER decoding")
    for json_file in json_files:
        try:
            cmd = [
                sys.executable,
                str(decoder_script),
                "--input", str(json_file)
            ]
            if not cper_file_names:
                cmd.extend(["--logpath", logpath or scan_folder])
            
            logging.info(f"Decoding CPER for: {json_file}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logging.info(f"Successfully decoded CPER for: {json_file}")
                if result.stdout:
                    logging.debug(f"CPER decoder output: {result.stdout}")
            else:
                logging.warning(f"CPER decoding failed for {json_file}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logging.error(f"CPER decoding timed out for: {json_file}")
        except Exception as e:
            logging.error(f"Error running CPER decoder for {json_file}: {e}")

def main():
    ascii_art = r'''
 _                                _                     
| | ___   __ _     __ _ _ __   __ _| |_   _ _______ _ __ 
| |/ _ \ / _` |   / _` | '_ \ / _` | | | | |_  / _ \ '__|
| | (_) | (_| |  | (_| | | | | (_| | | |_| |/ /  __/ |   
|_|\___/ \__, |___\__,_|_| |_|\__,_|_|\__, /___\___|_|   
         |___/_____|                  |___/             
    '''
    print(ascii_art)
    
    version = read_version()
    print(f"Version: {version}")
    
    if "--version" in sys.argv:
        sys.exit(0)
    
    # Load LLM configuration
    llm_config = load_llm_config()
    
    args = parse_args()
    
    result = create_testlog("LOG_ANALYZER", logpath=args.scan_folder)
    if result is None:
        print("Error creating log, exiting...")
        sys.exit(1)
    timestamp, log_file_path, log_folder, log_filename = result

    config = read_config_m(args.signature)
    
    logging.info(f"Scan folder set to: {args.scan_folder}")
    display_title("LOG_ANALYZER")

    if args.to_csv:
        logging.info("Converting JSON and XML files to CSV...")
        convert_files_to_csv(args.scan_folder)

    if args.decode_sel:
        logging.info("Decoding BMC SEL logs...")
        decode_bmc_sel_logs(args.scan_folder, config)

    if args.decode_cper:
        logging.info("Decoding CPER logs...")
        decode_cper_logs(args.scan_folder, args.logpath, args.cper_file_names)

    # Perform log analysis and pass through the no_stop flag AND the new compare_good_log flag
    critical_stop, killed_processes_info, log_analyzer_log_file = log_analyzer(
        config,
        args.scan_folder,
        no_stop=args.no_stop,
        compare_good_log=args.compare_good_log
    )

    if os.path.exists(log_analyzer_log_file):
        if args.ado_search:
            logging.info("Performing ADO search...")
            categorize_matched_lines_ado(args.scan_folder)
        else:
            logging.info("Log analysis without ADO search...")
            categorize_matched_lines(args.scan_folder)
            
        # Always convert generated log files to HTML after analysis
        logging.info("Converting generated log files to HTML...")
        log_files_to_convert = [
        "error-signatures-details.log",
        "error_signatures.log",
        "log_analyzer_output.log",
        "ado_match_result.log", 
        "ai_analysis_result.log",
        "stop_on_fail_result.log",
        "error_signatures_summary.log"
        ]
        base_log_folder = args.scan_folder   
        for log_file_name in log_files_to_convert:
            log_file_path = os.path.join(base_log_folder, log_file_name)
            if os.path.exists(log_file_path):
                html_path = convert_log_to_html(log_file_path)
                if html_path:
                    logging.info(f"Converted {log_file_path} to {html_path}")
                else:
                    logging.warning(f"Failed to convert {log_file_path}")
                
            else:
                logging.warning(f"{log_file_path} does not exist, skipping HTML conversion.")

        # Also convert any good_log analysis files to HTML
        import glob
        analysis_pattern = os.path.join(base_log_folder, "good_log_analysis_*.log")
        analysis_files = glob.glob(analysis_pattern)
        
        if analysis_files:
            logging.info(f"Found {len(analysis_files)} good_log analysis files to convert to HTML...")
            for analysis_file_path in analysis_files:
                html_path = convert_log_to_html(analysis_file_path)
                if html_path:
                    logging.info(f"Converted analysis file {analysis_file_path} to {html_path}")
                else:
                    logging.warning(f"Failed to convert analysis file {analysis_file_path}")
        else:
            logging.info("No good_log analysis files found to convert.")
                
        # Send error_signatures.log to LLM for summary analysis
        error_signatures_log_path = os.path.join(args.scan_folder, "error_signatures.log")
        if os.path.exists(error_signatures_log_path):
            logging.info("Sending error signatures to LLM for summary analysis...")
            summary_json_output = os.path.join(args.scan_folder, "error_signatures_summary.json")
            summary_analysis_output = os.path.join(args.scan_folder, "error_signatures_summary.log")
            
            try:
                send_summary_to_llm(
                    log_file_path=error_signatures_log_path,
                    json_output_path=summary_json_output,
                    analysis_output_path=summary_analysis_output,
                    skip_context_truncation=True,  # Don't truncate for comprehensive summary
                    llm_config=llm_config
                )
                logging.info(f"Error signatures summary completed. Results saved to {summary_analysis_output}")
                
                # Convert the summary log to HTML as well
                if os.path.exists(summary_analysis_output):
                    html_path = convert_log_to_html(summary_analysis_output)
                    if html_path:
                        logging.info(f"Converted summary analysis to HTML: {html_path}")
                        
            except Exception as e:
                logging.error(f"Failed to send error signatures to LLM for summary: {e}")
        else:
            logging.warning(f"Error signatures log not found at {error_signatures_log_path}, skipping LLM summary.")
            
    else:
        logging.error(f"Log_analyzer file not found: {log_analyzer_log_file}")
        
if __name__ == "__main__":
    main()