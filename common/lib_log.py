# LLM Configuration is now loaded from common/llm_config.json

from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from fuzzywuzzy import fuzz
from pathlib import Path
from typing import List, NamedTuple, Union, Dict
from typing import Optional
from typing import Tuple

import datetime
import glob
import json
import logging
import os
import paramiko
import platform

import re

import shutil

import socket
import subprocess
import sys
import tempfile
import time
import sqlite3
import csv
from xml.etree import ElementTree
import chardet  
from collections import defaultdict
import requests



if platform.system() == "Windows":
    logging.debug("Running Script on Windows")
    import wexpect as pexpect
    pexpect.exceptions = pexpect.wexpect_util
else:
    import pexpect


class HostInfo(NamedTuple):
    """Host Info Container"""
    user: str
    pw: str
    ip: str


def load_llm_config():
    """Load LLM configuration from common/llm_config.json"""
    # Try to find the common folder relative to this file
    current_dir = Path(__file__).resolve().parent
    common_path = current_dir.parent / "common"
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
            return default_config
    except Exception as e:
        logging.error(f"Error loading LLM config from {config_path}: {e}, using defaults")
        return default_config


def convert_json_to_csv(json_path, csv_path):
    """Convert a JSON file to a CSV file, ensuring list entries have separate rows."""
    try:
        with open(json_path, 'r', encoding='utf-8') as json_file:
            json_data = json.load(json_file)

        with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)

            if isinstance(json_data, dict):
                for key, value in json_data.items():
                    if isinstance(value, list):
                        # Write each list item as a separate row
                        if value and isinstance(value[0], dict):  # Check if list contains dicts
                            csv_writer.writerow(value[0].keys())  # Write headers
                            for item in value:
                                csv_writer.writerow(item.values())
                        else:
                            csv_writer.writerow([key])
                            for item in value:
                                csv_writer.writerow([item])
                    else:
                        csv_writer.writerow([key, value])
            elif isinstance(json_data, list):
                if json_data and isinstance(json_data[0], dict):  # List of dictionaries
                    csv_writer.writerow(json_data[0].keys())  # Write headers
                    for item in json_data:
                        csv_writer.writerow(item.values())
                else:
                    for item in json_data:
                        csv_writer.writerow([item])
            else:
                logging.warning(f"Unexpected JSON structure in {json_path}, skipping conversion.")
                return

        logging.info(f"Successfully converted JSON to CSV: {json_path} -> {csv_path}")

    except Exception as e:
        logging.warning(f"Failed to convert JSON to CSV for {json_path}: {e}")


def convert_xml_to_csv(xml_path, csv_path):
    """Convert an XML file to a CSV file, ensuring each list-like structure is processed separately."""
    try:
        tree = ElementTree.parse(xml_path)
        root = tree.getroot()

        with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)

            headers = []
            rows = []

            for entry in root:
                row = []
                for elem in entry:
                    if elem.tag not in headers:
                        headers.append(elem.tag)
                    row.append(elem.text.strip() if elem.text else "N/A")  # Handle empty text values
                rows.append(row)

            if headers:
                csv_writer.writerow(headers)
                csv_writer.writerows(rows)
            else:
                logging.warning(f"No structured elements found in XML file: {xml_path}")

        logging.info(f"Successfully converted XML to CSV: {xml_path} -> {csv_path}")

    except ElementTree.ParseError as e:
        logging.warning(f"XML parsing error in {xml_path}: {e}")
    except Exception as e:
        logging.warning(f"Failed to convert XML to CSV for {xml_path}: {e}")


def convert_files_to_csv(scan_folder):
    """Scan a folder for .json and .xml files and convert them to CSV."""
    for root, dirs, files in os.walk(scan_folder):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            csv_file = file_path.rsplit(".", 1)[0] + ".csv"

            if file_name.endswith(".json"):
                convert_json_to_csv(file_path, csv_file)
            elif file_name.endswith(".xml"):
                convert_xml_to_csv(file_path, csv_file)


def extract_hex_sequences(file_path):
    """
    Extract sequences of 16 consecutive hex bytes from the given file.
    Overwrites any existing output files.
    """
    hex_sequences = []
    hex_pattern = re.compile(r'\b([0-9A-Fa-f]{2}){16}\b')
    hex_space_pattern = re.compile(r'\b(?:[0-9A-Fa-f]{2} ){15}[0-9A-Fa-f]{2}\b')

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = hex_pattern.search(line)
            if match:
                hex_sequences.append(match.group(0))
            else:
                match = hex_space_pattern.search(line)
                if match:
                    hex_sequences.append(match.group(0).replace(" ", ""))  # Remove spaces

    # if no space 16 hex bytes found, save the 1st log, otherwise, save the 2nd log. shall be in special .sel format, to avoid multiple runs get duplicated analyze on these generated logs.
    if hex_sequences:
        output_file = f"{file_path}.raw_sel.sel" if hex_pattern.search(line) else f"{file_path}.raw_sel_space.sel"
        
        # Overwrite existing .log file
        with open(output_file, 'w') as f:
            f.write("\n".join(hex_sequences))
        
        logging.info(f"Extracted hex sequences written to {output_file}")
        return output_file

    return None

def run_sel_decoder(sut_sku, log_file):
    """
    Runs SELDecoder.py with the extracted SEL log while temporarily changing the working directory.
    Overwrites the existing .csv output if it exists.
    """
    output_csv = f"{log_file}.csv"

    # Get the base directory (one level up from the current script)
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Move one level up
    # Modified: SELDecoder.py is now located in the ../tools/SEL folder
    sel_dir = os.path.join(script_dir, "tools", "SEL")
    sel_decoder_path = os.path.join(sel_dir, "SELDecoder.py")

    # Normalize paths for Windows
    sel_dir = os.path.normpath(sel_dir)
    sel_decoder_path = os.path.normpath(sel_decoder_path)

    if not os.path.exists(sel_decoder_path):
        logging.error(f"SELDecoder.py not found at {sel_decoder_path}.")
        return

    # Use system default Python
    python_exe = "python"

    command = [
        python_exe, "SELDecoder.py",
        "-k", sut_sku,
        "-f", log_file,
        "-c", output_csv
    ]

    logging.info(f"Running SELDecoder in {sel_dir}: {' '.join(command)}")

    # Store current working directory
    original_cwd = os.getcwd()
    
    try:
        # Change to SEL directory
        os.chdir(sel_dir)

        # Ensure CSV gets overwritten by adding `-o` flag if SELDecoder supports it (optional)
        if os.path.exists(output_csv):
            logging.warning(f"Overwriting existing CSV: {output_csv}")
            os.remove(output_csv)  # Force delete if necessary

        # Run the script
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Log output and errors
        if result.stdout:
            logging.info(result.stdout)
        if result.stderr:
            logging.error(result.stderr)

    finally:
        # Revert to original working directory
        os.chdir(original_cwd)


def decode_bmc_sel_logs(log_folder, config):
    """
    Identify and process BMC SEL logs.
    """
    sut_sku = config.get("SUT_SKU", "Default_SKU")
    for signature in config.get("error_signatures", []):
        if "BMC SEL" in signature.get("description", ""):
            file_pattern = signature.get("file", "")
            matching_files = glob.glob(os.path.join(log_folder, '**', file_pattern), recursive=True)

            for log_file in matching_files:
                logging.info(f"Processing BMC SEL log: {log_file}")
                extracted_log = extract_hex_sequences(log_file)
                if extracted_log:
                    run_sel_decoder(sut_sku, extracted_log)


def send_summary_to_llm(log_file_path, json_output_path="response.json", 
                         analysis_output_path=None,
                         skip_context_truncation=True,
                         llm_config=None):
    """
    Send log content to LLM for comprehensive summary analysis.
    This function is specifically designed for creating summaries and always overwrites output files.
    """
    import tempfile
    import json
    import subprocess
    from pathlib import Path
    from datetime import datetime
    
    # Load LLM config if not provided
    if llm_config is None:
        llm_config = load_llm_config()
    
    # Read log file content
    with open(log_file_path, 'r', encoding='utf-8') as log_file:
        log_content = log_file.read()

    # Unless skip_context_truncation is True, limit the context to 1000 words
    if not skip_context_truncation:
        words = re.split(r'\s+', log_content)
        if len(words) > 1000:
            context_content = ' '.join(words[:1000]) + '...'
        else:
            context_content = log_content
    else:
        context_content = log_content

    logging.info("################# Summary Analysis - Log Content to be sent ###########################")
    logging.info(f"Log content:\n{context_content}")
    logging.info("##################################################################################")

    # Build payload with summary-specific prompt
    payload = {
        "model": llm_config["model"],
        "max_tokens": llm_config["max_tokens"],
        "messages": [
            {"role": "system", "content": "You are a Server and GPU debug engineer specializing in comprehensive error analysis and summary reporting."},
            {"role": "user", "content": (
                "Please provide a comprehensive summary of ALL error signatures found in this log. "
                "Analyze and categorize the errors by type (hardware, firmware, software, tool-related), "
                "identify patterns and frequency of occurrence, highlight the most critical issues, "
                "and provide recommendations for debugging steps and potential fixes or workarounds.\n\n"
                f"{context_content}"
            )}
        ]
    }

    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json', encoding='utf-8') as temp_payload_file:
        temp_payload_file_path = temp_payload_file.name
        json.dump(payload, temp_payload_file)

    logging.info("################# Start of Summary Analysis ###########################")
    logging.info("Sending error signatures to AI for comprehensive summary analysis... This may take some time.")

    curl_command = [
        'curl', '-X', 'POST', llm_config["api_url"], 
        '-H', 'Content-Type: application/json',
        '--data', f"@{temp_payload_file_path}"
    ]

    try:
        result = subprocess.run(curl_command, capture_output=True, text=True, timeout=llm_config["timeout"])
        Path(temp_payload_file_path).unlink(missing_ok=True)
        
        if result.returncode != 0:
            logging.error(f"Curl command failed: {result.stderr}")
            return
            
        response_data = json.loads(result.stdout)
        if "choices" in response_data and len(response_data["choices"]) > 0:
            human_readable_response = response_data["choices"][0]["message"]["content"]
        else:
            human_readable_response = "No response content received."

        # Always overwrite JSON output for summary
        with open(json_output_path, 'w', encoding='utf-8') as json_file:
            json.dump({"summary_response": human_readable_response}, json_file, indent=2)

        if analysis_output_path:
            # Always overwrite analysis output for summary (use 'w' mode)
            with open(analysis_output_path, 'w', encoding='utf-8') as analysis_file:
                analysis_file.write("==== ERROR SIGNATURES SUMMARY ANALYSIS ====\n")
                analysis_file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                analysis_file.write("=" * 60 + "\n\n")
                analysis_file.write("INPUT DATA:\n")
                analysis_file.write("-" * 20 + "\n")
                analysis_file.write(context_content)
                analysis_file.write("\n\n" + "=" * 60 + "\n")
                analysis_file.write("COMPREHENSIVE SUMMARY ANALYSIS:\n")
                analysis_file.write("=" * 60 + "\n\n")
                analysis_file.write(human_readable_response)
                analysis_file.write("\n\n" + "=" * 60 + "\n")
                analysis_file.write("==== END OF SUMMARY ANALYSIS ====\n")
        
        logging.info(f"Summary Analysis Response:\n{human_readable_response}")
        logging.info("################# End of Summary Analysis ###########################")
        
    except subprocess.TimeoutExpired:
        logging.error(f"Request to AI service timed out after {llm_config['timeout']} seconds.")
    except Exception as e:
        logging.error(f"An error occurred while sending the summary to AI: {e}")

def send_log_to_llm(log_file_path, json_output_path="response.json", 
                         analysis_output_path=None,
                         skip_context_truncation=False,
                         llm_config=None):
    # Load LLM config if not provided
    if llm_config is None:
        llm_config = load_llm_config()
        
    # Read log file content
    with open(log_file_path, 'r', encoding='utf-8') as log_file:
        log_content = log_file.read()

    # Unless skip_context_truncation is True, limit the context to 1000 words
    if not skip_context_truncation:
        words = re.split(r'\s+', log_content)
        if len(words) > 1000:
            context_content = ' '.join(words[:1000]) + '...'
        else:
            context_content = log_content
    else:
        context_content = log_content

    logging.info("################# Log Content to be sent ###########################")
    logging.info(f"Log content:\n{context_content}")
    logging.info("####################################################################")

    # Build payload; note the prompt no longer mentions word-limit details
    payload = {
        "model": llm_config["model"],
        "max_tokens": llm_config["max_tokens"],
        "messages": [
            {"role": "system", "content": "You are a Server and GPU debug engineer."},
            {"role": "user", "content": (
                "Based on the matched ADO contexts provided, analyze the error signatures, and identify most possible hardware, firmware, tool, and software root causes. \n\n"
                f"{context_content}"
            )}
        ]
    }

    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json', encoding='utf-8') as temp_payload_file:
        temp_payload_file_path = temp_payload_file.name
        json.dump(payload, temp_payload_file)

    logging.info("################# Start of AI Message ###########################")
    logging.info("Sending aggregated context to AI for analysis... This may take some time.")

    curl_command = [
        'curl', '-X', 'POST', llm_config["api_url"], 
        '-H', 'Content-Type: application/json',
        '--data', f"@{temp_payload_file_path}"
    ]

    try:
        result = subprocess.run(curl_command, capture_output=True, text=True, timeout=llm_config["timeout"])
        Path(temp_payload_file_path).unlink(missing_ok=True)
        if result.returncode != 0:
            logging.error(f"Curl command failed: {result.stderr}")
            return
        response_data = json.loads(result.stdout)
        if "choices" in response_data and len(response_data["choices"]) > 0:
            human_readable_response = response_data["choices"][0]["message"]["content"]
        else:
            human_readable_response = "No response content received."

        with open(json_output_path, 'w', encoding='utf-8') as json_file:
            json.dump({"response": human_readable_response}, json_file)

        if analysis_output_path:
            with open(analysis_output_path, 'a', encoding='utf-8') as analysis_file:
                analysis_file.write("==== AI Analysis Begin ====\n")
                analysis_file.write("==== AI Analysis Begin ====\n")
                analysis_file.write(context_content)
                analysis_file.write("\n---------------------------------------------------\n")
                analysis_file.write("---- AI Analysis ----\n")
                analysis_file.write(human_readable_response)
                analysis_file.write("\n==== End of AI Analysis ====\n\n")
        logging.info(f"Response Text:\n{human_readable_response}")
        logging.info("################# End of AI Message ###########################")
    except subprocess.TimeoutExpired:
        logging.error(f"Request to AI service timed out after {llm_config['timeout']} seconds.")
    except Exception as e:
        logging.error(f"An error occurred while sending the log to LLM: {e}")


# Fuzzy search function using SequenceMatcher

def fuzzy_search(text, keyword):
    if keyword.lower() in text.lower():
        return 1.0  # Exact match, return 100% match
    return SequenceMatcher(None, text.lower(), keyword.lower()).ratio()

# Function to load and fuzzy search the sanitized ADO JSON file with error signatures

def process_ado_json(input_file, keywords, threshold=0.5):
    """
    Process the simplified ADO JSON file and perform fuzzy search on specified fields.
    """
    logging.info(f"Opening ADO JSON file: {input_file}")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Error reading JSON file: {e}")
        return []

    results = []
    
    # Fields to search within the simplified JSON structure
    search_fields = [
        'System.Description', 'System.Title', 'System.History',
        'AzureCSI-V1.2-RequirementsTest.NextSteps', 'System.Tags',
        'Microsoft.VSTS.TCM.ReproSteps', 'Custom.CustomField3'
    ]
    
    for item in data:
        for field in search_fields:
            text_to_search = item.get(field, "")  # Access fields directly in the simplified JSON
            
            if text_to_search:  # Skip empty fields
                for keyword in keywords:
                    match_ratio = fuzzy_search(text_to_search, keyword)
                    match_percentage = round(match_ratio * 100, 2)

                    if match_percentage >= threshold * 100:
                        result = {
                            'ADO id': item.get('id', 'N/A'),
                            'title': item.get('System.Title', 'N/A'),
                            'description': text_to_search,
                            'repro_steps': item.get('Microsoft.VSTS.TCM.ReproSteps', 'N/A'),
                            'keyword': keyword,
                            'match_percentage': match_percentage
                        }
                        results.append(result)
                        logging.info(f"Match found: ADO id: {item.get('id', 'N/A')}, "
                                     f"Keyword: {keyword}, Match: {match_percentage}%, "
                                     f"Title: {item.get('System.Title', 'N/A')}")

    results.sort(key=lambda x: x['keyword'])
    return results

def categorize_matched_lines_ado(log_folder):
    # Step 1: Call categorize_matched_lines to categorize and process log analyzer output
    categorize_matched_lines(log_folder)
    logging.info("Doing ADO search...")

    # Step 2: Process ADO matches using the specified database file
    ado_db_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "log_analyzer",
        "ado_data.db"
    )
    
    # Check if ADO database exists before proceeding
    if not os.path.exists(ado_db_file):
        logging.warning(f"ADO database not found at {ado_db_file}. ADO search will be skipped.")
        # Create empty result file so downstream processes don't fail
        ado_match_result_file = os.path.join(log_folder, 'ado_match_result.log')
        with open(ado_match_result_file, 'w', encoding='utf-8') as result_file:
            result_file.write("[]")  # Empty JSON array
        logging.info("ADO search skipped - created empty result file")
        return
    
    process_ado_matches(log_folder, ado_db_file)
    logging.info("End of ADO search")

# Main function to categorize multiple matched signature lines into distinguishable categories.  

def categorize_matched_lines(log_folder):
    log_file = os.path.join(log_folder, "log_analyzer_output.log")
    if not os.path.exists(log_file):
        logging.error(f"Categorize_matched_lines cannot find Analyzer_output file: {log_file}")
        return
    # Step 1: Parse log_analyzer_output.log to capture file paths, matches, and missing signatures
    matched_lines = []
    missing_lines = []
    current_file_path = None

    with open(log_file, 'r') as file:
        for line in file:
            if line.startswith("Analyzing file:"):
                # Update current file path being analyzed
                current_file_path = line.split("Analyzing file:")[1].strip()
            elif "Error signature [" in line and "matched:" in line:
                # Append the matched signature and current file path
                matched_lines.append((line.strip(), current_file_path))
            elif "Error signature [" in line and "missing:" in line:
                # Append the missing signature and current file path
                missing_lines.append((line.strip(), current_file_path))

    logging.info(f"Found {len(matched_lines)} lines with matched error signatures in the log file.")
    logging.info(f"Found {len(missing_lines)} lines with missing error signatures in the log file.")

    # Step 2: Categorize based on the Message part but stop at "| Provider"
    error_signatures = {}
    for line, file_path in matched_lines + missing_lines:  # Process both matched and missing lines
        message_index = line.lower().find("message=")
        provider_index = line.lower().find("| provider")
        message_part = None

        if message_index != -1 and provider_index != -1:
            message_part = line[message_index + len("message="):provider_index].strip()

            if not message_part or message_part.lower() == "none":
                cleaned_line = clean_error_line(line)
                words = cleaned_line.split()
            else:
                words = message_part.split()
        else:
            if "error signature [" in line.lower() and ("matched:" in line.lower() or "missing:" in line.lower()):
                if "matched:" in line.lower():
                    start_index = line.lower().find("matched:") + len("matched:")
                elif "missing:" in line.lower():
                    start_index = line.lower().find("missing:") + len("missing:")
                line = line[start_index:].strip()

            words = line.split()

        category = ' '.join(words)

        if category:
            if category not in error_signatures:
                error_signatures[category] = []
            error_signatures[category].append((line, file_path))  # Store line and file path

    # The resulting `error_signatures` dictionary will now contain both matched and missing signatures categorized.

    # Step 3: Deduplicate for error_signatures.log
    deduplicated_signatures = deduplicate_signatures(error_signatures, threshold=80)

    # Step 4: Save all matches to "error-signatures-details.log"
    details_log_file = os.path.join(log_folder, "error-signatures-details.log")
    with open(details_log_file, 'w') as details_output:
        for category, entries in error_signatures.items():
            details_output.write(f"Category: {category}\n")
            for line, file_path in entries:
                details_output.write(f"{line}\nFile Path: {file_path}\n")
            details_output.write("============\n")

    logging.info(f"Detailed error signatures saved to {details_log_file}")

    # Step 5: Save deduplicated signatures to "error_signatures.log"
    category_log_file = os.path.join(log_folder, "error_signatures.log")
    with open(category_log_file, 'w') as category_output:
        for category in deduplicated_signatures.keys():
            category_output.write(f"{category}\n")

    logging.info(f"Categories saved to {category_log_file}")

    logging.info("########################################")
    logging.info("######## Categorized Error Signatures ########")
    logging.info("########################################")

    for category in deduplicated_signatures.keys():
        logging.warning(f"--- {category} ---")

    logging.info("########################################")
    logging.info("######## End of Error Signatures ########")
    logging.info("########################################")


def clean_error_signatures_with_llm(text, llm_config=None):
    """
    Send the provided text (error signatures) to an LLM with a prompt to remove all dates 
    and timestamps. Returns the cleaned text.
    """
    # Load LLM config if not provided
    if llm_config is None:
        llm_config = load_llm_config()
        
    prompt = (
        "Please remove all dates and timestamps from the following text. "
        "Return only the cleaned text without any explanations:\n\n" + text
    )
    
    payload = {
        "model": llm_config["model"],
        "max_tokens": llm_config["max_tokens"],
        "messages": [
            {"role": "system", "content": "You are a text cleaning assistant."},
            {"role": "user", "content": prompt}
        ]
    }
    
    # Write the payload to a temporary JSON file
    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json', encoding='utf-8') as temp_payload_file:
        temp_payload_file_path = temp_payload_file.name
        json.dump(payload, temp_payload_file)
    
    try:
        curl_command = [
            'curl', '-X', 'POST', llm_config["api_url"], 
            '-H', 'Content-Type: application/json',
            '--data', f"@{temp_payload_file_path}"
        ]
        result = subprocess.run(curl_command, capture_output=True, text=True, timeout=llm_config["timeout"])
        if result.returncode != 0:
            logging.error(f"Curl command failed in cleaning: {result.stderr}")
            return text  # Fallback to original text
        response_data = json.loads(result.stdout)
        if "choices" in response_data and len(response_data["choices"]) > 0:
            cleaned_text = response_data["choices"][0]["message"]["content"]
        else:
            cleaned_text = text
        return cleaned_text
    except Exception as e:
        logging.error(f"Error in LLM cleaning: {e}")
        return text
    finally:
        Path(temp_payload_file_path).unlink(missing_ok=True)


def truncate_text(text, max_words):
    """Truncate text to a maximum of max_words words."""
    words = re.split(r'\s+', text)
    if len(words) > max_words:
        return ' '.join(words[:max_words]) + '...'
    return text


def process_ado_matches(log_folder, db_file):
    """
    Process ADO matches by reading error signatures, cleaning them with LLM,
    and searching the ADO database for related work items.
    
    Args:
        log_folder: Path to the folder containing log analysis results
        db_file: Path to the ADO SQLite database file
    """
    error_signatures_log = os.path.join(log_folder, 'error_signatures.log')
    keywords = []

    # Read and clean up error signatures
    if os.path.exists(error_signatures_log):
        logging.info(f"Reading error signatures from {error_signatures_log}")
        try:
            with open(error_signatures_log, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except Exception as e:
            logging.error(f"Error reading error signatures file: {e}")
            raw_content = ""

        if raw_content.strip():
            logging.info("Cleaning error signatures via LLM")
            cleaned_content = clean_error_signatures_with_llm(raw_content)

            try:
                with open(error_signatures_log, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
            except Exception as e:
                logging.error(f"Error writing cleaned error signatures: {e}")

            for line in cleaned_content.splitlines():
                keyword = line.strip()
                if keyword:
                    keywords.append(keyword)
        else:
            logging.warning("Error signatures file is empty")
    else:
        logging.warning(f"Error signatures file not found: {error_signatures_log}")

    if not keywords:
        logging.warning("No keywords found in error_signatures.log, skipping ADO search")
        # Create empty result file so downstream processes don't fail
        ado_match_result_file = os.path.join(log_folder, 'ado_match_result.log')
        try:
            with open(ado_match_result_file, 'w', encoding='utf-8') as result_file:
                json.dump([], result_file, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Error creating empty ADO result file: {e}")
        return

    # Verify database exists before attempting connection
    if not os.path.exists(db_file):
        logging.warning(f"ADO database file not found: {db_file}. Skipping ADO search.")
        ado_match_result_file = os.path.join(log_folder, 'ado_match_result.log')
        try:
            with open(ado_match_result_file, 'w', encoding='utf-8') as result_file:
                json.dump([], result_file, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Error creating empty ADO result file: {e}")
        return

    # Log before hitting the SQLite DB
    logging.info("Doing ADO DB search...")
    ado_matches = process_ado_sqlite(db_file, keywords, threshold=0.6)

    # Write out raw ADO match results
    ado_match_result_file = os.path.join(log_folder, 'ado_match_result.log')
    try:
        with open(ado_match_result_file, 'w', encoding='utf-8') as result_file:
            json.dump(ado_matches, result_file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Error writing ADO match results: {e}")
        return

    if ado_matches:
        logging.info(f"Found {len(ado_matches)} ADO matches; results in {ado_match_result_file}")
    else:
        logging.info(f"No ADO matches found; created empty result file at {ado_match_result_file}")

    # Group matches for downstream AI analysis
    grouped_matches = defaultdict(list)
    for match in ado_matches:
        kw = match.get('keyword')
        if kw:
            grouped_matches[kw].append(match)

    # Reset AI analysis log
    ai_analysis_log = os.path.join(log_folder, 'ai_analysis_result.log')
    try:
        with open(ai_analysis_log, 'w', encoding='utf-8') as f:
            f.write("")
    except Exception as e:
        logging.error(f"Error creating AI analysis log file: {e}")


def process_ado_sqlite(db_file, keywords, threshold=0.5):
    """
    Process SQLite database and perform fuzzy search on specified fields.
    Returns empty list if database cannot be accessed or any errors occur.
    
    Args:
        db_file: Path to the ADO SQLite database file
        keywords: List of keywords to search for
        threshold: Minimum similarity threshold (0.0-1.0)
    
    Returns:
        List of matching ADO work items, or empty list if error/no matches
    """
    if not os.path.exists(db_file):
        logging.warning(f"ADO database file not found: {db_file}")
        return []
    
    if not keywords:
        logging.warning("No keywords provided for ADO search")
        return []
    
    # Test if file is a valid SQLite database
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Test basic connectivity
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if not tables:
            logging.warning(f"No tables found in ADO database: {db_file}")
            conn.close()
            return []
    except sqlite3.Error as e:
        logging.error(f"Failed to connect to ADO database {db_file}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error connecting to ADO database {db_file}: {e}")
        return []

    results = []
    search_fields = ['title', 'description', 'repro_steps', 'tags', 'custom_field']
    
    logging.info(f"Searching ADO database with {len(keywords)} keywords in {len(search_fields)} fields")

    try:
        # Check if the expected table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ado_data';")
        if not cursor.fetchone():
            logging.error("Table 'ado_data' not found in ADO database")
            return []

        # Check available columns in the table
        cursor.execute("PRAGMA table_info(ado_data);")
        columns_info = cursor.fetchall()
        available_columns = [col[1] for col in columns_info]  # Column names are in index 1
        
        # Filter search fields to only include available columns
        valid_search_fields = [field for field in search_fields if field in available_columns]
        if not valid_search_fields:
            logging.error(f"None of the expected search fields {search_fields} found in ADO database. Available columns: {available_columns}")
            return []
        
        if len(valid_search_fields) < len(search_fields):
            missing_fields = [field for field in search_fields if field not in available_columns]
            logging.warning(f"Some search fields not found in database: {missing_fields}. Using: {valid_search_fields}")

        total_searches = len(keywords) * len(valid_search_fields)
        search_count = 0
        
        for field in valid_search_fields:
            for keyword in keywords:
                search_count += 1
                if search_count % 10 == 0:  # Log progress every 10 searches
                    logging.debug(f"ADO search progress: {search_count}/{total_searches}")
                
                try:
                    query = f"SELECT id, title, {field} FROM ado_data WHERE {field} LIKE ? AND {field} IS NOT NULL"
                    cursor.execute(query, (f"%{keyword}%",))
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        if len(row) >= 3:  # Ensure we have all expected columns
                            search_text = row[2] or ""  # Handle None values
                            if search_text:  # Only process non-empty text
                                match_ratio = fuzzy_search(search_text, keyword)
                                match_percentage = round(match_ratio * 100, 2)

                                if match_percentage >= threshold * 100:
                                    result = {
                                        'ADO id': row[0],
                                        'title': row[1] or 'N/A',
                                        'description': search_text,
                                        'keyword': keyword,
                                        'match_percentage': match_percentage,
                                        'search_field': field
                                    }
                                    results.append(result)
                                    logging.info(f"Match found: ADO id: {row[0]}, Keyword: '{keyword}', Match: {match_percentage}%, Field: '{field}', Title: {row[1]}")
                        else:
                            logging.warning(f"Incomplete row data in ADO database: {row}")
                            
                except sqlite3.Error as e:
                    logging.warning(f"Error querying field '{field}' for keyword '{keyword}': {e}")
                    continue
                except Exception as e:
                    logging.warning(f"Unexpected error during search in field '{field}' for keyword '{keyword}': {e}")
                    continue

    except sqlite3.Error as e:
        logging.error(f"SQLite error during ADO database search: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during ADO database search: {e}")
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception as e:
            logging.warning(f"Error closing ADO database connection: {e}")

    # Sort results by keyword for easier analysis
    try:
        results.sort(key=lambda x: x.get('keyword', ''))
    except Exception as e:
        logging.warning(f"Error sorting ADO search results: {e}")

    logging.info(f"ADO search completed: {len(results)} matches found from {search_count} searches")
    return results


# Function to deduplicate signatures

def deduplicate_signatures(error_signatures, threshold=80):
    categories = list(error_signatures.keys())
    deduplicated = {}
    used_signatures = set()  # Track which signatures have already been used

    for i, category1 in enumerate(categories):
        if category1 in used_signatures:
            continue  # Skip if already processed as a similar signature

        found_similar = False
        for j, category2 in enumerate(categories):
            if i != j and category2 not in used_signatures:
                similarity = fuzz.ratio(category1, category2)
                if similarity >= threshold:
                    logging.info(f"Found similar categories: '{category1}' and '{category2}' with similarity {similarity}%")
                    found_similar = True
                    # Keep only one signature and mark the other as used
                    if category1 not in deduplicated:
                        deduplicated[category1] = error_signatures[category1]
                    used_signatures.add(category2)

        if not found_similar:
            deduplicated[category1] = error_signatures[category1]

    return deduplicated


# Function to clean up the error signature lines by removing unwanted parts

def clean_error_line(line):
    # Step 1: Extract text after "Message=" if it exists
    message_match = re.search(r'Message=(.*?)(?=\| Provider)', line)
    message_part = message_match.group(1).strip() if message_match else ""
    
    # Check if the message is 'None', then skip it
    if message_part.lower() == "none":
        message_part = ""

    # Step 2: Extract the "Provider=" part
    provider_match = re.search(r'Provider=(.*?)(?=\| Extra)', line)
    provider_part = provider_match.group(1).strip() if provider_match else ""

    # Step 3: Extract the "Extra=" part
    extra_match = re.search(r'Extra=(.*)', line)
    extra_part = extra_match.group(1).strip() if extra_match else ""

    # Step 4: Combine the cleaned parts (Message, Provider, Extra)
    cleaned_line = " ".join(part for part in [message_part, provider_part, extra_part] if part)

    # Step 5: Remove non-UTF-8 characters and extra spaces
    cleaned_line = re.sub(r'[^\x00-\x7F]+', '', cleaned_line)  # Remove non-UTF-8 characters
    cleaned_line = re.sub(r'[^a-zA-Z0-9\s\[\]\(\)\:\.\,\-]', '', cleaned_line)  # Remove unwanted characters
    cleaned_line = re.sub(r'\s+', ' ', cleaned_line).strip()  # Collapse multiple spaces

    return cleaned_line


##############
############## Log Merge and Reformat functions
##############


def convert_response_to_text(raw_response):
    # Use regex to find all the `response` fields and concatenate them
    responses = re.findall(r'"response":"(.*?)"', raw_response)
    
    # Join the individual responses into a single text block
    full_text = ''.join(responses)

    # Optional: Clean up any escape sequences (like \n or \r)
    full_text = full_text.replace("\\n", "\n").replace("\\r", "\r").replace('\\"', '"')
    
    return full_text


# Parse log entries from file and include the file name for tagging

def parse_log_reformat(log_file):
    # Modify the pattern to accept either an integer or "N/A" for the Id field
    log_pattern = re.compile(r"Id=(\d+|N/A)?\s*\|\s*Created=([^\|]+)\|\s*(.*)")
    logs = []

    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = log_pattern.match(line.strip())
                if match:
                    log_id = match.group(1)
                    if log_id == "N/A":
                        log_id = None  # Handle "N/A" as a null Id
                    else:
                        log_id = int(log_id) if log_id else None

                    created_time = match.group(2).strip()
                    details = match.group(3).strip()

                    # Check if the timestamp is valid
                    try:
                        parsed_time = datetime.datetime.strptime(created_time, "%Y-%m-%dT%H:%M:%S")
                        logs.append((log_id, parsed_time, details, log_file))
                    except ValueError:
                        logging.warning(f"Failed to parse timestamp: {created_time} in file {log_file}")
                        continue

        logging.info(f"Parsed {len(logs)} logs from {log_file}")
    except Exception as e:
        logging.error(f"Error reading {log_file}: {e}")

    return logs


# Recalculate timestamps for entries with 1970 or 2000 year

def recalculate_timestamps(logs):
    recalculated_logs = []
    correct_time = None

    # Traverse logs in reverse order to adjust the times
    for i in range(len(logs)-1, -1, -1):
        log_id, created_time, details, log_file = logs[i]
        year = created_time.year

        if year >= 2024:
            correct_time = created_time
            recalculated_logs.append((log_id, created_time, details, log_file))
        elif year == 2000 or year == 1970:
            if correct_time:
                recalculated_logs.append((log_id, correct_time, details, log_file))
                correct_time -= datetime.timedelta(seconds=1)
            else:
                recalculated_logs.append((log_id, created_time, details, log_file))
        else:
            recalculated_logs.append((log_id, created_time, details, log_file))

    return recalculated_logs[::-1]

# Sort and format log entries with file name tagging

def sort_and_format_logs(logs):
    sorted_logs = sorted(logs, key=lambda log: log[1])

    formatted_logs = []
    for log_id, created_time, details, log_file in sorted_logs:
        formatted_time = created_time.strftime("%Y-%m-%dT%H:%M:%S")
        formatted_logs.append((log_id, formatted_time, details, log_file))

    return formatted_logs

# Save recalculated logs to a file, conditionally append "File=" if merging multiple files

def save_logs_merge(formatted_logs, output_file, include_file=False):
    with open(output_file, 'w') as f:
        for log_id, created_time, details, log_file in formatted_logs:
            log_id_str = f"Id={log_id} | " if log_id is not None else ""
            if include_file:
                f.write(f"{log_id_str}Created={created_time} | {details} | File={log_file}\n")
            else:
                f.write(f"{log_id_str}Created={created_time} | {details}\n")


# Function to merge logs from multiple files and tag them with their source file name

def log_merge(log_folder, *log_files):
    all_logs = []

    logging.info(f"Merging logs from {len(log_files)} files...")

    for log_file in log_files:
        logs = parse_log_reformat(log_file)
        recalculated_logs = recalculate_timestamps(logs)
        all_logs.extend(recalculated_logs)

    # Sort all logs by Created time
    sorted_logs = sort_and_format_logs(all_logs)

    # Generate the output filename with timestamp in the log_folder
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(log_folder, f"merged_log.{timestamp}.log")

    # Save the merged and sorted logs to the output file, with "File={log_file}" at the end
    save_logs_merge(sorted_logs, output_file, include_file=True)
    logging.info(f"Merged logs saved to {output_file}")

    return output_file


def reorg_merge_log(config, log_folder):
    error_signatures = config.get('error_signatures', [])
    log_files = []

    # Ensure we're using absolute paths based on log_folder
    for sig in error_signatures:
        file_pattern = sig['file']
        
        # Find all files matching the pattern in the specified log_folder
        matching_files = glob.glob(os.path.join(log_folder, '**', file_pattern), recursive=True)
        
        if not matching_files:
            logging.warning(f"No files matched the pattern {file_pattern}")
            continue
        
        for log_file in matching_files:
            log_name = os.path.splitext(os.path.basename(log_file))[0]
            output_file = os.path.join(log_folder, f"sorted_{log_name}.log")

            logs = parse_log_reformat(log_file)
            if not logs:
                logging.warning(f"No logs were parsed from {log_file}")
                continue

            recalculated_logs = recalculate_timestamps(logs)
            formatted_logs = sort_and_format_logs(recalculated_logs)

            # Save the reformatted log to sorted_{log_name}.log in the log_folder
            save_logs_merge(formatted_logs, output_file, include_file=False)
            logging.info(f"Logs saved to {output_file}")
            log_files.append(output_file)

    # Step 2: Call log_merge() on these sorted log files, passing log_folder
    if log_files:
        merged_log = log_merge(log_folder, *log_files)
        logging.info(f"Merged log saved to {merged_log}")

        # Step 3: Return the full path of the merged log file
        return merged_log
    else:
        logging.warning("No logs were processed for merging.")
        return None


def robust_readlines(file_path):
    """
    Read the file as raw bytes, detect the best encoding with chardet,
    then decode with 'replace' so we never fail on invalid bytes.
    Finally, split into lines.
    """
    import chardet
    import logging
    
    with open(file_path, 'rb') as f:
        raw_data = f.read()

    # Use chardet to guess the encoding
    guess = chardet.detect(raw_data)  # e.g. {'encoding': 'UTF-8', 'confidence': 0.99}
    guessed_encoding = guess['encoding'] or 'utf-8'

    try:
        text = raw_data.decode(guessed_encoding, errors='replace')
    except Exception as e:
        logging.warning(f"Failed to decode {file_path} using {guessed_encoding}. "
                        f"Error: {e}. Falling back to 'latin-1'.")
        text = raw_data.decode('latin-1', errors='replace')

    return text.splitlines()


def compare_logs_and_highlight_differences(good_log_path, current_log_path):
    """
    Compare two log files and highlight differences, ignoring timestamps and hostname/IP related differences.
    Returns a list of meaningful differences.
    """
    import difflib
    import re
    
    def normalize_line_for_comparison(line):
        """Normalize line by removing timestamps, IPs, hostnames for comparison"""
        # Remove timestamps (various formats)
        line = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '[TIMESTAMP]', line)
        line = re.sub(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', '[TIMESTAMP]', line)
        line = re.sub(r'\d{2}-\d{2} \d{2}:\d{2}', '[TIMESTAMP]', line)
        
        # Remove IP addresses
        line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]', line)
        
        # Remove hostnames (basic pattern)
        line = re.sub(r'\b[a-zA-Z0-9-]+\.(?:local)\b', '[HOSTNAME]', line)
        
        # Remove MAC addresses
        line = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '[MAC]', line)
        
        # Remove UUIDs
        line = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[UUID]', line)
        
        return line.strip()
    
    try:
        # Read both files
        with open(good_log_path, 'r', encoding='utf-8', errors='replace') as f:
            good_lines = f.readlines()
        
        with open(current_log_path, 'r', encoding='utf-8', errors='replace') as f:
            current_lines = f.readlines()
        
        # Normalize lines for comparison
        good_normalized = [normalize_line_for_comparison(line) for line in good_lines]
        current_normalized = [normalize_line_for_comparison(line) for line in current_lines]
        
        # Get differences using difflib
        differ = difflib.unified_diff(
            good_normalized, 
            current_normalized, 
            fromfile=f"Good Log: {good_log_path}", 
            tofile=f"Current Log: {current_log_path}", 
            lineterm=''
        )
        
        differences = list(differ)
        
        # Filter out header lines and extract meaningful differences
        meaningful_differences = []
        for line in differences:
            if line.startswith('---') or line.startswith('+++') or line.startswith('@@'):
                continue
            if line.startswith('+') or line.startswith('-'):
                # Skip if the difference is just whitespace
                if line[1:].strip():
                    meaningful_differences.append(line)
        
        return meaningful_differences
        
    except Exception as e:
        logging.error(f"Error comparing logs {good_log_path} and {current_log_path}: {e}")
        return []


def log_separator(message, log_file_handle=None):
    """
    Print and optionally write a separator line with message to log file.
    Uses only ASCII characters for compatibility.
    """
    import logging
    
    separator_line = "=" * 80
    header_line = f"=== {message} ==="
    
    # Print to console
    logging.info(separator_line)
    logging.info(header_line) 
    logging.info(separator_line)
    
    # Write to log file if handle provided
    if log_file_handle:
        log_file_handle.write(f"{separator_line}\n")
        log_file_handle.write(f"{header_line}\n")
        log_file_handle.write(f"{separator_line}\n")


def read_log_files_for_comparison(good_log_path, current_log_path):
    """
    Read both log files and return their contents for LLM comparison.
    """
    import logging
    
    try:
        # Read good log
        with open(good_log_path, 'r', encoding='utf-8', errors='replace') as f:
            good_log_content = f.read()
        
        # Read current log  
        with open(current_log_path, 'r', encoding='utf-8', errors='replace') as f:
            current_log_content = f.read()
        
        return good_log_content, current_log_content
        
    except Exception as e:
        logging.error(f"Error reading logs {good_log_path} and {current_log_path}: {e}")
        return "", ""

def normalize_log_line(line):
    """
    Enhanced normalization for structured logs including HMC Redfish, BMC SEL, CPER, etc.
    Removes timestamps, IPs, device-specific info, binary data, and other noise.
    Returns only the essential content for meaningful comparison.
    """
    import re
    
    # Handle BMC SEL specific patterns first
    # Remove Original_Line numbers (BMC SEL format)
    line = re.sub(r'Original_Line:[0-9a-fA-F]+\s*\|', 'Original_Line:[LINE] |', line)
    
    # Remove hex data strings at beginning of BMC SEL lines (e.g., "01 00 02 1d 19 7f 68 20...")
    line = re.sub(r'\|\s*[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+\s*\|', '| [HEX_DATA] |', line)
    
    # Remove Raw hex data at end of BMC SEL lines
    line = re.sub(r'Raw:[0-9a-fA-F\s]+$', 'Raw:[HEX_DATA]', line)
    line = re.sub(r'Raw:[0-9a-fA-F\s]+,', 'Raw:[HEX_DATA],', line)
    
    # Remove various timestamp formats
    line = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '[TIMESTAMP]', line)
    line = re.sub(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', '[TIMESTAMP]', line)
    line = re.sub(r'\d{2}/\d{2}/\d{4}\s*\|\s*\d{2}:\d{2}:\d{2}', '[DATE] | [TIME]', line)
    line = re.sub(r'\d{2}-\d{2} \d{2}:\d{2}', '[TIMESTAMP]', line)
    line = re.sub(r'\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}', '[TIMESTAMP]', line)
    
    # Remove @odata.id paths (Redfish specific)
    line = re.sub(r'@odata\.id:[^,]+', '@odata.id:[PATH]', line)
    
    # Remove entry IDs and instance numbers
    line = re.sub(r'\bId:\d+', 'Id:[ID]', line)
    line = re.sub(r'\bentry_id:\d+', 'entry_id:[ID]', line)
    line = re.sub(r'\bEntryId:\d+', 'EntryId:[ID]', line)
    line = re.sub(r'Entries/\d+', 'Entries/[ID]', line)
    line = re.sub(r'Entry_\d+', 'Entry_[ID]', line)
    line = re.sub(r'recordId:0x[0-9a-fA-F]+', 'recordId:[ID]', line)
    
    # Remove DiagnosticData (base64/binary content)
    line = re.sub(r'DiagnosticData:[A-Za-z0-9+/=]+', 'DiagnosticData:[BINARY_DATA]', line)
    
    # Remove long base64-like encoded strings (20+ chars of base64 characters)
    line = re.sub(r'\b[A-Za-z0-9+/]{20,}=*\b', '[ENCODED_DATA]', line)
    
    # Normalize register addresses and values - enhanced for BMC SEL
    line = re.sub(r"'address':\s*'0x[0-9a-fA-F]+'", "'address': '[ADDR]'", line)
    line = re.sub(r"'value':\s*'0x[0-9a-fA-F]+'", "'value': '[VALUE]'", line)
    line = re.sub(r'"address":\s*"0x[0-9a-fA-F]+"', '"address": "[ADDR]"', line)
    line = re.sub(r'"value":\s*"0x[0-9a-fA-F]+"', '"value": "[VALUE]"', line)
    line = re.sub(r'Address.*?:\s*\d+', 'Address: [ADDR]', line)
    line = re.sub(r'Value.*?:\s*\d+', 'Value: [VALUE]', line)
    
    # BMC SEL specific register data normalization
    line = re.sub(r"'Register Data':\s*\d+", "'Register Data': [VALUE]", line)
    line = re.sub(r"'Sensor Reading[^']*':\s*\d+", "'Sensor Reading': [VALUE]", line)
    line = re.sub(r"'Fan RPM[^']*':\s*\d+", "'Fan RPM': [VALUE]", line)
    line = re.sub(r"'Event Data \d+':\s*\d+", "'Event Data': [VALUE]", line)
    
    # Remove IP addresses
    line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]', line)
    
    # Remove MAC addresses
    line = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '[MAC]', line)
    
    # Remove UUIDs and GUIDs
    line = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[UUID]', line)
    
    # Remove PCI bus addresses
    line = re.sub(r'\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]\b', '[PCI]', line)
    line = re.sub(r'\b[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]\b', '[PCI]', line)
    
    # Remove memory addresses (hex addresses) - more specific to avoid false positives
    line = re.sub(r'\b0x[0-9a-fA-F]{4,}\b', '[ADDR]', line)
    
    # Remove device numbers and IDs
    line = re.sub(r'\bdev_id[=:]\s*\d+', 'dev_id=[ID]', line)
    line = re.sub(r'\bid[=:]\s*\d+', 'id=[ID]', line)
    
    # Remove socket/instance numbers and sensor data
    line = re.sub(r'Socket:\d+', 'Socket:[ID]', line)
    line = re.sub(r'Instance:\d+', 'Instance:[ID]', line)
    line = re.sub(r'ErrorInstance:\d+', 'ErrorInstance:[ID]', line)
    line = re.sub(r'InstanceBase:\d+', 'InstanceBase:[ID]', line)
    line = re.sub(r'sensorNumber:\d+', 'sensorNumber:[ID]', line)
    line = re.sub(r'sensorID:0x[0-9a-fA-F]+', 'sensorID:[ID]', line)
    
    # Remove specific numeric IDs from CPER and BMC fields
    line = re.sub(r'ErrorType:\d+', 'ErrorType:[TYPE]', line)
    line = re.sub(r'RegisterCount:\d+', 'RegisterCount:[COUNT]', line)
    line = re.sub(r'Severity_Code:\d+', 'Severity_Code:[CODE]', line)
    line = re.sub(r'manufacturerID:\d+', 'manufacturerID:[ID]', line)
    
    # Remove OEM data and specific numeric values in BMC logs
    line = re.sub(r'OEM:\d+', 'OEM:[VALUE]', line)
    line = re.sub(r'eventDataIndex:\d+', 'eventDataIndex:[VALUE]', line)
    
    # Normalize slot numbers and similar identifiers
    line = re.sub(r"'[^']*Slot Number':\s*\d+", "'Slot Number': [NUM]", line)
    line = re.sub(r"'Thread ID':\s*'[^']+'", "'Thread ID': '[ID]'", line)
    line = re.sub(r"'Reset Type':\s*\d+", "'Reset Type': [TYPE]", line)
    
    # Remove hostnames and domain names
    line = re.sub(r'\b[a-zA-Z0-9-]+\.(?:local)\b', '[HOSTNAME]', line)
    
    # Remove specific serial numbers and IDs
    line = re.sub(r'\b[A-Z]{2,}\d{4,}\b', '[SERIAL]', line)
    
    # Remove Created= timestamp entries for serialized logs
    line = re.sub(r'Created=[^|,]+[|,]', 'Created=[TIMESTAMP],', line)
    line = re.sub(r'timestamp:[^,]+,', 'timestamp:[TIMESTAMP],', line)
    line = re.sub(r'date_time:[^,]+,', 'date_time:[TIMESTAMP],', line)
    
    # Remove Id= entries for serialized logs  
    line = re.sub(r'Id=\d+\s*[|,]', 'Id=[ID] |', line)
    
    # Normalize large numeric values (likely addresses or encoded values)
    line = re.sub(r'\b\d{8,}\b', '[NUMERIC]', line)
    
    # Remove version-specific type identifiers
    line = re.sub(r'#[A-Za-z]+\.v\d+_\d+_\d+\.[A-Za-z]+', '#[TYPE]', line)
    
    # Normalize recordType values
    line = re.sub(r'recordType:\d+', 'recordType:[TYPE]', line)
    line = re.sub(r'recordType:0x[0-9a-fA-F]+', 'recordType:[TYPE]', line)
    
    # Remove generatorId specific values but keep the type
    line = re.sub(r'generatorId:[^,]+,', 'generatorId:[GENERATOR],', line)
    
    # Normalize IPMI revision strings
    line = re.sub(r'revision:[^,]+,', 'revision:[VERSION],', line)
    
    # Normalize multiple spaces/punctuation to single space
    line = re.sub(r'\s+', ' ', line)
    line = re.sub(r'[,\s]*,[,\s]*', ', ', line)  # Clean up comma spacing
    line = re.sub(r'\|\s*\|', '| |', line)  # Clean up pipe spacing
    
    return line.strip()

def get_or_create_normalized_good_log(good_log_path):
    """
    Get normalized good log. If normalized version doesn't exist, create it.
    Returns path to normalized good log file.
    """
    import os
    import logging
    
    good_log_dir = os.path.dirname(good_log_path)
    good_log_filename = os.path.basename(good_log_path)
    normalized_filename = f"normalized_{good_log_filename}"
    normalized_path = os.path.join(good_log_dir, normalized_filename)
    
    # Check if normalized version already exists
    if os.path.exists(normalized_path):
        logging.info(f"Found existing normalized good log: {normalized_path}")
        return normalized_path
    
    # Create normalized version
    logging.info(f"Creating normalized good log: {normalized_path}")
    try:
        with open(good_log_path, 'r', encoding='utf-8', errors='replace') as f:
            good_log_lines = f.readlines()
        
        with open(normalized_path, 'w', encoding='utf-8') as f:
            for line in good_log_lines:
                normalized_line = normalize_log_line(line)
                if normalized_line:  # Skip empty lines
                    f.write(normalized_line + '\n')
        
        logging.info(f"Normalized good log created successfully: {normalized_path}")
        return normalized_path
        
    except Exception as e:
        logging.error(f"Failed to create normalized good log: {e}")
        return None

def fuzzy_match_lines(target_lines, good_lines, threshold=0.8):
    """
    Fuzzy match target lines against good lines.
    Returns list of unmatched lines from target.
    """
    from fuzzywuzzy import fuzz
    import logging
    
    unmatched_lines = []
    matched_count = 0
    
    logging.info(f"Starting fuzzy matching with threshold {threshold}")
    logging.info(f"Target lines: {len(target_lines)}, Good lines: {len(good_lines)}")
    
    for i, target_line in enumerate(target_lines):
        if not target_line.strip():
            continue
            
        best_match_ratio = 0
        
        # Find best match in good log
        for good_line in good_lines:
            if not good_line.strip():
                continue
                
            ratio = fuzz.ratio(target_line.lower(), good_line.lower()) / 100.0
            if ratio > best_match_ratio:
                best_match_ratio = ratio
                
            # Early exit if we find a good enough match
            if best_match_ratio >= threshold:
                break
        
        if best_match_ratio >= threshold:
            matched_count += 1
        else:
            unmatched_lines.append({
                'line_number': i + 1,
                'content': target_line,
                'best_match_ratio': best_match_ratio
            })
    
    logging.info(f"Fuzzy matching complete: {matched_count} matched, {len(unmatched_lines)} unmatched")
    return unmatched_lines

def send_good_log_analysis_to_llm(error_signature, good_log_content, current_log_content, good_log_path, current_log_path, 
                                  max_chunks=20,
                                  max_chunk_tokens=None,
                                  scan_folder=None,
                                  llm_config=None):
    """
    Send logs to LLM for comparison with normalization fallback for large logs.
    Now includes proper chunking support and better error handling.
    """
    import tempfile
    import json
    import subprocess
    import datetime
    import os
    import re
    import logging
    from pathlib import Path
    
    # Load LLM config if not provided
    if llm_config is None:
        llm_config = load_llm_config()
    
    def estimate_tokens(text):
        """Improved token estimation: ~4 characters per token for better accuracy"""
        if not text:
            return 0
        # More conservative estimation - models often use more tokens than expected
        return max(1, int(len(text) / 3.0))  # Changed from 3.5 to 3.0 for safety
    
    def estimate_tokens_per_line(lines_sample):
        """Estimate average tokens per line from a sample"""
        if not lines_sample:
            return 100  # Conservative fallback
        sample_text = "\n".join(lines_sample[:min(10, len(lines_sample))])
        avg = estimate_tokens(sample_text) / len(lines_sample[:min(10, len(lines_sample))])
        return max(50, avg)  # Minimum 50 tokens per line assumption
    
    # Create analysis info structure
    file_basename = os.path.basename(current_log_path)
    analysis_filename = f"good_log_analysis_{file_basename}.log"
    analysis_file_path = os.path.join(os.path.dirname(current_log_path), analysis_filename)
    html_file_path = analysis_file_path.replace('.log', '.html')
    
    analysis_info = {
        'signature_description': error_signature.get('description', 'N/A'),
        'current_log_path': current_log_path,
        'analysis_file_path': analysis_file_path,
        'html_file_path': html_file_path,
        'real_issue': False,
        'chunks_processed': 0,
        'successful_chunks': 0,
        'failed_chunks': 0
    }
    
    # Estimate token sizes
    good_log_tokens = estimate_tokens(good_log_content)
    current_log_tokens = estimate_tokens(current_log_content)
    
    # Construct signature info
    signature_info = f"""
Error Signature Information:
Description: {error_signature.get('description', 'N/A')}
Match Type: {error_signature.get('match_type', 'N/A')}
File Pattern: {error_signature.get('file', 'N/A')}
Error Text: {error_signature.get('error_text', [])}
Whitelist Text: {error_signature.get('whitelist_text', [])}
Comment: {error_signature.get('comment', 'N/A')}
"""
    
    # Calculate overhead
    system_message_tokens = estimate_tokens("You are a technical log analyzer. Focus ONLY on Critical and Warning level issues that require immediate attention. Ignore Info level issues and normal variations.")
    prompt_template_tokens = estimate_tokens("""Compare logs and identify ONLY Critical and Warning level issues. IGNORE: timestamps, IPs, hostnames, system IDs, environmental variations.""")
    signature_info_tokens = estimate_tokens(signature_info)
    response_buffer = 5000
    
    total_overhead = system_message_tokens + prompt_template_tokens + signature_info_tokens + good_log_tokens + response_buffer
    available_tokens = llm_config["max_context_tokens"] - total_overhead
    
    logging.info(f"Token analysis - Good log: {good_log_tokens}, Current log: {current_log_tokens}")
    logging.info(f"Total overhead: {total_overhead}, Available tokens: {available_tokens}")
    logging.info(f"Using normalization approach for focused analysis")
    
    # Always use normalization approach for better focus and efficiency
    try:
        # Step 1: Normalize current log lines and save normalized target log
        current_lines = current_log_content.split('\n')
        normalized_current_lines = [normalize_log_line(line) for line in current_lines if line.strip()]
        
        # Save normalized target log in same folder as target log
        target_dir = os.path.dirname(current_log_path)
        target_filename = os.path.basename(current_log_path)
        normalized_target_path = os.path.join(target_dir, f"{target_filename}.normalized")
        
        with open(normalized_target_path, 'w', encoding='utf-8') as f:
            for line in normalized_current_lines:
                f.write(line + '\n')
        logging.info(f"Normalized target log saved to: {normalized_target_path}")
        
        # Step 2: Get or create normalized good log
        normalized_good_log_path = get_or_create_normalized_good_log(good_log_path)
        if not normalized_good_log_path:
            error_msg = "Failed to create normalized good log"
            logging.error(error_msg)
            return False, error_msg, analysis_info
        
        # Read normalized good log
        with open(normalized_good_log_path, 'r', encoding='utf-8', errors='replace') as f:
            normalized_good_lines = [line.strip() for line in f.readlines() if line.strip()]
        
        # Step 3: Fuzzy match to find unmatched lines
        unmatched_lines = fuzzy_match_lines(normalized_current_lines, normalized_good_lines, threshold=0.8)
        
        logging.info(f"Normalization stats: {len(normalized_current_lines)} total lines, {len(unmatched_lines)} unmatched")
        
        if not unmatched_lines:
            # All lines matched - no issues
            analysis_result = """
real_issue: No

SUMMARY:
All normalized log lines matched the good baseline with 80%+ similarity. No critical or warning issues detected.
"""
            analysis_info['real_issue'] = False
            analysis_info['successful_chunks'] = 1
            
            # Save analysis
            with open(analysis_file_path, 'w', encoding='utf-8') as analysis_file:
                analysis_file.write(f"Normalized Good Log Comparison Analysis\n")
                analysis_file.write(f"=" * 120 + "\n")
                analysis_file.write(f"Good Log: {good_log_path}\n")
                analysis_file.write(f"Normalized Good Log: {normalized_good_log_path}\n")
                analysis_file.write(f"Normalized Target Log: {normalized_target_path}\n")
                analysis_file.write(f"Current Log: {current_log_path}\n")
                analysis_file.write(f"Error Signature: {error_signature.get('description', 'N/A')}\n")
                analysis_file.write(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                analysis_file.write(f"Method: Normalization + Fuzzy Matching (default approach)\n")
                analysis_file.write(f"Total lines analyzed: {len(normalized_current_lines)}\n")
                analysis_file.write(f"Matched lines: {len(normalized_current_lines)}\n")
                analysis_file.write(f"Unmatched lines: 0\n")
                analysis_file.write(f"=" * 120 + "\n\n")
                analysis_file.write(analysis_result)
            
            logging.info("Normalization approach completed - All lines matched, no issues detected")
            return False, analysis_result, analysis_info
        
        # Step 4: Calculate proper chunking based on available tokens
        # Use actual model limit from llm_config
        actual_max_tokens = llm_config["max_context_tokens"]
        adjusted_max_tokens = actual_max_tokens - response_buffer  # Available tokens
        
        # Estimate tokens per unmatched line more conservatively
        sample_lines = [item['content'] for item in unmatched_lines[:10]]
        avg_tokens_per_line = max(150, estimate_tokens_per_line(sample_lines) * 2.0)  # Very conservative estimate with 100% buffer
        
        # Calculate base prompt tokens more accurately
        base_prompt_template = f"""
{signature_info}

This is chunk X of Y. These log lines did not match the normalized good baseline (80%+ similarity threshold).
Please analyze these unmatched lines to identify ONLY Critical and Warning level issues.

IMPORTANT: Only respond with detailed analysis if you find Critical or Warning level issues. 
If you only find Info level issues or normal variations, respond with "real_issue: No" and "No critical or warning issues detected."

Log Type: {error_signature.get('description', 'Unknown')}
Chunk lines: XX (lines XX-XX of {len(unmatched_lines)} total unmatched)

UNMATCHED LINES:
"""
        
        base_prompt_tokens = estimate_tokens(base_prompt_template)
        
        # Calculate safe lines per chunk with aggressive safety margin
        available_for_content = adjusted_max_tokens - base_prompt_tokens
        lines_per_chunk = max(3, int(available_for_content / avg_tokens_per_line / 3))  # Divide by 3 for extra safety
        total_chunks = (len(unmatched_lines) + lines_per_chunk - 1) // lines_per_chunk  # Ceiling division
        
        logging.info(f"Chunking calculation (corrected):")
        logging.info(f"  - Actual model max tokens: {actual_max_tokens}")
        logging.info(f"  - Adjusted max tokens: {adjusted_max_tokens}")
        logging.info(f"  - Conservative tokens per line: {avg_tokens_per_line:.1f}")
        logging.info(f"  - Base prompt tokens: {base_prompt_tokens}")
        logging.info(f"  - Available for content: {available_for_content}")
        logging.info(f"  - Safe lines per chunk: {lines_per_chunk}")
        logging.info(f"  - Total chunks needed: {total_chunks}")
        
        if total_chunks > max_chunks:
            # Reduce lines per chunk to fit within max_chunks limit
            lines_per_chunk = max(1, len(unmatched_lines) // max_chunks)
            total_chunks = max_chunks
            logging.warning(f"Too many chunks needed, reducing to {max_chunks} chunks with {lines_per_chunk} lines each")
        
        # Step 5: Process chunks
        all_chunk_results = []
        issues_found = False
        
        # Initialize analysis file
        with open(analysis_file_path, 'w', encoding='utf-8') as analysis_file:
            header_content = f"""Normalized Good Log Comparison Analysis
{'=' * 120}
Good Log: {good_log_path}
Normalized Good Log: {normalized_good_log_path}
Normalized Target Log: {normalized_target_path}
Current Log: {current_log_path}
Error Signature: {error_signature.get('description', 'N/A')}
Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Method: Normalization + Fuzzy Matching + Chunking
Total lines analyzed: {len(normalized_current_lines)}
Matched lines: {len(normalized_current_lines) - len(unmatched_lines)}
Unmatched lines: {len(unmatched_lines)}
Processing in {total_chunks} chunks of ~{lines_per_chunk} lines each
{'=' * 120}

"""
            analysis_file.write(header_content)
            analysis_file.flush()  # Ensure header is written immediately
            
        logging.info(f"Analysis file initialized: {analysis_file_path}")
        
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * lines_per_chunk
            end_idx = min(start_idx + lines_per_chunk, len(unmatched_lines))
            chunk_lines = unmatched_lines[start_idx:end_idx]
            
            analysis_info['chunks_processed'] += 1
            
            logging.info(f"Processing chunk {chunk_idx + 1}/{total_chunks} ({len(chunk_lines)} lines)")
            
            # Create chunk content
            chunk_content = "\n".join([
                f"Line {item['line_number']}: {item['content']} (best match: {item['best_match_ratio']:.2%})"
                for item in chunk_lines
            ])
            
            # Create prompt for this chunk
            chunk_prompt = f"""
{signature_info}

This is chunk {chunk_idx + 1} of {total_chunks}. These log lines did not match the normalized good baseline (80%+ similarity threshold).
Please analyze these unmatched lines to identify ONLY Critical and Warning level issues.

IMPORTANT: Only respond with detailed analysis if you find Critical or Warning level issues. 
If you only find Info level issues or normal variations, respond with "real_issue: No" and "No critical or warning issues detected."

Log Type: {error_signature.get('description', 'Unknown')}
Chunk lines: {len(chunk_lines)} (lines {start_idx + 1}-{end_idx} of {len(unmatched_lines)} total unmatched)

UNMATCHED LINES:
{chunk_content}

Respond in this EXACT format:

real_issue: [Yes/No]

If real_issue is Yes, provide:
ANALYSIS TABLE:
| Category | Impact | Description | Suggestion | Lines |
|----------|--------|-------------|------------|-------|
| [Power/BootUp/Hardware/Software/PCIE/GPU/CPU/DIMM/Storage/Network/Management/Missing] | [Critical/Warning] | [Description] | [Suggested debug next step] | [Line references] |

SUMMARY:
[One sentence conclusion about Critical/Warning issues found]

If real_issue is No, only provide:
SUMMARY: No critical or warning issues detected in this chunk.
"""
            
            # Send chunk to LLM
            payload = {
                "model": llm_config["model"],
                "max_tokens": llm_config["max_tokens"],
                "temperature": 0.3,
                "chat_template_kwargs": {"enable_thinking": False},
                "messages": [
                    {"role": "system", "content": "You are a technical log analyzer. Focus ONLY on Critical and Warning level issues that require immediate attention. Ignore Info level issues and normal variations."},
                    {"role": "user", "content": chunk_prompt}
                ]
            }
            
            # Write payload to temp file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json', encoding='utf-8') as temp_payload_file:
                temp_payload_file_path = temp_payload_file.name
                json.dump(payload, temp_payload_file, indent=2)
            
            try:
                curl_command = [
                    'curl', '-X', 'POST', llm_config["api_url"], 
                    '-H', 'Content-Type: application/json; charset=utf-8',
                    '--data', f"@{temp_payload_file_path}",
                    '--connect-timeout', '15',
                    '--max-time', str(llm_config["timeout"]),
                    '-s', '--show-error', '--compressed'
                ]
                
                result = subprocess.run(
                    curl_command, 
                    capture_output=True, 
                    text=True, 
                    timeout=llm_config["timeout"],
                    encoding='utf-8',
                    errors='replace'
                )
                
                if result.returncode != 0:
                    error_msg = f"LLM request failed for chunk {chunk_idx + 1}: {result.stderr}"
                    logging.error(error_msg)
                    analysis_info['failed_chunks'] += 1
                    continue
                
                # Parse JSON response
                try:
                    response_data = json.loads(result.stdout)
                    
                    # Check if response is an error
                    if response_data.get("object") == "error":
                        error_msg = f"LLM API error for chunk {chunk_idx + 1}: {response_data.get('message', 'Unknown error')}"
                        logging.error(error_msg)
                        analysis_info['failed_chunks'] += 1
                        continue
                        
                except json.JSONDecodeError as e:
                    error_msg = f"Failed to parse JSON response for chunk {chunk_idx + 1}: {e}"
                    logging.error(error_msg)
                    analysis_info['failed_chunks'] += 1
                    continue
                
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    chunk_analysis = response_data["choices"][0]["message"]["content"].strip()
                    
                    # Check if real issue detected in this chunk
                    chunk_has_issue = "real_issue: yes" in chunk_analysis.lower()
                    if chunk_has_issue:
                        issues_found = True
                        logging.warning(f"Chunk {chunk_idx + 1} - Issues detected!")
                    else:
                        logging.info(f"Chunk {chunk_idx + 1} - No issues detected")
                    
                    analysis_info['successful_chunks'] += 1
                    all_chunk_results.append({
                        'chunk_id': chunk_idx + 1,
                        'has_issues': chunk_has_issue,
                        'analysis': chunk_analysis,
                        'lines_processed': len(chunk_lines)
                    })
                    
                    # Append chunk result to analysis file
                    with open(analysis_file_path, 'a', encoding='utf-8') as analysis_file:
                        chunk_header = f"\nCHUNK {chunk_idx + 1} ANALYSIS (lines {start_idx + 1}-{end_idx}):\n"
                        separator_line = f"=" * 80 + "\n"
                        chunk_info = f"Lines processed: {len(chunk_lines)}\n"
                        issue_status = f"Issues found: {'YES' if chunk_has_issue else 'NO'}\n"
                        sub_separator = f"-" * 60 + "\n"
                        
                        # Write chunk header
                        analysis_file.write(chunk_header)
                        analysis_file.write(separator_line)
                        analysis_file.write(chunk_info)
                        analysis_file.write(issue_status)
                        analysis_file.write(sub_separator)
                        
                        # Write the full LLM analysis
                        analysis_file.write("LLM DETAILED ANALYSIS:\n")
                        analysis_file.write("-" * 25 + "\n")
                        analysis_file.write(chunk_analysis)
                        analysis_file.write("\n\n")
                        
                        # Write the unmatched lines for reference
                        analysis_file.write(f"CHUNK {chunk_idx + 1} UNMATCHED LINES DETAILS:\n")
                        analysis_file.write("-" * 40 + "\n")
                        for item in chunk_lines:
                            line_details = f"Line {item['line_number']} (similarity: {item['best_match_ratio']:.1%}): {item['content']}\n"
                            analysis_file.write(line_details)
                        
                        analysis_file.write("\n" + "=" * 80 + "\n\n")
                        analysis_file.flush()
                
                else:
                    error_msg = f"Invalid LLM response structure for chunk {chunk_idx + 1}: {response_data}"
                    logging.error(error_msg)
                    analysis_info['failed_chunks'] += 1
                    continue
                    
            except subprocess.TimeoutExpired:
                error_msg = f"LLM request timeout for chunk {chunk_idx + 1}"
                logging.error(error_msg)
                analysis_info['failed_chunks'] += 1
                continue
                
            except Exception as e:
                error_msg = f"Error processing chunk {chunk_idx + 1}: {e}"
                logging.error(error_msg)
                analysis_info['failed_chunks'] += 1
                continue
                
            finally:
                # Clean up temp file
                try:
                    Path(temp_payload_file_path).unlink(missing_ok=True)
                except:
                    pass
        
        # Step 6: Compile final results
        analysis_info['real_issue'] = issues_found
        
        # Create summary
        if issues_found:
            issue_chunks = [r for r in all_chunk_results if r['has_issues']]
            summary = f"Issues detected in {len(issue_chunks)} out of {len(all_chunk_results)} chunks processed."
        else:
            summary = f"No critical or warning issues detected across {len(all_chunk_results)} chunks processed."
        
        # Append final summary to analysis file
        with open(analysis_file_path, 'a', encoding='utf-8') as analysis_file:
            analysis_file.write(f"FINAL ANALYSIS SUMMARY:\n")
            analysis_file.write(f"=" * 80 + "\n")
            analysis_file.write(f"Total chunks processed: {analysis_info['chunks_processed']}\n")
            analysis_file.write(f"Successful chunks: {analysis_info['successful_chunks']}\n")
            analysis_file.write(f"Failed chunks: {analysis_info['failed_chunks']}\n")
            analysis_file.write(f"Issues found: {'YES' if issues_found else 'NO'}\n")
            analysis_file.write(f"Summary: {summary}\n")
            analysis_file.write(f"=" * 80 + "\n")
        
        logging.info(f"Chunked analysis completed - {summary}")
        
        return issues_found, summary, analysis_info
        
    except Exception as e:
        error_msg = f"Error in normalization approach: {e}"
        logging.error(error_msg)
        
        # Create error analysis file
        with open(analysis_file_path, 'w', encoding='utf-8') as analysis_file:
            analysis_file.write(f"Good Log Comparison Analysis - NORMALIZATION ERROR\n")
            analysis_file.write(f"=" * 60 + "\n")
            analysis_file.write(f"Good Log: {good_log_path}\n")
            analysis_file.write(f"Current Log: {current_log_path}\n")
            analysis_file.write(f"Error Signature: {error_signature.get('description', 'N/A')}\n")
            analysis_file.write(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            analysis_file.write(f"=" * 60 + "\n\n")
            analysis_file.write(f"ERROR in normalization approach: {error_msg}\n")
        
        analysis_info['failed_chunks'] = 1
        return False, error_msg, analysis_info
        

def create_good_log_analysis_summary(scan_folder, analysis_results_list):
    """
    Create a summary HTML file in the scan_folder that links to all individual good log analyses.
    
    Args:
        scan_folder: Path to the scan folder where summary should be created
        analysis_results_list: List of analysis_info dictionaries from send_good_log_analysis_to_llm
    """
    import os
    import datetime
    import logging
    
    if not analysis_results_list:
        return
    
    summary_file_path = os.path.join(scan_folder, "summary_good_log_analysis.html")
    
    # Create HTML content
    rows_html = ""
    total_issues = 0
    total_analyses = 0
    
    for i, info in enumerate(analysis_results_list):
        status_text = "ISSUES DETECTED" if info['real_issue'] else "No Issues"
        status_class = "status-issue" if info['real_issue'] else "status-good"
        
        if info['real_issue']:
            total_issues += 1
        total_analyses += 1
        
        # Create relative paths to the analysis files
        try:
            rel_log_path = os.path.relpath(info['analysis_file_path'], scan_folder)
        except:
            rel_log_path = info['analysis_file_path']
        
        rows_html += f"""
        <tr class="{status_class}">
            <td>{i+1}</td>
            <td><strong>{status_text}</strong></td>
            <td>{info['signature_description']}</td>
            <td>{os.path.basename(info['current_log_path'])}</td>
            <td>{info['chunks_processed']}</td>
            <td>{info['successful_chunks']}/{info['chunks_processed']}</td>
            <td>
                <a href="{rel_log_path}" target="_blank">View Log File</a>
            </td>
        </tr>
        """
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Good Log Analysis Summary</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f7fa;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary-stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            flex: 1;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .issues-found {{ color: #e74c3c; }}
        .no-issues {{ color: #27ae60; }}
        .total-analyses {{ color: #3498db; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 15px;
            border-bottom: 1px solid #eee;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .status-issue {{
            border-left: 5px solid #e74c3c;
        }}
        .status-good {{
            border-left: 5px solid #27ae60;
        }}
        a {{
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Good Log Analysis Summary</h1>
        <p>Comprehensive comparison analysis results</p>
    </div>

    <div class="summary-stats">
        <div class="stat-card">
            <div class="stat-number total-analyses">{total_analyses}</div>
            <div class="stat-label">Total Analyses</div>
        </div>
        <div class="stat-card">
            <div class="stat-number issues-found">{total_issues}</div>
            <div class="stat-label">Issues Found</div>
        </div>
        <div class="stat-card">
            <div class="stat-number no-issues">{total_analyses - total_issues}</div>
            <div class="stat-label">Clean Results</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Status</th>
                <th>Error Signature</th>
                <th>Log File</th>
                <th>Chunks</th>
                <th>Success Rate</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div class="timestamp">
        Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
</body>
</html>"""

    with open(summary_file_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logging.info(f"Good log analysis summary created: {summary_file_path}")
    
    return summary_file_path


def log_analyzer(config, log_folder, no_stop=False, compare_good_log=False):
    """
    Analyze logs based on error signatures defined in config.
    
    Args:
        config: Configuration dictionary containing error signatures
        log_folder: Path to the folder containing logs to analyze
        no_stop: If True, don't exit on critical errors (default: False)
        compare_good_log: If True, enable good log comparison analysis using LLM when 
                         good_log path is specified in error signatures (default: False)
    
    Returns:
        Tuple of (stop_triggered, [], log_analyzer_log_file)
    """
    import datetime
    import glob
    import os
    import sys
    import logging
    
    log_analyzer_log_file = os.path.join(log_folder, 'log_analyzer_output.log')
    stop_on_fail_result_file = os.path.join(log_folder, 'stop_on_fail_result.log')

    # Initialize list to collect good log analyses for summary
    good_log_analyses = []

    # Write initial value 0 to the stop_on_fail_result.log file
    with open(stop_on_fail_result_file, 'w', encoding='utf-8') as stop_file:
        stop_file.write('0')

    with open(log_analyzer_log_file, 'w', encoding='utf-8') as log_file:
        log_separator("Starting Log Analysis", log_file)
        logging.info(f"Starting log analysis in folder: {log_folder}")
        log_file.write(f"Starting log analysis in folder: {log_folder}\n")

        # Log the compare_good_log parameter status
        logging.info(f"Good log comparison mode: {'ENABLED' if compare_good_log else 'DISABLED'}")
        log_file.write(f"Good log comparison mode: {'ENABLED' if compare_good_log else 'DISABLED'}\n")

        stop_triggered = False
        critical_stop_descriptions = []

        if 'error_signatures' not in config or not config['error_signatures']:
            logging.error("Configuration error: 'error_signatures' key not found or empty.")
            log_file.write("Configuration error: 'error_signatures' key not found or empty.\n")
            return stop_triggered, [], log_analyzer_log_file

        signature_count = 0
        total_signatures = len(config['error_signatures'])

        for sig in config['error_signatures']:
            signature_count += 1
            description = sig['description']
            file_pattern = sig['file']
            match_type = sig.get('match_type', 'ERROR').upper()
            stop_on_fail_check = sig.get('stop_on_fail_check', "false") == "true"
            good_log_path = sig.get('good_log')  # New field for good log comparison

            # Add separator between each signature analysis
            separator_message = f"Processing Signature {signature_count}/{total_signatures}: {description}"
            log_separator(separator_message, log_file)
            
            log_file.write(f"Processing signature: {description}\n")

            matching_files = glob.glob(os.path.join(log_folder, '**', file_pattern), recursive=True)
            if not matching_files:
                logging.info(f"No files found matching pattern {file_pattern} for signature: {description}")
                log_file.write(f"No files found that match the pattern {file_pattern}.\n")
                continue

            log_file.write(f"Files matching the pattern {file_pattern}: {', '.join(matching_files)}\n")

            # Check if good_log is specified for this signature AND compare_good_log is enabled
            if compare_good_log and good_log_path and os.path.exists(good_log_path):
                log_file.write(f"Good log comparison enabled using: {good_log_path}\n")
                logging.info(f"Good log comparison enabled for signature '{description}' using: {good_log_path}")
                
                for file_path in matching_files:
                    logging.info(f"Analyzing file with good_log comparison: {file_path}")
                    log_file.write(f"Analyzing file with good_log comparison: {file_path}\n")
                    
                    # Read both log files for LLM comparison
                    good_log_content, current_log_content = read_log_files_for_comparison(good_log_path, file_path)
                    
                    # Create a comparison analysis file for this comparison
                    file_basename = os.path.basename(file_path)
                    analysis_filename = f"good_log_analysis_{file_basename}.log"
                    analysis_file_path = os.path.join(log_folder, analysis_filename)
                    
                    if good_log_content and current_log_content:
                        # Send both logs directly to LLM for comparison and analysis
                        logging.info(f"Sending both logs to LLM for comparison and analysis...")
                        llm_config = load_llm_config()  # Load config for LLM analysis
                        is_real_issue, llm_response, analysis_info = send_good_log_analysis_to_llm(
                            sig, good_log_content, current_log_content, good_log_path, file_path, llm_config=llm_config
                        )
                        
                        # Collect analysis info for summary
                        good_log_analyses.append(analysis_info)
                        
                        log_file.write(f"LLM comparison analysis completed (saved to {analysis_filename})\n")
                        log_file.write(f"Analysis Result Summary: {'Issues detected' if is_real_issue else 'No issues detected'}\n")
                        logging.info(f"Analysis completed: {'Issues detected' if is_real_issue else 'No issues detected'}")
                        logging.info(f"Full analysis saved to: {analysis_info['analysis_file_path']}")
                        
                        if is_real_issue:
                            log_file.write(f"Error signature [{description}] matched via good_log comparison: Real issue detected\n")
                            logging.warning(f"Error signature [{description}] matched via good_log comparison: Real issue detected")
                            if stop_on_fail_check:
                                critical_stop_descriptions.append(description)
                                stop_triggered = True
                        else:
                            log_file.write(f"Good_log comparison completed - No real issues detected for file {file_path}\n")
                            logging.info(f"Good_log comparison completed - No real issues detected for file {file_path}")
                    else:
                        # Error reading files
                        with open(analysis_file_path, 'w', encoding='utf-8') as analysis_file:
                            analysis_file.write(f"Good Log Comparison Analysis - ERROR\n")
                            analysis_file.write(f"=" * 60 + "\n")
                            analysis_file.write(f"Good Log: {good_log_path}\n")
                            analysis_file.write(f"Current Log: {file_path}\n")
                            analysis_file.write(f"Error Signature: {description}\n")
                            analysis_file.write(f"=" * 60 + "\n")
                            analysis_file.write(f"ERROR: Failed to read one or both log files for comparison.\n")
                        
                        log_file.write(f"ERROR: Failed to read log files for comparison (documented in {analysis_filename})\n")
                        logging.error(f"Failed to read log files for comparison: {good_log_path} and {file_path}")
                
                # Now proceeding with traditional error signature analysis for the same files
                log_file.write(f"Now proceeding with traditional error signature analysis for the same files...\n")
                logging.info(f"Good log comparison completed, now running traditional error signature analysis")
            elif good_log_path and not compare_good_log:
                # Good log path is specified but comparison is disabled
                log_file.write(f"Good log path specified ({good_log_path}) but comparison disabled (--compare_good_log=False)\n")
                logging.info(f"Good log path specified for signature '{description}' but comparison disabled by parameter")

            # Original logic for files - runs for ALL signatures
            for file_path in matching_files:
                logging.info(f"Analyzing file: {file_path}")
                log_file.write(f"Analyzing file: {file_path}\n")

                if match_type == 'JSON':
                    # JSON analysis
                    matched_elements = analyze_json_file(file_path, sig, log_file)
                    if matched_elements:
                        for element, matched_pairs in matched_elements:
                            log_file.write(f"Error signature [{description}] matched in JSON: {matched_pairs}\n")
                            logging.warning(f"Error signature [{description}] matched in JSON: {matched_pairs}")
                        if stop_on_fail_check:
                            critical_stop_descriptions.append(description)
                            stop_triggered = True
                    else:
                        log_file.write(f"Good. JSON signature not seen in file {file_path}\n")
                        logging.info(f"Good. JSON signature not seen in file {file_path}")
                else:
                    # Robust reading approach
                    lines = robust_readlines(file_path)
                    total_lines = len(lines)
                    logging.info(f"Total number of lines in {file_path}: {total_lines}")
                    log_file.write(f"Total number of lines in {file_path}: {total_lines}\n")

                    # Run matching logic
                    if match_type == 'PASS':
                        pass_text = sig.get('pass_text', [])
                        matched_text = [pt for pt in pass_text if any(pt in line for line in lines)]
                        missing_text = [pt for pt in pass_text if pt not in matched_text]

                        if matched_text:
                            for text in matched_text:
                                log_file.write(f"Match found: {text}\n")
                                logging.info(f"Match found: {text}")

                        if missing_text:
                            for text in missing_text:
                                log_file.write(
                                    f"Error signature [{description}] missing: Expect - {text} - but not found \n"
                                )
                                logging.error(
                                    f"Error signature [{description}] missing: Expect - {text} - but not found "
                                )
                            if stop_on_fail_check:
                                critical_stop_descriptions.append(description)
                                stop_triggered = True
                        else:
                            log_file.write(f"Good. All pass criteria met for file {file_path}\n")
                            logging.info(f"Good. All pass criteria met for file {file_path}")

                    elif match_type == 'ERROR':
                        matched_lines = [
                            line for line in lines
                            if any(err.lower() in line.lower() for err in sig.get('error_text', []))
                            and not any(white.lower() in line.lower() for white in sig.get('whitelist_text', []))
                        ]
                        if matched_lines:
                            for line in matched_lines:
                                log_file.write(f"Error signature [{description}] matched: {line.strip()}\n")
                                logging.warning(f"Error signature [{description}] matched: {line.strip()}")
                            if stop_on_fail_check:
                                critical_stop_descriptions.append(description)
                                stop_triggered = True
                        else:
                            log_file.write(f"Good. Signature not seen in file {file_path}\n")
                            logging.info(f"Good. Signature not seen in file {file_path}")

                    else:
                        log_file.write(f"Unknown match_type: {match_type} for signature: {description}\n")
                        logging.error(f"Unknown match_type: {match_type} for signature: {description}")

        log_separator("Analysis Complete", log_file)
        logging.info("Completed processing all error signatures.")
        log_file.write("Completed processing all error signatures.\n")

        # Create summary if we have good log analyses (only when compare_good_log is enabled)
        if compare_good_log and good_log_analyses:
            summary_path = create_good_log_analysis_summary(log_folder, good_log_analyses)
            logging.info(f"Good log analysis summary created: {summary_path}")

        # Stop on fail if triggered
        if stop_triggered and not no_stop:
            with open(stop_on_fail_result_file, 'w', encoding='utf-8') as stop_file:
                stop_file.write('1')
            for description in critical_stop_descriptions:
                logging.error(f"Critical stop triggered by: {description}")
                log_file.write(f"Critical stop triggered by: {description}\n")
            sys.exit(1)

    return stop_triggered, [], log_analyzer_log_file


def analyze_json_file(file_path, signature, log_file):
    """
    Analyze a JSON file to match elements in arrays based on given conditions.
    """
    import json
    import logging
    
    error_text = signature.get('error_text', [])
    whitelist_text = signature.get('whitelist_text', [])
    matched_elements = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
    except UnicodeDecodeError as e:
        log_file.write(f"Error reading JSON file {file_path}: Encoding issue ({e}). Trying 'latin-1'.\n")
        logging.warning(f"Error reading JSON file {file_path}: Encoding issue ({e}). Retrying with 'latin-1'.")
        try:
            with open(file_path, 'r', encoding='latin-1') as file:
                json_data = json.load(file)
        except (UnicodeDecodeError, json.JSONDecodeError) as inner_e:
            log_file.write(f"Error reading JSON file {file_path} after retrying: {inner_e}\n")
            logging.error(f"Error reading JSON file {file_path} after retrying: {inner_e}")
            return matched_elements  # Return empty matched_elements to continue processing
    except json.JSONDecodeError as e:
        log_file.write(f"Error parsing JSON file {file_path}: Invalid JSON format ({e}).\n")
        logging.error(f"Error parsing JSON file {file_path}: Invalid JSON format ({e}).")
        return matched_elements  # Return empty matched_elements to continue processing

    def check_element(element):
        """Check if a JSON element matches error_text criteria and avoids whitelist_text."""
        matched_pairs = []
        for condition in error_text:
            for key, value in condition.items():
                if key in element and value in element[key]:
                    matched_pairs.append({key: value})
                elif key in element and value in element[key]:
                    matched_pairs.append({key: value})
                else:
                    return None  # Exit early if any condition is not met

        for whitelist in whitelist_text:
            if any(whitelist in str(value) for value in element.values()):
                return None  # Exclude if a whitelist condition is met

        return matched_pairs

    def traverse_json(data):
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    matched_pairs = check_element(item)
                    if matched_pairs:
                        matched_elements.append((item, matched_pairs))
        elif isinstance(data, dict):
            for key, value in data.items():
                traverse_json(value)

    traverse_json(json_data)
    return matched_elements


# Utility Functions

def display_title(title):
    logging.info("+" + "-" * (len(title) + 2) + "+")
    logging.info("| " + title + " |")
    logging.info("+" + "-" * (len(title) + 2) + "+")


def read_config_m(signature):
    try:
        # Determine the base path dynamically based on the OS
        base_path = Path("../sut") if os.name == "nt" else Path("../sut")
        
        # Recursively search for the settings file in the sut folder and its subfolders
        matching_files = list(base_path.rglob(f"settings.{signature}.json"))
        
        if not matching_files:
            raise FileNotFoundError(f"Configuration file for Signature {signature} not found.")
        
        if len(matching_files) > 1:
            logging.warning(
                f"Multiple configuration files found for Signature {signature}. Using the first match: {matching_files[0]}"
            )
        
        settings_filename = matching_files[0]
        
        # Read the corresponding settings file
        with settings_filename.open("r") as file:
            settings = json.load(file)
        
        # Append the 'FILE_NAME' key with signature value
        settings['FILE_NAME'] = signature
        
        return settings

    except Exception as e:
        logging.error(f"Error reading SUT-specific configuration file for Signature {signature}: {e}")
        return None


def progress_bar(sleep_time: int) -> None:
    logging.info(f"Delaying for {sleep_time}s...")
    for count in range(sleep_time + 1):
        bar_length = 60
        filled_up_length = int(round(bar_length * count  / float(sleep_time)))
        percentage = round(100 * count // sleep_time , 1)
        filled_bar = '=' * filled_up_length + ' ' * (bar_length - filled_up_length)
        sys.stdout.write(f"[{filled_bar}] {percentage}%\r")
        sys.stdout.flush()
        time.sleep(1)
    print()


def fetch_latest_error_signatures(log_folder):
    """
    Fetch and return the content lines from the latest error_signatures.log file in the specified folder.
    If the file is empty, return an empty list.
    """
    latest_file = None
    latest_mtime = 0
    
    # Traverse the log_folder recursively
    for root, _, files in os.walk(log_folder):
        for file in files:
            if file == "error_signatures.log":
                file_path = os.path.join(root, file)
                # Get the last modified time
                mtime = os.path.getmtime(file_path)
                if mtime > latest_mtime:
                    latest_mtime = mtime
                    latest_file = file_path
    
    # If no file is found, return an empty list
    if not latest_file:
        logging.info("No error_signatures.log found.")
        return []

    # Read and return content lines
    try:
        with open(latest_file, "r") as f:
            content = f.readlines()
            logging.info(f"Latest error_signatures.log: {latest_file}")
            return [line.strip() for line in content]  # Strip newline characters
    except Exception as e:
        logging.error(f"Error reading error_signatures.log: {e}")
        return []


def extract_stop_on_fail_reason(output):
    """
    Extract the 'stop_on_fail_reason' from the output.
    Handles cases where the output contains mixed content (logs + JSON).
    """
    try:
        # Attempt to isolate the JSON part of the output
        logging.info("Attempting to extract JSON from the output.")
        start_index = output.find('{')  # Find the first '{'
        end_index = output.rfind('}')   # Find the last '}'

        if start_index == -1 or end_index == -1:
            logging.error("No JSON object found in the output.")
            return "Unknown reason (JSON missing in output)"

        # Extract potential JSON string
        json_part = output[start_index:end_index + 1]
        logging.debug(f"Extracted JSON part: {json_part}")

        # Parse the JSON part
        result_json = json.loads(json_part)
        return result_json.get("stop_on_fail_reason", "Reason not specified")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}. Output: {output}")
        return "Unknown reason (Invalid JSON)"
    except Exception as e:
        logging.error(f"Unexpected error: {e}. Output: {output}")
        return "Unknown reason (Unexpected error)"


def make_logfolder(folder_name, logpath=None, skip_timestamp=False, skip_version=False, skip_hostname=False): 
    # Get version and hostname details, if required
    version = read_version() if not skip_version else ""
    hostname = socket.gethostname()[-5:] if not skip_hostname else ""  # Take only the last 5 characters
    
    # Construct folder name based on flags
    parts = [folder_name]
    if version:
        parts.append(version)
    # Avoid adding the hostname if it's already part of the folder_name
    if hostname and hostname not in folder_name:
        parts.append(hostname)
    if not skip_timestamp:
        timestamp = datetime.datetime.now().strftime("%m%d%H%M")  # Month-Day Hour-Minute
        parts.append(timestamp)

    # Join parts with hyphens to form the final folder name
    folder_name = "-".join(filter(None, parts))  # Filter out empty strings if any part is skipped

    # Set log folder path based on current directory
    log_folder = os.path.join(logpath or os.getcwd(), "logs", folder_name)

    # Print for debugging
    print(f"Constructed log folder path: {log_folder}")
    
    # Attempt to create the directory
    os.makedirs(log_folder, exist_ok=True)
    return log_folder


def get_timestamp():
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    return timestamp


def serialize_json(json_file_path, id_val=None, created_val=None, severity_val=None, message_val=None, provider_val=None, extra_val=None):
    def normalize_timestamp(timestamp):
        """Normalize timestamp to 'YYYY-MM-DDTHH:MM:SS' format."""
        try:
            # Try different formats that the timestamp might come in
            # Add or modify strptime formats as needed
            for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f'):
                try:
                    return datetime.datetime.strptime(timestamp, fmt).strftime('%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue
            logging.warning(f"Timestamp '{timestamp}' could not be normalized.")
            return timestamp  # Return original if it cannot be normalized
        except Exception as e:
            logging.error(f"Error normalizing timestamp '{timestamp}': {e}")
            return timestamp

    try:
        logging.info(f"Starting serialization of JSON file: {json_file_path}")
        
        with open(json_file_path, 'r', encoding='utf-8') as json_file:
            json_file_opened = json.load(json_file)
        
        logging.info(f"JSON file loaded successfully. Top-level structure type: {type(json_file_opened)}")
        
        if isinstance(json_file_opened, dict):
            if "Members" in json_file_opened and isinstance(json_file_opened["Members"], list):
                entries = json_file_opened["Members"]
            else:
                entries = [json_file_opened]
        elif isinstance(json_file_opened, list):
            entries = json_file_opened
        else:
            logging.error(f"Unsupported top-level JSON structure: {type(json_file_opened)}")
            return
        
        base_name = os.path.basename(json_file_path)
        name, ext = os.path.splitext(base_name)
        serialized_log_path = os.path.join(os.path.dirname(json_file_path), f"{name}_serialized.log")

        with open(serialized_log_path, 'w', encoding='utf-8') as log_file:
            for index, entry in enumerate(entries):
                if isinstance(entry, dict):
                    try:
                        id_value = entry.get(id_val, entry.get("Id", "N/A")) if id_val else entry.get("Id", "N/A")
                        created_value = entry.get(created_val, entry.get("Created", "N/A")) if created_val else entry.get("Created", "N/A")
                        created_value = normalize_timestamp(created_value)  # Normalize the timestamp
                        severity_value = entry.get(severity_val, entry.get("Severity", "N/A")) if severity_val else entry.get("Severity", "N/A")
                        message_value = entry.get(message_val, entry.get("Message", "N/A")) if message_val else entry.get("Message", "N/A")
                        provider_value = entry.get(provider_val, entry.get("ProviderName", "N/A")) if provider_val else entry.get("ProviderName", "N/A")
                        extra_value = entry.get(extra_val, entry.get("properties_decode", "N/A")) if extra_val else entry.get("properties_decode", "N/A")

                        if isinstance(message_value, str):
                            message_value = message_value.replace('\n', ' ').replace('\r', ' ')

                        if isinstance(extra_value, list):
                            cleaned_extra_value = ''.join([chr(item) if isinstance(item, int) and 32 <= item <= 126 else str(item) for item in extra_value])
                        else:
                            cleaned_extra_value = str(extra_value).replace('\n', ' ').replace('\r', ' ')

                        log_line = f"Id={id_value} | Created={created_value} | Severity={severity_value} | Message={message_value} | Provider={provider_value} | Extra={cleaned_extra_value}\n"
                        log_file.write(log_line)
                    except Exception as inner_exception:
                        logging.error(f"Error processing entry {index + 1}: {inner_exception}")
                else:
                    logging.error(f"Skipping entry {index + 1} that is not a dictionary: {entry}")

        logging.info(f"Serialized log written to {serialized_log_path}")
    
    except Exception as e:
        logging.error(f"An error occurred while serializing the log: {e}")


def create_testlog(test_name, logpath=None, skip_timestamp=False, skip_version=False, skip_hostname=False):
    # Call make_logfolder with additional flags
    log_folder = make_logfolder(test_name, logpath=logpath, skip_timestamp=skip_timestamp, skip_version=skip_version, skip_hostname=skip_hostname)
    
    if not os.path.isdir(log_folder):
        logging.error("Log folder creation failed, aborting...")
        return None, None, None, None

    # Prepare log file path and name
    timestamp = datetime.datetime.now().strftime("%m%d%H%M") if not skip_timestamp else ""
    log_filename = f"{test_name}_{timestamp}.log".strip("_")
    log_file_path = os.path.join(log_folder, log_filename)
    logging.info(f"Preparing to create log file: {log_file_path}")

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')

    # Add or replace the file handler
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setFormatter(formatter)
    handlers_to_keep = []
    
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
        elif isinstance(handler, logging.StreamHandler):
            handler.setFormatter(formatter)
            handlers_to_keep.append(handler)

    logger.handlers = handlers_to_keep + [file_handler]

    logging.info(f"Log file path: {log_file_path}")
    logging.info(f"Log folder: {log_folder}")
    logging.info(f"Log filename: {log_filename}")

    return timestamp if not skip_timestamp else None, log_file_path, log_folder, log_filename

def read_version():
    version_file = "version.txt"  # Read from the current folder

    try:
        with open(version_file, "r", encoding="utf-8") as f:
            version = f.read().strip()
            # Check for non-ASCII characters and invalid UTF-8 characters
            if not version or not version.isascii():
                print("Version contains non-ASCII characters or is empty, using '0'")
                return "0"
            # Optional: Check if the version is in the allowed format using regex
            
            pattern = r'^\d+\.\d+(\.[a-zA-Z]+)?$'
            if not re.match(pattern, version):              # ← This line should align with the lines above
                print("Version format is invalid, using '0'")
                return "0"
            return version
    except (FileNotFoundError, UnicodeDecodeError):
        # Handle file not found or unreadable content
        print("Version file not found or contains invalid characters, using '0'")
        return "0"