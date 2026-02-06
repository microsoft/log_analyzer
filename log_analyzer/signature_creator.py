#!/usr/bin/env python3
"""
Signature Creator - Interactive HTML-based web UI for creating and editing
log analyzer signature configuration files.

Usage:
    python signature_creator.py [--port PORT] [--signature NAME]

Requirements:
    - Python 3.7+ (no external dependencies)
    - Uses only built-in http.server module
"""

import argparse
import json
import os
import socket
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class SignatureHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the signature creator UI."""
    
    # Class variable to store the signature name
    signature_name = "sample"
    sut_folder = None

    def log_message(self, format, *args):
        """Override to customize log messages."""
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            # Serve the main HTML UI
            self.serve_html_ui()
        elif parsed_path.path == '/api/signature':
            # Load the signature file
            self.load_signature()
        elif parsed_path.path == '/api/list':
            # List available signature files
            self.list_signatures()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/api/signature':
            # Save the signature file
            self.save_signature()
        else:
            self.send_error(404, "Not Found")

    def serve_html_ui(self):
        """Serve the embedded HTML UI."""
        html_content = self.get_html_content()
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html_content.encode('utf-8')))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def load_signature(self):
        """Load signature JSON file and return it."""
        try:
            # Parse query parameters to get the signature name
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            signature_name = query_params.get('name', [self.signature_name])[0]
            
            signature_file = self.sut_folder / f"settings.{signature_name}.json"
            
            if not signature_file.exists():
                self.send_json_response({'error': f'Signature file not found: {signature_file}'}, 404)
                return
            
            with open(signature_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            response = {
                'signature_name': signature_name,
                'data': data,
                'file_path': str(signature_file)
            }
            self.send_json_response(response, 200)
        except json.JSONDecodeError as e:
            self.send_json_response({'error': f'Invalid JSON: {str(e)}'}, 400)
        except Exception as e:
            self.send_json_response({'error': f'Error loading signature: {str(e)}'}, 500)

    def save_signature(self):
        """Save signature JSON file."""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            signature_name = data.get('signature_name', self.signature_name)
            signature_data = data.get('data', {})
            
            signature_file = self.sut_folder / f"settings.{signature_name}.json"
            
            # Validate the data structure
            if 'error_signatures' not in signature_data:
                self.send_json_response({'error': 'Invalid signature data: missing error_signatures'}, 400)
                return
            
            # Write to file with pretty formatting
            with open(signature_file, 'w', encoding='utf-8') as f:
                json.dump(signature_data, f, indent=2, ensure_ascii=False)
            
            self.send_json_response({
                'success': True,
                'message': f'Signature saved to {signature_file}',
                'file_path': str(signature_file)
            }, 200)
        except json.JSONDecodeError as e:
            self.send_json_response({'error': f'Invalid JSON: {str(e)}'}, 400)
        except Exception as e:
            self.send_json_response({'error': f'Error saving signature: {str(e)}'}, 500)

    def list_signatures(self):
        """List all available signature files."""
        try:
            signature_files = []
            for file in self.sut_folder.glob("settings.*.json"):
                name = file.stem.replace("settings.", "")
                signature_files.append({
                    'name': name,
                    'path': str(file)
                })
            
            self.send_json_response({'signatures': signature_files}, 200)
        except Exception as e:
            self.send_json_response({'error': f'Error listing signatures: {str(e)}'}, 500)

    def send_json_response(self, data, status_code=200):
        """Send a JSON response."""
        json_data = json.dumps(data, indent=2)
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(json_data.encode('utf-8')))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def get_html_content(self):
        """Return the embedded HTML UI content."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analyzer - Signature Creator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .toolbar {
            background: #f5f5f5;
            padding: 20px 40px;
            border-bottom: 1px solid #ddd;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .toolbar label {
            font-weight: 600;
            margin-right: 5px;
        }
        
        .toolbar input, .toolbar select {
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .toolbar button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: background 0.3s;
        }
        
        .toolbar button:hover {
            background: #5568d3;
        }
        
        .toolbar button.save {
            background: #48bb78;
        }
        
        .toolbar button.save:hover {
            background: #38a169;
        }
        
        .toolbar button.add {
            background: #ed8936;
        }
        
        .toolbar button.add:hover {
            background: #dd6b20;
        }
        
        .content {
            padding: 40px;
        }
        
        .signature-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .signature-item {
            background: #f9f9f9;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            position: relative;
            transition: box-shadow 0.3s;
        }
        
        .signature-item:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .signature-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .signature-header h3 {
            color: #667eea;
            font-size: 1.3em;
        }
        
        .signature-actions {
            display: flex;
            gap: 10px;
        }
        
        .signature-actions button {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-delete {
            background: #f56565;
            color: white;
        }
        
        .btn-delete:hover {
            background: #e53e3e;
        }
        
        .btn-up, .btn-down {
            background: #cbd5e0;
            color: #2d3748;
        }
        
        .btn-up:hover, .btn-down:hover {
            background: #a0aec0;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 5px;
            color: #2d3748;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #cbd5e0;
            border-radius: 4px;
            font-size: 14px;
            font-family: inherit;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
            font-family: 'Courier New', monospace;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        .array-input {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        
        .array-item {
            display: flex;
            gap: 5px;
        }
        
        .array-item input {
            flex: 1;
        }
        
        .array-item button {
            padding: 5px 10px;
            background: #f56565;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .array-item button:hover {
            background: #e53e3e;
        }
        
        .add-array-item {
            margin-top: 5px;
            padding: 5px 10px;
            background: #48bb78;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            align-self: flex-start;
        }
        
        .add-array-item:hover {
            background: #38a169;
        }
        
        .status-message {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            z-index: 1000;
            animation: slideIn 0.3s;
        }
        
        .status-message.success {
            background: #48bb78;
        }
        
        .status-message.error {
            background: #f56565;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #718096;
        }
        
        .empty-state h2 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #667eea;
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Log Analyzer - Signature Creator</h1>
            <p>Create and edit log analyzer signature configuration files</p>
        </div>
        
        <div class="toolbar">
            <label for="signatureName">Signature:</label>
            <input type="text" id="signatureName" placeholder="sample" />
            
            <button onclick="loadSignature()">Load</button>
            <button onclick="saveSignature()" class="save">Save</button>
            <button onclick="addSignature()" class="add">+ Add Signature</button>
            <button onclick="viewJSON()">View JSON</button>
        </div>
        
        <div class="content">
            <div id="loading" class="loading">Loading...</div>
            <div id="signatureList" class="signature-list" style="display:none;"></div>
        </div>
    </div>

    <script>
        let currentData = { error_signatures: [] };
        let currentSignatureName = '';

        // Load signature on page load
        window.addEventListener('DOMContentLoaded', () => {
            const urlParams = new URLSearchParams(window.location.search);
            const sigName = urlParams.get('signature') || '';
            if (sigName) {
                document.getElementById('signatureName').value = sigName;
            }
            loadSignature();
        });

        async function loadSignature() {
            const signatureName = document.getElementById('signatureName').value.trim() || 'sample';
            currentSignatureName = signatureName;
            
            try {
                const response = await fetch(`/api/signature?name=${encodeURIComponent(signatureName)}`);
                const result = await response.json();
                
                if (response.ok) {
                    currentData = result.data;
                    renderSignatures();
                    showStatus('Signature loaded successfully', 'success');
                } else {
                    showStatus(`Error: ${result.error}`, 'error');
                    // Initialize empty signature if not found
                    currentData = { error_signatures: [] };
                    renderSignatures();
                }
            } catch (error) {
                showStatus(`Error loading signature: ${error.message}`, 'error');
            }
        }

        async function saveSignature() {
            const signatureName = document.getElementById('signatureName').value.trim() || 'sample';
            
            try {
                const response = await fetch('/api/signature', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        signature_name: signatureName,
                        data: currentData
                    })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showStatus('Signature saved successfully!', 'success');
                } else {
                    showStatus(`Error: ${result.error}`, 'error');
                }
            } catch (error) {
                showStatus(`Error saving signature: ${error.message}`, 'error');
            }
        }

        function renderSignatures() {
            const container = document.getElementById('signatureList');
            const loading = document.getElementById('loading');
            
            loading.style.display = 'none';
            container.style.display = 'block';
            container.innerHTML = '';
            
            if (!currentData.error_signatures || currentData.error_signatures.length === 0) {
                container.innerHTML = '<div class="empty-state"><h2>No signatures yet</h2><p>Click "+ Add Signature" to create your first signature</p></div>';
                return;
            }
            
            currentData.error_signatures.forEach((sig, index) => {
                const sigElement = createSignatureElement(sig, index);
                container.appendChild(sigElement);
            });
        }

        function createSignatureElement(sig, index) {
            const div = document.createElement('div');
            div.className = 'signature-item';
            
            const matchType = sig.match_type || 'ERROR';
            const showErrorText = matchType === 'ERROR' || matchType === 'JSON';
            const showPassText = matchType === 'PASS';
            
            div.innerHTML = `
                <div class="signature-header">
                    <h3>Signature #${index + 1}: ${sig.description || 'Unnamed'}</h3>
                    <div class="signature-actions">
                        <button class="btn-up" onclick="moveSignature(${index}, -1)" ${index === 0 ? 'disabled' : ''}>↑</button>
                        <button class="btn-down" onclick="moveSignature(${index}, 1)" ${index === currentData.error_signatures.length - 1 ? 'disabled' : ''}>↓</button>
                        <button class="btn-delete" onclick="deleteSignature(${index})">Delete</button>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Description:</label>
                        <input type="text" value="${escapeHtml(sig.description || '')}" onchange="updateSignature(${index}, 'description', this.value)" />
                    </div>
                    <div class="form-group">
                        <label>Match Type:</label>
                        <select onchange="updateSignature(${index}, 'match_type', this.value); renderSignatures();">
                            <option value="ERROR" ${matchType === 'ERROR' ? 'selected' : ''}>ERROR</option>
                            <option value="PASS" ${matchType === 'PASS' ? 'selected' : ''}>PASS</option>
                            <option value="JSON" ${matchType === 'JSON' ? 'selected' : ''}>JSON</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>File Pattern:</label>
                        <input type="text" value="${escapeHtml(sig.file || '')}" onchange="updateSignature(${index}, 'file', this.value)" />
                    </div>
                    <div class="form-group">
                        <label>Stop on Fail:</label>
                        <select onchange="updateSignature(${index}, 'stop_on_fail_check', this.value)">
                            <option value="false" ${String(sig.stop_on_fail_check) === 'false' ? 'selected' : ''}>false</option>
                            <option value="true" ${String(sig.stop_on_fail_check) === 'true' ? 'selected' : ''}>true</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Good Log (Optional):</label>
                    <input type="text" value="${escapeHtml(sig.good_log || '')}" onchange="updateSignature(${index}, 'good_log', this.value)" />
                </div>
                
                ${showErrorText ? `
                <div class="form-group">
                    <label>${matchType === 'JSON' ? 'Error Criteria (JSON key-value pairs):' : 'Error Text (strings to match):'}</label>
                    <div class="array-input" id="error-text-${index}">
                        ${(sig.error_text || []).map((text, i) => `
                            <div class="array-item">
                                <input type="text" value="${escapeHtml(text)}" onchange="updateArrayItem(${index}, 'error_text', ${i}, this.value)" />
                                <button onclick="removeArrayItem(${index}, 'error_text', ${i})">Remove</button>
                            </div>
                        `).join('')}
                        <button class="add-array-item" onclick="addArrayItem(${index}, 'error_text')">+ Add ${matchType === 'JSON' ? 'Criteria' : 'Text'}</button>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Whitelist Text (strings to exclude):</label>
                    <div class="array-input" id="whitelist-text-${index}">
                        ${(sig.whitelist_text || []).map((text, i) => `
                            <div class="array-item">
                                <input type="text" value="${escapeHtml(text)}" onchange="updateArrayItem(${index}, 'whitelist_text', ${i}, this.value)" />
                                <button onclick="removeArrayItem(${index}, 'whitelist_text', ${i})">Remove</button>
                            </div>
                        `).join('')}
                        <button class="add-array-item" onclick="addArrayItem(${index}, 'whitelist_text')">+ Add Text</button>
                    </div>
                </div>
                ` : ''}
                
                ${showPassText ? `
                <div class="form-group">
                    <label>Pass Text (strings that MUST be found):</label>
                    <div class="array-input" id="pass-text-${index}">
                        ${(sig.pass_text || []).map((text, i) => `
                            <div class="array-item">
                                <input type="text" value="${escapeHtml(text)}" onchange="updateArrayItem(${index}, 'pass_text', ${i}, this.value)" />
                                <button onclick="removeArrayItem(${index}, 'pass_text', ${i})">Remove</button>
                            </div>
                        `).join('')}
                        <button class="add-array-item" onclick="addArrayItem(${index}, 'pass_text')">+ Add Text</button>
                    </div>
                </div>
                ` : ''}
                
                <div class="form-group">
                    <label>Comment:</label>
                    <textarea onchange="updateSignature(${index}, 'comment', this.value)">${escapeHtml(sig.comment || '')}</textarea>
                </div>
            `;
            
            return div;
        }

        function addSignature() {
            const newSig = {
                description: 'New Signature',
                match_type: 'ERROR',
                file: '',
                error_text: [],
                whitelist_text: [],
                stop_on_fail_check: 'false',
                comment: ''
            };
            currentData.error_signatures.push(newSig);
            renderSignatures();
        }

        function deleteSignature(index) {
            if (confirm('Are you sure you want to delete this signature?')) {
                currentData.error_signatures.splice(index, 1);
                renderSignatures();
            }
        }

        function moveSignature(index, direction) {
            const newIndex = index + direction;
            if (newIndex >= 0 && newIndex < currentData.error_signatures.length) {
                const temp = currentData.error_signatures[index];
                currentData.error_signatures[index] = currentData.error_signatures[newIndex];
                currentData.error_signatures[newIndex] = temp;
                renderSignatures();
            }
        }

        function updateSignature(index, field, value) {
            currentData.error_signatures[index][field] = value;
        }

        function updateArrayItem(sigIndex, field, itemIndex, value) {
            if (!currentData.error_signatures[sigIndex][field]) {
                currentData.error_signatures[sigIndex][field] = [];
            }
            currentData.error_signatures[sigIndex][field][itemIndex] = value;
        }

        function addArrayItem(sigIndex, field) {
            if (!currentData.error_signatures[sigIndex][field]) {
                currentData.error_signatures[sigIndex][field] = [];
            }
            currentData.error_signatures[sigIndex][field].push('');
            renderSignatures();
        }

        function removeArrayItem(sigIndex, field, itemIndex) {
            currentData.error_signatures[sigIndex][field].splice(itemIndex, 1);
            renderSignatures();
        }

        function viewJSON() {
            const jsonStr = JSON.stringify(currentData, null, 2);
            const newWindow = window.open('', '_blank');
            newWindow.document.write(`
                <html>
                <head>
                    <title>Signature JSON</title>
                    <style>
                        body { font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }
                        pre { white-space: pre-wrap; word-wrap: break-word; }
                    </style>
                </head>
                <body>
                    <h1>Signature JSON</h1>
                    <pre>${escapeHtml(jsonStr)}</pre>
                </body>
                </html>
            `);
        }

        function showStatus(message, type) {
            const statusDiv = document.createElement('div');
            statusDiv.className = `status-message ${type}`;
            statusDiv.textContent = message;
            document.body.appendChild(statusDiv);
            
            setTimeout(() => {
                statusDiv.remove();
            }, 3000);
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
"""


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Create a socket to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception:
        return "127.0.0.1"


def main():
    """Main entry point for the signature creator."""
    parser = argparse.ArgumentParser(
        description='Log Analyzer Signature Creator - Interactive Web UI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python signature_creator.py
  python signature_creator.py --port 8080 --signature sample
  python signature_creator.py --port 9000 --signature gpu_debug
        """
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to bind the web server (default: 8080)'
    )
    
    parser.add_argument(
        '--signature',
        type=str,
        default='sample',
        help='Signature name to load/edit (loads sut/settings.{name}.json) (default: sample)'
    )
    
    args = parser.parse_args()
    
    # Determine paths
    script_dir = Path(__file__).resolve().parent
    sut_folder = script_dir.parent / "sut"
    
    # Verify sut folder exists
    if not sut_folder.exists():
        print(f"Error: sut folder not found at {sut_folder}")
        print("Creating sut folder...")
        sut_folder.mkdir(parents=True, exist_ok=True)
    
    # Set class variables
    SignatureHandler.signature_name = args.signature
    SignatureHandler.sut_folder = sut_folder
    
    # Create HTTP server
    server_address = ('0.0.0.0', args.port)
    httpd = HTTPServer(server_address, SignatureHandler)
    
    # Get local IP for display
    local_ip = get_local_ip()
    
    # Print banner
    print("=" * 60)
    print("🔍 Signature Creator is ready!")
    print("=" * 60)
    print(f"Signature name: {args.signature}")
    print(f"Configuration folder: {sut_folder}")
    print("")
    print("Open in browser:")
    print(f"  Local:   http://localhost:{args.port}")
    print(f"  Network: http://{local_ip}:{args.port}")
    print("")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        httpd.shutdown()
        print("Server stopped.")


if __name__ == '__main__':
    main()
