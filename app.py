import os
import json
import base64
import logging
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from decryptors import DECRYPTORS

# ─── Configuration ──────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
PORT = int(os.getenv('PORT', 5000))

logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO)
logger = logging.getLogger(__name__)

# ─── Helper: Detect extension from filename ────────────────────
def detect_extension(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext in DECRYPTORS:
        return ext
    # Fallback: check against known extensions
    for known in DECRYPTORS:
        if filename.lower().endswith(known):
            return known
    return None

# ─── Helper: Attempt magic‑byte detection ─────────────────────
def detect_by_magic(data: bytes) -> str:
    """Optional: detect file type by header if extension missing."""
    # NPVT files often start with b'NPVTSUB1' or b'NPVT1'
    if data.startswith(b'NPVTSUB1') or data.startswith(b'NPVT1'):
        return '.npvt'
    # EHI files are binary, but we can't easily detect; rely on extension
    # SSC are plain text starting with "ssc://" or JSON-like
    try:
        text = data[:100].decode('utf-8', errors='ignore')
        if text.strip().startswith('ssc://') or text.strip().startswith('{'):
            return '.ssc'
    except:
        pass
    # Dark Tunnel often starts with base64 JSON after "://"
    # HTTP Custom is tricky – rely on extension.
    return None

@app.route('/')
def index():
  return send_file('index.html')

# ─── Main Decrypt Endpoint ──────────────────────────────────────
@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """
    Accept a file (multipart/form-data) and return decrypted JSON.
    Form field name: 'file' (required)
    Optional: 'filename' (if not provided, we use the uploaded file's name)
    """
    try:
        # 1. Get file from request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in request'}), 400

        uploaded = request.files['file']
        if uploaded.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        # 2. Read file data
        data = uploaded.read()
        if len(data) == 0:
            return jsonify({'error': 'File is empty'}), 400
        if len(data) > MAX_FILE_SIZE:
            return jsonify({'error': f'File exceeds {MAX_FILE_SIZE//1024//1024}MB limit'}), 413

        # 3. Determine extension
        filename = uploaded.filename
        ext = detect_extension(filename)
        if not ext:
            # Try magic detection
            ext = detect_by_magic(data)
        if not ext:
            return jsonify({'error': f'Unsupported file type: {filename}'}), 400

        # 4. Get decryptor
        decryptor = DECRYPTORS.get(ext)
        if not decryptor:
            return jsonify({'error': f'No decryptor for extension {ext}'}), 400

        # 5. Decrypt
        logger.info(f'Decrypting {filename} as {ext}')
        result = decryptor(data)
        if result is None:
            return jsonify({'error': 'Decryption failed – invalid or corrupted file'}), 400

        # 6. Return JSON response
        return jsonify({
            'status': 'success',
            'extension': ext,
            'filename': filename,
            'decrypted': result
        })

    except Exception as e:
        logger.exception('Unexpected error during decryption')
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

# ─── Alternative: Decrypt from Base64 JSON ─────────────────────
@app.route('/decrypt/base64', methods=['POST'])
def decrypt_base64():
    """
    Accept JSON: {"file": "<base64 string>", "filename": "optional"}
    Returns same structure as /decrypt.
    """
    try:
        data = request.get_json()
        if not data or 'file' not in data:
            return jsonify({'error': 'Missing "file" field in JSON'}), 400

        file_b64 = data['file']
        # Remove data URL prefix if present
        if ',' in file_b64:
            file_b64 = file_b64.split(',')[1]
        file_bytes = base64.b64decode(file_b64)

        filename = data.get('filename', 'unknown.bin')
        if len(file_bytes) > MAX_FILE_SIZE:
            return jsonify({'error': f'File exceeds {MAX_FILE_SIZE//1024//1024}MB limit'}), 413

        ext = detect_extension(filename)
        if not ext:
            ext = detect_by_magic(file_bytes)
        if not ext:
            return jsonify({'error': f'Unsupported file type: {filename}'}), 400

        decryptor = DECRYPTORS.get(ext)
        if not decryptor:
            return jsonify({'error': f'No decryptor for extension {ext}'}), 400

        result = decryptor(file_bytes)
        if result is None:
            return jsonify({'error': 'Decryption failed'}), 400

        return jsonify({
            'status': 'success',
            'extension': ext,
            'filename': filename,
            'decrypted': result
        })

    except base64.binascii.Error:
        return jsonify({'error': 'Invalid base64 encoding'}), 400
    except Exception as e:
        logger.exception('Error in /decrypt/base64')
        return jsonify({'error': f'Internal error: {str(e)}'}), 500

# ─── Health Check ────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'supported_extensions': list(DECRYPTORS.keys()),
        'version': '2.0.0'
    })

# ─── Run ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)