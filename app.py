# app.py - Fixed using dark_cloud_decryptor for string

import os
import io
import json
import base64
import logging
import zipfile
import requests
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from decryptors import DECRYPTORS
from decryptors.dark_cloud_decryptor import DTDecryptor as DarkCloudDecryptor

app = Flask(__name__)
CORS(app)

MAX_FILE_SIZE = 10 * 1024 * 1024
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
PORT = int(os.getenv('PORT', 5000))

logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO)
logger = logging.getLogger(__name__)

def detect_extension(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext in DECRYPTORS:
        return ext
    for known in DECRYPTORS:
        if filename.lower().endswith(known):
            return known
    return None

def detect_by_magic(data: bytes) -> str:
    if data.startswith(b'NPVTSUB1') or data.startswith(b'NPVT1'):
        return '.npvt'
    try:
        text = data[:100].decode('utf-8', errors='ignore')
        if text.strip().startswith('ssc://') or text.strip().startswith('{'):
            return '.ssc'
    except:
        pass
    return None

@app.route('/')
def index():
    return send_file('index.html')

# ─── Dark Tunnel String Decrypt Endpoint using Dark Cloud Decryptor ──────
@app.route('/decrypt/darktunnel', methods=['POST'])
def decrypt_dark_tunnel_string():
    try:
        if request.is_json:
            data = request.get_json()
            if not data or 'string' not in data:
                return jsonify({'error': 'Missing "string" field'}), 400
            raw_string = data['string'].strip()
        else:
            raw_string = request.data.decode('utf-8', errors='ignore').strip()
            if not raw_string:
                return jsonify({'error': 'Empty request body'}), 400

        logger.info(f'Decrypting dark tunnel string with dark_cloud_decryptor (length: {len(raw_string)})')

        # Remove prefix
        if raw_string.startswith('darktunnel://'):
            raw_string = raw_string[12:].strip()
        elif '://' in raw_string:
            raw_string = raw_string.split('://', 1)[1]

        if not raw_string:
            return jsonify({'error': 'Invalid dark tunnel format'}), 400

        # Clean and fix
        raw_string = ''.join(raw_string.split())
        if raw_string.startswith('/'):
            raw_string = raw_string[1:]

        # Use dark_cloud_decryptor
        file_bytes = raw_string.encode('utf-8')
        result = DarkCloudDecryptor.execute(file_bytes)

        if result is None:
            return jsonify({'error': 'Decryption failed - invalid dark tunnel string'}), 400

        try:
            json_start = result.find('{')
            if json_start != -1:
                json_end = result.rfind('}') + 1
                if json_end > json_start:
                    parsed = json.loads(result[json_start:json_end])
                    return jsonify({
                        'status': 'success',
                        'type': 'dark_tunnel',
                        'decrypted': parsed,
                        'formatted': result
                    })
        except:
            pass

        return jsonify({
            'status': 'success',
            'type': 'dark_tunnel',
            'decrypted': result,
            'formatted': result
        })

    except Exception as e:
        logger.exception('Error in /decrypt/darktunnel')
        return jsonify({'error': f'Internal error: {str(e)}'}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file'}), 400

        uploaded = request.files['file']
        if uploaded.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        data = uploaded.read()
        if len(data) == 0:
            return jsonify({'error': 'Empty file'}), 400
        if len(data) > MAX_FILE_SIZE:
            return jsonify({'error': f'File exceeds {MAX_FILE_SIZE//1024//1024}MB'}), 413

        filename = uploaded.filename
        ext = detect_extension(filename)
        if not ext:
            ext = detect_by_magic(data)
        if not ext:
            return jsonify({'error': f'Unsupported: {filename}'}), 400

        decryptor = DECRYPTORS.get(ext)
        if not decryptor:
            return jsonify({'error': f'No decryptor for {ext}'}), 400

        logger.info(f'Decrypting {filename} as {ext}')
        result = decryptor(data)
        if result is None:
            return jsonify({'error': 'Decryption failed'}), 400

        return jsonify({
            'status': 'success',
            'extension': ext,
            'filename': filename,
            'decrypted': result
        })

    except Exception as e:
        logger.exception('Error in /decrypt')
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt/base64', methods=['POST'])
def decrypt_base64():
    try:
        data = request.get_json()
        if not data or 'file' not in data:
            return jsonify({'error': 'Missing "file" field'}), 400

        file_b64 = data['file']
        if ',' in file_b64:
            file_b64 = file_b64.split(',')[1]
        file_bytes = base64.b64decode(file_b64)

        filename = data.get('filename', 'unknown.bin')
        if len(file_bytes) > MAX_FILE_SIZE:
            return jsonify({'error': f'File exceeds {MAX_FILE_SIZE//1024//1024}MB'}), 413

        ext = detect_extension(filename)
        if not ext:
            ext = detect_by_magic(file_bytes)
        if not ext:
            return jsonify({'error': f'Unsupported: {filename}'}), 400

        decryptor = DECRYPTORS.get(ext)
        if not decryptor:
            return jsonify({'error': f'No decryptor for {ext}'}), 400

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

# ─── EHI Cloud Decrypt Endpoint ──────────────────────────────────
@app.route('/decrypt/ehi-cloud', methods=['POST'])
def decrypt_ehi_cloud():
    """
    Decrypt EHI from cloud link.
    Accepts JSON: {"url": "https://ehi.link/WPKKACR9"} or {"key": "WPKKACR9"}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON body'}), 400
        
        # Get URL or key
        url = data.get('url', '').strip()
        key = data.get('key', '').strip()
        
        if not url and not key:
            return jsonify({'error': 'Missing "url" or "key" field'}), 400
        
        # Construct URL if key provided
        if key and not url:
            url = f"https://ehi.link/{key}"
        
        # Validate URL
        if not url.startswith('https://ehi.link/'):
            return jsonify({'error': 'Invalid EHI cloud URL. Must be https://ehi.link/...'}), 400
        
        logger.info(f'Fetching EHI from cloud: {url}')
        
        # Fetch the file
        try:
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f'Failed to fetch EHI: {e}')
            return jsonify({'error': f'Failed to fetch from cloud: {str(e)}'}), 400
        
        # Get the content
        file_bytes = response.content
        logger.info(f'Downloaded {len(file_bytes)} bytes from {url}')
        
        # Check if it's a valid EHI file (magic check)
        if len(file_bytes) < 10:
            return jsonify({'error': 'Downloaded file is too small'}), 400
        
        # Decrypt using EHIDecryptor
        result = EHIDecryptor.execute(file_bytes)
        
        if result is None or result.startswith('❌'):
            return jsonify({'error': result or 'Decryption failed'}), 400
        
        # Parse the result to extract JSON
        try:
            json_start = result.find('{')
            if json_start != -1:
                json_end = result.rfind('}') + 1
                if json_end > json_start:
                    parsed = json.loads(result[json_start:json_end])
                    return jsonify({
                        'status': 'success',
                        'type': 'ehi_cloud',
                        'source': url,
                        'decrypted': parsed,
                        'formatted': result
                    })
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'type': 'ehi_cloud',
            'source': url,
            'decrypted': result,
            'formatted': result
        })
        
    except Exception as e:
        logger.exception('Error in /decrypt/ehi-cloud')
        return jsonify({'error': f'Internal error: {str(e)}'}), 500


def _extract_json_from_decrypted(decrypted_str):
    """Pull the JSON object/array out of a banner-wrapped decrypted string."""
    if isinstance(decrypted_str, (dict, list)):
        return decrypted_str  # already parsed
    s = str(decrypted_str)
    # Find the first { or [ and the matching last } or ]
    start = -1
    for ch, end_ch in [('{', '}'), ('[', ']')]:
        idx = s.find(ch)
        if idx != -1 and (start == -1 or idx < start):
            start = idx
            end = s.rfind(end_ch)
    if start == -1:
        return None
    try:
        return json.loads(s[start:end + 1])
    except Exception:
        return None


def _build_hc_file(config_json):
    """HTTP Custom — importable JSON. Strip the Protections wrapper, keep Config fields."""
    if isinstance(config_json, dict):
        # If it came from our decryptor it has {"Protections": ..., "Config": {...}}
        inner = config_json.get('Config', config_json)
        return json.dumps(inner, indent=4, ensure_ascii=False).encode('utf-8')
    return json.dumps(config_json, indent=4, ensure_ascii=False).encode('utf-8')


def _build_ehi_file(config_json):
    """HTTP Injector — .ehi is a ZIP archive containing the config JSON."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('config.json', json.dumps(config_json, indent=4, ensure_ascii=False))
    buf.seek(0)
    return buf.read()


def _build_npvt_file(config_json):
    """NPVT — plain JSON config."""
    return json.dumps(config_json, indent=4, ensure_ascii=False).encode('utf-8')


def _build_ssc_file(config_json):
    """SSH Custom — plain JSON config."""
    return json.dumps(config_json, indent=4, ensure_ascii=False).encode('utf-8')


def _build_dark_file(config_json):
    """Dark Tunnel / Dark Cloud — plain JSON config."""
    return json.dumps(config_json, indent=4, ensure_ascii=False).encode('utf-8')


EXT_BUILDERS = {
    '.hc':         (_build_hc_file,   'application/octet-stream', '.hc'),
    '.ehi':        (_build_ehi_file,   'application/zip',          '.ehi'),
    '.ehi_cloud':  (_build_ehi_file,   'application/zip',          '.ehi'),
    'ehi_cloud':   (_build_ehi_file,   'application/zip',          '.ehi'),
    '.npvt':       (_build_npvt_file,  'application/octet-stream', '.npvt'),
    '.ssc':        (_build_ssc_file,   'application/octet-stream', '.ssc'),
    '.dark':       (_build_dark_file,  'application/octet-stream', '.dark'),
    '.darktunnel': (_build_dark_file,  'application/octet-stream', '.dark'),
    '.darkcloud':  (_build_dark_file,  'application/octet-stream', '.dark'),
    'dark_tunnel': (_build_dark_file,  'application/octet-stream', '.dark'),
}


@app.route('/rebuild', methods=['POST'])
def rebuild_file():
    """
    Reconstruct a proper importable config file from decrypted data.
    Body JSON: { "decrypted": <str|obj>, "extension": ".hc", "filename": "optional" }
    Returns the binary file as a download.
    """
    try:
        data = request.get_json()
        if not data or 'decrypted' not in data:
            return jsonify({'error': 'Missing "decrypted" field'}), 400

        decrypted = data['decrypted']
        ext = data.get('extension', '').lower().strip()
        filename_base = data.get('filename', 'config')
        # Strip any existing extension from filename_base
        if '.' in filename_base:
            filename_base = filename_base.rsplit('.', 1)[0]

        builder_info = EXT_BUILDERS.get(ext)
        if not builder_info:
            return jsonify({'error': f'No file builder for extension: {ext}'}), 400

        builder_fn, mime_type, out_ext = builder_info

        # Extract JSON from the decrypted string/object
        config_json = _extract_json_from_decrypted(decrypted)
        if config_json is None:
            return jsonify({'error': 'Could not extract JSON config from decrypted data'}), 400

        file_bytes = builder_fn(config_json)
        out_filename = filename_base + out_ext

        logger.info(f'Rebuilt {out_filename} ({len(file_bytes)} bytes) for ext={ext}')

        return send_file(
            io.BytesIO(file_bytes),
            mimetype=mime_type,
            as_attachment=True,
            download_name=out_filename
        )

    except Exception as e:
        logger.exception('Error in /rebuild')
        return jsonify({'error': f'Internal error: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'supported_extensions': list(DECRYPTORS.keys()),
        'version': '2.1.0',
        'endpoints': {
            '/decrypt': 'POST - Upload file',
            '/decrypt/base64': 'POST - Base64 file',
            '/decrypt/darktunnel': 'POST - Dark tunnel string (using dark_cloud_decryptor)',
            '/health': 'GET - Health check'
        }
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🔥 DARK TUNNEL DECRYPTOR API")
    print("=" * 60)
    print(f"📍 Port: {PORT}")
    print(f"🐞 Debug: {DEBUG}")
    print("=" * 60)
    print("🔥 Using dark_cloud_decryptor for string decryption")
    print("  POST /decrypt/ehi-cloud   - EHI cloud link")
    print("=" * 60)
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)