# app.py - Fixed using dark_cloud_decryptor for string

import os
import io
import json
import uuid
import time
import base64
import logging
import requests
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from decryptors.builders import BUILDERS, BUILD_META
from decryptors import DECRYPTORS
from decryptors.dark_cloud_decryptor import DTDecryptor as DarkCloudDecryptor

app = Flask(__name__)
CORS(app)

MAX_FILE_SIZE = 10 * 1024 * 1024

# ─── Server-side token store for binary rebuild ───────────────────────────────
_REBUILD_STORE: dict = {}
_TOKEN_TTL = 3600  # seconds

def _clean_tokens():
    now = time.time()
    expired = [k for k, v in _REBUILD_STORE.items() if now - v['ts'] > _TOKEN_TTL]
    for k in expired:
        del _REBUILD_STORE[k]

def _store_for_rebuild(raw_bytes: bytes, ext: str, filename: str) -> str:
    _clean_tokens()
    token = str(uuid.uuid4())
    _REBUILD_STORE[token] = {
        'raw': raw_bytes,
        'ext': ext,
        'filename': filename,
        'ts': time.time(),
    }
    return token
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

        rebuild_token = _store_for_rebuild(file_bytes, '.dark', 'config.dark')

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
                        'formatted': result,
                        'rebuild_token': rebuild_token,
                    })
        except:
            pass

        return jsonify({
            'status': 'success',
            'type': 'dark_tunnel',
            'decrypted': result,
            'formatted': result,
            'rebuild_token': rebuild_token,
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

        rebuild_token = _store_for_rebuild(data, ext, filename)
        return jsonify({
            'status': 'success',
            'extension': ext,
            'filename': filename,
            'decrypted': result,
            'rebuild_token': rebuild_token,
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

        rebuild_token = _store_for_rebuild(file_bytes, ext, filename)
        return jsonify({
            'status': 'success',
            'extension': ext,
            'filename': filename,
            'decrypted': result,
            'rebuild_token': rebuild_token,
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
        
        rebuild_token = _store_for_rebuild(file_bytes, '.ehi', 'config.ehi')

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
                        'formatted': result,
                        'rebuild_token': rebuild_token,
                    })
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'type': 'ehi_cloud',
            'source': url,
            'decrypted': result,
            'formatted': result,
            'rebuild_token': rebuild_token,
        })
        
    except Exception as e:
        logger.exception('Error in /decrypt/ehi-cloud')
        return jsonify({'error': f'Internal error: {str(e)}'}), 500


@app.route('/rebuild/<token>', methods=['GET'])
def rebuild_file(token):
    """
    Retrieve original raw file bytes from server store, re-encrypt with lock
    flags stripped, and stream back a proper importable binary file.
    """
    try:
        entry = _REBUILD_STORE.get(token)
        if not entry:
            return jsonify({'error': 'Token expired or not found. Re-decrypt the file to get a new token.'}), 404

        raw_bytes = entry['raw']
        ext       = entry['ext']
        filename  = entry['filename']

        builder = BUILDERS.get(ext)
        if not builder:
            return jsonify({'error': f'No binary builder for extension: {ext}'}), 400

        built = builder(raw_bytes)
        if built is None:
            return jsonify({'error': f'Failed to rebuild {ext} — format may not be fully supported yet'}), 500

        mime, out_ext = BUILD_META.get(ext, ('application/octet-stream', ext))
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        out_filename = base_name + '_unlocked' + out_ext

        logger.info(f'Rebuilt {out_filename} ({len(built)} bytes) for ext={ext}')

        return send_file(
            io.BytesIO(built),
            mimetype=mime,
            as_attachment=True,
            download_name=out_filename,
        )

    except Exception as e:
        logger.exception('Error in /rebuild/<token>')
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