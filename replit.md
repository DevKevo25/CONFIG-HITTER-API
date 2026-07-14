# Decryptor API

Unified REST API for decrypting VPN and proxy config files (.hc, .ehi, .npvt, .ssc, .dark, .darkcloud). Includes a full interactive documentation frontend.

## Stack

- **Backend:** Python 3.12, Flask 2.3.3, flask-cors
- **Crypto:** pycryptodome, argon2-cffi, msgpack
- **Frontend:** Vanilla HTML/CSS/JS (single `index.html` served by Flask)

## Run

The workflow **Decryptor API** runs `python app.py`. The server listens on port 5000.

```bash
python app.py
```

Environment variables (all optional):
| Var     | Default | Description               |
|---------|---------|---------------------------|
| `PORT`  | `5000`  | Port to listen on         |
| `DEBUG` | `False` | Enable Flask debug mode   |

## API Endpoints

| Method | Path                  | Description                              |
|--------|-----------------------|------------------------------------------|
| GET    | `/health`             | Service status, version, extensions list |
| POST   | `/decrypt`            | Upload file (multipart/form-data)        |
| POST   | `/decrypt/base64`     | Decrypt base64-encoded file (JSON body)  |
| POST   | `/decrypt/darktunnel` | Decrypt a Dark Tunnel string             |
| POST   | `/decrypt/ehi-cloud`  | Fetch & decrypt from ehi.link URL        |

## Supported File Extensions

`.hc`, `.ehi`, `.npvt`, `.ssc`, `.dark`, `.darktunnel`, `.darkcloud`, `.ehi_cloud`

Format is auto-detected from the filename extension, with magic-byte fallback for `.npvt` and `.ssc`.

## Project Structure

```
app.py              # Flask app & route handlers
index.html          # Interactive API documentation frontend
requirements.txt    # Python dependencies
decryptors/
  __init__.py       # Decryptor registry (DECRYPTORS dict)
  http_custom.py    # .hc decryptor
  ehi.py            # .ehi decryptor
  npvt.py           # .npvt decryptor
  ssc.py            # .ssc decryptor
  dark_tunnel.py    # .dark / .darktunnel decryptor
  dark_cloud_decryptor.py  # Dark Cloud + string decryptor
  ehi_cloud.py      # EHI cloud decryptor
dark_string.py      # Dark tunnel string utilities
```

## User Preferences

- Keep the existing project structure — do not migrate or restructure.
- The frontend is a single `index.html` served by Flask (no separate frontend build step).
