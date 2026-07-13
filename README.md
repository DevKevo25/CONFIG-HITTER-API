# Decryptor API

Unified REST API for decrypting HTTP Custom (.hc), EHI (.ehi), NPVT (.npvt), SSC (.ssc), and Dark Tunnel (.dark) config files.

## Endpoints

- `GET /health` – service status & supported extensions
- `POST /decrypt` – upload file (multipart/form-data, field `file`)
- `POST /decrypt/base64` – send JSON `{"file": "<base64>", "filename": "optional"}`

## Response

```json
{
  "status": "success",
  "extension": ".hc",
  "filename": "config.hc",
  "decrypted": "HABIBI HTTP CUSTOM SCRIPT\n==============================\n\n{ ... }"
}# CONFIG-HITTER-API
