# decryptors/dark_cloud_decryptor.py - FINAL WORKING VERSION

import json
import base64
import re
import contextlib
from typing import Optional, Dict, Any, Union, List
from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


class DTConstants:
    KEY_256: bytes = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
    KEY_192: bytes = b"F)J@NcRfUjXn2r4u7x!A%D*G"
    IV: bytes = bytes.fromhex("232e39185523184a5723586242200e05")


class DTDecryptor:

    @staticmethod
    def _base64_decode_safe(data: str) -> bytes:
        data = data.strip()
        clean_data = data.replace('-', '+').replace('_', '/')
        if pad := len(clean_data) % 4:
            clean_data += "=" * (4 - pad)
        return base64.b64decode(clean_data)

    @staticmethod
    def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)

    @staticmethod
    def _is_utf8_printable(value: bytes) -> bool:
        if not value: 
            return False
        try:
            return bool(re.fullmatch(r"[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*", value.decode("utf-8")))
        except UnicodeDecodeError:
            return False

    @classmethod
    def _try_parse_json_string(cls, value: str) -> Union[Dict, List, str]:
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            with contextlib.suppress(Exception):
                fixed_json = re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)', r'\1"\2"', stripped)
                return cls._normalize_for_json(json.loads(fixed_json))
        return value

    @classmethod
    def _normalize_for_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: cls._normalize_for_json(v) for k, v in value.items() if k != "Password"}
        if isinstance(value, list):
            return [cls._normalize_for_json(v) for v in value]
        if isinstance(value, bytes):
            return cls._try_parse_json_string(value.decode("utf-8")) if cls._is_utf8_printable(value) else list(value)
        if isinstance(value, str):
            return cls._try_parse_json_string(value)
        return value

    @classmethod
    def _clean_encrypted(cls, value: Any, key: bytes, iv: bytes) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if isinstance(k, str) and k.startswith("Encrypted") and v and isinstance(v, (bytes, bytearray)):
                    try:
                        cleaned[k] = cls._aes_cfb_decrypt(bytes(v), key, iv)
                    except Exception:
                        cleaned[k] = v
                else:
                    cleaned[k] = cls._clean_encrypted(v, key, iv)
            return cleaned
        if isinstance(value, list):
            return [cls._clean_encrypted(v, key, iv) for v in value]
        return value

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not MSGPACK_AVAILABLE:
            return None

        try:
            raw_input = file_bytes.decode('utf-8', errors='ignore').strip()
            if not raw_input: 
                return None
            
            if "://" in raw_input:
                raw_input = raw_input.split("://", 1)[1]

            raw_input = ''.join(raw_input.split())
            
            # Remove leading slash if present
            if raw_input.startswith('/'):
                raw_input = raw_input[1:]

            # Decode base64
            decoded_bytes = cls._base64_decode_safe(raw_input)
            
            # Try to parse as JSON first (this is the outer layer)
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                outer = json.loads(decoded_str)
            except:
                try:
                    decoded_str = decoded_bytes.decode('latin-1')
                    outer = json.loads(decoded_str)
                except:
                    # If not JSON, treat as encrypted data directly
                    outer = None
            
            if outer and "encryptedLockedConfig" in outer:
                # JSON path - decrypt encryptedLockedConfig
                encrypted_locked_config = cls._base64_decode_safe(outer["encryptedLockedConfig"])
                decrypted_outer = cls._aes_cfb_decrypt(encrypted_locked_config, DTConstants.KEY_256, DTConstants.IV)
                unpacked_outer = msgpack.unpackb(decrypted_outer, raw=False, strict_map_key=False)
                
                if "EncryptedLockedConfig" in unpacked_outer:
                    decrypted_inner = cls._aes_cfb_decrypt(unpacked_outer["EncryptedLockedConfig"], DTConstants.KEY_192, DTConstants.IV)
                    unpacked_inner = msgpack.unpackb(decrypted_inner, raw=False, strict_map_key=False)
                    unpacked_outer["EncryptedLockedConfig"] = cls._clean_encrypted(unpacked_inner, DTConstants.KEY_192, DTConstants.IV)

                outer["encryptedLockedConfig"] = unpacked_outer
                normalized = cls._normalize_for_json(outer)
                
                return (
                    f"KEVO LOVES DARK TUNNEL SCRIPT\n"
                    f"{'='*30}\n\n"
                    f"{json.dumps(normalized, indent=4, ensure_ascii=False)}\n\n"
                    f"{'='*30}\n"
                    f"code : @KEVO_LOVES"
                )
            else:
                # Binary path - decrypt directly
                decrypted_data = cls._aes_cfb_decrypt(decoded_bytes, DTConstants.KEY_256, DTConstants.IV)
                
                # Try msgpack unpack
                try:
                    unpacked = msgpack.unpackb(decrypted_data, raw=False, strict_map_key=False)
                except:
                    # Try with different options
                    try:
                        unpacked = msgpack.unpackb(decrypted_data, raw=False, strict_map_key=False, use_list=False)
                    except:
                        # Try to strip extra bytes and retry
                        for i in range(1, 20):
                            try:
                                unpacked = msgpack.unpackb(decrypted_data[:-i], raw=False, strict_map_key=False)
                                break
                            except:
                                continue
                        else:
                            return None
                
                if isinstance(unpacked, dict):
                    if "EncryptedLockedConfig" in unpacked:
                        try:
                            encrypted_inner = unpacked["EncryptedLockedConfig"]
                            if isinstance(encrypted_inner, bytes):
                                decrypted_inner = cls._aes_cfb_decrypt(encrypted_inner, DTConstants.KEY_192, DTConstants.IV)
                                unpacked_inner = msgpack.unpackb(decrypted_inner, raw=False, strict_map_key=False)
                                unpacked["EncryptedLockedConfig"] = cls._clean_encrypted(unpacked_inner, DTConstants.KEY_192, DTConstants.IV)
                        except:
                            pass
                    
                    normalized = cls._normalize_for_json(unpacked)
                    return (
                        f"KEVO LOVES DARK TUNNEL SCRIPT\n"
                        f"{'='*30}\n\n"
                        f"{json.dumps(normalized, indent=4, ensure_ascii=False)}\n\n"
                        f"{'='*30}\n"
                        f"code : @KEVO_LOVES"
                    )
                else:
                    return (
                        f"KEVO LOVES DARK TUNNEL SCRIPT\n"
                        f"{'='*30}\n\n"
                        f"{json.dumps(unpacked, indent=4, ensure_ascii=False)}\n\n"
                        f"{'='*30}\n"
                        f"code : @KEVO_LOVES"
                    )
            
        except Exception as e:
            return None


def run(file_bytes: bytes) -> Optional[str]:
    return DTDecryptor.execute(file_bytes)