"""
decryptors/builders.py

Proper binary re-encryptors for each supported format.
Every builder takes the original raw file bytes and returns a fully
rebuilt binary with all lock/protection flags stripped — importable
and freely editable in the respective app.
"""

import io
import os
import json
import base64
import struct
import hashlib
import contextlib
from typing import Optional

from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


# ─── Common helpers ───────────────────────────────────────────────────────────

_LOCK_EXACT = {
    "islocked", "ispasswordlocked", "lockallconfig",
    "blockedbyroot", "blockedbyhwid", "blockedbypassword",
    "lockedbyroot", "lockedbyhwid", "lockedbypassword",
    "lockedconfig", "isexpired", "islockbypassword",
}

def _is_lock_flag(key: str) -> bool:
    return isinstance(key, str) and key.lower() in _LOCK_EXACT

def _strip_locks(obj):
    """Recursively set boolean lock-flag fields to False."""
    if isinstance(obj, dict):
        return {k: (False if _is_lock_flag(k) else _strip_locks(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_locks(x) for x in obj]
    return obj


# ═══════════════════════════════════════════════════════════════════════════════
# DARK TUNNEL  (.dark / .darktunnel / .darkcloud)
# Format: base64(JSON({encryptedLockedConfig: base64(AES-CFB(KEY_256, IV, msgpack(...)))}))
# Inner layer: encryptedLockedConfig key inside msgpack → AES-CFB(KEY_192, IV, msgpack(...))
# ═══════════════════════════════════════════════════════════════════════════════

_DT_KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
_DT_KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
_DT_IV      = bytes.fromhex("232e39185523184a5723586242200e05")


def _dt_aes(data: bytes, key: bytes, encrypt: bool) -> bytes:
    c = AES.new(key, AES.MODE_CFB, iv=_DT_IV, segment_size=128)
    return c.encrypt(data) if encrypt else c.decrypt(data)


def _dt_b64d(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _dt_b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _dt_unpack(data: bytes):
    """Try msgpack unpack, trimming trailing bytes on failure (mirrors decryptor)."""
    if not HAS_MSGPACK:
        return None
    for trim in range(20):
        try:
            return msgpack.unpackb(data if trim == 0 else data[:-trim],
                                   raw=False, strict_map_key=False)
        except Exception:
            pass
    return None


def build_dark(raw_bytes: bytes) -> Optional[bytes]:
    """Rebuild Dark Tunnel / Dark Cloud binary with lock flags stripped."""
    if not HAS_MSGPACK:
        return None
    try:
        text = raw_bytes.decode('utf-8', errors='ignore').strip()
        if '://' in text:
            text = text.split('://', 1)[1]
        text = ''.join(text.split()).lstrip('/')

        outer = json.loads(_dt_b64d(text).decode('utf-8'))
        if 'encryptedLockedConfig' not in outer:
            return None

        # Decrypt outer msgpack layer
        enc_outer = _dt_b64d(outer['encryptedLockedConfig'])
        dec_outer_bytes = _dt_aes(enc_outer, _DT_KEY_256, encrypt=False)
        unpacked = _dt_unpack(dec_outer_bytes)
        if unpacked is None:
            return None

        # Strip locks at outer msgpack level
        unpacked = _strip_locks(unpacked)

        # Decrypt & rebuild inner EncryptedLockedConfig layer
        if isinstance(unpacked, dict) and 'EncryptedLockedConfig' in unpacked:
            enc_inner = unpacked['EncryptedLockedConfig']
            if isinstance(enc_inner, (bytes, bytearray)):
                dec_inner_bytes = _dt_aes(bytes(enc_inner), _DT_KEY_192, encrypt=False)
                inner = _dt_unpack(dec_inner_bytes)
                if inner is not None:
                    inner = _strip_locks(inner)
                    repacked_inner = msgpack.packb(inner, use_bin_type=True)
                    unpacked['EncryptedLockedConfig'] = _dt_aes(repacked_inner, _DT_KEY_192, encrypt=True)

        # Re-encrypt outer msgpack
        repacked_outer = msgpack.packb(unpacked, use_bin_type=True)
        re_enc_outer = _dt_aes(repacked_outer, _DT_KEY_256, encrypt=True)

        outer['encryptedLockedConfig'] = _dt_b64e(re_enc_outer)
        # Strip any lock flags at the outer JSON level too
        outer = _strip_locks(outer)

        result = _dt_b64e(json.dumps(outer, ensure_ascii=False).encode('utf-8'))
        return result.encode('ascii')
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SSH CUSTOM  (.ssc)
# Format: hex(ChaCha20(L1_KEY, FIXED_NONCE, JSON))  [or two-layer with L2]
# Lock flags are at the outer JSON / L2 JSON level — L3-encrypted per-config
# fields (g, h, l, o, p, v, x, i, w) are left untouched.
# ═══════════════════════════════════════════════════════════════════════════════

_SSC_NONCE = struct.pack('<Q', 0xf7479d9f87f3d074)
_SSC_L1    = bytes.fromhex("c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b")
_SSC_L2    = bytes.fromhex("7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e")


def _ssc_chacha(key: bytes, nonce: bytes, data: bytes) -> bytes:
    c = ChaCha20.new(key=key, nonce=nonce)
    c.seek(64)
    return c.encrypt(data)  # ChaCha20 encrypt == decrypt


def _ssc_parse_json(b: bytes) -> Optional[dict]:
    text = b.decode('utf-8', errors='ignore').split('\x00')[0]
    s, e = text.find('{'), text.rfind('}')
    if s == -1:
        return None
    with contextlib.suppress(Exception):
        return json.loads(text[s:e + 1])
    return None


def build_ssc(raw_bytes: bytes) -> Optional[bytes]:
    """Rebuild SSH Custom binary with lock flags stripped.

    Only strips lock flags at the outer JSON level.  The L3-encrypted
    per-config fields (payload, proxy, password, etc.) are left in their
    original encrypted form so the app can still decrypt them normally.
    """
    try:
        content = raw_bytes.decode('utf-8-sig', errors='ignore').strip()
        is_uri = content.startswith("ssc://")
        if is_uri:
            content = content[6:][::-1]

        hex_str = "".join(content.split())
        if len(hex_str) % 2 != 0:
            return None

        l1_plain = _ssc_chacha(_SSC_L1, _SSC_NONCE, bytes.fromhex(hex_str))
        l1_json = _ssc_parse_json(l1_plain)
        if not l1_json:
            return None

        if "c" in l1_json and isinstance(l1_json.get("a"), str):
            # Two-layer: decrypt L2, strip locks, re-encrypt L2
            l2_nonce = bytes.fromhex(l1_json["a"][:16])
            l2_plain = _ssc_chacha(_SSC_L2, l2_nonce, bytes.fromhex(l1_json["c"]))
            l2_json = _ssc_parse_json(l2_plain)
            if not l2_json:
                return None
            # Strip lock flags at L2 level; leave encrypted fields untouched
            l2_json = _strip_locks(l2_json)
            l2_enc = _ssc_chacha(_SSC_L2, l2_nonce,
                                 json.dumps(l2_json, ensure_ascii=False).encode('utf-8'))
            l1_json["c"] = l2_enc.hex()
            # Also strip any lock flags at L1 level
            l1_json = _strip_locks(l1_json)
        else:
            # Single-layer: strip lock flags at L1 level
            l1_json = _strip_locks(l1_json)

        l1_enc = _ssc_chacha(_SSC_L1, _SSC_NONCE,
                             json.dumps(l1_json, ensure_ascii=False).encode('utf-8'))
        result = l1_enc.hex().encode('ascii')

        if is_uri:
            return ("ssc://" + result.decode('ascii')[::-1]).encode('ascii')
        return result
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP CUSTOM  (.hc)
# Format: XOR(magic, hex_string_bytes(ChaCha20(KEY[5], STATIC_NONCE, outer_json)))
# KEY INVARIANT: The file bytes ARE the magic-XOR of the ASCII hex representation
# of the ciphertext — not the ciphertext bytes themselves.
# ═══════════════════════════════════════════════════════════════════════════════

_HC_MAGIC        = bytes.fromhex("e382e4b8adc386f09f9293")
_HC_STATIC_NONCE = b'\xdb' * 8

_HC_CHACHA_KEYS = [
    bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
    bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
    bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
    bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
    bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
    bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
    bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
    bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
]

_HC_JKL_OLD = bytes([0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,0xcf,0xce,0xcd,0xcc,
                     0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4])
_HC_JKL_NEW = bytes([8,9,10,11,12,13,14,15,17,17,5,4,3,2,1,0,255,254,253,252])

# Token positions that carry lock/protection data
_HC_LOCK_POSITIONS = {2, 3, 4, 15, 21}  # lockAllConfig, blockedByRoot, expiryTime, blockedByHwid, blockedByPassword


def _hc_xor(data: bytes) -> bytes:
    """XOR data bytes with the repeating magic key."""
    k = _HC_MAGIC
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))


def _hc_abc_decrypt(raw: str, key: bytes, nonce: bytes = _HC_STATIC_NONCE) -> str:
    with contextlib.suppress(Exception):
        clean = ''.join(c for c in raw if c in '0123456789abcdefABCDEF')
        if len(clean) % 2:
            clean = '0' + clean
        data = bytes.fromhex(clean)
        if len(data) > 16:
            c = ChaCha20.new(key=key, nonce=nonce)
            c.seek(64)
            return c.decrypt(data[:-16]).decode('utf-8', errors='ignore')
    return ""


def _hc_abc_encrypt(plaintext: str, key: bytes, nonce: bytes = _HC_STATIC_NONCE) -> str:
    """ChaCha20 encrypt plaintext → hex string with 16 appended null bytes."""
    with contextlib.suppress(Exception):
        c = ChaCha20.new(key=key, nonce=nonce)
        c.seek(64)
        return (c.encrypt(plaintext.encode('utf-8')) + b'\x00' * 16).hex()
    return ""


def _hc_f(x: int) -> int:
    """JKL bit-mixing function (self-inverse)."""
    return ((x ^ 0xff) & 0xca) | (x & 0x35)


def _hc_jkl_decrypt(s: str, is_new: bool = False) -> str:
    key = _HC_JKL_NEW if is_new else _HC_JKL_OLD
    with contextlib.suppress(Exception):
        pad_s = s + '=' * (-len(s) % 4)
        data = bytearray(base64.b64decode(pad_s, validate=True))
        for i, d in enumerate(data):
            k = key[i % 20]
            data[i] = _hc_f(d) ^ _hc_f(k)
        return base64.b64decode(bytes(data).decode('utf-8')).decode('utf-8')
    return s


def _hc_jkl_encrypt(plaintext: str, is_new: bool = False) -> str:
    """Inverse of _hc_jkl_decrypt: plaintext → JKL-encoded string."""
    key = _HC_JKL_NEW if is_new else _HC_JKL_OLD
    with contextlib.suppress(Exception):
        inner_b64 = base64.b64encode(plaintext.encode('utf-8'))
        outer = bytearray(len(inner_b64))
        for i, b in enumerate(inner_b64):
            k = key[i % 20]
            outer[i] = _hc_f(b ^ _hc_f(k))
        return base64.b64encode(bytes(outer)).decode('ascii')
    return plaintext


def _hc_decrypt_token(token: str, dyn_nonce: bytes, is_new: bool) -> str:
    """Fully decrypt a single HC config token to its plain value."""
    if not token:
        return token
    if is_new:
        clean = ''.join(c for c in token if c in '0123456789abcdefABCDEF')
        if len(clean) % 2:
            clean = '0' + clean
        if len(clean) >= 32:
            with contextlib.suppress(Exception):
                data = bytes.fromhex(clean)
                if len(data) > 16:
                    for key in _HC_CHACHA_KEYS:
                        c = ChaCha20.new(key=key, nonce=dyn_nonce)
                        c.seek(64)
                        dec = c.decrypt(data[:-16]).decode('utf-8', errors='ignore')
                        for jkl_new in (True, False):
                            out = _hc_jkl_decrypt(dec, jkl_new)
                            if out != dec and out and any(ord(ch) >= 32 for ch in out):
                                return out
                        if any(x in dec for x in ("HTTP", "@", ":", "{")):
                            return dec
        for jkl_new in (True, False):
            out = _hc_jkl_decrypt(token, jkl_new)
            if out != token:
                return out
        return token
    else:
        is_hex = bool(token and len(token) >= 16 and
                      all(c in '0123456789abcdefABCDEF' for c in token.strip()))
        if is_hex:
            dec = _hc_abc_decrypt(token, _HC_CHACHA_KEYS[7], dyn_nonce)
        else:
            dec = token
        for jkl_new in (True, False):
            out = _hc_jkl_decrypt(dec or token, jkl_new)
            if out and out != (dec or token):
                return out
        return dec or token


def _hc_encrypt_token(plain: str, is_new: bool) -> str:
    """Re-encrypt a plain token value using STATIC_NONCE."""
    if not plain:
        return ""
    jkl = _hc_jkl_encrypt(plain, is_new=is_new)
    # Use KEY[1] for new format, KEY[7] for old — mirrors what the app uses
    # when there is no lock metadata (static nonce path)
    key = _HC_CHACHA_KEYS[1] if is_new else _HC_CHACHA_KEYS[7]
    return _hc_abc_encrypt(jkl, key, _HC_STATIC_NONCE)


def build_hc(raw_bytes: bytes) -> Optional[bytes]:
    """Rebuild HTTP Custom binary with lock flags stripped.

    Critical: file bytes = XOR(ASCII_hex_string_bytes, magic).
    The XOR operates on the hex character bytes, NOT the binary ciphertext.
    """
    try:
        # Step 1: XOR file bytes with magic → ASCII hex payload
        as_bytes = raw_bytes.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore')
        hex_payload = _hc_xor(as_bytes).decode('utf-8', errors='ignore')

        # Step 2: Decrypt outer envelope (ChaCha20 with KEY[5] + static nonce)
        outer_str = _hc_abc_decrypt(hex_payload, _HC_CHACHA_KEYS[5])
        if not outer_str.strip().startswith('{'):
            return None
        outer = json.loads(outer_str)

        cfg_obj = outer.get("cfg", {})
        is_new_format = isinstance(cfg_obj, dict) and "content" in cfg_obj

        # Step 3: Extract lock metadata and compute dynamic nonce
        meta = {}
        if is_new_format:
            for src_key, name in {'b': 'hwid', 'f': 'area'}.items():
                val = str(outer.get(src_key) or cfg_obj.get(src_key) or "")
                if val:
                    meta[name] = val
            target_cipher = cfg_obj.get('content')
            split_delim   = "[splitConfig]"
        else:
            obj_a = outer.get('a', {}) if isinstance(outer.get('a'), dict) else {}
            for src_key, name in {'bb': 'hwid', 'e': 'password', 'fe': 'area', 'ed': 'provider'}.items():
                raw_val = outer.get(src_key) if src_key == 'e' else obj_a.get(src_key)
                if raw_val:
                    dec_val = _hc_abc_decrypt(str(raw_val), _HC_CHACHA_KEYS[7])
                    if dec_val:
                        meta[name] = dec_val
            target_cipher = outer.get('xy') or obj_a.get('xy')
            split_delim   = outer.get('uv') or obj_a.get('uv')

        if not target_cipher or not split_delim:
            return None

        def _to_hex(s): return s.encode().hex() if s else ""
        h, pw, pr, a = meta.get('hwid'), meta.get('password'), meta.get('provider'), meta.get('area')
        derived_hex = (_to_hex(h) * 2) if (h and not any((pw, pr, a))) \
                      else (_to_hex(pw) + _to_hex(h) + _to_hex(pr) + _to_hex(a))
        dyn_nonce = bytearray(_HC_STATIC_NONCE)
        if derived_hex:
            with contextlib.suppress(Exception):
                for i, b in enumerate(bytes.fromhex(derived_hex)[:8]):
                    dyn_nonce[i] = b
        dyn_nonce = bytes(dyn_nonce)

        # Step 4: Decrypt inner token string
        used_key = None
        if is_new_format:
            xy_dec = None
            for k in _HC_CHACHA_KEYS:
                temp = _hc_abc_decrypt(str(target_cipher), k)
                if temp and split_delim in temp:
                    xy_dec, used_key = temp, k
                    break
            if not xy_dec:
                return None
        else:
            xy_dec = _hc_abc_decrypt(str(target_cipher), _HC_CHACHA_KEYS[1])
            used_key = _HC_CHACHA_KEYS[1]
            if not xy_dec:
                return None

        # Step 5: Process tokens — zero lock positions, re-encrypt others with STATIC_NONCE
        tokens = xy_dec.split(str(split_delim))
        new_tokens = []
        for i, token in enumerate(tokens):
            if i in _HC_LOCK_POSITIONS:
                new_tokens.append("")  # clear lock token
            else:
                plain = _hc_decrypt_token(token, dyn_nonce, is_new_format)
                if plain and plain != token:
                    new_tokens.append(_hc_encrypt_token(plain, is_new_format))
                else:
                    new_tokens.append(token)

        new_xy_dec = str(split_delim).join(new_tokens)
        # Re-encrypt with the same key and STATIC_NONCE (no lock metadata → app uses static nonce)
        new_xy = _hc_abc_encrypt(new_xy_dec, used_key, _HC_STATIC_NONCE)

        # Step 6: Rebuild outer JSON with lock metadata removed
        if is_new_format:
            new_cfg = dict(cfg_obj)
            new_cfg['content'] = new_xy
            new_cfg.pop('b', None)
            new_cfg.pop('f', None)
            new_outer = dict(outer)
            new_outer['cfg'] = new_cfg
            new_outer.pop('b', None)
            new_outer.pop('f', None)
        else:
            new_obj_a = dict(outer.get('a', {}) if isinstance(outer.get('a'), dict) else {})
            new_obj_a.pop('bb', None)
            new_obj_a['xy'] = new_xy
            new_outer = dict(outer)
            new_outer.pop('e', None)
            new_outer['a'] = new_obj_a
            new_outer['xy'] = new_xy

        # Step 7: Re-encrypt outer JSON → hex string → XOR with magic → file bytes
        # CRITICAL: XOR is applied to the ASCII hex string bytes, not the binary ciphertext.
        new_hex_payload = _hc_abc_encrypt(
            json.dumps(new_outer, ensure_ascii=False), _HC_CHACHA_KEYS[5])
        # new_hex_payload is a hex string (ASCII); XOR those character bytes to produce the file
        return _hc_xor(new_hex_payload.encode('latin-1'))

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# EHI  (.ehi)
# Outer: custom binary header → AES-CBC(L1_KEY, iv) → l1_text → parts
#        parts[2] → AES-CBC(L2_KEY, l2_nonce) → XXTEA(EOO_MASTER_KEY) → config JSON
# Inner: config['configData'] → XOR layer → base64 → Argon2 → ChaCha20-Poly1305 → inner JSON
# ═══════════════════════════════════════════════════════════════════════════════

_EHI_L1_KEY     = bytes.fromhex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
_EHI_L2_KEY     = bytes.fromhex("b2bc617c32d8b9eb1943a5ffa8051eea")
_EHI_EOO_KEY    = b"null=V5kU5+FFrY\x00"
_EHI_BYPASS_IVS = (
    bytes.fromhex("221d572349555f1d112133236b1f4a3f"),
    bytes.fromhex("5543494c53443e3f4a6a4539384e776a"),
    bytes.fromhex("374c2541575e4d531a3c327b75431e5f"),
)
_EHI_STD_ALPHA    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_EHI_CUSTOM_ALPHA = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
_EHI_DEC_TABLE    = str.maketrans(_EHI_CUSTOM_ALPHA, _EHI_STD_ALPHA)
_EHI_ENC_TABLE    = str.maketrans(_EHI_STD_ALPHA, _EHI_CUSTOM_ALPHA)


def _ehi_custom_b64_decode(s: str) -> bytes:
    clean = s.replace("?", "")
    clean += '=' * (-len(clean) % 4)
    return base64.b64decode(clean.translate(_EHI_DEC_TABLE))


def _ehi_custom_b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii').translate(_EHI_ENC_TABLE)


def _ehi_xor_decrypt(ciphertext_str: str, key: str) -> Optional[str]:
    with contextlib.suppress(Exception):
        raw = _ehi_custom_b64_decode(ciphertext_str[::-1])
        hex_str = raw.decode('ascii')
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        raw_bytes = bytes.fromhex(hex_str)
        kl = len(key)
        # Skip positions where raw_byte == key_byte (signals null/padding in original)
        dec = bytearray(b ^ ord(key[i % kl]) for i, b in enumerate(raw_bytes)
                        if (b ^ ord(key[i % kl])) != 0)
        return dec.decode('utf-8')
    return None


def _ehi_xor_encrypt(plaintext: str, key: str) -> str:
    """Exact inverse of _ehi_xor_decrypt for non-null plaintext (standard JSON)."""
    kl = len(key)
    # XOR each plaintext byte with the key; since JSON has no null bytes,
    # no positions will equal the key byte, so the decrypt filter is a no-op.
    xored = bytes(b ^ ord(key[i % kl]) for i, b in enumerate(plaintext.encode('utf-8')))
    hex_str = xored.hex().encode('ascii')
    custom_b64 = _ehi_custom_b64_encode(hex_str)
    return custom_b64[::-1]


def _xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    """XXTEA encryption — exact inverse of EHIDecryptor._xxtea_decrypt."""
    actual_len = len(data)
    padded_blocks = (actual_len + 7) // 4
    padded_data = data + b'\x00' * (padded_blocks * 4 - actual_len)
    n = padded_blocks + 1
    all_bytes = padded_data + struct.pack('<I', actual_len)
    k = struct.unpack('<4I', key.ljust(16, b'\x00')[:16])
    v = list(struct.unpack(f'<{n}I', all_bytes))
    delta = 0x9e3779b9
    q = 6 + 52 // n
    sum_val = 0
    z = v[n - 1]
    for _ in range(q):
        sum_val = (sum_val + delta) & 0xffffffff
        e = (sum_val >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ \
                 ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z))
            z = v[p] = (v[p] + mx) & 0xffffffff
        y = v[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ \
             ((sum_val ^ y) + (k[((n - 1) & 3) ^ e] ^ z))
        z = v[n - 1] = (v[n - 1] + mx) & 0xffffffff
    return struct.pack(f'<{n}I', *v)


def _ehi_generate_master_key(config: dict) -> bytes:
    payload = "".join(str(p) for p in (
        config.get("configAesKey", ""),
        config.get("configIdentifier", ""),
        config.get("configSalt", ""),
        str(config.get("configTimestamp", 0)),
        str(config.get("configExpiryTimestamp", 0)),
        config.get("lockModes", ""),
        config.get("lockModesHash", ""),
        config.get("configHwid", ""),
        config.get("configLockMobileOperatorId", ""),
    ) if p)
    return hashlib.sha256(payload.encode('utf-8')).digest()


def _ehi_parse_file(file_bytes: bytes):
    """Parse EHI binary → (header_bytes, pad3_bytes, payload_bytes)."""
    f = io.BytesIO(file_bytes)

    part1_lb = f.read(2)
    if len(part1_lb) < 2:
        return None, None, None
    part1_len = struct.unpack('>H', part1_lb)[0]
    part1 = f.read(part1_len)
    pad1 = f.read(8)

    part2_lb = f.read(2)
    if len(part2_lb) < 2:
        return None, None, None
    part2_len = struct.unpack('>H', part2_lb)[0]
    part2 = f.read(part2_len)
    pad2 = f.read(8)

    p_len_b = f.read(4)
    if len(p_len_b) < 4:
        return None, None, None
    p_len = struct.unpack('>I', p_len_b)[0]
    pad3 = f.read(8)
    payload = f.read(p_len)

    header = (part1_lb + part1 + pad1 +
               part2_lb + part2 + pad2)
    return header, pad3, payload


def _ehi_build_file(header: bytes, pad3: bytes, new_payload: bytes) -> bytes:
    return header + struct.pack('>I', len(new_payload)) + pad3 + new_payload


def build_ehi(raw_bytes: bytes) -> Optional[bytes]:
    """Rebuild HTTP Injector .ehi binary with lock flags stripped."""
    if not HAS_ARGON2:
        return None
    try:
        header, pad3, payload = _ehi_parse_file(raw_bytes)
        if payload is None:
            return None

        # Try each IV to decrypt payload
        config = None
        matched_iv = None
        l2_nonce_used = None
        parts_1 = None

        all_ivs = _EHI_BYPASS_IVS + (
            bytes.fromhex("2c5d1147bbad422b3b334d4d235f1a53"),
            bytes.fromhex("522b01433a5e8b2fc7549e1ad368e541"),
            bytes.fromhex("337a1035aaedf3458ca167e92d74b839"),
        )
        for iv in all_ivs:
            with contextlib.suppress(Exception):
                c1 = AES.new(_EHI_L1_KEY, AES.MODE_CBC, iv)
                l1_text = unpad(c1.decrypt(payload), 16).decode('utf-8')
                parts = l1_text.split(":")
                if len(parts) < 3:
                    continue
                l2_nonce_b = base64.b64decode(parts[0])
                c2 = AES.new(_EHI_L2_KEY, AES.MODE_CBC, l2_nonce_b)
                garbage = unpad(c2.decrypt(base64.b64decode(parts[2])), 16)
                from decryptors.ehi import EHIDecryptor
                final_raw = EHIDecryptor._xxtea_decrypt(garbage, _EHI_EOO_KEY)
                start_idx = final_raw.find(b'{')
                if start_idx == -1:
                    continue
                config = json.loads(final_raw[start_idx:].decode('utf-8', errors='ignore'))
                matched_iv = iv
                l2_nonce_used = l2_nonce_b
                parts_1 = parts[1] if len(parts) > 1 else ""
                break

        if config is None or matched_iv is None:
            return None

        target_salt = config.get('configSalt', "EVZJNI")
        is_bypass = matched_iv in _EHI_BYPASS_IVS

        if is_bypass:
            # No inner configData encryption layer — just strip locks from outer config
            modified_config = _strip_locks(config)
        else:
            # Decrypt configData → inner JSON → strip locks → re-encrypt
            config_data = config.get('configData')
            if not config_data:
                return None
            aaa_result = _ehi_xor_decrypt(config_data, target_salt)
            if not aaa_result:
                return None
            raw_payload = base64.b64decode(aaa_result)
            if len(raw_payload) <= 50:
                return None

            # Generate master key from ORIGINAL config (before any modification)
            # so the Argon2 key matches what we'll store in the rebuilt file
            argon_key = hash_secret_raw(
                secret=_ehi_generate_master_key(config),
                salt=raw_payload[0x0a:0x1a],
                time_cost=int.from_bytes(raw_payload[1:5], "little"),
                memory_cost=int.from_bytes(raw_payload[5:9], "little"),
                parallelism=raw_payload[9],
                hash_len=32,
                type=Argon2Type.ID,
            )
            orig_nonce = raw_payload[0x1a:0x32]
            aad = raw_payload[:0x1a]
            c3 = ChaCha20_Poly1305.new(key=argon_key, nonce=orig_nonce)
            c3.update(aad)
            inner_json_bytes = c3.decrypt_and_verify(raw_payload[0x32:-16], raw_payload[-16:])
            inner_json = json.loads(inner_json_bytes.decode('utf-8', errors='ignore'))

            # Strip lock flags from inner JSON
            inner_json = _strip_locks(inner_json)
            new_inner_bytes = json.dumps(inner_json, ensure_ascii=False).encode('utf-8')

            # Re-encrypt with same AAD + same nonce (Argon2 key is deterministic from config)
            c4 = ChaCha20_Poly1305.new(key=argon_key, nonce=orig_nonce)
            c4.update(aad)
            new_ciphertext, new_tag = c4.encrypt_and_digest(new_inner_bytes)

            new_raw_payload = aad + orig_nonce + new_ciphertext + new_tag
            new_aaa_result = base64.b64encode(new_raw_payload).decode('ascii')
            new_config_data = _ehi_xor_encrypt(new_aaa_result, target_salt)

            modified_config = dict(config)
            modified_config['configData'] = new_config_data
            # Strip lock flags from the outer config dict too
            modified_config = _strip_locks(modified_config)

        # Re-encrypt outer: config JSON → XXTEA → AES-CBC(L2) → l1_text → AES-CBC(L1)
        config_bytes = json.dumps(modified_config, ensure_ascii=False).encode('utf-8')
        new_garbage = _xxtea_encrypt(config_bytes, _EHI_EOO_KEY)
        c2_enc = AES.new(_EHI_L2_KEY, AES.MODE_CBC, l2_nonce_used)
        enc_parts2 = c2_enc.encrypt(pad(new_garbage, 16))
        new_l1_text = (f"{base64.b64encode(l2_nonce_used).decode()}"
                       f":{parts_1}"
                       f":{base64.b64encode(enc_parts2).decode()}")
        c1_enc = AES.new(_EHI_L1_KEY, AES.MODE_CBC, matched_iv)
        new_payload = c1_enc.encrypt(pad(new_l1_text.encode('utf-8'), 16))

        return _ehi_build_file(header, pad3, new_payload)

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# NPVT  (.npvt)
# Format: "NPVT1" or "NPVTSUB1" + index,base64(IV[16] + ciphertext)
# Cipher: whitebox CTR (encrypt_block used as keystream generator) — symmetric
# ═══════════════════════════════════════════════════════════════════════════════

def build_npvt(raw_bytes: bytes) -> Optional[bytes]:
    """Rebuild NPVT binary with lock flags stripped."""
    try:
        from decryptors.npvt import load_whitebox_state, whitebox_encrypt_block, decrypt_logic

        content = raw_bytes.decode('utf-8', errors='ignore').strip()
        prefix = ""
        if content.startswith("NPVTSUB1"):
            prefix = "NPVTSUB1"
            content = content[8:].strip()
        elif content.startswith("NPVT1"):
            prefix = "NPVT1"
            content = content[5:].strip()
        else:
            return None

        parts = content.split(',', 1)
        if len(parts) < 2:
            return None
        index_part, b64_payload = parts[0], parts[1].strip()

        # Decrypt
        p2, p3, p4, p5 = load_whitebox_state()
        decrypted_str = decrypt_logic(b64_payload, p2, p3, p4, p5)
        if not decrypted_str:
            return None

        # Strip locks — preserve the full structure (list or dict)
        new_plain = decrypted_str
        try:
            parsed = json.loads(decrypted_str)
            if isinstance(parsed, list):
                # Preserve entire list, stripping locks from each dict element
                stripped = [_strip_locks(item) if isinstance(item, dict) else item
                            for item in parsed]
                new_plain = json.dumps(stripped, ensure_ascii=False)
            elif isinstance(parsed, dict):
                new_plain = json.dumps(_strip_locks(parsed), ensure_ascii=False)
        except Exception:
            pass

        # Re-encrypt using the same whitebox CTR cipher (encrypt == decrypt)
        raw_b64 = list(base64.b64decode(b64_payload))
        iv = bytearray(raw_b64[:16])  # reuse original IV

        plain_bytes = new_plain.encode('utf-8')
        ciphertext = bytearray()
        current_iv = bytearray(iv)
        keystream = None
        for j, pb in enumerate(plain_bytes):
            if j % 16 == 0:
                keystream = whitebox_encrypt_block(current_iv, p2, p3, p4, p5)
                # Increment IV (little-endian counter)
                for kk in range(15, -1, -1):
                    current_iv[kk] = (current_iv[kk] + 1) & 0xFF
                    if current_iv[kk] != 0:
                        break
            ciphertext.append(pb ^ keystream[j % 16])

        new_b64 = base64.b64encode(bytes(iv) + bytes(ciphertext)).decode('ascii')
        return f"{prefix}{index_part},{new_b64}".encode('ascii')

    except Exception:
        return None


# ─── Dispatch table ───────────────────────────────────────────────────────────

BUILDERS = {
    '.hc':         build_hc,
    '.ehi':        build_ehi,
    '.ehi_cloud':  build_ehi,
    '.npvt':       build_npvt,
    '.ssc':        build_ssc,
    '.dark':       build_dark,
    '.darktunnel': build_dark,
    '.darkcloud':  build_dark,
}

# Mime types and output extensions for each format
BUILD_META = {
    '.hc':         ('application/octet-stream', '.hc'),
    '.ehi':        ('application/octet-stream', '.ehi'),
    '.ehi_cloud':  ('application/octet-stream', '.ehi'),
    '.npvt':       ('application/octet-stream', '.npvt'),
    '.ssc':        ('application/octet-stream', '.ssc'),
    '.dark':       ('application/octet-stream', '.dark'),
    '.darktunnel': ('application/octet-stream', '.dark'),
    '.darkcloud':  ('application/octet-stream', '.dark'),
}
