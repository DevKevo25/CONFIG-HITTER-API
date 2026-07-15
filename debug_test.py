# debug_test.py

import json
import sys
from dark_string import DARK_STRING
from decryptors.dark_cloud_decryptor import DTDecryptor

print("=" * 60)
print("🔍 TESTING DARK CLOUD DECRYPTOR")
print("=" * 60)

# Extract just the base64 part
if DARK_STRING.startswith('darktunnel://'):
    raw = DARK_STRING[12:].strip()
else:
    raw = DARK_STRING

raw = ''.join(raw.split())
print(f"Raw length: {len(raw)}")
print(f"Raw first 100: {raw[:100]}...")
print("=" * 60)

result = DTDecryptor.execute(raw.encode('utf-8'))

if result:
    print("\n✅ DECRYPTION SUCCESSFUL!")
    print("=" * 60)
    print(result)
else:
    print("\n❌ DECRYPTION FAILED")