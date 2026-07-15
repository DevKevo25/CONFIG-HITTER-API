# debug_test.py - Updated with dark_string.py import

import json
import sys

# Import the dark string from dark_string.py
try:
    from dark_string import DARK_STRING
    dark_string = DARK_STRING
    print("✅ Loaded DARK_STRING from dark_string.py")
except ImportError:
    print("❌ dark_string.py not found! Please create it with your string.")
    sys.exit(1)

from decryptors.dark_cloud_decryptor import DTDecryptor

print("=" * 60)
print("🔍 TESTING FIXED DARK CLOUD DECRYPTOR")
print("=" * 60)

# Remove prefix
if dark_string.startswith('darktunnel://'):
    raw = dark_string[12:].strip()
else:
    raw = dark_string

# Clean
raw = ''.join(raw.split())

print(f"Raw length: {len(raw)}")
print(f"Raw first 100: {raw[:100]}...")
print("=" * 60)

# Test the decryptor
result = DTDecryptor.execute(raw.encode('utf-8'))

if result:
    print("\n✅ DECRYPTION SUCCESSFUL!")
    print("=" * 60)
    # Try to parse the JSON from the result
    try:
        json_start = result.find('{')
        if json_start != -1:
            json_end = result.rfind('}') + 1
            if json_end > json_start:
                json_str = result[json_start:json_end]
                parsed = json.loads(json_str)
                print("\n📝 Decrypted JSON:")
                print("=" * 60)
                print(json.dumps(parsed, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Could not parse JSON: {e}")
        print("\n📝 Raw Result:")
        print("=" * 60)
        print(result)
else:
    print("\n❌ DECRYPTION FAILED")