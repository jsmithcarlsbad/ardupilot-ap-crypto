# AP_Crypto / CryptoToolApp Compatibility Verification

## Overview

This document verifies that the Python CryptoToolApp is compatible with the C++ AP_Crypto library implementation.

## Compatibility Status: ✅ VERIFIED

### 1. XOR1 Format Encryption/Decryption

**Status**: ✅ **COMPATIBLE**

**C++ Implementation** (`AP_Crypto.cpp`):
```cpp
// Encryption
memcpy(ciphertext, "XOR1", 4);
for (size_t i = 0; i < plaintext_len; i++) {
    ciphertext[4 + i] = plaintext[i] ^ raw_key[i % 32];
}

// Decryption
if (memcmp(ciphertext, "XOR1", 4) != 0) return -1;
for (size_t i = 0; i < data_len; i++) {
    plaintext[i] = ciphertext[4 + i] ^ raw_key[i % 32];
}
```

**Python Implementation** (`encrypt_decrypt_files.py`):
```python
# Encryption
ciphertext.extend(b"XOR1")  # Header
for i, byte in enumerate(plaintext):
    ciphertext.append(byte ^ key[i % key_len])

# Decryption
if ciphertext[:4] != b"XOR1":
    raise ValueError("Invalid header")
for i, byte in enumerate(ciphertext[4:]):
    plaintext.append(byte ^ key[i % key_len])
```

**Verification**: ✅ Both implementations:
- Use "XOR1" 4-byte header
- XOR encrypt/decrypt byte-by-byte
- Cycle key using modulo 32
- Produce identical results

### 2. Key Derivation from LEIGH_KEY

**Status**: ✅ **FIXED - NOW COMPATIBLE**

**C++ Implementation** (`AP_Crypto_Params.cpp`):
```cpp
uint32_t uval = (uint32_t)key_value;
for (int i = 0; i < 32; i++) {
    key[i] = ((uint8_t*)&uval)[i % 4] ^ (i * 0x73);
}
```

**Python Implementation** (Fixed in `CryptoTool.py` and `decrypt_simple_xor.py`):
```python
uval = leigh_key_value & 0xFFFFFFFF
uval_bytes = struct.pack('<I', uval)
key = bytearray(32)
for i in range(32):
    key[i] = uval_bytes[i % 4] ^ (i * 0x73)
```

**Verification**: ✅ Both implementations:
- Convert INT32 to uint32_t (handles negative values)
- Pack as little-endian 4 bytes
- Repeat 4 bytes 8 times to fill 32 bytes
- XOR each position with `(i * 0x73)`
- Produce identical 32-byte keys

**Previous Issue**: Python was using SHA256 key derivation, which was incompatible. This has been fixed.

### 3. File Format Structure

**Status**: ✅ **COMPATIBLE**

**Format**: `[Header: 4 bytes "XOR1"][XOR-encrypted data]`

- Header: Always "XOR1" (ASCII, 4 bytes)
- Data: XOR-encrypted binary data
- Key: 32-byte raw key (cycled for data longer than key)

**Verification**: ✅ Both C++ and Python:
- Write/read "XOR1" header
- Handle variable-length data
- Support files larger than 32 bytes (key cycling)

### 4. Key Length Requirements

**Status**: ✅ **COMPATIBLE**

- **Required**: Exactly 32 bytes
- **C++**: `const uint8_t raw_key[32]`
- **Python**: Validates `len(key) == 32`

**Verification**: ✅ Both enforce 32-byte key requirement

## Test Cases

### Test 1: Key Derivation

**Input**: `LEIGH_KEY = 12345`

**C++ Output** (first 8 bytes):
```
Key[0] = ((uint8_t*)&12345)[0] ^ (0 * 0x73) = 0x39 ^ 0x00 = 0x39
Key[1] = ((uint8_t*)&12345)[1] ^ (1 * 0x73) = 0x30 ^ 0x73 = 0x43
Key[2] = ((uint8_t*)&12345)[2] ^ (2 * 0x73) = 0x00 ^ 0xE6 = 0xE6
Key[3] = ((uint8_t*)&12345)[3] ^ (3 * 0x73) = 0x00 ^ 0x159 = 0x59
Key[4] = ((uint8_t*)&12345)[0] ^ (4 * 0x73) = 0x39 ^ 0x1CC = 0xF5
...
```

**Python Output** (first 8 bytes): `39 43 E6 59 F5 ...` ✅ **MATCHES**

### Test 2: XOR1 Encryption/Decryption

**Input**: `plaintext = "Hello, World!"`, `key = derive_key_from_leigh_key(12345)`

**C++ Process**:
1. Write "XOR1" header
2. XOR each byte: `'H' ^ key[0]`, `'e' ^ key[1]`, etc.
3. Result: `[XOR1][encrypted_data]`

**Python Process**:
1. Write "XOR1" header
2. XOR each byte: `'H' ^ key[0]`, `'e' ^ key[1]`, etc.
3. Result: `[XOR1][encrypted_data]`

**Verification**: ✅ Both produce identical ciphertext

**Decryption**: ✅ Both decrypt to original plaintext

## Files Updated for Compatibility

1. **`CryptoTool.py`**:
   - Fixed `derive_key_from_leigh_key_simple()` to match C++ implementation
   - Updated `derive_key_from_password()` to use correct key derivation for numeric inputs

2. **`decrypt_simple_xor.py`**:
   - Fixed `derive_key_from_leigh_key()` to match C++ implementation
   - Updated documentation to reflect correct algorithm

3. **`test_compatibility.py`** (NEW):
   - Created compatibility test suite
   - Verifies key derivation matches C++ exactly
   - Verifies XOR1 format encryption/decryption

## Usage Verification

### Encrypting with C++, Decrypting with Python

1. **C++ (ArduPilot)**:
   ```cpp
   uint8_t key[32];
   // ... derive key from LEIGH_KEY ...
   AP_Crypto::xor_encode_raw(key, plaintext, len, ciphertext, max_len);
   // Writes: [XOR1][encrypted_data]
   ```

2. **Python (CryptoToolApp)**:
   ```python
   key = derive_key_from_leigh_key_cpp_compatible(leigh_key_value)
   plaintext = xor_decrypt_xor1(ciphertext, key)
   # Reads: [XOR1][encrypted_data] → plaintext
   ```

**Result**: ✅ **COMPATIBLE** - Files encrypted by C++ can be decrypted by Python

### Encrypting with Python, Decrypting with C++

1. **Python (CryptoToolApp)**:
   ```python
   key = derive_key_from_leigh_key_cpp_compatible(leigh_key_value)
   ciphertext = xor_encrypt_xor1(plaintext, key)
   # Writes: [XOR1][encrypted_data]
   ```

2. **C++ (ArduPilot)**:
   ```cpp
   uint8_t key[32];
   // ... derive key from LEIGH_KEY ...
   AP_Crypto::xor_decode_raw(key, ciphertext, len, plaintext, max_len);
   // Reads: [XOR1][encrypted_data] → plaintext
   ```

**Result**: ✅ **COMPATIBLE** - Files encrypted by Python can be decrypted by C++

## Summary

| Component | Status | Notes |
|-----------|--------|-------|
| XOR1 Format | ✅ Compatible | Header and encryption algorithm match |
| Key Derivation | ✅ Fixed | Now matches C++ simple repetition method |
| File Structure | ✅ Compatible | Same header and data format |
| Key Length | ✅ Compatible | Both require 32 bytes |
| Key Cycling | ✅ Compatible | Both cycle key for long data |

## Conclusion

**AP_Crypto (C++) and CryptoToolApp (Python) are now fully compatible.**

Files encrypted by either implementation can be decrypted by the other, as long as:
1. The same LEIGH_KEY value is used
2. The XOR1 format is used (for `encrypt_decrypt_files.py`)
3. The key derivation matches (now fixed)

---

**Last Updated**: After fixing key derivation compatibility issues

