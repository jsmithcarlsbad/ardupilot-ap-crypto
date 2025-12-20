# AP_Crypto Implementation Guide for ArduPilot (XOR-Only Version)

This document provides step-by-step instructions for implementing a **simplified XOR-only** AP_Crypto library into a fresh ArduPilot clone targeting the **CubeOrangePlus** board.

## ⚠️ Important: XOR-Only Implementation

This guide implements **ONLY simple XOR encryption** - no Fernet, no ChaCha20-Poly1305, no complex cryptography. 

**Key Characteristics**:
- ✅ Simple XOR encryption/decryption
- ✅ "XOR1" header format for file identification
- ✅ Streaming support for large files
- ✅ Key storage and management
- ❌ NO cryptographic security (basic obfuscation only)
- ❌ NO authentication/MAC
- ❌ NO base64 encoding (raw binary format)

**Use Case**: Basic file obfuscation for non-sensitive data. NOT suitable for security-critical applications.

## Overview

AP_Crypto is a simple XOR-based encryption library for ArduPilot that provides:
- Simple XOR encryption/decryption (raw binary format with "XOR1" header)
- Streaming encryption for large files (log files)
- Lua script encryption/decryption
- Key storage and management via StorageManager
- Parameter-based key configuration (LEIGH_KEY)

**Note**: This implementation uses simple XOR encryption only. It does NOT use Fernet, ChaCha20-Poly1305, or any other complex cryptographic algorithms. XOR encryption provides basic obfuscation but is NOT cryptographically secure.

## Target Configuration

- **Repository**: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto`
- **Target Board**: CubeOrangePlus
- **Build Command**: `./waf configure --board CubeOrangePlus && ./waf plane`

## Implementation Steps

### Step 1: Create AP_Crypto Library Directory Structure

Create the library directory:
```bash
mkdir -p libraries/AP_Crypto
```

### Step 2: Create Core AP_Crypto Library Files

#### 2.1 Create `libraries/AP_Crypto/AP_Crypto_config.h`

```cpp
#pragma once

#include <AP_HAL/AP_HAL_Boards.h>

#ifndef AP_CRYPTO_ENABLED
#define AP_CRYPTO_ENABLED 1
#endif

// Simple XOR-based encryption
// Note: XOR encryption provides basic obfuscation but is NOT cryptographically secure
// File format: [Header:4 bytes "XOR1"][XOR-encrypted data]
```

#### 2.2 Create `libraries/AP_Crypto/AP_Crypto.h`

**ACTION REQUIRED**: Create a simplified header file with XOR-only functions:

```cpp
#pragma once

#include "AP_Crypto_config.h"

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>
#include <AP_Filesystem/AP_Filesystem.h>

/*
  AP_Crypto - Simple XOR-based encryption for ArduPilot
  
  Provides XOR encryption/decryption for files.
  Format: [Header:4 bytes "XOR1"][XOR-encrypted data]
  Key: 32-byte raw key (not base64-encoded)
*/
class AP_Crypto
{
public:
    /*
      XOR encode (encrypt) data using raw key bytes
      
      @param raw_key: 32-byte encryption key (raw bytes)
      @param plaintext: Input plaintext data
      @param plaintext_len: Length of plaintext
      @param ciphertext: Output buffer for encrypted data
      @param ciphertext_max: Maximum size of ciphertext buffer
      @return: Length of ciphertext written (header + data), or -1 on error
     */
    static int xor_encode_raw(const uint8_t raw_key[32], 
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, size_t ciphertext_max);

    /*
      XOR decode (decrypt) data using raw key bytes
      
      @param raw_key: 32-byte decryption key (raw bytes)
      @param ciphertext: Input encrypted data (with "XOR1" header)
      @param ciphertext_len: Length of ciphertext
      @param plaintext: Output buffer for decrypted data
      @param plaintext_max: Maximum size of plaintext buffer
      @return: Length of plaintext written, or -1 on error
     */
    static int xor_decode_raw(const uint8_t raw_key[32], 
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, size_t plaintext_max);

    /*
      Generate a random 32-byte key
      
      @param key_out: Output buffer for 32-byte key
      @return: true on success, false on failure
     */
    static bool generate_key(uint8_t key_out[32]);

    /*
      Streaming XOR encryption context for large files
     */
    struct StreamingEncrypt {
        uint8_t key[32];              // Encryption key
        size_t bytes_encrypted;       // Total bytes encrypted so far
        bool initialized;             // Whether context is initialized
    };

    /*
      Initialize streaming XOR encryption context
      
      @param ctx: Streaming encryption context
      @param raw_key: 32-byte encryption key (raw bytes)
      @return: true on success, false on failure
     */
    static bool streaming_encrypt_init_xor(StreamingEncrypt *ctx, const uint8_t raw_key[32]);

    /*
      Write header for streaming encryption ("XOR1")
      
      @param ctx: Streaming encryption context
      @param fd: File descriptor to write to
      @return: true on success, false on failure
     */
    static bool streaming_encrypt_write_header_xor(StreamingEncrypt *ctx, int fd);

    /*
      Encrypt and write a chunk of data (streaming XOR)
      
      @param ctx: Streaming encryption context
      @param fd: File descriptor to write to
      @param plaintext: Plaintext data to encrypt
      @param plaintext_len: Length of plaintext data
      @return: Number of bytes written, or -1 on error
     */
    static ssize_t streaming_encrypt_write_xor(StreamingEncrypt *ctx, int fd,
                                               const uint8_t *plaintext, size_t plaintext_len);

    /*
      Finalize streaming encryption
      
      @param ctx: Streaming encryption context
      @param fd: File descriptor to write to
      @return: true on success, false on failure
     */
    static bool streaming_encrypt_finalize_xor(StreamingEncrypt *ctx, int fd);

    /*
      Cleanup streaming encryption context
      
      @param ctx: Streaming encryption context
     */
    static void streaming_encrypt_cleanup(StreamingEncrypt *ctx);

    /*
      Streaming XOR decryption context for large files
     */
    struct StreamingDecrypt {
        uint8_t key[32];              // Decryption key
        size_t bytes_decrypted;       // Total bytes decrypted so far
        bool initialized;             // Whether context is initialized
    };

    /*
      Initialize streaming XOR decryption context from file header
      
      @param ctx: Streaming decryption context
      @param raw_key: 32-byte decryption key (raw bytes)
      @param fd: File descriptor (must be positioned at start of file)
      @return: true on success, false on failure
     */
    static bool streaming_decrypt_init_xor(StreamingDecrypt *ctx, const uint8_t raw_key[32], int fd);

    /*
      Decrypt and read a chunk of data (streaming XOR)
      
      @param ctx: Streaming decryption context
      @param fd: File descriptor to read from
      @param plaintext: Output buffer for decrypted data
      @param plaintext_max: Maximum size of plaintext buffer
      @return: Number of bytes decrypted, or -1 on error
     */
    static ssize_t streaming_decrypt_read_xor(StreamingDecrypt *ctx, int fd,
                                             uint8_t *plaintext, size_t plaintext_max);

    /*
      Finalize streaming decryption
      
      @param ctx: Streaming decryption context
      @param fd: File descriptor to read from
      @return: true on success, false on failure
     */
    static bool streaming_decrypt_finalize_xor(StreamingDecrypt *ctx, int fd);

    /*
      Cleanup streaming decryption context
      
      @param ctx: Streaming decryption context
     */
    static void streaming_decrypt_cleanup(StreamingDecrypt *ctx);

    /*
      Convenience helpers that use stored key or the board-derived key
      to initialize XOR mode streaming encryption/decryption.
     */
    static bool streaming_encrypt_init_xor_from_params(StreamingEncrypt *ctx);
    static bool streaming_decrypt_init_xor_from_params(StreamingDecrypt *ctx, int fd);

    /*
      Key storage and retrieval functions
     */
    
    /*
      Store encryption key in persistent storage
      
      @param key: 32-byte encryption key (raw bytes)
      @return: true on success, false on failure
     */
    static bool store_key(const uint8_t key[32]);
    
    /*
      Retrieve encryption key from persistent storage
      
      @param key: Output buffer for 32-byte key
      @return: true if key was found and retrieved, false otherwise
     */
    static bool retrieve_key(uint8_t key[32]);
    
    /*
      Check if a key is stored in persistent storage
      
      @return: true if key exists, false otherwise
     */
    static bool has_stored_key(void);
    
    /*
      Generate and store a new encryption key
      
      @param key: Output buffer for generated key (optional, can be nullptr)
      @return: true on success, false on failure
     */
    static bool generate_and_store_key(uint8_t key[32] = nullptr);
    
    /*
      Derive key from board ID (fallback if no stored key)
      
      @param key: Output buffer for 32-byte key
      @return: true on success, false on failure
     */
    static bool derive_key_from_board_id(uint8_t key[32]);
};

#endif  // AP_CRYPTO_ENABLED
```

#### 2.3 Create `libraries/AP_Crypto/AP_Crypto.cpp`

**ACTION REQUIRED**: Create a simplified implementation with XOR-only functions:

Key implementation details:
- Simple XOR encryption/decryption (byte-by-byte XOR with key)
- File format: `[Header:4 bytes "XOR1"][XOR-encrypted data]`
- Streaming XOR encryption for large files
- Key storage using StorageManager
- Board ID-based key derivation (using BLAKE2b from monocypher if available, or simple hash)

**Implementation Notes**:
- XOR encryption: `ciphertext[i] = plaintext[i] ^ key[(position + i) % 32]`
- Header: 4-byte ASCII string "XOR1" to identify encrypted files
- No MAC/authentication - XOR provides no integrity checking
- Key is 32 bytes, cycled through for data longer than key
- For key derivation, you can use BLAKE2b from monocypher OR a simple hash function

**Simplified Implementation** (approximately 300-400 lines):
- `xor_encode_raw()`: XOR encrypts data and prepends "XOR1" header
- `xor_decode_raw()`: Reads "XOR1" header and XOR decrypts data
- `streaming_encrypt_init_xor()`: Initializes streaming context
- `streaming_encrypt_write_header_xor()`: Writes "XOR1" header
- `streaming_encrypt_write_xor()`: XOR encrypts and writes chunk
- `streaming_encrypt_finalize_xor()`: Finalizes (just syncs file)
- `streaming_decrypt_init_xor()`: Reads and validates "XOR1" header
- `streaming_decrypt_read_xor()`: XOR decrypts and reads chunk
- Key storage functions (same as before)
- Key derivation (can use simple hash or BLAKE2b if monocypher available)

#### 2.4 Create `libraries/AP_Crypto/AP_Crypto_Params.h`

**ACTION REQUIRED**: Copy the complete file content from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto_Params.h`

This provides the `LEIGH_KEY` parameter for key management via MAVLink.
- Total: ~64 lines

#### 2.5 Create `libraries/AP_Crypto/AP_Crypto_Params.cpp`

**ACTION REQUIRED**: Copy the complete file content from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto_Params.cpp`

- Total: ~77 lines

Implements parameter handling and key derivation from INT32 values.

### Step 3: Create Integration Files for AP_Scripting

#### 3.1 Create `libraries/AP_Scripting/lua_encrypted_reader.h`

```cpp
#pragma once

#include <AP_Crypto/AP_Crypto.h>

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>

// Read and decrypt encrypted Lua file
// Returns decrypted content or nullptr on error
uint8_t* lua_read_encrypted_file(const char *filename, size_t *out_len);

#endif  // AP_CRYPTO_ENABLED
```

#### 3.2 Create `libraries/AP_Scripting/lua_encrypted_reader.cpp`

**ACTION REQUIRED**: Copy the complete file content from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Scripting/lua_encrypted_reader.cpp`

Implements Lua file decryption using AP_Crypto.

Key features:
- Detects old "ELUA" binary format (backward compatibility)
- Detects new AP_Crypto XOR format (starts with "XOR1" header)
- Uses `AP_Crypto::xor_decode_raw()` for decryption
- Retrieves key from storage or derives from board ID
- Reads entire encrypted file, decrypts, and returns plaintext

### Step 4: Create Integration Files for AP_Logger

#### 4.1 Create `libraries/AP_Logger/lua_encrypted_log_writer.h`

```cpp
#pragma once

#include <AP_Crypto/AP_Crypto.h>

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>

// Streaming XOR-encrypted log writer
class LuaEncryptedLogWriter {
public:
    bool init(const char *filename);
    bool write(const uint8_t *data, size_t len);
    bool finalize();
    void cleanup();
    
private:
    AP_Crypto::StreamingEncrypt ctx;
    int fd;
    bool initialized;
};

#endif  // AP_CRYPTO_ENABLED
```

#### 4.2 Create `libraries/AP_Logger/lua_encrypted_log_writer.cpp`

**ACTION REQUIRED**: Copy the complete file content from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Logger/lua_encrypted_log_writer.cpp`

Implements streaming XOR log encryption using AP_Crypto streaming APIs.

Key features:
- Uses `AP_Crypto::streaming_encrypt_init_xor_from_params()` to get key
- Uses `AP_Crypto::streaming_encrypt_write_header_xor()` to write "XOR1" header
- Uses `AP_Crypto::streaming_encrypt_write_xor()` to encrypt and write chunks
- Uses `AP_Crypto::streaming_encrypt_finalize_xor()` to finalize
- No MAC/authentication - XOR only provides basic obfuscation

### Step 5: Modify Existing Files

#### 5.1 Modify `libraries/AP_Scripting/lua_scripts.cpp`

Add include and integration:
```cpp
#if AP_CRYPTO_ENABLED
#include "lua_encrypted_reader.h"
#endif

// In the file loading function, add:
#if AP_CRYPTO_ENABLED
    // Try to read as encrypted file first
    size_t decrypted_len;
    uint8_t *decrypted = lua_read_encrypted_file(filename, &decrypted_len);
    if (decrypted != nullptr) {
        // Load decrypted content
        // ... implementation details
        hal.util->free_type(decrypted, decrypted_len, AP_HAL::Util::MEM_DMA_SAFE);
        return true;
    }
#endif
```

#### 5.2 Modify `libraries/AP_Logger/AP_Logger.cpp`

Add include:
```cpp
#if AP_CRYPTO_ENABLED
#include "lua_encrypted_log_writer.h"
#endif
```

Add encrypted logging support in the log writing functions.

#### 5.3 Modify `libraries/AP_Logger/AP_Logger.h`

Add encrypted log writer member variable if needed.

#### 5.4 Modify `libraries/AP_Logger/AP_Logger_File.cpp`

Integrate encrypted log writing when writing to files.

#### 5.5 Modify `libraries/AP_Logger/AP_Logger_MAVLinkLogTransfer.cpp`

Add support for encrypted log transfer if needed.

#### 5.6 Modify `libraries/GCS_MAVLink/GCS_Param.cpp`

Add handling for `LEIGH_KEY` parameter:
- When reading: always return 0 (security)
- When writing: extract value and call `AP_Crypto_Params::handle_key_set()`

### Step 6: Add Build System Integration

#### 6.1 Modify `wscript` (root)

Find the section where libraries are configured (around line 609):
```python
cfg.recurse('libraries/AP_Scripting')
```

Add after it:
```python
cfg.recurse('libraries/AP_Crypto')
```

Find the section where libraries are built (around line 873):
```python
dirs_to_recurse.append('libraries/AP_Scripting')
```

Add after it:
```python
dirs_to_recurse.append('libraries/AP_Crypto')
```

#### 6.2 Create `libraries/AP_Crypto/wscript` (if needed)

Most ArduPilot libraries don't need a wscript file - the build system auto-discovers .cpp files. However, if you need special build rules, create:

```python
#!/usr/bin/env python
# encoding: utf-8

def build(bld):
    # AP_Crypto library files are auto-discovered
    pass
```

### Step 7: Add Vehicle Integration

#### 7.1 Add AP_Crypto_Params to Vehicle Parameters

For ArduPlane, modify `ArduPlane/Parameters.cpp` or the appropriate parameters file:

```cpp
#include <AP_Crypto/AP_Crypto_Params.h>

#if AP_CRYPTO_ENABLED
static AP_Crypto_Params crypto_params;
#endif

// In the parameter table, add:
#if AP_CRYPTO_ENABLED
    AP_GROUPINFO("CRYPTO", XX, Parameters, crypto_params),
#endif
```

Replace `XX` with the next available parameter group number.

### Step 8: Create Documentation Files

#### 8.1 Create `libraries/AP_Crypto/README.md`

**ACTION REQUIRED**: Copy from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/README.md`

#### 8.2 Create `libraries/AP_Crypto/INTEGRATION.md`

**ACTION REQUIRED**: Copy from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/INTEGRATION.md`

#### 8.3 Create `libraries/AP_Crypto/KEY_STORAGE.md`

**ACTION REQUIRED**: Copy from:
`https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/KEY_STORAGE.md`

### Step 9: Create Python Tools (Optional but Recommended)

#### 9.1 Create `libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/` directory structure

```bash
mkdir -p libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/scripts
```

#### 9.2 Create Python XOR encryption/decryption tool

Create a simple Python script `encrypt_decrypt_files.py` that supports XOR encryption:

```python
#!/usr/bin/env python3
"""
Simple XOR encryption/decryption tool for AP_Crypto
Format: [Header:4 bytes "XOR1"][XOR-encrypted data]
"""

import sys
import argparse

def xor_encrypt(plaintext, key):
    """XOR encrypt data with key"""
    key_len = len(key)
    ciphertext = bytearray()
    ciphertext.extend(b"XOR1")  # Header
    for i, byte in enumerate(plaintext):
        ciphertext.append(byte ^ key[i % key_len])
    return bytes(ciphertext)

def xor_decrypt(ciphertext, key):
    """XOR decrypt data with key"""
    if len(ciphertext) < 4:
        raise ValueError("File too short")
    if ciphertext[:4] != b"XOR1":
        raise ValueError("Invalid header - not XOR1 format")
    key_len = len(key)
    plaintext = bytearray()
    for i, byte in enumerate(ciphertext[4:]):
        plaintext.append(byte ^ key[i % key_len])
    return bytes(plaintext)

def main():
    parser = argparse.ArgumentParser(description='XOR encrypt/decrypt files for AP_Crypto')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Operation mode')
    parser.add_argument('input', help='Input file')
    parser.add_argument('output', help='Output file')
    parser.add_argument('--key', required=True, help='32-byte key (hex string or file)')
    args = parser.parse_args()
    
    # Read key
    if len(args.key) == 64:  # Hex string
        key = bytes.fromhex(args.key)
    else:  # Assume file path
        with open(args.key, 'rb') as f:
            key = f.read(32)
    
    if len(key) != 32:
        print("Error: Key must be exactly 32 bytes", file=sys.stderr)
        sys.exit(1)
    
    # Read input
    with open(args.input, 'rb') as f:
        data = f.read()
    
    # Process
    if args.mode == 'encrypt':
        result = xor_encrypt(data, key)
    else:
        result = xor_decrypt(data, key)
    
    # Write output
    with open(args.output, 'wb') as f:
        f.write(result)
    
    print(f"Success: {args.mode}ed {len(data)} bytes -> {len(result)} bytes")

if __name__ == '__main__':
    main()
```

**Note**: This is a simplified XOR-only tool. The original repository may have more features, but for XOR-only implementation, this is sufficient.

### Step 10: Verify Dependencies

Ensure these dependencies are available:
- `AP_CheckFirmware/monocypher.h` - Optional, only needed for BLAKE2b key derivation (can use simple hash instead)
- `AP_Filesystem` - File system access (required)
- `StorageManager` - Persistent storage (required)
- `AP_Param` - Parameter system (required)

**Note**: For XOR-only implementation, monocypher is optional. You can implement key derivation using a simple hash function if monocypher is not available.

### Step 11: Build and Test

#### 11.1 Configure build

```bash
cd /path/to/ardupilot
./waf configure --board CubeOrangePlus
```

#### 11.2 Build ArduPlane

```bash
./waf plane
```

#### 11.3 Verify build

Check that:
- No compilation errors related to AP_Crypto
- Binary size is reasonable (XOR-only AP_Crypto adds ~10-20KB, much smaller than full crypto)
- All dependencies are resolved

#### 11.4 Test on hardware

1. Flash firmware to CubeOrangePlus
2. Set `LEIGH_KEY` parameter via MAVLink (test value)
3. Verify key is stored and retrieved
4. Test Lua script encryption/decryption
5. Test log file encryption

## File Checklist

### Core Library Files
- [ ] `libraries/AP_Crypto/AP_Crypto_config.h`
- [ ] `libraries/AP_Crypto/AP_Crypto.h`
- [ ] `libraries/AP_Crypto/AP_Crypto.cpp`
- [ ] `libraries/AP_Crypto/AP_Crypto_Params.h`
- [ ] `libraries/AP_Crypto/AP_Crypto_Params.cpp`

### Integration Files
- [ ] `libraries/AP_Scripting/lua_encrypted_reader.h`
- [ ] `libraries/AP_Scripting/lua_encrypted_reader.cpp`
- [ ] `libraries/AP_Logger/lua_encrypted_log_writer.h`
- [ ] `libraries/AP_Logger/lua_encrypted_log_writer.cpp`

### Modified Files
- [ ] `libraries/AP_Scripting/lua_scripts.cpp`
- [ ] `libraries/AP_Logger/AP_Logger.cpp`
- [ ] `libraries/AP_Logger/AP_Logger.h`
- [ ] `libraries/AP_Logger/AP_Logger_File.cpp`
- [ ] `libraries/AP_Logger/AP_Logger_MAVLinkLogTransfer.cpp`
- [ ] `libraries/GCS_MAVLink/GCS_Param.cpp`
- [ ] `wscript` (root)
- [ ] Vehicle parameters file (e.g., `ArduPlane/Parameters.cpp`)

### Documentation
- [ ] `libraries/AP_Crypto/README.md`
- [ ] `libraries/AP_Crypto/INTEGRATION.md`
- [ ] `libraries/AP_Crypto/KEY_STORAGE.md`

### Python Tools (Optional)
- [ ] `libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/encrypt_decrypt_files.py` (XOR-only version)
- [ ] `libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/README.md` (documentation for XOR tool)

## Key Implementation Details

### Crypto Algorithm
- **Encryption**: Simple XOR (NOT cryptographically secure - basic obfuscation only)
- **Key Format**: Raw 32-byte keys (not base64-encoded)
- **File Format**: `[Header:4 bytes "XOR1"][XOR-encrypted data]` (raw binary)
- **XOR Method**: `ciphertext[i] = plaintext[i] ^ key[(position + i) % 32]`

### Key Management
- Keys stored in `StorageManager::StorageKeys` area
- Priority: Stored key → Board ID derived → Hardcoded fallback
- `LEIGH_KEY` parameter allows key setting via MAVLink (write-only, reads as 0)
- Key derivation: Uses BLAKE2b (if monocypher available) or simple hash from board ID

### Streaming Encryption
- Uses raw binary format with "XOR1" header
- No MAC/authentication - XOR provides no integrity checking
- Simple byte-by-byte XOR encryption
- Key is cycled through for data longer than 32 bytes

### Backward Compatibility
- Old "ELUA" binary format still supported for Lua files
- New AP_Crypto XOR format is default (identified by "XOR1" header)

### Security Warning
**IMPORTANT**: XOR encryption is NOT cryptographically secure. It provides basic obfuscation only and can be easily broken. Do NOT use for sensitive data. For production use, consider implementing proper encryption (AES, ChaCha20, etc.).

## Troubleshooting

### Build Errors

1. **Missing monocypher.h**: Optional - only needed for BLAKE2b key derivation. You can implement simple hash-based key derivation instead.
2. **StorageManager errors**: Verify StorageManager is available for target board
3. **Link errors**: Check that all AP_Crypto files are included in build

### Runtime Errors

1. **Key storage fails**: Check StorageManager has sufficient space (needs 40+ bytes)
2. **Decryption fails**: Verify key matches between encryption and decryption
3. **File access errors**: Check file system is mounted and accessible

### Verification

1. **Check key storage**: Use MAVLink to set `LEIGH_KEY` and verify it's stored
2. **Test encryption**: Encrypt a test file and verify it can be decrypted
3. **Test streaming**: Create a large log file and verify encryption works

## Notes for AI Implementation

When implementing this in another Cursor instance:

1. **Read source files carefully**: The actual implementation files contain important details
2. **Preserve exact code**: Copy files exactly as they appear in the source repository
3. **Check dependencies**: Verify all includes and dependencies are available
4. **Test incrementally**: Build after each major step to catch errors early
5. **Verify integration points**: The modifications to existing files are critical
6. **Check build system**: Ensure wscript changes are correct for your ArduPilot version

## Reference

- Source repository: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto`
- Target board: CubeOrangePlus
- ArduPilot documentation: https://ardupilot.org/dev/
- Monocypher documentation: https://monocypher.org/ (optional, only for BLAKE2b key derivation)

## Build Verification

After implementation, verify the build produces the same binary by:

1. Comparing binary sizes
2. Comparing checksums (if keys are the same)
3. Testing functionality on hardware
4. Verifying encrypted files can be decrypted with Python tool

---

## Critical Implementation Note

**IMPORTANT**: This guide provides the structure and integration points, but you **MUST** copy the actual source code files from the repository:

```bash
# Clone or access the source repository
git clone https://github.com/jsmithcarlsbad/ardupilot-ap-crypto.git
# OR browse files directly on GitHub

# Copy all files exactly as they appear - do not recreate from scratch
# The implementation details, especially cryptographic operations, are critical
```

### Quick File Copy Reference

All files should be copied from:
- `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/tree/master/libraries/AP_Crypto`
- `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/tree/master/libraries/AP_Scripting` (for lua_encrypted_reader files)
- `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/tree/master/libraries/AP_Logger` (for lua_encrypted_log_writer files)

## XOR Implementation Example

For reference, here's a simplified XOR implementation pattern:

```cpp
// XOR encode with "XOR1" header
int AP_Crypto::xor_encode_raw(const uint8_t raw_key[32], 
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, size_t ciphertext_max)
{
    if (raw_key == nullptr || plaintext == nullptr || ciphertext == nullptr) {
        return -1;
    }
    
    size_t total_len = 4 + plaintext_len; // "XOR1" header + data
    if (ciphertext_max < total_len) {
        return -1;
    }
    
    // Write header
    memcpy(ciphertext, "XOR1", 4);
    
    // XOR encrypt data
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[4 + i] = plaintext[i] ^ raw_key[i % 32];
    }
    
    return (int)total_len;
}

// XOR decode (reads "XOR1" header)
int AP_Crypto::xor_decode_raw(const uint8_t raw_key[32], 
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, size_t plaintext_max)
{
    if (raw_key == nullptr || ciphertext == nullptr || plaintext == nullptr) {
        return -1;
    }
    
    if (ciphertext_len < 4) {
        return -1; // Too short for header
    }
    
    // Verify header
    if (memcmp(ciphertext, "XOR1", 4) != 0) {
        return -1; // Invalid header
    }
    
    size_t data_len = ciphertext_len - 4;
    if (plaintext_max < data_len) {
        return -1;
    }
    
    // XOR decrypt data
    for (size_t i = 0; i < data_len; i++) {
        plaintext[i] = ciphertext[4 + i] ^ raw_key[i % 32];
    }
    
    return (int)data_len;
}
```

**Note**: This is a simplified example. The actual implementation should include proper error handling, file I/O for streaming, and key management integration.

