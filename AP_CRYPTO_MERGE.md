# Complete Guide: Adding AP_Crypto to ArduPilot from GitHub

This document provides **complete, detailed step-by-step instructions** for adding the AP_Crypto library to a fresh ArduPilot clone from GitHub. This guide is designed for third parties who want to integrate AP_Crypto into their own ArduPilot fork or build.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Overview](#overview)
3. [Step-by-Step Implementation](#step-by-step-implementation)
4. [Critical Fixes and Safety Checks](#critical-fixes-and-safety-checks)
5. [Build System Integration](#build-system-integration)
6. [Testing and Verification](#testing-and-verification)
7. [Troubleshooting](#troubleshooting)
8. [File Checklist](#file-checklist)

---

## Prerequisites

### Required Knowledge
- Basic understanding of C++ and ArduPilot codebase structure
- Familiarity with Git and command-line tools
- Understanding of ArduPilot's build system (Waf)

### Required Tools
- Git
- Python 3 (for Waf build system)
- ARM GCC toolchain (for embedded builds)
- Text editor or IDE

### Source Repository
- **ArduPilot GitHub**: `https://github.com/ArduPilot/ardupilot.git` (or your fork)
- **AP_Crypto Source**: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto.git` (reference implementation)

---

## Overview

### What is AP_Crypto?

AP_Crypto is a simplified XOR-based encryption library for ArduPilot that provides:
- Simple XOR encryption/decryption (basic obfuscation, NOT cryptographically secure)
- Streaming encryption for large files (log files)
- Lua script encryption/decryption
- Key storage and management via StorageManager
- Parameter-based key configuration via MAVLink

### Important Security Note

⚠️ **XOR encryption is NOT cryptographically secure**. It provides basic obfuscation only and can be easily broken. This implementation is suitable for:
- Basic file obfuscation
- Non-sensitive data protection
- Development/testing scenarios

**NOT suitable for**:
- Security-critical applications
- Sensitive data protection
- Production security requirements

### What This Guide Covers

This guide will walk you through:
1. Creating all AP_Crypto library files
2. Integrating with AP_Scripting (Lua encryption)
3. Integrating with AP_Logger (log file encryption)
4. Adding MAVLink parameter support
5. Integrating with vehicle code (ArduPlane example)
6. Build system configuration
7. Critical safety fixes to prevent MAVLink connection issues

---

## Step-by-Step Implementation

### Step 1: Clone ArduPilot Repository

```bash
# Clone ArduPilot (or use your existing clone)
git clone https://github.com/ArduPilot/ardupilot.git
cd ardupilot

# Checkout the version you want to use (e.g., latest stable)
git checkout Copter-4.4  # or Plane-4.4, Rover-4.4, etc.
```

### Step 2: Create AP_Crypto Library Directory

```bash
mkdir -p libraries/AP_Crypto
```

### Step 3: Create Core AP_Crypto Library Files

#### 3.1 Create `libraries/AP_Crypto/AP_Crypto_config.h`

Create this file with the following content:

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

#### 3.2 Create `libraries/AP_Crypto/AP_Crypto.h`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto.h`
- Or create based on the header structure shown in the original APC_MERGE.md

This file defines the AP_Crypto class with XOR encryption functions.

#### 3.3 Create `libraries/AP_Crypto/AP_Crypto.cpp`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto.cpp`

**Critical Implementation Details**:
- XOR encryption: `ciphertext[i] = plaintext[i] ^ key[i % 32]`
- File format: `[Header:4 bytes "XOR1"][XOR-encrypted data]`
- Key storage using `StorageManager::StorageKeys` area
- Board ID-based key derivation as fallback

**IMPORTANT**: The actual implementation includes critical safety checks for storage access. Do not skip these!

#### 3.4 Create `libraries/AP_Crypto/AP_Crypto_Params.h`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto_Params.h`

This file defines the `AP_Crypto_Params` class for MAVLink parameter integration.

#### 3.5 Create `libraries/AP_Crypto/AP_Crypto_Params.cpp`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/AP_Crypto_Params.cpp`

**Critical Features**:
- Parameter definitions: `LEIGH_CRYPT_KEY` and `LEIGH_CRYPT_LVL`
- Key derivation from INT32 parameter value
- **Safety check**: `AP_Param::initialised()` before accessing parameters
- **Safety check**: `StorageManager::storage_failed()` before storage access

#### 3.6 Create `libraries/AP_Crypto/wscript`

Create a minimal wscript file:

```python
#!/usr/bin/env python
# encoding: utf-8

def configure(cfg):
    # AP_Crypto library files are auto-discovered by the build system
    pass

def build(bld):
    # AP_Crypto library files are auto-discovered by the build system
    pass
```

### Step 4: Create Integration Files for AP_Scripting

#### 4.1 Create `libraries/AP_Scripting/lua_encrypted_reader.h`

Create this file:

```cpp
#pragma once

#include <AP_Crypto/AP_Crypto_config.h>

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>

// Read and decrypt encrypted Lua file
// Returns decrypted content or nullptr on error
// Caller must free the returned buffer using hal.util->free_type()
uint8_t* lua_read_encrypted_file(const char *filename, size_t *out_len);

#endif  // AP_CRYPTO_ENABLED
```

#### 4.2 Create `libraries/AP_Scripting/lua_encrypted_reader.cpp`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Scripting/lua_encrypted_reader.cpp`

**Key Features**:
- Detects "XOR1" header format
- Uses `AP_Crypto::xor_decode_raw()` for decryption
- Checks `AP_Crypto_Params::is_encryption_enabled()` before decrypting
- Retrieves key from storage or derives from board ID

### Step 5: Create Integration Files for AP_Logger

#### 5.1 Create `libraries/AP_Logger/lua_encrypted_log_writer.h`

Create this file:

```cpp
#pragma once

#include <AP_Crypto/AP_Crypto_config.h>

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

#### 5.2 Create `libraries/AP_Logger/lua_encrypted_log_writer.cpp`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Logger/lua_encrypted_log_writer.cpp`

**Key Features**:
- Uses `AP_Crypto::streaming_encrypt_init_xor_from_params()` to get key
- Checks `AP_Crypto_Params::is_encryption_enabled()` before encrypting
- Writes "XOR1" header
- Streaming XOR encryption for large files

### Step 6: Modify Existing Files

#### 6.1 Modify `libraries/AP_Scripting/lua_scripts.cpp`

Find the function that loads Lua scripts (typically `load_script()` or similar). Add the following:

**At the top of the file, add includes:**

```cpp
#if AP_CRYPTO_ENABLED
#include "lua_encrypted_reader.h"
#endif
```

**In the Lua file loading function, add before attempting to load plaintext:**

```cpp
#if AP_CRYPTO_ENABLED
    // Try to read as encrypted file first
    size_t decrypted_len;
    uint8_t *decrypted = lua_read_encrypted_file(filename, &decrypted_len);
    if (decrypted != nullptr) {
        // Load decrypted content into Lua
        // Implementation depends on your Lua loading code
        // Example:
        if (luaL_loadbuffer(L, (const char*)decrypted, decrypted_len, filename) == LUA_OK) {
            hal.util->free_type(decrypted, decrypted_len, AP_HAL::Util::MEM_DMA_SAFE);
            return true;
        }
        hal.util->free_type(decrypted, decrypted_len, AP_HAL::Util::MEM_DMA_SAFE);
    }
#endif
```

**Note**: The exact integration depends on how your version of ArduPilot loads Lua scripts. Check the existing code structure first.

#### 6.2 Modify `libraries/GCS_MAVLink/GCS_Param.cpp`

This is a **CRITICAL** modification. Add the following:

**At the top of the file, add includes:**

```cpp
#include <AP_Crypto/AP_Crypto_config.h>
#if AP_CRYPTO_ENABLED
#include <AP_Crypto/AP_Crypto_Params.h>
#endif
```

**In `handle_param_set()` function, add special handling for `LEIGH_CRYPT_KEY`:**

Find the function `GCS_MAVLINK::handle_param_set()` (around line 277). After the permission check and before the normal parameter set, add:

```cpp
#if AP_CRYPTO_ENABLED
    // Special handling for LEIGH_CRYPT_KEY parameter
    if (strcmp(key, "LEIGH_CRYPT_KEY") == 0) {
        // Handle key setting via AP_Crypto_Params
        int32_t key_value = (int32_t)packet.param_value;
        if (key_value != 0) {
            // Only process non-zero values (zero means "don't change")
            AP_Crypto_Params::handle_key_set(key_value);
        }
        // Set parameter value to 0 (actual key is stored separately, reads will return 0)
        // We need to save this to keep parameter system consistent
        vp->set_float(0.0f, var_type);
        vp->save(!is_equal(0.0f, old_value));  // Save if value changed
        
        // Still send back 0 for security
        send_parameter_value(key, var_type, 0.0f);
        return;
    }
#endif
```

**In `queued_param_send()` function, add handling to return 0 for `LEIGH_CRYPT_KEY`:**

Find the function `GCS_MAVLINK::queued_param_send()` (around line 45). In the loop that sends parameters, add:

```cpp
        float param_value = _queued_parameter->cast_to_float(_queued_parameter_type);
#if AP_CRYPTO_ENABLED
        // LEIGH_CRYPT_KEY is write-only for security - always return 0 when reading
        if (strcmp(param_name, "LEIGH_CRYPT_KEY") == 0) {
            param_value = 0.0f;
        }
#endif
```

**In `send_parameter_value()` function, add handling:**

Find the function `GCS_MAVLINK::send_parameter_value()` (around line 358). Modify it:

```cpp
void GCS_MAVLINK::send_parameter_value(const char *param_name, ap_var_type param_type, float param_value)
{
    if (!HAVE_PAYLOAD_SPACE(chan, PARAM_VALUE)) {
        return;
    }
#if AP_CRYPTO_ENABLED
    // LEIGH_CRYPT_KEY is write-only for security - always return 0 when reading
    float send_value = param_value;
    if (param_name != nullptr && strcmp(param_name, "LEIGH_CRYPT_KEY") == 0) {
        send_value = 0.0f;
    }
    mavlink_msg_param_value_send(
        chan,
        param_name,
        send_value,
        mav_param_type(param_type),
        AP_Param::count_parameters(),
        -1);
#else
    mavlink_msg_param_value_send(
        chan,
        param_name,
        param_value,
        mav_param_type(param_type),
        AP_Param::count_parameters(),
        -1);
#endif
}
```

**In `param_io_timer()` function, add handling:**

Find the function `GCS_MAVLINK::param_io_timer()` (around line 422). In the section where `reply.value` is set, add:

```cpp
    if (vp != nullptr) {
#if AP_CRYPTO_ENABLED
        // LEIGH_CRYPT_KEY is write-only for security - always return 0 when reading
        if (strcmp(reply.param_name, "LEIGH_CRYPT_KEY") == 0) {
            reply.value = 0.0f;
        } else {
            reply.value = vp->cast_to_float(reply.p_type);
        }
#else
        reply.value = vp->cast_to_float(reply.p_type);
#endif
        reply.param_error = MAV_PARAM_ERROR_NO_ERROR;
    }
```

**In `queued_param_send()` async reply section, add handling:**

Find where async parameter replies are sent (around line 551). Add:

```cpp
        if (reply.param_error == MAV_PARAM_ERROR_NO_ERROR) {
#if AP_CRYPTO_ENABLED
            // LEIGH_CRYPT_KEY is write-only for security - always return 0 when reading
            float send_value = reply.value;
            if (strcmp(reply.param_name, "LEIGH_CRYPT_KEY") == 0) {
                send_value = 0.0f;
            }
            mavlink_msg_param_value_send(
                reply.chan,
                reply.param_name,
                send_value,
                mav_param_type(reply.p_type),
                reply.count,
                reply.param_index);
#else
            mavlink_msg_param_value_send(
                reply.chan,
                reply.param_name,
                reply.value,
                mav_param_type(reply.p_type),
                reply.count,
                reply.param_index);
#endif
        }
```

### Step 7: Add Vehicle Integration (ArduPlane Example)

#### 7.1 Modify `ArduPlane/Plane.h`

Find the `Plane` class definition. Add:

**In the includes section:**

```cpp
#include <AP_Crypto/AP_Crypto_config.h>
#if AP_CRYPTO_ENABLED
#include <AP_Crypto/AP_Crypto_Params.h>
#endif
```

**In the class member variables section, add:**

```cpp
#if AP_CRYPTO_ENABLED
    AP_Crypto_Params crypto_params;
#endif
```

#### 7.2 Modify `ArduPlane/Parameters.h`

Find the `Parameters` class and locate the enum that defines parameter keys (typically an enum with `k_param_*` entries). Add:

```cpp
        k_param_crypto_params,
```

**Note**: The exact location depends on your ArduPilot version. Find where other parameter keys are defined and add it there.

#### 7.3 Modify `ArduPlane/Parameters.cpp`

**At the top, add includes:**

```cpp
#include <AP_Crypto/AP_Crypto_config.h>
#if AP_CRYPTO_ENABLED
#include <AP_Crypto/AP_Crypto_Params.h>
#endif
```

**In the parameter table (typically `AP_Param::GroupInfo` array), add:**

```cpp
#if AP_CRYPTO_ENABLED
    // @Group:
    // @Path: ../libraries/AP_Crypto/AP_Crypto_Params.cpp
    GOBJECT(crypto_params, "", AP_Crypto_Params),
#endif
```

**Note**: 
- The empty string `""` as the second parameter removes the group prefix, so parameters appear as `LEIGH_CRYPT_KEY` and `LEIGH_CRYPT_LVL` (not `CRYPTO_LEIGH_CRYPT_KEY`)
- This is important to keep parameter names under the 16-character limit

### Step 8: Build System Integration

#### 8.1 Modify `Tools/ardupilotwaf/ardupilotwaf.py`

Find the `COMMON_VEHICLE_DEPENDENT_LIBRARIES` list (around line 27). Add:

```python
COMMON_VEHICLE_DEPENDENT_LIBRARIES = [
    'AP_AccelCal',
    # ... existing libraries ...
    'AP_Crypto',  # Add this line
    # ... rest of libraries ...
]
```

**Note**: The exact location in the list doesn't matter, but it should be alphabetically organized if the list is sorted.

#### 8.2 Verify `wscript` (Root)

Most ArduPilot versions auto-discover libraries, so you typically **don't need** to modify the root `wscript`. However, if your version requires explicit library registration:

Find where libraries are configured (search for `cfg.recurse('libraries/...')`). If `AP_Scripting` is listed, you can add after it:

```python
cfg.recurse('libraries/AP_Crypto')
```

**But**: Modern ArduPilot versions auto-discover libraries, so this is usually **not needed**.

### Step 9: Create Python Tools (Optional)

#### 9.1 Create Directory Structure

```bash
mkdir -p libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/scripts
```

#### 9.2 Create `libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/scripts/encrypt_decrypt_files.py`

**ACTION REQUIRED**: Copy the complete file from:
- Source: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto/blob/master/libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/scripts/encrypt_decrypt_files.py`

This tool allows encrypting/decrypting files from the command line for testing.

---

## Critical Fixes and Safety Checks

### Why These Fixes Are Critical

During initial implementation, the code caused MAVLink connection failures. These fixes prevent:
- MAVLink connection hangs
- Parameter enumeration failures
- Storage access blocking during parameter handling
- Crashes during initialization

### Fix 1: Storage Access Safety Checks

**In `libraries/AP_Crypto/AP_Crypto.cpp`, function `store_key()`:**

```cpp
bool AP_Crypto::store_key(const uint8_t key[32])
{
    if (key == nullptr) {
        return false;
    }
    
    // Check if storage has failed
    if (StorageManager::storage_failed()) {
        return false;
    }
    
    // Safety check: ensure storage is initialized
    if (_crypto_storage.size() == 0) {
        // Storage area not available
        return false;
    }
    
    // Store key at offset 0 in StorageKeys area
    bool result = _crypto_storage.write_block(CRYPTO_KEY_STORAGE_OFFSET, key, 32);
    
    // Don't fail if write returns false - storage might be busy
    return result;
}
```

**Why**: Prevents blocking or crashing if storage isn't ready during MAVLink parameter handling.

### Fix 2: Parameter Access Safety Checks

**In `libraries/AP_Crypto/AP_Crypto_Params.cpp`, function `is_encryption_enabled()`:**

```cpp
bool AP_Crypto_Params::is_encryption_enabled(void)
{
    // Safety check: don't access parameters if system not initialized
    if (!AP_Param::initialised()) {
        return false;  // Default to disabled if param system not ready
    }
    
    enum ap_var_type ptype;
    AP_Int8 *crypto_enable = (AP_Int8*)AP_Param::find("LEIGH_CRYPT_LVL", &ptype);
    if (crypto_enable != nullptr) {
        return crypto_enable->get() != 0;
    }
    // Default to disabled if parameter not found
    return false;
}
```

**Why**: Prevents crashes if called before the parameter system is initialized.

### Fix 3: Storage Access in Key Setting

**In `libraries/AP_Crypto/AP_Crypto_Params.cpp`, function `handle_key_set()`:**

```cpp
void AP_Crypto_Params::handle_key_set(int32_t key_value)
{
    if (key_value == 0) {
        return;  // Ignore zero values
    }
    
    // Safety checks: don't access storage if it has failed or isn't ready
    if (StorageManager::storage_failed()) {
        return;  // Storage not available, skip key storage
    }
    
    // ... key derivation code ...
    
    // Store the derived key
    // Note: We ignore the return value to avoid blocking MAVLink communication
    (void)AP_Crypto::store_key(key);
}
```

**Why**: Prevents blocking MAVLink communication if storage write fails or takes too long.

### Fix 4: Parameter Save in MAVLink Handler

**In `libraries/GCS_MAVLink/GCS_Param.cpp`, function `handle_param_set()`:**

```cpp
#if AP_CRYPTO_ENABLED
    if (strcmp(key, "LEIGH_CRYPT_KEY") == 0) {
        // ... handle key setting ...
        
        // CRITICAL: Save the parameter value to keep parameter system consistent
        vp->set_float(0.0f, var_type);
        vp->save(!is_equal(0.0f, old_value));  // Save if value changed
        
        // ... rest of handling ...
    }
#endif
```

**Why**: Ensures the parameter system remains consistent, preventing "Bad parameter table" errors.

### Fix 5: Include StorageManager Header

**In `libraries/AP_Crypto/AP_Crypto_Params.cpp`:**

```cpp
#include <StorageManager/StorageManager.h>
```

**Why**: Required for `StorageManager::storage_failed()` check.

---

## Build System Integration

### Verify Build System Configuration

1. **Check library discovery**: Most ArduPilot versions auto-discover libraries in `libraries/` directory
2. **Verify `ardupilotwaf.py`**: Ensure `AP_Crypto` is in `COMMON_VEHICLE_DEPENDENT_LIBRARIES`
3. **Check `wscript`**: Most versions don't need explicit `cfg.recurse()` calls

### Build Commands

```bash
# Configure for your board (replace with your target board)
./waf configure --board CubeOrangePlus

# Build ArduPlane (or your vehicle)
./waf plane

# Or build other vehicles
./waf copter
./waf rover
```

### Expected Build Output

- No compilation errors related to AP_Crypto
- Library files are compiled and linked
- Binary size increases by ~10-20KB (XOR-only implementation is lightweight)

---

## Testing and Verification

### Test 1: Build Verification

```bash
# Build should complete without errors
./waf configure --board <your-board>
./waf plane
```

### Test 2: MAVLink Connection

1. Flash firmware to your board
2. Connect via Mission Planner (or other GCS)
3. **Verify**: Connection succeeds (no "Only 1 heartbeat received" error)
4. **Verify**: Parameters enumerate correctly

### Test 3: Parameter Visibility

1. In Mission Planner, open Parameters list
2. **Verify**: `LEIGH_CRYPT_KEY` appears in the list
3. **Verify**: `LEIGH_CRYPT_LVL` appears in the list
4. **Verify**: `LEIGH_CRYPT_KEY` reads as `0` (write-only for security)

### Test 4: Parameter Setting

1. Set `LEIGH_CRYPT_KEY` to a test value (e.g., `12345`)
2. **Verify**: Parameter accepts the value
3. **Verify**: Parameter still reads as `0` (security feature)
4. **Verify**: No MAVLink connection issues

### Test 5: Encryption Enable/Disable

1. Set `LEIGH_CRYPT_LVL` to `1` (enabled)
2. **Verify**: Parameter saves correctly
3. Set `LEIGH_CRYPT_LVL` to `0` (disabled)
4. **Verify**: Parameter saves correctly

### Test 6: Lua Script Encryption (Optional)

1. Encrypt a test Lua script using the Python tool
2. Upload to the board
3. **Verify**: Script loads and runs correctly

### Test 7: Log File Encryption (Optional)

1. Enable encryption (`LEIGH_CRYPT_LVL = 1`)
2. Generate a log file
3. **Verify**: Log file has "XOR1" header
4. Decrypt using Python tool
5. **Verify**: Decrypted log is readable

---

## Troubleshooting

### Build Errors

#### Error: "AP_CRYPTO_ENABLED is not defined"

**Solution**: Ensure `AP_Crypto_config.h` is included before any `#if AP_CRYPTO_ENABLED` checks:

```cpp
#include <AP_Crypto/AP_Crypto_config.h>
#if AP_CRYPTO_ENABLED
// ... code ...
#endif
```

#### Error: "undefined reference to AP_Crypto::..."

**Solution**: Verify `AP_Crypto` is in `COMMON_VEHICLE_DEPENDENT_LIBRARIES` in `Tools/ardupilotwaf/ardupilotwaf.py`

#### Error: "k_param_crypto_params is not a member"

**Solution**: Ensure you added `k_param_crypto_params` to the enum in `ArduPlane/Parameters.h` (or equivalent for your vehicle)

### Runtime Errors

#### MAVLink Connection Fails

**Symptoms**: "Only 1 heartbeat received" or connection timeout

**Solutions**:
1. Verify all safety checks are in place (see Critical Fixes section)
2. Check that `StorageManager::storage_failed()` check is in `handle_key_set()`
3. Verify `AP_Param::initialised()` check is in `is_encryption_enabled()`
4. Ensure parameter save is called in `handle_param_set()` for `LEIGH_CRYPT_KEY`

#### "Bad parameter table" Error

**Symptoms**: Mission Planner reports "Bad parameter table"

**Solutions**:
1. Verify parameter names are under 16 characters (`LEIGH_CRYPT_KEY` = 15 chars, `LEIGH_CRYPT_LVL` = 15 chars)
2. Check that `GOBJECT(crypto_params, "", AP_Crypto_Params)` uses empty string `""` to remove group prefix
3. Verify parameter count is correct (check `AP_Param::count_parameters()`)

#### Parameters Don't Appear

**Symptoms**: `LEIGH_CRYPT_KEY` and `LEIGH_CRYPT_LVL` don't show in parameter list

**Solutions**:
1. Verify `crypto_params` is added to parameter table in `ArduPlane/Parameters.cpp`
2. Check that `k_param_crypto_params` is in the enum in `ArduPlane/Parameters.h`
3. Verify `crypto_params` member is declared in `Plane.h`
4. Rebuild and reflash firmware

#### Storage Access Fails

**Symptoms**: Key setting doesn't work, storage errors

**Solutions**:
1. Verify `StorageManager::StorageKeys` area is available on your board
2. Check that `_crypto_storage.size() > 0` check is in `store_key()`
3. Verify `StorageManager::storage_failed()` check is in place

### Verification Checklist

- [ ] Build completes without errors
- [ ] MAVLink connects successfully
- [ ] Both `LEIGH_CRYPT_KEY` and `LEIGH_CRYPT_LVL` appear in parameter list
- [ ] `LEIGH_CRYPT_KEY` reads as `0` (write-only)
- [ ] Setting `LEIGH_CRYPT_KEY` doesn't break connection
- [ ] Setting `LEIGH_CRYPT_LVL` works correctly
- [ ] No "Bad parameter table" errors
- [ ] No storage access errors in logs

---

## File Checklist

Use this checklist to verify all files are created/modified:

### Core Library Files
- [ ] `libraries/AP_Crypto/AP_Crypto_config.h`
- [ ] `libraries/AP_Crypto/AP_Crypto.h`
- [ ] `libraries/AP_Crypto/AP_Crypto.cpp`
- [ ] `libraries/AP_Crypto/AP_Crypto_Params.h`
- [ ] `libraries/AP_Crypto/AP_Crypto_Params.cpp`
- [ ] `libraries/AP_Crypto/wscript`

### Integration Files
- [ ] `libraries/AP_Scripting/lua_encrypted_reader.h`
- [ ] `libraries/AP_Scripting/lua_encrypted_reader.cpp`
- [ ] `libraries/AP_Logger/lua_encrypted_log_writer.h`
- [ ] `libraries/AP_Logger/lua_encrypted_log_writer.cpp`

### Modified Files
- [ ] `libraries/AP_Scripting/lua_scripts.cpp` (added encrypted file reading)
- [ ] `libraries/GCS_MAVLink/GCS_Param.cpp` (added parameter handling)
- [ ] `ArduPlane/Plane.h` (added crypto_params member)
- [ ] `ArduPlane/Parameters.h` (added k_param_crypto_params enum)
- [ ] `ArduPlane/Parameters.cpp` (added GOBJECT for crypto_params)
- [ ] `Tools/ardupilotwaf/ardupilotwaf.py` (added AP_Crypto to libraries list)

### Optional Files
- [ ] `libraries/AP_Crypto/PTYHON_CRYPTO_TOOL/scripts/encrypt_decrypt_files.py`

---

## Key Implementation Details

### Parameter Names

- `LEIGH_CRYPT_KEY`: Write-only encryption key parameter (reads as 0 for security)
- `LEIGH_CRYPT_LVL`: Encryption enable/disable (0=disabled, 1=enabled)

**Important**: Parameter names are 15 characters to stay under the 16-character limit.

### File Format

- **Header**: 4 bytes "XOR1" (ASCII)
- **Data**: XOR-encrypted binary data
- **Key**: 32-byte raw key (not base64-encoded)

### Key Management

1. **Stored Key**: If a key is stored via `LEIGH_CRYPT_KEY` parameter, it's used
2. **Board ID Derived**: If no stored key, key is derived from board ID
3. **Storage**: Keys stored in `StorageManager::StorageKeys` area at offset 0

### Safety Features

- Storage access checks prevent blocking during MAVLink communication
- Parameter initialization checks prevent crashes during startup
- Non-blocking storage writes prevent connection hangs
- Parameter save ensures parameter system consistency

---

## Reference

- **Source Repository**: `https://github.com/jsmithcarlsbad/ardupilot-ap-crypto`
- **ArduPilot Documentation**: `https://ardupilot.org/dev/`
- **ArduPilot GitHub**: `https://github.com/ArduPilot/ardupilot`

---

## Summary

This guide provides complete instructions for adding AP_Crypto to a fresh ArduPilot clone. The key points are:

1. **Copy source files** from the reference repository (don't recreate from scratch)
2. **Add safety checks** to prevent MAVLink connection issues
3. **Integrate with existing systems** (AP_Scripting, AP_Logger, GCS_MAVLink)
4. **Configure build system** to include the library
5. **Test thoroughly** to verify functionality

The critical fixes (storage safety checks, parameter initialization checks) are essential for preventing MAVLink connection failures. Do not skip these!

---

**Last Updated**: Based on successful implementation in ArduPilot with AP_Crypto integration working correctly with Mission Planner connection.

