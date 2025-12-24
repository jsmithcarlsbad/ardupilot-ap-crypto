# CryptoTool - Complete Documentation

## Overview

CryptoTool is a Python-based encryption/decryption application designed for working with ArduPilot AP_Crypto encrypted files. It provides both a graphical user interface (GUI) and command-line tools for encrypting and decrypting Lua scripts, log files, and other data files.

### Features

- **GUI Application**: User-friendly PySide6-based interface for batch file operations
- **Command-Line Tools**: Multiple CLI tools for automation and scripting
- **XOR-Based Encryption**: Simple XOR encryption compatible with AP_Crypto library
- **Multiple File Formats**: Supports `.lua`, `.lua.enc`, and `.tlog` files
- **Key Derivation**: Supports LEIGH_KEY parameter values, hex keys, and password strings
- **Batch Processing**: Process multiple files at once with progress tracking
- **Theme Support**: Customizable dark/light themes using qt-material

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [GUI Application](#gui-application)
4. [Command-Line Tools](#command-line-tools)
5. [Key Management](#key-management)
6. [File Formats](#file-formats)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Navigate to CryptoToolApp Directory

```bash
cd libraries/AP_Crypto/CryptoToolApp
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows
```

### Step 3: Install Dependencies

**For GUI Application:**
```bash
pip install PySide6 qt-material
```

**For Command-Line Tools Only:**
No additional dependencies required (uses Python standard library only)

### Step 4: Verify Installation

```bash
python CryptoTool.py --version  # Should show version info
```

---

## Quick Start

### GUI Application

1. **Launch the application:**
   ```bash
   python CryptoTool.py
   ```

2. **Select a folder** containing files to encrypt/decrypt

3. **Enter your key** (LEIGH_KEY value, hex key, or password)

4. **Select files** to process (check the checkboxes)

5. **Choose operation** (Encrypt or Decrypt)

6. **Click "Process Selected"** button

### Command-Line Tool

**Encrypt a file:**
```bash
python encrypt_decrypt_files.py encrypt input.lua output.lua.enc --key <your-32-byte-hex-key>
```

**Decrypt a file:**
```bash
python encrypt_decrypt_files.py decrypt input.lua.enc output.lua --key <your-32-byte-hex-key>
```

---

## GUI Application

### Main Window

The GUI application (`CryptoTool.py`) provides a user-friendly interface for batch file operations.

#### Interface Components

1. **Password/Key Input Field**
   - Enter LEIGH_KEY value, hex key, or password
   - Supports multiple key formats (see [Key Management](#key-management))

2. **Operation Selection**
   - **Encrypt Radio Button**: Encrypt selected files
   - **Decrypt Radio Button**: Decrypt selected files

3. **Folder Selection**
   - **Folder Path Field**: Display current working folder
   - **Select Folder Button**: Browse and select folder

4. **File List**
   - Shows all `.lua`, `.lua.enc`, and `.tlog` files in selected folder
   - Checkboxes to select files for processing
   - Visual indicators:
     - 🔒 Red lock icon: Encrypted files (`.lua.enc`, `.tlog`)
     - 🔓 Unlock icon: Unencrypted files (`.lua`)

5. **Action Buttons**
   - **Select All**: Check all files in the list
   - **Clear Selections**: Uncheck all files
   - **Process Selected**: Execute encrypt/decrypt operation

6. **Progress Bar**
   - Shows processing progress
   - Updates in real-time during batch operations

### Usage Workflow

1. **Launch Application**
   ```bash
   python CryptoTool.py
   ```

2. **Select Working Folder**
   - Click "Select Folder" button
   - Navigate to folder containing files to process
   - Folder path is saved for next session

3. **Enter Key/Password**
   - Type LEIGH_KEY value (numeric)
   - Or enter hex key (64 hex characters)
   - Or enter password string (8+ characters)

4. **Select Files**
   - Check files you want to process
   - Use "Select All" or "Clear Selections" for bulk operations
   - Selected files are remembered per folder

5. **Choose Operation**
   - Select "Encrypt" for `.lua` files
   - Select "Decrypt" for `.lua.enc` or `.tlog` files

6. **Process Files**
   - Click "Process Selected" button
   - Watch progress bar for status
   - Results shown in message box

### File Processing Rules

- **Encryption**:
  - Only processes `.lua` files
  - Creates `.lua.enc` files
  - Removes original `.lua` file after encryption

- **Decryption**:
  - Only processes `.lua.enc` and `.tlog` files
  - Creates `.lua` files (from `.lua.enc`)
  - Creates `.log` files (from `.tlog`)
  - Removes original encrypted file after decryption

- **Automatic Skipping**:
  - Skips files that are already in the target state
  - Shows information dialog with skipped files

### Visual Indicators

- **Encrypted Files** (`.lua.enc`, `.tlog`):
  - Red lock icon (🔒)
  - Red text color
  - Highlighted background

- **Unencrypted Files** (`.lua`):
  - Unlock icon (🔓)
  - Normal text color

---

## Command-Line Tools

### 1. encrypt_decrypt_files.py

Simple XOR encryption/decryption tool with "XOR1" header format.

#### Usage

```bash
python encrypt_decrypt_files.py <mode> <input> <output> --key <key>
```

#### Arguments

- `mode`: Operation mode - `encrypt` or `decrypt`
- `input`: Input file path
- `output`: Output file path
- `--key`: 32-byte key (hex string or file path)

#### Key Format

- **Hex String**: 64 hex characters (e.g., `0123456789abcdef...`)
- **Key File**: Path to file containing 32 bytes of binary key data

#### Examples

**Encrypt a file:**
```bash
python encrypt_decrypt_files.py encrypt script.lua script.lua.enc \
  --key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

**Decrypt a file:**
```bash
python encrypt_decrypt_files.py decrypt script.lua.enc script.lua \
  --key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

**Using key file:**
```bash
python encrypt_decrypt_files.py encrypt script.lua script.lua.enc \
  --key /path/to/keyfile.bin
```

#### File Format

- **Header**: 4 bytes "XOR1" (ASCII)
- **Data**: XOR-encrypted binary data
- **Key**: 32-byte raw key (cycled for data longer than key)

### 2. decrypt_simple_xor.py

Decrypt files using simplified XOR encryption (no header, SHA256 keystream).

#### Usage

```bash
python decrypt_simple_xor.py <input_file> <output_file> --leigh-key <value>
```

#### Arguments

- `input_file`: Encrypted input file
- `output_file`: Decrypted output file
- `--leigh-key`: LEIGH_KEY parameter value (INT32)
- `--chunk-size`: Optional chunk size for streaming (default: 64KB)

#### Key Derivation

```
Key = SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
```

#### Keystream Generation

```
For each 32-byte block:
  Keystream = SHA256(key + counter)
  Plaintext = Ciphertext XOR Keystream
```

#### Example

```bash
python decrypt_simple_xor.py encrypted.tlog decrypted.log --leigh-key 74768360
```

### 3. simple_encrypt.py

Encrypt/decrypt using HMAC-based keystream (includes MAC for integrity).

#### Usage

```bash
python simple_encrypt.py <action> <input> <output> <LEIGH_KEY>
```

#### Arguments

- `action`: `encrypt` or `decrypt`
- `input`: Input file path
- `output`: Output file path
- `LEIGH_KEY`: LEIGH_KEY parameter value (float or integer)

#### Features

- Uses PBKDF2 for key derivation
- HMAC-SHA256 for keystream generation
- Includes MAC (Message Authentication Code) for integrity verification
- Format: `[nonce:16 bytes][ciphertext:variable][mac:16 bytes]`

#### Example

```bash
python simple_encrypt.py encrypt test.log test.log.enc 74768360
python simple_encrypt.py decrypt test.log.enc test.log.dec 74768360
```

---

## Key Management

### Key Formats

CryptoTool supports multiple key formats:

#### 1. LEIGH_KEY Parameter Value (Numeric)

**Format**: Integer or float value (e.g., `74768360` or `74768360.0`)

**Key Derivation**:
```python
Key = SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
```

**Usage in GUI**: Enter the numeric value directly
**Usage in CLI**: Pass as integer or float

**Example**:
```
LEIGH_KEY = 74768360
→ Key = SHA256(pack('<i', 74768360) + b'LEIGH_KEY_SALT_1')
```

#### 2. Hex Key String

**Format**: 64 hex characters (32 bytes)

**Examples**:
- `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- `01 23 45 67 89 ab cd ef ...` (spaces allowed, will be removed)

**Usage in GUI**: Enter hex string (spaces optional)
**Usage in CLI**: Use `--key` parameter with hex string

**Validation**:
- Minimum: 8 hex characters (4 bytes)
- Maximum: 64 hex characters (32 bytes)
- Must have even number of characters

#### 3. Password String

**Format**: UTF-8 string (8-100 characters)

**Key Derivation**:
- If length < 32 bytes: Pad with zeros
- If length > 32 bytes: Truncate to 32 bytes
- If length = 32 bytes: Use directly

**Usage in GUI**: Enter password string
**Usage in CLI**: Not directly supported (use hex key format)

**Example**:
```
Password: "MySecretPassword123"
→ Key = "MySecretPassword123" + zeros (padded to 32 bytes)
```

### Key Derivation Details

#### For LEIGH_KEY (Numeric)

```python
import struct
import hashlib

leigh_key_value = 74768360  # INT32 value
salt = b'LEIGH_KEY_SALT_1'  # 16 bytes
seed_bytes = struct.pack('<i', leigh_key_value)  # INT32 little-endian
key = hashlib.sha256(seed_bytes + salt).digest()  # 32 bytes
```

#### For Hex Keys

```python
hex_string = "0123456789abcdef..."  # 64 hex chars
key = bytes.fromhex(hex_string)  # 32 bytes
```

#### For Password Strings

```python
password = "MyPassword"
password_bytes = password.encode('utf-8')
if len(password_bytes) < 32:
    key = password_bytes + b'\x00' * (32 - len(password_bytes))
elif len(password_bytes) > 32:
    key = password_bytes[:32]
else:
    key = password_bytes
```

### Key Storage

- Keys are **never stored** in plaintext
- Keys are derived on-the-fly from user input
- No key files are created or saved
- For security, always use LEIGH_KEY parameter values from ArduPilot

---

## File Formats

### Supported File Types

1. **`.lua`**: Plaintext Lua scripts
2. **`.lua.enc`**: Encrypted Lua scripts (XOR format)
3. **`.tlog`**: Encrypted telemetry log files (XOR format)
4. **`.log`**: Decrypted log files (output from `.tlog` decryption)

### Encryption Formats

#### Format 1: XOR1 Header Format

**Used by**: `encrypt_decrypt_files.py`

**Structure**:
```
[Header: 4 bytes "XOR1"][XOR-encrypted data]
```

**Encryption**:
```python
ciphertext[i] = plaintext[i] ^ key[i % 32]
```

**Features**:
- Simple XOR encryption
- 4-byte "XOR1" header for identification
- Key cycles for data longer than 32 bytes

#### Format 2: Simplified XOR (No Header)

**Used by**: `decrypt_simple_xor.py`, GUI application for `.tlog` files

**Structure**:
```
[XOR-encrypted data only - no header]
```

**Encryption**:
```python
# For each 32-byte block:
keystream = SHA256(key + counter)
ciphertext[i] = plaintext[i] ^ keystream[i % 32]
```

**Features**:
- SHA256-based keystream generation
- Counter-based block encryption
- No header or metadata

#### Format 3: HMAC-Based (With MAC)

**Used by**: `simple_encrypt.py`

**Structure**:
```
[Nonce: 16 bytes][Ciphertext: variable][MAC: 16 bytes]
```

**Encryption**:
```python
nonce = random_16_bytes()
keystream = HMAC_SHA256(key, nonce + counter)
ciphertext = plaintext XOR keystream
mac = HMAC_SHA256(key, nonce + ciphertext)[:16]
output = nonce + ciphertext + mac
```

**Features**:
- HMAC-SHA256 keystream
- Random nonce per encryption
- MAC for integrity verification

---

## Configuration

### CryptoTool.ini

The application saves settings in `CryptoTool.ini` file.

#### Location

```
libraries/AP_Crypto/CryptoToolApp/CryptoTool.ini
```

#### Settings

```ini
[Settings]
selected_folder = /path/to/folder
checked_files = file1.lua,file2.lua.enc
style = dark_amber.xml
darkmode = true
```

#### Configuration Options

- **`selected_folder`**: Last selected folder path
- **`checked_files`**: Comma-separated list of checked files (per folder)
- **`style`**: qt-material theme name (e.g., `dark_amber.xml`, `light_blue.xml`)
- **`darkmode`**: Boolean (`true`/`false`) - legacy setting, use `style` instead

#### Available Themes

Common qt-material themes:
- `dark_amber.xml`
- `dark_blue.xml`
- `dark_cyan.xml`
- `dark_lightgreen.xml`
- `dark_pink.xml`
- `dark_purple.xml`
- `dark_red.xml`
- `dark_teal.xml`
- `light_amber.xml`
- `light_blue.xml`
- `light_cyan.xml`
- `light_lightgreen.xml`
- `light_pink.xml`
- `light_purple.xml`
- `light_red.xml`
- `light_teal.xml`

---

## Troubleshooting

### Common Issues

#### 1. "No module named 'PySide6'"

**Problem**: PySide6 not installed

**Solution**:
```bash
pip install PySide6
```

Or activate virtual environment:
```bash
source venv/bin/activate
pip install PySide6
```

#### 2. "qt-material not available"

**Problem**: qt-material package not installed (optional)

**Solution**:
```bash
pip install qt-material
```

**Note**: Application works without qt-material, but themes won't be available.

#### 3. "Key must be exactly 32 bytes"

**Problem**: Invalid key format or length

**Solutions**:
- For hex keys: Use exactly 64 hex characters
- For LEIGH_KEY: Enter numeric value (e.g., `74768360`)
- For passwords: Use 8-100 characters

#### 4. "Invalid header - not XOR1 format"

**Problem**: File is not in XOR1 format (used by `encrypt_decrypt_files.py`)

**Solutions**:
- File may be in different encryption format
- Try using `decrypt_simple_xor.py` instead
- Check if file is actually encrypted

#### 5. "MAC verification failed"

**Problem**: Wrong key or corrupted file (when using `simple_encrypt.py`)

**Solutions**:
- Verify LEIGH_KEY value is correct
- Check if file was corrupted during transfer
- Ensure using same key format as encryption

#### 6. Files Not Appearing in List

**Problem**: Files not showing in GUI file list

**Solutions**:
- Ensure files have correct extensions: `.lua`, `.lua.enc`, or `.tlog`
- Check folder path is correct
- Verify files exist in selected folder
- Try refreshing folder (change and change back)

#### 7. "Password Too Short" or "Hex Key Too Short"

**Problem**: Key validation failed

**Solutions**:
- Hex keys: Minimum 8 hex characters (4 bytes)
- Passwords: Minimum 8 characters
- LEIGH_KEY: Any numeric value is accepted

### Debug Mode

To see detailed error messages, run from command line:

```bash
python CryptoTool.py
```

Errors will be displayed in terminal output.

### Log Files

The application doesn't create log files. All errors are shown in:
- GUI: Message boxes and status bar
- CLI: Standard error output

---

## API Reference

### GUI Application Classes

#### `CryptoToolWindow`

Main window class for the GUI application.

**Methods**:
- `load_ui()`: Load UI from `CryptoTool.ui` file
- `load_settings()`: Load settings from `CryptoTool.ini`
- `save_settings()`: Save settings to `CryptoTool.ini`
- `select_folder()`: Open folder selection dialog
- `load_files_from_folder(folder_path)`: Load files into list widget
- `process_selected()`: Execute encrypt/decrypt operation
- `derive_key_from_password(password)`: Derive key from password input

### Encryption Functions

#### `encrypt_simple_xor_format(key_bytes, plaintext)`

Encrypt using simplified XOR format (no header, SHA256 keystream).

**Parameters**:
- `key_bytes` (bytes): 32-byte encryption key
- `plaintext` (bytes): Input plaintext data

**Returns**: Encrypted ciphertext (bytes)

#### `decrypt_simple_xor_format(key_bytes, file_data)`

Decrypt using simplified XOR format.

**Parameters**:
- `key_bytes` (bytes): 32-byte decryption key
- `file_data` (bytes): Encrypted file data

**Returns**: Decrypted plaintext (bytes)

#### `derive_key_from_leigh_key_simple(leigh_key_value)`

Derive 32-byte key from LEIGH_KEY INT32 value.

**Parameters**:
- `leigh_key_value` (int): LEIGH_KEY parameter value

**Returns**: 32-byte key (bytes)

**Algorithm**:
```python
Key = SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
```

#### `derive_key_from_password(password, salt=None)`

Derive key from password, hex key, or LEIGH_KEY value.

**Parameters**:
- `password` (str): Password, hex key, or LEIGH_KEY value
- `salt` (bytes, optional): Salt for key derivation

**Returns**: Base64url-encoded key (str)

**Supported Formats**:
1. Numeric string → LEIGH_KEY derivation
2. Hex string → Direct hex parsing
3. Password string → UTF-8 encoding with padding/truncation

### File Operations

#### `encrypt_file(key_b64, input_file, output_file)`

Encrypt a file using XOR-based encryption.

**Parameters**:
- `key_b64` (str): Base64url-encoded key
- `input_file` (str): Input file path
- `output_file` (str): Output file path

**Raises**: `IOError`, `ValueError`

#### `decrypt_file(key_b64, input_file, output_file, alt_key_b64=None, alt_key2_b64=None)`

Decrypt a file using XOR-based decryption.

**Parameters**:
- `key_b64` (str): Base64url-encoded primary key
- `input_file` (str): Input file path
- `output_file` (str): Output file path
- `alt_key_b64` (str, optional): Alternative key to try
- `alt_key2_b64` (str, optional): Second alternative key

**Raises**: `IOError`, `ValueError`

---

## Examples

### Example 1: Encrypt Lua Script via GUI

1. Launch `CryptoTool.py`
2. Select folder containing `script.lua`
3. Enter LEIGH_KEY value: `74768360`
4. Check `script.lua` in file list
5. Select "Encrypt" radio button
6. Click "Process Selected"
7. Result: `script.lua.enc` created, `script.lua` removed

### Example 2: Decrypt Log File via CLI

```bash
python decrypt_simple_xor.py encrypted.tlog decrypted.log --leigh-key 74768360
```

### Example 3: Batch Encrypt Multiple Files

1. Launch `CryptoTool.py`
2. Select folder with multiple `.lua` files
3. Enter key
4. Click "Select All"
5. Select "Encrypt"
6. Click "Process Selected"
7. All `.lua` files encrypted to `.lua.enc`

### Example 4: Using Hex Key

**GUI**:
- Enter hex key: `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

**CLI**:
```bash
python encrypt_decrypt_files.py encrypt file.lua file.lua.enc \
  --key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### Example 5: Decrypt Telemetry Log

```bash
# Using LEIGH_KEY value
python decrypt_simple_xor.py flight.tlog flight.log --leigh-key 74768360

# Or use GUI:
# 1. Select folder with .tlog files
# 2. Enter LEIGH_KEY value
# 3. Check .tlog files
# 4. Select "Decrypt"
# 5. Process
```

---

## Security Notes

### ⚠️ Important Security Warnings

1. **XOR Encryption is NOT Cryptographically Secure**
   - XOR encryption provides basic obfuscation only
   - Can be easily broken with known plaintext attacks
   - NOT suitable for sensitive data protection

2. **Key Management**
   - Never store keys in plaintext
   - Use LEIGH_KEY parameter values from ArduPilot
   - Don't share keys via insecure channels

3. **File Integrity**
   - XOR format (no header) has no integrity checking
   - Corrupted files may decrypt to garbage data
   - Use HMAC-based format (`simple_encrypt.py`) for integrity verification

4. **Password Security**
   - Use strong passwords (8+ characters, mixed case, numbers)
   - Prefer LEIGH_KEY numeric values over passwords
   - Don't reuse passwords

### Best Practices

1. **Use LEIGH_KEY Values**: More secure than password strings
2. **Verify Decryption**: Always verify decrypted files are correct
3. **Backup Original Files**: Keep backups before encryption
4. **Secure Key Storage**: Don't commit keys to version control
5. **Use Appropriate Format**: Choose encryption format based on security needs

---

## Version Information

- **Application**: CryptoTool
- **Python Version**: 3.8+
- **GUI Framework**: PySide6
- **Theme Library**: qt-material (optional)
- **Compatibility**: ArduPilot AP_Crypto library

---

## License

This tool is part of the ArduPilot AP_Crypto project. See main project license for details.

---

## Support

For issues, questions, or contributions:
- Check the main AP_Crypto documentation
- Review ArduPilot documentation
- Submit issues to the project repository

---

## Changelog

### Version 1.0
- Initial release
- GUI application with PySide6
- Command-line tools
- Support for .lua, .lua.enc, and .tlog files
- Multiple key formats (LEIGH_KEY, hex, password)
- Theme support with qt-material

---

**Last Updated**: Based on CryptoTool implementation in AP_Crypto project

