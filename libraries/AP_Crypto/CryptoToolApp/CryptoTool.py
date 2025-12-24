#!/usr/bin/env python3
"""
CryptoTool - A Python application with PySide6 GUI
"""

import sys
import os
import base64
import struct
import time
import secrets
import re
from pathlib import Path
from configparser import ConfigParser
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox,
    QLineEdit, QRadioButton, QPushButton, QListWidget, QListWidgetItem, QProgressBar, QStyle,
)
from PySide6.QtCore import Qt, QFile, QIODevice
from PySide6.QtGui import QColor, QPalette, QIcon, QPixmap, QPainter, QPen, QBrush
from PySide6.QtUiTools import QUiLoader

try:
    import qt_material
    QT_MATERIAL_AVAILABLE = True
except ImportError:
    QT_MATERIAL_AVAILABLE = False
    print("Warning: qt-material not available. Install with: pip install qt-material")

# All encryption/decryption now uses XOR-based method only
# No external crypto libraries needed beyond standard library


def base64url_encode(data):
    """Encode data to base64url without padding."""
    encoded = base64.b64encode(data).decode('ascii')
    encoded = encoded.rstrip('=')
    encoded = encoded.replace('+', '-')
    encoded = encoded.replace('/', '_')
    return encoded


def base64url_decode(data):
    """Decode base64url data."""
    data = data.replace('-', '+')
    data = data.replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)


def derive_key_from_leigh_key_simple(leigh_key_value):
    """Derive key from LEIGH_KEY INT32 using SHA256 (simplified method).
    
    Based on COMPLETE_ENCRYPTION_SOLUTION.md:
    Key = SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
    
    Args:
        leigh_key_value: LEIGH_KEY parameter value (INT32)
    
    Returns:
        32-byte key
    """
    import struct
    import hashlib
    salt = b'LEIGH_KEY_SALT_1'  # 16 bytes
    seed_bytes = struct.pack('<i', leigh_key_value)  # INT32 little-endian
    return hashlib.sha256(seed_bytes + salt).digest()

def decrypt_simple_xor_format(key_bytes, file_data):
    """Decrypt using simplified XOR format (no header, no MAC, no nonce).
    
    Based on COMPLETE_ENCRYPTION_SOLUTION.md:
    - Keystream: SHA256(key + counter) for each 32-byte block
    - Decryption: XOR ciphertext with keystream
    
    Args:
        key_bytes: 32-byte decryption key
        file_data: Complete file data (binary, just ciphertext)
    
    Returns:
        Decrypted plaintext bytes
    """
    import struct
    import hashlib
    
    if len(key_bytes) != 32:
        raise ValueError("Key must be 32 bytes")
    
    def generate_keystream_block(key, counter):
        """Generate 32-byte keystream block for given counter."""
        counter_bytes = struct.pack('<Q', counter)  # uint64_t little-endian
        return hashlib.sha256(key + counter_bytes).digest()
    
    # Decrypt in 32-byte blocks
    plaintext = bytearray()
    counter = 0
    i = 0
    
    while i < len(file_data):
        # Generate keystream for this block
        keystream = generate_keystream_block(key_bytes, counter)
        
        # XOR this 32-byte block (or remainder)
        block_size = min(32, len(file_data) - i)
        for j in range(block_size):
            plaintext.append(file_data[i + j] ^ keystream[j])
        
        i += block_size
        counter += 1
    
    return bytes(plaintext)

def encrypt_simple_xor_format(key_bytes, plaintext):
    """Encrypt using simplified XOR format (no header, no MAC, no nonce).
    
    Based on COMPLETE_ENCRYPTION_SOLUTION.md:
    - Keystream: SHA256(key + counter) for each 32-byte block
    - Encryption: XOR plaintext with keystream
    
    Args:
        key_bytes: 32-byte encryption key
        plaintext: Input plaintext data (bytes)
    
    Returns:
        Encrypted ciphertext bytes
    """
    import struct
    import hashlib
    
    if len(key_bytes) != 32:
        raise ValueError("Key must be 32 bytes")
    
    def generate_keystream_block(key, counter):
        """Generate 32-byte keystream block for given counter."""
        counter_bytes = struct.pack('<Q', counter)  # uint64_t little-endian
        return hashlib.sha256(key + counter_bytes).digest()
    
    # Encrypt in 32-byte blocks
    ciphertext = bytearray()
    counter = 0
    i = 0
    
    while i < len(plaintext):
        # Generate keystream for this block
        keystream = generate_keystream_block(key_bytes, counter)
        
        # XOR this 32-byte block (or remainder)
        block_size = min(32, len(plaintext) - i)
        for j in range(block_size):
            ciphertext.append(plaintext[i + j] ^ keystream[j])
        
        i += block_size
        counter += 1
    
    return bytes(ciphertext)

def derive_key_from_password(password, salt=None):
    """Derive a 32-byte key from password.
    Supports multiple formats:
    1. Hex key string (e.g., "01 23 45 67 ..." or "01234567...") - parsed as hex bytes
    2. Numeric LEIGH_KEY: SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1") - matches AP_CRYPTO
    3. Password string - converted to bytes directly (padded/truncated to 32 bytes)
    This matches the XOR-based encryption format used by AP_CRYPTO."""
    # Remove whitespace from input
    password_clean = password.strip()
    
    # First, check if it's a pure number (all digits) - treat as LEIGH_KEY for SHA256
    # This takes priority over hex key detection
    if password_clean.isdigit():
        # It's a pure number - use simplified SHA256 key derivation (COMPLETE_ENCRYPTION_SOLUTION.md)
        try:
            leigh_key_value = int(password_clean)
            key_bytes = derive_key_from_leigh_key_simple(leigh_key_value)
            return base64url_encode(key_bytes)
        except (ValueError, OverflowError):
            # Number too large or invalid - fall through to other methods
            pass
    # Check if input looks like a hex key (contains ONLY hex chars and spaces/tabs)
    # First, check if there are any non-hex, non-whitespace characters
    # If there are, it's definitely not a hex key - treat as password
    elif not re.search(r'[^0-9a-fA-F\s\t]', password_clean):
        # Only contains hex chars and whitespace - might be a hex key
        # Remove all whitespace to check hex character count
        hex_chars_only = re.sub(r'[\s\t]', '', password_clean)
        hex_char_count = len(hex_chars_only)
        
        # If it's a valid hex string (even length, at least 2 chars), try to parse it
        # But only if it contains letters (a-f, A-F) - pure numbers are handled as seeds
        if hex_char_count >= 2 and hex_char_count % 2 == 0 and re.search(r'[a-fA-F]', hex_chars_only):
            # Contains hex letters - treat as hex key
            # Remove all whitespace and parse as hex
            hex_string = hex_chars_only
            try:
                key_bytes = bytes.fromhex(hex_string)
                
                # Handle hex keys of different lengths
                if len(key_bytes) == 32:
                    # Perfect - exactly 32 bytes
                    return base64url_encode(key_bytes)
                elif len(key_bytes) == 16:
                    # 16-byte key - duplicate it to make 32 bytes (common pattern)
                    key_bytes = key_bytes + key_bytes
                    return base64url_encode(key_bytes)
                elif len(key_bytes) < 32:
                    # Pad with zeros if shorter (but warn if very short)
                    if len(key_bytes) < 16:
                        raise ValueError(
                            f"Hex key is too short: {len(key_bytes)} bytes ({hex_char_count} hex chars). "
                            f"Need at least 16 bytes (32 hex characters) or exactly 32 bytes (64 hex characters). "
                            f"Example 32-byte key: '01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 10 32 54 76 98 ba dc fe ef cd ab 89 67 45 23 01'"
                        )
                    # Pad with zeros to 32 bytes
                    key_bytes = key_bytes + b'\x00' * (32 - len(key_bytes))
                    return base64url_encode(key_bytes)
                else:
                    # Truncate if longer than 32 bytes
                    key_bytes = key_bytes[:32]
                    return base64url_encode(key_bytes)
            except ValueError as e:
                # Re-raise ValueError (our custom error messages)
                raise
            except Exception:
                # Other exceptions - not valid hex, fall through to treat as password
                pass
    
    # Not a hex key - check if it's a numeric seed for SHA256 derivation (simplified method)
    # Try to parse as INT32 (for LEIGH_KEY from MAVLink)
    try:
        seed_int = int(password_clean)
        # It's a number - use SHA256 derivation (COMPLETE_ENCRYPTION_SOLUTION.md)
        # Key = SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
        import hashlib
        salt = b'LEIGH_KEY_SALT_1'  # 16 bytes
        seed_bytes_le = struct.pack('<i', seed_int)  # INT32 little-endian
        key_bytes = hashlib.sha256(seed_bytes_le + salt).digest()
        return base64url_encode(key_bytes)
    except ValueError:
        # Not a number - check if user accidentally entered the salt or password string
        if password_clean == "LEIGH_KEY_SALT_1" or password_clean.upper() == "LEIGH_KEY_SALT_1":
            raise ValueError(
                "You entered the salt value 'LEIGH_KEY_SALT_1' instead of the LEIGH_KEY seed value.\n"
                "Please enter the INT32 LEIGH_KEY value (a number) that was set via MAVLink.\n"
                "The key will be derived using SHA256(LEIGH_KEY_INT32_bytes + salt)."
            )
        # Check if user entered a password string when they should enter a numeric seed
        if "LEIGH" in password_clean.upper() and "AEROSPACE" in password_clean.upper():
            raise ValueError(
                "You entered a password string, but .tlog files require the INT32 LEIGH_KEY seed value.\n"
                "Please enter the numeric LEIGH_KEY value (a number) that was set via MAVLink.\n"
                "Example: If LEIGH_KEY was set to 12345, enter '12345' (not the password string).\n"
                "The key will be derived using SHA256(LEIGH_KEY_INT32_bytes + salt)."
            )
        # Not a number - treat as password string
        pass
    
    # Not a hex key or numeric seed - treat as password string
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Pad or truncate to exactly 32 bytes
    if len(password_bytes) < 32:
        # Pad with zeros if shorter
        key_bytes = password_bytes + b'\x00' * (32 - len(password_bytes))
    elif len(password_bytes) > 32:
        # Truncate if longer
        key_bytes = password_bytes[:32]
    else:
        # Exactly 32 bytes
        key_bytes = password_bytes
    
    return base64url_encode(key_bytes)


def encrypt_data(key_b64, plaintext):
    """Encrypt data using XOR-based format (simplified method).
    
    Uses XOR encryption with SHA256 keystream generation.
    No header, no MAC, no nonce - just ciphertext.
    """
    key_bytes = base64url_decode(key_b64)
    if len(key_bytes) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Use XOR-based encryption
    return encrypt_simple_xor_format(key_bytes, plaintext)


def encrypt_file(key_b64, input_file, output_file):
    """Encrypt a file using XOR-based encryption."""
    try:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
    except IOError as e:
        raise IOError(f"Error reading input file: {e}")
    
    try:
        # XOR encryption returns binary ciphertext (no base64 encoding)
        ciphertext = encrypt_data(key_b64, plaintext)
    except Exception as e:
        raise ValueError(f"Error encrypting data: {e}")
    
    try:
        # Write binary ciphertext directly (XOR format has no header/MAC)
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
    except IOError as e:
        raise IOError(f"Error writing output file: {e}")
    
    return True


def decrypt_file(key_b64, input_file, output_file, alt_key_b64=None, alt_key2_b64=None):
    """Decrypt a file.
    
    Args:
        key_b64: Primary key (base64url-encoded)
        input_file: Input file path
        output_file: Output file path
        alt_key_b64: Alternative key to try if primary fails (e.g., big-endian variant)
        alt_key2_b64: Second alternative key (e.g., salt+seed instead of seed+salt)
    """
    input_path = Path(input_file)
    is_tlog = input_path.suffix.lower() == '.tlog'
    
    key_bytes = base64url_decode(key_b64)
    if len(key_bytes) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Add alternative keys if provided
    alt_key_bytes = None
    if alt_key_b64:
        try:
            alt_key_bytes = base64url_decode(alt_key_b64)
            if len(alt_key_bytes) != 32:
                alt_key_bytes = None
        except:
            alt_key_bytes = None
    
    alt_key2_bytes = None
    if alt_key2_b64:
        try:
            alt_key2_bytes = base64url_decode(alt_key2_b64)
            if len(alt_key2_bytes) != 32:
                alt_key2_bytes = None
        except:
            alt_key2_bytes = None
    
    # Debug: Verify key matches expected format
    # For password "LEIGH AEROSPACE DEADBEEF_IS_COLD", key should be those bytes directly
    expected_key_hex = "4c45494748204145524f53504143452044454144424545465f49535f434f4c44"
    if key_bytes.hex() == expected_key_hex:
        # Key matches - this is correct
        pass
    else:
        # Key doesn't match - this might be the issue
        # But continue anyway in case password is different
        pass
    
    try:
        # Read file as binary (XOR format has no header, just ciphertext)
        with open(input_file, 'rb') as f:
            file_data = f.read()
        
        if len(file_data) == 0:
            raise ValueError("File is empty")
        
        # Use XOR-based decryption (only supported method)
        plaintext = decrypt_simple_xor_format(key_bytes, file_data)
    except IOError as e:
        raise IOError(f"Error reading input file: {e}")
    
    try:
        with open(output_file, 'wb') as f:
            f.write(plaintext)
    except IOError as e:
        raise IOError(f"Error writing output file: {e}")
    
    return True


class CryptoToolWindow(QMainWindow):
    """Main window for the CryptoTool application"""
    
    def __init__(self):
        super().__init__()
        # Initialize INI file path
        self.ini_file_path = Path(__file__).parent / "CryptoTool.ini"
        self.config = ConfigParser()
        
        # Load settings first so theme can be applied correctly
        self.load_settings()
        self.load_ui()
        self.setup_connections()
    
    def load_ui(self):
        """Load the UI from CryptoTool.ui file"""
        ui_file_path = Path(__file__).parent / "CryptoTool.ui"
        
        if not ui_file_path.exists():
            QMessageBox.critical(
                None, 
                "Error", 
                f"UI file not found: {ui_file_path}"
            )
            sys.exit(1)
        
        ui_file = QFile(str(ui_file_path))
        if not ui_file.open(QIODevice.ReadOnly):
            QMessageBox.critical(
                None,
                "Error",
                f"Cannot open UI file: {ui_file.errorString()}"
            )
            sys.exit(1)
        
        loader = QUiLoader()
        # Load without parent to avoid conflicts
        loaded_ui = loader.load(ui_file, None)
        ui_file.close()
        
        if not loaded_ui:
            QMessageBox.critical(
                None,
                "Error",
                f"Cannot load UI file: {loader.errorString()}"
            )
            sys.exit(1)
        
        # Find all widgets from the loaded UI
        # Store references to UI elements using findChild to access nested widgets
        self.password_edit = loaded_ui.findChild(QLineEdit, "passwordLineEdit")
        # Set maximum length to allow hex keys (64 hex chars) and spaces
        # Allow up to 100 characters to accommodate hex keys with spaces
        if self.password_edit:
            self.password_edit.setMaxLength(100)
        self.encrypt_radio = loaded_ui.findChild(QRadioButton, "encryptRadioButton")
        self.decrypt_radio = loaded_ui.findChild(QRadioButton, "decryptRadioButton")
        self.process_btn = loaded_ui.findChild(QPushButton, "processSelectedPushButton")
        self.folder_edit = loaded_ui.findChild(QLineEdit, "FolderLineEdit")
        self.select_folder_btn = loaded_ui.findChild(QPushButton, "FolderSelectPushButton")
        self.file_list = loaded_ui.findChild(QListWidget, "FilesListWidget")
        self.select_all_btn = loaded_ui.findChild(QPushButton, "pushButton")
        self.clear_selections_btn = loaded_ui.findChild(QPushButton, "pushButton_2")
        self.progress_bar = loaded_ui.findChild(QProgressBar, "busyProgressBar")
        
        
        # Initialize progress bar to 0 on program start
        if self.progress_bar:
            self.progress_bar.setValue(0)
            self.progress_bar.setMinimum(0)
            self.progress_bar.setMaximum(100)
        
        # Verify all widgets were found
        if not all([self.password_edit, self.encrypt_radio, self.decrypt_radio, 
                   self.process_btn, self.folder_edit, self.select_folder_btn, self.file_list,
                   self.select_all_btn, self.clear_selections_btn]):
            QMessageBox.critical(
                None,
                "Error",
                "Failed to find some UI widgets. Please check the UI file."
            )
            sys.exit(1)
        
        # Now copy properties from loaded UI to self
        self.setWindowTitle(loaded_ui.windowTitle())
        self.setGeometry(loaded_ui.geometry())
        self.setCentralWidget(loaded_ui.centralwidget)
        self.setStatusBar(loaded_ui.statusbar)
        
        # Reparent widgets to self to ensure they stay alive
        # The widgets are already part of the central widget, so they should be fine
        # But we need to keep a reference to loaded_ui to prevent it from being deleted
        self._loaded_ui = loaded_ui
        
        # Update window title
        self.setWindowTitle("CryptoTool")
        
        # Apply theme after UI is loaded
        self.apply_theme()
        
        # Load folder setting after UI is ready
        self.load_folder_setting()
    
    def apply_theme(self):
        """Apply qt-material theme based on Style setting"""
        if not QT_MATERIAL_AVAILABLE:
            return
        
        # Get Style setting from INI file
        style = self.get_style()
        
        # Apply theme
        app = QApplication.instance()
        if app:
            qt_material.apply_stylesheet(app, theme=style)
            # Process events to ensure theme is applied
            QApplication.processEvents()
    
    def get_style(self):
        """Get Style setting from INI file, default to dark_amber.xml"""
        try:
            # Read config if not already read
            if self.ini_file_path.exists():
                self.config.read(self.ini_file_path)
            if self.config.has_section('Settings'):
                style = self.config.get('Settings', 'Style', fallback='dark_amber.xml')
                return style
        except Exception:
            pass
        return 'dark_amber.xml'  # Default style
    
    def set_style(self, style_name):
        """Set Style setting and save to INI file"""
        try:
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            self.config.set('Settings', 'Style', style_name)
            self.save_settings()
            # Reapply theme
            self.apply_theme()
        except Exception as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Could not save Style setting: {str(e)}"
            )
    
    def get_dark_mode(self):
        """Get DarkMode setting from INI file, default to True"""
        try:
            # Read config if not already read
            if self.ini_file_path.exists():
                self.config.read(self.ini_file_path)
            if self.config.has_section('Settings'):
                dark_mode_str = self.config.get('Settings', 'DarkMode', fallback='true')
                return dark_mode_str.lower() == 'true'
        except Exception:
            pass
        return True  # Default to dark mode
    
    def set_dark_mode(self, enabled):
        """Set DarkMode setting and save to INI file"""
        try:
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            self.config.set('Settings', 'DarkMode', 'true' if enabled else 'false')
            self.save_settings()
            # Reapply theme
            self.apply_theme()
        except Exception as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Could not save DarkMode setting: {str(e)}"
            )
    
    def get_ini_file_path(self):
        """Get the path to the INI configuration file"""
        return self.ini_file_path
    
    def load_settings(self):
        """Load settings from CryptoTool.ini file"""
        if self.ini_file_path.exists():
            try:
                self.config.read(self.ini_file_path)
                # DarkMode is loaded in apply_theme() which is called after UI load
                # Folder path will be loaded after UI is created
            except Exception as e:
                # If there's an error reading the INI file, just continue
                # The app will work without saved settings
                pass
    
    def load_folder_setting(self):
        """Load the saved folder path after UI is ready"""
        try:
            if self.config.has_section('Settings'):
                folder_path = self.config.get('Settings', 'selected_folder', fallback='')
                if folder_path and Path(folder_path).exists() and self.folder_edit:
                    self.folder_edit.setText(folder_path)
                    self.load_files_from_folder(folder_path)
        except Exception as e:
            # If there's an error, just continue
            pass
    
    def get_checked_files(self):
        """Get list of currently checked file names"""
        checked_files = []
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if item and item.checkState() == Qt.Checked:
                checked_files.append(item.text())
        return checked_files
    
    def save_settings(self):
        """Save settings to CryptoTool.ini file"""
        try:
            # Ensure Settings section exists
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            
            # Save the selected folder
            folder_path = self.folder_edit.text()
            self.config.set('Settings', 'selected_folder', folder_path)
            
            # Save checked files for this folder
            checked_files = self.get_checked_files()
            # Store as comma-separated list
            checked_files_str = ','.join(checked_files)
            self.config.set('Settings', 'checked_files', checked_files_str)
            
            # Save Style if it doesn't exist (preserve it if it does)
            if not self.config.has_option('Settings', 'Style'):
                self.config.set('Settings', 'Style', 'dark_amber.xml')  # Default style
            
            # Preserve DarkMode if it exists (for backward compatibility)
            if not self.config.has_option('Settings', 'DarkMode'):
                self.config.set('Settings', 'DarkMode', 'true')  # Default to dark mode
            
            # Write to file
            with open(self.ini_file_path, 'w') as configfile:
                self.config.write(configfile)
        except Exception as e:
            # If there's an error saving, show a warning but don't crash
            QMessageBox.warning(
                self,
                "Warning",
                f"Could not save settings: {str(e)}"
            )
    
    def setup_connections(self):
        """Connect UI signals to slots"""
        self.process_btn.clicked.connect(self.process_selected)
        self.select_folder_btn.clicked.connect(self.select_folder)
        # Update file list when folder path is manually changed
        self.folder_edit.editingFinished.connect(self.on_folder_changed)
        # Connect Select All and Clear Selections buttons
        if self.select_all_btn:
            self.select_all_btn.clicked.connect(self.select_all_files)
        if self.clear_selections_btn:
            self.clear_selections_btn.clicked.connect(self.clear_all_selections)
        # Connect password validation
        if self.password_edit:
            self.password_edit.textChanged.connect(self.on_password_changed)
    
    def select_all_files(self):
        """Check all files in the list"""
        # Reset progress bar when selection changes
        if self.progress_bar:
            self.progress_bar.setValue(0)
        
        # Temporarily disconnect to avoid saving on each change
        try:
            self.file_list.itemChanged.disconnect(self.on_item_check_changed)
        except TypeError:
            pass
        
        # Check all items
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if item:
                item.setCheckState(Qt.Checked)
        
        # Reconnect and save settings once
        self.file_list.itemChanged.connect(self.on_item_check_changed)
        self.save_settings()
        self.statusBar().showMessage(f"Selected all {self.file_list.count()} file(s)")
    
    def clear_all_selections(self):
        """Uncheck all files in the list"""
        # Reset progress bar when selection changes
        if self.progress_bar:
            self.progress_bar.setValue(0)
        
        # Temporarily disconnect to avoid saving on each change
        try:
            self.file_list.itemChanged.disconnect(self.on_item_check_changed)
        except TypeError:
            pass
        
        # Uncheck all items
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if item:
                item.setCheckState(Qt.Unchecked)
        
        # Reconnect and save settings once
        self.file_list.itemChanged.connect(self.on_item_check_changed)
        self.save_settings()
        self.statusBar().showMessage("Cleared all selections")
    
    def on_password_changed(self, text):
        """Handle when password text changes - validate length"""
        # Allow longer passwords for hex keys (up to 100 chars to allow spaces in hex format)
        # The actual validation happens in process_selected()
        # No need to truncate here - let users enter hex keys
        pass
    
    def on_item_check_changed(self, item):
        """Handle when a checkbox state changes - save settings and reset progress"""
        # Reset progress bar when selection changes
        if self.progress_bar:
            self.progress_bar.setValue(0)
        # Save the checked files to INI file
        self.save_settings()
    
    def select_folder(self):
        """Open folder browser dialog to select the folder that will be used for operations"""
        # Use the current folder as the starting directory if available
        current_folder = self.folder_edit.text()
        if not current_folder or not Path(current_folder).exists():
            # Start from root to show all drives including external drives
            # On Linux, this will show /media, /mnt, and all mounted drives
            # On Windows, this will show all drive letters (C:\, D:\, E:\, etc.)
            if sys.platform == "win32":
                # On Windows, prefer E: drive if it exists, otherwise use first available drive
                if os.path.exists("E:\\"):
                    current_folder = "E:\\"
                else:
                    # Get the first available drive
                    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
                    if drives:
                        current_folder = drives[0]
                    else:
                        current_folder = "C:\\"
            else:
                # On Linux/Unix, start from root to show all mounted drives
                current_folder = "/"
        
        # Open folder selection dialog with options to show external drives
        # Use DontUseNativeDialog to ensure better visibility of all drives
        # This makes it easier to navigate to external drives mounted under /media, /mnt, etc.
        options = QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Operate On (including external drives)",
            current_folder,
            options
        )
        
        # If a folder was selected, use it as the operation folder
        if folder:
            # Set the selected folder in the line edit (this is the folder that will be operated on)
            self.folder_edit.setText(folder)
            # Load files from the selected folder into the list
            self.load_files_from_folder(folder)
            # Save the selected folder to INI file so it's remembered next time
            self.save_settings()
    
    def on_folder_changed(self):
        """Handle when folder path is manually changed in the line edit"""
        folder_path = self.folder_edit.text()
        if folder_path:
            folder = Path(folder_path)
            if folder.exists() and folder.is_dir():
                self.load_files_from_folder(folder_path)
                self.save_settings()  # Save the folder path to INI file
            else:
                # Clear the file list if folder doesn't exist
                self.file_list.clear()
                self.statusBar().showMessage(f"Folder not found: {folder_path}")
    
    def get_saved_checked_files(self):
        """Get list of checked files from INI file"""
        checked_files = []
        try:
            if self.config.has_section('Settings'):
                checked_files_str = self.config.get('Settings', 'checked_files', fallback='')
                if checked_files_str:
                    checked_files = [f.strip() for f in checked_files_str.split(',') if f.strip()]
        except Exception:
            pass
        return checked_files
    
    def create_lock_icon(self):
        """Create a simple monochrome lock icon in red"""
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Use red color for the lock icon
        icon_color = QColor(255, 0, 0)
        pen = QPen(icon_color, 2)
        painter.setPen(pen)
        # Draw a simple lock shape
        # Lock body (rectangle)
        painter.drawRect(4, 8, 8, 6)
        # Lock shackle (semicircle)
        painter.drawArc(5, 4, 6, 6, 0, 180 * 16)
        painter.end()
        return QIcon(pixmap)
    
    def create_unlock_icon(self):
        """Create a simple monochrome unlock icon in white"""
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Use white color for the unlock icon
        icon_color = QColor(255, 255, 255)
        pen = QPen(icon_color, 2)
        painter.setPen(pen)
        # Draw a simple unlock shape
        # Lock body (rectangle with opening)
        painter.drawLine(4, 8, 4, 14)  # Left side
        painter.drawLine(12, 8, 12, 14)  # Right side
        painter.drawLine(4, 8, 12, 8)  # Top
        painter.drawLine(4, 14, 12, 14)  # Bottom
        # Open shackle (semicircle with opening)
        painter.drawArc(5, 4, 6, 6, 45 * 16, 135 * 16)
        painter.end()
        return QIcon(pixmap)
    
    def load_files_from_folder(self, folder_path):
        """Load .lua, .lua.enc, and .tlog files from the selected folder into the list widget with checkboxes"""
        self.file_list.clear()
        
        # Reset progress bar when file selection changes
        if self.progress_bar:
            self.progress_bar.setValue(0)
        
        try:
            folder = Path(folder_path)
            if folder.exists() and folder.is_dir():
                # Get saved checked files from INI
                saved_checked_files = self.get_saved_checked_files()
                
                # Get all .lua files, .lua.enc files, and .tlog files in the folder
                lua_files = sorted(folder.glob("*.lua"))
                lua_enc_files = sorted(folder.glob("*.lua.enc"))
                tlog_files = sorted(folder.glob("*.tlog"))
                all_files = lua_files + lua_enc_files + tlog_files
                
                if all_files:
                    for file_path in all_files:
                        if file_path.is_file():
                            # Check if file is encrypted (ends with .lua.enc or .tlog)
                            is_encrypted = file_path.name.endswith('.lua.enc') or file_path.name.endswith('.tlog')
                            
                            # Create a list item with checkbox
                            item = QListWidgetItem(file_path.name)
                            # Make the item checkable
                            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                            
                            # Set icon based on encryption status (second column)
                            # Use monochrome lock/unlock icons
                            app = QApplication.instance()
                            if app:
                                if is_encrypted:
                                    # Use red locked icon for encrypted files
                                    # Always use custom red lock icon for consistency
                                    locked_icon = self.create_lock_icon()
                                    item.setIcon(locked_icon)
                                else:
                                    # Use unlocked icon for unencrypted files
                                    unlocked_icon = QIcon.fromTheme("unlock")
                                    if unlocked_icon.isNull():
                                        unlocked_icon = QIcon.fromTheme("object-unlocked")
                                    if unlocked_icon.isNull():
                                        unlocked_icon = QIcon.fromTheme("emblem-unlocked")
                                    if unlocked_icon.isNull():
                                        unlocked_icon = QIcon.fromTheme("security-low")
                                    # If still no icon, create a simple monochrome unlock icon
                                    if unlocked_icon.isNull():
                                        unlocked_icon = self.create_unlock_icon()
                                    item.setIcon(unlocked_icon)
                            
                            # Restore checked state if this file was previously checked
                            if file_path.name in saved_checked_files:
                                item.setCheckState(Qt.Checked)
                            else:
                                item.setCheckState(Qt.Unchecked)
                            
                            # Add item to the list first
                            self.file_list.addItem(item)
                            
                            # Highlight encrypted files with theme's selected color
                            # Set colors after item is added to ensure they're applied
                            if is_encrypted:
                                # Store encrypted flag in user data first
                                item.setData(Qt.ItemDataRole.UserRole, "encrypted")
                                # Get the theme's highlight/selected color from palette
                                app = QApplication.instance()
                                if app:
                                    palette = app.palette()
                                    highlight_color = palette.color(QPalette.ColorRole.Highlight)
                                    # Use red for encrypted file text color
                                    red_text_color = QColor(255, 0, 0)  # Explicit RGB red
                                    red_brush = QBrush(red_text_color)
                                    highlight_brush = QBrush(highlight_color)
                                    # Set background and foreground using QBrush
                                    item.setBackground(highlight_brush)
                                    item.setForeground(red_brush)
                                    # Force update to ensure colors are applied
                                    self.file_list.update()
                                    # Also update after a short delay to ensure theme doesn't override
                                    QApplication.processEvents()
                    
                    # Connect item changed signal to save settings when checkboxes change
                    # Disconnect first to avoid multiple connections
                    try:
                        self.file_list.itemChanged.disconnect(self.on_item_check_changed)
                    except TypeError:
                        # Not connected yet, which is fine
                        pass
                    self.file_list.itemChanged.connect(self.on_item_check_changed)
                    
                    checked_count = len([f for f in saved_checked_files if (folder / f).exists()])
                    lua_count = len(lua_files)
                    enc_count = len(lua_enc_files)
                    tlog_count = len(tlog_files)
                    self.statusBar().showMessage(
                        f"Loaded {lua_count} .lua file(s), {enc_count} .lua.enc file(s), {tlog_count} .tlog file(s) ({checked_count} checked)"
                    )
                else:
                    self.statusBar().showMessage("No .lua, .lua.enc, or .tlog files found in the selected folder")
        except Exception as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Error loading files: {str(e)}"
            )
            self.statusBar().showMessage("Error loading files")
    
    def get_operation_folder(self):
        """Get the folder path from the line edit that will be operated on"""
        folder_path = self.folder_edit.text().strip()
        if not folder_path:
            return None
        folder = Path(folder_path)
        if folder.exists() and folder.is_dir():
            return folder
        return None
    
    def process_selected(self):
        """Process the selected action (encrypt/decrypt)"""
        # Get the operation folder from the line edit
        operation_folder = self.get_operation_folder()
        if not operation_folder:
            QMessageBox.warning(
                self,
                "Warning",
                "Please select a valid folder to operate on."
            )
            return
        
        password = self.password_edit.text().strip()  # Remove any leading/trailing whitespace
        if not password:
            QMessageBox.warning(
                self,
                "Warning",
                "Please enter a password."
            )
            return
        
        # Validate password length
        # Allow hex keys (up to 100 chars to accommodate spaces in hex format like "01 23 45 ...")
        # For regular passwords, minimum 8 characters
        password_clean = password.strip()
        hex_string_no_spaces = re.sub(r'[\s\t]', '', password_clean)
        is_hex_key = len(hex_string_no_spaces) > 0 and re.match(r'^[0-9a-fA-F]+$', hex_string_no_spaces)
        
        if is_hex_key:
            # Hex key validation - allow 8-64 hex characters (4-32 bytes)
            # Allow 8-character hex keys (4 bytes) for shorter keys
            if len(hex_string_no_spaces) < 8:
                QMessageBox.warning(
                    self,
                    "Hex Key Too Short",
                    f"Hex key must be at least 4 bytes (8 hex characters). Got {len(hex_string_no_spaces) // 2} bytes ({len(hex_string_no_spaces)} hex characters)."
                )
                return
            if len(hex_string_no_spaces) % 2 != 0:
                QMessageBox.warning(
                    self,
                    "Hex Key Invalid",
                    f"Hex key must have an even number of characters. Got {len(hex_string_no_spaces)} hex characters."
                )
                return
            if len(hex_string_no_spaces) > 64:
                QMessageBox.warning(
                    self,
                    "Hex Key Too Long",
                    f"Hex key must be at most 32 bytes (64 hex characters). Got {len(hex_string_no_spaces) // 2} bytes ({len(hex_string_no_spaces)} hex characters)."
                )
                return
        else:
            # Regular password validation - allow 8 characters or more, maximum 100 to allow flexibility
            # Allow 8-character keys (for numeric LEIGH_KEY values or short passwords)
            if len(password) < 8:
                QMessageBox.warning(
                    self,
                    "Password Too Short",
                    "Password must be at least 8 characters long. Please enter a password with at least 8 characters."
                )
                return
            # Note: 8-character passwords are allowed (minimum is 8)
            if len(password) > 100:
                QMessageBox.warning(
                    self,
                    "Password Too Long",
                    "Password must be 100 characters or less."
                )
                return
        
        if not self.encrypt_radio.isChecked() and not self.decrypt_radio.isChecked():
            QMessageBox.warning(
                self,
                "Warning",
                "Please select an action (Encrypt or Decrypt)."
            )
            return
        
        # Get checked items (files with checkboxes checked)
        checked_files = []
        skipped_files = []
        action = "encrypt" if self.encrypt_radio.isChecked() else "decrypt"
        
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if item and item.checkState() == Qt.Checked:
                filename = item.text()
                file_path = operation_folder / filename
                if file_path.exists():
                    is_encrypted = filename.endswith('.lua.enc') or filename.endswith('.tlog')
                    
                    # Filter files based on action and current state
                    if action == "encrypt":
                        # Skip files that are already encrypted
                        if is_encrypted:
                            skipped_files.append(filename)
                            continue
                        # Only process .lua files (not .lua.enc or .tlog)
                        if file_path.suffix.lower() == '.lua':
                            checked_files.append(file_path)
                    else:  # decrypt
                        # Skip files that are already decrypted
                        if not is_encrypted:
                            skipped_files.append(filename)
                            continue
                        # Only process .lua.enc or .tlog files
                        if is_encrypted:
                            checked_files.append(file_path)
        
        # Show warning if files were skipped
        if skipped_files:
            skipped_list = "\n".join(skipped_files[:10])  # Show first 10
            if len(skipped_files) > 10:
                skipped_list += f"\n... and {len(skipped_files) - 10} more"
            QMessageBox.information(
                self,
                "Files Skipped",
                f"Skipped {len(skipped_files)} file(s) that are already {action}ed:\n\n{skipped_list}"
            )
        
        if not checked_files:
            QMessageBox.warning(
                self,
                "Warning",
                f"No files to {action}. Please check files that need to be {action}ed."
            )
            return
        
        file_count = len(checked_files)
        
        # Clear and initialize progress bar
        if self.progress_bar:
            self.progress_bar.setValue(0)
            self.progress_bar.setMaximum(file_count)
            self.progress_bar.setMinimum(0)
        
        # Derive key from password
        try:
            # Derive key from password using XOR-based method
            # For numeric passwords: SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
            # For other passwords: pad/truncate to 32 bytes
            default_salt = b'LEIGH_KEY_SALT_1'
            key_b64 = derive_key_from_password(password, salt=default_salt)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to derive key from password: {str(e)}"
            )
            return
        
        # Process files
        success_count = 0
        error_count = 0
        error_messages = []
        
        self.statusBar().showMessage(
            f"Processing {file_count} file(s) - {action.capitalize()}ing..."
        )
        
        for index, file_path in enumerate(checked_files, 1):
            try:
                if action == "encrypt":
                    # Encrypt: input.lua -> input.lua.enc
                    # Files are already filtered - only .lua files reach here
                    output_file = file_path.with_suffix('.lua.enc')
                    encrypt_file(key_b64, str(file_path), str(output_file))
                    # Remove original file to change extension to reflect encryption status
                    if output_file.exists():
                        file_path.unlink()  # Delete original .lua file
                    success_count += 1
                else:
                    # Decrypt: input.lua.enc -> input.lua, or input.tlog -> input.log
                    if file_path.name.endswith('.lua.enc'):
                        output_file = file_path.parent / (file_path.name[:-8] + '.lua')
                    elif file_path.name.endswith('.tlog'):
                        # Rename .tlog extension to .log when decrypting
                        output_file = file_path.parent / (file_path.stem + '.log')
                    else:
                        output_file = file_path.parent / (file_path.name + '.decrypted')
                    
                    # Use XOR-based decryption (only supported method)
                    decrypt_file(key_b64, str(file_path), str(output_file))
                    # Remove original file to change extension to reflect encryption status
                    if output_file.exists():
                        file_path.unlink()  # Delete original encrypted file
                    success_count += 1
                    
            except Exception as e:
                error_count += 1
                error_messages.append(f"{file_path.name}: {str(e)}")
            
            # Update progress bar
            if self.progress_bar:
                self.progress_bar.setValue(index)
                # Process events to update UI
                QApplication.processEvents()
        
        # Show results
        if error_count == 0:
            QMessageBox.information(
                self,
                "Success",
                f"Successfully {action}ed {success_count} file(s)."
            )
            self.statusBar().showMessage(f"Successfully {action}ed {success_count} file(s)")
        else:
            error_text = "\n".join(error_messages[:10])  # Show first 10 errors
            if len(error_messages) > 10:
                error_text += f"\n... and {len(error_messages) - 10} more errors"
            
            QMessageBox.warning(
                self,
                "Processing Complete",
                f"Processed {success_count} file(s) successfully.\n"
                f"Failed to process {error_count} file(s):\n\n{error_text}"
            )
            self.statusBar().showMessage(
                f"Processed {success_count} file(s), {error_count} error(s)"
            )
        
        # Reset progress bar to 0 after completion
        if self.progress_bar:
            self.progress_bar.setValue(0)
        
        # Reload files to show updated list
        self.load_files_from_folder(str(operation_folder))


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    window = CryptoToolWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

