#!/usr/bin/env python3
"""
Simple encryption/decryption using only Python standard library.

This is a pure-Python implementation that requires NO external libraries.
Uses only: hashlib, hmac, secrets, struct (all standard library)
"""

import hashlib
import hmac
import secrets
from struct import pack, unpack


def derive_key(password_or_leigh_key, salt=b'LEIGH_KEY_SALT_1'):
    """
    Derive a 32-byte encryption key from password or LEIGH_KEY.
    
    Args:
        password_or_leigh_key: Either a float (LEIGH_KEY from ArduPilot parameter) 
                               or string (password)
        salt: Salt bytes for key derivation (default: b'LEIGH_KEY_SALT_1')
    
    Returns:
        32-byte key derived using PBKDF2
    
    Note:
        ArduPilot stores parameters as 32-bit floats. When Mission Planner sets
        LEIGH_KEY to 74768360, it's stored as float 74768360.0. This function
        converts the float to IEEE 754 little-endian format for key derivation.
    """
    if isinstance(password_or_leigh_key, (int, float)):
        # LEIGH_KEY: ArduPilot stores parameters as 32-bit floats
        # Convert to IEEE 754 little-endian float (4 bytes)
        # This matches how ArduPilot stores the parameter internally
        seed = pack('<f', float(password_or_leigh_key))
    else:
        # Password: convert to bytes
        seed = str(password_or_leigh_key).encode('utf-8')
    
    # PBKDF2 with SHA-256, 10000 iterations (slower = more secure against brute force)
    key = hashlib.pbkdf2_hmac('sha256', seed, salt, 10000)
    return key


def generate_keystream(key, nonce, length):
    """
    Generate a keystream using HMAC-SHA256.
    
    This creates a cryptographically secure random-looking keystream by:
    1. HMAC-SHA256(key, nonce + counter) for each 32-byte block
    2. Counter increments for each block
    
    Args:
        key: 32-byte encryption key
        nonce: 16-byte nonce (unique per encryption)
        length: Desired keystream length in bytes
    
    Returns:
        Keystream bytes of specified length
    """
    keystream = b''
    counter = 0
    while len(keystream) < length:
        # HMAC(key, nonce + counter) → 32 bytes per block
        # Use big-endian 64-bit counter (allows up to 2^64 blocks)
        data = nonce + pack('>Q', counter)  # >Q = big-endian unsigned long long
        block = hmac.new(key, data, hashlib.sha256).digest()
        keystream += block
        counter += 1
    return keystream[:length]


def encrypt_simple(key, plaintext):
    """
    Encrypt plaintext using simple XOR cipher with HMAC-based keystream.
    
    Process:
    1. Generate random 16-byte nonce
    2. Generate keystream using HMAC-SHA256
    3. XOR plaintext with keystream
    4. Compute MAC: HMAC(key, nonce + ciphertext)
    5. Return: nonce + ciphertext + mac
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt (bytes)
    
    Returns:
        Encrypted data: [nonce: 16 bytes][ciphertext: variable][mac: 16 bytes]
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    
    # Generate random nonce (unique per encryption)
    nonce = secrets.token_bytes(16)
    
    # Generate keystream (same length as plaintext)
    keystream = generate_keystream(key, nonce, len(plaintext))
    
    # XOR encrypt: ciphertext = plaintext XOR keystream
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    
    # Generate MAC: HMAC(key, nonce + ciphertext)
    # MAC ensures integrity - detects tampering or wrong key
    mac_data = nonce + ciphertext
    mac = hmac.new(key, mac_data, hashlib.sha256).digest()[:16]  # Use first 16 bytes
    
    # Return: nonce + ciphertext + mac
    return nonce + ciphertext + mac


def decrypt_simple(key, encrypted_data):
    """
    Decrypt encrypted data and verify MAC.
    
    Process:
    1. Extract nonce, ciphertext, and MAC
    2. Verify MAC: compute HMAC(key, nonce + ciphertext) and compare
    3. Generate keystream
    4. XOR decrypt: plaintext = ciphertext XOR keystream
    5. Return plaintext
    
    Args:
        key: 32-byte decryption key (must match encryption key)
        encrypted_data: Encrypted data from encrypt_simple()
    
    Returns:
        Decrypted plaintext (bytes)
    
    Raises:
        ValueError: If MAC verification fails (wrong key or corrupted data)
    """
    if not isinstance(encrypted_data, bytes):
        raise TypeError("encrypted_data must be bytes")
    
    if len(encrypted_data) < 32:  # Minimum: 16 nonce + 16 MAC
        raise ValueError("Encrypted data too short (need at least 32 bytes)")
    
    # Extract components
    nonce = encrypted_data[:16]
    mac = encrypted_data[-16:]
    ciphertext = encrypted_data[16:-16]
    
    if len(ciphertext) == 0:
        raise ValueError("No ciphertext data (file contains only nonce and MAC)")
    
    # Verify MAC first (before attempting decryption)
    mac_data = nonce + ciphertext
    computed_mac = hmac.new(key, mac_data, hashlib.sha256).digest()[:16]
    
    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(mac, computed_mac):
        raise ValueError(
            "MAC verification failed - the encryption key may be incorrect "
            "or the file may be corrupted"
        )
    
    # Generate keystream (same as encryption)
    keystream = generate_keystream(key, nonce, len(ciphertext))
    
    # XOR decrypt: plaintext = ciphertext XOR keystream
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    
    return plaintext


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file.
    
    Args:
        input_file: Path to plaintext file
        output_file: Path to write encrypted file
        key: 32-byte encryption key
    """
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    encrypted = encrypt_simple(key, plaintext)
    
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    
    print(f"Encrypted {len(plaintext)} bytes → {len(encrypted)} bytes")
    print(f"  Overhead: {len(encrypted) - len(plaintext)} bytes (nonce + MAC)")


def decrypt_file(input_file, output_file, key):
    """
    Decrypt a file.
    
    Args:
        input_file: Path to encrypted file
        output_file: Path to write decrypted file
        key: 32-byte decryption key
    """
    with open(input_file, 'rb') as f:
        encrypted = f.read()
    
    try:
        plaintext = decrypt_simple(key, encrypted)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return False
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    
    print(f"Decrypted {len(encrypted)} bytes → {len(plaintext)} bytes")
    return True


# Example usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 4:
        print("Usage:")
        print("  Encrypt: python3 simple_encrypt.py encrypt <input> <output> <LEIGH_KEY>")
        print("  Decrypt: python3 simple_encrypt.py decrypt <input> <output> <LEIGH_KEY>")
        print()
        print("Example:")
        print("  python3 simple_encrypt.py encrypt test.log test.log.enc 74768360")
        print("  python3 simple_encrypt.py decrypt test.log.enc test.log.dec 74768360")
        print()
        print("Note: LEIGH_KEY is stored as a 32-bit float in ArduPilot.")
        print("      You can use integer values (74768360) or float values (74768360.0)")
        sys.exit(1)
    
    action = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Get key (LEIGH_KEY as float - ArduPilot stores parameters as floats)
    try:
        leigh_key = float(sys.argv[4])
    except (IndexError, ValueError):
        print("Error: LEIGH_KEY must be a number (e.g., 74768360 or 74768360.0)")
        print("Note: ArduPilot stores parameters as 32-bit floats")
        sys.exit(1)
    
    # Derive key
    key = derive_key(leigh_key)
    print(f"Using LEIGH_KEY: {leigh_key} (stored as float: {pack('<f', leigh_key).hex()})")
    print(f"Derived key (first 16 bytes): {key[:16].hex()}")
    
    # Encrypt or decrypt
    if action == 'encrypt':
        encrypt_file(input_file, output_file, key)
        print(f"✓ Encrypted: {input_file} → {output_file}")
    elif action == 'decrypt':
        if decrypt_file(input_file, output_file, key):
            print(f"✓ Decrypted: {input_file} → {output_file}")
        else:
            sys.exit(1)
    else:
        print(f"Error: Unknown action '{action}' (use 'encrypt' or 'decrypt')")
        sys.exit(1)

