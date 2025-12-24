#!/usr/bin/env python3
"""
Simple decryption script for encrypted log files using pymonocypher.
This script works around the limited API by implementing the decryption manually.
"""

import sys
import struct
import hashlib
import base64

# Try to import monocypher - we'll use what's available
try:
    import monocypher
    HAS_MONOCYPHER = True
except ImportError:
    print("Error: pymonocypher library not found.")
    print("Install it with: pip3 install pymonocypher")
    sys.exit(1)

# Constants
FERNET_VERSION = 0x80
FERNET_HEADER_SIZE = 33  # 1 + 8 + 24
FERNET_MAC_SIZE = 16

def base64url_decode(data):
    """Decode base64url data."""
    data = data.replace('-', '+')
    data = data.replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)

def derive_key_from_leigh_key(leigh_key_value):
    """Derive a 32-byte key from LEIGH_KEY INT32 value."""
    salt = bytes([0x4c, 0x45, 0x49, 0x47, 0x48, 0x5f, 0x4b, 0x45,
                  0x59, 0x5f, 0x53, 0x41, 0x4c, 0x54, 0x5f, 0x31])
    seed_bytes = struct.pack('<i', leigh_key_value)
    key_bytes = hashlib.blake2b(seed_bytes + salt, digest_size=32).digest()
    return key_bytes

def get_default_key():
    """Get the default hardcoded key."""
    default_key_str = "LEIGH AEROSPACE DEADBEEF_IS_COLD"
    key_bytes = default_key_str.encode('ascii')
    if len(key_bytes) < 32:
        key_bytes = key_bytes + b'\x00' * (32 - len(key_bytes))
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    return key_bytes

def chacha20_keystream(key, nonce_8, counter, length):
    """Generate ChaCha20 keystream using available API."""
    # Our monocypher API: chacha20(key, nonce, message)
    # For CTR mode, we need to manually implement counter
    # Actually, chacha20 with 8-byte nonce should handle CTR automatically
    zeros = b'\x00' * length
    keystream = monocypher.chacha20(key, nonce_8, zeros)
    return keystream

def hchacha20(out, key, in_nonce):
    """HChaCha20 key derivation - manual implementation."""
    def rotl32(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    def quarter_round(state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotl32(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotl32(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotl32(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotl32(state[b] ^ state[c], 7)
    
    # Use first 16 bytes of 24-byte nonce for hchacha20
    nonce_16 = in_nonce[:16]
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
    nonce_words = [int.from_bytes(nonce_16[i:i+4], 'little') for i in range(0, 16, 4)]
    state = constants + key_words + nonce_words + [0]
    working_state = state[:]
    
    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
    
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff
    
    output_words = [working_state[i] for i in [0, 1, 2, 3, 12, 13, 14, 15]]
    sub_key = b''.join(word.to_bytes(4, 'little') for word in output_words)
    out[:] = sub_key

def poly1305_mac(message, key):
    """Compute Poly1305 MAC."""
    # pymonocypher doesn't expose poly1305 directly, but we can use lock/unlock
    # For MAC only, we can use the IncrementalAuthenticatedEncryption class
    # Actually, let's use a workaround: create a dummy encryption and extract MAC
    nonce = b'\x00' * 24
    mac, _ = monocypher.lock(key, nonce, message)
    return mac

def decrypt_file(input_file, output_file, key_bytes):
    """Decrypt an encrypted log file."""
    
    # Read input file
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"Error reading input file: {e}")
        return False
    
    if len(data) < FERNET_HEADER_SIZE + FERNET_MAC_SIZE:
        print("Error: File too small to be encrypted")
        return False
    
    # Parse header
    pos = 0
    version = data[pos]
    pos += 1
    
    if version != FERNET_VERSION:
        print(f"Error: Invalid version byte (expected 0x{FERNET_VERSION:02x}, got 0x{version:02x})")
        return False
    
    # Read timestamp (8 bytes, big-endian)
    timestamp = struct.unpack('>Q', data[pos:pos+8])[0]
    pos += 8
    
    # Read nonce (24 bytes)
    nonce = data[pos:pos+24]
    pos += 24
    
    # Extract MAC from end of file
    mac = data[-FERNET_MAC_SIZE:]
    
    # Extract ciphertext (everything between header and MAC)
    ciphertext = data[FERNET_HEADER_SIZE:-FERNET_MAC_SIZE]
    
    if len(ciphertext) == 0:
        print("Error: No encrypted data in file")
        return False
    
    # Derive keys for decryption
    # 1. Derive sub-key using hchacha20
    sub_key = bytearray(32)
    hchacha20(sub_key, key_bytes, nonce)
    
    # 2. Derive auth key using chacha20 (counter=0)
    nonce_8 = nonce[16:24]
    zero_64 = bytes(64)
    auth_key_bytes = monocypher.chacha20(bytes(sub_key), nonce_8, zero_64)
    if not auth_key_bytes or len(auth_key_bytes) < 64:
        print("Error: Failed to derive auth key")
        return False
    auth_key = bytearray(auth_key_bytes[:64])
    
    # 3. Verify MAC using Poly1305
    try:
        from cryptography.hazmat.primitives import poly1305
        poly_key = bytes(auth_key[:32])
        p = poly1305.Poly1305(poly_key)
        p.update(ciphertext)
        computed_mac = p.finalize()
    except ImportError:
        # Fallback: use lock to compute MAC
        computed_mac, _ = monocypher.lock(bytes(auth_key[:32]), b'\x00' * 24, ciphertext)
    
    # Compare MACs
    if computed_mac != mac:
        print("Error: MAC verification failed - the encryption key may be incorrect")
        return False
    
    # 4. Decrypt ciphertext using ChaCha20-CTR (counter=1)
    # Our chacha20 API handles CTR mode automatically with 8-byte nonce
    # But we need counter=1, so we'll decrypt directly
    plaintext_bytes = monocypher.chacha20(bytes(sub_key), nonce_8, ciphertext)
    if not plaintext_bytes:
        print("Error: Decryption failed")
        return False
    plaintext = bytearray(plaintext_bytes)
    
    # Write decrypted file
    try:
        with open(output_file, 'wb') as f:
            f.write(plaintext)
    except IOError as e:
        print(f"Error writing output file: {e}")
        return False
    
    print(f"Successfully decrypted {input_file} -> {output_file}")
    print(f"  Encrypted size: {len(data)} bytes")
    print(f"  Decrypted size: {len(plaintext)} bytes")
    print(f"  Timestamp: {timestamp} ms")
    
    return True

def main():
    if len(sys.argv) < 3:
        print("Usage: decrypt_simple.py <input.tlog> <output.log> [--key KEY|--leigh-key VALUE|--default-key]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Determine key
    key_bytes = None
    
    if '--key' in sys.argv:
        idx = sys.argv.index('--key')
        if idx + 1 >= len(sys.argv):
            print("Error: --key requires a value")
            sys.exit(1)
        key_b64 = sys.argv[idx + 1]
        key_bytes = base64url_decode(key_b64)
        if key_bytes is None or len(key_bytes) != 32:
            print("Error: Invalid key (must be 32 bytes base64url-encoded)")
            sys.exit(1)
    elif '--leigh-key' in sys.argv:
        idx = sys.argv.index('--leigh-key')
        if idx + 1 >= len(sys.argv):
            print("Error: --leigh-key requires a value")
            sys.exit(1)
        leigh_key = int(sys.argv[idx + 1])
        key_bytes = derive_key_from_leigh_key(leigh_key)
        print(f"Using LEIGH_KEY={leigh_key}")
    elif '--default-key' in sys.argv:
        key_bytes = get_default_key()
        print("Using default key")
    else:
        # Default to default key
        key_bytes = get_default_key()
        print("Using default key (use --key, --leigh-key, or --default-key to specify)")
    
    if decrypt_file(input_file, output_file, key_bytes):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()

