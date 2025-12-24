#!/usr/bin/env python3
"""
Decrypt files using the simplified XOR encryption method.
Based on COMPLETE_ENCRYPTION_SOLUTION.md

Algorithm:
- Key derivation: SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1") → 32 bytes
- Keystream: For each 32-byte block, SHA256(key + counter) → 32 bytes
- Decryption: XOR ciphertext with keystream
- Format: Just ciphertext (no header, no MAC, no nonce)
"""

import sys
import struct
import hashlib
import argparse

def derive_key_from_leigh_key(leigh_key_value):
    """Derive key from LEIGH_KEY INT32 using SHA256."""
    salt = b'LEIGH_KEY_SALT_1'  # 16 bytes
    seed_bytes = struct.pack('<i', leigh_key_value)  # INT32 little-endian
    return hashlib.sha256(seed_bytes + salt).digest()

def generate_keystream_block(key, counter):
    """Generate 32-byte keystream block for given counter."""
    counter_bytes = struct.pack('<Q', counter)  # uint64_t little-endian
    return hashlib.sha256(key + counter_bytes).digest()

def decrypt_file(input_file, output_file, leigh_key_value, chunk_size=64*1024):
    """
    Decrypt file using simple XOR encryption.
    
    Args:
        input_file: Path to encrypted file
        output_file: Path to output decrypted file
        leigh_key_value: LEIGH_KEY parameter value (INT32)
        chunk_size: Chunk size for streaming (default: 64KB)
    """
    # Derive key
    key = derive_key_from_leigh_key(leigh_key_value)
    print(f"LEIGH_KEY: {leigh_key_value}")
    print(f"Derived key: {key.hex()}")
    print()
    
    # Decrypt in chunks
    counter = 0
    total_bytes = 0
    
    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        while True:
            ciphertext_chunk = fin.read(chunk_size)
            if not ciphertext_chunk:
                break
            
            # Decrypt chunk
            plaintext_chunk = bytearray()
            i = 0
            while i < len(ciphertext_chunk):
                # Generate keystream for this block
                keystream = generate_keystream_block(key, counter)
                
                # XOR this 32-byte block (or remainder)
                block_size = min(32, len(ciphertext_chunk) - i)
                for j in range(block_size):
                    plaintext_chunk.append(ciphertext_chunk[i + j] ^ keystream[j])
                
                i += block_size
                counter += 1
            
            fout.write(plaintext_chunk)
            total_bytes += len(plaintext_chunk)
            
            # Progress update
            if total_bytes % (10 * 1024 * 1024) == 0:  # Every 10MB
                print(f"Decrypted {total_bytes / (1024*1024):.1f} MB...", end='\r')
    
    print(f"\n✅ Decryption complete: {total_bytes} bytes")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Decrypt files using simplified XOR encryption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Algorithm:
  Key: SHA256(LEIGH_KEY_INT32_bytes + "LEIGH_KEY_SALT_1")
  Keystream: SHA256(key + counter) for each 32-byte block
  Decryption: XOR ciphertext with keystream
  
Format:
  Just ciphertext (no header, no MAC, no nonce)
        """
    )
    parser.add_argument('input_file', help='Input encrypted file')
    parser.add_argument('output_file', help='Output decrypted file')
    parser.add_argument('--leigh-key', type=int, required=True,
                       help='LEIGH_KEY parameter value (INT32)')
    parser.add_argument('--chunk-size', type=int, default=64*1024,
                       help='Chunk size for streaming (default: 64KB)')
    
    args = parser.parse_args()
    
    try:
        decrypt_file(args.input_file, args.output_file, args.leigh_key, args.chunk_size)
        return 0
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())



