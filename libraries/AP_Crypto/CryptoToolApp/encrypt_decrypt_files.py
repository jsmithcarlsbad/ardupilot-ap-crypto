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

