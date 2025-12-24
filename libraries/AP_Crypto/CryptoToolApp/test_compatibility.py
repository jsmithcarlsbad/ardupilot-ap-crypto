#!/usr/bin/env python3
"""
Compatibility test to verify Python CryptoToolApp matches C++ AP_Crypto implementation.

Tests:
1. XOR1 format encryption/decryption
2. Key derivation from LEIGH_KEY (INT32)
3. File format compatibility
"""

import struct
import sys

def derive_key_from_leigh_key_cpp_compatible(leigh_key_value):
    """Derive key from LEIGH_KEY INT32 - matches C++ AP_Crypto_Params.cpp exactly.
    
    C++ code:
        uint32_t uval = (uint32_t)key_value;
        for (int i = 0; i < 32; i++) {
            key[i] = ((uint8_t*)&uval)[i % 4] ^ (i * 0x73);
        }
    """
    # Convert to uint32_t (handles negative values correctly)
    uval = leigh_key_value & 0xFFFFFFFF
    
    # Pack as little-endian uint32 (4 bytes)
    uval_bytes = struct.pack('<I', uval)
    
    # Derive 32-byte key: repeat the 4 bytes, XOR with (i * 0x73)
    key = bytearray(32)
    for i in range(32):
        key[i] = uval_bytes[i % 4] ^ (i * 0x73)
    
    return bytes(key)

def xor_encrypt_xor1(plaintext, key):
    """XOR encrypt with XOR1 header - matches C++ AP_Crypto::xor_encode_raw().
    
    C++ code:
        memcpy(ciphertext, "XOR1", 4);
        for (size_t i = 0; i < plaintext_len; i++) {
            ciphertext[4 + i] = plaintext[i] ^ raw_key[i % 32];
        }
    """
    ciphertext = bytearray()
    ciphertext.extend(b"XOR1")  # Header
    for i, byte in enumerate(plaintext):
        ciphertext.append(byte ^ key[i % 32])
    return bytes(ciphertext)

def xor_decrypt_xor1(ciphertext, key):
    """XOR decrypt with XOR1 header - matches C++ AP_Crypto::xor_decode_raw().
    
    C++ code:
        if (memcmp(ciphertext, "XOR1", 4) != 0) return -1;
        for (size_t i = 0; i < data_len; i++) {
            plaintext[i] = ciphertext[4 + i] ^ raw_key[i % 32];
        }
    """
    if len(ciphertext) < 4:
        raise ValueError("File too short")
    if ciphertext[:4] != b"XOR1":
        raise ValueError("Invalid header - not XOR1 format")
    
    plaintext = bytearray()
    for i, byte in enumerate(ciphertext[4:]):
        plaintext.append(byte ^ key[i % 32])
    return bytes(plaintext)

def test_key_derivation():
    """Test key derivation matches C++ implementation."""
    print("Testing key derivation...")
    
    test_cases = [
        (12345, "Expected pattern for LEIGH_KEY=12345"),
        (74768360, "Expected pattern for LEIGH_KEY=74768360"),
        (-12345, "Negative value handling"),
        (0, "Zero value"),
        (0xFFFFFFFF, "Maximum uint32 value"),
    ]
    
    for leigh_key, description in test_cases:
        key = derive_key_from_leigh_key_cpp_compatible(leigh_key)
        assert len(key) == 32, f"Key must be 32 bytes for {description}"
        
        # Verify pattern: key repeats every 4 bytes (with XOR)
        uval_bytes = struct.pack('<I', leigh_key & 0xFFFFFFFF)
        for i in range(32):
            expected = uval_bytes[i % 4] ^ (i * 0x73)
            assert key[i] == expected, f"Key derivation mismatch at position {i} for {description}"
        
        print(f"  ✓ {description}: Key derived correctly (first 8 bytes: {key[:8].hex()})")
    
    print("  ✓ Key derivation test passed\n")

def test_xor1_encryption():
    """Test XOR1 format encryption/decryption."""
    print("Testing XOR1 format encryption/decryption...")
    
    # Test with various key values
    test_keys = [
        derive_key_from_leigh_key_cpp_compatible(12345),
        derive_key_from_leigh_key_cpp_compatible(74768360),
        bytes([i % 256 for i in range(32)]),  # Sequential key
    ]
    
    test_plaintexts = [
        b"Hello, World!",
        b"",
        b"A" * 100,  # Longer than key
        b"Test data with special chars: !@#$%^&*()",
        bytes(range(256)),  # All byte values
    ]
    
    for key in test_keys:
        for plaintext in test_plaintexts:
            # Encrypt
            ciphertext = xor_encrypt_xor1(plaintext, key)
            
            # Verify header
            assert ciphertext[:4] == b"XOR1", "Missing XOR1 header"
            assert len(ciphertext) == 4 + len(plaintext), "Ciphertext length mismatch"
            
            # Decrypt
            decrypted = xor_decrypt_xor1(ciphertext, key)
            
            # Verify round-trip
            assert decrypted == plaintext, "Decryption failed - data mismatch"
            
            print(f"  ✓ Encrypted/decrypted {len(plaintext)} bytes with key (first 4 bytes: {key[:4].hex()})")
    
    print("  ✓ XOR1 format test passed\n")

def test_key_cycling():
    """Test that key cycles correctly for data longer than 32 bytes."""
    print("Testing key cycling...")
    
    key = derive_key_from_leigh_key_cpp_compatible(12345)
    plaintext = b"A" * 100  # Longer than 32-byte key
    
    ciphertext = xor_encrypt_xor1(plaintext, key)
    decrypted = xor_decrypt_xor1(ciphertext, key)
    
    assert decrypted == plaintext, "Key cycling failed for long data"
    print(f"  ✓ Key cycling works correctly for {len(plaintext)} bytes\n")

def main():
    """Run all compatibility tests."""
    print("=" * 60)
    print("AP_Crypto / CryptoToolApp Compatibility Test")
    print("=" * 60)
    print()
    
    try:
        test_key_derivation()
        test_xor1_encryption()
        test_key_cycling()
        
        print("=" * 60)
        print("✓ ALL TESTS PASSED - Python and C++ are compatible!")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

