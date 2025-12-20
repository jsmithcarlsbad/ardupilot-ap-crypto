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

