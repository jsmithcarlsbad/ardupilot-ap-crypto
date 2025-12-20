#include "AP_Crypto.h"

#if AP_CRYPTO_ENABLED

#include <AP_HAL/AP_HAL.h>
#include <StorageManager/StorageManager.h>
#include <string.h>

#if defined(HAVE_MONOCYPHER) && defined(AP_CHECK_FIRMWARE_ENABLED)
#include <AP_CheckFirmware/monocypher.h>
#endif

extern const AP_HAL::HAL& hal;

// Key storage using StorageManager
#define CRYPTO_KEY_STORAGE_OFFSET 0  // Offset within StorageKeys area
static StorageAccess _crypto_storage(StorageManager::StorageKeys);

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

bool AP_Crypto::generate_key(uint8_t key_out[32])
{
    if (key_out == nullptr) {
        return false;
    }
    
    // Use HAL random number generator
    if (!hal.util->get_random_vals(key_out, 32)) {
        return false;
    }
    
    return true;
}

bool AP_Crypto::streaming_encrypt_init_xor(StreamingEncrypt *ctx, const uint8_t raw_key[32])
{
    if (ctx == nullptr || raw_key == nullptr) {
        return false;
    }
    
    memcpy(ctx->key, raw_key, 32);
    ctx->bytes_encrypted = 0;
    ctx->initialized = true;
    
    return true;
}

bool AP_Crypto::streaming_encrypt_write_header_xor(StreamingEncrypt *ctx, int fd)
{
    if (ctx == nullptr || !ctx->initialized || fd < 0) {
        return false;
    }
    
    const uint8_t header[4] = {'X', 'O', 'R', '1'};
    ssize_t written = AP::FS().write(fd, header, 4);
    
    return (written == 4);
}

ssize_t AP_Crypto::streaming_encrypt_write_xor(StreamingEncrypt *ctx, int fd,
                                               const uint8_t *plaintext, size_t plaintext_len)
{
    if (ctx == nullptr || !ctx->initialized || fd < 0 || plaintext == nullptr) {
        return -1;
    }
    
    // Encrypt in place (we'll use a temporary buffer)
    uint8_t encrypted[256];
    size_t total_written = 0;
    
    for (size_t offset = 0; offset < plaintext_len; offset += 256) {
        size_t chunk_len = (plaintext_len - offset > 256) ? 256 : (plaintext_len - offset);
        
        // XOR encrypt chunk
        for (size_t i = 0; i < chunk_len; i++) {
            size_t key_idx = (ctx->bytes_encrypted + i) % 32;
            encrypted[i] = plaintext[offset + i] ^ ctx->key[key_idx];
        }
        
        // Write encrypted chunk
        ssize_t written = AP::FS().write(fd, encrypted, chunk_len);
        if (written < 0 || (size_t)written != chunk_len) {
            return -1;
        }
        
        ctx->bytes_encrypted += chunk_len;
        total_written += written;
    }
    
    return total_written;
}

bool AP_Crypto::streaming_encrypt_finalize_xor(StreamingEncrypt *ctx, int fd)
{
    if (ctx == nullptr || !ctx->initialized || fd < 0) {
        return false;
    }
    
    // Sync file
    AP::FS().fsync(fd);
    
    return true;
}

void AP_Crypto::streaming_encrypt_cleanup(StreamingEncrypt *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    
    memset(ctx->key, 0, 32);
    ctx->bytes_encrypted = 0;
    ctx->initialized = false;
}

bool AP_Crypto::streaming_decrypt_init_xor(StreamingDecrypt *ctx, const uint8_t raw_key[32], int fd)
{
    if (ctx == nullptr || raw_key == nullptr || fd < 0) {
        return false;
    }
    
    // Read and verify header
    uint8_t header[4];
    ssize_t read_bytes = AP::FS().read(fd, header, 4);
    if (read_bytes != 4) {
        return false;
    }
    
    if (memcmp(header, "XOR1", 4) != 0) {
        return false;
    }
    
    memcpy(ctx->key, raw_key, 32);
    ctx->bytes_decrypted = 0;
    ctx->initialized = true;
    
    return true;
}

ssize_t AP_Crypto::streaming_decrypt_read_xor(StreamingDecrypt *ctx, int fd,
                                             uint8_t *plaintext, size_t plaintext_max)
{
    if (ctx == nullptr || !ctx->initialized || fd < 0 || plaintext == nullptr) {
        return -1;
    }
    
    // Read encrypted chunk
    uint8_t encrypted[256];
    size_t read_len = (plaintext_max > 256) ? 256 : plaintext_max;
    ssize_t read_bytes = AP::FS().read(fd, encrypted, read_len);
    
    if (read_bytes <= 0) {
        return read_bytes;
    }
    
    // XOR decrypt
    for (ssize_t i = 0; i < read_bytes; i++) {
        size_t key_idx = (ctx->bytes_decrypted + i) % 32;
        plaintext[i] = encrypted[i] ^ ctx->key[key_idx];
    }
    
    ctx->bytes_decrypted += read_bytes;
    
    return read_bytes;
}

bool AP_Crypto::streaming_decrypt_finalize_xor(StreamingDecrypt *ctx, int fd)
{
    if (ctx == nullptr || !ctx->initialized || fd < 0) {
        return false;
    }
    
    // Nothing special needed for XOR
    return true;
}

void AP_Crypto::streaming_decrypt_cleanup(StreamingDecrypt *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    
    memset(ctx->key, 0, 32);
    ctx->bytes_decrypted = 0;
    ctx->initialized = false;
}

bool AP_Crypto::streaming_encrypt_init_xor_from_params(StreamingEncrypt *ctx)
{
    if (ctx == nullptr) {
        return false;
    }
    
    uint8_t key[32];
    
    // Try to get key from storage or derive from board
    if (!retrieve_key(key)) {
        if (!derive_key_from_board_id(key)) {
            return false;
        }
    }
    
    return streaming_encrypt_init_xor(ctx, key);
}

bool AP_Crypto::streaming_decrypt_init_xor_from_params(StreamingDecrypt *ctx, int fd)
{
    if (ctx == nullptr || fd < 0) {
        return false;
    }
    
    uint8_t key[32];
    
    // Try to get key from storage or derive from board
    if (!retrieve_key(key)) {
        if (!derive_key_from_board_id(key)) {
            return false;
        }
    }
    
    return streaming_decrypt_init_xor(ctx, key, fd);
}

bool AP_Crypto::store_key(const uint8_t key[32])
{
    if (key == nullptr) {
        return false;
    }
    
    // Store key at offset 0 in StorageKeys area
    return _crypto_storage.write_block(CRYPTO_KEY_STORAGE_OFFSET, key, 32);
}

bool AP_Crypto::retrieve_key(uint8_t key[32])
{
    if (key == nullptr) {
        return false;
    }
    
    // Read key from offset 0 in StorageKeys area
    return _crypto_storage.read_block(key, CRYPTO_KEY_STORAGE_OFFSET, 32);
}

bool AP_Crypto::has_stored_key(void)
{
    uint8_t key[32];
    return retrieve_key(key);
}

bool AP_Crypto::generate_and_store_key(uint8_t key[32])
{
    uint8_t new_key[32];
    
    if (!generate_key(new_key)) {
        return false;
    }
    
    if (!store_key(new_key)) {
        return false;
    }
    
    if (key != nullptr) {
        memcpy(key, new_key, 32);
    }
    
    return true;
}

bool AP_Crypto::derive_key_from_board_id(uint8_t key[32])
{
    if (key == nullptr) {
        return false;
    }
    
    // Simple key derivation from board ID
    // Get board ID (system ID)
    uint8_t board_id[12];
    uint8_t board_id_len = sizeof(board_id);
    if (!hal.util->get_system_id_unformatted(board_id, board_id_len)) {
        // Fallback: use a hardcoded key if board ID not available
        memset(key, 0x42, 32);
        return true;
    }
    
    // Simple hash-based key derivation
    // Use BLAKE2b if available, otherwise simple hash
    #if defined(HAVE_MONOCYPHER) && defined(AP_CHECK_FIRMWARE_ENABLED)
    uint8_t salt[16] = "ArduPilotCrypto";
    crypto_blake2b(key, 32, board_id, board_id_len, salt, sizeof(salt));
    #else
    // Simple hash: XOR board ID bytes and repeat
    for (int i = 0; i < 32; i++) {
        key[i] = board_id[i % board_id_len] ^ (i * 0x37);
    }
    #endif
    
    return true;
}

#endif  // AP_CRYPTO_ENABLED

