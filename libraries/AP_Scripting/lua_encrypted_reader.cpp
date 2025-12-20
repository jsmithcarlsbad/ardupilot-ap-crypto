#include "lua_encrypted_reader.h"

#if AP_CRYPTO_ENABLED

#include <AP_Crypto/AP_Crypto.h>
#include <AP_Filesystem/AP_Filesystem.h>
#include <AP_HAL/AP_HAL.h>
#include <sys/stat.h>

extern const AP_HAL::HAL& hal;

uint8_t* lua_read_encrypted_file(const char *filename, size_t *out_len)
{
    if (filename == nullptr || out_len == nullptr) {
        return nullptr;
    }
    
    *out_len = 0;
    
    // Open file
    int fd = AP::FS().open(filename, O_RDONLY);
    if (fd < 0) {
        return nullptr;
    }
    
    // Get file size
    struct stat st;
    if (AP::FS().stat(filename, &st) != 0) {
        AP::FS().close(fd);
        return nullptr;
    }
    
    size_t file_size = st.st_size;
    if (file_size < 4) {
        AP::FS().close(fd);
        return nullptr;
    }
    
    // Read entire file
    uint8_t *encrypted_data = (uint8_t*)hal.util->malloc_type(file_size, AP_HAL::Util::MEM_DMA_SAFE);
    if (encrypted_data == nullptr) {
        AP::FS().close(fd);
        return nullptr;
    }
    
    ssize_t read_bytes = AP::FS().read(fd, encrypted_data, file_size);
    AP::FS().close(fd);
    
    if (read_bytes != (ssize_t)file_size) {
        hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
        return nullptr;
    }
    
    // Check for "XOR1" header (new format)
    if (file_size >= 4 && memcmp(encrypted_data, "XOR1", 4) == 0) {
        // New AP_Crypto XOR format
        uint8_t key[32];
        
        // Try to get key
        if (!AP_Crypto::retrieve_key(key)) {
            if (!AP_Crypto::derive_key_from_board_id(key)) {
                hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
                return nullptr;
            }
        }
        
        // Decrypt
        size_t plaintext_len = file_size - 4;
        uint8_t *plaintext = (uint8_t*)hal.util->malloc_type(plaintext_len, AP_HAL::Util::MEM_DMA_SAFE);
        if (plaintext == nullptr) {
            hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
            return nullptr;
        }
        
        int decrypted_len = AP_Crypto::xor_decode_raw(key, encrypted_data, file_size, plaintext, plaintext_len);
        hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
        
        if (decrypted_len < 0) {
            hal.util->free_type(plaintext, plaintext_len, AP_HAL::Util::MEM_DMA_SAFE);
            return nullptr;
        }
        
        *out_len = decrypted_len;
        return plaintext;
    }
    
    // Check for old "ELUA" format (backward compatibility)
    if (file_size >= 4 && memcmp(encrypted_data, "ELUA", 4) == 0) {
        // Old format - for now, just return as-is (or implement old decryption)
        // For backward compatibility, you might want to implement old decryption
        hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
        return nullptr;  // Old format not supported in XOR-only version
    }
    
    // Not an encrypted file
    hal.util->free_type(encrypted_data, file_size, AP_HAL::Util::MEM_DMA_SAFE);
    return nullptr;
}

#endif  // AP_CRYPTO_ENABLED

