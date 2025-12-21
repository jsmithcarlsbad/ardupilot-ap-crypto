#include "lua_encrypted_log_writer.h"

#if AP_CRYPTO_ENABLED

#include <AP_Crypto/AP_Crypto.h>
#include <AP_Crypto/AP_Crypto_Params.h>
#include <AP_Filesystem/AP_Filesystem.h>

bool LuaEncryptedLogWriter::init(const char *filename)
{
    if (filename == nullptr) {
        return false;
    }
    
    // Check if encryption is enabled
    if (!AP_Crypto_Params::is_encryption_enabled()) {
        return false;  // Encryption disabled, don't initialize encrypted writer
    }
    
    // Open file
    fd = AP::FS().open(filename, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        return false;
    }
    
    // Initialize encryption context
    if (!AP_Crypto::streaming_encrypt_init_xor_from_params(&ctx)) {
        AP::FS().close(fd);
        fd = -1;
        return false;
    }
    
    // Write header
    if (!AP_Crypto::streaming_encrypt_write_header_xor(&ctx, fd)) {
        AP_Crypto::streaming_encrypt_cleanup(&ctx);
        AP::FS().close(fd);
        fd = -1;
        return false;
    }
    
    initialized = true;
    return true;
}

bool LuaEncryptedLogWriter::write(const uint8_t *data, size_t len)
{
    if (!initialized || fd < 0 || data == nullptr) {
        return false;
    }
    
    ssize_t written = AP_Crypto::streaming_encrypt_write_xor(&ctx, fd, data, len);
    return (written == (ssize_t)len);
}

bool LuaEncryptedLogWriter::finalize()
{
    if (!initialized || fd < 0) {
        return false;
    }
    
    bool result = AP_Crypto::streaming_encrypt_finalize_xor(&ctx, fd);
    AP::FS().close(fd);
    fd = -1;
    initialized = false;
    
    return result;
}

void LuaEncryptedLogWriter::cleanup()
{
    if (initialized) {
        AP_Crypto::streaming_encrypt_cleanup(&ctx);
        if (fd >= 0) {
            AP::FS().close(fd);
            fd = -1;
        }
        initialized = false;
    }
}

#endif  // AP_CRYPTO_ENABLED

