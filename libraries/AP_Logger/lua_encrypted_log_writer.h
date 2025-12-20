#pragma once

#include <AP_Crypto/AP_Crypto.h>

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>

// Streaming XOR-encrypted log writer
class LuaEncryptedLogWriter {
public:
    bool init(const char *filename);
    bool write(const uint8_t *data, size_t len);
    bool finalize();
    void cleanup();
    
private:
    AP_Crypto::StreamingEncrypt ctx;
    int fd;
    bool initialized;
};

#endif  // AP_CRYPTO_ENABLED

