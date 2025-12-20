#pragma once

#include <AP_Crypto/AP_Crypto.h>

#if AP_CRYPTO_ENABLED

#include <stdint.h>
#include <stddef.h>

// Read and decrypt encrypted Lua file
// Returns decrypted content or nullptr on error
uint8_t* lua_read_encrypted_file(const char *filename, size_t *out_len);

#endif  // AP_CRYPTO_ENABLED

