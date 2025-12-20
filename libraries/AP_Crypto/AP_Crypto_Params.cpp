#include "AP_Crypto_Params.h"

#if AP_CRYPTO_ENABLED

#include <AP_Crypto/AP_Crypto.h>
#include <AP_HAL/AP_HAL.h>

extern const AP_HAL::HAL& hal;

AP_Crypto_Params::AP_Crypto_Params(void)
{
    AP_Param::setup_object_defaults(this, var_info);
}

const struct AP_Param::GroupInfo AP_Crypto_Params::var_info[] = {
    // @Param: LEIGH_KEY
    // @DisplayName: Encryption Key
    // @Description: Encryption key for AP_Crypto (write-only for security, reads as 0)
    // @User: Advanced
    // @Range: -2147483648 2147483647
    AP_GROUPINFO("LEIGH_KEY", 1, AP_Crypto_Params, _key_param, 0),
    
    AP_GROUPEND
};

void AP_Crypto_Params::handle_key_set(int32_t key_value)
{
    if (key_value == 0) {
        return;  // Ignore zero values
    }
    
    // Derive 32-byte key from INT32 value
    uint8_t key[32];
    
    // Simple key derivation: repeat the INT32 bytes
    uint32_t uval = (uint32_t)key_value;
    for (int i = 0; i < 32; i++) {
        key[i] = ((uint8_t*)&uval)[i % 4] ^ (i * 0x73);
    }
    
    // Store the derived key
    AP_Crypto::store_key(key);
}

#endif  // AP_CRYPTO_ENABLED

