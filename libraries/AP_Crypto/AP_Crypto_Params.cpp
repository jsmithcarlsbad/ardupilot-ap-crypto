#include "AP_Crypto_Params.h"

#if AP_CRYPTO_ENABLED

#include <AP_Crypto/AP_Crypto.h>
#include <AP_HAL/AP_HAL.h>
#include <AP_Param/AP_Param.h>
#include <StorageManager/StorageManager.h>

extern const AP_HAL::HAL& hal;

AP_Crypto_Params::AP_Crypto_Params(void)
{
    AP_Param::setup_object_defaults(this, var_info);
}

const struct AP_Param::GroupInfo AP_Crypto_Params::var_info[] = {
    // @Param: LEIGH_CRYPT_KEY
    // @DisplayName: Encryption Key
    // @Description: Encryption key for AP_Crypto (write-only for security, reads as 0)
    // @User: Advanced
    // @Range: -2147483648 2147483647
    AP_GROUPINFO("LEIGH_CRYPT_KEY", 1, AP_Crypto_Params, _key_param, 0),
    
    // @Param: LEIGH_CRYPT_LVL
    // @DisplayName: Encryption Level
    // @Description: Encryption level for Lua scripts and logs (0=disabled/no encryption, 1=enabled). Defaults to 0 (no encryption).
    // @User: Advanced
    // @Values: 0:Disabled,1:Enabled
    AP_GROUPINFO("LEIGH_CRYPT_LVL", 2, AP_Crypto_Params, _crypto_enable, 0),
    
    AP_GROUPEND
};

void AP_Crypto_Params::handle_key_set(int32_t key_value)
{
    if (key_value == 0) {
        return;  // Ignore zero values
    }
    
    // Safety checks: don't access storage if it has failed or isn't ready
    // This prevents blocking or crashes during MAVLink parameter handling
    if (StorageManager::storage_failed()) {
        return;  // Storage not available, skip key storage
    }
    
    // Derive 32-byte key from INT32 value
    uint8_t key[32];
    
    // Simple key derivation: repeat the INT32 bytes
    uint32_t uval = (uint32_t)key_value;
    for (int i = 0; i < 32; i++) {
        key[i] = ((uint8_t*)&uval)[i % 4] ^ (i * 0x73);
    }
    
    // Store the derived key
    // Note: store_key() has its own safety checks and will return false
    // if storage isn't ready. We ignore the return value to avoid blocking
    // MAVLink communication if storage write fails.
    (void)AP_Crypto::store_key(key);
}

bool AP_Crypto_Params::is_encryption_enabled(void)
{
    // Safety check: don't access parameters if system not initialized
    if (!AP_Param::initialised()) {
        return false;  // Default to disabled if param system not ready
    }
    
    enum ap_var_type ptype;
    AP_Int8 *crypto_enable = (AP_Int8*)AP_Param::find("LEIGH_CRYPT_LVL", &ptype);
    if (crypto_enable != nullptr) {
        return crypto_enable->get() != 0;
    }
    // Default to disabled if parameter not found
    return false;
}

#endif  // AP_CRYPTO_ENABLED

