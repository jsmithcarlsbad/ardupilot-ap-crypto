#pragma once

#include "AP_Crypto_config.h"

#if AP_CRYPTO_ENABLED

#include <AP_Param/AP_Param.h>
#include <stdint.h>

/*
  AP_Crypto_Params - Parameter-based key management for AP_Crypto
  
  Provides LEIGH_KEY parameter for setting encryption key via MAVLink
*/
class AP_Crypto_Params : public AP_Param
{
public:
    AP_Crypto_Params(void);
    
    static const struct AP_Param::GroupInfo var_info[];
    
    // Handle key setting from parameter
    static void handle_key_set(int32_t key_value);
    
private:
    AP_Int32 _key_param;  // LEIGH_KEY parameter (write-only, reads as 0)
};

#endif  // AP_CRYPTO_ENABLED

