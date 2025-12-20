#pragma once

#include <AP_HAL/AP_HAL_Boards.h>

#ifndef AP_CRYPTO_ENABLED
#define AP_CRYPTO_ENABLED 1
#endif

// Simple XOR-based encryption
// Note: XOR encryption provides basic obfuscation but is NOT cryptographically secure
// File format: [Header:4 bytes "XOR1"][XOR-encrypted data]

