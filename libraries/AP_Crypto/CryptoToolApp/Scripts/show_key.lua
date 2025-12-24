-- Display LEIGH_KEY and LEIGH_CRYPTO_LEVEL parameter values once per second in warning color
-- Safe version with full error handling to prevent boot failures

local MAV_SEVERITY = {EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFO=6, DEBUG=7}

-- Safely initialize parameters with error handling
local leigh_key_param = nil
local leigh_key_ok = false
local leigh_crypto_level_param = nil
local crypto_level_ok = false

local success, err = pcall(function()
    leigh_key_param = Parameter()
    if leigh_key_param:init("LEIGH_KEY") then
        leigh_key_ok = true
    end
end)

if not success then
    -- Parameter initialization failed, continue without it
    leigh_key_ok = false
end

success, err = pcall(function()
    leigh_crypto_level_param = Parameter()
    if leigh_crypto_level_param:init("LEIGH_CRYPTO_LEVEL") then
        crypto_level_ok = true
    end
end)

if not success then
    -- Parameter initialization failed, continue without it
    crypto_level_ok = false
end

-- If neither parameter exists, exit gracefully without error
if not leigh_key_ok and not crypto_level_ok then
    return
end

function update()
    -- Wrap everything in error handling to prevent fatal errors
    local success, err = pcall(function()
        -- Build message with available parameters
        local msg_parts = {}
        
        if leigh_key_ok and leigh_key_param then
            local leigh_key_value = leigh_key_param:get()
            if leigh_key_value then
                local key_int = math.floor(leigh_key_value + 0.5)
                table.insert(msg_parts, string.format("LEIGH_KEY: %d", key_int))
                
                -- Calculate derivation info
                local b0 = key_int % 256
                local b1 = math.floor(key_int / 256) % 256
                local b2 = math.floor(key_int / 65536) % 256
                local b3 = math.floor(key_int / 16777216) % 256
                local seed_hex = string.format("%02x%02x%02x%02x", b0, b1, b2, b3)
                local salt_hex = "4c454947485f4b45595f53414c545f31"
                local input_hex = seed_hex .. salt_hex
                
                -- Send derivation info as separate messages
                gcs:send_text(MAV_SEVERITY.INFO, string.format("SEED=%s", seed_hex))
                gcs:send_text(MAV_SEVERITY.INFO, string.format("SALT=%s", salt_hex))
                gcs:send_text(MAV_SEVERITY.INFO, string.format("INPUT=%s", input_hex))
            end
        end
        
        if crypto_level_ok and leigh_crypto_level_param then
            local crypto_level_value = leigh_crypto_level_param:get()
            if crypto_level_value then
                table.insert(msg_parts, string.format("CRYPTO_LEVEL: %d", crypto_level_value))
            end
        end
        
        if #msg_parts > 0 then
            -- Send message in warning color (yellow/orange)
            gcs:send_text(MAV_SEVERITY.WARNING, table.concat(msg_parts, ", "))
        end
    end)
    
    if not success then
        -- Error occurred, but don't crash - just skip this update
        -- Optionally log error (but don't spam)
    end
    
    -- Reschedule to run again in 1000ms (1 second)
    return update, 1000
end

-- Start the update loop with error handling
success, err = pcall(function()
    return update()
end)

if not success then
    -- If initial call fails, exit silently
    return
end

