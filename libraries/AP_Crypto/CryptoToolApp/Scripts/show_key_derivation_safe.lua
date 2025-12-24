--[[
Safe Lua script to display LEIGH_KEY and key derivation inputs.
This version has extensive error handling to prevent breaking the Lua system.
]]

local MAV_SEVERITY = {EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFO=6, DEBUG=7}

-- Safely convert number to hex
local function hex2(n)
    local ok, result = pcall(function()
        return string.format("%02x", n & 0xFF)
    end)
    if ok then
        return result
    else
        return "??"
    end
end

-- Safely convert bytes to hex
local function tohex(bytes)
    local ok, result = pcall(function()
        if not bytes or #bytes == 0 then
            return ""
        end
        local s = {}
        for i = 1, #bytes do
            s[i] = hex2(bytes[i])
        end
        return table.concat(s, "")
    end)
    if ok then
        return result
    else
        return "ERROR"
    end
end

-- Safely convert INT32 to bytes
local function int32_bytes(v)
    local ok, result = pcall(function()
        if not v then
            return {}
        end
        -- Handle as signed 32-bit integer
        local val = math.floor(v + 0.5)
        if val >= 2147483648 then
            val = val - 4294967296
        end
        return {
            (val >> 0) & 0xFF,
            (val >> 8) & 0xFF,
            (val >> 16) & 0xFF,
            (val >> 24) & 0xFF
        }
    end)
    if ok then
        return result
    else
        return {0, 0, 0, 0}
    end
end

-- Main function with full error handling
local function main()
    local success, err = pcall(function()
        -- Get parameter
        local p = Parameter()
        if not p then
            gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: No Parameter object")
            return
        end
        
        if not p:init("LEIGH_KEY") then
            gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: LEIGH_KEY not found")
            return
        end
        
        local key_val_float = p:get()
        if not key_val_float then
            gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: Could not get LEIGH_KEY value")
            return
        end
        
        local key_val = math.floor(key_val_float + 0.5)
        
        -- Salt bytes
        local salt = {0x4c,0x45,0x49,0x47,0x48,0x5f,0x4b,0x45,0x59,0x5f,0x53,0x41,0x4c,0x54,0x5f,0x31}
        
        -- Convert to bytes
        local seed = int32_bytes(key_val)
        if #seed ~= 4 then
            gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: Seed conversion failed")
            return
        end
        
        -- Build input
        local inp = {}
        for i = 1, 4 do
            inp[i] = seed[i]
        end
        for i = 1, 16 do
            inp[i + 4] = salt[i]
        end
        
        -- Send messages
        gcs:send_text(MAV_SEVERITY.WARNING, "DERIV: KEY=" .. tostring(key_val))
        gcs:send_text(MAV_SEVERITY.INFO, "DERIV: SEED=" .. tohex(seed))
        gcs:send_text(MAV_SEVERITY.INFO, "DERIV: SALT=" .. tohex(salt))
        gcs:send_text(MAV_SEVERITY.INFO, "DERIV: INPUT=" .. tohex(inp))
    end)
    
    if not success then
        gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: Script error: " .. tostring(err))
    end
end

-- Run with error handling
local ok, err = pcall(main)
if not ok then
    -- Last resort error message
    gcs:send_text(MAV_SEVERITY.ERROR, "DERIV: Fatal error")
end

-- Return nil to exit (don't schedule updates)
return nil

