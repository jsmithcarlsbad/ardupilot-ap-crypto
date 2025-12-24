-- Display LEIGH_KEY and key derivation - working version
-- Based on show_key.lua pattern that works

local MAV_SEVERITY = {EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFO=6, DEBUG=7}

local p = Parameter()
if not p:init("LEIGH_KEY") then
    return
end

local key = math.floor(p:get() + 0.5)

-- Convert INT32 to little-endian bytes
local b0 = key % 256
local b1 = math.floor(key / 256) % 256
local b2 = math.floor(key / 65536) % 256
local b3 = math.floor(key / 16777216) % 256

local seed_hex = string.format("%02x%02x%02x%02x", b0, b1, b2, b3)
local salt_hex = "4c454947485f4b45595f53414c545f31"
local input_hex = seed_hex .. salt_hex

-- Send messages
gcs:send_text(MAV_SEVERITY.WARNING, "DERIV KEY=" .. tostring(key))
gcs:send_text(MAV_SEVERITY.INFO, "DERIV SEED=" .. seed_hex)
gcs:send_text(MAV_SEVERITY.INFO, "DERIV SALT=" .. salt_hex)
gcs:send_text(MAV_SEVERITY.INFO, "DERIV INPUT=" .. input_hex)

-- Exit (no return function = runs once and exits)
return

