# Debugging MAVLink Connection Failure

## Current Status
- Vehicle type switching (Plane → Copter → Plane) did NOT fix the issue
- COM4 access denied error persists
- This suggests either:
  1. Hardware/driver issue
  2. Code bug preventing MAVLink initialization
  3. Parameter corruption that persists across vehicle type changes
  4. Crypto code interfering with initialization

## Diagnostic Steps

### Step 1: Test if Board is Booting
1. Connect via USB
2. Open Device Manager → Ports (COM & LPT)
3. Check if COM4 appears and has no warning icons
4. If COM4 doesn't appear, the board isn't being recognized (driver issue)

### Step 2: Test Raw Serial Communication
Use a serial terminal (PuTTY, Tera Term, or the diagnostic script):

```bash
# On Windows, use PuTTY or similar
# Connect to COM4 at 115200 baud, 8N1
# You should see boot messages if the board is working
```

If you see boot messages but no MAVLink, the issue is in MAVLink initialization.

### Step 3: Test with Diagnostic Script
Run the diagnostic script (if you have Python/pymavlink):

```bash
python3 diagnose_connection.py COM4 115200
```

This will test:
- Serial port accessibility
- MAVLink heartbeat reception
- Multiple baud rates

### Step 4: Check if Crypto Code is the Issue
Temporarily disable crypto to test:

1. Edit `libraries/AP_Crypto/AP_Crypto_config.h`:
   ```cpp
   #define AP_CRYPTO_ENABLED 0  // Temporarily disable
   ```

2. Rebuild and flash
3. Test connection

If this fixes it, the crypto code is interfering.

### Step 5: Check Serial Port Parameters
Even after vehicle type switch, check these parameters if you can connect briefly:

- `SERIAL0_PROTOCOL` should be `2` (MAVLink2)
- `SERIAL0_BAUD` should be `115` (115200) or `57` (57600)
- `SERIAL0_OPTIONS` should be `0`
- `BRD_SER2_RTSCTS` should be `0`

### Step 6: Check for Boot Messages
If you can see boot messages via serial terminal:
- Look for "ArduPilot Ready" message
- Check for any error messages
- Look for "Bad parameter table" errors
- Check if MAVLink channels are being initialized

### Step 7: Hardware Test
1. Try a different USB cable
2. Try a different USB port
3. Try a different computer
4. Check if the board boots (LEDs, etc.)

## Potential Code Issues

### Issue 1: Crypto Parameter Access During Init
The `is_encryption_enabled()` function is called from:
- `lua_encrypted_reader.cpp` - when loading Lua scripts
- `lua_encrypted_log_writer.cpp` - when initializing log writer

If these are called too early, they might cause issues. However, we added a safety check for `AP_Param::initialised()`.

### Issue 2: Parameter Table Corruption
If the parameter table is corrupted, switching vehicle types might not fully reset it. Try:
1. Complete parameter wipe via CLI (if accessible)
2. Or use a parameter file to force reset

### Issue 3: Serial Port Initialization Order
The serial ports are initialized in `AP_SerialManager::init()`, which is called from `AP_Vehicle::setup()`. If something fails here, MAVLink won't work.

## Quick Test: Disable Crypto Temporarily

To rule out crypto code as the cause:

1. **Disable in config:**
   ```cpp
   // libraries/AP_Crypto/AP_Crypto_config.h
   #define AP_CRYPTO_ENABLED 0
   ```

2. **Rebuild and flash**

3. **Test connection**

If this works, we know the crypto code is the issue and need to fix it.

## Alternative: Use Different Connection Method

If USB/Serial0 isn't working:
- Try Serial1 or Serial2 if available
- Use WiFi telemetry if configured
- Use Bluetooth if available
- Use TCP/IP if supported

## Next Steps

1. **First**: Test with crypto disabled to rule it out
2. **Second**: Check if board is booting (serial terminal)
3. **Third**: Use diagnostic script to test MAVLink
4. **Fourth**: Check hardware (cable, port, drivers)

