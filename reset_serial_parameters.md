# Resetting Serial Port Parameters to Fix COM Port Access Issues

## Problem
"Access to COM4 is denied" - This is often caused by invalid serial port configuration parameters that prevent proper communication.

## Solution 1: Switch Vehicle Types (Quick Fix)
As mentioned in user groups, switching vehicle types forces a parameter reset:

1. **Flash ArduCopter firmware** to your board
   - This will reset all parameters to defaults
   - The format version change triggers parameter erasure

2. **Flash ArduPlane firmware** back
   - Parameters are reset again to Plane defaults
   - Serial port settings should now be correct

## Solution 2: Reset Parameters via Parameter File
If you can access the board via another method (USB, different serial port):

1. Create a parameter file with these critical serial parameters reset:
   ```
   SERIAL0_PROTOCOL,2
   SERIAL0_BAUD,115
   SERIAL0_OPTIONS,0
   SERIAL1_PROTOCOL,2
   SERIAL1_BAUD,57
   SERIAL1_OPTIONS,0
   SERIAL2_PROTOCOL,2
   SERIAL2_BAUD,57
   SERIAL2_OPTIONS,0
   BRD_SER2_RTSCTS,0
   ```

2. Load this parameter file via Mission Planner or another method

## Solution 3: Critical Serial Parameters to Check

If you can connect via Mission Planner (even briefly), check these parameters:

### Serial 0 (USB Console - COM4)
- **SERIAL0_PROTOCOL**: Should be `2` (MAVLink2)
- **SERIAL0_BAUD**: Should be `115` (115200 baud) or `57` (57600 baud)
- **SERIAL0_OPTIONS**: Should be `0` (no special options)

### Serial 1 (Telemetry 1)
- **SERIAL1_PROTOCOL**: Should be `2` (MAVLink2) or `1` (MAVLink1)
- **SERIAL1_BAUD**: Should be `57` (57600) or `115` (115200)
- **SERIAL1_OPTIONS**: Should be `0`

### Serial 2 (Telemetry 2)
- **SERIAL2_PROTOCOL**: Should be `2` (MAVLink2) or `1` (MAVLink1) or `0` (None)
- **SERIAL2_BAUD**: Should be `57` (57600) or `115` (115200)
- **SERIAL2_OPTIONS**: Should be `0`
- **BRD_SER2_RTSCTS**: Should be `0` (Disabled)

## Common Invalid Values That Cause Problems

1. **SERIAL0_PROTOCOL set to non-MAVLink value** (e.g., 22 for SLCAN)
   - This prevents Mission Planner from connecting
   - The code has a safety check that should prevent this, but old saved values might persist

2. **SERIAL0_BAUD set to unsupported value**
   - Some boards don't support all baud rates
   - Very high baud rates (>1.5MBaud) may not work on all hardware

3. **SERIAL0_OPTIONS with problematic bits set**
   - Bit 10: "Don't forward mavlink to/from" - This would break communication!
   - Other bits might cause issues depending on hardware

4. **BRD_SER2_RTSCTS set to Auto (2) or Enabled (1) without proper hardware**
   - Can cause communication failures if RTS/CTS pins aren't connected

## Solution 4: Use CLI (Command Line Interface)
If you can access the CLI via another serial port or USB:

```
# Reset Serial 0 to safe defaults
set SERIAL0_PROTOCOL 2
set SERIAL0_BAUD 115
set SERIAL0_OPTIONS 0

# Reset Serial 1
set SERIAL1_PROTOCOL 2
set SERIAL1_BAUD 57
set SERIAL1_OPTIONS 0

# Reset Serial 2
set SERIAL2_PROTOCOL 2
set SERIAL2_BAUD 57
set SERIAL2_OPTIONS 0
set BRD_SER2_RTSCTS 0

# Save parameters
save
```

## Prevention: Code Safety Checks

The code already has some safety checks:
- `AP_SerialManager::init()` forces SERIAL0_PROTOCOL to MAVLink if it's set to something else
- But this only works if the code runs, which requires the board to boot properly

## Why Vehicle Type Switching Works

When you flash a different vehicle type:
1. The firmware format version changes
2. `AP_Vehicle::load_parameters()` detects the version mismatch
3. It calls `StorageManager::erase()` and `AP_Param::erase_all()`
4. All parameters are reset to defaults
5. Serial port parameters return to safe values

This is why switching from Plane → Copter → Plane fixes the issue.

