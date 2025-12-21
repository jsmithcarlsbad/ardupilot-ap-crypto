# Fixing Windows COM Port Access Denied Error

## Problem
Mission Planner reports: "Access to COM4 is denied"

## Common Causes and Solutions

### 1. Another Program is Using COM4
**Check:**
- Close all other programs that might use COM4 (other instances of Mission Planner, QGroundControl, PuTTY, terminal emulators, etc.)
- Check Windows Device Manager → Ports (COM & LPT) → Right-click COM4 → Properties → See if "This device is in use"

**Solution:**
- Close all programs using COM4
- Unplug and replug the USB cable
- Restart Mission Planner

### 2. Mission Planner Needs Administrator Rights
**Solution:**
- Right-click Mission Planner shortcut
- Select "Run as administrator"
- Try connecting again

### 3. COM Port Driver Issue
**Check:**
- Device Manager → Ports (COM & LPT)
- Look for COM4 - if it has a yellow warning triangle, the driver is missing or corrupted

**Solution:**
- Right-click COM4 → Update driver
- Or uninstall the device, unplug USB, replug USB (Windows will reinstall driver)

### 4. Port is Locked by Previous Session
**Solution:**
- Close Mission Planner completely
- Unplug USB cable
- Wait 10 seconds
- Plug USB cable back in
- Wait for Windows to recognize the device
- Open Mission Planner and try again

### 5. Wrong COM Port Selected
**Check:**
- Device Manager → Ports (COM & LPT) to see what COM port your device is actually on
- It might have changed (e.g., COM3, COM5, etc.)
- In Mission Planner: Right-click the connection dropdown → Refresh
- Select the correct COM port

### 6. USB Cable or Port Issue
**Solution:**
- Try a different USB cable
- Try a different USB port on your computer
- Try a USB 2.0 port instead of USB 3.0 (or vice versa)

### 7. Windows COM Port Permissions
**Solution (Advanced):**
1. Open Device Manager
2. Right-click COM4 → Properties
3. Go to "Port Settings" tab → "Advanced"
4. Check "Use FIFO buffers" and adjust buffer sizes if needed
5. Click OK and restart Mission Planner

### 8. Check if Port Exists
**Solution:**
- Open Device Manager
- If COM4 doesn't appear, the device isn't recognized
- Check if the flight controller shows up under "Other devices" or "Unknown devices"
- You may need to install drivers (STM32 Virtual COM Port driver, or CH340/CP2102 drivers depending on your board)

## Quick Diagnostic Steps

1. **Check what's using COM4:**
   ```powershell
   # Open PowerShell as Administrator
   Get-PnpDevice -Class Ports | Where-Object {$_.FriendlyName -like "*COM4*"}
   ```

2. **Check if port is accessible:**
   - Open Device Manager
   - Expand "Ports (COM & LPT)"
   - Look for your device (might be listed as "STM32 Virtual COM Port" or similar)
   - Note the COM port number

3. **Test with another program:**
   - Try connecting with PuTTY or another serial terminal
   - If that works, the issue is Mission Planner specific
   - If that also fails, it's a Windows/driver issue

## For CubeOrangePlus Specifically

The CubeOrangePlus typically uses:
- **USB Serial Port**: Usually COM3, COM4, or higher
- **Driver**: STM32 Virtual COM Port driver (should install automatically)

If the driver isn't installing:
1. Download STM32 Virtual COM Port driver from STMicroelectronics website
2. Install it manually
3. Unplug and replug the USB cable

## Alternative: Use Different Connection Method

If COM port continues to have issues:
- Try connecting via **TCP/IP** if your flight controller supports it
- Use **USB passthrough** if available
- Try **Bluetooth** or **WiFi telemetry** if configured

