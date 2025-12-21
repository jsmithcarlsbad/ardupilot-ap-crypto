#!/bin/bash
#
# Flash script for CubeOrangePlus board
# Builds and uploads the latest firmware to the board
#

set -e  # Exit on error

BOARD="CubeOrangePlus"
TARGET="plane"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "wscript" ] || [ ! -d "libraries" ]; then
    print_error "This script must be run from the ArduPilot root directory"
    exit 1
fi

# Parse command line arguments
CLEAN_BUILD=false
UPLOAD_ONLY=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --upload-only)
            UPLOAD_ONLY=true
            SKIP_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean        Clean build before compiling"
            echo "  --upload-only  Skip build, only upload existing firmware"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "This script will:"
            echo "  1. Build the firmware for CubeOrangePlus"
            echo "  2. Upload it to the connected board"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Step 1: Clean build if requested
if [ "$CLEAN_BUILD" = true ] && [ "$SKIP_BUILD" = false ]; then
    print_info "Cleaning build directory..."
    ./waf clean
fi

# Step 2: Configure and build
if [ "$SKIP_BUILD" = false ]; then
    print_info "Configuring build for $BOARD..."
    ./waf configure --board $BOARD
    
    print_info "Building $TARGET firmware..."
    ./waf $TARGET
    
    if [ $? -ne 0 ]; then
        print_error "Build failed!"
        exit 1
    fi
    
    print_info "Build completed successfully!"
else
    print_info "Skipping build (--upload-only mode)"
fi

# Step 3: Find the firmware file
FIRMWARE_APJ="build/${BOARD}/bin/ardu${TARGET}.apj"
FIRMWARE_BIN="build/${BOARD}/bin/ardu${TARGET}.bin"

if [ ! -f "$FIRMWARE_APJ" ] && [ ! -f "$FIRMWARE_BIN" ]; then
    print_error "Firmware file not found!"
    print_error "Expected: $FIRMWARE_APJ or $FIRMWARE_BIN"
    exit 1
fi

# Step 4: Check permissions
print_info "Checking USB permissions..."

# Check if user is in dialout group
if ! groups | grep -q dialout; then
    print_warn "User is not in 'dialout' group. This may cause permission errors."
    print_warn "To fix, run: sudo usermod -a -G dialout $USER"
    print_warn "Then log out and back in, or run: newgrp dialout"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Aborted. Please fix permissions first."
        exit 1
    fi
fi

# Step 5: Upload firmware
print_info "Preparing to upload firmware..."

# Check if uploader.py exists
UPLOADER_SCRIPT="Tools/scripts/uploader.py"
if [ ! -f "$UPLOADER_SCRIPT" ]; then
    print_error "Uploader script not found: $UPLOADER_SCRIPT"
    exit 1
fi

# Try to find the board
print_info "Looking for $BOARD board..."

# Check for USB device
USB_DEVICE=""
if [ -d "/dev/serial/by-id" ]; then
    # Look for CubePilot devices
    USB_DEVICE=$(find /dev/serial/by-id -name "*CubePilot*" -o -name "*Cube*" 2>/dev/null | head -1)
    if [ -n "$USB_DEVICE" ]; then
        print_info "Found USB device: $USB_DEVICE"
    fi
fi

# Try using waf --upload first (simplest method)
print_info "Attempting upload using waf --upload..."
if ./waf $TARGET --upload 2>&1 | tee /tmp/waf_upload.log; then
    print_info "Upload completed successfully!"
    exit 0
else
    # Check if it was a permission error
    if grep -q "Permission denied\|Errno 13" /tmp/waf_upload.log 2>/dev/null; then
        print_error "Permission denied accessing USB port!"
        print_error ""
        print_error "To fix this, run:"
        print_error "  sudo usermod -a -G dialout $USER"
        print_error "Then either:"
        print_error "  - Log out and back in, OR"
        print_error "  - Run: newgrp dialout"
        print_error ""
        print_warn "Alternatively, you can use sudo (not recommended):"
        print_warn "  sudo ./waf $TARGET --upload"
    fi
fi

# If waf --upload failed, try using uploader.py
print_warn "waf --upload failed, trying uploader.py..."

# Determine which firmware file to use
if [ -f "$FIRMWARE_APJ" ]; then
    FIRMWARE_FILE="$FIRMWARE_APJ"
    print_info "Using APJ firmware: $FIRMWARE_FILE"
elif [ -f "$FIRMWARE_BIN" ]; then
    FIRMWARE_FILE="$FIRMWARE_BIN"
    print_warn "Using BIN firmware (APJ preferred): $FIRMWARE_FILE"
fi

# Try uploader.py with auto-detection
print_info "Attempting upload with uploader.py (auto-detect port)..."
if python3 "$UPLOADER_SCRIPT" "$FIRMWARE_FILE" 2>&1; then
    print_info "Upload completed successfully!"
    exit 0
fi

# If auto-detect failed and we found a USB device, try with specific port
if [ -n "$USB_DEVICE" ]; then
    print_info "Attempting upload with specific port: $USB_DEVICE"
    if python3 "$UPLOADER_SCRIPT" --port "$USB_DEVICE" "$FIRMWARE_FILE" 2>&1; then
        print_info "Upload completed successfully!"
        exit 0
    fi
fi

# Last resort: try common ports
print_warn "Auto-detection failed. Trying common ports..."
for PORT in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyUSB0 /dev/ttyUSB1; do
    if [ -e "$PORT" ]; then
        print_info "Trying port: $PORT"
        if python3 "$UPLOADER_SCRIPT" --port "$PORT" "$FIRMWARE_FILE" 2>&1; then
            print_info "Upload completed successfully on $PORT!"
            exit 0
        fi
    fi
done

# If all methods failed
print_error "All upload methods failed!"
print_error ""
print_error "Troubleshooting steps:"
print_error "1. Make sure the board is connected via USB"
print_error "2. Put the board into bootloader mode:"
print_error "   - Hold the boot button while powering on, OR"
print_error "   - Use Mission Planner to enter bootloader mode"
print_error "3. Check USB permissions:"
print_error "   sudo usermod -a -G dialout \$USER"
print_error "   (then log out and back in)"
print_error "4. Try manual upload:"
print_error "   python3 $UPLOADER_SCRIPT $FIRMWARE_FILE"
print_error ""
print_error "Firmware location: $FIRMWARE_FILE"

exit 1

