#!/bin/bash
#
# Fix USB serial port permissions for ArduPilot development
#

set -e

USER_NAME=$(whoami)

echo "=========================================="
echo "USB Serial Port Permission Fix"
echo "=========================================="
echo ""

# Check if already in dialout group
if groups | grep -q dialout; then
    echo "✓ User '$USER_NAME' is already in 'dialout' group"
    echo ""
    echo "If you still have permission issues, try:"
    echo "  1. Log out and back in"
    echo "  2. Or run: newgrp dialout"
    exit 0
fi

echo "User '$USER_NAME' is NOT in 'dialout' group"
echo ""
echo "This script will add you to the 'dialout' group, which allows"
echo "access to USB serial ports (needed for flashing firmware)."
echo ""

read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Adding user to dialout group..."
if sudo usermod -a -G dialout "$USER_NAME"; then
    echo "✓ Successfully added to dialout group!"
    echo ""
    echo "IMPORTANT: You need to apply the group change by either:"
    echo ""
    echo "  Option 1 (Recommended): Log out and back in"
    echo ""
    echo "  Option 2: Run this command in your current shell:"
    echo "    newgrp dialout"
    echo ""
    echo "After that, you should be able to access USB serial ports."
else
    echo "✗ Failed to add user to dialout group"
    echo "You may need to run this script with sudo privileges"
    exit 1
fi


