#!/usr/bin/env python3
"""
Test MAVLink connection to ArduPilot board
"""
import sys
import time
import serial
from pymavlink import mavutil

def test_connection(port, baud=115200):
    """Test MAVLink connection to the specified port"""
    print(f"Attempting to connect to {port} at {baud} baud...")
    
    try:
        # Try to create MAVLink connection
        connection = mavutil.mavlink_connection(port, baud=baud, timeout=2)
        print(f"Connection object created, waiting for heartbeat...")
        
        # Wait for heartbeat (up to 10 seconds)
        start_time = time.time()
        heartbeat_received = False
        
        while time.time() - start_time < 10:
            msg = connection.recv_match(type='HEARTBEAT', blocking=True, timeout=1)
            if msg:
                print(f"✓ HEARTBEAT received!")
                print(f"  System ID: {msg.get_srcSystem()}")
                print(f"  Component ID: {msg.get_srcComponent()}")
                print(f"  Autopilot: {msg.autopilot}")
                print(f"  Base mode: {msg.base_mode}")
                print(f"  Custom mode: {msg.custom_mode}")
                heartbeat_received = True
                break
        
        if not heartbeat_received:
            print("✗ No heartbeat received within 10 seconds")
            return False
        
        # Try to request parameters
        print("\nRequesting parameter list...")
        connection.param_request_list()
        
        param_count = 0
        start_time = time.time()
        while time.time() - start_time < 5:
            msg = connection.recv_match(type=['PARAM_VALUE', 'PARAM_COUNT'], blocking=True, timeout=1)
            if msg:
                if msg.get_type() == 'PARAM_VALUE':
                    param_count += 1
                    if param_count <= 5:  # Show first 5 parameters
                        print(f"  Parameter {param_count}: {msg.param_id} = {msg.param_value}")
                elif msg.get_type() == 'PARAM_COUNT':
                    print(f"  Total parameters: {msg.param_count}")
        
        if param_count > 0:
            print(f"✓ Successfully received {param_count} parameters")
        else:
            print("✗ No parameters received")
        
        # Check for CRYPTO_LEIGH_KEY parameter
        print("\nChecking for CRYPTO_LEIGH_KEY parameter...")
        connection.param_request_read('CRYPTO_LEIGH_KEY')
        time.sleep(1)
        msg = connection.recv_match(type='PARAM_VALUE', blocking=True, timeout=2)
        if msg and msg.param_id == 'CRYPTO_LEIGH_KEY':
            print(f"✓ Found CRYPTO_LEIGH_KEY parameter (value: {msg.param_value})")
        else:
            print("✗ CRYPTO_LEIGH_KEY parameter not found or not received")
        
        print("\n✓ MAVLink connection test completed successfully!")
        return True
        
    except serial.SerialException as e:
        print(f"✗ Serial port error: {e}")
        print("  Make sure:")
        print("  1. The board is connected and powered")
        print("  2. You have permission to access the port (try: sudo usermod -a -G dialout $USER)")
        print("  3. The port is not already in use")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    # Try common ports and baud rates
    ports_to_try = ['/dev/ttyACM0', '/dev/ttyACM1']
    bauds_to_try = [57600, 115200, 921600]
    
    if len(sys.argv) > 1:
        ports_to_try = [sys.argv[1]]
    if len(sys.argv) > 2:
        bauds_to_try = [int(sys.argv[2])]
    
    success = False
    for port in ports_to_try:
        for baud in bauds_to_try:
            print(f"\n{'='*60}")
            if test_connection(port, baud):
                success = True
                break
        if success:
            break
    
    if not success:
        print(f"\n{'='*60}")
        print("✗ Could not establish MAVLink connection")
        print("\nTroubleshooting:")
        print("1. Check if the board is powered and connected")
        print("2. Verify the serial port: ls -la /dev/ttyACM*")
        print("3. Add user to dialout group: sudo usermod -a -G dialout $USER")
        print("   (then log out and back in)")
        print("4. Try different baud rates: 57600, 115200, 921600")
        sys.exit(1)
    else:
        sys.exit(0)


