#!/usr/bin/env python3
"""
Diagnostic script to test MAVLink connection and identify issues
"""
import sys
import time
import serial
from pymavlink import mavutil

def test_serial_connection(port, baud=115200, timeout=5):
    """Test basic serial port connection"""
    print(f"\n=== Testing Serial Port: {port} at {baud} baud ===")
    
    try:
        ser = serial.Serial(port, baud, timeout=timeout)
        print(f"✓ Serial port opened successfully")
        
        # Try to read any data
        print("Waiting for data (5 seconds)...")
        start_time = time.time()
        data_received = False
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)
                print(f"✓ Received {len(data)} bytes: {data[:20].hex()}")
                data_received = True
                break
            time.sleep(0.1)
        
        if not data_received:
            print("✗ No data received from device")
        
        ser.close()
        return data_received
        
    except serial.SerialException as e:
        print(f"✗ Serial port error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_mavlink_connection(port, baud=115200):
    """Test MAVLink connection"""
    print(f"\n=== Testing MAVLink Connection: {port} at {baud} baud ===")
    
    try:
        # Try different baud rates
        baud_rates = [115200, 57600, 38400, 9600]
        
        for test_baud in baud_rates:
            print(f"\nTrying {test_baud} baud...")
            try:
                master = mavutil.mavlink_connection(
                    f'{port}:{test_baud}',
                    source_system=255,
                    source_component=0,
                    timeout=3
                )
                
                print(f"  Waiting for heartbeat...")
                msg = master.recv_match(type='HEARTBEAT', timeout=3)
                if msg:
                    print(f"  ✓ Heartbeat received at {test_baud} baud!")
                    print(f"    System ID: {msg.get_srcSystem()}")
                    print(f"    Component ID: {msg.get_srcComponent()}")
                    print(f"    Type: {msg.type}")
                    print(f"    Autopilot: {msg.autopilot}")
                    print(f"    Base Mode: {msg.base_mode}")
                    
                    # Try to get more messages
                    print(f"  Waiting for more messages (5 seconds)...")
                    msg_count = 0
                    start_time = time.time()
                    while time.time() - start_time < 5:
                        msg = master.recv_match(timeout=1)
                        if msg:
                            msg_count += 1
                            print(f"    Received: {msg.get_type()}")
                    
                    print(f"  Total messages received: {msg_count}")
                    master.close()
                    return True
                else:
                    print(f"  ✗ No heartbeat at {test_baud} baud")
                    master.close()
                    
            except Exception as e:
                print(f"  ✗ Error at {test_baud} baud: {e}")
                continue
        
        return False
        
    except Exception as e:
        print(f"✗ MAVLink connection error: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 diagnose_connection.py <COM_PORT> [baud_rate]")
        print("Example: python3 diagnose_connection.py COM4 115200")
        sys.exit(1)
    
    port = sys.argv[1]
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    
    print("=" * 60)
    print("MAVLink Connection Diagnostic Tool")
    print("=" * 60)
    
    # Test 1: Basic serial connection
    serial_ok = test_serial_connection(port, baud)
    
    if serial_ok:
        # Test 2: MAVLink connection
        mavlink_ok = test_mavlink_connection(port, baud)
        
        if mavlink_ok:
            print("\n" + "=" * 60)
            print("✓ Connection test PASSED")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("✗ MAVLink connection FAILED")
            print("\nPossible issues:")
            print("  1. Board is not sending MAVLink messages")
            print("  2. Wrong baud rate")
            print("  3. Serial port configuration issue")
            print("  4. Firmware bug preventing MAVLink initialization")
            print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("✗ Serial port connection FAILED")
        print("\nPossible issues:")
        print("  1. Wrong COM port")
        print("  2. Driver not installed")
        print("  3. Port locked by another program")
        print("  4. Hardware issue")
        print("=" * 60)

if __name__ == "__main__":
    main()

