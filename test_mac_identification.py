#!/usr/bin/env python3
"""
Test script for MAC-based device identification

This script tests the new MAC-based device identification system by simulating
a device that changes IP addresses but keeps the same MAC address.
"""

import os
import sys
import time
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

# Set environment variables for Flask app
os.environ['FLASK_ENV'] = 'development'
os.environ['DEBUG'] = 'true'
os.environ['NETWORK_RANGE'] = '192.168.86.0/24'

from app import create_app
from models import db, Device
from monitoring.scanner import NetworkScanner

def test_mac_based_identification():
    """Test MAC-based device identification with IP changes"""
    
    print("Testing MAC-Based Device Identification")
    print("=" * 45)
    
    # Create Flask app and get application context
    app, socketio = create_app()
    
    with app.app_context():
        # Create scanner instance
        scanner = NetworkScanner(app)
        
        # Test device info - simulating the same device with different IPs
        test_mac = "aa:bb:cc:dd:ee:ff"
        test_device_name = "test-device.lan"
        
        print(f"Test MAC Address: {test_mac}")
        print(f"Test Device Name: {test_device_name}")
        print()
        
        # Step 1: Initial device discovery with first IP
        print("Step 1: Initial device discovery")
        initial_device_info = {
            'ip': '192.168.86.100',
            'mac': test_mac,
            'hostname': test_device_name,
            'source': 'test'
        }
        
        print(f"  Discovering device: {initial_device_info['ip']} (MAC: {test_mac})")
        scanner.process_discovered_device(initial_device_info)
        
        # Check if device was created
        device = Device.query.filter_by(mac_address=test_mac).first()
        if device:
            print(f"  ✓ Device created: ID {device.id}, IP {device.ip_address}")
            initial_device_id = device.id
        else:
            print("  ✗ Device not created!")
            return False
        
        print()
        
        # Step 2: Same device with new IP (DHCP change simulation)
        print("Step 2: DHCP IP address change simulation")
        changed_device_info = {
            'ip': '192.168.86.101',  # Different IP
            'mac': test_mac,         # Same MAC
            'hostname': test_device_name,
            'source': 'test'
        }
        
        print(f"  Device reconnects with new IP: {changed_device_info['ip']} (same MAC: {test_mac})")
        scanner.process_discovered_device(changed_device_info)
        
        # Check if IP was updated (should be same device)
        device_after_change = Device.query.filter_by(mac_address=test_mac).first()
        if device_after_change:
            print(f"  ✓ Device updated: ID {device_after_change.id}, IP {device_after_change.ip_address}")
            
            if device_after_change.id == initial_device_id:
                print("  ✓ Same device record maintained (no duplicate created)")
            else:
                print("  ✗ Different device record - duplication occurred!")
                return False
                
            if device_after_change.ip_address == changed_device_info['ip']:
                print("  ✓ IP address updated successfully")
            else:
                print("  ✗ IP address not updated!")
                return False
        else:
            print("  ✗ Device not found after IP change!")
            return False
        
        print()
        
        # Step 3: Check IP change history
        print("Step 3: Verify IP change history")
        
        # Query IP change history
        history = db.session.execute(db.text("""
            SELECT old_ip_address, new_ip_address, change_reason, detected_by
            FROM device_ip_history 
            WHERE device_id = :device_id
            ORDER BY changed_at DESC
        """), {'device_id': device_after_change.id}).fetchall()
        
        if history:
            print(f"  ✓ Found {len(history)} IP change record(s):")
            for record in history:
                print(f"    {record[0]} → {record[1]} ({record[2]}, detected by: {record[3]})")
        else:
            print("  ✗ No IP change history found!")
            return False
        
        print()
        
        # Step 4: Check device count (should not have increased)
        print("Step 4: Verify no duplicate devices created")
        
        total_devices = Device.query.count()
        test_devices = Device.query.filter_by(mac_address=test_mac).count()
        
        print(f"  Total devices in database: {total_devices}")
        print(f"  Test devices with MAC {test_mac}: {test_devices}")
        
        if test_devices == 1:
            print("  ✓ No duplicate devices created")
        else:
            print(f"  ✗ Found {test_devices} devices with same MAC - duplicates exist!")
            return False
        
        print()
        
        # Cleanup: Remove test device
        print("Cleanup: Removing test device")
        
        device_id = device_after_change.id
        
        # Clean up related records first to avoid foreign key issues
        db.session.execute(db.text("""
            DELETE FROM device_ip_history WHERE device_id = :device_id
        """), {'device_id': device_id})
        
        db.session.execute(db.text("""
            DELETE FROM monitoring_data WHERE device_id = :device_id
        """), {'device_id': device_id})
        
        db.session.execute(db.text("""
            DELETE FROM bandwidth_data WHERE device_id = :device_id
        """), {'device_id': device_id})
        
        db.session.execute(db.text("""
            DELETE FROM alerts WHERE device_id = :device_id
        """), {'device_id': device_id})
        
        # Now delete the device
        db.session.delete(device_after_change)
        db.session.commit()
        print("  ✓ Test device and all related data removed")
        
        print()
        print("=" * 45)
        print("✓ MAC-Based Device Identification Test PASSED")
        print("✓ DHCP IP address changes are handled correctly")
        print("✓ Device history and settings are preserved")
        print("✓ No duplicate devices are created")
        
        return True

def test_device_without_mac():
    """Test handling of devices without MAC addresses"""
    
    print("\nTesting Device Without MAC Address")
    print("=" * 35)
    
    app, socketio = create_app()
    
    with app.app_context():
        scanner = NetworkScanner(app)
        
        # Test device without MAC
        device_info = {
            'ip': '192.168.86.102',
            'mac': None,  # No MAC address
            'hostname': 'no-mac-device.lan',
            'source': 'test'
        }
        
        print(f"  Testing device without MAC: {device_info['ip']}")
        scanner.process_discovered_device(device_info)
        
        # Check if device was created
        device = Device.query.filter_by(ip_address=device_info['ip']).first()
        if device:
            print(f"  ✓ Device created: ID {device.id}, IP {device.ip_address}")
            print(f"  ✓ MAC address: {device.mac_address or 'None (as expected)'}")
            
            # Cleanup
            db.session.delete(device)
            db.session.commit()
            print("  ✓ Test device removed")
            
            return True
        else:
            print("  ✗ Device without MAC not created!")
            return False

if __name__ == '__main__':
    print("HomeNetMon MAC-Based Device Identification Tests")
    print("=" * 50)
    
    success = True
    
    try:
        # Test 1: MAC-based identification with IP changes
        if not test_mac_based_identification():
            success = False
        
        # Test 2: Device without MAC address
        if not test_device_without_mac():
            success = False
            
    except Exception as e:
        print(f"\nTest failed with exception: {e}")
        import traceback
        traceback.print_exc()
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 ALL TESTS PASSED! MAC-based identification is working correctly.")
    else:
        print("❌ SOME TESTS FAILED! Please check the implementation.")
    print("=" * 50)