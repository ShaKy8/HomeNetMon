#!/usr/bin/env python3

import sys
import os
sys.path.append('/home/kyle/ClaudeCode/HomeNetMon')

# Set environment variables
os.environ['NETWORK_RANGE'] = '192.168.86.0/24'
os.environ['DEBUG'] = 'true'

from flask import Flask
from models import db, Device, init_db
from config import Config
from monitoring.scanner import NetworkScanner

def reclassify_all_devices():
    """Reclassify all existing devices with new detection logic"""
    
    # Create Flask app context
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db(app)
    
    with app.app_context():
        scanner = NetworkScanner(app)
        
        devices = Device.query.all()
        updated_count = 0
        
        print(f"Reclassifying {len(devices)} devices...")
        
        for device in devices:
            device_info = {
                'hostname': device.hostname,
                'vendor': device.vendor,
                'ip': device.ip_address,
                'mac': device.mac_address
            }
            
            old_type = device.device_type
            new_type = scanner.classify_device_type(device_info)
            
            if old_type != new_type:
                device.device_type = new_type
                updated_count += 1
                print(f"Updated {device.ip_address} ({device.display_name}): {old_type} -> {new_type}")
        
        if updated_count > 0:
            db.session.commit()
            print(f"Successfully updated {updated_count} device classifications")
        else:
            print("No device classifications needed updating")
            
        # Show summary of device types
        type_counts = {}
        for device in Device.query.all():
            device_type = device.device_type or 'unknown'
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        
        print("\nDevice Type Summary:")
        for device_type, count in sorted(type_counts.items()):
            print(f"  {device_type}: {count} devices")

if __name__ == '__main__':
    reclassify_all_devices()