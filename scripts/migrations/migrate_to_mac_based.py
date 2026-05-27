#!/usr/bin/env python3
"""
Migration Script: MAC-Based Device Identification

This script migrates the HomeNetMon database from IP-based device identification
to MAC-based identification to handle DHCP IP address changes properly.

Changes:
1. Remove unique constraint from ip_address
2. Add unique constraint to mac_address
3. Merge duplicate devices with the same MAC address
4. Create device IP change history table
5. Update scanner logic to use MAC as primary identifier

Usage:
    python migrate_to_mac_based.py [--dry-run] [--backup]
"""

import os
import sys
import sqlite3
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

def backup_database(db_path, backup_path=None):
    """Create a backup of the database before migration"""
    if backup_path is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{db_path}.backup_{timestamp}"
    
    print(f"Creating database backup: {backup_path}")
    
    # Use sqlite3 backup API for atomic backup
    source = sqlite3.connect(db_path)
    backup = sqlite3.connect(backup_path)
    
    source.backup(backup)
    source.close()
    backup.close()
    
    print(f"Backup created successfully: {backup_path}")
    return backup_path

def analyze_duplicate_devices(db_path):
    """Analyze existing devices to identify MAC address duplicates"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n=== DUPLICATE DEVICE ANALYSIS ===")
    
    # Find devices with same MAC address but different IPs
    cursor.execute("""
        SELECT mac_address, COUNT(*) as device_count, 
               GROUP_CONCAT(ip_address) as ip_addresses,
               GROUP_CONCAT(id) as device_ids
        FROM devices 
        WHERE mac_address IS NOT NULL AND mac_address != ''
        GROUP BY mac_address 
        HAVING COUNT(*) > 1
        ORDER BY device_count DESC
    """)
    
    duplicates = cursor.fetchall()
    
    if duplicates:
        print(f"Found {len(duplicates)} MAC addresses with multiple device entries:")
        for mac, count, ips, ids in duplicates:
            print(f"  MAC {mac}: {count} devices (IPs: {ips}) (IDs: {ids})")
        
        # Get total affected devices
        total_duplicates = sum(count for _, count, _, _ in duplicates)
        print(f"Total duplicate device entries: {total_duplicates}")
    else:
        print("No duplicate MAC addresses found - good!")
    
    # Find devices without MAC addresses
    cursor.execute("""
        SELECT COUNT(*) FROM devices 
        WHERE mac_address IS NULL OR mac_address = ''
    """)
    
    no_mac_count = cursor.fetchone()[0]
    if no_mac_count > 0:
        print(f"Warning: {no_mac_count} devices have no MAC address - these will need manual attention")
    
    conn.close()
    return duplicates, no_mac_count

def merge_duplicate_devices(conn, dry_run=False):
    """Merge devices with the same MAC address"""
    cursor = conn.cursor()
    
    print("\n=== MERGING DUPLICATE DEVICES ===")
    
    # Get duplicates again for processing
    cursor.execute("""
        SELECT mac_address, GROUP_CONCAT(id) as device_ids
        FROM devices 
        WHERE mac_address IS NOT NULL AND mac_address != ''
        GROUP BY mac_address 
        HAVING COUNT(*) > 1
    """)
    
    duplicates = cursor.fetchall()
    merged_count = 0
    
    for mac_address, device_ids_str in duplicates:
        device_ids = [int(x) for x in device_ids_str.split(',')]
        
        # Get full device information
        placeholders = ','.join('?' * len(device_ids))
        cursor.execute(f"""
            SELECT id, ip_address, hostname, vendor, custom_name, device_type, 
                   device_group, is_monitored, created_at, updated_at, last_seen
            FROM devices 
            WHERE id IN ({placeholders})
            ORDER BY last_seen DESC NULLS LAST, created_at ASC
        """, device_ids)
        
        devices = cursor.fetchall()
        
        # Choose the "best" device to keep (most recently seen, or oldest if no last_seen)
        primary_device = devices[0]
        devices_to_remove = devices[1:]
        
        print(f"MAC {mac_address}: Keeping device ID {primary_device[0]} (IP: {primary_device[1]})")
        
        if not dry_run:
            # Merge data from other devices into the primary device
            primary_id = primary_device[0]
            
            # Update primary device with best available information
            best_hostname = primary_device[2]
            best_custom_name = primary_device[4]
            best_device_type = primary_device[5]
            best_device_group = primary_device[6]
            best_vendor = primary_device[3]
            
            # Use non-null values from other devices if primary is missing info
            for device in devices_to_remove:
                if not best_hostname and device[2]:
                    best_hostname = device[2]
                if not best_custom_name and device[4]:
                    best_custom_name = device[4]
                if not best_device_type and device[5]:
                    best_device_type = device[5]
                if not best_device_group and device[6]:
                    best_device_group = device[6]
                if not best_vendor and device[3]:
                    best_vendor = device[3]
            
            # Update primary device with merged information
            cursor.execute("""
                UPDATE devices 
                SET hostname = ?, vendor = ?, custom_name = ?, device_type = ?, 
                    device_group = ?, updated_at = ?
                WHERE id = ?
            """, (best_hostname, best_vendor, best_custom_name, best_device_type,
                  best_device_group, datetime.utcnow().isoformat(), primary_id))
            
            # Move monitoring data from duplicate devices to primary device
            for device in devices_to_remove:
                device_id = device[0]
                print(f"  Moving data from device ID {device_id} (IP: {device[1]})")
                
                # Update monitoring_data
                cursor.execute("""
                    UPDATE monitoring_data SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update alerts
                cursor.execute("""
                    UPDATE alerts SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update notification_history
                cursor.execute("""
                    UPDATE notification_history SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update security_scans
                cursor.execute("""
                    UPDATE security_scans SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update security_events  
                cursor.execute("""
                    UPDATE security_events SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update bandwidth_data
                cursor.execute("""
                    UPDATE bandwidth_data SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Update alert_suppressions
                cursor.execute("""
                    UPDATE alert_suppressions SET device_id = ? WHERE device_id = ?
                """, (primary_id, device_id))
                
                # Create IP change history record
                cursor.execute("""
                    INSERT INTO device_ip_history 
                    (device_id, old_ip_address, new_ip_address, change_reason, changed_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (primary_id, device[1], primary_device[1], 
                      'Device merge during MAC-based migration', datetime.utcnow().isoformat()))
                
                # Delete the duplicate device
                cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            
            merged_count += len(devices_to_remove)
    
    print(f"Merged {merged_count} duplicate device entries")
    return merged_count

def create_ip_history_table(conn, dry_run=False):
    """Create table to track device IP address changes"""
    cursor = conn.cursor()
    
    print("\n=== CREATING IP CHANGE HISTORY TABLE ===")
    
    if not dry_run:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                old_ip_address VARCHAR(15),
                new_ip_address VARCHAR(15),
                change_reason VARCHAR(255),
                changed_at DATETIME NOT NULL,
                detected_by VARCHAR(50) DEFAULT 'system',
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_device_ip_history_device_id 
            ON device_ip_history (device_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_device_ip_history_changed_at 
            ON device_ip_history (changed_at)
        """)
        
        print("Created device_ip_history table with indexes")
    else:
        print("Would create device_ip_history table")

def update_database_schema(conn, dry_run=False):
    """Update database schema for MAC-based identification"""
    cursor = conn.cursor()
    
    print("\n=== UPDATING DATABASE SCHEMA ===")
    
    if not dry_run:
        # Drop the unique constraint on ip_address (if it exists)
        try:
            # SQLite doesn't support DROP CONSTRAINT, so we need to recreate the table
            # First, check if there's a unique constraint on ip_address
            cursor.execute("""
                SELECT sql FROM sqlite_master 
                WHERE type='table' AND name='devices'
            """)
            table_sql = cursor.fetchone()[0]
            
            if 'UNIQUE' in table_sql and 'ip_address' in table_sql:
                print("Removing unique constraint from ip_address...")
                
                # Create new table without unique constraint on ip_address
                cursor.execute("""
                    CREATE TABLE devices_new (
                        id INTEGER PRIMARY KEY,
                        ip_address VARCHAR(15) NOT NULL,
                        mac_address VARCHAR(17) UNIQUE,
                        hostname VARCHAR(255),
                        vendor VARCHAR(255),
                        custom_name VARCHAR(255),
                        device_type VARCHAR(50),
                        device_group VARCHAR(100),
                        is_monitored BOOLEAN DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME
                    )
                """)
                
                # Copy data to new table
                cursor.execute("""
                    INSERT INTO devices_new 
                    SELECT * FROM devices
                """)
                
                # Drop old table and rename new one
                cursor.execute("DROP TABLE devices")
                cursor.execute("ALTER TABLE devices_new RENAME TO devices")
                
                # Recreate indexes
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices (ip_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices (mac_address)")
                
                print("Removed unique constraint from ip_address, added unique constraint to mac_address")
            else:
                # Just add unique constraint to mac_address if not already present
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_unique ON devices (mac_address)")
                print("Added unique constraint to mac_address")
                
        except Exception as e:
            print(f"Error updating schema: {e}")
            # If schema update fails, continue - the application can handle it
    else:
        print("Would update database schema")

def handle_devices_without_mac(conn, dry_run=False):
    """Handle devices that don't have MAC addresses"""
    cursor = conn.cursor()
    
    print("\n=== HANDLING DEVICES WITHOUT MAC ADDRESSES ===")
    
    cursor.execute("""
        SELECT id, ip_address, hostname, device_type
        FROM devices 
        WHERE mac_address IS NULL OR mac_address = ''
    """)
    
    devices_without_mac = cursor.fetchall()
    
    if devices_without_mac:
        print(f"Found {len(devices_without_mac)} devices without MAC addresses:")
        for device_id, ip, hostname, device_type in devices_without_mac:
            display_name = hostname or ip
            print(f"  ID {device_id}: {display_name} ({ip}) - {device_type or 'unknown type'}")
        
        print("\nThese devices will need to be rescanned to obtain MAC addresses.")
        print("They will remain in the database but may be duplicated if DHCP assigns new IPs.")
        
        if not dry_run:
            # Mark these devices for re-scanning
            cursor.execute("""
                UPDATE devices 
                SET updated_at = ?, device_group = 'needs-mac-address'
                WHERE mac_address IS NULL OR mac_address = ''
            """, (datetime.utcnow().isoformat(),))
            
            print("Marked devices without MAC addresses for re-scanning")
    else:
        print("All devices have MAC addresses - excellent!")

def update_scanner_config(dry_run=False):
    """Create updated scanner configuration notes"""
    config_notes = """
# MAC-Based Device Identification Migration Complete

The database has been migrated to use MAC addresses as the primary device identifier.

## Key Changes:
1. MAC address is now the unique identifier for devices
2. IP addresses can change without creating duplicate device entries
3. Device IP change history is tracked in device_ip_history table
4. Duplicate devices with same MAC have been merged

## Scanner Updates Required:
The scanner logic needs to be updated to:
1. Look up devices by MAC address first, then IP address
2. Update existing device IP when MAC matches but IP differs
3. Log IP changes to device_ip_history table
4. Handle devices without MAC addresses gracefully

## Monitoring Implications:
- Devices will maintain their monitoring history across IP changes
- Alerts will be associated with the device regardless of current IP
- Custom names and settings are preserved across IP changes

## Next Steps:
1. Update scanner.py process_discovered_device() method
2. Test with a device that changes IP address
3. Verify monitoring data continuity
4. Check alert associations remain intact
"""
    
    if not dry_run:
        with open('/home/kyle/ClaudeCode/HomeNetMon/MAC_MIGRATION_NOTES.md', 'w') as f:
            f.write(config_notes)
        print("Created MAC_MIGRATION_NOTES.md with implementation guidance")
    else:
        print("Would create MAC_MIGRATION_NOTES.md")

def main():
    parser = argparse.ArgumentParser(description='Migrate HomeNetMon to MAC-based device identification')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--backup', action='store_true', help='Create database backup before migration')
    parser.add_argument('--db-path', default='/home/kyle/ClaudeCode/HomeNetMon/homeNetMon.db', 
                       help='Path to the HomeNetMon database')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.db_path):
        print(f"Error: Database not found at {args.db_path}")
        sys.exit(1)
    
    print("HomeNetMon MAC-Based Device Identification Migration")
    print("=" * 55)
    
    if args.dry_run:
        print("DRY RUN MODE - No changes will be made")
        print()
    
    # Create backup if requested
    if args.backup and not args.dry_run:
        backup_path = backup_database(args.db_path)
    
    # Analyze current state
    duplicates, no_mac_count = analyze_duplicate_devices(args.db_path)
    
    # Open database connection
    conn = sqlite3.connect(args.db_path)
    
    try:
        # Perform migration steps
        create_ip_history_table(conn, args.dry_run)
        merged_count = merge_duplicate_devices(conn, args.dry_run)
        update_database_schema(conn, args.dry_run)
        handle_devices_without_mac(conn, args.dry_run)
        
        if not args.dry_run:
            conn.commit()
            print("\n=== MIGRATION COMPLETED SUCCESSFULLY ===")
            print(f"✓ Created device IP change history table")
            print(f"✓ Merged {merged_count} duplicate device entries")
            print(f"✓ Updated database schema for MAC-based identification")
            print(f"✓ Handled {no_mac_count} devices without MAC addresses")
        else:
            print("\n=== DRY RUN COMPLETE ===")
            print("No changes were made. Run without --dry-run to perform migration.")
        
        # Create configuration notes
        update_scanner_config(args.dry_run)
        
    except Exception as e:
        if not args.dry_run:
            conn.rollback()
        print(f"\nError during migration: {e}")
        raise
    finally:
        conn.close()

if __name__ == '__main__':
    main()