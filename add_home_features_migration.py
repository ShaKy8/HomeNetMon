#!/usr/bin/env python3
"""
Database migration to add home-friendly features:
- room_location: Room assignment for devices  
- device_priority: Priority level (critical, important, normal, optional)
"""

import sqlite3
import sys
import os

def run_migration():
    """Add room_location and device_priority columns to devices table"""
    
    # Database path
    db_path = 'homeNetMon.db'
    
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(devices)")
        columns = [column[1] for column in cursor.fetchall()]
        
        migrations_applied = []
        
        # Add room_location column if it doesn't exist
        if 'room_location' not in columns:
            print("Adding room_location column...")
            cursor.execute("""
                ALTER TABLE devices 
                ADD COLUMN room_location VARCHAR(100)
            """)
            migrations_applied.append('room_location')
        else:
            print("room_location column already exists")
        
        # Add device_priority column if it doesn't exist  
        if 'device_priority' not in columns:
            print("Adding device_priority column...")
            cursor.execute("""
                ALTER TABLE devices 
                ADD COLUMN device_priority VARCHAR(20) DEFAULT 'normal'
            """)
            migrations_applied.append('device_priority')
        else:
            print("device_priority column already exists")
        
        # Commit changes
        if migrations_applied:
            conn.commit()
            print(f"✅ Successfully added columns: {', '.join(migrations_applied)}")
        else:
            print("✅ No migration needed - all columns already exist")
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(devices)")
        columns_after = [column[1] for column in cursor.fetchall()]
        
        if 'room_location' in columns_after and 'device_priority' in columns_after:
            print("✅ Migration verified successfully")
            return True
        else:
            print("❌ Migration verification failed")
            return False
            
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def main():
    """Main migration function"""
    print("🏠 HomeNetMon Database Migration: Adding Home Features")
    print("=" * 60)
    
    success = run_migration()
    
    if success:
        print("\n🎉 Migration completed successfully!")
        print("You can now use room assignments and device priorities in HomeNetMon")
        sys.exit(0)
    else:
        print("\n💥 Migration failed!")
        print("Please check the error messages above and try again")
        sys.exit(1)

if __name__ == '__main__':
    main()