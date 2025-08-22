#!/usr/bin/env python3
"""
Database migration script to add notification columns to alerts table
"""
import sqlite3
import os

def migrate_database():
    db_path = 'homeNetMon.db'
    
    # Also check instance directory
    if not os.path.exists(db_path):
        db_path = 'instance/homeNetMon.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    print(f"Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Add notification columns to alerts table
        print("Adding notification_sent column...")
        cursor.execute("ALTER TABLE alerts ADD COLUMN notification_sent BOOLEAN DEFAULT 0")
        
        print("Adding notification_count column...")
        cursor.execute("ALTER TABLE alerts ADD COLUMN notification_count INTEGER DEFAULT 0")
        
        print("Adding last_notification_at column...")
        cursor.execute("ALTER TABLE alerts ADD COLUMN last_notification_at DATETIME")
        
        print("Adding notification_status column...")
        cursor.execute("ALTER TABLE alerts ADD COLUMN notification_status VARCHAR(20) DEFAULT 'pending'")
        
        conn.commit()
        print("Migration completed successfully!")
        return True
        
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Columns already exist - migration not needed")
            return True
        else:
            print(f"Migration failed: {e}")
            return False
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()