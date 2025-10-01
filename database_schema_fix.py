#!/usr/bin/env python3
"""
Database schema fix for device_ip_history table
Adds missing columns to match what the scanner code expects
"""

import sqlite3
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def fix_device_ip_history_schema():
    """Fix the device_ip_history table schema to match expected columns"""
    db_path = os.path.join(os.path.dirname(__file__), 'homeNetMon.db')
    
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        return False
    
    print(f"Connecting to database: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check current schema
        cursor.execute("PRAGMA table_info(device_ip_history)")
        columns = cursor.fetchall()
        current_columns = [col[1] for col in columns]
        
        print(f"Current columns: {current_columns}")
        
        # Check which columns we need to add
        required_columns = {
            'change_reason': 'VARCHAR(255)',
            'changed_at': 'DATETIME',  # Remove NOT NULL for initial creation
            'detected_by': 'VARCHAR(50) DEFAULT "system"'
        }
        
        columns_to_add = []
        for col_name, col_def in required_columns.items():
            if col_name not in current_columns:
                columns_to_add.append((col_name, col_def))
        
        if not columns_to_add:
            print("✓ All required columns already exist")
            return True
        
        print(f"Adding missing columns: {[col[0] for col in columns_to_add]}")
        
        # Add missing columns
        for col_name, col_def in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE device_ip_history ADD COLUMN {col_name} {col_def}")
                print(f"✓ Added column: {col_name}")
            except sqlite3.Error as e:
                print(f"✗ Failed to add column {col_name}: {e}")
                return False
        
        # Migrate data from old columns to new columns if they exist
        if 'change_detected_at' in current_columns:
            cursor.execute("UPDATE device_ip_history SET changed_at = change_detected_at WHERE changed_at IS NULL")
            print("✓ Migrated change_detected_at to changed_at")
        
        if 'change_source' in current_columns:
            cursor.execute("UPDATE device_ip_history SET detected_by = change_source WHERE detected_by IS NULL OR detected_by = ''")
            print("✓ Migrated change_source to detected_by")
        
        # Set default values for NULL columns
        cursor.execute("UPDATE device_ip_history SET change_reason = 'Legacy record' WHERE change_reason IS NULL")
        cursor.execute("UPDATE device_ip_history SET changed_at = change_detected_at WHERE changed_at IS NULL")
        cursor.execute("UPDATE device_ip_history SET detected_by = COALESCE(change_source, 'system') WHERE detected_by IS NULL OR detected_by = ''")
        print("✓ Set default values for existing records")
        
        conn.commit()
        print("✓ Database schema updated successfully")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing database schema: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = fix_device_ip_history_schema()
    sys.exit(0 if success else 1)