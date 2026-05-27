#!/usr/bin/env python3
"""
Fix unique constraint issue - remove unique constraint from ip_address
"""

import sqlite3
import os

def fix_unique_constraint(db_path='homeNetMon.db'):
    """Remove unique constraint from ip_address column"""
    
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return False
    
    print("Fixing unique constraint on ip_address...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check current constraints
        print("Current indexes:")
        indexes = cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='devices'").fetchall()
        for idx in indexes:
            if idx[0]:
                print(f"  {idx[0]}")
        
        # Drop the unique index on ip_address
        cursor.execute("DROP INDEX IF EXISTS ix_devices_ip_address")
        print("Dropped unique index on ip_address")
        
        # Create non-unique index for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices (ip_address)")
        print("Created non-unique index on ip_address")
        
        conn.commit()
        
        # Verify changes
        print("\nIndexes after fix:")
        indexes = cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='devices'").fetchall()
        for idx in indexes:
            if idx[0]:
                print(f"  {idx[0]}")
        
        print("\n✓ Unique constraint fix completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error fixing constraint: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    fix_unique_constraint()