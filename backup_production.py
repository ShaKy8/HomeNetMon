#!/usr/bin/env python3
"""
Automated backup system for HomeNetMon production
Creates database backups with retention policy
"""

import os
import shutil
import sqlite3
import gzip
from datetime import datetime, timedelta
from pathlib import Path

def create_backup():
    """Create compressed database backup"""

    # Configuration
    db_path = Path("/opt/homenetmon/data/homeNetMon.db")
    backup_dir = Path("/opt/homenetmon/backups")
    retention_days = 30

    # Create backup directory
    backup_dir.mkdir(exist_ok=True)

    # Create backup filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"homeNetMon_backup_{timestamp}.db"
    compressed_file = backup_dir / f"homeNetMon_backup_{timestamp}.db.gz"

    try:
        # Create database backup
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_file) as backup:
                source.backup(backup)

        # Compress backup
        with open(backup_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Remove uncompressed backup
        backup_file.unlink()

        print(f"✅ Backup created: {compressed_file}")

        # Cleanup old backups
        cleanup_old_backups(backup_dir, retention_days)

        return True

    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def cleanup_old_backups(backup_dir, retention_days):
    """Remove backups older than retention period"""
    cutoff_date = datetime.now() - timedelta(days=retention_days)

    for backup_file in backup_dir.glob("homeNetMon_backup_*.db.gz"):
        if backup_file.stat().st_mtime < cutoff_date.timestamp():
            backup_file.unlink()
            print(f"🗑️ Removed old backup: {backup_file.name}")

if __name__ == "__main__":
    create_backup()
