#!/usr/bin/env python3
"""
Database Performance Optimization for HomeNetMon
Adds indexes, optimizes queries, and improves database performance
"""

import sqlite3
import time
from pathlib import Path

def optimize_database(db_path='homeNetMon.db'):
    """Apply database optimizations"""
    print(f"Optimizing database: {db_path}")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Apply SQLite optimization settings
        optimizations = [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=10000",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA mmap_size=134217728",  # 128MB
            "PRAGMA optimize"
        ]

        for optimization in optimizations:
            try:
                cursor.execute(optimization)
                print(f"✅ Applied: {optimization}")
            except Exception as e:
                print(f"⚠️ Failed: {optimization} - {e}")

        # Add performance indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
            "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_monitoring_data_device_id ON monitoring_data(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_monitoring_data_timestamp ON monitoring_data(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_monitoring_data_device_timestamp ON monitoring_data(device_id, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_notification_history_timestamp ON notification_history(timestamp)",
        ]

        for index_sql in indexes:
            try:
                start_time = time.time()
                cursor.execute(index_sql)
                duration = (time.time() - start_time) * 1000
                print(f"✅ Created index: {index_sql.split()[-1]} ({duration:.1f}ms)")
            except Exception as e:
                print(f"⚠️ Index creation failed: {e}")

        # Analyze tables for query optimization
        tables = ['devices', 'monitoring_data', 'alerts', 'performance_metrics']
        for table in tables:
            try:
                cursor.execute(f"ANALYZE {table}")
                print(f"✅ Analyzed table: {table}")
            except Exception as e:
                print(f"⚠️ Analysis failed for {table}: {e}")

        conn.commit()
        conn.close()

        print("🚀 Database optimization completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Database optimization failed: {e}")
        return False

if __name__ == "__main__":
    optimize_database()
