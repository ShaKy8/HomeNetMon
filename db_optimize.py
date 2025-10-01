#!/usr/bin/env python3
"""
Standalone Database Optimization for HomeNetMon
"""

import sqlite3
import os
import time
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_FILE = "homeNetMon.db"

def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_FILE):
        logger.error(f"Database file {DB_FILE} not found!")
        return None
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def add_critical_indexes():
    """Add critical database indexes for performance"""
    indexes_to_create = [
        # Critical composite index for monitoring data queries
        "CREATE INDEX IF NOT EXISTS idx_monitoring_device_timestamp ON monitoring_data(device_id, timestamp DESC)",
        
        # Index for timestamp-based cleanup queries  
        "CREATE INDEX IF NOT EXISTS idx_monitoring_timestamp ON monitoring_data(timestamp)",
        
        # Composite index for alert queries
        "CREATE INDEX IF NOT EXISTS idx_alerts_device_resolved_created ON alerts(device_id, resolved, created_at DESC)",
        
        # Index for performance metrics queries
        "CREATE INDEX IF NOT EXISTS idx_performance_device_timestamp ON performance_metrics(device_id, timestamp DESC)",
        
        # Index for device status queries
        "CREATE INDEX IF NOT EXISTS idx_devices_monitored_last_seen ON devices(is_monitored, last_seen DESC)",
        
        # Additional indexes for frequently accessed columns
        "CREATE INDEX IF NOT EXISTS idx_monitoring_response_time ON monitoring_data(response_time) WHERE response_time IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity_created ON alerts(severity, created_at DESC) WHERE resolved = 0"
    ]
    
    logger.info("Adding critical database indexes...")
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        for i, index_sql in enumerate(indexes_to_create, 1):
            try:
                start_time = time.time()
                conn.execute(index_sql)
                conn.commit()
                duration = time.time() - start_time
                logger.info(f"✓ Created index {i}/7 in {duration:.2f}s")
            except Exception as e:
                logger.warning(f"Index {i} may already exist: {e}")
        
        logger.info("Database indexes optimization completed!")
        return True
        
    finally:
        conn.close()

def cleanup_old_monitoring_data(retention_days=7):
    """Aggressive cleanup of old monitoring data"""
    logger.info(f"Starting aggressive data cleanup (keeping last {retention_days} days)...")
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        cutoff_str = cutoff_date.isoformat()
        
        # Get count before cleanup
        cursor = conn.execute("SELECT COUNT(*) FROM monitoring_data")
        total_records = cursor.fetchone()[0]
        
        cursor = conn.execute("SELECT COUNT(*) FROM monitoring_data WHERE timestamp < ?", (cutoff_str,))
        old_records_count = cursor.fetchone()[0]
        
        logger.info(f"Total monitoring records: {total_records:,}")
        logger.info(f"Records to delete (older than {cutoff_date}): {old_records_count:,}")
        
        if old_records_count == 0:
            logger.info("No old records to clean up")
            return True
        
        # Delete old records
        start_time = time.time()
        cursor = conn.execute("DELETE FROM monitoring_data WHERE timestamp < ?", (cutoff_str,))
        deleted_count = cursor.rowcount
        conn.commit()
        
        duration = time.time() - start_time
        logger.info(f"✓ Deleted {deleted_count:,} old monitoring records in {duration:.2f}s")
        return True
        
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
        return False
    finally:
        conn.close()

def cleanup_old_performance_metrics(retention_days=7):
    """Clean up old performance metrics"""
    logger.info("Cleaning up old performance metrics...")
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        # Check if table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='performance_metrics'")
        if not cursor.fetchone():
            logger.info("Performance metrics table doesn't exist, skipping...")
            return True
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        cutoff_str = cutoff_date.isoformat()
        
        cursor = conn.execute("SELECT COUNT(*) FROM performance_metrics WHERE timestamp < ?", (cutoff_str,))
        old_metrics_count = cursor.fetchone()[0]
        
        if old_metrics_count > 0:
            cursor = conn.execute("DELETE FROM performance_metrics WHERE timestamp < ?", (cutoff_str,))
            deleted = cursor.rowcount
            conn.commit()
            logger.info(f"✓ Deleted {deleted:,} old performance metrics")
        else:
            logger.info("No old performance metrics to clean")
            
        return True
        
    except Exception as e:
        logger.warning(f"Performance metrics cleanup failed: {e}")
        return False
    finally:
        conn.close()

def cleanup_resolved_alerts(retention_days=30):
    """Clean up old resolved alerts"""
    logger.info("Cleaning up old resolved alerts...")
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        cutoff_str = cutoff_date.isoformat()
        
        cursor = conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved = 1 AND resolved_at < ?", (cutoff_str,))
        old_alerts_count = cursor.fetchone()[0]
        
        if old_alerts_count > 0:
            cursor = conn.execute("DELETE FROM alerts WHERE resolved = 1 AND resolved_at < ?", (cutoff_str,))
            deleted = cursor.rowcount
            conn.commit()
            logger.info(f"✓ Deleted {deleted:,} old resolved alerts")
        else:
            logger.info("No old resolved alerts to clean")
            
        return True
        
    except Exception as e:
        logger.warning(f"Resolved alerts cleanup failed: {e}")
        return False
    finally:
        conn.close()

def vacuum_database():
    """Vacuum the database to reclaim space"""
    logger.info("Running database VACUUM to reclaim space...")
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        start_time = time.time()
        conn.execute("VACUUM")
        duration = time.time() - start_time
        logger.info(f"✓ Database VACUUM completed in {duration:.2f}s")
        return True
        
    except Exception as e:
        logger.error(f"VACUUM failed: {e}")
        return False
    finally:
        conn.close()

def analyze_database():
    """Analyze database statistics"""
    logger.info("Analyzing database statistics...")
    
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        # Get table sizes
        stats_queries = [
            ("Devices", "SELECT COUNT(*) FROM devices"),
            ("Monitoring Data", "SELECT COUNT(*) FROM monitoring_data"),
            ("Alerts", "SELECT COUNT(*) FROM alerts"),
            ("Active Alerts", "SELECT COUNT(*) FROM alerts WHERE resolved = 0"),
        ]
        
        # Check if performance_metrics table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='performance_metrics'")
        if cursor.fetchone():
            stats_queries.append(("Performance Metrics", "SELECT COUNT(*) FROM performance_metrics"))
        
        for table_name, query in stats_queries:
            try:
                cursor = conn.execute(query)
                result = cursor.fetchone()[0]
                logger.info(f"{table_name}: {result:,} records")
            except Exception as e:
                logger.warning(f"Could not get {table_name} count: {e}")
        
        # Get database file size
        if os.path.exists(DB_FILE):
            size_mb = os.path.getsize(DB_FILE) / (1024 * 1024)
            logger.info(f"Database file size: {size_mb:.1f} MB")
            
    except Exception as e:
        logger.error(f"Database analysis failed: {e}")
    finally:
        conn.close()

def main():
    """Main optimization routine"""
    logger.info("=== HomeNetMon Database Performance Optimization ===")
    
    if not os.path.exists(DB_FILE):
        logger.error(f"Database file {DB_FILE} not found!")
        return 1
    
    try:
        # Show initial stats
        logger.info("BEFORE optimization:")
        analyze_database()
        
        # Phase 1: Add indexes
        if not add_critical_indexes():
            logger.error("Index creation failed")
            return 1
        
        # Phase 2: Data cleanup
        cleanup_old_monitoring_data(retention_days=7)  # Aggressive: keep only 7 days
        cleanup_old_performance_metrics(retention_days=7)
        cleanup_resolved_alerts(retention_days=30)  # Keep resolved alerts for 30 days
        
        # Phase 3: Vacuum database
        if not vacuum_database():
            logger.warning("Database vacuum failed, but continuing...")
        
        # Show final stats
        logger.info("\nAFTER optimization:")
        analyze_database()
        
        logger.info("=== Database optimization completed successfully! ===")
        return 0
        
    except Exception as e:
        logger.error(f"Optimization failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())