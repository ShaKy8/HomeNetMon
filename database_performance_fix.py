#!/usr/bin/env python3
"""
Database Performance Optimization Script for HomeNetMon
Adds critical indexes and implements aggressive data cleanup
"""

import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app import app as flask_app
from models import db, Device, MonitoringData, Alert, PerformanceMetrics
from sqlalchemy import text, func
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    for i, index_sql in enumerate(indexes_to_create, 1):
        try:
            start_time = time.time()
            db.session.execute(text(index_sql))
            db.session.commit()
            duration = time.time() - start_time
            logger.info(f"✓ Created index {i}/7 in {duration:.2f}s")
        except Exception as e:
            logger.warning(f"Index {i} may already exist or failed: {e}")
            db.session.rollback()
    
    logger.info("Database indexes optimization completed!")

def cleanup_old_monitoring_data(retention_days=7):
    """Aggressive cleanup of old monitoring data"""
    logger.info(f"Starting aggressive data cleanup (keeping last {retention_days} days)...")
    
    # Calculate cutoff date
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    # Get count before cleanup
    total_records = db.session.query(func.count(MonitoringData.id)).scalar()
    old_records_query = db.session.query(func.count(MonitoringData.id)).filter(
        MonitoringData.timestamp < cutoff_date
    )
    old_records_count = old_records_query.scalar()
    
    logger.info(f"Total monitoring records: {total_records:,}")
    logger.info(f"Records to delete (older than {cutoff_date}): {old_records_count:,}")
    
    if old_records_count == 0:
        logger.info("No old records to clean up")
        return
    
    # Delete in batches to avoid locking the database
    batch_size = 10000
    total_deleted = 0
    
    while True:
        # Delete batch
        start_time = time.time()
        result = db.session.execute(
            text(f"""
                DELETE FROM monitoring_data 
                WHERE id IN (
                    SELECT id FROM monitoring_data 
                    WHERE timestamp < :cutoff_date 
                    LIMIT {batch_size}
                )
            """),
            {"cutoff_date": cutoff_date}
        )
        
        deleted_count = result.rowcount
        if deleted_count == 0:
            break
            
        total_deleted += deleted_count
        db.session.commit()
        
        duration = time.time() - start_time
        logger.info(f"Deleted {deleted_count:,} records in {duration:.2f}s (total: {total_deleted:,})")
        
        # Small delay to prevent overwhelming the database
        time.sleep(0.1)
    
    logger.info(f"✓ Cleanup completed! Deleted {total_deleted:,} old monitoring records")

def cleanup_old_performance_metrics(retention_days=7):
    """Clean up old performance metrics"""
    logger.info("Cleaning up old performance metrics...")
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    # Check if PerformanceMetrics table exists
    try:
        old_metrics_count = db.session.query(func.count(PerformanceMetrics.id)).filter(
            PerformanceMetrics.timestamp < cutoff_date
        ).scalar()
        
        if old_metrics_count > 0:
            deleted = db.session.query(PerformanceMetrics).filter(
                PerformanceMetrics.timestamp < cutoff_date
            ).delete()
            db.session.commit()
            logger.info(f"✓ Deleted {deleted:,} old performance metrics")
        else:
            logger.info("No old performance metrics to clean")
            
    except Exception as e:
        logger.warning(f"Performance metrics cleanup skipped: {e}")
        db.session.rollback()

def cleanup_resolved_alerts(retention_days=30):
    """Clean up old resolved alerts"""
    logger.info("Cleaning up old resolved alerts...")
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    old_alerts_count = db.session.query(func.count(Alert.id)).filter(
        Alert.resolved == True,
        Alert.resolved_at < cutoff_date
    ).scalar()
    
    if old_alerts_count > 0:
        deleted = db.session.query(Alert).filter(
            Alert.resolved == True,
            Alert.resolved_at < cutoff_date
        ).delete()
        db.session.commit()
        logger.info(f"✓ Deleted {deleted:,} old resolved alerts")
    else:
        logger.info("No old resolved alerts to clean")

def vacuum_database():
    """Vacuum the database to reclaim space"""
    logger.info("Running database VACUUM to reclaim space...")
    
    try:
        # Close current connection
        db.session.close()
        
        # Run VACUUM in a new connection
        engine = db.engine
        with engine.connect() as conn:
            conn.execute(text("VACUUM"))
            conn.commit()
        
        logger.info("✓ Database VACUUM completed")
        
    except Exception as e:
        logger.error(f"VACUUM failed: {e}")

def analyze_database():
    """Analyze database statistics"""
    logger.info("Analyzing database statistics...")
    
    try:
        # Get table sizes
        stats_queries = [
            ("Devices", "SELECT COUNT(*) FROM devices"),
            ("Monitoring Data", "SELECT COUNT(*) FROM monitoring_data"),
            ("Alerts", "SELECT COUNT(*) FROM alerts"),
            ("Active Alerts", "SELECT COUNT(*) FROM alerts WHERE resolved = 0"),
        ]
        
        # Try to get performance metrics count
        try:
            stats_queries.append(("Performance Metrics", "SELECT COUNT(*) FROM performance_metrics"))
        except:
            pass
        
        for table_name, query in stats_queries:
            try:
                result = db.session.execute(text(query)).scalar()
                logger.info(f"{table_name}: {result:,} records")
            except Exception as e:
                logger.warning(f"Could not get {table_name} count: {e}")
        
        # Get database file size
        db_file = "homeNetMon.db"
        if os.path.exists(db_file):
            size_mb = os.path.getsize(db_file) / (1024 * 1024)
            logger.info(f"Database file size: {size_mb:.1f} MB")
            
    except Exception as e:
        logger.error(f"Database analysis failed: {e}")

def main():
    """Main optimization routine"""
    logger.info("=== HomeNetMon Database Performance Optimization ===")
    
    # Use existing Flask app context
    with flask_app.app_context():
        try:
            # Show initial stats
            logger.info("BEFORE optimization:")
            analyze_database()
            
            # Phase 1: Add indexes
            add_critical_indexes()
            
            # Phase 2: Data cleanup
            cleanup_old_monitoring_data(retention_days=7)  # Aggressive: keep only 7 days
            cleanup_old_performance_metrics(retention_days=7)
            cleanup_resolved_alerts(retention_days=30)  # Keep resolved alerts for 30 days
            
            # Phase 3: Vacuum database
            vacuum_database()
            
            # Show final stats
            logger.info("\nAFTER optimization:")
            analyze_database()
            
            logger.info("=== Database optimization completed successfully! ===")
            
        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            db.session.rollback()
            return 1
    
    return 0

if __name__ == "__main__":
    exit(main())