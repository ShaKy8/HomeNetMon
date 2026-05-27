#!/usr/bin/env python3
"""
Database Index Optimization Script
Adds critical indexes to improve query performance for production use.
"""

import logging
from models import db, Device, MonitoringData, Alert, Configuration, DeviceIpHistory
from sqlalchemy import Index, text
from datetime import datetime

logger = logging.getLogger(__name__)


def add_database_indexes():
    """Add performance-critical database indexes."""
    
    logger.info("Starting database index optimization...")
    
    try:
        # Device table indexes
        logger.info("Adding Device table indexes...")
        
        # Index on ip_address (already exists as unique, but ensure it's optimal)
        # Index on last_seen for quick status queries
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen DESC)"))
        except Exception as e:
            logger.warning(f"Index idx_devices_last_seen might already exist: {e}")
        
        # Index on device_type for filtering
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_type ON devices (device_type)"))
        except Exception as e:
            logger.warning(f"Index idx_devices_type might already exist: {e}")
        
        # Index on is_monitored for filtering
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_monitored ON devices (is_monitored)"))
        except Exception as e:
            logger.warning(f"Index idx_devices_monitored might already exist: {e}")
        
        # Index on device_group for filtering
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_group ON devices (device_group)"))
        except Exception as e:
            logger.warning(f"Index idx_devices_group might already exist: {e}")
        
        # Composite index for common queries
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_monitored_type ON devices (is_monitored, device_type)"))
        except Exception as e:
            logger.warning(f"Index idx_devices_monitored_type might already exist: {e}")
        
        # MonitoringData table indexes (critical for performance)
        logger.info("Adding MonitoringData table indexes...")
        
        # Index on device_id and timestamp (most important for time-series queries)
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_monitoring_device_timestamp ON monitoring_data (device_id, timestamp DESC)"))
        except Exception as e:
            logger.warning(f"Index idx_monitoring_device_timestamp might already exist: {e}")
        
        # Index on timestamp alone for cleanup queries
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_monitoring_timestamp ON monitoring_data (timestamp DESC)"))
        except Exception as e:
            logger.warning(f"Index idx_monitoring_timestamp might already exist: {e}")
        
        # Index on response_time for analytics
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_monitoring_response_time ON monitoring_data (response_time)"))
        except Exception as e:
            logger.warning(f"Index idx_monitoring_response_time might already exist: {e}")
        
        # Composite index for status queries
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_monitoring_device_time_response ON monitoring_data (device_id, timestamp DESC, response_time)"))
        except Exception as e:
            logger.warning(f"Index idx_monitoring_device_time_response might already exist: {e}")
        
        # Alert table indexes
        logger.info("Adding Alert table indexes...")
        
        # Index on device_id and resolved status
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_alerts_device_resolved ON alerts (device_id, resolved)"))
        except Exception as e:
            logger.warning(f"Index idx_alerts_device_resolved might already exist: {e}")
        
        # Index on created_at for recent alerts
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC)"))
        except Exception as e:
            logger.warning(f"Index idx_alerts_created_at might already exist: {e}")
        
        # Index on resolved and severity for filtering
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_alerts_resolved_severity ON alerts (resolved, severity)"))
        except Exception as e:
            logger.warning(f"Index idx_alerts_resolved_severity might already exist: {e}")
        
        # Configuration table indexes
        logger.info("Adding Configuration table indexes...")
        
        # Index on key for quick lookups (probably already exists)
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_config_key ON configuration (key)"))
        except Exception as e:
            logger.warning(f"Index idx_config_key might already exist: {e}")
        
        # Index on updated_at for change tracking
        try:
            db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_config_updated_at ON configuration (updated_at DESC)"))
        except Exception as e:
            logger.warning(f"Index idx_config_updated_at might already exist: {e}")
        
        # DeviceIpHistory table indexes (if exists)
        logger.info("Adding DeviceIpHistory table indexes...")
        
        try:
            # Check if table exists first
            db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='device_ip_history'"))
            result = db.session.fetchone()
            
            if result:
                # Index on device_id and changed_at
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_device_ip_history_device_date ON device_ip_history (device_id, changed_at DESC)"))
        except Exception as e:
            logger.warning(f"DeviceIpHistory table might not exist: {e}")
        
        # Commit all index creations
        db.session.commit()
        logger.info("Database indexes added successfully!")
        
        # Analyze tables to update statistics (SQLite specific)
        logger.info("Updating table statistics...")
        try:
            db.session.execute(text("ANALYZE"))
            db.session.commit()
            logger.info("Table statistics updated")
        except Exception as e:
            logger.warning(f"Could not update statistics: {e}")
        
    except Exception as e:
        logger.error(f"Error adding database indexes: {e}")
        db.session.rollback()
        raise


def show_index_status():
    """Show current database indexes for verification."""
    
    logger.info("Current database indexes:")
    
    try:
        # Get all indexes
        result = db.session.execute(text("""
            SELECT 
                name,
                tbl_name,
                sql
            FROM sqlite_master 
            WHERE type = 'index' 
            AND name NOT LIKE 'sqlite_%'
            ORDER BY tbl_name, name
        """))
        
        indexes = result.fetchall()
        
        if indexes:
            print("\n" + "="*80)
            print("DATABASE INDEXES")
            print("="*80)
            
            current_table = None
            for index in indexes:
                if current_table != index.tbl_name:
                    current_table = index.tbl_name
                    print(f"\nTable: {current_table}")
                    print("-" * 40)
                
                print(f"  Index: {index.name}")
                if index.sql:
                    print(f"    SQL: {index.sql}")
                else:
                    print("    SQL: (system index)")
            print("\n" + "="*80)
        else:
            print("No custom indexes found")
            
    except Exception as e:
        logger.error(f"Error showing indexes: {e}")


def optimize_database():
    """Perform database optimization tasks."""
    
    logger.info("Performing database optimization...")
    
    try:
        # Vacuum the database (SQLite)
        logger.info("Vacuuming database...")
        db.session.execute(text("VACUUM"))
        
        # Reindex everything
        logger.info("Reindexing database...")
        db.session.execute(text("REINDEX"))
        
        logger.info("Database optimization complete")
        
    except Exception as e:
        logger.error(f"Error optimizing database: {e}")


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    from app import create_app
    app, socketio = create_app()
    
    with app.app_context():
        print("HomeNetMon Database Index Optimization")
        print("=====================================")
        
        # Show current status
        show_index_status()
        
        # Add indexes
        add_database_indexes()
        
        # Show updated status
        print("\nAfter optimization:")
        show_index_status()
        
        # Optimize database
        optimize_database()
        
        print("\nDatabase optimization complete!")
        print("Your HomeNetMon application should now perform much better.")