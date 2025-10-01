#!/usr/bin/env python3
"""
Database Query Performance Optimizer
Analyzes and optimizes database queries for HomeNetMon
"""

import os
import sqlite3
import time
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseQueryOptimizer:
    """Optimizes database queries and creates necessary indexes"""

    def __init__(self, db_path='homeNetMon.db'):
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def connect(self):
        """Connect to the database"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        # Enable query planner for analysis
        self.cursor.execute("PRAGMA query_only = 0")
        self.cursor.execute("PRAGMA foreign_keys = ON")

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

    def analyze_tables(self):
        """Analyze all tables for optimization opportunities"""
        logger.info("Analyzing database tables...")

        # Update table statistics
        self.cursor.execute("ANALYZE")

        # Get table information
        self.cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """)
        tables = [row[0] for row in self.cursor.fetchall()]

        table_info = {}
        for table in tables:
            self.cursor.execute(f"SELECT COUNT(*) FROM {table}")
            row_count = self.cursor.fetchone()[0]

            # Get table size
            self.cursor.execute(f"PRAGMA page_count")
            page_count = self.cursor.fetchone()[0]
            self.cursor.execute(f"PRAGMA page_size")
            page_size = self.cursor.fetchone()[0]

            table_info[table] = {
                'rows': row_count,
                'size_mb': (page_count * page_size) / (1024 * 1024)
            }

            logger.info(f"  {table}: {row_count:,} rows")

        return table_info

    def create_optimized_indexes(self):
        """Create performance-critical indexes"""
        logger.info("Creating optimized indexes...")

        indexes = [
            # Device table indexes
            ("idx_device_ip_monitored", "devices", "(ip_address, is_monitored)"),
            ("idx_device_status", "devices", "(status)"),
            ("idx_device_type_priority", "devices", "(device_type, device_priority)"),
            ("idx_device_last_seen", "devices", "(last_seen DESC)"),

            # MonitoringData indexes for fast queries
            ("idx_monitoring_device_timestamp", "monitoring_data", "(device_id, timestamp DESC)"),
            ("idx_monitoring_timestamp", "monitoring_data", "(timestamp DESC)"),
            ("idx_monitoring_status_time", "monitoring_data", "(status, timestamp DESC)"),

            # Alert indexes
            ("idx_alert_device_active", "alerts", "(device_id, is_active)"),
            ("idx_alert_timestamp", "alerts", "(created_at DESC)"),
            ("idx_alert_type_active", "alerts", "(alert_type, is_active)"),

            # Performance metrics indexes
            ("idx_perf_device_time", "performance_metrics", "(device_id, timestamp DESC)"),
            ("idx_perf_metric_type", "performance_metrics", "(metric_type, timestamp DESC)"),

            # Configuration index
            ("idx_config_key", "configuration", "(key)"),
        ]

        created = 0
        for index_name, table, columns in indexes:
            try:
                # Check if index exists
                self.cursor.execute(f"""
                    SELECT name FROM sqlite_master
                    WHERE type='index' AND name='{index_name}'
                """)
                if not self.cursor.fetchone():
                    # Create index
                    self.cursor.execute(f"CREATE INDEX {index_name} ON {table} {columns}")
                    logger.info(f"  Created index: {index_name}")
                    created += 1
                else:
                    logger.debug(f"  Index exists: {index_name}")
            except sqlite3.Error as e:
                logger.warning(f"  Failed to create index {index_name}: {e}")

        self.conn.commit()
        logger.info(f"Created {created} new indexes")
        return created

    def optimize_slow_queries(self):
        """Identify and optimize slow queries"""
        logger.info("Optimizing slow queries...")

        # Common slow queries and their optimizations
        slow_queries = [
            {
                'name': 'Recent monitoring data',
                'original': """
                    SELECT * FROM monitoring_data
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 100
                """,
                'optimized': """
                    SELECT device_id, timestamp, response_time, status
                    FROM monitoring_data
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 100
                """,
                'test_params': (1,)
            },
            {
                'name': 'Active alerts count',
                'original': """
                    SELECT COUNT(*) FROM alerts
                    WHERE is_active = 1
                """,
                'optimized': """
                    SELECT COUNT(*) FROM alerts
                    WHERE is_active = 1
                """,
                'test_params': ()
            },
            {
                'name': 'Device status summary',
                'original': """
                    SELECT d.*,
                           (SELECT response_time FROM monitoring_data
                            WHERE device_id = d.id
                            ORDER BY timestamp DESC LIMIT 1) as last_response
                    FROM devices d
                    WHERE d.is_monitored = 1
                """,
                'optimized': """
                    SELECT d.id, d.ip_address, d.hostname, d.status,
                           m.response_time as last_response
                    FROM devices d
                    LEFT JOIN (
                        SELECT device_id, response_time,
                               ROW_NUMBER() OVER (PARTITION BY device_id
                                                 ORDER BY timestamp DESC) as rn
                        FROM monitoring_data
                    ) m ON d.id = m.device_id AND m.rn = 1
                    WHERE d.is_monitored = 1
                """,
                'test_params': ()
            }
        ]

        improvements = []
        for query_info in slow_queries:
            try:
                # Test original query
                start = time.time()
                self.cursor.execute(query_info['original'], query_info['test_params'])
                original_time = (time.time() - start) * 1000

                # Test optimized query (if different)
                if query_info['original'] != query_info['optimized']:
                    start = time.time()
                    self.cursor.execute(query_info['optimized'], query_info['test_params'])
                    optimized_time = (time.time() - start) * 1000

                    improvement = ((original_time - optimized_time) / original_time) * 100
                    improvements.append({
                        'name': query_info['name'],
                        'original_ms': original_time,
                        'optimized_ms': optimized_time,
                        'improvement_pct': improvement
                    })

                    logger.info(f"  {query_info['name']}: {original_time:.2f}ms → {optimized_time:.2f}ms "
                              f"({improvement:.1f}% faster)")
            except Exception as e:
                logger.warning(f"  Failed to test query '{query_info['name']}': {e}")

        return improvements

    def vacuum_database(self):
        """Vacuum database to reclaim space and optimize"""
        logger.info("Vacuuming database...")

        # Get size before vacuum
        self.cursor.execute("PRAGMA page_count")
        pages_before = self.cursor.fetchone()[0]
        self.cursor.execute("PRAGMA page_size")
        page_size = self.cursor.fetchone()[0]
        size_before = (pages_before * page_size) / (1024 * 1024)

        # Vacuum
        self.conn.execute("VACUUM")

        # Get size after vacuum
        self.cursor.execute("PRAGMA page_count")
        pages_after = self.cursor.fetchone()[0]
        size_after = (pages_after * page_size) / (1024 * 1024)

        space_saved = size_before - size_after
        logger.info(f"  Database size: {size_before:.2f}MB → {size_after:.2f}MB "
                   f"(saved {space_saved:.2f}MB)")

        return space_saved

    def cleanup_old_data(self, days=7):
        """Clean up old monitoring data"""
        logger.info(f"Cleaning up data older than {days} days...")

        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Clean monitoring_data
        self.cursor.execute("""
            DELETE FROM monitoring_data
            WHERE timestamp < ?
        """, (cutoff_date,))
        monitoring_deleted = self.cursor.rowcount

        # Clean performance_metrics
        self.cursor.execute("""
            DELETE FROM performance_metrics
            WHERE timestamp < ?
        """, (cutoff_date,))
        performance_deleted = self.cursor.rowcount

        # Clean old resolved alerts
        self.cursor.execute("""
            DELETE FROM alerts
            WHERE is_active = 0 AND resolved_at < ?
        """, (cutoff_date,))
        alerts_deleted = self.cursor.rowcount

        self.conn.commit()

        logger.info(f"  Deleted: {monitoring_deleted} monitoring records, "
                   f"{performance_deleted} performance metrics, "
                   f"{alerts_deleted} old alerts")

        return monitoring_deleted + performance_deleted + alerts_deleted

    def optimize_settings(self):
        """Apply optimal SQLite settings"""
        logger.info("Applying optimal database settings...")

        settings = [
            ("PRAGMA cache_size = -64000", "Set cache to 64MB"),
            ("PRAGMA temp_store = MEMORY", "Use memory for temp storage"),
            ("PRAGMA mmap_size = 268435456", "Enable memory-mapped I/O (256MB)"),
            ("PRAGMA synchronous = NORMAL", "Balanced durability/performance"),
            ("PRAGMA journal_mode = WAL", "Enable Write-Ahead Logging"),
            ("PRAGMA wal_autocheckpoint = 1000", "Auto-checkpoint every 1000 pages"),
            ("PRAGMA optimize", "Run query optimizer")
        ]

        for setting, description in settings:
            try:
                self.cursor.execute(setting)
                logger.info(f"  {description}")
            except Exception as e:
                logger.warning(f"  Failed to apply '{setting}': {e}")

    def run_full_optimization(self):
        """Run complete database optimization"""
        logger.info("=" * 60)
        logger.info("Starting Database Query Optimization")
        logger.info("=" * 60)

        try:
            self.connect()

            # Analyze tables
            table_info = self.analyze_tables()

            # Apply optimal settings
            self.optimize_settings()

            # Create indexes
            indexes_created = self.create_optimized_indexes()

            # Optimize queries
            query_improvements = self.optimize_slow_queries()

            # Clean old data
            records_cleaned = self.cleanup_old_data()

            # Vacuum database
            space_saved = self.vacuum_database()

            logger.info("=" * 60)
            logger.info("Optimization Complete!")
            logger.info(f"  - Indexes created: {indexes_created}")
            logger.info(f"  - Records cleaned: {records_cleaned:,}")
            logger.info(f"  - Space saved: {space_saved:.2f}MB")
            logger.info(f"  - Query improvements: {len(query_improvements)}")
            logger.info("=" * 60)

            return True

        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            return False
        finally:
            self.close()


def main():
    """Main entry point"""
    optimizer = DatabaseQueryOptimizer()
    success = optimizer.run_full_optimization()

    if success:
        logger.info("\n✅ Database optimization completed successfully!")
        logger.info("Your HomeNetMon application should now run faster.")
    else:
        logger.error("\n❌ Database optimization failed. Check the logs above.")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())