#!/usr/bin/env python3
"""
Emergency Database Cleanup and Archival for HomeNetMon
CRITICAL: Addresses severe database bloat (5.5M rows, 974MB) causing performance issues
"""

import os
import sys
import json
import time
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime, timedelta

class EmergencyDatabaseCleanup:
    def __init__(self, db_path="homeNetMon.db", backup_dir="database_archives"):
        self.db_path = Path(db_path)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)

        # Archive data older than these days
        self.retention_policies = {
            'bandwidth_data': 30,        # Keep only 30 days (5.5M rows!)
            'performance_metrics': 30,   # Keep only 30 days (330K rows)
            'monitoring_data': 90,       # Keep 90 days (114K rows)
            'notification_history': 90,  # Keep 90 days
            'security_scans': 180,       # Keep 180 days (security important)
            'security_events': 180,      # Keep 180 days
            'alerts': 365               # Keep alerts for 1 year
        }

        # Color codes
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'reset': '\033[0m'
        }

    def log_action(self, level, action, details, count=None):
        """Log cleanup action"""
        colors = {
            'critical': self.colors['red'],
            'warning': self.colors['yellow'],
            'success': self.colors['green'],
            'info': self.colors['blue']
        }

        icons = {
            'critical': '🚨',
            'warning': '⚠️',
            'success': '✅',
            'info': 'ℹ️'
        }

        color = colors.get(level, self.colors['blue'])
        icon = icons.get(level, 'ℹ️')

        count_str = f" ({count:,} rows)" if count is not None else ""
        print(f"{color}{icon} {action}: {details}{count_str}{self.colors['reset']}")

    def create_full_backup(self):
        """Create full database backup before cleanup"""
        print(f"\n{self.colors['cyan']}💾 Creating Full Database Backup{self.colors['reset']}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f"homeNetMon_backup_{timestamp}.db"

        try:
            # Copy the database file
            shutil.copy2(self.db_path, backup_path)

            backup_size_mb = backup_path.stat().st_size / (1024 * 1024)
            self.log_action('success', 'Full Backup Created', f"{backup_path} ({backup_size_mb:.1f}MB)")

            return backup_path

        except Exception as e:
            self.log_action('critical', 'Backup Failed', str(e))
            raise

    def analyze_table_sizes(self):
        """Analyze current table sizes"""
        print(f"\n{self.colors['cyan']}📊 Analyzing Table Sizes{self.colors['reset']}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                table_sizes = []
                total_rows = 0

                for table in self.retention_policies.keys():
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]
                        total_rows += row_count
                        table_sizes.append((table, row_count))

                        if row_count > 100000:
                            self.log_action('critical', 'Large Table', table, row_count)
                        elif row_count > 10000:
                            self.log_action('warning', 'Medium Table', table, row_count)
                        else:
                            self.log_action('info', 'Small Table', table, row_count)

                    except Exception as e:
                        self.log_action('warning', 'Table Check Failed', f"{table}: {e}")

                self.log_action('info', 'Total Monitored Rows', f"{total_rows:,} rows")
                return table_sizes

        except Exception as e:
            self.log_action('critical', 'Analysis Failed', str(e))
            raise

    def archive_old_data(self, table, retention_days):
        """Archive old data from a table"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if table has timestamp column
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]

                timestamp_col = None
                for col in ['timestamp', 'created_at', 'checked_at', 'time']:
                    if col in columns:
                        timestamp_col = col
                        break

                if not timestamp_col:
                    self.log_action('warning', 'Archive Skipped', f"{table} - No timestamp column found")
                    return 0

                # Calculate cutoff date
                cutoff_date = datetime.now() - timedelta(days=retention_days)
                cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')

                # Count old records
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {timestamp_col} < ?", (cutoff_str,))
                old_count = cursor.fetchone()[0]

                if old_count == 0:
                    self.log_action('info', 'No Old Data', f"{table} - All data within retention period")
                    return 0

                # Create archive table name
                archive_table = f"{table}_archive_{datetime.now().strftime('%Y%m%d')}"

                # Create archive table with same structure
                cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'")
                create_sql = cursor.fetchone()[0]
                archive_sql = create_sql.replace(f'CREATE TABLE {table}', f'CREATE TABLE IF NOT EXISTS {archive_table}')
                cursor.execute(archive_sql)

                # Move old data to archive table
                cursor.execute(f"""
                    INSERT INTO {archive_table}
                    SELECT * FROM {table}
                    WHERE {timestamp_col} < ?
                """, (cutoff_str,))

                # Delete old data from main table
                cursor.execute(f"DELETE FROM {table} WHERE {timestamp_col} < ?", (cutoff_str,))

                # Commit changes
                conn.commit()

                self.log_action('success', 'Data Archived', f"{table} → {archive_table}", old_count)
                return old_count

        except Exception as e:
            self.log_action('critical', 'Archive Failed', f"{table}: {e}")
            return 0

    def optimize_database(self):
        """Optimize database after cleanup"""
        print(f"\n{self.colors['cyan']}🔧 Optimizing Database{self.colors['reset']}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Apply optimization settings
                optimizations = [
                    ("PRAGMA journal_mode=WAL", "Enable Write-Ahead Logging"),
                    ("PRAGMA synchronous=NORMAL", "Set synchronous mode"),
                    ("PRAGMA cache_size=-10000", "Increase cache size"),
                    ("PRAGMA temp_store=MEMORY", "Use memory for temp storage"),
                    ("PRAGMA mmap_size=134217728", "Set memory map size"),
                    ("PRAGMA foreign_keys=ON", "Enable foreign key constraints"),
                    ("VACUUM", "Reclaim unused space"),
                    ("PRAGMA optimize", "Optimize query planner")
                ]

                for sql, description in optimizations:
                    try:
                        cursor.execute(sql)
                        self.log_action('success', 'Applied', description)
                    except Exception as e:
                        self.log_action('warning', 'Optimization Failed', f"{description}: {e}")

                conn.commit()

        except Exception as e:
            self.log_action('critical', 'Database Optimization Failed', str(e))

    def verify_cleanup_results(self):
        """Verify cleanup results"""
        print(f"\n{self.colors['cyan']}🔍 Verifying Cleanup Results{self.colors['reset']}")

        try:
            # Check new database size
            new_size_mb = self.db_path.stat().st_size / (1024 * 1024)
            self.log_action('info', 'New Database Size', f"{new_size_mb:.1f}MB")

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check table sizes after cleanup
                total_rows = 0
                for table in self.retention_policies.keys():
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]
                        total_rows += row_count

                        if row_count < 100000:
                            self.log_action('success', 'Table Size Good', table, row_count)
                        else:
                            self.log_action('warning', 'Table Still Large', table, row_count)

                    except Exception as e:
                        self.log_action('warning', 'Verification Failed', f"{table}: {e}")

                self.log_action('info', 'Total Rows After Cleanup', f"{total_rows:,} rows")

                # Test query performance
                start_time = time.time()
                cursor.execute("SELECT COUNT(*) FROM devices")
                query_time_ms = (time.time() - start_time) * 1000

                self.log_action('info', 'Query Performance Test', f"{query_time_ms:.2f}ms")

                return new_size_mb, total_rows

        except Exception as e:
            self.log_action('critical', 'Verification Failed', str(e))
            return None, None

    def run_emergency_cleanup(self):
        """Run complete emergency cleanup process"""
        print(f"{self.colors['red']}🚨 EMERGENCY DATABASE CLEANUP STARTING{self.colors['reset']}")
        print(f"Target: Reduce 974MB database with 5.5M+ rows")
        print(f"Action: Archive old data based on retention policies")
        print("=" * 80)

        start_time = time.time()

        try:
            # Step 1: Create backup
            backup_path = self.create_full_backup()

            # Step 2: Analyze current state
            table_sizes = self.analyze_table_sizes()

            # Step 3: Archive old data
            print(f"\n{self.colors['cyan']}🗂️ Archiving Old Data{self.colors['reset']}")
            total_archived = 0

            for table, retention_days in self.retention_policies.items():
                self.log_action('info', 'Archiving', f"{table} (keep {retention_days} days)")
                archived_count = self.archive_old_data(table, retention_days)
                total_archived += archived_count

            # Step 4: Optimize database
            self.optimize_database()

            # Step 5: Verify results
            new_size_mb, new_total_rows = self.verify_cleanup_results()

            # Step 6: Generate summary
            self.generate_cleanup_summary(start_time, total_archived, new_size_mb, new_total_rows)

            return True

        except Exception as e:
            self.log_action('critical', 'Cleanup Failed', str(e))
            print(f"\n{self.colors['red']}💥 CLEANUP FAILED - Database backup available at: {backup_path}{self.colors['reset']}")
            return False

    def generate_cleanup_summary(self, start_time, total_archived, new_size_mb, new_total_rows):
        """Generate cleanup summary report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Emergency Cleanup Summary{self.colors['reset']}")
        print("=" * 80)

        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"📁 Archived Rows: {total_archived:,}")

        if new_size_mb:
            original_size = 974.4  # From the health assessment
            size_reduction = original_size - new_size_mb
            size_reduction_pct = (size_reduction / original_size) * 100

            print(f"💾 Size Reduction: {size_reduction:.1f}MB ({size_reduction_pct:.1f}%)")
            print(f"📊 New Database Size: {new_size_mb:.1f}MB")

            if new_size_mb < 500:
                print(f"{self.colors['green']}✅ Database size now within recommended limits!{self.colors['reset']}")
            elif new_size_mb < 750:
                print(f"{self.colors['yellow']}⚠️ Database size improved but still large{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ Database size still critical - more cleanup needed{self.colors['reset']}")

        if new_total_rows:
            print(f"📈 Remaining Rows: {new_total_rows:,}")

        print(f"\n💡 Next Steps:")
        print("  1. Test application performance after cleanup")
        print("  2. Run backend performance test to verify improvements")
        print("  3. Set up automated data archival processes")
        print("  4. Monitor database growth going forward")

        print(f"\n📋 Archive Tables Created:")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_archive_%'")
                archive_tables = cursor.fetchall()
                for table in archive_tables:
                    print(f"  • {table[0]}")
        except:
            print("  • Archive table listing failed")

        print(f"\n⏰ Cleanup completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main emergency cleanup function"""
    print(f"🚨 EMERGENCY DATABASE CLEANUP TOOL")
    print(f"📊 Target: Fix critical database bloat (974MB, 5.5M+ rows)")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Verify database exists
    db_path = Path("homeNetMon.db")
    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        sys.exit(1)

    # Run cleanup
    cleanup = EmergencyDatabaseCleanup()
    success = cleanup.run_emergency_cleanup()

    if success:
        print(f"\n{cleanup.colors['green']}🎉 EMERGENCY CLEANUP COMPLETED SUCCESSFULLY!{cleanup.colors['reset']}")
        print("The database should now perform significantly better under load.")
        sys.exit(0)
    else:
        print(f"\n{cleanup.colors['red']}💥 EMERGENCY CLEANUP FAILED!{cleanup.colors['reset']}")
        print("Check the error messages above and backup database.")
        sys.exit(1)

if __name__ == "__main__":
    main()