#!/usr/bin/env python3
"""
Comprehensive Database Health Assessment for HomeNetMon
Analyzes database performance, structure, integrity, and optimization opportunities
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict

class DatabaseHealthAssessment:
    def __init__(self, db_path="homeNetMon.db", project_path=None):
        self.db_path = Path(db_path)
        self.project_path = Path(project_path or Path.cwd())
        self.findings = defaultdict(list)
        self.metrics = {}
        self.recommendations = []

        # Color codes for output
        self.colors = {
            'red': '\033[91m',
            'yellow': '\033[93m',
            'green': '\033[92m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }

    def log_finding(self, level, category, metric, value, target="", recommendation=""):
        """Log a database health finding"""
        finding = {
            'level': level,
            'category': category,
            'metric': metric,
            'value': value,
            'target': target,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.findings[level].append(finding)

        # Color mapping
        colors = {
            'excellent': self.colors['green'],
            'good': self.colors['blue'],
            'warning': self.colors['yellow'],
            'critical': self.colors['red'],
            'info': self.colors['cyan']
        }

        icons = {
            'excellent': '🚀',
            'good': '✅',
            'warning': '⚠️',
            'critical': '❌',
            'info': 'ℹ️'
        }

        color = colors.get(level, self.colors['white'])
        icon = icons.get(level, 'ℹ️')

        print(f"{color}{icon} {category}: {metric} = {value}{self.colors['reset']}")
        if target:
            print(f"    Target: {target}")
        if recommendation:
            print(f"    └─ {recommendation}")

    def assess_database_structure(self):
        """Assess database structure and schema health"""
        print(f"\n{self.colors['cyan']}🏗️ Assessing Database Structure{self.colors['reset']}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get basic database info
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
                index_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='view'")
                view_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'")
                trigger_count = cursor.fetchone()[0]

                self.log_finding('info', 'Structure', 'Tables', table_count)
                self.log_finding('info', 'Structure', 'Indexes', index_count)
                self.log_finding('info', 'Structure', 'Views', view_count)
                self.log_finding('info', 'Structure', 'Triggers', trigger_count)

                # Analyze table structures
                self._analyze_table_structures(cursor)

                # Check for missing foreign keys
                self._check_foreign_key_constraints(cursor)

                # Analyze index effectiveness
                self._analyze_index_effectiveness(cursor)

        except Exception as e:
            self.log_finding('critical', 'Structure', 'Analysis Error', str(e),
                           recommendation="Check database connectivity and permissions")

    def _analyze_table_structures(self, cursor):
        """Analyze individual table structures"""
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                # Get table info
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()

                # Check for primary keys
                primary_keys = [col for col in columns if col[5] == 1]  # pk column is index 5
                if not primary_keys:
                    self.log_finding('warning', 'Schema', f'{table} Primary Key', 'Missing',
                                   recommendation="Consider adding a primary key for better performance")

                # Check for appropriate data types
                for col in columns:
                    col_name, col_type, not_null, default_val, pk = col[1], col[2], col[3], col[4], col[5]

                    # Check for TEXT columns that might benefit from constraints
                    if col_type.upper() == 'TEXT' and 'id' in col_name.lower():
                        self.log_finding('info', 'Schema', f'{table}.{col_name}', 'TEXT type for ID field',
                                       recommendation="Consider using INTEGER for ID fields")

                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]

                if row_count > 100000:
                    self.log_finding('warning', 'Data Volume', f'{table} Rows', f"{row_count:,}",
                                   "< 100K for optimal performance",
                                   "Consider data archival or partitioning strategies")
                elif row_count > 10000:
                    self.log_finding('good', 'Data Volume', f'{table} Rows', f"{row_count:,}")
                else:
                    self.log_finding('excellent', 'Data Volume', f'{table} Rows', f"{row_count:,}")

                self.metrics[f'{table}_row_count'] = row_count

            except Exception as e:
                self.log_finding('warning', 'Schema', f'{table} Analysis', f'Error: {e}')

    def _check_foreign_key_constraints(self, cursor):
        """Check for proper foreign key constraints"""
        cursor.execute("PRAGMA foreign_keys")
        fk_enabled = cursor.fetchone()[0]

        if fk_enabled:
            self.log_finding('good', 'Constraints', 'Foreign Keys', 'Enabled')
        else:
            self.log_finding('warning', 'Constraints', 'Foreign Keys', 'Disabled',
                           recommendation="Enable foreign key constraints for data integrity")

        # Check for referential integrity issues
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA foreign_key_check({table})")
                violations = cursor.fetchall()
                if violations:
                    self.log_finding('critical', 'Integrity', f'{table} FK Violations', len(violations),
                                   "0 violations", "Fix foreign key constraint violations")
                else:
                    self.log_finding('good', 'Integrity', f'{table} FK Check', 'Clean')
            except Exception as e:
                self.log_finding('info', 'Integrity', f'{table} FK Check', f'Skipped: {e}')

    def _analyze_index_effectiveness(self, cursor):
        """Analyze index usage and effectiveness"""
        cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
        indexes = cursor.fetchall()

        for index_name, table_name in indexes:
            try:
                # Get index info
                cursor.execute(f"PRAGMA index_info({index_name})")
                index_columns = cursor.fetchall()

                # Check if index is used (this is approximate for SQLite)
                cursor.execute(f"PRAGMA index_list({table_name})")
                index_list = cursor.fetchall()

                self.log_finding('info', 'Indexes', f'{table_name}.{index_name}',
                               f"{len(index_columns)} columns")

            except Exception as e:
                self.log_finding('warning', 'Indexes', f'{index_name}', f'Analysis error: {e}')

    def assess_database_performance(self):
        """Assess database performance characteristics"""
        print(f"\n{self.colors['cyan']}⚡ Assessing Database Performance{self.colors['reset']}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Test basic query performance
                self._test_query_performance(cursor)

                # Check database settings
                self._check_database_settings(cursor)

                # Analyze query patterns
                self._analyze_query_patterns(cursor)

                # Check for bottlenecks
                self._identify_performance_bottlenecks(cursor)

        except Exception as e:
            self.log_finding('critical', 'Performance', 'Assessment Error', str(e))

    def _test_query_performance(self, cursor):
        """Test performance of common queries"""
        # Performance test queries
        test_queries = [
            ("SELECT COUNT(*) FROM devices", "Device Count Query"),
            ("SELECT COUNT(*) FROM monitoring_data", "Monitoring Data Count"),
            ("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 10", "Recent Devices"),
            ("SELECT * FROM monitoring_data ORDER BY timestamp DESC LIMIT 100", "Recent Monitoring"),
            ("SELECT device_id, AVG(response_time) FROM monitoring_data GROUP BY device_id LIMIT 20", "Device Averages"),
            ("SELECT COUNT(*) FROM alerts WHERE status = 'active'", "Active Alerts Count"),
        ]

        total_query_time = 0
        successful_queries = 0

        for query, name in test_queries:
            try:
                start_time = time.time()
                cursor.execute(query)
                results = cursor.fetchall()
                query_time = (time.time() - start_time) * 1000  # Convert to milliseconds

                total_query_time += query_time
                successful_queries += 1

                # Classify query performance
                if query_time <= 10:
                    level = 'excellent'
                elif query_time <= 50:
                    level = 'good'
                elif query_time <= 200:
                    level = 'warning'
                else:
                    level = 'critical'

                self.log_finding(level, 'Query Performance', name, f"{query_time:.2f}ms",
                               "< 50ms optimal", "Add indexes or optimize query" if level in ['warning', 'critical'] else "")

                self.metrics[f'query_{name.lower().replace(" ", "_")}_ms'] = query_time

            except Exception as e:
                self.log_finding('warning', 'Query Performance', name, f'Error: {e}')

        # Overall performance assessment
        if successful_queries > 0:
            avg_query_time = total_query_time / successful_queries
            if avg_query_time <= 25:
                self.log_finding('excellent', 'Overall Performance', 'Average Query Time', f"{avg_query_time:.2f}ms")
            elif avg_query_time <= 100:
                self.log_finding('good', 'Overall Performance', 'Average Query Time', f"{avg_query_time:.2f}ms")
            else:
                self.log_finding('warning', 'Overall Performance', 'Average Query Time', f"{avg_query_time:.2f}ms",
                               "< 100ms target", "Database optimization needed")

    def _check_database_settings(self, cursor):
        """Check SQLite database settings and optimizations"""
        settings_to_check = [
            ("journal_mode", "WAL", "Write-Ahead Logging"),
            ("synchronous", "1", "Synchronous Mode"),
            ("cache_size", "-10000", "Cache Size"),
            ("temp_store", "2", "Temp Store"),
            ("mmap_size", "134217728", "Memory Map Size")
        ]

        for setting, optimal_value, description in settings_to_check:
            try:
                cursor.execute(f"PRAGMA {setting}")
                current_value = str(cursor.fetchone()[0])

                if current_value == optimal_value:
                    self.log_finding('good', 'Configuration', description, current_value)
                else:
                    self.log_finding('warning', 'Configuration', description, current_value,
                                   f"Optimal: {optimal_value}", f"Set PRAGMA {setting}={optimal_value}")

            except Exception as e:
                self.log_finding('info', 'Configuration', description, f'Check failed: {e}')

    def _analyze_query_patterns(self, cursor):
        """Analyze query patterns and usage"""
        # Check if there's a query log table
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='query_performance_log'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) FROM query_performance_log")
                log_count = cursor.fetchone()[0]

                if log_count > 0:
                    self.log_finding('good', 'Query Monitoring', 'Performance Log Entries', f"{log_count:,}")

                    # Analyze slow queries
                    cursor.execute("""
                        SELECT query_type, AVG(execution_time_ms), COUNT(*)
                        FROM query_performance_log
                        WHERE execution_time_ms > 100
                        GROUP BY query_type
                        ORDER BY AVG(execution_time_ms) DESC
                        LIMIT 5
                    """)
                    slow_queries = cursor.fetchall()

                    for query_type, avg_time, count in slow_queries:
                        self.log_finding('warning', 'Slow Queries', query_type,
                                       f"{avg_time:.1f}ms avg ({count} occurrences)",
                                       "< 100ms target", "Optimize these query patterns")
                else:
                    self.log_finding('info', 'Query Monitoring', 'Performance Log', 'Empty')
            else:
                self.log_finding('info', 'Query Monitoring', 'Performance Log', 'Not enabled')
        except Exception as e:
            self.log_finding('info', 'Query Monitoring', 'Analysis', f'Unavailable: {e}')

    def _identify_performance_bottlenecks(self, cursor):
        """Identify potential performance bottlenecks"""
        # Check for tables without indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                # Check for indexes on this table
                cursor.execute(f"PRAGMA index_list({table})")
                indexes = cursor.fetchall()

                if not indexes:
                    # Get row count to determine impact
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    row_count = cursor.fetchone()[0]

                    if row_count > 1000:
                        self.log_finding('warning', 'Performance Bottleneck', f'{table} No Indexes',
                                       f"{row_count:,} rows", "Add appropriate indexes",
                                       "Large table without indexes will cause slow queries")

                # Check for large text/blob columns that might slow queries
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()

                for col in columns:
                    col_name, col_type = col[1], col[2]
                    if col_type.upper() in ['TEXT', 'BLOB']:
                        # Sample a few rows to check for large content
                        try:
                            cursor.execute(f"SELECT LENGTH({col_name}) FROM {table} WHERE {col_name} IS NOT NULL ORDER BY LENGTH({col_name}) DESC LIMIT 1")
                            result = cursor.fetchone()
                            if result and result[0] > 10000:  # > 10KB
                                self.log_finding('warning', 'Performance Bottleneck',
                                               f'{table}.{col_name}', f"Max size: {result[0]:,} bytes",
                                               "< 10KB recommended", "Consider storing large content separately")
                        except:
                            pass  # Skip if column doesn't exist or other error

            except Exception as e:
                self.log_finding('info', 'Performance Bottleneck', f'{table}', f'Analysis skipped: {e}')

    def assess_database_integrity(self):
        """Assess database integrity and consistency"""
        print(f"\n{self.colors['cyan']}🔍 Assessing Database Integrity{self.colors['reset']}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Run integrity check
                cursor.execute("PRAGMA integrity_check")
                integrity_results = cursor.fetchall()

                if len(integrity_results) == 1 and integrity_results[0][0] == 'ok':
                    self.log_finding('excellent', 'Integrity', 'Database Check', 'OK')
                else:
                    self.log_finding('critical', 'Integrity', 'Database Check',
                                   f"{len(integrity_results)} issues found",
                                   recommendation="Run database repair or restore from backup")

                # Check for orphaned records
                self._check_orphaned_records(cursor)

                # Check data consistency
                self._check_data_consistency(cursor)

                # Check for duplicate data
                self._check_duplicate_data(cursor)

        except Exception as e:
            self.log_finding('critical', 'Integrity', 'Assessment Error', str(e))

    def _check_orphaned_records(self, cursor):
        """Check for orphaned records in related tables"""
        orphan_checks = [
            ("monitoring_data", "device_id", "devices", "id", "Monitoring data without devices"),
            ("alerts", "device_id", "devices", "id", "Alerts without devices"),
            ("escalation_executions", "device_id", "devices", "id", "Escalation executions without devices"),
        ]

        for child_table, child_key, parent_table, parent_key, description in orphan_checks:
            try:
                # Check if tables exist
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{child_table}'")
                if not cursor.fetchone():
                    continue

                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{parent_table}'")
                if not cursor.fetchone():
                    continue

                # Check for orphaned records
                cursor.execute(f"""
                    SELECT COUNT(*)
                    FROM {child_table} c
                    LEFT JOIN {parent_table} p ON c.{child_key} = p.{parent_key}
                    WHERE p.{parent_key} IS NULL AND c.{child_key} IS NOT NULL
                """)
                orphan_count = cursor.fetchone()[0]

                if orphan_count > 0:
                    self.log_finding('warning', 'Data Integrity', description, f"{orphan_count:,} orphaned records",
                                   "0 orphaned records", "Clean up orphaned data")
                else:
                    self.log_finding('good', 'Data Integrity', description, 'No orphaned records')

            except Exception as e:
                self.log_finding('info', 'Data Integrity', description, f'Check failed: {e}')

    def _check_data_consistency(self, cursor):
        """Check for data consistency issues"""
        consistency_checks = [
            ("devices", "last_seen > created_at", "Device last_seen before created_at"),
            ("monitoring_data", "response_time >= 0", "Negative response times"),
            ("alerts", "created_at <= updated_at", "Alert updated before created"),
        ]

        for table, condition, description in consistency_checks:
            try:
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                if not cursor.fetchone():
                    continue

                # Invert condition to find violations
                inverse_condition = condition.replace(">=", "<").replace(">", "<=").replace("<=", ">")
                if "=" in condition and not ">=" in condition and not "<=" in condition:
                    inverse_condition = condition.replace("=", "!=")

                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE NOT ({condition})")
                violation_count = cursor.fetchone()[0]

                if violation_count > 0:
                    self.log_finding('warning', 'Data Consistency', description,
                                   f"{violation_count:,} violations", "0 violations",
                                   "Review and fix data consistency issues")
                else:
                    self.log_finding('good', 'Data Consistency', description, 'Consistent')

            except Exception as e:
                self.log_finding('info', 'Data Consistency', description, f'Check failed: {e}')

    def _check_duplicate_data(self, cursor):
        """Check for duplicate data that might indicate issues"""
        # Check for duplicate device entries
        try:
            cursor.execute("""
                SELECT ip_address, COUNT(*)
                FROM devices
                GROUP BY ip_address
                HAVING COUNT(*) > 1
            """)
            duplicate_ips = cursor.fetchall()

            if duplicate_ips:
                total_duplicates = sum(count - 1 for _, count in duplicate_ips)
                self.log_finding('warning', 'Data Quality', 'Duplicate Device IPs',
                               f"{total_duplicates} duplicates", "No duplicates",
                               "Remove or consolidate duplicate device entries")
            else:
                self.log_finding('good', 'Data Quality', 'Device IP Uniqueness', 'No duplicates')

        except Exception as e:
            self.log_finding('info', 'Data Quality', 'Duplicate Check', f'Failed: {e}')

    def assess_database_size_and_growth(self):
        """Assess database size and growth patterns"""
        print(f"\n{self.colors['cyan']}📈 Assessing Database Size and Growth{self.colors['reset']}")

        try:
            # Database file size
            db_size_bytes = self.db_path.stat().st_size
            db_size_mb = db_size_bytes / (1024 * 1024)

            if db_size_mb < 100:
                self.log_finding('excellent', 'Storage', 'Database Size', f"{db_size_mb:.1f}MB")
            elif db_size_mb < 500:
                self.log_finding('good', 'Storage', 'Database Size', f"{db_size_mb:.1f}MB")
            elif db_size_mb < 1000:
                self.log_finding('warning', 'Storage', 'Database Size', f"{db_size_mb:.1f}MB",
                               "< 500MB recommended", "Consider data archival strategies")
            else:
                self.log_finding('critical', 'Storage', 'Database Size', f"{db_size_mb:.1f}MB",
                               "< 1GB critical", "Implement data archival immediately")

            # Analyze table sizes
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                tables = [row[0] for row in cursor.fetchall()]

                table_sizes = []
                total_rows = 0

                for table in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]
                        total_rows += row_count

                        # Estimate table size (rough approximation)
                        cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'")
                        table_sql = cursor.fetchone()[0] or ""
                        estimated_row_size = len(table_sql.split(',')) * 20  # Rough estimate
                        estimated_size_mb = (row_count * estimated_row_size) / (1024 * 1024)

                        table_sizes.append((table, row_count, estimated_size_mb))

                        if row_count > 1000000:  # 1M rows
                            self.log_finding('warning', 'Table Growth', f'{table} Size',
                                           f"{row_count:,} rows (~{estimated_size_mb:.1f}MB)",
                                           "< 1M rows recommended", "Consider partitioning or archival")

                    except Exception as e:
                        self.log_finding('info', 'Table Growth', f'{table}', f'Size check failed: {e}')

                # Overall row count
                self.log_finding('info', 'Storage', 'Total Rows', f"{total_rows:,}")

                # Largest tables
                largest_tables = sorted(table_sizes, key=lambda x: x[1], reverse=True)[:5]
                self.log_finding('info', 'Storage', 'Largest Tables',
                               ', '.join([f"{table}({rows:,})" for table, rows, _ in largest_tables]))

        except Exception as e:
            self.log_finding('critical', 'Storage', 'Assessment Error', str(e))

    def generate_optimization_recommendations(self):
        """Generate specific optimization recommendations"""
        print(f"\n{self.colors['cyan']}💡 Generating Optimization Recommendations{self.colors['reset']}")

        recommendations = []

        # Analyze findings to generate recommendations
        critical_issues = len(self.findings['critical'])
        warning_issues = len(self.findings['warning'])

        if critical_issues > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Database Integrity',
                'recommendation': f'Address {critical_issues} critical database issues immediately',
                'action': 'Run integrity checks and repair database'
            })

        if warning_issues > 5:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Performance',
                'recommendation': f'Resolve {warning_issues} performance warnings',
                'action': 'Optimize queries, add indexes, review data patterns'
            })

        # Specific recommendations based on metrics
        if self.metrics.get('monitoring_data_row_count', 0) > 100000:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Data Management',
                'recommendation': 'Implement data archival for monitoring_data table',
                'action': 'Archive data older than 30-90 days to separate tables'
            })

        # Performance-based recommendations
        slow_queries = [f for f in self.findings['warning'] + self.findings['critical']
                       if f['category'] == 'Query Performance']
        if slow_queries:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Query Performance',
                'recommendation': f'Optimize {len(slow_queries)} slow queries',
                'action': 'Add indexes, rewrite queries, analyze execution plans'
            })

        # Configuration recommendations
        config_issues = [f for f in self.findings['warning'] if f['category'] == 'Configuration']
        if config_issues:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Configuration',
                'recommendation': f'Update {len(config_issues)} database configuration settings',
                'action': 'Apply recommended PRAGMA settings for performance'
            })

        return recommendations

    def generate_health_report(self):
        """Generate comprehensive database health report"""
        print(f"\n{self.colors['purple']}📊 Database Health Assessment Report{self.colors['reset']}")
        print("=" * 80)

        # Summary statistics
        total_findings = sum(len(findings) for findings in self.findings.values())
        excellent_count = len(self.findings['excellent'])
        good_count = len(self.findings['good'])
        warning_count = len(self.findings['warning'])
        critical_count = len(self.findings['critical'])

        print(f"\n📈 Health Summary:")
        print(f"  Total Assessments: {total_findings}")
        print(f"  Excellent: {excellent_count}")
        print(f"  Good: {good_count}")
        print(f"  Warnings: {warning_count}")
        print(f"  Critical: {critical_count}")

        # Calculate health score
        health_score = self._calculate_health_score()
        print(f"\n🎯 Database Health Score: {health_score}/100")

        if health_score >= 90:
            status = f"{self.colors['green']}🚀 EXCELLENT{self.colors['reset']}"
        elif health_score >= 75:
            status = f"{self.colors['blue']}✅ GOOD{self.colors['reset']}"
        elif health_score >= 60:
            status = f"{self.colors['yellow']}⚠️ NEEDS ATTENTION{self.colors['reset']}"
        else:
            status = f"{self.colors['red']}❌ CRITICAL{self.colors['reset']}"

        print(f"  Status: {status}")

        # Key metrics
        if self.metrics:
            print(f"\n📊 Key Metrics:")
            important_metrics = [
                'monitoring_data_row_count', 'devices_row_count', 'alerts_row_count',
                'query_device_count_query_ms', 'query_recent_devices_ms'
            ]
            for metric in important_metrics:
                if metric in self.metrics:
                    value = self.metrics[metric]
                    if 'ms' in metric:
                        print(f"  {metric.replace('_', ' ').title()}: {value:.2f}ms")
                    else:
                        print(f"  {metric.replace('_', ' ').title()}: {value:,}")

        # Critical issues
        if critical_count > 0:
            print(f"\n🚨 Critical Issues:")
            for finding in self.findings['critical'][:5]:
                print(f"  • {finding['category']}: {finding['metric']} = {finding['value']}")

        # Optimization recommendations
        recommendations = self.generate_optimization_recommendations()
        if recommendations:
            print(f"\n💡 Optimization Recommendations:")
            for i, rec in enumerate(recommendations[:8], 1):
                priority_icon = "🔴" if rec['priority'] == 'CRITICAL' else "🟡" if rec['priority'] == 'HIGH' else "🟢"
                print(f"  {i}. {priority_icon} {rec['recommendation']}")
                print(f"     Action: {rec['action']}")

        print(f"\n⏰ Assessment Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return health_score

    def _calculate_health_score(self):
        """Calculate overall database health score"""
        score = 100

        # Deduct points for issues
        score -= len(self.findings['critical']) * 25
        score -= len(self.findings['warning']) * 10

        # Add bonus points for excellent metrics
        score += len(self.findings['excellent']) * 2

        # Bonus for good performance
        avg_query_time = 0
        query_metrics = [v for k, v in self.metrics.items() if 'query_' in k and '_ms' in k]
        if query_metrics:
            avg_query_time = sum(query_metrics) / len(query_metrics)
            if avg_query_time < 25:
                score += 10
            elif avg_query_time < 50:
                score += 5

        return max(0, min(100, score))

    def save_health_report(self):
        """Save detailed health report to file"""
        report_file = self.project_path / "database_health_report.json"

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'database_path': str(self.db_path),
            'summary': {
                'health_score': self._calculate_health_score(),
                'total_findings': sum(len(findings) for findings in self.findings.values()),
                'excellent_count': len(self.findings['excellent']),
                'good_count': len(self.findings['good']),
                'warning_count': len(self.findings['warning']),
                'critical_count': len(self.findings['critical'])
            },
            'findings': dict(self.findings),
            'metrics': self.metrics,
            'recommendations': self.generate_optimization_recommendations()
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {report_file}")
        return report_file

def main():
    """Main function to run database health assessment"""
    project_path = Path.cwd()
    db_path = project_path / "homeNetMon.db"

    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        print("Please ensure the database file exists before running the assessment.")
        sys.exit(1)

    print(f"🔍 Starting Comprehensive Database Health Assessment")
    print(f"📊 Database: {db_path}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    assessor = DatabaseHealthAssessment(db_path, project_path)

    # Run all assessments
    assessor.assess_database_structure()
    assessor.assess_database_performance()
    assessor.assess_database_integrity()
    assessor.assess_database_size_and_growth()

    # Generate and save report
    health_score = assessor.generate_health_report()
    assessor.save_health_report()

    # Exit with appropriate code
    if health_score >= 75:
        sys.exit(0)  # Good health
    elif health_score >= 60:
        sys.exit(1)  # Needs attention
    else:
        sys.exit(2)  # Critical issues

if __name__ == "__main__":
    main()