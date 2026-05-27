"""
Resource Monitoring and Cleanup Service for HomeNetMon.

This service monitors system resources and implements cleanup strategies
for optimal performance and storage management.
"""

import os
import gc
import psutil
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from models import db, MonitoringData, Alert, Device
from sqlalchemy import text, func
from core.error_handler import handle_errors, DatabaseError

logger = logging.getLogger(__name__)


class ResourceMonitor:
    """Monitor system resources and implement cleanup strategies."""

    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self.monitor_thread = None
        self._stop_event = threading.Event()

        # Resource thresholds
        self.thresholds = {
            'memory_warning': 80,      # Warn at 80% memory usage
            'memory_critical': 90,     # Critical at 90% memory usage
            'disk_warning': 85,        # Warn at 85% disk usage
            'disk_critical': 95,       # Critical at 95% disk usage
            'cpu_sustained': 85,       # Sustained CPU usage threshold
            'cpu_duration': 300,       # Duration for sustained CPU (seconds)
        }

        # Cleanup configurations
        self.cleanup_config = {
            'old_monitoring_data_days': 30,    # Keep monitoring data for 30 days
            'old_bandwidth_data_days': 30,     # Keep bandwidth data for 30 days
            'old_performance_metrics_days': 30,  # Keep performance metrics for 30 days
            'resolved_alerts_days': 7,         # Keep resolved alerts for 7 days
            'log_files_days': 14,              # Keep log files for 14 days
            'temp_files_days': 1,              # Clean temp files older than 1 day
            'cache_files_hours': 24,           # Clean cache files older than 24 hours
        }

    def start_monitoring(self):
        """Start resource monitoring in background thread."""
        if self.is_running:
            logger.warning("Resource monitor is already running")
            return

        self.is_running = True
        self._stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Resource monitoring started")

    def stop_monitoring(self):
        """Stop resource monitoring."""
        if not self.is_running:
            return

        self.is_running = False
        self._stop_event.set()

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)

        logger.info("Resource monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        cpu_high_start = None

        # Run cleanup once shortly after start so a stale DB gets pruned on boot.
        first_cleanup_done = False

        while self.is_running and not self._stop_event.is_set():
            try:
                # Get current resource usage
                resources = self.get_resource_usage()

                # Check thresholds and take action
                self._check_memory_usage(resources['memory_percent'])
                self._check_disk_usage(resources['disk_percent'])
                cpu_high_start = self._check_cpu_usage(resources['cpu_percent'], cpu_high_start)

                # Perform periodic cleanup (every hour) plus one initial pass
                if not first_cleanup_done or int(time.time()) % 3600 < 60:
                    self._perform_cleanup()
                    first_cleanup_done = True

                # Sleep for monitoring interval (5 minutes)
                self._stop_event.wait(300)

            except Exception as e:
                logger.error(f"Error in resource monitoring loop: {e}")
                self._stop_event.wait(60)  # Wait 1 minute before retrying

    @handle_errors()
    def get_resource_usage(self) -> Dict:
        """Get current system resource usage."""
        try:
            # Memory usage
            memory = psutil.virtual_memory()

            # Disk usage (application directory)
            app_path = Path(__file__).parent.parent
            disk = psutil.disk_usage(str(app_path))

            # CPU usage (average over 1 second)
            cpu_percent = psutil.cpu_percent(interval=1)

            # Process-specific metrics
            process = psutil.Process()
            process_memory = process.memory_info().rss / 1024 / 1024  # MB
            process_cpu = process.cpu_percent()

            # Database size (if SQLite)
            db_size = 0
            try:
                db_path = app_path / 'homeNetMon.db'
                if db_path.exists():
                    db_size = db_path.stat().st_size / 1024 / 1024  # MB
            except Exception:
                pass

            return {
                'timestamp': datetime.utcnow(),
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / 1024 / 1024 / 1024,
                'memory_used_gb': memory.used / 1024 / 1024 / 1024,
                'disk_percent': (disk.used / disk.total) * 100,
                'disk_free_gb': disk.free / 1024 / 1024 / 1024,
                'disk_used_gb': disk.used / 1024 / 1024 / 1024,
                'cpu_percent': cpu_percent,
                'process_memory_mb': process_memory,
                'process_cpu_percent': process_cpu,
                'database_size_mb': db_size,
                'load_average': os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0
            }

        except Exception as e:
            logger.error(f"Error getting resource usage: {e}")
            return {}

    def _check_memory_usage(self, memory_percent: float):
        """Check memory usage and take action if needed."""
        if memory_percent >= self.thresholds['memory_critical']:
            logger.critical(f"Critical memory usage: {memory_percent:.1f}%")
            self._emergency_cleanup()
        elif memory_percent >= self.thresholds['memory_warning']:
            logger.warning(f"High memory usage: {memory_percent:.1f}%")
            self._perform_memory_cleanup()

    def _check_disk_usage(self, disk_percent: float):
        """Check disk usage and take action if needed."""
        if disk_percent >= self.thresholds['disk_critical']:
            logger.critical(f"Critical disk usage: {disk_percent:.1f}%")
            self._emergency_disk_cleanup()
        elif disk_percent >= self.thresholds['disk_warning']:
            logger.warning(f"High disk usage: {disk_percent:.1f}%")
            self._perform_disk_cleanup()

    def _check_cpu_usage(self, cpu_percent: float, cpu_high_start: Optional[datetime]) -> Optional[datetime]:
        """Check CPU usage and track sustained high usage."""
        if cpu_percent >= self.thresholds['cpu_sustained']:
            if cpu_high_start is None:
                cpu_high_start = datetime.utcnow()
            elif (datetime.utcnow() - cpu_high_start).total_seconds() >= self.thresholds['cpu_duration']:
                logger.warning(f"Sustained high CPU usage: {cpu_percent:.1f}% for {self.thresholds['cpu_duration']} seconds")
                self._handle_high_cpu()
        else:
            cpu_high_start = None

        return cpu_high_start

    def _perform_cleanup(self):
        """Perform regular cleanup operations."""
        logger.info("Performing scheduled resource cleanup")

        try:
            self._cleanup_old_monitoring_data()
            self._cleanup_old_bandwidth_data()
            self._cleanup_old_performance_metrics()
            self._cleanup_resolved_alerts()
            self._cleanup_log_files()
            self._cleanup_temp_files()
            self._cleanup_cache_files()
            gc.collect()

        except Exception as e:
            logger.error(f"Error during regular cleanup: {e}")

    def _perform_memory_cleanup(self):
        """Perform memory-focused cleanup."""
        logger.info("Performing memory cleanup due to high usage")

        try:
            self._cleanup_old_monitoring_data(days=7)
            self._cleanup_old_bandwidth_data(days=7)
            self._cleanup_old_performance_metrics(days=7)
            self._cleanup_resolved_alerts(days=1)
            gc.collect()

        except Exception as e:
            logger.error(f"Error during memory cleanup: {e}")

    def _perform_disk_cleanup(self):
        """Perform disk-focused cleanup."""
        logger.info("Performing disk cleanup due to high usage")

        try:
            self._cleanup_old_monitoring_data(days=7)
            self._cleanup_old_bandwidth_data(days=7)
            self._cleanup_old_performance_metrics(days=7)
            self._cleanup_log_files(days=7)
            self._cleanup_temp_files(days=0)
            self._cleanup_cache_files(hours=1)

        except Exception as e:
            logger.error(f"Error during disk cleanup: {e}")

    def _emergency_cleanup(self):
        """Emergency cleanup when resources are critically low."""
        logger.critical("Performing emergency cleanup - critical resource usage")

        try:
            self._cleanup_old_monitoring_data(days=3)
            self._cleanup_old_bandwidth_data(days=3)
            self._cleanup_old_performance_metrics(days=3)
            self._cleanup_resolved_alerts(days=0)
            self._cleanup_log_files(days=3)
            self._cleanup_temp_files(days=0)
            self._cleanup_cache_files(hours=0)

            for _ in range(3):
                gc.collect()

        except Exception as e:
            logger.error(f"Error during emergency cleanup: {e}")

    def _emergency_disk_cleanup(self):
        """Emergency disk cleanup."""
        logger.critical("Performing emergency disk cleanup")
        self._emergency_cleanup()

        try:
            app_path = Path(__file__).parent.parent
            for log_file in app_path.glob("*.log*"):
                if log_file.stat().st_size > 100 * 1024 * 1024:  # >100MB
                    logger.info(f"Removing large log file: {log_file}")
                    log_file.unlink()

        except Exception as e:
            logger.error(f"Error during emergency disk cleanup: {e}")

    def _handle_high_cpu(self):
        """Handle sustained high CPU usage."""
        logger.warning("Handling sustained high CPU usage")

        try:
            if self.app and hasattr(self.app, 'monitor_service'):
                monitor_service = self.app.monitor_service
                if hasattr(monitor_service, 'reduce_monitoring_frequency'):
                    monitor_service.reduce_monitoring_frequency(duration_minutes=30)

        except Exception as e:
            logger.error(f"Error handling high CPU usage: {e}")

    def _delete_rows_older_than(self, table: str, column: str, cutoff: datetime, label: str) -> int:
        """Delete rows older than `cutoff` from `table.column`. Returns rows deleted.

        Silently skips tables that don't exist — schema variations across test
        fixtures and partially-migrated production DBs would otherwise spam the
        log on every cleanup pass.
        """
        if not self.app:
            return 0

        with self.app.app_context():
            try:
                deleted = db.session.execute(
                    text(f"DELETE FROM {table} WHERE {column} < :cutoff"),
                    {'cutoff': cutoff}
                ).rowcount
                db.session.commit()

                if deleted:
                    logger.info(f"Cleaned up {deleted} {label} older than {cutoff.isoformat()}")
                return deleted

            except Exception as e:
                db.session.rollback()
                if 'no such table' in str(e).lower():
                    logger.debug(f"Skipping {label} cleanup: table {table} not present")
                    return 0
                raise DatabaseError(f"Failed to cleanup {label}: {e}")

    @handle_errors()
    def _cleanup_old_monitoring_data(self, days: int = None):
        """Clean up old monitoring data."""
        days = days if days is not None else self.cleanup_config['old_monitoring_data_days']
        cutoff = datetime.utcnow() - timedelta(days=days)
        self._delete_rows_older_than('monitoring_data', 'timestamp', cutoff, 'monitoring records')

    @handle_errors()
    def _cleanup_old_bandwidth_data(self, days: int = None):
        """Clean up old bandwidth_data rows."""
        days = days if days is not None else self.cleanup_config['old_bandwidth_data_days']
        cutoff = datetime.utcnow() - timedelta(days=days)
        self._delete_rows_older_than('bandwidth_data', 'timestamp', cutoff, 'bandwidth records')

    @handle_errors()
    def _cleanup_old_performance_metrics(self, days: int = None):
        """Clean up old performance_metrics rows."""
        days = days if days is not None else self.cleanup_config['old_performance_metrics_days']
        cutoff = datetime.utcnow() - timedelta(days=days)
        self._delete_rows_older_than('performance_metrics', 'timestamp', cutoff, 'performance records')

    @handle_errors()
    def _cleanup_resolved_alerts(self, days: int = None):
        """Clean up resolved alerts."""
        if not self.app:
            return

        days = days if days is not None else self.cleanup_config['resolved_alerts_days']
        cutoff = datetime.utcnow() - timedelta(days=days)

        with self.app.app_context():
            try:
                deleted = db.session.execute(
                    text("DELETE FROM alerts WHERE resolved = 1 AND resolved_at < :cutoff"),
                    {'cutoff': cutoff}
                ).rowcount
                db.session.commit()

                if deleted:
                    logger.info(f"Cleaned up {deleted} resolved alerts older than {days} days")

            except Exception as e:
                db.session.rollback()
                raise DatabaseError(f"Failed to cleanup resolved alerts: {e}")

    def _cleanup_log_files(self, days: int = None):
        """Clean up old log files."""
        days = days if days is not None else self.cleanup_config['log_files_days']
        cutoff = datetime.utcnow() - timedelta(days=days)

        try:
            app_path = Path(__file__).parent.parent
            logs_path = app_path / 'logs'

            if logs_path.exists():
                cleaned = 0
                for log_file in logs_path.glob('*.log*'):
                    if log_file.stat().st_mtime < cutoff.timestamp():
                        log_file.unlink()
                        cleaned += 1

                if cleaned:
                    logger.info(f"Cleaned up {cleaned} log files older than {days} days")

        except Exception as e:
            logger.error(f"Error cleaning up log files: {e}")

    def _cleanup_temp_files(self, days: int = None):
        """Clean up temporary files."""
        days = days if days is not None else self.cleanup_config['temp_files_days']
        cutoff = datetime.utcnow() - timedelta(days=days)

        try:
            import tempfile
            temp_dirs = [tempfile.gettempdir(), '/tmp', '/var/tmp']

            cleaned = 0
            for temp_dir in temp_dirs:
                temp_path = Path(temp_dir)
                if temp_path.exists():
                    for pattern in ['homenetmon_*', 'HomeNetMon_*', '*.tmp']:
                        for temp_file in temp_path.glob(pattern):
                            try:
                                if temp_file.stat().st_mtime < cutoff.timestamp():
                                    temp_file.unlink()
                                    cleaned += 1
                            except Exception:
                                continue

            if cleaned:
                logger.info(f"Cleaned up {cleaned} temporary files older than {days} days")

        except Exception as e:
            logger.error(f"Error cleaning up temporary files: {e}")

    def _cleanup_cache_files(self, hours: int = None):
        """Clean up cache files."""
        hours = hours if hours is not None else self.cleanup_config['cache_files_hours']
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        try:
            app_path = Path(__file__).parent.parent
            bundles_path = app_path / 'static' / 'bundles'
            if bundles_path.exists():
                cleaned = 0
                for cache_file in bundles_path.glob('*.gz'):
                    if cache_file.stat().st_mtime < cutoff.timestamp():
                        cache_file.unlink()
                        cleaned += 1

                if cleaned:
                    logger.info(f"Cleaned up {cleaned} cache files older than {hours} hours")

        except Exception as e:
            logger.error(f"Error cleaning up cache files: {e}")

    @handle_errors()
    def get_cleanup_recommendations(self) -> List[Dict]:
        """Get recommendations for cleanup based on current resource usage."""
        recommendations = []

        try:
            resources = self.get_resource_usage()

            if resources.get('memory_percent', 0) > 70:
                recommendations.append({
                    'type': 'memory',
                    'severity': 'medium',
                    'action': 'cleanup_monitoring_data',
                    'description': 'High memory usage detected. Consider cleaning old monitoring data.'
                })

            if resources.get('disk_percent', 0) > 80:
                recommendations.append({
                    'type': 'disk',
                    'severity': 'high',
                    'action': 'cleanup_logs_and_cache',
                    'description': 'High disk usage detected. Clean up log files and cache.'
                })

            if resources.get('database_size_mb', 0) > 500:
                recommendations.append({
                    'type': 'database',
                    'severity': 'medium',
                    'action': 'optimize_database',
                    'description': 'Large database size. Consider optimizing and cleaning old data.'
                })

        except Exception as e:
            logger.error(f"Error getting cleanup recommendations: {e}")

        return recommendations

    def health_check(self) -> Dict:
        """Get resource monitor health status."""
        try:
            resources = self.get_resource_usage()

            status = 'healthy'
            issues = []

            if resources.get('memory_percent', 0) > self.thresholds['memory_warning']:
                status = 'warning'
                issues.append(f"High memory usage: {resources.get('memory_percent', 0):.1f}%")

            if resources.get('disk_percent', 0) > self.thresholds['disk_warning']:
                status = 'warning' if status != 'critical' else 'critical'
                issues.append(f"High disk usage: {resources.get('disk_percent', 0):.1f}%")

            if resources.get('memory_percent', 0) > self.thresholds['memory_critical'] or \
               resources.get('disk_percent', 0) > self.thresholds['disk_critical']:
                status = 'critical'

            return {
                'status': status,
                'is_running': self.is_running,
                'resources': resources,
                'issues': issues,
                'thresholds': self.thresholds
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'is_running': self.is_running
            }


# Global resource monitor instance
global_resource_monitor = ResourceMonitor()
