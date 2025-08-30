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
        
        while self.is_running and not self._stop_event.is_set():
            try:
                # Get current resource usage
                resources = self.get_resource_usage()
                
                # Check thresholds and take action
                self._check_memory_usage(resources['memory_percent'])
                self._check_disk_usage(resources['disk_percent'])
                cpu_high_start = self._check_cpu_usage(resources['cpu_percent'], cpu_high_start)
                
                # Perform periodic cleanup (every hour)
                if int(time.time()) % 3600 < 60:  # Within first minute of hour
                    self._perform_cleanup()
                    
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
            except:
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
            # Clean old monitoring data
            self._cleanup_old_monitoring_data()
            
            # Clean resolved alerts
            self._cleanup_resolved_alerts()
            
            # Clean log files
            self._cleanup_log_files()
            
            # Clean temporary files
            self._cleanup_temp_files()
            
            # Clean cache files
            self._cleanup_cache_files()
            
            # Force garbage collection
            gc.collect()
            
        except Exception as e:
            logger.error(f"Error during regular cleanup: {e}")
            
    def _perform_memory_cleanup(self):
        """Perform memory-focused cleanup."""
        logger.info("Performing memory cleanup due to high usage")
        
        try:
            # Clean old monitoring data more aggressively
            self._cleanup_old_monitoring_data(days=7)  # Keep only 7 days instead of 30
            
            # Clean resolved alerts more aggressively
            self._cleanup_resolved_alerts(days=1)  # Keep only 1 day instead of 7
            
            # Force garbage collection
            gc.collect()
            
        except Exception as e:
            logger.error(f"Error during memory cleanup: {e}")
            
    def _perform_disk_cleanup(self):
        """Perform disk-focused cleanup."""
        logger.info("Performing disk cleanup due to high usage")
        
        try:
            # Clean old monitoring data aggressively
            self._cleanup_old_monitoring_data(days=7)
            
            # Clean log files
            self._cleanup_log_files(days=7)
            
            # Clean all temporary files
            self._cleanup_temp_files(days=0)
            
            # Clean cache files
            self._cleanup_cache_files(hours=1)
            
        except Exception as e:
            logger.error(f"Error during disk cleanup: {e}")
            
    def _emergency_cleanup(self):
        """Emergency cleanup when resources are critically low."""
        logger.critical("Performing emergency cleanup - critical resource usage")
        
        try:
            # Aggressive data cleanup
            self._cleanup_old_monitoring_data(days=3)  # Keep only 3 days
            self._cleanup_resolved_alerts(days=0)      # Remove all resolved alerts
            self._cleanup_log_files(days=3)            # Keep only 3 days of logs
            self._cleanup_temp_files(days=0)           # Remove all temp files
            self._cleanup_cache_files(hours=0)         # Remove all cache files
            
            # Force garbage collection multiple times
            for _ in range(3):
                gc.collect()
                
        except Exception as e:
            logger.error(f"Error during emergency cleanup: {e}")
            
    def _emergency_disk_cleanup(self):
        """Emergency disk cleanup."""
        logger.critical("Performing emergency disk cleanup")
        self._emergency_cleanup()
        
        # Additional disk-specific cleanup
        try:
            # Clean database logs if they exist
            app_path = Path(__file__).parent.parent
            for log_file in app_path.glob("*.log*"):
                if log_file.stat().st_size > 100 * 1024 * 1024:  # Files larger than 100MB
                    logger.info(f"Removing large log file: {log_file}")
                    log_file.unlink()
                    
        except Exception as e:
            logger.error(f"Error during emergency disk cleanup: {e}")
            
    def _handle_high_cpu(self):
        """Handle sustained high CPU usage."""
        logger.warning("Handling sustained high CPU usage")
        
        try:
            # Reduce monitoring frequency temporarily
            if self.app and hasattr(self.app, 'monitor_service'):
                monitor_service = self.app.monitor_service
                if hasattr(monitor_service, 'reduce_monitoring_frequency'):
                    monitor_service.reduce_monitoring_frequency(duration_minutes=30)
                    
        except Exception as e:
            logger.error(f"Error handling high CPU usage: {e}")
            
    @handle_errors()
    def _cleanup_old_monitoring_data(self, days: int = None):
        """Clean up old monitoring data."""
        if not self.app:
            return
            
        days = days or self.cleanup_config['old_monitoring_data_days']
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        with self.app.app_context():
            try:
                deleted_count = db.session.execute(\n                    text(\"DELETE FROM monitoring_data WHERE timestamp < :cutoff_date\"),\n                    {'cutoff_date': cutoff_date}\n                ).rowcount\n                \n                db.session.commit()\n                \n                if deleted_count > 0:\n                    logger.info(f\"Cleaned up {deleted_count} monitoring records older than {days} days\")\n                    \n            except Exception as e:\n                db.session.rollback()\n                raise DatabaseError(f\"Failed to cleanup monitoring data: {e}\")\n                \n    @handle_errors()\n    def _cleanup_resolved_alerts(self, days: int = None):\n        \"\"\"Clean up resolved alerts.\"\"\"\n        if not self.app:\n            return\n            \n        days = days or self.cleanup_config['resolved_alerts_days']\n        cutoff_date = datetime.utcnow() - timedelta(days=days)\n        \n        with self.app.app_context():\n            try:\n                deleted_count = db.session.execute(\n                    text(\"DELETE FROM alerts WHERE resolved = 1 AND resolved_at < :cutoff_date\"),\n                    {'cutoff_date': cutoff_date}\n                ).rowcount\n                \n                db.session.commit()\n                \n                if deleted_count > 0:\n                    logger.info(f\"Cleaned up {deleted_count} resolved alerts older than {days} days\")\n                    \n            except Exception as e:\n                db.session.rollback()\n                raise DatabaseError(f\"Failed to cleanup resolved alerts: {e}\")\n                \n    def _cleanup_log_files(self, days: int = None):\n        \"\"\"Clean up old log files.\"\"\"\n        days = days or self.cleanup_config['log_files_days']\n        cutoff_date = datetime.utcnow() - timedelta(days=days)\n        \n        try:\n            app_path = Path(__file__).parent.parent\n            logs_path = app_path / 'logs'\n            \n            if logs_path.exists():\n                cleaned_count = 0\n                for log_file in logs_path.glob('*.log*'):\n                    if log_file.stat().st_mtime < cutoff_date.timestamp():\n                        log_file.unlink()\n                        cleaned_count += 1\n                        \n                if cleaned_count > 0:\n                    logger.info(f\"Cleaned up {cleaned_count} log files older than {days} days\")\n                    \n        except Exception as e:\n            logger.error(f\"Error cleaning up log files: {e}\")\n            \n    def _cleanup_temp_files(self, days: int = None):\n        \"\"\"Clean up temporary files.\"\"\"\n        days = days or self.cleanup_config['temp_files_days']\n        cutoff_date = datetime.utcnow() - timedelta(days=days)\n        \n        try:\n            import tempfile\n            temp_dirs = [tempfile.gettempdir(), '/tmp', '/var/tmp']\n            \n            cleaned_count = 0\n            for temp_dir in temp_dirs:\n                temp_path = Path(temp_dir)\n                if temp_path.exists():\n                    # Only clean files related to HomeNetMon\n                    for pattern in ['homenetmon_*', 'HomeNetMon_*', '*.tmp']:\n                        for temp_file in temp_path.glob(pattern):\n                            try:\n                                if temp_file.stat().st_mtime < cutoff_date.timestamp():\n                                    temp_file.unlink()\n                                    cleaned_count += 1\n                            except:\n                                continue  # Skip files we can't access\n                                \n            if cleaned_count > 0:\n                logger.info(f\"Cleaned up {cleaned_count} temporary files older than {days} days\")\n                \n        except Exception as e:\n            logger.error(f\"Error cleaning up temporary files: {e}\")\n            \n    def _cleanup_cache_files(self, hours: int = None):\n        \"\"\"Clean up cache files.\"\"\"\n        hours = hours or self.cleanup_config['cache_files_hours']\n        cutoff_date = datetime.utcnow() - timedelta(hours=hours)\n        \n        try:\n            app_path = Path(__file__).parent.parent\n            \n            # Clean bundle cache files\n            bundles_path = app_path / 'static' / 'bundles'\n            if bundles_path.exists():\n                cleaned_count = 0\n                for cache_file in bundles_path.glob('*.gz'):\n                    if cache_file.stat().st_mtime < cutoff_date.timestamp():\n                        cache_file.unlink()\n                        cleaned_count += 1\n                        \n                if cleaned_count > 0:\n                    logger.info(f\"Cleaned up {cleaned_count} cache files older than {hours} hours\")\n                    \n        except Exception as e:\n            logger.error(f\"Error cleaning up cache files: {e}\")\n            \n    @handle_errors()\n    def get_cleanup_recommendations(self) -> List[Dict]:\n        \"\"\"Get recommendations for cleanup based on current resource usage.\"\"\"\n        recommendations = []\n        \n        try:\n            resources = self.get_resource_usage()\n            \n            if resources.get('memory_percent', 0) > 70:\n                recommendations.append({\n                    'type': 'memory',\n                    'severity': 'medium',\n                    'action': 'cleanup_monitoring_data',\n                    'description': 'High memory usage detected. Consider cleaning old monitoring data.'\n                })\n                \n            if resources.get('disk_percent', 0) > 80:\n                recommendations.append({\n                    'type': 'disk',\n                    'severity': 'high',\n                    'action': 'cleanup_logs_and_cache',\n                    'description': 'High disk usage detected. Clean up log files and cache.'\n                })\n                \n            if resources.get('database_size_mb', 0) > 500:\n                recommendations.append({\n                    'type': 'database',\n                    'severity': 'medium',\n                    'action': 'optimize_database',\n                    'description': 'Large database size. Consider optimizing and cleaning old data.'\n                })\n                \n        except Exception as e:\n            logger.error(f\"Error getting cleanup recommendations: {e}\")\n            \n        return recommendations\n        \n    def health_check(self) -> Dict:\n        \"\"\"Get resource monitor health status.\"\"\"\n        try:\n            resources = self.get_resource_usage()\n            \n            status = 'healthy'\n            issues = []\n            \n            if resources.get('memory_percent', 0) > self.thresholds['memory_warning']:\n                status = 'warning'\n                issues.append(f\"High memory usage: {resources.get('memory_percent', 0):.1f}%\")\n                \n            if resources.get('disk_percent', 0) > self.thresholds['disk_warning']:\n                status = 'warning' if status != 'critical' else 'critical'\n                issues.append(f\"High disk usage: {resources.get('disk_percent', 0):.1f}%\")\n                \n            if resources.get('memory_percent', 0) > self.thresholds['memory_critical'] or \\\n               resources.get('disk_percent', 0) > self.thresholds['disk_critical']:\n                status = 'critical'\n                \n            return {\n                'status': status,\n                'is_running': self.is_running,\n                'resources': resources,\n                'issues': issues,\n                'thresholds': self.thresholds\n            }\n            \n        except Exception as e:\n            return {\n                'status': 'error',\n                'error': str(e),\n                'is_running': self.is_running\n            }\n\n\n# Global resource monitor instance\nglobal_resource_monitor = ResourceMonitor()