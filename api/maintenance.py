"""
Database and Site Maintenance API
Provides user-friendly maintenance operations for HomeNetMon.
"""

import os
import time
import psutil
import logging
import sqlite3
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from sqlalchemy import text, func
from models import db, Device, MonitoringData, Alert, PerformanceMetrics
from core.db_config import DatabaseOptimizer
from services.query_cache import query_cache
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)
maintenance_bp = Blueprint('maintenance', __name__)

@maintenance_bp.route('/database/health', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_database_health():
    """Get comprehensive database health information."""
    try:
        # Get database file stats
        db_file = 'homeNetMon.db'
        db_stats = {}
        
        if os.path.exists(db_file):
            db_size = os.path.getsize(db_file)
            db_stats = {
                'size_bytes': db_size,
                'size_mb': round(db_size / 1024**2, 2),
                'size_gb': round(db_size / 1024**3, 3)
            }
        
        # Get record counts
        total_monitoring = db.session.query(func.count(MonitoringData.id)).scalar() or 0
        total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
        total_devices = db.session.query(func.count(Device.id)).scalar() or 0
        
        # Get oldest and newest records
        oldest_record = db.session.query(func.min(MonitoringData.timestamp)).scalar()
        newest_record = db.session.query(func.max(MonitoringData.timestamp)).scalar()
        
        # Calculate data retention info
        if oldest_record:
            data_span_days = (datetime.utcnow() - oldest_record).days
        else:
            data_span_days = 0
        
        # Get disk space
        disk_usage = psutil.disk_usage(os.getcwd())
        
        return jsonify({
            'success': True,
            'database': db_stats,
            'records': {
                'monitoring_data': total_monitoring,
                'alerts': total_alerts,
                'devices': total_devices,
                'data_span_days': data_span_days,
                'oldest_record': oldest_record.isoformat() if oldest_record else None,
                'newest_record': newest_record.isoformat() if newest_record else None
            },
            'disk_space': {
                'total_gb': round(disk_usage.total / 1024**3, 2),
                'used_gb': round(disk_usage.used / 1024**3, 2),
                'free_gb': round(disk_usage.free / 1024**3, 2),
                'percent_used': round((disk_usage.used / disk_usage.total) * 100, 1)
            },
            'recommendations': _get_maintenance_recommendations(db_stats.get('size_mb', 0), 
                                                              total_monitoring, data_span_days)
        })
        
    except Exception as e:
        logger.error(f"Error getting database health: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@maintenance_bp.route('/database/cleanup', methods=['POST'])
@create_endpoint_limiter('strict')
def manual_database_cleanup():
    """Perform manual database cleanup with progress feedback."""
    try:
        data = request.get_json() or {}
        retention_days = data.get('retention_days', 7)
        
        # Validate retention days
        if not isinstance(retention_days, int) or retention_days < 1 or retention_days > 365:
            return jsonify({
                'success': False,
                'error': 'Retention days must be between 1 and 365'
            }), 400
        
        logger.info(f"Starting manual database cleanup with {retention_days} days retention")
        
        # Get initial stats
        initial_size = os.path.getsize('homeNetMon.db') if os.path.exists('homeNetMon.db') else 0
        initial_monitoring = db.session.query(func.count(MonitoringData.id)).scalar() or 0
        initial_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Clean monitoring data
        monitoring_deleted = db.session.query(MonitoringData).filter(
            MonitoringData.timestamp < cutoff_date
        ).delete(synchronize_session=False)
        
        # Clean resolved alerts older than cutoff
        alerts_deleted = db.session.query(Alert).filter(
            Alert.created_at < cutoff_date,
            Alert.resolved == True
        ).delete(synchronize_session=False)
        
        # Clean performance metrics if they exist
        perf_deleted = 0
        try:
            perf_deleted = db.session.query(PerformanceMetrics).filter(
                PerformanceMetrics.timestamp < cutoff_date
            ).delete(synchronize_session=False)
        except Exception as e:
            logger.warning(f"Performance metrics cleanup failed: {e}")
        
        db.session.commit()
        
        # Clear query cache after cleanup
        query_cache.clear()
        
        # Get final stats
        final_size = os.path.getsize('homeNetMon.db') if os.path.exists('homeNetMon.db') else 0
        final_monitoring = db.session.query(func.count(MonitoringData.id)).scalar() or 0
        final_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
        
        space_saved = initial_size - final_size
        space_saved_mb = round(space_saved / 1024**2, 2)
        
        logger.info(f"Manual cleanup complete: {monitoring_deleted + alerts_deleted + perf_deleted} records deleted, {space_saved_mb}MB saved")
        
        return jsonify({
            'success': True,
            'message': f'Database cleanup completed successfully',
            'details': {
                'retention_days': retention_days,
                'records_deleted': {
                    'monitoring_data': monitoring_deleted,
                    'alerts': alerts_deleted,
                    'performance_metrics': perf_deleted,
                    'total': monitoring_deleted + alerts_deleted + perf_deleted
                },
                'records_remaining': {
                    'monitoring_data': final_monitoring,
                    'alerts': final_alerts
                },
                'space_saved': {
                    'bytes': space_saved,
                    'mb': space_saved_mb,
                    'gb': round(space_saved / 1024**3, 3)
                },
                'database_size_after': {
                    'bytes': final_size,
                    'mb': round(final_size / 1024**2, 2)
                },
                'cleanup_time': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during manual database cleanup: {e}")
        return jsonify({
            'success': False,
            'error': f'Database cleanup failed: {str(e)}'
        }), 500

@maintenance_bp.route('/database/optimize', methods=['POST'])
@create_endpoint_limiter('critical')
def manual_database_optimize():
    """Perform manual database optimization (VACUUM/ANALYZE)."""
    try:
        data = request.get_json() or {}
        operations = data.get('operations', ['vacuum', 'analyze'])
        
        logger.info(f"Starting manual database optimization: {operations}")
        
        # Get initial size
        initial_size = os.path.getsize('homeNetMon.db') if os.path.exists('homeNetMon.db') else 0
        
        optimizer = DatabaseOptimizer(db)
        results = {}
        
        # Run VACUUM if requested
        if 'vacuum' in operations:
            start_time = time.time()
            vacuum_result = optimizer.vacuum_database()
            vacuum_time = time.time() - start_time
            results['vacuum'] = {
                'success': vacuum_result,
                'duration_seconds': round(vacuum_time, 2)
            }
        
        # Run ANALYZE if requested
        if 'analyze' in operations:
            start_time = time.time()
            analyze_result = optimizer.analyze_database()
            analyze_time = time.time() - start_time
            results['analyze'] = {
                'success': analyze_result,
                'duration_seconds': round(analyze_time, 2)
            }
        
        # Get final size and calculate space saved
        final_size = os.path.getsize('homeNetMon.db') if os.path.exists('homeNetMon.db') else 0
        space_saved = initial_size - final_size
        space_saved_mb = round(space_saved / 1024**2, 2)
        
        # Clear query cache after optimization
        query_cache.clear()
        
        logger.info(f"Manual optimization complete: {space_saved_mb}MB saved")
        
        return jsonify({
            'success': True,
            'message': f'Database optimization completed successfully',
            'details': {
                'operations_requested': operations,
                'results': results,
                'space_saved': {
                    'bytes': space_saved,
                    'mb': space_saved_mb,
                    'gb': round(space_saved / 1024**3, 3)
                },
                'database_size_before_mb': round(initial_size / 1024**2, 2),
                'database_size_after_mb': round(final_size / 1024**2, 2),
                'optimization_time': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error during manual database optimization: {e}")
        return jsonify({
            'success': False,
            'error': f'Database optimization failed: {str(e)}'
        }), 500

@maintenance_bp.route('/system/health-check', methods=['POST'])
@create_endpoint_limiter('strict')
def manual_health_check():
    """Perform comprehensive system health check."""
    try:
        logger.info("Starting manual system health check")
        
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'checks': {}
        }
        
        # Database connectivity
        try:
            db.session.execute(text('SELECT 1'))
            health_report['checks']['database'] = {
                'status': 'healthy',
                'message': 'Database connection working'
            }
        except Exception as e:
            health_report['checks']['database'] = {
                'status': 'unhealthy',
                'message': f'Database connection failed: {str(e)}'
            }
            health_report['overall_status'] = 'unhealthy'
        
        # System resources
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(os.getcwd())
            
            # CPU check
            if cpu_percent > 80:
                health_report['checks']['cpu'] = {
                    'status': 'warning',
                    'message': f'High CPU usage: {cpu_percent:.1f}%'
                }
            else:
                health_report['checks']['cpu'] = {
                    'status': 'healthy',
                    'message': f'CPU usage normal: {cpu_percent:.1f}%'
                }
            
            # Memory check
            if memory.percent > 85:
                health_report['checks']['memory'] = {
                    'status': 'warning',
                    'message': f'High memory usage: {memory.percent:.1f}%'
                }
            else:
                health_report['checks']['memory'] = {
                    'status': 'healthy',
                    'message': f'Memory usage normal: {memory.percent:.1f}%'
                }
            
            # Disk space check
            if disk.percent > 90:
                health_report['checks']['disk_space'] = {
                    'status': 'critical',
                    'message': f'Low disk space: {disk.percent:.1f}% used'
                }
                health_report['overall_status'] = 'unhealthy'
            elif disk.percent > 80:
                health_report['checks']['disk_space'] = {
                    'status': 'warning',
                    'message': f'Disk space getting low: {disk.percent:.1f}% used'
                }
            else:
                health_report['checks']['disk_space'] = {
                    'status': 'healthy',
                    'message': f'Disk space good: {disk.percent:.1f}% used'
                }
                
        except Exception as e:
            health_report['checks']['system_resources'] = {
                'status': 'error',
                'message': f'Could not check system resources: {str(e)}'
            }
        
        # Service health checks
        try:
            # Check if monitoring services are responding
            device_count = db.session.query(func.count(Device.id)).scalar()
            recent_monitoring = db.session.query(func.count(MonitoringData.id)).filter(
                MonitoringData.timestamp > datetime.utcnow() - timedelta(minutes=10)
            ).scalar()
            
            if device_count > 0 and recent_monitoring > 0:
                health_report['checks']['monitoring_service'] = {
                    'status': 'healthy',
                    'message': f'Monitoring active: {recent_monitoring} checks in last 10 minutes'
                }
            elif device_count > 0:
                health_report['checks']['monitoring_service'] = {
                    'status': 'warning',
                    'message': 'No recent monitoring data - service may be stopped'
                }
            else:
                health_report['checks']['monitoring_service'] = {
                    'status': 'info',
                    'message': 'No devices configured for monitoring'
                }
                
        except Exception as e:
            health_report['checks']['monitoring_service'] = {
                'status': 'error',
                'message': f'Could not check monitoring service: {str(e)}'
            }
        
        # Determine final overall status
        if any(check['status'] == 'critical' for check in health_report['checks'].values()):
            health_report['overall_status'] = 'critical'
        elif any(check['status'] == 'unhealthy' for check in health_report['checks'].values()):
            health_report['overall_status'] = 'unhealthy'
        elif any(check['status'] == 'warning' for check in health_report['checks'].values()):
            health_report['overall_status'] = 'warning'
        
        logger.info(f"Manual health check complete: {health_report['overall_status']}")
        
        return jsonify({
            'success': True,
            'health_report': health_report
        })
        
    except Exception as e:
        logger.error(f"Error during manual health check: {e}")
        return jsonify({
            'success': False,
            'error': f'Health check failed: {str(e)}'
        }), 500

@maintenance_bp.route('/system/resources', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_system_resources():
    """Get current system resource utilization."""
    try:
        # CPU information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory information
        memory = psutil.virtual_memory()
        
        # Disk information
        disk = psutil.disk_usage(os.getcwd())
        
        # Network I/O
        net_io = psutil.net_io_counters()
        
        # Process information
        current_process = psutil.Process()
        app_memory_mb = round(current_process.memory_info().rss / 1024**2, 1)
        
        return jsonify({
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'cpu': {
                'percent': round(cpu_percent, 1),
                'cores': cpu_count,
                'status': 'critical' if cpu_percent > 80 else 'warning' if cpu_percent > 60 else 'healthy'
            },
            'memory': {
                'total_gb': round(memory.total / 1024**3, 2),
                'used_gb': round(memory.used / 1024**3, 2),
                'available_gb': round(memory.available / 1024**3, 2),
                'percent': round(memory.percent, 1),
                'app_memory_mb': app_memory_mb,
                'status': 'critical' if memory.percent > 85 else 'warning' if memory.percent > 70 else 'healthy'
            },
            'disk': {
                'total_gb': round(disk.total / 1024**3, 2),
                'used_gb': round(disk.used / 1024**3, 2),
                'free_gb': round(disk.free / 1024**3, 2),
                'percent': round(disk.percent, 1),
                'status': 'critical' if disk.percent > 90 else 'warning' if disk.percent > 80 else 'healthy'
            },
            'network': {
                'bytes_sent_mb': round(net_io.bytes_sent / 1024**2, 2),
                'bytes_recv_mb': round(net_io.bytes_recv / 1024**2, 2)
            } if net_io else None
        })
        
    except Exception as e:
        logger.error(f"Error getting system resources: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@maintenance_bp.route('/logs/cleanup', methods=['POST'])
@create_endpoint_limiter('strict')
def cleanup_logs():
    """Clean up old log files to free space."""
    try:
        data = request.get_json() or {}
        days_to_keep = data.get('days_to_keep', 7)
        
        logger.info(f"Starting log cleanup: keeping {days_to_keep} days")
        
        # Find log files
        log_files = []
        log_extensions = ['.log', '.log.1', '.log.2', '.log.3']
        current_dir = os.getcwd()
        
        total_size_before = 0
        files_cleaned = 0
        
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        # Look for log files in common locations
        for root, dirs, files in os.walk(current_dir):
            for file in files:
                if any(file.endswith(ext) for ext in log_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        file_stat = os.stat(file_path)
                        file_mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                        file_size = file_stat.st_size
                        total_size_before += file_size
                        
                        # Delete old log files
                        if file_mod_time < cutoff_date and file_size > 0:
                            os.remove(file_path)
                            files_cleaned += 1
                            logger.info(f"Deleted old log file: {file_path}")
                            
                    except (OSError, IOError) as e:
                        logger.warning(f"Could not process log file {file_path}: {e}")
        
        space_saved_mb = round((total_size_before) / 1024**2, 2)  # Approximation
        
        return jsonify({
            'success': True,
            'message': f'Log cleanup completed',
            'details': {
                'days_kept': days_to_keep,
                'files_cleaned': files_cleaned,
                'estimated_space_saved_mb': space_saved_mb,
                'cleanup_time': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error during log cleanup: {e}")
        return jsonify({
            'success': False,
            'error': f'Log cleanup failed: {str(e)}'
        }), 500

def _get_maintenance_recommendations(db_size_mb, total_monitoring, data_span_days):
    """Generate maintenance recommendations based on current state."""
    recommendations = []
    
    # Database size recommendations
    if db_size_mb > 500:
        recommendations.append({
            'type': 'warning',
            'category': 'database_size',
            'message': f'Database is large ({db_size_mb}MB). Consider reducing data retention period.',
            'action': 'cleanup'
        })
    elif db_size_mb > 1000:
        recommendations.append({
            'type': 'critical',
            'category': 'database_size', 
            'message': f'Database is very large ({db_size_mb}MB). Cleanup recommended immediately.',
            'action': 'cleanup'
        })
    
    # Data retention recommendations
    if data_span_days > 60:
        recommendations.append({
            'type': 'info',
            'category': 'data_retention',
            'message': f'You have {data_span_days} days of data. Consider optimizing database.',
            'action': 'optimize'
        })
    
    # Record count recommendations
    if total_monitoring > 100000:
        recommendations.append({
            'type': 'info',
            'category': 'record_count',
            'message': f'Large number of monitoring records ({total_monitoring:,}). Regular cleanup recommended.',
            'action': 'cleanup'
        })
    
    # Default recommendations if none
    if not recommendations:
        recommendations.append({
            'type': 'success',
            'category': 'general',
            'message': 'Database health looks good! Consider running optimization monthly.',
            'action': 'optimize'
        })
    
    return recommendations