"""
Comprehensive health check endpoints with detailed system status.
"""

import logging
import time
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List
from flask import Blueprint, jsonify, current_app
from sqlalchemy import text
from models import db, Device, Alert, MonitoringData
from core.cache_layer import get_cache_health, global_cache
from core.query_profiler import global_profiler
from core.db_config import ConnectionPoolMonitor
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

health_check_bp = Blueprint('health_check', __name__)

@health_check_bp.route('/health', methods=['GET'])
@create_endpoint_limiter('relaxed')
def basic_health_check():
    """Basic health check endpoint."""
    try:
        # Simple database connectivity test
        db.session.execute(text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'HomeNetMon'
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'HomeNetMon',
            'error': str(e)
        }), 503

@health_check_bp.route('/health/detailed', methods=['GET'])
@create_endpoint_limiter('relaxed')
def detailed_health_check():
    """Detailed health check with component status."""
    try:
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'HomeNetMon',
            'checks': {}
        }
        
        overall_healthy = True
        
        # Database health
        db_health = _check_database_health()
        health_data['checks']['database'] = db_health
        if not db_health['healthy']:
            overall_healthy = False
            
        # Cache health
        cache_health = _check_cache_health()
        health_data['checks']['cache'] = cache_health
        if not cache_health['healthy']:
            overall_healthy = False
            
        # System resources health
        system_health = _check_system_health()
        health_data['checks']['system'] = system_health
        if not system_health['healthy']:
            overall_healthy = False
            
        # Application services health
        services_health = _check_services_health()
        health_data['checks']['services'] = services_health
        if not services_health['healthy']:
            overall_healthy = False
            
        # Monitoring health
        monitoring_health = _check_monitoring_health()
        health_data['checks']['monitoring'] = monitoring_health
        if not monitoring_health['healthy']:
            overall_healthy = False
            
        health_data['status'] = 'healthy' if overall_healthy else 'unhealthy'
        
        return jsonify(health_data), 200 if overall_healthy else 503
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 503

@health_check_bp.route('/health/database', methods=['GET'])
@create_endpoint_limiter('relaxed')
def database_health_check():
    """Database-specific health check."""
    return jsonify(_check_database_health())

@health_check_bp.route('/health/system', methods=['GET'])
@create_endpoint_limiter('relaxed')
def system_health_check():
    """System resources health check."""
    return jsonify(_check_system_health())

@health_check_bp.route('/health/monitoring', methods=['GET'])
@create_endpoint_limiter('relaxed')
def monitoring_health_check():
    """Monitoring services health check."""
    return jsonify(_check_monitoring_health())

@health_check_bp.route('/readiness', methods=['GET'])
@create_endpoint_limiter('relaxed')
def readiness_probe():
    """Kubernetes readiness probe endpoint."""
    try:
        # Check critical dependencies
        db.session.execute(text('SELECT 1'))
        
        # Check if monitoring data is recent
        latest_data = MonitoringData.query.order_by(
            MonitoringData.timestamp.desc()
        ).first()
        
        if latest_data:
            age = (datetime.utcnow() - latest_data.timestamp).total_seconds()
            if age > 600:  # No data in last 10 minutes
                return jsonify({
                    'status': 'not_ready',
                    'reason': 'No recent monitoring data'
                }), 503
                
        return jsonify({
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'not_ready',
            'error': str(e)
        }), 503

@health_check_bp.route('/liveness', methods=['GET'])
@create_endpoint_limiter('relaxed')
def liveness_probe():
    """Kubernetes liveness probe endpoint."""
    try:
        # Basic application responsiveness test
        start_time = time.time()
        test_value = sum(range(1000))  # Simple CPU test
        response_time = time.time() - start_time
        
        if response_time > 5.0:  # Application is too slow
            return jsonify({
                'status': 'not_alive',
                'reason': f'Response time too slow: {response_time:.2f}s'
            }), 503
            
        return jsonify({
            'status': 'alive',
            'response_time_ms': round(response_time * 1000, 2)
        })
        
    except Exception as e:
        return jsonify({
            'status': 'not_alive',
            'error': str(e)
        }), 503

@health_check_bp.route('/health/dependencies', methods=['GET'])
@create_endpoint_limiter('relaxed')
def dependencies_health_check():
    """Check health of external dependencies."""
    dependencies = {
        'timestamp': datetime.utcnow().isoformat(),
        'dependencies': {}
    }
    
    all_healthy = True
    
    # Check database
    db_result = _test_database_connection()
    dependencies['dependencies']['database'] = db_result
    if not db_result['available']:
        all_healthy = False
        
    # Check network connectivity
    network_result = _test_network_connectivity()
    dependencies['dependencies']['network'] = network_result
    if not network_result['available']:
        all_healthy = False
        
    # Check system resources
    resources_result = _check_critical_resources()
    dependencies['dependencies']['resources'] = resources_result
    if not resources_result['available']:
        all_healthy = False
        
    dependencies['status'] = 'healthy' if all_healthy else 'unhealthy'
    
    return jsonify(dependencies), 200 if all_healthy else 503

@health_check_bp.route('/metrics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def application_metrics():
    """Application metrics endpoint."""
    try:
        metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'uptime_seconds': _get_application_uptime(),
            'database': _get_database_metrics(),
            'cache': _get_cache_metrics(),
            'system': _get_system_metrics(),
            'monitoring': _get_monitoring_metrics(),
            'performance': _get_performance_metrics()
        }
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Failed to get application metrics: {e}")
        return jsonify({'error': 'Failed to retrieve metrics'}), 500

def _check_database_health() -> Dict[str, Any]:
    """Check database health."""
    try:
        start_time = time.time()
        
        # Test basic connectivity
        db.session.execute(text('SELECT 1'))
        
        # Test read operations
        device_count = Device.query.count()
        alert_count = Alert.query.count()
        
        # Check for recent monitoring data
        latest_data = MonitoringData.query.order_by(
            MonitoringData.timestamp.desc()
        ).first()
        
        response_time = time.time() - start_time
        
        # Check connection pool
        pool_monitor = ConnectionPoolMonitor(db)
        pool_health = pool_monitor.check_health()
        
        return {
            'healthy': pool_health[0],
            'response_time_ms': round(response_time * 1000, 2),
            'device_count': device_count,
            'alert_count': alert_count,
            'latest_data_age_seconds': (
                (datetime.utcnow() - latest_data.timestamp).total_seconds()
                if latest_data else None
            ),
            'connection_pool': {
                'status': 'healthy' if pool_health[0] else 'unhealthy',
                'message': pool_health[1]
            }
        }
        
    except Exception as e:
        return {
            'healthy': False,
            'error': str(e),
            'response_time_ms': None
        }

def _check_cache_health() -> Dict[str, Any]:
    """Check cache system health."""
    try:
        cache_health = get_cache_health()
        
        return {
            'healthy': cache_health['status'] == 'healthy',
            'status': cache_health['status'],
            'hit_rate_percent': cache_health['statistics']['hit_rate_percent'],
            'utilization_percent': cache_health['utilization_percent'],
            'issues': cache_health.get('issues', [])
        }
        
    except Exception as e:
        return {
            'healthy': False,
            'error': str(e)
        }

def _check_system_health() -> Dict[str, Any]:
    """Check system resource health."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_healthy = cpu_percent < 90
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_healthy = memory.percent < 90
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_healthy = disk.percent < 90
        
        # Load average
        load_avg = os.getloadavg()
        cpu_count = psutil.cpu_count()
        load_healthy = load_avg[0] < cpu_count * 2
        
        overall_healthy = all([cpu_healthy, memory_healthy, disk_healthy, load_healthy])
        
        return {
            'healthy': overall_healthy,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'load_average_1m': load_avg[0],
            'cpu_count': cpu_count,
            'thresholds': {
                'cpu_threshold': 90,
                'memory_threshold': 90,
                'disk_threshold': 90,
                'load_threshold': cpu_count * 2
            }
        }
        
    except Exception as e:
        return {
            'healthy': False,
            'error': str(e)
        }

def _check_services_health() -> Dict[str, Any]:
    """Check application services health."""
    try:
        # Check if application instance has service manager
        app_instance = getattr(current_app, 'application_instance', None)
        
        if not app_instance:
            return {
                'healthy': False,
                'error': 'Application instance not available'
            }
            
        services_healthy = True
        service_statuses = {}
        
        # Check service manager
        if hasattr(app_instance, 'service_manager'):
            service_health = app_instance.service_manager.health_check()
            service_statuses['service_manager'] = service_health
            if service_health['health'] != 'healthy':
                services_healthy = False
        
        # Check WebSocket manager
        if hasattr(app_instance, 'websocket_optimizer'):
            ws_health = app_instance.websocket_optimizer.health_check()
            service_statuses['websocket_optimizer'] = ws_health
            if ws_health['status'] != 'healthy':
                services_healthy = False
                
        return {
            'healthy': services_healthy,
            'services': service_statuses
        }
        
    except Exception as e:
        return {
            'healthy': False,
            'error': str(e)
        }

def _check_monitoring_health() -> Dict[str, Any]:
    """Check monitoring system health."""
    try:
        # Check recent monitoring data
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_data_count = MonitoringData.query.filter(
            MonitoringData.timestamp >= one_hour_ago
        ).count()
        
        # Check active devices
        active_device_count = Device.query.filter_by(is_monitored=True).count()
        
        # Check alerts
        active_alert_count = Alert.query.filter_by(resolved=False).count()
        
        # Expected data points (assuming 60 second intervals)
        expected_data_points = active_device_count * 60
        data_health = recent_data_count >= (expected_data_points * 0.8)  # 80% threshold
        
        return {
            'healthy': data_health and active_device_count > 0,
            'active_devices': active_device_count,
            'recent_data_points': recent_data_count,
            'expected_data_points': expected_data_points,
            'active_alerts': active_alert_count,
            'data_collection_rate': (
                (recent_data_count / expected_data_points * 100) 
                if expected_data_points > 0 else 0
            )
        }
        
    except Exception as e:
        return {
            'healthy': False,
            'error': str(e)
        }

def _test_database_connection() -> Dict[str, Any]:
    """Test database connection."""
    try:
        start_time = time.time()
        result = db.session.execute(text('SELECT COUNT(*) FROM devices')).scalar()
        response_time = time.time() - start_time
        
        return {
            'available': True,
            'response_time_ms': round(response_time * 1000, 2),
            'device_count': result
        }
        
    except Exception as e:
        return {
            'available': False,
            'error': str(e)
        }

def _test_network_connectivity() -> Dict[str, Any]:
    """Test network connectivity."""
    try:
        import socket
        
        # Test local network connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Try to connect to a local gateway (assuming 192.168.1.1)
        try:
            result = sock.connect_ex(('8.8.8.8', 53))  # Google DNS
            network_available = result == 0
        except:
            network_available = False
        finally:
            sock.close()
            
        return {
            'available': network_available,
            'test_target': '8.8.8.8:53'
        }
        
    except Exception as e:
        return {
            'available': False,
            'error': str(e)
        }

def _check_critical_resources() -> Dict[str, Any]:
    """Check critical system resources."""
    try:
        # Memory check (critical at 95%)
        memory = psutil.virtual_memory()
        memory_critical = memory.percent >= 95
        
        # Disk check (critical at 95%)
        disk = psutil.disk_usage('/')
        disk_critical = disk.percent >= 95
        
        # File descriptor check
        try:
            process = psutil.Process()
            fd_count = process.num_fds()
            fd_critical = fd_count > 1000  # Arbitrary threshold
        except:
            fd_critical = False
            
        resources_available = not (memory_critical or disk_critical or fd_critical)
        
        return {
            'available': resources_available,
            'memory_critical': memory_critical,
            'disk_critical': disk_critical,
            'file_descriptor_critical': fd_critical
        }
        
    except Exception as e:
        return {
            'available': False,
            'error': str(e)
        }

def _get_application_uptime() -> float:
    """Get application uptime in seconds."""
    from core.application import SERVER_START_TIME
    return (datetime.now() - SERVER_START_TIME).total_seconds()

def _get_database_metrics() -> Dict[str, Any]:
    """Get database metrics."""
    try:
        pool_monitor = ConnectionPoolMonitor(db)
        return pool_monitor.get_metrics()
    except:
        return {}

def _get_cache_metrics() -> Dict[str, Any]:
    """Get cache metrics."""
    try:
        return global_cache.get_stats()
    except:
        return {}

def _get_system_metrics() -> Dict[str, Any]:
    """Get system metrics."""
    try:
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'load_average': os.getloadavg()[0]
        }
    except:
        return {}

def _get_monitoring_metrics() -> Dict[str, Any]:
    """Get monitoring metrics."""
    try:
        return {
            'total_devices': Device.query.count(),
            'monitored_devices': Device.query.filter_by(is_monitored=True).count(),
            'active_alerts': Alert.query.filter_by(resolved=False).count()
        }
    except:
        return {}

def _get_performance_metrics() -> Dict[str, Any]:
    """Get performance metrics."""
    try:
        return global_profiler.get_performance_summary()
    except:
        return {}