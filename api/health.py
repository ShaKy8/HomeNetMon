from flask import Blueprint, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_
from models import db, Device, MonitoringData, Alert
import logging
import psutil
import threading
import time

health_bp = Blueprint('health', __name__)
logger = logging.getLogger(__name__)

# Global variables for bandwidth monitoring
bandwidth_data = {
    'download_mbps': 0,
    'upload_mbps': 0,
    'timestamp': None,
    'available': False
}
bandwidth_lock = threading.Lock()

def get_network_bandwidth():
    """Get current network bandwidth usage"""
    try:
        # Get network interface statistics
        net_io_before = psutil.net_io_counters()
        time.sleep(1)  # Wait 1 second to calculate rate
        net_io_after = psutil.net_io_counters()
        
        # Calculate bytes per second
        bytes_sent_per_sec = net_io_after.bytes_sent - net_io_before.bytes_sent
        bytes_recv_per_sec = net_io_after.bytes_recv - net_io_before.bytes_recv
        
        # Convert to Mbps
        upload_mbps = round((bytes_sent_per_sec * 8) / (1024 * 1024), 2)
        download_mbps = round((bytes_recv_per_sec * 8) / (1024 * 1024), 2)
        
        with bandwidth_lock:
            bandwidth_data.update({
                'download_mbps': download_mbps,
                'upload_mbps': upload_mbps,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'available': True
            })
        
        return True
    except Exception as e:
        logger.warning(f"Failed to get bandwidth data: {e}")
        with bandwidth_lock:
            bandwidth_data.update({
                'download_mbps': 0,
                'upload_mbps': 0,
                'timestamp': None,
                'available': False
            })
        return False

def start_bandwidth_monitoring():
    """Start background bandwidth monitoring"""
    def monitor_bandwidth():
        while True:
            try:
                get_network_bandwidth()
                time.sleep(30)  # Update every 30 seconds
            except Exception as e:
                logger.error(f"Bandwidth monitoring error: {e}")
                time.sleep(60)  # Wait longer on error
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_bandwidth, daemon=True)
    monitor_thread.start()
    logger.info("Bandwidth monitoring started")

# Initialize bandwidth monitoring when module loads
start_bandwidth_monitoring()

@health_bp.route('/overview', methods=['GET'])
def get_health_overview():
    """Get comprehensive network health overview"""
    try:
        # Get current timestamp for calculations
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_1h = now - timedelta(hours=1)
        last_week = now - timedelta(days=7)
        yesterday_start = now - timedelta(days=1)
        yesterday_end = now - timedelta(hours=24)
        
        # Basic device counts
        total_devices = Device.query.filter_by(is_monitored=True).count()
        
        # Device status calculations
        online_threshold = now - timedelta(minutes=10)  # 10 minutes threshold
        
        devices_online = Device.query.filter(
            and_(
                Device.is_monitored == True,
                Device.last_seen >= online_threshold
            )
        ).count()
        
        devices_offline = total_devices - devices_online
        
        # Response time calculations
        avg_response_time = db.session.query(func.avg(MonitoringData.response_time))\
            .filter(MonitoringData.timestamp >= last_1h)\
            .filter(MonitoringData.response_time > 0)\
            .scalar()
        
        avg_response_time = round(float(avg_response_time) if avg_response_time else 0, 2)
        
        # Alert counts
        active_alerts = Alert.query.filter_by(resolved=False).count()
        critical_alerts = Alert.query.filter(
            and_(
                Alert.resolved == False,
                Alert.severity == 'critical'
            )
        ).count()
        
        # Calculate uptime percentage (last 24h)
        total_checks_24h = MonitoringData.query\
            .filter(MonitoringData.timestamp >= last_24h)\
            .count()
        
        successful_checks_24h = MonitoringData.query\
            .filter(MonitoringData.timestamp >= last_24h)\
            .filter(MonitoringData.response_time > 0)\
            .count()
        
        uptime_percentage = round(
            (successful_checks_24h / total_checks_24h * 100) if total_checks_24h > 0 else 0,
            1
        )
        
        # Calculate network health score
        health_score = calculate_health_score(
            devices_online, total_devices, avg_response_time, 
            active_alerts, uptime_percentage
        )
        
        # Calculate historical comparisons
        historical_data = calculate_historical_comparisons(
            last_24h, yesterday_start, yesterday_end, last_week
        )
        
        # Get recent activity (last 50 events)
        recent_activity = get_recent_network_activity(50)
        
        # Network performance trends
        performance_trends = get_performance_trends(last_24h)
        
        # Get current bandwidth data
        with bandwidth_lock:
            bandwidth_usage = bandwidth_data.copy()
        
        return jsonify({
            'success': True,
            'timestamp': now.isoformat() + 'Z',
            'health_score': health_score,
            'network_status': {
                'total_devices': total_devices,
                'devices_online': devices_online,
                'devices_offline': devices_offline,
                'online_percentage': round((devices_online / total_devices * 100) if total_devices > 0 else 0, 1),
                'avg_response_time_ms': avg_response_time,
                'uptime_percentage_24h': uptime_percentage
            },
            'alerts': {
                'total_active': active_alerts,
                'critical_count': critical_alerts,
                'has_critical': critical_alerts > 0
            },
            'bandwidth': bandwidth_usage,
            'performance_trends': performance_trends,
            'recent_activity': recent_activity,
            'status_summary': get_status_summary(health_score, critical_alerts),
            'historical_comparisons': historical_data
        })
        
    except Exception as e:
        logger.error(f"Error generating health overview: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to generate health overview'
        }), 500

@health_bp.route('/score', methods=['GET'])
def get_health_score():
    """Get just the network health score"""
    try:
        now = datetime.utcnow()
        online_threshold = now - timedelta(minutes=10)
        
        # Quick calculations for health score
        total_devices = Device.query.filter_by(is_monitored=True).count()
        devices_online = Device.query.filter(
            and_(
                Device.is_monitored == True,
                Device.last_seen >= online_threshold
            )
        ).count()
        
        # Average response time (last hour)
        last_1h = now - timedelta(hours=1)
        avg_response_time = db.session.query(func.avg(MonitoringData.response_time))\
            .filter(MonitoringData.timestamp >= last_1h)\
            .filter(MonitoringData.response_time > 0)\
            .scalar()
        avg_response_time = float(avg_response_time) if avg_response_time else 0
        
        # Active alerts
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Uptime (simplified)
        uptime_percentage = 95.0  # Placeholder for quick response
        
        health_score = calculate_health_score(
            devices_online, total_devices, avg_response_time,
            active_alerts, uptime_percentage
        )
        
        return jsonify({
            'success': True,
            'health_score': health_score,
            'timestamp': now.isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error calculating health score: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to calculate health score'
        }), 500

@health_bp.route('/topology', methods=['GET'])
def get_network_topology():
    """Get simplified network topology for mini-map"""
    try:
        devices = Device.query.filter_by(is_monitored=True).all()
        online_threshold = datetime.utcnow() - timedelta(minutes=10)
        
        topology_data = []
        for device in devices:
            # Determine device status
            status = 'online' if device.last_seen and device.last_seen >= online_threshold else 'offline'
            
            # Get latest response time
            latest_data = MonitoringData.query\
                .filter_by(device_id=device.id)\
                .order_by(MonitoringData.timestamp.desc())\
                .first()
            
            response_time = latest_data.response_time if latest_data and latest_data.response_time is not None and latest_data.response_time > 0 else None
            
            topology_data.append({
                'id': device.id,
                'ip_address': device.ip_address,
                'name': device.display_name,
                'type': device.device_type or 'unknown',
                'status': status,
                'response_time': response_time,
                'group': device.device_group,
                'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None
            })
        
        return jsonify({
            'success': True,
            'devices': topology_data,
            'total_count': len(topology_data),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error getting network topology: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get network topology'
        }), 500

def calculate_health_score(devices_online, total_devices, avg_response_time, active_alerts, uptime_percentage):
    """Calculate overall network health score (0-100)"""
    if total_devices == 0:
        return 0
    
    # Device availability score (40% weight)
    availability_score = (devices_online / total_devices) * 40
    
    # Response time score (25% weight) - Good: <50ms, Fair: <200ms, Poor: >200ms
    if avg_response_time == 0:
        response_score = 25  # No data, assume neutral
    elif avg_response_time < 50:
        response_score = 25
    elif avg_response_time < 200:
        response_score = 15
    else:
        response_score = 5
    
    # Alert impact score (20% weight) - Penalty for active alerts
    alert_penalty = min(active_alerts * 5, 20)  # Max 20 points penalty
    alert_score = 20 - alert_penalty
    
    # Uptime score (15% weight)
    uptime_score = (uptime_percentage / 100) * 15
    
    # Calculate total score
    total_score = availability_score + response_score + alert_score + uptime_score
    
    return round(max(0, min(100, total_score)), 1)

def get_recent_network_activity(limit=50):
    """Get recent network activity events"""
    try:
        # Get recent device discoveries (new devices)
        recent_devices = Device.query\
            .filter(Device.created_at >= datetime.utcnow() - timedelta(days=1))\
            .order_by(Device.created_at.desc())\
            .limit(10).all()
        
        # Get recent alerts
        recent_alerts = Alert.query\
            .filter(Alert.created_at >= datetime.utcnow() - timedelta(days=1))\
            .order_by(Alert.created_at.desc())\
            .limit(20).all()
        
        activity = []
        
        # Add device discoveries
        for device in recent_devices:
            activity.append({
                'type': 'device_discovered',
                'timestamp': device.created_at.isoformat() + 'Z',
                'message': f'New device discovered: {device.display_name} ({device.ip_address})',
                'device_name': device.display_name,
                'device_ip': device.ip_address,
                'icon': 'plus-circle',
                'severity': 'info'
            })
        
        # Add alerts
        for alert in recent_alerts:
            activity.append({
                'type': 'alert',
                'timestamp': alert.created_at.isoformat() + 'Z',
                'message': alert.message,
                'device_name': alert.device.display_name if alert.device else 'System',
                'device_ip': alert.device.ip_address if alert.device else None,
                'icon': 'exclamation-triangle' if alert.severity == 'critical' else 'info-circle',
                'severity': alert.severity
            })
        
        # Sort by timestamp (most recent first) and limit
        activity.sort(key=lambda x: x['timestamp'], reverse=True)
        return activity[:limit]
        
    except Exception as e:
        logger.error(f"Error getting recent activity: {e}")
        return []

def get_performance_trends(since_time):
    """Get performance trend data for sparkline charts"""
    try:
        # Response time trend (hourly averages)
        response_trend = db.session.query(
            func.strftime('%Y-%m-%d %H:00:00', MonitoringData.timestamp).label('hour'),
            func.avg(MonitoringData.response_time).label('avg_response')
        ).filter(
            MonitoringData.timestamp >= since_time,
            MonitoringData.response_time > 0
        ).group_by(
            func.strftime('%Y-%m-%d %H:00:00', MonitoringData.timestamp)
        ).order_by('hour').all()
        
        response_data = [
            {
                'timestamp': hour.replace(' ', 'T') + 'Z',  # Convert to ISO format
                'value': round(float(avg_response), 2)
            }
            for hour, avg_response in response_trend
        ]
        
        # Device availability trend (devices online per hour)
        # This is simplified - in production you might want more detailed tracking
        availability_data = []  # Placeholder
        
        return {
            'response_time': response_data,
            'device_availability': availability_data,
            'bandwidth_usage': []  # Placeholder for bandwidth trends
        }
        
    except Exception as e:
        logger.error(f"Error getting performance trends: {e}")
        return {
            'response_time': [],
            'device_availability': [],
            'bandwidth_usage': []
        }

def get_status_summary(health_score, critical_alerts):
    """Get human-readable status summary"""
    if critical_alerts > 0:
        return {
            'status': 'critical',
            'message': f'{critical_alerts} critical issue{"s" if critical_alerts > 1 else ""} requiring attention',
            'color': 'danger'
        }
    elif health_score >= 90:
        return {
            'status': 'excellent',
            'message': 'Network is performing excellently',
            'color': 'success'
        }
    elif health_score >= 75:
        return {
            'status': 'good',
            'message': 'Network is performing well',
            'color': 'success'
        }
    elif health_score >= 60:
        return {
            'status': 'fair',
            'message': 'Network performance is acceptable with minor issues',
            'color': 'warning'
        }
    else:
        return {
            'status': 'poor',
            'message': 'Network has significant performance issues',
            'color': 'danger'
        }

def calculate_historical_comparisons(last_24h, yesterday_start, yesterday_end, last_week):
    """Calculate historical comparisons for metrics"""
    try:
        # Yesterday's average response time
        yesterday_avg_response = db.session.query(func.avg(MonitoringData.response_time))\
            .filter(MonitoringData.timestamp >= yesterday_end)\
            .filter(MonitoringData.timestamp < yesterday_start)\
            .filter(MonitoringData.response_time > 0)\
            .scalar()
        
        # Current hour's average response time
        current_hour_avg = db.session.query(func.avg(MonitoringData.response_time))\
            .filter(MonitoringData.timestamp >= datetime.utcnow() - timedelta(hours=1))\
            .filter(MonitoringData.response_time > 0)\
            .scalar()
        
        # Calculate percentage changes
        response_time_change = 0
        if yesterday_avg_response and current_hour_avg:
            response_time_change = round(
                ((float(current_hour_avg) - float(yesterday_avg_response)) / float(yesterday_avg_response)) * 100, 
                1
            )
        
        # Device count change (simplified - assumes devices don't change often)
        total_devices_now = Device.query.filter_by(is_monitored=True).count()
        
        # Alert count comparison
        yesterday_alerts = Alert.query.filter(
            Alert.created_at >= yesterday_end,
            Alert.created_at < yesterday_start,
            Alert.resolved == False
        ).count()
        
        current_alerts = Alert.query.filter_by(resolved=False).count()
        alert_change = current_alerts - yesterday_alerts
        
        # Uptime comparison (last 24h vs previous 24h)
        prev_24h_start = yesterday_end - timedelta(hours=24)
        prev_24h_checks = MonitoringData.query\
            .filter(MonitoringData.timestamp >= prev_24h_start)\
            .filter(MonitoringData.timestamp < yesterday_end)\
            .count()
        
        prev_24h_successful = MonitoringData.query\
            .filter(MonitoringData.timestamp >= prev_24h_start)\
            .filter(MonitoringData.timestamp < yesterday_end)\
            .filter(MonitoringData.response_time > 0)\
            .count()
        
        prev_uptime = (prev_24h_successful / prev_24h_checks * 100) if prev_24h_checks > 0 else 0
        
        current_24h_checks = MonitoringData.query\
            .filter(MonitoringData.timestamp >= last_24h)\
            .count()
        
        current_24h_successful = MonitoringData.query\
            .filter(MonitoringData.timestamp >= last_24h)\
            .filter(MonitoringData.response_time > 0)\
            .count()
        
        current_uptime = (current_24h_successful / current_24h_checks * 100) if current_24h_checks > 0 else 0
        uptime_change = round(current_uptime - prev_uptime, 1)
        
        return {
            'response_time': {
                'current_avg': float(current_hour_avg) if current_hour_avg else 0,
                'yesterday_avg': float(yesterday_avg_response) if yesterday_avg_response else 0,
                'percentage_change': response_time_change,
                'trend': 'improving' if response_time_change < 0 else 'degrading' if response_time_change > 0 else 'stable'
            },
            'alerts': {
                'current_count': current_alerts,
                'yesterday_count': yesterday_alerts,
                'change': alert_change,
                'trend': 'improving' if alert_change < 0 else 'degrading' if alert_change > 0 else 'stable'
            },
            'uptime': {
                'current_24h': round(current_uptime, 1),
                'previous_24h': round(prev_uptime, 1),
                'change': uptime_change,
                'trend': 'improving' if uptime_change > 0 else 'degrading' if uptime_change < 0 else 'stable'
            },
            'devices': {
                'total_monitored': total_devices_now,
                'change_message': f'{total_devices_now} devices being monitored'
            }
        }
        
    except Exception as e:
        logger.error(f"Error calculating historical comparisons: {e}")
        return {
            'response_time': {'current_avg': 0, 'yesterday_avg': 0, 'percentage_change': 0, 'trend': 'stable'},
            'alerts': {'current_count': 0, 'yesterday_count': 0, 'change': 0, 'trend': 'stable'},
            'uptime': {'current_24h': 0, 'previous_24h': 0, 'change': 0, 'trend': 'stable'},
            'devices': {'total_monitored': 0, 'change_message': 'No data available'}
        }