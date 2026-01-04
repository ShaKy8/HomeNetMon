from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func
from models import db, Device, MonitoringData, Alert, BandwidthData
from monitoring.monitor import DeviceMonitor
from services.pagination import paginator, create_pagination_response
import ipaddress
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import time
from api.rate_limited_endpoints import create_endpoint_limiter

monitoring_bp = Blueprint('monitoring', __name__)

# Simple cache for background activity endpoint (30-second cache)
_background_activity_cache = {
    'data': None,
    'timestamp': 0,
    'ttl': 30  # 30 seconds
}

def _get_cached_background_activity():
    """Get cached background activity data if still valid"""
    current_time = time.time()
    if (_background_activity_cache['data'] is not None and 
        current_time - _background_activity_cache['timestamp'] < _background_activity_cache['ttl']):
        return _background_activity_cache['data']
    return None

def _cache_background_activity(data):
    """Cache background activity data"""
    _background_activity_cache['data'] = data
    _background_activity_cache['timestamp'] = time.time()

def get_current_network_range():
    """Get the currently configured network range"""
    try:
        from models import Configuration
        return Configuration.get_value('network_range', '192.168.86.0/24')
    except (ImportError, AttributeError) as e:
        # Fallback to config if database is not available
        from config import Config
        return Config.NETWORK_RANGE

def is_device_in_network_range(device_ip, network_range):
    """Check if a device IP is within the specified network range"""
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        ip = ipaddress.ip_address(device_ip)
        return ip in network
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        return False

def filter_devices_by_network_range(query, network_range=None):
    """Filter device query by current network range"""
    if network_range is None:
        network_range = get_current_network_range()
    
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        # Create a filter for devices within the network range
        network_base = str(network.network_address)
        network_parts = network_base.split('.')
        
        if network.prefixlen >= 24:
            # /24 or smaller network - filter by first 3 octets
            prefix = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}."
            return query.filter(Device.ip_address.like(f"{prefix}%"))
        elif network.prefixlen >= 16:
            # /16 to /23 network - filter by first 2 octets
            prefix = f"{network_parts[0]}.{network_parts[1]}."
            return query.filter(Device.ip_address.like(f"{prefix}%"))
        elif network.prefixlen >= 8:
            # /8 to /15 network - filter by first octet
            prefix = f"{network_parts[0]}."
            return query.filter(Device.ip_address.like(f"{prefix}%"))
        else:
            # Larger networks - return all devices
            return query
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError, AttributeError) as e:
        # If network parsing fails, return original query
        return query

@monitoring_bp.route('/scan', methods=['POST'])
@create_endpoint_limiter('critical')
def trigger_network_scan():
    """Trigger manual network scan"""
    try:
        from flask import current_app
        
        # Get the network scanner instance from the app
        if not hasattr(current_app, '_scanner'):
            return jsonify({
                'success': False,
                'error': 'Network scanner not available'
            }), 503
        
        scanner = current_app._scanner
        
        # Check if scanner is currently running a scan
        if hasattr(scanner, 'is_scanning') and scanner.is_scanning:
            return jsonify({
                'success': False,
                'error': 'Network scan already in progress'
            }), 429
        
        # Trigger the scan in a background thread
        import threading
        
        def run_scan():
            try:
                scanner.scan_network()
            except Exception as e:
                current_app.logger.error(f"Background scan error: {e}")
        
        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Network scan initiated',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/reload-config', methods=['POST'])
@create_endpoint_limiter('critical')
def reload_scanner_config():
    """Force reload scanner configuration"""
    try:
        from flask import current_app
        
        # Get the network scanner instance from the app
        if not hasattr(current_app, '_scanner'):
            return jsonify({
                'success': False,
                'error': 'Network scanner not available'
            }), 503
        
        scanner = current_app._scanner
        
        # Force reload configuration
        if hasattr(scanner, 'reload_config'):
            scanner.reload_config()
            return jsonify({
                'success': True,
                'message': 'Scanner configuration reloaded',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scanner does not support configuration reload'
            }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/data', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_data():
    """Get monitoring data with optional filtering and pagination"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        
        # Build query
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = MonitoringData.query.filter(MonitoringData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(MonitoringData.device_id == device_id)
        
        # Order by timestamp (newest first)
        query = query.order_by(MonitoringData.timestamp.desc())
        
        # Get pagination parameters
        page, per_page = paginator.get_request_pagination()
        
        # Apply pagination
        pagination_result = paginator.paginate_query(
            query,
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        monitoring_data = pagination_result['items']
        
        # Convert to dict format with device info
        data = []
        for item in monitoring_data:
            item_dict = item.to_dict()
            item_dict['device_name'] = item.device.display_name
            item_dict['device_ip'] = item.device.ip_address
            data.append(item_dict)
        
        return jsonify({
            'monitoring_data': data,
            'pagination': {
                'page': pagination_result['page'],
                'per_page': pagination_result['per_page'],
                'total': pagination_result['total'],
                'pages': pagination_result['pages'],
                'has_prev': pagination_result['has_prev'],
                'has_next': pagination_result['has_next']
            },
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/statistics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_statistics():
    """Get monitoring statistics"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        
        monitor = DeviceMonitor()
        
        if device_id:
            # Device-specific statistics
            stats = monitor.get_device_statistics(device_id, hours)
            if not stats:
                return jsonify({'error': 'Device not found or no data available'}), 404
            return jsonify(stats)
        else:
            # Network-wide statistics
            stats = monitor.get_network_statistics(hours)
            if not stats:
                return jsonify({'error': 'No monitoring data available'}), 404
            return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@lru_cache(maxsize=1)
def _cached_live_ping_scan(network_range_str, cache_key):
    """Cached live ping scan to avoid repeated scans"""
    try:
        # Use fping for fast network-wide ping
        result = subprocess.run(
            ['fping', '-g', network_range_str, '-q', '-a'],
            capture_output=True, text=True, timeout=30, shell=False
        )
        
        if result.returncode in [0, 1]:  # 0 = all responded, 1 = some responded
            online_ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip()]
            return len(online_ips), online_ips
        else:
            return 0, []
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: no live ping data available
        return 0, []

def get_live_network_stats(network_range):
    """Get live network statistics using fping"""
    # Create cache key based on current time (cache for 30 seconds)
    cache_key = int(time.time() // 30)  # 30-second cache buckets
    
    # Clear cache if it's getting too old
    if hasattr(_cached_live_ping_scan, 'cache_info'):
        _cached_live_ping_scan.cache_clear()
    
    online_count, online_ips = _cached_live_ping_scan(network_range, cache_key)
    return {
        'live_devices_online': online_count,
        'live_scan_available': online_count > 0,
        'online_ips': online_ips
    }

@monitoring_bp.route('/quick-stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_quick_stats():
    """Get quick statistics for sidebar display with optional live ping data"""
    try:
        # Get current network range
        network_range = get_current_network_range()
        
        # Get live network data (with caching)
        include_live = request.args.get('live', 'true').lower() == 'true'
        live_stats = {}
        if include_live:
            live_stats = get_live_network_stats(network_range)
        
        # Filter devices by current network range
        base_query = Device.query
        filtered_query = filter_devices_by_network_range(base_query, network_range)
        
        # Get total devices count (only in current network range)
        total_devices = filtered_query.count()
        
        # Get monitored devices count (only in current network range)
        monitored_query = filter_devices_by_network_range(
            Device.query.filter_by(is_monitored=True), 
            network_range
        )
        monitored_devices = monitored_query.count()
        
        # Determine status of monitored devices (based on last_seen within 10 minutes)
        online_threshold = datetime.utcnow() - timedelta(minutes=10)
        devices_up_query = filter_devices_by_network_range(
            Device.query.filter(
                Device.is_monitored == True,
                Device.last_seen >= online_threshold
            ),
            network_range
        )
        devices_up = devices_up_query.count()
        
        devices_down = monitored_devices - devices_up
        
        # Use live ping results if available and higher than database count
        if include_live and live_stats.get('live_scan_available'):
            live_devices_online = live_stats['live_devices_online']
            # If live scan shows more devices online, use that count
            if live_devices_online > devices_up:
                devices_up = live_devices_online
                # Adjust total devices to reflect reality
                if live_devices_online > total_devices:
                    total_devices = live_devices_online
                # Recalculate devices down based on discovered devices
                devices_down = max(0, total_devices - devices_up)
        
        # Get active alerts count (for devices in current network only)
        # Get device IDs in current network
        current_network_device_ids = [d.id for d in filtered_query.all()]
        if current_network_device_ids:
            active_alerts = Alert.query.filter(
                Alert.resolved == False,
                Alert.device_id.in_(current_network_device_ids)
            ).count()
        else:
            active_alerts = 0
        
        result = {
            'total_devices': total_devices,
            'devices_up': devices_up, 
            'devices_down': devices_down,
            'active_alerts': active_alerts,
            'monitored_devices': monitored_devices,
            'network_range': network_range,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Include live stats info if requested
        if include_live:
            result.update({
                'live_scan_enabled': True,
                'live_devices_online': live_stats.get('live_devices_online', 0),
                'data_source': 'database_plus_live' if live_stats.get('live_scan_available') else 'database_only'
            })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/chart-data', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_chart_data():
    """Simple chart data endpoint for testing"""
    try:
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        
        if not device_id:
            return jsonify({'error': 'Device ID required'}), 400
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get recent monitoring data for the device
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        ).order_by(MonitoringData.timestamp.desc()).limit(100).all()
        
        # Format data for chart
        timeline_data = []
        for data_point in monitoring_data:
            timeline_data.append({
                'timestamp': data_point.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'avg_response_time': data_point.response_time
            })
        
        return jsonify({
            'timeline': timeline_data,
            'count': len(timeline_data),
            'interval': 'raw',
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_timeline():
    """Get monitoring timeline data for charts"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        interval = request.args.get('interval', default='hour')  # hour, 30min, 15min, 5min
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Build simple query to get raw monitoring data
        query = MonitoringData.query.filter(MonitoringData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(MonitoringData.device_id == device_id)
        
        monitoring_data = query.order_by(MonitoringData.timestamp).all()
        
        # Group data by time intervals in Python
        timeline_data = []
        current_bucket = None
        bucket_data = []
        
        # Determine time bucket size
        if interval == '5min':
            bucket_minutes = 5
        elif interval == '15min':
            bucket_minutes = 15
        elif interval == '30min':
            bucket_minutes = 30
        else:  # hour
            bucket_minutes = 60
        
        for data_point in monitoring_data:
            # Calculate bucket timestamp
            timestamp = data_point.timestamp
            minutes_since_epoch = int(timestamp.timestamp() / 60)
            bucket_minutes_since_epoch = (minutes_since_epoch // bucket_minutes) * bucket_minutes
            bucket_timestamp = datetime.fromtimestamp(bucket_minutes_since_epoch * 60)
            
            # Check if we need to start a new bucket
            if current_bucket is None or current_bucket != bucket_timestamp:
                # Process previous bucket
                if current_bucket is not None and bucket_data:
                    response_times = [d.response_time for d in bucket_data if d.response_time is not None]
                    total_checks = len(bucket_data)
                    successful_checks = len(response_times)
                    
                    timeline_data.append({
                        'timestamp': current_bucket.strftime('%Y-%m-%d %H:%M:%S'),
                        'avg_response_time': sum(response_times) / len(response_times) if response_times else None,
                        'min_response_time': min(response_times) if response_times else None,
                        'max_response_time': max(response_times) if response_times else None,
                        'success_rate': round((successful_checks / total_checks * 100), 2) if total_checks > 0 else 0,
                        'total_checks': total_checks,
                        'successful_checks': successful_checks
                    })
                
                # Start new bucket
                current_bucket = bucket_timestamp
                bucket_data = []
            
            bucket_data.append(data_point)
        
        # Process the last bucket
        if current_bucket is not None and bucket_data:
            response_times = [d.response_time for d in bucket_data if d.response_time is not None]
            total_checks = len(bucket_data)
            successful_checks = len(response_times)
            
            timeline_data.append({
                'timestamp': current_bucket.strftime('%Y-%m-%d %H:%M:%S'),
                'avg_response_time': sum(response_times) / len(response_times) if response_times else None,
                'min_response_time': min(response_times) if response_times else None,
                'max_response_time': max(response_times) if response_times else None,
                'success_rate': round((successful_checks / total_checks * 100), 2) if total_checks > 0 else 0,
                'total_checks': total_checks,
                'successful_checks': successful_checks
            })
        
        return jsonify({
            'timeline': timeline_data,
            'count': len(timeline_data),
            'interval': interval,
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alerts():
    """Get alerts with optional filtering"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        severity = request.args.get('severity')
        resolved = request.args.get('resolved')
        hours = request.args.get('hours', default=168, type=int)  # Default 7 days
        limit = request.args.get('limit', default=50, type=int)
        
        # Build query
        query = Alert.query
        
        if device_id:
            query = query.filter(Alert.device_id == device_id)
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if resolved is not None:
            resolved_bool = resolved.lower() == 'true'
            query = query.filter(Alert.resolved == resolved_bool)
        
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(Alert.created_at >= cutoff)
        
        alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()
        
        # Convert to dict format
        alerts_data = [alert.to_dict() for alert in alerts]
        
        return jsonify({
            'alerts': alerts_data,
            'count': len(alerts_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@create_endpoint_limiter('strict')
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        data = request.get_json() or {}
        acknowledged_by = data.get('acknowledged_by', 'api_user')
        
        alert.acknowledge(acknowledged_by)
        
        # Emit real-time update
        try:
            from flask import current_app
            if hasattr(current_app, 'emit_alert_update'):
                current_app.emit_alert_update(alert, 'acknowledged')
        except Exception as e:
            current_app.logger.error(f"Error emitting alert acknowledgment update: {e}")
        
        return jsonify(alert.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/acknowledge-all', methods=['POST'])
@create_endpoint_limiter('bulk')
def acknowledge_all_alerts():
    """Acknowledge all active alerts"""
    try:
        data = request.get_json() or {}
        acknowledged_by = data.get('acknowledged_by', 'web_user')
        
        # Get all unacknowledged alerts
        active_alerts = Alert.query.filter_by(acknowledged=False).all()
        
        acknowledged_count = 0
        for alert in active_alerts:
            alert.acknowledge(acknowledged_by)
            acknowledged_count += 1
        
        return jsonify({
            'message': f'Acknowledged {acknowledged_count} alerts',
            'count': acknowledged_count
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@create_endpoint_limiter('strict')
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        alert.resolve()
        
        # Emit real-time update
        try:
            from flask import current_app
            if hasattr(current_app, 'emit_alert_update'):
                current_app.emit_alert_update(alert, 'resolved')
        except Exception as e:
            current_app.logger.error(f"Error emitting alert resolution update: {e}")
        
        return jsonify(alert.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>', methods=['DELETE'])
# @create_endpoint_limiter('critical')  # Temporarily disabled for debugging
def delete_alert(alert_id):
    """Delete a specific alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        # Store alert info for response
        alert_info = {
            'id': alert.id,
            'device_name': alert.device.display_name,
            'device_ip': alert.device.ip_address,
            'alert_type': alert.alert_type,
            'message': alert.message
        }
        
        db.session.delete(alert)
        db.session.commit()
        
        # Emit real-time update
        try:
            from flask import current_app
            if hasattr(current_app, 'socketio'):
                # Emit deletion event
                current_app.socketio.emit('alert_update', {
                    'type': 'alert_update',
                    'alert': {
                        'id': alert_info['id'],
                        'device_name': alert_info['device_name'],
                        'device_ip': alert_info['device_ip'],
                        'action': 'deleted'
                    },
                    'action': 'deleted',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
        except Exception as e:
            current_app.logger.error(f"Error emitting alert deletion update: {e}")
        
        # Brief pause for individual deletions (2 minutes)
        from flask import current_app
        if hasattr(current_app, 'alert_manager'):
            current_app.alert_manager.set_alert_pause(2)
        
        return jsonify({
            'message': f'Alert deleted successfully',
            'deleted_alert': alert_info,
            'alert_generation_paused': '2 minutes'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/delete-all', methods=['DELETE'])
@create_endpoint_limiter('critical')
def delete_all_alerts():
    """Delete all alerts"""
    try:
        data = request.get_json() or {}
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({
                'error': 'Please confirm deletion by sending {"confirm": true}',
                'warning': 'This action will permanently delete all alerts and cannot be undone'
            }), 400
        
        # Count alerts before deletion
        total_alerts = Alert.query.count()
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Delete all alerts
        deleted_count = Alert.query.delete()
        db.session.commit()
        
        # Pause alert generation for 10 minutes to prevent immediate regeneration
        from flask import current_app
        if hasattr(current_app, 'alert_manager'):
            current_app.alert_manager.set_alert_pause(10)
        
        return jsonify({
            'message': f'Successfully deleted {deleted_count} alerts',
            'total_deleted': deleted_count,
            'previously_active': active_alerts,
            'previously_total': total_alerts,
            'alert_generation_paused': '10 minutes'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/bulk-delete', methods=['DELETE'])
@create_endpoint_limiter('critical')
def bulk_delete_alerts():
    """Delete alerts by specific criteria (type, status, etc.)"""
    try:
        data = request.get_json() or {}

        # Build query based on criteria
        query = Alert.query
        criteria_used = []

        # Filter by alert type
        if 'alert_type' in data:
            alert_types = data['alert_type']
            if isinstance(alert_types, str):
                alert_types = [alert_types]
            query = query.filter(Alert.alert_type.in_(alert_types))
            criteria_used.append(f"type: {', '.join(alert_types)}")

        # Filter by resolved status
        if 'resolved' in data:
            resolved_status = data['resolved']
            query = query.filter(Alert.resolved == resolved_status)
            criteria_used.append(f"resolved: {resolved_status}")

        # Filter by severity
        if 'severity' in data:
            severities = data['severity']
            if isinstance(severities, str):
                severities = [severities]
            query = query.filter(Alert.severity.in_(severities))
            criteria_used.append(f"severity: {', '.join(severities)}")

        # Get count and summary before deletion
        alerts_to_delete = query.all()
        delete_count = len(alerts_to_delete)

        if delete_count == 0:
            return jsonify({
                'message': 'No alerts match the specified criteria',
                'deleted_count': 0,
                'criteria': criteria_used
            })

        # Generate summary
        summary = {}
        for alert in alerts_to_delete:
            key = f"{alert.alert_type}_{alert.severity}"
            summary[key] = summary.get(key, 0) + 1

        # Delete matching alerts
        query.delete(synchronize_session=False)
        db.session.commit()

        # Pause alert generation proportional to deletion count
        pause_minutes = min(10, max(2, delete_count // 20))
        from flask import current_app
        if hasattr(current_app, 'alert_manager'):
            current_app.alert_manager.set_alert_pause(pause_minutes)

        return jsonify({
            'message': f'Successfully deleted {delete_count} alerts matching criteria',
            'deleted_count': delete_count,
            'criteria': criteria_used,
            'summary': summary,
            'alert_generation_paused': f'{pause_minutes} minutes'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/cleanup-duplicates', methods=['POST'])
@create_endpoint_limiter('strict')
def cleanup_duplicate_alerts():
    """Clean up duplicate alerts using correlation service"""
    try:
        from flask import current_app
        
        if not hasattr(current_app, 'alert_manager'):
            return jsonify({'error': 'Alert manager not available'}), 500
        
        # Get counts before cleanup
        before_count = Alert.query.filter_by(resolved=False).count()
        
        # Run cleanup
        current_app.alert_manager.cleanup_duplicate_alerts()
        
        # Get counts after cleanup
        after_count = Alert.query.filter_by(resolved=False).count()
        cleaned_count = before_count - after_count
        
        return jsonify({
            'message': f'Successfully cleaned up {cleaned_count} duplicate alerts',
            'before_count': before_count,
            'after_count': after_count,
            'cleaned_count': cleaned_count
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_status():
    """Get overall monitoring system status"""
    try:
        # Get system statistics
        monitor = DeviceMonitor()
        network_stats = monitor.get_network_statistics(hours=1)

        # Fetch devices and batch data to avoid N+1 queries
        devices = Device.query.filter_by(is_monitored=True).all()
        device_ids = [d.id for d in devices]
        batch_data = Device.batch_get_device_data(device_ids)

        # Count devices by status using batch data
        status_counts = {
            'up': 0,
            'down': 0,
            'warning': 0,
            'unknown': 0
        }
        threshold = datetime.utcnow() - timedelta(seconds=900)

        for device in devices:
            # Calculate status without triggering additional queries
            if not device.last_seen:
                status = 'unknown'
            elif device.last_seen < threshold:
                status = 'down'
            else:
                # Check monitoring data for warning state
                monitoring_data = batch_data['monitoring_data'].get(device.id)
                if monitoring_data and monitoring_data.response_time and monitoring_data.response_time > 500:
                    status = 'warning'
                else:
                    status = 'up'
            if status in status_counts:
                status_counts[status] += 1

        # Aggregate alert counts in a single query
        alert_severity_counts = db.session.query(
            Alert.severity,
            func.count(Alert.id)
        ).filter(Alert.resolved == False).group_by(Alert.severity).all()

        alert_counts = {'critical': 0, 'warning': 0, 'info': 0}
        for severity, count in alert_severity_counts:
            if severity in alert_counts:
                alert_counts[severity] = count

        # Recent monitoring activity
        recent_checks = MonitoringData.query.filter(
            MonitoringData.timestamp >= datetime.utcnow() - timedelta(minutes=5)
        ).count()

        return jsonify({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_devices': len(devices),
            'status_counts': status_counts,
            'alert_counts': alert_counts,
            'recent_checks': recent_checks,
            'network_stats': network_stats,
            'monitoring_active': True  # This would be determined by checking if monitoring services are running
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/export', methods=['GET'])
@create_endpoint_limiter('relaxed')
def export_monitoring_data():
    """Export monitoring data as CSV"""
    try:
        from io import StringIO
        import csv
        from flask import Response
        
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=168, type=int)  # Default 7 days
        
        # Validate parameters
        if hours > 720:  # Max 30 days for export
            hours = 720
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = db.session.query(
            MonitoringData.timestamp,
            Device.ip_address,
            Device.custom_name,
            Device.hostname,
            MonitoringData.response_time
        ).join(Device).filter(MonitoringData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(Device.id == device_id)
        
        results = query.order_by(MonitoringData.timestamp.desc()).all()
        
        # Generate CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Timestamp', 'IP Address', 'Device Name', 'Hostname', 'Response Time (ms)'])
        
        # Write data
        for row in results:
            device_name = row.custom_name or row.hostname or 'Unknown'
            response_time = f"{row.response_time:.2f}" if row.response_time else "N/A"
            writer.writerow([
                row.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                row.ip_address,
                device_name,
                row.hostname or 'N/A',
                response_time
            ])
        
        output.seek(0)
        
        # Create response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=homeNetMon_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/background-activity', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_background_activity():
    """Get background monitoring activity information with caching"""
    try:
        # Check cache first
        cached_data = _get_cached_background_activity()
        if cached_data:
            return jsonify(cached_data)
        
        # Cache miss - compute fresh data
        from config import Config
        
        # Calculate next scan time based on configuration
        scan_interval_seconds = Config.SCAN_INTERVAL
        ping_interval_seconds = Config.PING_INTERVAL
        
        # Find the most recent monitoring data to estimate when last ping occurred
        last_monitoring_data = MonitoringData.query.order_by(MonitoringData.timestamp.desc()).first()
        last_ping_time = last_monitoring_data.timestamp if last_monitoring_data else None
        
        # Find most recent device creation/update as proxy for last scan
        last_device_update = Device.query.order_by(Device.created_at.desc()).first()
        last_scan_time = last_device_update.created_at if last_device_update else None
        
        # Calculate next scan time - simplified approach
        # Since we don't have perfect tracking of when scans actually run,
        # let's just estimate based on the scan interval
        now = datetime.utcnow()
        
        if last_scan_time:
            time_since_last_scan = now - last_scan_time
            seconds_since_scan = time_since_last_scan.total_seconds()
            
            # If it's been longer than the scan interval, next scan should be soon
            if seconds_since_scan >= scan_interval_seconds:
                # Estimate next scan in 1-5 minutes
                next_scan_time = now + timedelta(seconds=min(300, scan_interval_seconds))
            else:
                # Calculate remaining time until next scan
                remaining_seconds = scan_interval_seconds - seconds_since_scan
                next_scan_time = now + timedelta(seconds=remaining_seconds)
        else:
            # No previous scan, assume next scan soon
            next_scan_time = now + timedelta(seconds=min(300, scan_interval_seconds))
        
        # Calculate next ping time based on ping interval and last ping time
        if last_ping_time:
            time_since_last_ping = now - last_ping_time
            seconds_since_ping = time_since_last_ping.total_seconds()
            
            # If it's been longer than the ping interval, next ping should be soon
            if seconds_since_ping >= ping_interval_seconds:
                # Estimate next ping in 30 seconds
                next_ping_time = now + timedelta(seconds=30)
            else:
                # Calculate remaining time until next ping
                remaining_seconds = ping_interval_seconds - seconds_since_ping
                next_ping_time = now + timedelta(seconds=remaining_seconds)
        else:
            # No previous ping, assume next ping soon
            next_ping_time = now + timedelta(seconds=min(30, ping_interval_seconds))
        
        # Check if background monitoring is active (simplified check)
        monitoring_active = True  # This could be enhanced to check actual service status
        
        # Get recent activity counts
        cutoff_1hour = datetime.utcnow() - timedelta(hours=1)
        recent_ping_count = MonitoringData.query.filter(MonitoringData.timestamp >= cutoff_1hour).count()
        
        cutoff_24hours = datetime.utcnow() - timedelta(hours=24)
        device_changes_24h = Device.query.filter(Device.updated_at >= cutoff_24hours).count()
        
        # Prepare response data
        response_data = {
            'monitoring_active': monitoring_active,
            'last_ping_time': (last_ping_time.isoformat() + 'Z') if last_ping_time else None,
            'last_scan_time': (last_scan_time.isoformat() + 'Z') if last_scan_time else None,
            'next_scan_time': (next_scan_time.isoformat() + 'Z') if next_scan_time else None,
            'next_ping_time': (next_ping_time.isoformat() + 'Z') if next_ping_time else None,
            'ping_interval_seconds': ping_interval_seconds,
            'scan_interval_seconds': scan_interval_seconds,
            'recent_activity': {
                'ping_count_1h': recent_ping_count,
                'device_changes_24h': device_changes_24h
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Cache the response
        _cache_background_activity(response_data)
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/topology-test', methods=['GET'])
@create_endpoint_limiter('critical')
def get_topology_test():
    """Network topology endpoint with all real devices"""
    try:
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        device_ids = [d.id for d in devices]

        # Batch fetch all related data to avoid N+1 queries
        batch_data = Device.batch_get_device_data(device_ids, include_uptime=True)

        # Pre-calculate device statuses
        threshold = datetime.utcnow() - timedelta(seconds=900)
        device_statuses = {}
        for device in devices:
            if not device.last_seen:
                device_statuses[device.id] = 'unknown'
            elif device.last_seen < threshold:
                device_statuses[device.id] = 'down'
            else:
                monitoring_data = batch_data['monitoring_data'].get(device.id)
                if monitoring_data and monitoring_data.response_time and monitoring_data.response_time > 500:
                    device_statuses[device.id] = 'warning'
                else:
                    device_statuses[device.id] = 'up'

        # Create nodes for devices
        nodes = []
        color_map = {
            'up': '#28a745',
            'down': '#dc3545',
            'warning': '#ffc107',
            'unknown': '#6c757d'
        }
        icon_map = {
            'router': '🌐',
            'computer': '💻',
            'phone': '📱',
            'camera': '📷',
            'iot': '🏠',
            'printer': '🖨️',
            'storage': '💾',
            'gaming': '🎮',
            'media': '📺',
            'apple': '🍎',
            'smart_home': '🏡',
            'unknown': '❓'
        }

        for device in devices:
            # Get data from batch results
            latest_data = batch_data['monitoring_data'].get(device.id)
            latest_response_time = latest_data.response_time if latest_data else None
            active_alerts = batch_data['alert_counts'].get(device.id, 0)
            uptime_pct = batch_data['uptime_percentages'].get(device.id, 0)
            status = device_statuses[device.id]

            nodes.append({
                'id': str(device.id),
                'label': device.display_name,
                'ip': device.ip_address,
                'status': status,
                'color': color_map.get(status, '#6c757d'),
                'icon': icon_map.get(device.device_type, '❓'),
                'device_type': device.device_type,
                'response_time': latest_response_time,
                'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
                'uptime_percentage': uptime_pct,
                'active_alerts': active_alerts,
                'size': 20 + uptime_pct / 5  # Size based on uptime
            })

        # Create edges (connections) - hub topology with router at center
        edges = []
        router_device = None

        # Find the router (usually .1 in the network)
        for device in devices:
            device_type = device.device_type or ''
            if device.ip_address.endswith('.1') or 'router' in device_type.lower():
                router_device = device
                break

        # If no explicit router found, use the first device as hub
        if not router_device and devices:
            router_device = devices[0]

        # Create star topology with router at center
        if router_device:
            for device in devices:
                if device.id != router_device.id:
                    # Connection strength based on response time (use batch data)
                    strength = 1.0
                    latest_data = batch_data['monitoring_data'].get(device.id)
                    if latest_data and latest_data.response_time:
                        # Lower response time = stronger connection
                        strength = max(0.1, 1.0 - (latest_data.response_time / 1000.0))

                    status = device_statuses[device.id]
                    edges.append({
                        'source': str(router_device.id),
                        'target': str(device.id),
                        'strength': strength,
                        'color': '#28a745' if status == 'up' else '#dc3545'
                    })

        return jsonify({
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'total_devices': len(devices),
                'subnets': 1,
                'connections': len(edges)
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/topology', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_topology():
    """Get network topology data for interactive graph visualization"""
    try:
        # Get all devices
        devices = Device.query.filter_by(is_monitored=True).all()
        device_ids = [d.id for d in devices]

        # Batch fetch all related data to avoid N+1 queries
        batch_data = Device.batch_get_device_data(device_ids, include_uptime=True)

        # Pre-calculate device statuses
        threshold = datetime.utcnow() - timedelta(seconds=900)
        device_statuses = {}
        for device in devices:
            if not device.last_seen:
                device_statuses[device.id] = 'unknown'
            elif device.last_seen < threshold:
                device_statuses[device.id] = 'down'
            else:
                monitoring_data = batch_data['monitoring_data'].get(device.id)
                if monitoring_data and monitoring_data.response_time and monitoring_data.response_time > 500:
                    device_statuses[device.id] = 'warning'
                else:
                    device_statuses[device.id] = 'up'

        # Create nodes for devices
        nodes = []
        color_map = {
            'up': '#28a745',
            'down': '#dc3545',
            'warning': '#ffc107',
            'unknown': '#6c757d'
        }
        icon_map = {
            'router': '🌐',
            'computer': '💻',
            'phone': '📱',
            'camera': '📷',
            'iot': '🏠',
            'printer': '🖨️',
            'storage': '💾',
            'gaming': '🎮',
            'media': '📺',
            'apple': '🍎',
            'smart_home': '🏡',
            'unknown': '❓'
        }

        for device in devices:
            # Get data from batch results
            latest_data = batch_data['monitoring_data'].get(device.id)
            latest_response_time = latest_data.response_time if latest_data else None
            active_alerts = batch_data['alert_counts'].get(device.id, 0)
            uptime_pct = batch_data['uptime_percentages'].get(device.id, 0)
            status = device_statuses[device.id]

            nodes.append({
                'id': str(device.id),
                'label': device.display_name,
                'ip': device.ip_address,
                'status': status,
                'color': color_map.get(status, '#6c757d'),
                'icon': icon_map.get(device.device_type, '❓'),
                'device_type': device.device_type,
                'response_time': latest_response_time,
                'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
                'uptime_percentage': uptime_pct,
                'active_alerts': active_alerts,
                'size': 20 + uptime_pct / 5  # Size based on uptime
            })

        # Create edges (connections) - for now, we'll connect everything to the router
        edges = []
        router_device = None

        # Find the router (usually .1 in the network)
        for device in devices:
            device_type = device.device_type or ''
            if device.ip_address.endswith('.1') or 'router' in device_type.lower():
                router_device = device
                break

        # If no explicit router found, use the first device as hub
        if not router_device and devices:
            router_device = devices[0]

        # Create star topology with router at center
        if router_device:
            for device in devices:
                if device.id != router_device.id:
                    # Connection strength based on response time (use batch data)
                    strength = 1.0
                    latest_data = batch_data['monitoring_data'].get(device.id)
                    if latest_data and latest_data.response_time:
                        # Lower response time = stronger connection
                        strength = max(0.1, 1.0 - (latest_data.response_time / 1000.0))

                    status = device_statuses[device.id]
                    edges.append({
                        'source': str(router_device.id),
                        'target': str(device.id),
                        'strength': strength,
                        'color': '#28a745' if status == 'up' else '#dc3545'
                    })
        
        # Add some subnet-based connections for more realistic topology
        subnet_groups = {}
        for device in devices:
            # Group by subnet (first 3 octets)
            subnet = '.'.join(device.ip_address.split('.')[:-1])
            if subnet not in subnet_groups:
                subnet_groups[subnet] = []
            subnet_groups[subnet].append(device)
        
        # Connect devices within same subnet
        for subnet, subnet_devices in subnet_groups.items():
            if len(subnet_devices) > 2:  # Only if there are multiple devices
                for i, device1 in enumerate(subnet_devices):
                    for device2 in subnet_devices[i+1:]:
                        # Add subnet connections with lower strength
                        if device1.id != device2.id:
                            edges.append({
                                'source': str(device1.id),
                                'target': str(device2.id),
                                'strength': 0.3,
                                'color': '#e9ecef',
                                'type': 'subnet'
                            })
        
        return jsonify({
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'total_devices': len(devices),
                'subnets': len(subnet_groups),
                'connections': len(edges)
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/bandwidth', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bandwidth_data():
    """Get bandwidth usage data with optional filtering"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=100, type=int)
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        if limit > 1000:  # Max 1000 records
            limit = 1000
        
        # Build query
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = BandwidthData.query.filter(BandwidthData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(BandwidthData.device_id == device_id)
        
        bandwidth_data = query.order_by(BandwidthData.timestamp.desc()).limit(limit).all()
        
        # Convert to dict format
        data = []
        for item in bandwidth_data:
            item_dict = item.to_dict()
            item_dict['device_name'] = item.device.display_name
            item_dict['device_ip'] = item.device.ip_address
            data.append(item_dict)
        
        return jsonify({
            'bandwidth_data': data,
            'count': len(data),
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/bandwidth/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bandwidth_timeline():
    """Get bandwidth timeline data for charts"""
    try:
        # Query parameters
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        interval = request.args.get('interval', default='hour')  # hour, 30min, 15min, 5min
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = BandwidthData.query.filter(BandwidthData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(BandwidthData.device_id == device_id)
        
        bandwidth_data = query.order_by(BandwidthData.timestamp).all()
        
        # Group data by time intervals
        timeline_data = []
        current_bucket = None
        bucket_data = []
        
        # Determine time bucket size
        if interval == '5min':
            bucket_minutes = 5
        elif interval == '15min':
            bucket_minutes = 15
        elif interval == '30min':
            bucket_minutes = 30
        else:  # hour
            bucket_minutes = 60
        
        for data_point in bandwidth_data:
            # Calculate bucket timestamp
            timestamp = data_point.timestamp
            minutes_since_epoch = int(timestamp.timestamp() / 60)
            bucket_minutes_since_epoch = (minutes_since_epoch // bucket_minutes) * bucket_minutes
            bucket_timestamp = datetime.fromtimestamp(bucket_minutes_since_epoch * 60)
            
            # Check if we need to start a new bucket
            if current_bucket is None or current_bucket != bucket_timestamp:
                # Process previous bucket
                if current_bucket is not None and bucket_data:
                    in_mbps_values = [d.bandwidth_in_mbps for d in bucket_data]
                    out_mbps_values = [d.bandwidth_out_mbps for d in bucket_data]
                    
                    timeline_data.append({
                        'timestamp': current_bucket.strftime('%Y-%m-%d %H:%M:%S'),
                        'avg_bandwidth_in_mbps': sum(in_mbps_values) / len(in_mbps_values) if in_mbps_values else 0,
                        'avg_bandwidth_out_mbps': sum(out_mbps_values) / len(out_mbps_values) if out_mbps_values else 0,
                        'peak_bandwidth_in_mbps': max(in_mbps_values) if in_mbps_values else 0,
                        'peak_bandwidth_out_mbps': max(out_mbps_values) if out_mbps_values else 0,
                        'total_bytes_in': sum(d.bytes_in for d in bucket_data),
                        'total_bytes_out': sum(d.bytes_out for d in bucket_data),
                        'sample_count': len(bucket_data)
                    })
                
                # Start new bucket
                current_bucket = bucket_timestamp
                bucket_data = []
            
            bucket_data.append(data_point)
        
        # Process the last bucket
        if current_bucket is not None and bucket_data:
            in_mbps_values = [d.bandwidth_in_mbps for d in bucket_data]
            out_mbps_values = [d.bandwidth_out_mbps for d in bucket_data]
            
            timeline_data.append({
                'timestamp': current_bucket.strftime('%Y-%m-%d %H:%M:%S'),
                'avg_bandwidth_in_mbps': sum(in_mbps_values) / len(in_mbps_values) if in_mbps_values else 0,
                'avg_bandwidth_out_mbps': sum(out_mbps_values) / len(out_mbps_values) if out_mbps_values else 0,
                'peak_bandwidth_in_mbps': max(in_mbps_values) if in_mbps_values else 0,
                'peak_bandwidth_out_mbps': max(out_mbps_values) if out_mbps_values else 0,
                'total_bytes_in': sum(d.bytes_in for d in bucket_data),
                'total_bytes_out': sum(d.bytes_out for d in bucket_data),
                'sample_count': len(bucket_data)
            })
        
        return jsonify({
            'timeline': timeline_data,
            'count': len(timeline_data),
            'interval': interval,
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/bandwidth/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bandwidth_summary():
    """Get bandwidth usage summary statistics"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get network-wide bandwidth statistics
        result = db.session.execute(
            db.text("""
                SELECT 
                    SUM(bytes_in) as total_bytes_in,
                    SUM(bytes_out) as total_bytes_out,
                    AVG(bandwidth_in_mbps) as avg_bandwidth_in,
                    AVG(bandwidth_out_mbps) as avg_bandwidth_out,
                    MAX(bandwidth_in_mbps + bandwidth_out_mbps) as peak_total_bandwidth,
                    COUNT(DISTINCT device_id) as active_devices,
                    COUNT(*) as total_measurements
                FROM bandwidth_data 
                WHERE timestamp >= :cutoff
            """),
            {'cutoff': cutoff}
        ).fetchone()
        
        # Get top bandwidth consumers
        top_consumers = db.session.execute(
            db.text("""
                SELECT 
                    d.id,
                    d.ip_address,
                    d.custom_name,
                    d.hostname,
                    d.device_type,
                    SUM(b.bytes_in + b.bytes_out) as total_bytes,
                    AVG(b.bandwidth_in_mbps + b.bandwidth_out_mbps) as avg_total_mbps,
                    MAX(b.bandwidth_in_mbps + b.bandwidth_out_mbps) as peak_total_mbps
                FROM devices d
                JOIN bandwidth_data b ON d.id = b.device_id
                WHERE b.timestamp >= :cutoff
                GROUP BY d.id, d.ip_address, d.custom_name, d.hostname, d.device_type
                ORDER BY total_bytes DESC
                LIMIT 10
            """),
            {'cutoff': cutoff}
        ).fetchall()
        
        # Format top consumers
        top_consumers_list = []
        for row in top_consumers:
            device_name = row[2] or row[3] or f"Device {row[1]}"
            top_consumers_list.append({
                'device_id': row[0],
                'ip_address': row[1],
                'device_name': device_name,
                'device_type': row[4],
                'total_gb': round(row[5] / (1024**3), 2) if row[5] else 0,
                'avg_mbps': round(row[6], 2) if row[6] else 0,
                'peak_mbps': round(row[7], 2) if row[7] else 0
            })
        
        # Get current real-time bandwidth (last 5 minutes)
        recent_cutoff = datetime.utcnow() - timedelta(minutes=5)
        current_result = db.session.execute(
            db.text("""
                SELECT 
                    AVG(bandwidth_in_mbps) as current_in_mbps,
                    AVG(bandwidth_out_mbps) as current_out_mbps
                FROM bandwidth_data 
                WHERE timestamp >= :recent_cutoff
            """),
            {'recent_cutoff': recent_cutoff}
        ).fetchone()
        
        summary = {
            'period_hours': hours,
            'total_data': {
                'total_gb_in': round(result[0] / (1024**3), 2) if result[0] else 0,
                'total_gb_out': round(result[1] / (1024**3), 2) if result[1] else 0,
                'total_gb': round((result[0] + result[1]) / (1024**3), 2) if result[0] and result[1] else 0
            },
            'average_bandwidth': {
                'avg_in_mbps': round(result[2], 2) if result[2] else 0,
                'avg_out_mbps': round(result[3], 2) if result[3] else 0,
                'avg_total_mbps': round((result[2] + result[3]), 2) if result[2] and result[3] else 0
            },
            'peak_bandwidth': {
                'peak_total_mbps': round(result[4], 2) if result[4] else 0
            },
            'current_bandwidth': {
                'current_in_mbps': round(current_result[0], 2) if current_result[0] else 0,
                'current_out_mbps': round(current_result[1], 2) if current_result[1] else 0,
                'current_total_mbps': round((current_result[0] + current_result[1]), 2) if current_result[0] and current_result[1] else 0
            },
            'statistics': {
                'active_devices': result[5] or 0,
                'total_measurements': result[6] or 0
            },
            'top_consumers': top_consumers_list,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/bandwidth/devices', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_bandwidth_rankings():
    """Get bandwidth usage rankings by device"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=20, type=int)
        
        # Validate parameters
        if hours > 168:  # Max 7 days
            hours = 168
        if limit > 100:  # Max 100 devices
            limit = 100
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get device bandwidth statistics
        device_stats = db.session.execute(
            db.text("""
                SELECT 
                    d.id,
                    d.ip_address,
                    d.custom_name,
                    d.hostname,
                    d.device_type,
                    d.vendor,
                    SUM(b.bytes_in) as total_bytes_in,
                    SUM(b.bytes_out) as total_bytes_out,
                    AVG(b.bandwidth_in_mbps) as avg_in_mbps,
                    AVG(b.bandwidth_out_mbps) as avg_out_mbps,
                    MAX(b.bandwidth_in_mbps) as peak_in_mbps,
                    MAX(b.bandwidth_out_mbps) as peak_out_mbps,
                    COUNT(b.id) as measurement_count
                FROM devices d
                LEFT JOIN bandwidth_data b ON d.id = b.device_id AND b.timestamp >= :cutoff
                WHERE d.is_monitored = 1
                GROUP BY d.id, d.ip_address, d.custom_name, d.hostname, d.device_type, d.vendor
                ORDER BY (COALESCE(total_bytes_in, 0) + COALESCE(total_bytes_out, 0)) DESC
                LIMIT :limit
            """),
            {'cutoff': cutoff, 'limit': limit}
        ).fetchall()
        
        # Format device statistics
        devices = []
        for row in device_stats:
            device_name = row[2] or row[3] or f"Device {row[1]}"
            total_bytes = (row[6] or 0) + (row[7] or 0)
            
            devices.append({
                'device_id': row[0],
                'ip_address': row[1],
                'device_name': device_name,
                'hostname': row[3],
                'device_type': row[4],
                'vendor': row[5],
                'bandwidth_stats': {
                    'total_gb_in': round((row[6] or 0) / (1024**3), 2),
                    'total_gb_out': round((row[7] or 0) / (1024**3), 2),
                    'total_gb': round(total_bytes / (1024**3), 2),
                    'avg_in_mbps': round(row[8], 2) if row[8] else 0,
                    'avg_out_mbps': round(row[9], 2) if row[9] else 0,
                    'avg_total_mbps': round((row[8] or 0) + (row[9] or 0), 2),
                    'peak_in_mbps': round(row[10], 2) if row[10] else 0,
                    'peak_out_mbps': round(row[11], 2) if row[11] else 0,
                    'peak_total_mbps': round((row[10] or 0) + (row[11] or 0), 2),
                    'measurement_count': row[12] or 0
                }
            })
        
        return jsonify({
            'devices': devices,
            'count': len(devices),
            'period_hours': hours,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/priority-summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alert_priority_summary():
    """Get priority summary of all active alerts"""
    try:
        from services.alert_priority import AlertPriorityScorer
        
        # Get active alerts
        active_alerts = Alert.query.filter_by(resolved=False).all()
        
        # Calculate priority summary
        scorer = AlertPriorityScorer(current_app._get_current_object())
        summary = scorer.get_priority_summary(active_alerts)
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/recalculate-priorities', methods=['POST'])
@create_endpoint_limiter('strict')
def recalculate_alert_priorities():
    """Recalculate priorities for all active alerts"""
    try:
        from services.alert_priority import AlertPriorityScorer
        
        # Get active alerts
        active_alerts = Alert.query.filter_by(resolved=False).all()
        
        scorer = AlertPriorityScorer(current_app._get_current_object())
        updated_count = 0
        
        for alert in active_alerts:
            score, level, breakdown = scorer.calculate_priority_score(alert)
            alert.priority_score = score
            alert.priority_level = level
            alert.priority_breakdown = json.dumps(breakdown)
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Recalculated priorities for {updated_count} alerts',
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/by-priority', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alerts_by_priority():
    """Get alerts sorted by priority score"""
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        resolved = request.args.get('resolved', 'false').lower() == 'true'
        min_priority = request.args.get('min_priority', 0, type=int)
        
        # Build query
        query = Alert.query
        
        if not resolved:
            query = query.filter_by(resolved=False)
        
        if min_priority > 0:
            query = query.filter(Alert.priority_score >= min_priority)
        
        # Order by priority score (highest first), then by creation time
        alerts = query.order_by(
            Alert.priority_score.desc(),
            Alert.created_at.desc()
        ).limit(limit).all()
        
        return jsonify([alert.to_dict() for alert in alerts])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>/priority', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alert_priority_details(alert_id):
    """Get detailed priority breakdown for a specific alert"""
    try:
        alert = Alert.query.get(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Recalculate current priority (in case factors have changed)
        from services.alert_priority import AlertPriorityScorer
        scorer = AlertPriorityScorer(current_app._get_current_object())
        current_score, current_level, current_breakdown = scorer.calculate_priority_score(alert)
        
        return jsonify({
            'alert_id': alert.id,
            'stored_priority': {
                'score': alert.priority_score,
                'level': alert.priority_level,
                'breakdown': json.loads(alert.priority_breakdown) if alert.priority_breakdown else None
            },
            'current_priority': {
                'score': current_score,
                'level': current_level,
                'breakdown': current_breakdown
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/bulk-acknowledge', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_acknowledge_alerts():
    """Acknowledge multiple alerts at once"""
    try:
        data = request.get_json()
        
        if not data or 'alert_ids' not in data:
            return jsonify({'error': 'alert_ids list is required'}), 400
        
        alert_ids = data['alert_ids']
        acknowledged_by = data.get('acknowledged_by', 'bulk_operation')
        
        if not isinstance(alert_ids, list):
            return jsonify({'error': 'alert_ids must be a list'}), 400
        
        # Find alerts to acknowledge
        alerts = Alert.query.filter(
            Alert.id.in_(alert_ids),
            Alert.acknowledged == False
        ).all()
        
        acknowledged_count = 0
        for alert in alerts:
            alert.acknowledge(acknowledged_by)
            acknowledged_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Acknowledged {acknowledged_count} alerts',
            'acknowledged_count': acknowledged_count,
            'requested_count': len(alert_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/bulk-resolve', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_resolve_alerts():
    """Resolve multiple alerts at once"""
    try:
        data = request.get_json()
        
        if not data or 'alert_ids' not in data:
            return jsonify({'error': 'alert_ids list is required'}), 400
        
        alert_ids = data['alert_ids']
        
        if not isinstance(alert_ids, list):
            return jsonify({'error': 'alert_ids must be a list'}), 400
        
        # Find alerts to resolve
        alerts = Alert.query.filter(
            Alert.id.in_(alert_ids),
            Alert.resolved == False
        ).all()
        
        resolved_count = 0
        for alert in alerts:
            alert.resolve()
            resolved_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Resolved {resolved_count} alerts',
            'resolved_count': resolved_count,
            'requested_count': len(alert_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/bulk-delete', methods=['POST'])
@create_endpoint_limiter('critical')
def bulk_delete_alerts_by_ids():
    """Delete multiple alerts at once (for resolved alerts only)"""
    try:
        data = request.get_json()
        
        if not data or 'alert_ids' not in data:
            return jsonify({'error': 'alert_ids list is required'}), 400
        
        alert_ids = data['alert_ids']
        force = data.get('force', False)  # Allow forcing deletion of unresolved alerts
        
        if not isinstance(alert_ids, list):
            return jsonify({'error': 'alert_ids must be a list'}), 400
        
        # Build query - only allow deletion of resolved alerts unless force=true
        query = Alert.query.filter(Alert.id.in_(alert_ids))
        if not force:
            query = query.filter(Alert.resolved == True)
        
        alerts_to_delete = query.all()
        
        if not alerts_to_delete:
            return jsonify({
                'success': True,
                'message': 'No alerts found to delete (only resolved alerts can be deleted unless force=true)',
                'deleted_count': 0,
                'requested_count': len(alert_ids)
            })
        
        deleted_count = len(alerts_to_delete)
        
        # Delete alerts
        for alert in alerts_to_delete:
            db.session.delete(alert)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} alerts',
            'deleted_count': deleted_count,
            'requested_count': len(alert_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/bulk-update-priority', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_update_alert_priority():
    """Update priority for multiple alerts at once"""
    try:
        data = request.get_json()
        
        if not data or 'alert_ids' not in data:
            return jsonify({'error': 'alert_ids list is required'}), 400
        
        alert_ids = data['alert_ids']
        
        if not isinstance(alert_ids, list):
            return jsonify({'error': 'alert_ids must be a list'}), 400
        
        # Find alerts to update
        alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
        
        from services.alert_priority import AlertPriorityScorer
        scorer = AlertPriorityScorer(current_app._get_current_object())
        
        updated_count = 0
        for alert in alerts:
            score, level, breakdown = scorer.calculate_priority_score(alert)
            alert.priority_score = score
            alert.priority_level = level
            alert.priority_breakdown = json.dumps(breakdown)
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Updated priority for {updated_count} alerts',
            'updated_count': updated_count,
            'requested_count': len(alert_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/suppressions', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alert_suppressions():
    """Get all alert suppression rules"""
    try:
        from models import AlertSuppression
        
        suppressions = AlertSuppression.query.order_by(AlertSuppression.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'suppressions': [suppression.to_dict() for suppression in suppressions],
            'count': len(suppressions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/suppressions', methods=['POST'])
@create_endpoint_limiter('strict')
def create_alert_suppression():
    """Create a new alert suppression rule"""
    try:
        from models import AlertSuppression
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not data.get('name'):
            return jsonify({'error': 'Name is required'}), 400
        
        # Parse datetime fields if provided
        start_time = None
        end_time = None
        
        if data.get('start_time'):
            try:
                start_time = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00')).replace(tzinfo=None)
            except ValueError:
                return jsonify({'error': 'Invalid start_time format. Use ISO format.'}), 400
        
        if data.get('end_time'):
            try:
                end_time = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00')).replace(tzinfo=None)
            except ValueError:
                return jsonify({'error': 'Invalid end_time format. Use ISO format.'}), 400
        
        suppression = AlertSuppression(
            name=data['name'],
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            device_id=data.get('device_id'),
            alert_type=data.get('alert_type'),
            severity=data.get('severity'),
            start_time=start_time,
            end_time=end_time,
            daily_start_hour=data.get('daily_start_hour'),
            daily_end_hour=data.get('daily_end_hour'),
            suppression_type=data.get('suppression_type', 'silence'),
            priority_reduction=data.get('priority_reduction', 0),
            delay_minutes=data.get('delay_minutes', 0),
            created_by=data.get('created_by', 'api_user')
        )
        
        db.session.add(suppression)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alert suppression rule created successfully',
            'suppression': suppression.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/suppressions/<int:suppression_id>', methods=['PUT'])
@create_endpoint_limiter('strict')
def update_alert_suppression(suppression_id):
    """Update an alert suppression rule"""
    try:
        from models import AlertSuppression
        
        suppression = AlertSuppression.query.get(suppression_id)
        if not suppression:
            return jsonify({'error': 'Suppression rule not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'name' in data:
            suppression.name = data['name']
        if 'description' in data:
            suppression.description = data['description']
        if 'enabled' in data:
            suppression.enabled = data['enabled']
        if 'device_id' in data:
            suppression.device_id = data['device_id']
        if 'alert_type' in data:
            suppression.alert_type = data['alert_type']
        if 'severity' in data:
            suppression.severity = data['severity']
        if 'suppression_type' in data:
            suppression.suppression_type = data['suppression_type']
        if 'priority_reduction' in data:
            suppression.priority_reduction = data['priority_reduction']
        if 'delay_minutes' in data:
            suppression.delay_minutes = data['delay_minutes']
        if 'daily_start_hour' in data:
            suppression.daily_start_hour = data['daily_start_hour']
        if 'daily_end_hour' in data:
            suppression.daily_end_hour = data['daily_end_hour']
        
        # Handle datetime fields
        if 'start_time' in data:
            if data['start_time']:
                try:
                    suppression.start_time = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00')).replace(tzinfo=None)
                except ValueError:
                    return jsonify({'error': 'Invalid start_time format. Use ISO format.'}), 400
            else:
                suppression.start_time = None
        
        if 'end_time' in data:
            if data['end_time']:
                try:
                    suppression.end_time = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00')).replace(tzinfo=None)
                except ValueError:
                    return jsonify({'error': 'Invalid end_time format. Use ISO format.'}), 400
            else:
                suppression.end_time = None
        
        suppression.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alert suppression rule updated successfully',
            'suppression': suppression.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/suppressions/<int:suppression_id>', methods=['DELETE'])
@create_endpoint_limiter('critical')
def delete_alert_suppression(suppression_id):
    """Delete an alert suppression rule"""
    try:
        from models import AlertSuppression
        
        suppression = AlertSuppression.query.get(suppression_id)
        if not suppression:
            return jsonify({'error': 'Suppression rule not found'}), 404
        
        db.session.delete(suppression)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alert suppression rule deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/suppressions/active', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_active_suppressions():
    """Get currently active suppression rules"""
    try:
        from models import AlertSuppression
        
        all_suppressions = AlertSuppression.query.filter_by(enabled=True).all()
        active_suppressions = [s for s in all_suppressions if s.is_currently_active()]
        
        return jsonify({
            'success': True,
            'active_suppressions': [suppression.to_dict() for suppression in active_suppressions],
            'count': len(active_suppressions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alert_timeline(alert_id):
    """Get timeline for a specific alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        timeline = []
        
        # Alert creation
        timeline.append({
            'timestamp': alert.created_at.isoformat() + 'Z',
            'action': 'Alert Created',
            'description': f'{alert.severity.title()} alert created for {alert.device.display_name}',
            'icon': 'bi-exclamation-triangle',
            'color': 'danger' if alert.severity == 'critical' else 'warning' if alert.severity == 'warning' else 'info'
        })
        
        # Acknowledgment
        if alert.acknowledged:
            timeline.append({
                'timestamp': alert.acknowledged_at.isoformat() + 'Z',
                'action': 'Alert Acknowledged',
                'description': f'Acknowledged by {alert.acknowledged_by}',
                'icon': 'bi-check',
                'color': 'success'
            })
        
        # Resolution
        if alert.resolved:
            timeline.append({
                'timestamp': alert.resolved_at.isoformat() + 'Z',
                'action': 'Alert Resolved',
                'description': 'Alert was resolved',
                'icon': 'bi-check-circle',
                'color': 'success'
            })
        
        # Get related monitoring data around the alert time
        alert_time = alert.created_at
        time_window = timedelta(hours=1)
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == alert.device_id,
            MonitoringData.timestamp >= alert_time - time_window,
            MonitoringData.timestamp <= alert_time + time_window
        ).order_by(MonitoringData.timestamp).limit(10).all()
        
        # Add significant monitoring events
        for data in monitoring_data:
            if data.response_time is None:
                timeline.append({
                    'timestamp': data.timestamp.isoformat() + 'Z',
                    'action': 'Connection Failed',
                    'description': f'Device ping failed at {data.timestamp.strftime("%H:%M:%S")}',
                    'icon': 'bi-x-circle',
                    'color': 'danger'
                })
            elif data.response_time > 1000:  # High latency
                timeline.append({
                    'timestamp': data.timestamp.isoformat() + 'Z',
                    'action': 'High Latency Detected',
                    'description': f'Response time: {data.response_time:.0f}ms',
                    'icon': 'bi-clock',
                    'color': 'warning'
                })
        
        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return jsonify({
            'timeline': timeline,
            'alert_id': alert_id,
            'device_name': alert.device.display_name
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>/unified-timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_unified_alert_timeline(alert_id):
    """Get unified timeline for a specific alert including notifications"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        timeline = []
        
        # Alert creation
        timeline.append({
            'timestamp': alert.created_at.isoformat() + 'Z',
            'type': 'alert',
            'action': 'Alert Created',
            'description': f'{alert.severity.title()} alert created for {alert.device.display_name}',
            'icon': 'bi-exclamation-triangle',
            'color': 'danger' if alert.severity == 'critical' else 'warning' if alert.severity == 'warning' else 'info',
            'details': {
                'alert_type': alert.alert_type,
                'message': alert.message,
                'severity': alert.severity
            }
        })
        
        # Add notifications for this alert
        from models import NotificationHistory
        notifications = NotificationHistory.query.filter_by(alert_id=alert_id)\
                                                 .order_by(NotificationHistory.sent_at)\
                                                 .all()
        
        for notification in notifications:
            status_color = 'success' if notification.delivery_status == 'success' else 'danger' if notification.delivery_status == 'failed' else 'secondary'
            timeline.append({
                'timestamp': notification.sent_at.isoformat() + 'Z',
                'type': 'notification',
                'action': f'Notification {notification.delivery_status.title()}',
                'description': f'{notification.notification_type.replace("_", " ").title()} notification {notification.delivery_status}',
                'icon': 'bi-bell' if notification.delivery_status == 'success' else 'bi-bell-slash' if notification.delivery_status == 'failed' else 'bi-bell',
                'color': status_color,
                'details': {
                    'notification_type': notification.notification_type,
                    'title': notification.title,
                    'priority': notification.priority,
                    'delivery_status': notification.delivery_status,
                    'error_message': notification.error_message
                }
            })
        
        # Acknowledgment
        if alert.acknowledged:
            timeline.append({
                'timestamp': alert.acknowledged_at.isoformat() + 'Z',
                'type': 'alert',
                'action': 'Alert Acknowledged',
                'description': f'Acknowledged by {alert.acknowledged_by}',
                'icon': 'bi-check',
                'color': 'success',
                'details': {
                    'acknowledged_by': alert.acknowledged_by
                }
            })
        
        # Resolution
        if alert.resolved:
            timeline.append({
                'timestamp': alert.resolved_at.isoformat() + 'Z',
                'type': 'alert',
                'action': 'Alert Resolved',
                'description': 'Alert was resolved',
                'icon': 'bi-check-circle',
                'color': 'success',
                'details': {}
            })
        
        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return jsonify({
            'alert_id': alert_id,
            'timeline': timeline,
            'summary': {
                'total_events': len(timeline),
                'notifications_sent': len(notifications),
                'notification_success_rate': round(
                    (len([n for n in notifications if n.delivery_status == 'success']) / len(notifications) * 100) 
                    if notifications else 0, 1
                ),
                'alert_duration': (
                    (alert.resolved_at - alert.created_at).total_seconds() / 60
                    if alert.resolved else 
                    (datetime.utcnow() - alert.created_at).total_seconds() / 60
                )
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_summary():
    """Get comprehensive monitoring summary for high-level dashboard"""
    try:
        from models import Device, Alert, MonitoringData
        from datetime import datetime, timedelta
        
        # Get current network range
        network_range = get_current_network_range()
        
        # Get device counts
        total_devices = Device.query.count()
        
        # Determine status of devices (based on last_seen within 10 minutes)
        online_threshold = datetime.utcnow() - timedelta(minutes=10)
        devices_up = Device.query.filter(
            Device.is_monitored == True,
            Device.last_seen >= online_threshold
        ).count()
        
        devices_down = Device.query.filter(
            Device.is_monitored == True,
            Device.last_seen < online_threshold
        ).count()
        
        devices_unknown = total_devices - devices_up - devices_down
        
        # Get active alerts count
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Calculate average response time from recent monitoring data
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_data = MonitoringData.query.filter(
            MonitoringData.timestamp >= one_hour_ago,
            MonitoringData.response_time.isnot(None)
        ).all()
        
        avg_response_time = 0
        if recent_data:
            response_times = [d.response_time for d in recent_data if d.response_time]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Calculate network uptime (percentage of devices up)
        network_uptime = "99.9%"  # Default value
        if total_devices > 0:
            uptime_percent = (devices_up / total_devices) * 100
            network_uptime = f"{uptime_percent:.1f}%"
        
        return jsonify({
            'total_devices': total_devices,
            'devices_up': devices_up,
            'devices_down': devices_down,
            'devices_unknown': devices_unknown,
            'active_alerts': active_alerts,
            'avg_response_time': round(avg_response_time, 2),
            'network_uptime': network_uptime,
            'network_range': network_range,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@monitoring_bp.route('/recent-activity', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_recent_activity():
    """Get recent network activity for dashboard feed"""
    try:
        from models import Device, Alert, MonitoringData
        from datetime import datetime, timedelta
        
        limit = request.args.get('limit', 10, type=int)
        activities = []
        
        # Get recent device status changes
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        # Get recent alerts
        recent_alerts = Alert.query.filter(
            Alert.created_at >= one_hour_ago
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        
        for alert in recent_alerts:
            activities.append({
                'type': 'alert',
                'message': f'{alert.device.display_name}: {alert.message}',
                'timestamp': alert.created_at.isoformat() + 'Z',
                'severity': alert.severity
            })
        
        # Get recent device status changes
        recent_devices = Device.query.filter(
            Device.updated_at >= one_hour_ago
        ).order_by(Device.updated_at.desc()).limit(limit).all()
        
        for device in recent_devices:
            if device.status == 'up':
                activities.append({
                    'type': 'device_up',
                    'message': f'{device.display_name} came online',
                    'timestamp': device.updated_at.isoformat() + 'Z',
                    'severity': 'info'
                })
            elif device.status == 'down':
                activities.append({
                    'type': 'device_down',
                    'message': f'{device.display_name} went offline',
                    'timestamp': device.updated_at.isoformat() + 'Z',
                    'severity': 'warning'
                })
        
        # Sort by timestamp and limit
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        activities = activities[:limit]
        
        return jsonify({
            'activities': activities,
            'count': len(activities)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
