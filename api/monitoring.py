from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func
from models import db, Device, MonitoringData, Alert, BandwidthData
from monitoring.monitor import DeviceMonitor

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/scan', methods=['POST'])
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
def get_monitoring_data():
    """Get monitoring data with optional filtering"""
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
        query = MonitoringData.query.filter(MonitoringData.timestamp >= cutoff)
        
        if device_id:
            query = query.filter(MonitoringData.device_id == device_id)
        
        monitoring_data = query.order_by(MonitoringData.timestamp.desc()).limit(limit).all()
        
        # Convert to dict format
        data = []
        for item in monitoring_data:
            item_dict = item.to_dict()
            item_dict['device_name'] = item.device.display_name
            item_dict['device_ip'] = item.device.ip_address
            data.append(item_dict)
        
        return jsonify({
            'monitoring_data': data,
            'count': len(data),
            'hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/statistics', methods=['GET'])
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

@monitoring_bp.route('/chart-data', methods=['GET'])
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
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        data = request.get_json() or {}
        acknowledged_by = data.get('acknowledged_by', 'api_user')
        
        alert.acknowledge(acknowledged_by)
        
        return jsonify(alert.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/acknowledge-all', methods=['POST'])
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
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        alert.resolve()
        
        return jsonify(alert.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/alerts/<int:alert_id>', methods=['DELETE'])
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

@monitoring_bp.route('/alerts/cleanup-duplicates', methods=['POST'])
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
def get_monitoring_status():
    """Get overall monitoring system status"""
    try:
        # Get system statistics
        monitor = DeviceMonitor()
        network_stats = monitor.get_network_statistics(hours=1)
        
        # Count devices by status
        devices = Device.query.filter_by(is_monitored=True).all()
        status_counts = {
            'up': 0,
            'down': 0,
            'warning': 0,
            'unknown': 0
        }
        
        for device in devices:
            status = device.status
            if status in status_counts:
                status_counts[status] += 1
        
        # Active alerts by severity
        alert_counts = {
            'critical': Alert.query.filter_by(resolved=False, severity='critical').count(),
            'warning': Alert.query.filter_by(resolved=False, severity='warning').count(),
            'info': Alert.query.filter_by(resolved=False, severity='info').count()
        }
        
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
def get_background_activity():
    """Get background monitoring activity information"""
    try:
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
        
        return jsonify({
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
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/topology-test', methods=['GET'])
def get_topology_test():
    """Network topology endpoint with all real devices"""
    try:
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        # Create nodes for devices
        nodes = []
        for device in devices:
            # Determine node color based on status
            color_map = {
                'up': '#28a745',
                'down': '#dc3545', 
                'warning': '#ffc107',
                'unknown': '#6c757d'
            }
            
            # Get device type icon
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
            
            # Get latest response time directly to avoid property caching issues
            latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                             .order_by(MonitoringData.timestamp.desc())\
                                             .first()
            latest_response_time = latest_data.response_time if latest_data else None
            
            # Get active alerts count
            active_alerts = Alert.query.filter_by(device_id=device.id, resolved=False).count()
            
            nodes.append({
                'id': str(device.id),
                'label': device.display_name,
                'ip': device.ip_address,
                'status': device.status,
                'color': color_map.get(device.status, '#6c757d'),
                'icon': icon_map.get(device.device_type, '❓'),
                'device_type': device.device_type,
                'response_time': latest_response_time,
                'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
                'uptime_percentage': device.uptime_percentage or 0,
                'active_alerts': active_alerts,
                'size': 20 + (device.uptime_percentage or 0) / 5  # Size based on uptime
            })
        
        # Create edges (connections) - hub topology with router at center
        edges = []
        router_device = None
        
        # Find the router (usually .1 in the network)
        for device in devices:
            if device.ip_address.endswith('.1') or 'router' in device.device_type.lower():
                router_device = device
                break
        
        # If no explicit router found, use the first device as hub
        if not router_device and devices:
            router_device = devices[0]
        
        # Create star topology with router at center
        if router_device:
            for device in devices:
                if device.id != router_device.id:
                    # Connection strength based on response time
                    strength = 1.0
                    # Get latest response time for this device
                    latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                                     .order_by(MonitoringData.timestamp.desc())\
                                                     .first()
                    if latest_data and latest_data.response_time:
                        # Lower response time = stronger connection
                        strength = max(0.1, 1.0 - (latest_data.response_time / 1000.0))
                    
                    edges.append({
                        'source': str(router_device.id),
                        'target': str(device.id),
                        'strength': strength,
                        'color': '#28a745' if device.status == 'up' else '#dc3545'
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
def get_network_topology():
    """Get network topology data for interactive graph visualization"""
    try:
        # Get all devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        # Create nodes for devices
        nodes = []
        for device in devices:
            # Determine node color based on status
            color_map = {
                'up': '#28a745',
                'down': '#dc3545', 
                'warning': '#ffc107',
                'unknown': '#6c757d'
            }
            
            # Get device type icon
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
            
            # Get latest response time directly to avoid property caching issues
            latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                             .order_by(MonitoringData.timestamp.desc())\
                                             .first()
            latest_response_time = latest_data.response_time if latest_data else None
            
            # Get active alerts count
            active_alerts = Alert.query.filter_by(device_id=device.id, resolved=False).count()
            
            nodes.append({
                'id': str(device.id),
                'label': device.display_name,
                'ip': device.ip_address,
                'status': device.status,
                'color': color_map.get(device.status, '#6c757d'),
                'icon': icon_map.get(device.device_type, '❓'),
                'device_type': device.device_type,
                'response_time': latest_response_time,
                'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
                'uptime_percentage': device.uptime_percentage or 0,
                'active_alerts': active_alerts,
                'size': 20 + (device.uptime_percentage or 0) / 5  # Size based on uptime
            })
        
        # Create edges (connections) - for now, we'll connect everything to the router
        # In a real network, you'd determine actual topology through ARP tables, switch data, etc.
        edges = []
        router_device = None
        
        # Find the router (usually .1 in the network)
        for device in devices:
            if device.ip_address.endswith('.1') or 'router' in device.device_type.lower():
                router_device = device
                break
        
        # If no explicit router found, use the first device as hub
        if not router_device and devices:
            router_device = devices[0]
        
        # Create star topology with router at center
        if router_device:
            for device in devices:
                if device.id != router_device.id:
                    # Connection strength based on response time
                    strength = 1.0
                    # Get latest response time for this device
                    latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                                     .order_by(MonitoringData.timestamp.desc())\
                                                     .first()
                    if latest_data and latest_data.response_time:
                        # Lower response time = stronger connection
                        strength = max(0.1, 1.0 - (latest_data.response_time / 1000.0))
                    
                    edges.append({
                        'source': str(router_device.id),
                        'target': str(device.id),
                        'strength': strength,
                        'color': '#28a745' if device.status == 'up' else '#dc3545'
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