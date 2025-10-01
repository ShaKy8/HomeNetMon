# HomeNetMon Mobile API - Optimized for mobile applications and SDKs
from flask import Blueprint, request, jsonify, g
from datetime import datetime, timedelta
import json
import time
import gzip
import base64
from collections import defaultdict
import logging
from functools import wraps
from models import Device, MonitoringData, Alert, db
import sqlalchemy as sa
from api.rate_limited_endpoints import create_endpoint_limiter

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
mobile_api = Blueprint('mobile_api', __name__, url_prefix='/api/mobile/v1')

# ============================================================================
# Mobile API Middleware and Utilities
# ============================================================================

def mobile_auth_required(f):
    """Enhanced auth decorator for mobile clients"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_manager = get_auth_manager()
        
        # Check for API key in header
        api_key = request.headers.get('X-API-Key')
        session_token = request.headers.get('Authorization')
        
        if session_token and session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        user_data = None
        
        # Try API key first
        if api_key:
            user_data = auth_manager.validate_api_key(api_key)
            if user_data:
                user_data['auth_method'] = 'api_key'
        
        # Fall back to session token
        if not user_data and session_token:
            user_data = auth_manager.validate_session(session_token)
            if user_data:
                user_data['auth_method'] = 'session'
        
        if not user_data:
            return jsonify({
                'error': 'Authentication required',
                'code': 'AUTH_REQUIRED',
                'message': 'Valid API key or session token required'
            }), 401
        
        # Add user data to request context
        g.current_user = user_data
        return f(*args, **kwargs)
    
    return decorated_function

def compress_response(data, threshold=1024):
    """Compress response data if it exceeds threshold"""
    json_data = json.dumps(data)
    
    if len(json_data) > threshold:
        # Compress the data
        compressed = gzip.compress(json_data.encode('utf-8'))
        
        # Return compressed data with metadata
        return {
            'compressed': True,
            'data': base64.b64encode(compressed).decode('utf-8'),
            'original_size': len(json_data),
            'compressed_size': len(compressed)
        }
    
    return {'compressed': False, 'data': data}

def paginate_results(query, page=1, per_page=50, max_per_page=200):
    """Paginate query results for mobile consumption"""
    page = max(1, page)
    per_page = min(max_per_page, max(1, per_page))
    
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'items': items,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page * per_page < total
        }
    }

# ============================================================================
# Device Management API
# ============================================================================

@mobile_api.route('/devices', methods=['GET'])
@create_endpoint_limiter('relaxed')
@mobile_auth_required
def get_devices():
    """Get devices with mobile-optimized format"""
    try:
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        status_filter = request.args.get('status')
        device_type = request.args.get('device_type')
        search = request.args.get('search')
        include_metrics = request.args.get('include_metrics', 'false').lower() == 'true'
        compress = request.args.get('compress', 'true').lower() == 'true'
        
        # Build query
        query = Device.query
        
        # Apply filters
        if status_filter:
            query = query.filter(Device.status == status_filter)
        
        if device_type:
            query = query.filter(Device.device_type == device_type)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                sa.or_(
                    Device.display_name.ilike(search_term),
                    Device.ip_address.ilike(search_term),
                    Device.mac_address.ilike(search_term)
                )
            )
        
        # Order by last seen (most recent first)
        query = query.order_by(Device.last_seen.desc().nullslast())
        
        # Paginate results
        result = paginate_results(query, page, per_page)
        
        # Format devices for mobile
        devices = []
        for device in result['items']:
            device_data = {
                'id': device.id,
                'display_name': device.display_name,
                'ip_address': device.ip_address,
                'mac_address': device.mac_address,
                'device_type': device.device_type,
                'status': device.status,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'uptime_percentage': device.uptime_percentage() or 0,
                'latest_response_time': device.latest_response_time,
                'active_alerts': device.active_alerts or 0,
                'device_group': device.device_group,
                'created_at': device.created_at.isoformat(),
                'vendor': device.vendor
            }
            
            # Include detailed metrics if requested
            if include_metrics:
                device_data['metrics'] = get_device_metrics_summary(device.id)
            
            devices.append(device_data)
        
        response_data = {
            'success': True,
            'devices': devices,
            'pagination': result['pagination'],
            'filters': {
                'status': status_filter,
                'device_type': device_type,
                'search': search
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Compress if requested and beneficial
        if compress:
            response_data = compress_response(response_data)
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve devices',
            'code': 'DEVICES_ERROR',
            'message': str(e)
        }), 500

@mobile_api.route('/devices/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
@mobile_auth_required
def get_device_details(device_id):
    """Get detailed device information"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Get recent monitoring data
        hours_back = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours_back)
        
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= since
        ).order_by(MonitoringData.timestamp.desc()).limit(100).all()
        
        # Get recent alerts
        recent_alerts = Alert.query.filter(
            Alert.device_id == device_id,
            Alert.created_at >= since
        ).order_by(Alert.created_at.desc()).limit(10).all()
        
        # Format response
        device_data = {
            'id': device.id,
            'display_name': device.display_name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'device_type': device.device_type,
            'status': device.status,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'uptime_percentage': device.uptime_percentage() or 0,
            'latest_response_time': device.latest_response_time,
            'active_alerts': device.active_alerts or 0,
            'device_group': device.device_group,
            'created_at': device.created_at.isoformat(),
            'vendor': device.vendor,
            'description': device.description,
            'monitoring_enabled': device.monitoring_enabled,
            
            # Recent metrics
            'recent_metrics': [
                {
                    'timestamp': data.timestamp.isoformat(),
                    'response_time': data.response_time,
                    'packet_loss': data.packet_loss,
                    'status': data.status
                }
                for data in monitoring_data
            ],
            
            # Recent alerts
            'recent_alerts': [
                {
                    'id': alert.id,
                    'severity': alert.severity,
                    'message': alert.message,
                    'created_at': alert.created_at.isoformat(),
                    'acknowledged': alert.acknowledged,
                    'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
                }
                for alert in recent_alerts
            ],
            
            # Performance summary
            'performance_summary': calculate_device_performance_summary(device_id, hours_back)
        }
        
        return jsonify({
            'success': True,
            'device': device_data,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve device details',
            'code': 'DEVICE_ERROR',
            'message': str(e)
        }), 500

def get_device_metrics_summary(device_id):
    """Get device metrics summary"""
    try:
        # Get last 24 hours of data
        since = datetime.utcnow() - timedelta(hours=24)
        
        metrics = db.session.query(
            sa.func.avg(MonitoringData.response_time).label('avg_response_time'),
            sa.func.min(MonitoringData.response_time).label('min_response_time'),
            sa.func.max(MonitoringData.response_time).label('max_response_time'),
            sa.func.avg(MonitoringData.packet_loss).label('avg_packet_loss'),
            sa.func.count(MonitoringData.id).label('total_checks')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= since
        ).first()
        
        if metrics and metrics.total_checks:
            return {
                'avg_response_time': round(metrics.avg_response_time or 0, 2),
                'min_response_time': round(metrics.min_response_time or 0, 2),
                'max_response_time': round(metrics.max_response_time or 0, 2),
                'avg_packet_loss': round(metrics.avg_packet_loss or 0, 2),
                'total_checks': metrics.total_checks,
                'period_hours': 24
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting device metrics for {device_id}: {e}")
        return None

def calculate_device_performance_summary(device_id, hours_back):
    """Calculate device performance summary"""
    try:
        since = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Get status distribution
        status_counts = db.session.query(
            MonitoringData.status,
            sa.func.count(MonitoringData.id).label('count')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= since
        ).group_by(MonitoringData.status).all()
        
        total_checks = sum(count.count for count in status_counts)
        
        if total_checks == 0:
            return None
        
        status_distribution = {
            status.status: {
                'count': status.count,
                'percentage': round((status.count / total_checks) * 100, 2)
            }
            for status in status_counts
        }
        
        # Calculate uptime percentage
        up_count = sum(
            count.count for count in status_counts 
            if count.status in ['up', 'responding']
        )
        uptime_percentage = round((up_count / total_checks) * 100, 2)
        
        return {
            'uptime_percentage': uptime_percentage,
            'total_checks': total_checks,
            'status_distribution': status_distribution,
            'period_hours': hours_back
        }
        
    except Exception as e:
        logger.error(f"Error calculating performance summary for {device_id}: {e}")
        return None

# ============================================================================
# Real-time Data Sync API
# ============================================================================

@mobile_api.route('/sync/delta', methods=['GET'])
@create_endpoint_limiter('relaxed')
@mobile_auth_required
def get_delta_sync():
    """Get incremental updates since last sync"""
    try:
        # Parse parameters
        last_sync = request.args.get('last_sync')
        include_devices = request.args.get('include_devices', 'true').lower() == 'true'
        include_alerts = request.args.get('include_alerts', 'true').lower() == 'true'
        include_monitoring = request.args.get('include_monitoring', 'false').lower() == 'true'
        
        if last_sync:
            try:
                last_sync_time = datetime.fromisoformat(last_sync.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid last_sync format. Use ISO 8601 format.',
                    'code': 'INVALID_TIMESTAMP'
                }), 400
        else:
            # Default to last hour if no sync time provided
            last_sync_time = datetime.utcnow() - timedelta(hours=1)
        
        delta_data = {}
        
        # Get updated devices
        if include_devices:
            updated_devices = Device.query.filter(
                Device.updated_at >= last_sync_time
            ).all()
            
            delta_data['devices'] = {
                'updated': [
                    {
                        'id': device.id,
                        'display_name': device.display_name,
                        'ip_address': device.ip_address,
                        'status': device.status,
                        'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                        'uptime_percentage': device.uptime_percentage() or 0,
                        'latest_response_time': device.latest_response_time,
                        'active_alerts': device.active_alerts or 0,
                        'updated_at': device.updated_at.isoformat()
                    }
                    for device in updated_devices
                ],
                'count': len(updated_devices)
            }
        
        # Get new/updated alerts
        if include_alerts:
            new_alerts = Alert.query.filter(
                Alert.created_at >= last_sync_time
            ).order_by(Alert.created_at.desc()).limit(100).all()
            
            updated_alerts = Alert.query.filter(
                Alert.updated_at >= last_sync_time,
                Alert.created_at < last_sync_time
            ).order_by(Alert.updated_at.desc()).limit(50).all()
            
            delta_data['alerts'] = {
                'new': [
                    {
                        'id': alert.id,
                        'device_id': alert.device_id,
                        'severity': alert.severity,
                        'message': alert.message,
                        'created_at': alert.created_at.isoformat(),
                        'acknowledged': alert.acknowledged
                    }
                    for alert in new_alerts
                ],
                'updated': [
                    {
                        'id': alert.id,
                        'acknowledged': alert.acknowledged,
                        'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                        'updated_at': alert.updated_at.isoformat()
                    }
                    for alert in updated_alerts
                ],
                'new_count': len(new_alerts),
                'updated_count': len(updated_alerts)
            }
        
        # Get recent monitoring data
        if include_monitoring:
            recent_monitoring = MonitoringData.query.filter(
                MonitoringData.timestamp >= last_sync_time
            ).order_by(MonitoringData.timestamp.desc()).limit(500).all()
            
            delta_data['monitoring'] = {
                'data': [
                    {
                        'device_id': data.device_id,
                        'timestamp': data.timestamp.isoformat(),
                        'response_time': data.response_time,
                        'packet_loss': data.packet_loss,
                        'status': data.status
                    }
                    for data in recent_monitoring
                ],
                'count': len(recent_monitoring)
            }
        
        return jsonify({
            'success': True,
            'delta': delta_data,
            'sync_timestamp': datetime.utcnow().isoformat(),
            'last_sync': last_sync_time.isoformat(),
            'has_more': False  # Could implement pagination for large deltas
        })
        
    except Exception as e:
        logger.error(f"Error in delta sync: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve delta sync',
            'code': 'SYNC_ERROR',
            'message': str(e)
        }), 500

@mobile_api.route('/sync/batch', methods=['POST'])
@create_endpoint_limiter('bulk')
@mobile_auth_required
def batch_sync():
    """Batch sync operations for offline queue processing"""
    try:
        data = request.get_json()
        
        if not data or 'operations' not in data:
            return jsonify({
                'success': False,
                'error': 'Operations array required',
                'code': 'INVALID_REQUEST'
            }), 400
        
        operations = data['operations']
        results = []
        
        for i, operation in enumerate(operations):
            try:
                result = process_sync_operation(operation)
                results.append({
                    'index': i,
                    'success': True,
                    'result': result
                })
            except Exception as e:
                logger.error(f"Error processing operation {i}: {e}")
                results.append({
                    'index': i,
                    'success': False,
                    'error': str(e),
                    'operation': operation.get('type', 'unknown')
                })
        
        # Commit all successful operations
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing batch sync: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to commit batch operations',
                'code': 'COMMIT_ERROR',
                'results': results
            }), 500
        
        return jsonify({
            'success': True,
            'results': results,
            'processed': len(operations),
            'successful': sum(1 for r in results if r['success']),
            'failed': sum(1 for r in results if not r['success']),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in batch sync: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to process batch sync',
            'code': 'BATCH_ERROR',
            'message': str(e)
        }), 500

def process_sync_operation(operation):
    """Process individual sync operation"""
    op_type = operation.get('type')
    
    if op_type == 'acknowledge_alert':
        alert_id = operation.get('alert_id')
        alert = Alert.query.get(alert_id)
        if alert:
            alert.acknowledged = True
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = g.current_user['username']
            return {'alert_id': alert_id, 'acknowledged': True}
        else:
            raise ValueError(f"Alert {alert_id} not found")
    
    elif op_type == 'update_device':
        device_id = operation.get('device_id')
        updates = operation.get('updates', {})
        device = Device.query.get(device_id)
        if device:
            for key, value in updates.items():
                if hasattr(device, key) and key in ['display_name', 'description', 'device_group']:
                    setattr(device, key, value)
            device.updated_at = datetime.utcnow()
            return {'device_id': device_id, 'updated': True}
        else:
            raise ValueError(f"Device {device_id} not found")
    
    elif op_type == 'ping_device':
        device_id = operation.get('device_id')
        # Queue ping operation (implementation would depend on monitoring system)
        return {'device_id': device_id, 'ping_queued': True}
    
    else:
        raise ValueError(f"Unknown operation type: {op_type}")

# ============================================================================
# Network Summary API
# ============================================================================

@mobile_api.route('/network/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
@mobile_auth_required
def get_network_summary():
    """Get network overview optimized for mobile dashboards"""
    try:
        # Cache duration for summary data
        cache_minutes = request.args.get('cache', 5, type=int)
        
        # Get device counts by status
        device_counts = db.session.query(
            Device.status,
            sa.func.count(Device.id).label('count')
        ).group_by(Device.status).all()
        
        total_devices = sum(count.count for count in device_counts)
        
        status_summary = {}
        for status in device_counts:
            status_summary[status.status] = {
                'count': status.count,
                'percentage': round((status.count / total_devices * 100), 1) if total_devices > 0 else 0
            }
        
        # Get recent alert summary
        recent_alerts = db.session.query(
            Alert.severity,
            sa.func.count(Alert.id).label('count')
        ).filter(
            Alert.acknowledged == False,
            Alert.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).group_by(Alert.severity).all()
        
        alert_summary = {}
        for alert in recent_alerts:
            alert_summary[alert.severity] = alert.count
        
        # Get top 5 problematic devices
        problematic_devices = Device.query.filter(
            Device.active_alerts > 0
        ).order_by(Device.active_alerts.desc()).limit(5).all()
        
        # Get network performance metrics
        last_hour = datetime.utcnow() - timedelta(hours=1)
        avg_response_time = db.session.query(
            sa.func.avg(MonitoringData.response_time)
        ).filter(
            MonitoringData.timestamp >= last_hour
        ).scalar() or 0
        
        return jsonify({
            'success': True,
            'summary': {
                'total_devices': total_devices,
                'status_distribution': status_summary,
                'alert_summary': alert_summary,
                'network_performance': {
                    'avg_response_time': round(avg_response_time, 2),
                    'period': '1 hour'
                },
                'problematic_devices': [
                    {
                        'id': device.id,
                        'name': device.display_name,
                        'ip': device.ip_address,
                        'alerts': device.active_alerts,
                        'status': device.status
                    }
                    for device in problematic_devices
                ]
            },
            'timestamp': datetime.utcnow().isoformat(),
            'cache_duration': cache_minutes * 60
        })
        
    except Exception as e:
        logger.error(f"Error getting network summary: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve network summary',
            'code': 'SUMMARY_ERROR',
            'message': str(e)
        }), 500

# ============================================================================
# Mobile-Specific Utilities
# ============================================================================

@mobile_api.route('/ping/<int:device_id>', methods=['POST'])
@create_endpoint_limiter('strict')
@mobile_auth_required
def ping_device(device_id):
    """Trigger device ping from mobile client"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Queue ping operation (would integrate with monitoring system)
        # For now, return success response
        
        return jsonify({
            'success': True,
            'message': f'Ping queued for {device.display_name}',
            'device_id': device_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error pinging device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to ping device',
            'code': 'PING_ERROR',
            'message': str(e)
        }), 500

@mobile_api.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@create_endpoint_limiter('strict')
@mobile_auth_required
def acknowledge_alert(alert_id):
    """Acknowledge alert from mobile client"""
    try:
        alert = Alert.query.get_or_404(alert_id)
        
        if alert.acknowledged:
            return jsonify({
                'success': True,
                'message': 'Alert already acknowledged',
                'alert_id': alert_id,
                'acknowledged_at': alert.acknowledged_at.isoformat()
            })
        
        alert.acknowledged = True
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = g.current_user['username']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alert acknowledged successfully',
            'alert_id': alert_id,
            'acknowledged_at': alert.acknowledged_at.isoformat(),
            'acknowledged_by': alert.acknowledged_by
        })
        
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Failed to acknowledge alert',
            'code': 'ACK_ERROR',
            'message': str(e)
        }), 500

@mobile_api.route('/config/mobile', methods=['GET'])
@create_endpoint_limiter('relaxed')
@mobile_auth_required
def get_mobile_config():
    """Get mobile app configuration"""
    try:
        config = {
            'app_version': '1.0.0',
            'api_version': 'v1',
            'features': {
                'push_notifications': True,
                'offline_mode': True,
                'real_time_sync': True,
                'device_control': g.current_user['role'] == 'admin'
            },
            'sync_intervals': {
                'devices': 30,  # seconds
                'alerts': 15,
                'monitoring': 60
            },
            'ui_config': {
                'theme': 'auto',
                'card_layout': 'compact',
                'show_charts': True,
                'refresh_indicator': True
            },
            'limits': {
                'max_devices_per_request': 100,
                'max_monitoring_points': 500,
                'cache_duration': 300
            }
        }
        
        return jsonify({
            'success': True,
            'config': config,
            'user': {
                'username': g.current_user['username'],
                'role': g.current_user['role'],
                'permissions': g.current_user.get('permissions', ['read'])
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting mobile config: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve mobile configuration',
            'code': 'CONFIG_ERROR',
            'message': str(e)
        }), 500

# ============================================================================
# Error Handlers
# ============================================================================

@mobile_api.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Resource not found',
        'code': 'NOT_FOUND',
        'message': 'The requested resource was not found'
    }), 404

@mobile_api.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'code': 'RATE_LIMIT',
        'message': 'Too many requests. Please slow down.'
    }), 429

@mobile_api.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'code': 'INTERNAL_ERROR',
        'message': 'An unexpected error occurred'
    }), 500