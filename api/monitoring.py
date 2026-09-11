import ipaddress
import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import lru_cache

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from api.rate_limited_endpoints import create_endpoint_limiter
from models import Alert, Device, InterfaceBandwidth, MonitoringData, db
from monitoring.monitor import DeviceMonitor
from services.pagination import create_pagination_response, paginator

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

        # Build query with eager loading to avoid N+1 queries
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = MonitoringData.query.options(
            joinedload(MonitoringData.device)
        ).filter(MonitoringData.timestamp >= cutoff)

        if device_id:
            query = query.filter(MonitoringData.device_id == device_id)

        # Order by timestamp (newest first)
        query = query.order_by(MonitoringData.timestamp.desc())

        # Pagination: ?limit= (what the device page sends) is an alias of ?per_page=, capped at 2000
        page, per_page = paginator.get_request_pagination()
        limit = request.args.get('limit', type=int)
        if limit:
            per_page = max(1, min(limit, 2000))

        pagination_result = paginator.paginate_query(
            query,
            page=page,
            per_page=per_page,
            error_out=False,
            max_per_page=2000,
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

        query = Alert.query.filter_by(acknowledged=False, resolved=False)
        prefix = data.get('alert_type_prefix')
        if prefix:
            query = query.filter(Alert.alert_type.like(f"{prefix}%"))
        acknowledged_count = query.update(
            {'acknowledged': True, 'acknowledged_at': datetime.utcnow(), 'acknowledged_by': acknowledged_by},
            synchronize_session=False,
        )
        db.session.commit()

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
@create_endpoint_limiter('strict')
def delete_alert(alert_id):
    """Delete a specific alert"""
    try:
        from sqlalchemy.orm import joinedload
        alert = Alert.query.options(joinedload(Alert.device)).get_or_404(alert_id)

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


# ---------------------------------------------------------------------------
# Bandwidth: host interface throughput (InterfaceBandwidth). Response keys are
# kept compatible with the analytics page; "devices" now means interfaces.
# ---------------------------------------------------------------------------

def _bandwidth_window_args(max_hours=168):
    hours = request.args.get('hours', default=24, type=int)
    hours = max(1, min(hours, max_hours))
    interface = request.args.get('interface', type=str)
    return hours, interface, datetime.utcnow() - timedelta(hours=hours)


def _bandwidth_base_query(cutoff, interface):
    q = InterfaceBandwidth.query.filter(InterfaceBandwidth.timestamp >= cutoff)
    if interface:
        q = q.filter(InterfaceBandwidth.interface == interface)
    return q


@monitoring_bp.route('/bandwidth/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bandwidth_timeline():
    """Interface throughput bucketed for charts (sum across interfaces per bucket)."""
    try:
        hours, interface, cutoff = _bandwidth_window_args()
        interval = request.args.get('interval', default='hour')
        bucket_minutes = {'5min': 5, '15min': 15, '30min': 30}.get(interval, 60)
        rows = _bandwidth_base_query(cutoff, interface).order_by(InterfaceBandwidth.timestamp).all()

        buckets = {}
        for r in rows:
            minute = int(r.timestamp.timestamp() // 60)
            key = (minute // bucket_minutes) * bucket_minutes
            b = buckets.setdefault(key, {'in': [], 'out': [], 'bytes_in': 0, 'bytes_out': 0, 'n': 0})
            b['in'].append(r.mbps_in or 0)
            b['out'].append(r.mbps_out or 0)
            b['bytes_in'] += r.bytes_in or 0
            b['bytes_out'] += r.bytes_out or 0
            b['n'] += 1

        timeline = []
        for key in sorted(buckets):
            b = buckets[key]
            timeline.append({
                'timestamp': datetime.utcfromtimestamp(key * 60).strftime('%Y-%m-%d %H:%M:%S'),
                'avg_bandwidth_in_mbps': sum(b['in']) / len(b['in']),
                'avg_bandwidth_out_mbps': sum(b['out']) / len(b['out']),
                'peak_bandwidth_in_mbps': max(b['in']),
                'peak_bandwidth_out_mbps': max(b['out']),
                'total_bytes_in': b['bytes_in'],
                'total_bytes_out': b['bytes_out'],
                'sample_count': b['n'],
            })
        return jsonify({'timeline': timeline, 'count': len(timeline), 'interval': interval,
                        'hours': hours, 'interface': interface})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@monitoring_bp.route('/bandwidth/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bandwidth_summary():
    """Aggregate host throughput over the window, plus per-interface totals."""
    try:
        hours, interface, cutoff = _bandwidth_window_args()
        q = _bandwidth_base_query(cutoff, interface)
        agg = q.with_entities(
            func.coalesce(func.sum(InterfaceBandwidth.bytes_in), 0),
            func.coalesce(func.sum(InterfaceBandwidth.bytes_out), 0),
            func.avg(InterfaceBandwidth.mbps_in),
            func.avg(InterfaceBandwidth.mbps_out),
            func.max(InterfaceBandwidth.mbps_in + InterfaceBandwidth.mbps_out),
            func.count(func.distinct(InterfaceBandwidth.interface)),
            func.count(InterfaceBandwidth.id),
        ).one()

        per_iface = (q.with_entities(
            InterfaceBandwidth.interface,
            func.sum(InterfaceBandwidth.bytes_in + InterfaceBandwidth.bytes_out),
            func.avg(InterfaceBandwidth.mbps_in + InterfaceBandwidth.mbps_out),
            func.max(InterfaceBandwidth.mbps_in + InterfaceBandwidth.mbps_out),
        ).group_by(InterfaceBandwidth.interface).order_by(func.sum(InterfaceBandwidth.bytes_in + InterfaceBandwidth.bytes_out).desc()).all())

        recent = (_bandwidth_base_query(datetime.utcnow() - timedelta(minutes=10), interface)
                  .with_entities(func.avg(InterfaceBandwidth.mbps_in), func.avg(InterfaceBandwidth.mbps_out)).one())

        gb = 1024 ** 3
        r2 = lambda v: round(v or 0, 2)
        return jsonify({
            'period_hours': hours,
            'source': 'host_interface_counters',
            'total_data': {'total_gb_in': round(agg[0] / gb, 2), 'total_gb_out': round(agg[1] / gb, 2),
                           'total_gb': round((agg[0] + agg[1]) / gb, 2)},
            'average_bandwidth': {'avg_in_mbps': r2(agg[2]), 'avg_out_mbps': r2(agg[3]),
                                  'avg_total_mbps': r2((agg[2] or 0) + (agg[3] or 0))},
            'peak_bandwidth': {'peak_total_mbps': r2(agg[4])},
            'current_bandwidth': {'current_in_mbps': r2(recent[0]), 'current_out_mbps': r2(recent[1]),
                                  'current_total_mbps': r2((recent[0] or 0) + (recent[1] or 0))},
            'statistics': {'active_interfaces': agg[5] or 0, 'total_measurements': agg[6] or 0},
            'top_consumers': [{'interface': name, 'device_name': name, 'ip_address': 'host interface',
                               'total_gb': round((total or 0) / gb, 2), 'avg_mbps': r2(avg), 'peak_mbps': r2(peak)}
                              for name, total, avg, peak in per_iface],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@monitoring_bp.route('/bandwidth/devices', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_bandwidth_rankings():
    """Per-interface ranking (kept at this URL for the analytics page)."""
    try:
        hours, interface, cutoff = _bandwidth_window_args()
        limit = max(1, min(request.args.get('limit', default=20, type=int), 100))
        rows = (_bandwidth_base_query(cutoff, interface).with_entities(
            InterfaceBandwidth.interface,
            func.sum(InterfaceBandwidth.bytes_in), func.sum(InterfaceBandwidth.bytes_out),
            func.avg(InterfaceBandwidth.mbps_in), func.avg(InterfaceBandwidth.mbps_out),
            func.max(InterfaceBandwidth.mbps_in), func.max(InterfaceBandwidth.mbps_out),
            func.count(InterfaceBandwidth.id),
        ).group_by(InterfaceBandwidth.interface)
         .order_by((func.sum(InterfaceBandwidth.bytes_in) + func.sum(InterfaceBandwidth.bytes_out)).desc())
         .limit(limit).all())

        gb = 1024 ** 3
        r2 = lambda v: round(v or 0, 2)
        devices = []
        for name, bin_, bout, ain, aout, pin, pout, n in rows:
            devices.append({
                'interface': name, 'device_name': name, 'ip_address': 'host interface',
                'bandwidth_stats': {
                    'total_gb_in': round((bin_ or 0) / gb, 2), 'total_gb_out': round((bout or 0) / gb, 2),
                    'total_gb': round(((bin_ or 0) + (bout or 0)) / gb, 2),
                    'avg_in_mbps': r2(ain), 'avg_out_mbps': r2(aout), 'avg_total_mbps': r2((ain or 0) + (aout or 0)),
                    'peak_in_mbps': r2(pin), 'peak_out_mbps': r2(pout), 'peak_total_mbps': r2((pin or 0) + (pout or 0)),
                    'measurement_count': n or 0,
                },
            })
        return jsonify({'devices': devices, 'count': len(devices), 'period_hours': hours,
                        'source': 'host_interface_counters', 'timestamp': datetime.utcnow().isoformat() + 'Z'})
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
@create_endpoint_limiter('strict')
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


@monitoring_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitoring_summary():
    """Get comprehensive monitoring summary for high-level dashboard"""
    try:
        from models import Device, Alert, MonitoringData
        from datetime import datetime, timedelta

        from services.device_counts import summarize
        counts = summarize()
        network_range = counts['network_range']
        total_devices = counts['total_devices']
        devices_up = counts['devices_up']
        devices_down = counts['devices_down']
        devices_unknown = counts['devices_unknown']
        active_alerts = counts['active_alerts']

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

        # Network uptime = share of monitored (pinged) devices currently up
        network_uptime = "0.0%"
        if counts['monitored_devices'] > 0:
            network_uptime = f"{(devices_up / counts['monitored_devices']) * 100:.1f}%"

        return jsonify({
            'total_devices': total_devices,
            'monitored_devices': counts['monitored_devices'],
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
