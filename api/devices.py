from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
from models import db, Device, MonitoringData, Alert, DeviceIpHistory
from monitoring.monitor import DeviceMonitor
from api.rate_limited_endpoints import create_endpoint_limiter
from services.query_cache import get_cached_device_list, invalidate_device_cache
from services.pagination import paginator, create_pagination_response
from core.validators import InputValidator, validate_request
import logging
import ping3

# Import ultra-fast cache if available
try:
    from services.ultra_cache import device_cache, cached_query, response_cache
    ULTRA_CACHE_AVAILABLE = True
except ImportError:
    ULTRA_CACHE_AVAILABLE = False
    # Fallback decorator
    def cached_query(ttl=60):
        def decorator(func):
            return func
        return decorator

logger = logging.getLogger(__name__)

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_devices():
    """Get all devices with optional filtering - ULTRA-CACHED VERSION"""

    # Ultra-fast response cache for frequently accessed endpoints
    if ULTRA_CACHE_AVAILABLE:
        cache_key = f"devices:{request.args}"
        cached_result = response_cache.get(cache_key)
        if cached_result:
            return cached_result
    try:
        # Validate and sanitize query parameters
        group = InputValidator.sanitize_string(request.args.get('group', ''), max_length=100)
        device_type = InputValidator.validate_device_type(request.args.get('type', ''))
        status = request.args.get('status', '')
        if status and status not in ['up', 'down', 'warning', 'unknown']:
            status = None
        monitored_only = InputValidator.validate_boolean(request.args.get('monitored', 'false'))
        network_filter = InputValidator.validate_boolean(request.args.get('network_filter', 'false'))  # Changed default to false
        
        # PERFORMANCE OPTIMIZATION: Use cached device list for massive speed improvement
        try:
            devices_data = get_cached_device_list(current_app.app_context)
            logger.info(f"=== API get_devices: Retrieved {len(devices_data)} devices from get_cached_device_list ===")
        except Exception as e:
            logger.warning(f"Cache failed, falling back to database query: {e}")
            # Fallback to original query if cache fails
            return get_devices_fallback(group, device_type, status, monitored_only, network_filter)
        
        # Apply client-side filtering to cached data (much faster than DB queries)
        filtered_devices = devices_data
        
        # Apply network range filtering if requested  
        if network_filter:
            from api.monitoring import is_device_in_network_range, get_current_network_range
            network_range = get_current_network_range()
            filtered_devices = [d for d in filtered_devices if is_device_in_network_range(d['ip_address'], network_range)]
        
        if group:
            filtered_devices = [d for d in filtered_devices if d.get('device_group') == group]
        
        if device_type:
            filtered_devices = [d for d in filtered_devices if d.get('device_type') == device_type]
        
        if monitored_only:
            filtered_devices = [d for d in filtered_devices if d.get('is_monitored')]
        
        if status:
            filtered_devices = [d for d in filtered_devices if d.get('status') == status]

        logger.info(f"=== After filtering: {len(filtered_devices)} devices (network_filter={network_filter}, group={group}, type={device_type}, status={status}, monitored={monitored_only}) ===")

        # Sort by IP address (cached data might not be sorted)
        try:
            import ipaddress
            filtered_devices.sort(key=lambda x: ipaddress.ip_address(x['ip_address']))
        except:
            # Fallback to string sorting if IP parsing fails
            filtered_devices.sort(key=lambda x: x['ip_address'])
        
        # Only apply pagination if explicitly requested
        if 'page' in request.args or 'per_page' in request.args:
            # Apply pagination to cached results
            page, per_page = paginator.get_request_pagination()
            total = len(filtered_devices)
            start = (page - 1) * per_page
            end = start + per_page
            paginated_devices = filtered_devices[start:end]
            
            # Calculate pagination metadata
            import math
            pages = math.ceil(total / per_page)
            
            response = {
                'success': True,
                'devices': paginated_devices,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': pages,
                    'has_prev': page > 1,
                    'has_next': page < pages
                },
                'cached': True  # Indicate this response was cached
            }
        else:
            # No pagination - return all devices (for main dashboard compatibility)
            response = {
                'success': True,
                'devices': filtered_devices,
                'total': len(filtered_devices),
                'cached': True  # Indicate this response was cached
            }

        # Cache the response for fast subsequent requests
        if ULTRA_CACHE_AVAILABLE:
            response_cache.set(cache_key, response)

        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in cached get_devices: {e}")
        # Fallback to non-cached version
        return get_devices_fallback(
            request.args.get('group'),
            request.args.get('type'),
            request.args.get('status'),
            request.args.get('monitored', 'false').lower() == 'true',
            request.args.get('network_filter', 'false').lower() == 'true'  # Changed default to false to match primary path
        )

def get_devices_fallback(group=None, device_type=None, status=None, monitored_only=False, network_filter=False):
    """Fallback method for device retrieval when cache fails - WITH PAGINATION"""
    try:
        # Build query
        query = Device.query
        
        # Apply network range filtering if requested
        if network_filter:
            from api.monitoring import filter_devices_by_network_range
            query = filter_devices_by_network_range(query)
        
        if group:
            query = query.filter(Device.device_group == group)
        
        if device_type:
            query = query.filter(Device.device_type == device_type)
        
        if monitored_only:
            query = query.filter(Device.is_monitored == True)
        
        # Order query for consistent results
        query = query.order_by(Device.ip_address)
        
        # Only apply pagination if explicitly requested
        use_pagination = 'page' in request.args or 'per_page' in request.args
        
        if use_pagination:
            # Get pagination parameters
            page, per_page = paginator.get_request_pagination()
            
            # Use database pagination for optimal performance
            pagination_result = paginator.paginate_query(
                query, 
                page=page, 
                per_page=per_page,
                error_out=False
            )
            
            devices = pagination_result['items']
        else:
            # No pagination - get all devices
            devices = query.all()
            pagination_result = None
        
        # Filter by status if requested (client-side filtering since status is computed)
        if status:
            devices = [d for d in devices if d.status == status]
        
        # Use optimized queries with new indexes
        device_ids = [d.id for d in devices]
        
        if not device_ids:
            if use_pagination and pagination_result:
                return jsonify({
                    'success': True,
                    'devices': [],
                    'pagination': {
                        'page': pagination_result['page'],
                        'per_page': pagination_result['per_page'],
                        'total': pagination_result['total'],
                        'pages': pagination_result['pages'],
                        'has_prev': pagination_result['has_prev'],
                        'has_next': pagination_result['has_next']
                    },
                    'cached': False
                })
            else:
                return jsonify({
                    'success': True,
                    'devices': [],
                    'total': 0,
                    'cached': False
                })
        
        # OPTIMIZATION: Use indexed query for latest monitoring data (much faster)
        from sqlalchemy import func, and_
        latest_monitoring_subquery = db.session.query(
            MonitoringData.device_id,
            func.max(MonitoringData.timestamp).label('max_timestamp')
        ).filter(MonitoringData.device_id.in_(device_ids)).group_by(MonitoringData.device_id).subquery()
        
        latest_monitoring = db.session.query(MonitoringData).join(
            latest_monitoring_subquery,
            and_(
                MonitoringData.device_id == latest_monitoring_subquery.c.device_id,
                MonitoringData.timestamp == latest_monitoring_subquery.c.max_timestamp
            )
        ).all()
        
        # Create lookup dict for O(1) access
        monitoring_lookup = {md.device_id: md for md in latest_monitoring}
        
        # Get active alerts count for all devices in one query
        alert_counts = db.session.query(
            Alert.device_id,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.device_id.in_(device_ids),
            Alert.resolved == False
        ).group_by(Alert.device_id).all()
        
        # Create lookup dict for O(1) access
        alerts_lookup = {ac.device_id: ac.count for ac in alert_counts}
        
        # Convert to dict format
        devices_data = []
        for device in devices:
            device_dict = device.to_dict()
            
            # Add latest monitoring data from lookup
            latest_data = monitoring_lookup.get(device.id)
            device_dict['latest_response_time'] = latest_data.response_time if latest_data else None
            device_dict['latest_check'] = latest_data.timestamp.isoformat() if latest_data else None
            
            # Add active alerts count from lookup
            device_dict['active_alerts'] = alerts_lookup.get(device.id, 0)
            
            devices_data.append(device_dict)
        
        # Return response with optional pagination
        if use_pagination and pagination_result:
            return jsonify({
                'success': True,
                'devices': devices_data,
                'pagination': {
                    'page': pagination_result['page'],
                    'per_page': pagination_result['per_page'],
                    'total': pagination_result['total'],
                    'pages': pagination_result['pages'],
                    'has_prev': pagination_result['has_prev'],
                    'has_next': pagination_result['has_next']
                },
                'cached': False
            })
        else:
            return jsonify({
                'success': True,
                'devices': devices_data,
                'total': len(devices_data),
                'cached': False
            })
        
    except Exception as e:
        logger.error(f"Error in fallback get_devices: {e}")
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device(device_id):
    """Get specific device details"""
    try:
        device = Device.query.get_or_404(device_id)
        
        device_dict = device.to_dict()
        
        # Add recent monitoring data (last 24 hours)
        cutoff = datetime.utcnow() - timedelta(hours=24)
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        ).order_by(MonitoringData.timestamp.desc()).limit(100).all()
        
        device_dict['monitoring_history'] = [data.to_dict() for data in monitoring_data]
        
        # Add recent alerts
        recent_alerts = Alert.query.filter_by(device_id=device_id)\
                                  .order_by(Alert.created_at.desc())\
                                  .limit(10).all()
        
        device_dict['alerts'] = [alert.to_dict() for alert in recent_alerts]
        
        # PERFORMANCE OPTIMIZATION: Calculate statistics efficiently using direct SQL
        from datetime import datetime, timedelta
        from sqlalchemy import func
        
        # Calculate 24h and 7d statistics in batch queries
        now = datetime.utcnow()
        cutoff_24h = now - timedelta(hours=24)
        cutoff_7d = now - timedelta(days=7)
        
        # Get 24h statistics
        stats_24h_raw = db.session.query(
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(func.case((MonitoringData.response_time.isnot(None), 1), else_=0)).label('successful_checks'),
            func.avg(MonitoringData.response_time).label('avg_response_time'),
            func.min(MonitoringData.response_time).label('min_response_time'),
            func.max(MonitoringData.response_time).label('max_response_time'),
            func.avg(MonitoringData.packet_loss).label('avg_packet_loss')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff_24h
        ).first()
        
        # Get 7d statistics
        stats_7d_raw = db.session.query(
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(func.case((MonitoringData.response_time.isnot(None), 1), else_=0)).label('successful_checks'),
            func.avg(MonitoringData.response_time).label('avg_response_time'),
            func.min(MonitoringData.response_time).label('min_response_time'),
            func.max(MonitoringData.response_time).label('max_response_time'),
            func.avg(MonitoringData.packet_loss).label('avg_packet_loss')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff_7d
        ).first()
        
        # Format statistics
        def format_stats(raw_stats):
            if not raw_stats or raw_stats.total_checks == 0:
                return {
                    'total_checks': 0,
                    'successful_checks': 0,
                    'uptime_percentage': 0.0,
                    'avg_response_time': None,
                    'min_response_time': None,
                    'max_response_time': None,
                    'avg_packet_loss': 0.0
                }
            
            successful = raw_stats.successful_checks or 0
            total = raw_stats.total_checks or 0
            uptime_percentage = (successful / total * 100) if total > 0 else 0.0
            
            return {
                'total_checks': total,
                'successful_checks': successful,
                'uptime_percentage': round(uptime_percentage, 2),
                'avg_response_time': round(float(raw_stats.avg_response_time), 2) if raw_stats.avg_response_time else None,
                'min_response_time': round(float(raw_stats.min_response_time), 2) if raw_stats.min_response_time else None,
                'max_response_time': round(float(raw_stats.max_response_time), 2) if raw_stats.max_response_time else None,
                'avg_packet_loss': round(float(raw_stats.avg_packet_loss), 2) if raw_stats.avg_packet_loss else 0.0
            }
        
        device_dict['statistics'] = {
            '24h': format_stats(stats_24h_raw),
            '7d': format_stats(stats_7d_raw)
        }
        
        return jsonify({
            'success': True,
            'device': device_dict
        })
        
    except Exception as e:
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

@devices_bp.route('', methods=['POST'])
@create_endpoint_limiter('strict')
def create_device():
    """Create a new device"""
    try:
        try:
            data = request.get_json()
        except Exception:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        if not data or 'ip_address' not in data:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(data['ip_address'])
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Check if device already exists
        existing = Device.query.filter_by(ip_address=data['ip_address']).first()
        if existing:
            return jsonify({'error': 'Device with this IP already exists'}), 400
        
        # Create new device
        device = Device(
            ip_address=data['ip_address'],
            mac_address=data.get('mac_address'),
            hostname=data.get('hostname'),
            custom_name=data.get('custom_name'),
            device_type=data.get('device_type', 'unknown'),
            device_group=data.get('device_group'),
            is_monitored=data.get('is_monitored', True)
        )
        
        db.session.add(device)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'device': device.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['PUT', 'PATCH'])
@create_endpoint_limiter('strict')  
@validate_request(allowed_fields=['ip_address', 'custom_name', 'device_type', 'device_group', 'room_location', 'device_priority', 'is_monitored', 'hostname'])
def update_device(device_id):
    """Update device details with validation"""
    try:
        # Validate device_id
        device_id = InputValidator.validate_integer(device_id, min_val=1)
        device = Device.query.get_or_404(device_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Handle IP address change validation
        if 'ip_address' in data:
            try:
                new_ip = InputValidator.validate_ip_address(data['ip_address'])
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
            
            # Check if IP already exists on another device
            existing_device = Device.query.filter(
                Device.ip_address == new_ip,
                Device.id != device_id
            ).first()
            if existing_device:
                return jsonify({'error': 'IP address already in use by another device'}), 400
            
            device.ip_address = new_ip
        
        # Update and validate allowed fields
        allowed_fields = ['custom_name', 'device_type', 'device_group', 'room_location', 'device_priority', 'is_monitored', 'hostname']
        updated_fields = {}
        
        for field in allowed_fields:
            if field in data:
                old_value = getattr(device, field, None)
                
                # Validate each field
                if field == 'custom_name':
                    value = InputValidator.sanitize_string(data[field], max_length=255)
                elif field == 'device_type':
                    value = InputValidator.validate_device_type(data[field])
                elif field == 'device_group':
                    value = InputValidator.sanitize_string(data[field], max_length=100)
                elif field == 'room_location':
                    value = InputValidator.sanitize_string(data[field], max_length=100) if data[field] else None
                elif field == 'device_priority':
                    # Validate device priority is one of the allowed values
                    valid_priorities = ['critical', 'important', 'normal', 'optional']
                    if data[field] not in valid_priorities:
                        return jsonify({'error': f'device_priority must be one of: {", ".join(valid_priorities)}'}), 400
                    value = data[field]
                elif field == 'is_monitored':
                    value = InputValidator.validate_boolean(data[field])
                elif field == 'hostname':
                    value = InputValidator.validate_hostname(data[field]) if data[field] else None
                else:
                    value = data[field]
                    
                setattr(device, field, value)
                updated_fields[field] = {'old': old_value, 'new': value}
        
        device.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'device': device.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['DELETE'])
@create_endpoint_limiter('strict')
def delete_device(device_id):
    """Delete a device"""
    try:
        device = Device.query.get_or_404(device_id)
        
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Device deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>/ip-history', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_ip_history(device_id):
    """Get IP address change history for a device"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Get IP address change history from database
        history_records = DeviceIpHistory.query.filter_by(device_id=device_id)\
                                              .order_by(DeviceIpHistory.change_detected_at.desc())\
                                              .limit(50).all()  # Limit to last 50 changes
        
        history_list = [record.to_dict() for record in history_records]
        
        return jsonify({
            'success': True,
            'device_id': device_id,
            'device_name': device.display_name,
            'current_ip': device.ip_address,
            'mac_address': device.mac_address,
            'ip_history': history_list,
            'total_changes': len(history_list)
        })
        
    except Exception as e:
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

# Removed duplicate ping_device function - using ping_single_device instead

def track_ip_change(device_id, old_ip, new_ip, source='auto_discovery', notes=None):
    """Utility function to track IP address changes"""
    try:
        # DeviceIpHistory already imported at module level
        
        # Don't create duplicate records for the same change
        existing = DeviceIpHistory.query.filter_by(
            device_id=device_id,
            new_ip_address=new_ip
        ).order_by(DeviceIpHistory.change_detected_at.desc()).first()
        
        # If the most recent record already has this IP, don't duplicate
        if existing and existing.new_ip_address == new_ip:
            return existing
            
        # Create new history record
        history_record = DeviceIpHistory(
            device_id=device_id,
            old_ip_address=old_ip,
            new_ip_address=new_ip,
            change_source=source,
            notes=notes
        )
        
        db.session.add(history_record)
        db.session.commit()
        
        logger.info(f"Tracked IP change for device {device_id}: {old_ip} -> {new_ip} (source: {source})")
        return history_record
        
    except Exception as e:
        logger.error(f"Failed to track IP change: {e}")
        return None

@devices_bp.route('/<int:device_id>/ip-history', methods=['POST'])
@create_endpoint_limiter('strict')
def log_ip_change(device_id):
    """Manually log an IP address change"""
    try:
        device = Device.query.get_or_404(device_id)
        data = request.get_json()
        
        old_ip = data.get('old_ip_address')
        new_ip = data.get('new_ip_address') 
        notes = data.get('notes', '')
        
        if not new_ip:
            return jsonify({'error': 'new_ip_address is required'}), 400
            
        # Track the change
        history_record = track_ip_change(
            device_id=device_id,
            old_ip=old_ip,
            new_ip=new_ip,
            source='manual_log',
            notes=notes
        )
        
        if history_record:
            return jsonify({
                'success': True,
                'message': 'IP change logged successfully',
                'history_record': history_record.to_dict()
            })
        else:
            return jsonify({'error': 'Failed to log IP change'}), 500
            
    except Exception as e:
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/ping-all', methods=['POST'])
@create_endpoint_limiter('intensive')
def ping_all_devices():
    """Ping all monitored devices"""
    import subprocess
    import re
    import ipaddress
    
    # Get all monitored devices
    devices = Device.query.filter_by(is_monitored=True).all()
    
    if not devices:
        return jsonify({'error': 'No monitored devices found'}), 404
    
    results = []
    
    # Ping each device
    for device in devices:
        # SECURITY: Validate IP address to prevent command injection
        try:
            ipaddress.ip_address(device.ip_address)
        except ValueError:
            logger.warning(f"Invalid IP address format for device {device.id}: {device.ip_address}")
            results.append({
                'device_id': device.id,
                'ip_address': device.ip_address,
                'display_name': device.display_name,
                'response_time': None,
                'success': False,
                'error': 'Invalid IP address format'
            })
            continue
        
        cmd = ['ping', '-c', '1', '-W', '3', device.ip_address]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
            success = result.returncode == 0
            response_time = None
            
            if success:
                time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
                response_time = float(time_match.group(1)) if time_match else 0.0
                device.last_seen = datetime.utcnow()
            
            results.append({
                'device_id': device.id,
                'ip_address': device.ip_address,
                'display_name': device.display_name,
                'response_time': response_time,
                'success': success
            })
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping timeout for device {device.id}: {device.ip_address}")
            results.append({
                'device_id': device.id,
                'ip_address': device.ip_address,
                'display_name': device.display_name,
                'response_time': None,
                'success': False,
                'error': 'Ping timeout'
            })
        except Exception as e:
            logger.error(f"Ping error for device {device.id}: {e}")
            results.append({
                'device_id': device.id,
                'ip_address': device.ip_address,
                'display_name': device.display_name,
                'response_time': None,
                'success': False,
                'error': str(e)
            })
    
    # Commit all database updates
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Calculate summary
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    
    return jsonify({
        'success': True,
        'devices_pinged': total,
        'results': results,
        'summary': {
            'total_devices': total,
            'successful': successful,
            'failed': total - successful,
            'success_rate': round((successful / total) * 100, 1) if total > 0 else 0
        },
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })

@devices_bp.route('/groups', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_groups():
    """Get all device groups"""
    try:
        groups = db.session.query(Device.device_group)\
                          .filter(Device.device_group.isnot(None))\
                          .distinct()\
                          .all()
        
        group_list = [group[0] for group in groups if group[0]]
        
        return jsonify({
            'success': True,
            'groups': sorted(group_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/types', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_types():
    """Get all device types"""
    try:
        types = db.session.query(Device.device_type)\
                         .filter(Device.device_type.isnot(None))\
                         .distinct()\
                         .all()
        
        type_list = [type_item[0] for type_item in types if type_item[0]]
        
        return jsonify({
            'success': True,
            'types': sorted(type_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/test-ping/<string:ip>', methods=['GET'])
@create_endpoint_limiter('critical')
def test_ping(ip):
    """Test ping functionality with direct IP"""
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        # Use ping3 for consistent behavior
        response_time = ping3.ping(ip, timeout=3)
        
        if response_time is not None:
            return jsonify({
                'success': True,
                'ip': ip,
                'response_time': response_time * 1000,  # Convert to ms
                'reachable': True
            })
        else:
            return jsonify({
                'success': True,
                'ip': ip,
                'response_time': None,
                'reachable': False
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>/ping-test', methods=['POST'])
@create_endpoint_limiter('critical')
def ping_device_test(device_id):
    """Simple ping test endpoint"""
    try:
        from flask import current_app
        import subprocess
        import re
        import ipaddress
        
        device = Device.query.get_or_404(device_id)
        ip = device.ip_address
        
        # SECURITY: Validate IP address to prevent command injection
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Simple ping test
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '3', ip], 
            capture_output=True, 
            text=True, 
            timeout=5,
            shell=False
        )
        
        if result.returncode == 0:
            # Parse ping output to extract response time
            time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
            response_time = float(time_match.group(1)) if time_match else 0.0
            
            return jsonify({
                'device_id': device_id,
                'ip_address': ip,
                'success': True,
                'response_time': response_time,
                'output': result.stdout
            })
        else:
            return jsonify({
                'device_id': device_id,
                'ip_address': ip,
                'success': False,
                'response_time': None,
                'error': result.stderr
            })
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'device_id': device_id,
            'ip_address': ip,
            'success': False,
            'response_time': None,
            'error': 'Ping timeout'
        }), 408
    except Exception as e:
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_devices_summary():
    """Get summary statistics of all devices"""
    try:
        # PERFORMANCE OPTIMIZATION: Use direct SQL aggregation instead of loading all devices
        from sqlalchemy import func, case, and_, or_
        from datetime import datetime, timedelta
        
        # Calculate status efficiently using the same logic as the status property
        # A device is 'up' if it has successful monitoring data within the ping interval plus buffer
        # The ping interval is 600 seconds (10 minutes), so we use 15 minutes (900 seconds) to account for network delays
        # 'down' if it has data but none successful in the monitoring window
        # 'unknown' if no monitoring data exists
        cutoff_time = datetime.utcnow() - timedelta(seconds=900)  # 15 minutes
        
        # Get latest monitoring data timestamp for each device
        latest_monitoring_subquery = db.session.query(
            MonitoringData.device_id,
            func.max(MonitoringData.timestamp).label('latest_timestamp'),
            func.count(MonitoringData.id).label('total_monitoring_records')
        ).group_by(MonitoringData.device_id).subquery()
        
        # Get latest monitoring data with response times
        latest_data_subquery = db.session.query(
            MonitoringData.device_id,
            MonitoringData.response_time,
            MonitoringData.timestamp
        ).join(
            latest_monitoring_subquery,
            and_(
                MonitoringData.device_id == latest_monitoring_subquery.c.device_id,
                MonitoringData.timestamp == latest_monitoring_subquery.c.latest_timestamp
            )
        ).subquery()
        
        # Count devices by calculated status with fallback to device.status field
        # First check monitoring data, then fall back to device.status if no recent data
        status_query = db.session.query(
            func.count(Device.id).label('total_devices'),
            func.count(case((Device.is_monitored == True, 1))).label('monitored_devices'),
            func.sum(case((
                or_(
                    # Has recent successful monitoring data
                    and_(
                        latest_data_subquery.c.timestamp >= cutoff_time,
                        latest_data_subquery.c.response_time.isnot(None)
                    ),
                    # OR no monitoring data but device.status is 'up'
                    and_(
                        latest_monitoring_subquery.c.total_monitoring_records == None,
                        Device.status == 'up'
                    )
                ), 1
            ), else_=0)).label('devices_up'),
            func.sum(case((
                or_(
                    # Has monitoring data but it's old or failed
                    and_(
                        latest_monitoring_subquery.c.total_monitoring_records > 0,
                        or_(
                            latest_data_subquery.c.timestamp < cutoff_time,
                            latest_data_subquery.c.response_time.is_(None)
                        )
                    ),
                    # OR no monitoring data but device.status is 'down'
                    and_(
                        latest_monitoring_subquery.c.total_monitoring_records == None,
                        Device.status == 'down'
                    )
                ), 1
            ), else_=0)).label('devices_down'),
            func.sum(case((
                and_(
                    latest_monitoring_subquery.c.total_monitoring_records == None,
                    or_(Device.status == 'unknown', Device.status == None)
                ), 1
            ), else_=0)).label('devices_unknown')
        ).outerjoin(
            latest_monitoring_subquery,
            Device.id == latest_monitoring_subquery.c.device_id
        ).outerjoin(
            latest_data_subquery,
            Device.id == latest_data_subquery.c.device_id
        ).first()
        
        # Get device type counts efficiently
        type_counts_query = db.session.query(
            func.coalesce(Device.device_type, 'unknown').label('device_type'),
            func.count(Device.id).label('count')
        ).group_by(Device.device_type).all()
        
        type_counts = {row.device_type: row.count for row in type_counts_query}
        
        # Get active alerts count
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Extract values with defaults
        total_devices = status_query.total_devices or 0
        devices_up = status_query.devices_up or 0
        devices_down = status_query.devices_down or 0
        devices_unknown = status_query.devices_unknown or 0
        monitored_devices = status_query.monitored_devices or 0
        
        # Calculate uptime percentage
        uptime_percentage = round((devices_up / total_devices) * 100, 1) if total_devices > 0 else 0
        
        return jsonify({
            'success': True,
            'summary': {
                'total_devices': total_devices,
                'monitored_devices': monitored_devices,
                'devices_up': devices_up,
                'devices_down': devices_down,
                'devices_unknown': devices_unknown,
                'uptime_percentage': uptime_percentage,
                'active_alerts': active_alerts,
                'device_types': type_counts
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting device summary: {e}")
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/monitored', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_monitored_devices():
    """Get only devices that are being monitored"""
    try:
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True)\
                             .order_by(Device.ip_address)\
                             .all()
        
        # PERFORMANCE OPTIMIZATION: Batch load monitoring data and alerts to avoid N+1 queries
        device_ids = [d.id for d in devices]
        
        # Get latest monitoring data for all devices in one query
        from sqlalchemy import func, and_
        subquery = db.session.query(
            MonitoringData.device_id,
            func.max(MonitoringData.timestamp).label('max_timestamp')
        ).filter(MonitoringData.device_id.in_(device_ids)).group_by(MonitoringData.device_id).subquery()
        
        latest_monitoring = db.session.query(MonitoringData).join(
            subquery,
            and_(
                MonitoringData.device_id == subquery.c.device_id,
                MonitoringData.timestamp == subquery.c.max_timestamp
            )
        ).all()
        
        # Create lookup dict for O(1) access
        monitoring_lookup = {md.device_id: md for md in latest_monitoring}
        
        # Get active alerts count for all devices in one query
        alert_counts = db.session.query(
            Alert.device_id,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.device_id.in_(device_ids),
            Alert.resolved == False
        ).group_by(Alert.device_id).all()
        
        # Create lookup dict for O(1) access
        alerts_lookup = {ac.device_id: ac.count for ac in alert_counts}
        
        # Convert to dict format with additional monitoring data
        devices_data = []
        for device in devices:
            device_dict = device.to_dict()
            
            # Add latest monitoring data from lookup
            latest_data = monitoring_lookup.get(device.id)
            device_dict['latest_response_time'] = latest_data.response_time if latest_data else None
            device_dict['latest_check'] = latest_data.timestamp.isoformat() if latest_data else None
            
            # Add active alerts count from lookup
            device_dict['active_alerts'] = alerts_lookup.get(device.id, 0)
            
            devices_data.append(device_dict)
        
        return jsonify({
            'success': True,
            'devices': devices_data,
            'count': len(devices_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting monitored devices: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@devices_bp.route('/bulk-update', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_update_devices():
    """Bulk update device properties"""
    try:
        # INPUT VALIDATION: Parse JSON and validate basic structure
        try:
            data = request.get_json()
        except Exception:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # INPUT VALIDATION: Validate device_ids
        device_ids = data.get('device_ids', [])
        if not device_ids or not isinstance(device_ids, list):
            return jsonify({
                'success': False,
                'error': 'device_ids must be a non-empty list'
            }), 400
        
        # INPUT VALIDATION: Ensure device_ids are integers
        try:
            device_ids = [int(did) for did in device_ids if did is not None]
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': 'All device_ids must be valid integers'
            }), 400
        
        if len(device_ids) > 1000:  # Prevent DOS attacks with massive bulk operations
            return jsonify({
                'success': False,
                'error': 'Cannot update more than 1000 devices at once'
            }), 400
        
        updates = {}
        
        # Extract update fields - check both direct fields and nested 'updates' object
        update_source = data.get('updates', data)  # Use 'updates' if present, otherwise use data directly
        
        # INPUT VALIDATION: Validate update fields
        if 'is_monitored' in update_source:
            if not isinstance(update_source['is_monitored'], bool):
                return jsonify({
                    'success': False,
                    'error': 'is_monitored must be a boolean value'
                }), 400
            updates['is_monitored'] = update_source['is_monitored']
        
        if 'device_group' in update_source:
            device_group = update_source['device_group']
            if device_group is not None and not isinstance(device_group, str):
                return jsonify({
                    'success': False,
                    'error': 'device_group must be a string or null'
                }), 400
            if device_group is not None and len(device_group) > 100:
                return jsonify({
                    'success': False,
                    'error': 'device_group must be less than 100 characters'
                }), 400
            updates['device_group'] = device_group
        
        if 'device_type' in update_source:
            device_type = update_source['device_type']
            if device_type is not None and not isinstance(device_type, str):
                return jsonify({
                    'success': False,
                    'error': 'device_type must be a string or null'
                }), 400
            if device_type is not None and len(device_type) > 50:
                return jsonify({
                    'success': False,
                    'error': 'device_type must be less than 50 characters'
                }), 400
            updates['device_type'] = device_type
        
        if not updates:
            return jsonify({
                'success': False,
                'error': 'No valid update fields specified'
            }), 400
        
        # Check which devices exist
        existing_devices = Device.query.filter(Device.id.in_(device_ids)).all()
        existing_device_ids = [d.id for d in existing_devices]
        invalid_device_ids = [did for did in device_ids if did not in existing_device_ids]
        
        # Perform bulk update on existing devices
        updated_count = Device.query.filter(Device.id.in_(existing_device_ids))\
                                  .update(updates, synchronize_session='fetch')
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'updated_count': updated_count,
            'message': f'Updated {updated_count} devices'
        }
        
        # Include errors for invalid device IDs
        if invalid_device_ids:
            response_data['errors'] = [f'Device ID {did} not found' for did in invalid_device_ids]
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in bulk update: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@devices_bp.route('/bulk-ping', methods=['POST'])
@create_endpoint_limiter('intensive')
def bulk_ping_devices():
    """Trigger ping for multiple devices"""
    try:
        # INPUT VALIDATION: Parse JSON and validate basic structure
        try:
            data = request.get_json()
        except Exception:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # INPUT VALIDATION: Validate device_ids
        device_ids = data.get('device_ids', [])
        if not device_ids or not isinstance(device_ids, list):
            return jsonify({
                'success': False,
                'error': 'device_ids must be a non-empty list'
            }), 400
        
        # INPUT VALIDATION: Ensure device_ids are integers and limit size
        try:
            device_ids = [int(did) for did in device_ids if did is not None]
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': 'All device_ids must be valid integers'
            }), 400
        
        if len(device_ids) > 100:  # Prevent DOS attacks with massive ping operations
            return jsonify({
                'success': False,
                'error': 'Cannot ping more than 100 devices at once'
            }), 400
        
        # Get devices
        devices = Device.query.filter(Device.id.in_(device_ids)).all()
        
        if not devices:
            return jsonify({
                'success': False,
                'error': 'No valid devices found'
            }), 404
        
        # Trigger ping via device monitor
        from flask import current_app
        if hasattr(current_app, '_monitor'):
            monitor = current_app._monitor
            for device in devices:
                # Queue immediate ping for each device
                monitor.queue_immediate_ping(device.id)
        
        return jsonify({
            'success': True,
            'message': f'Ping initiated for {len(devices)} devices',
            'pinged_count': len(devices)
        })
        
    except Exception as e:
        logger.error(f"Error in bulk ping: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@devices_bp.route('/<int:device_id>/ping', methods=['POST'])
@create_endpoint_limiter('strict')
def ping_single_device(device_id):
    """Trigger ping for a single device"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Trigger ping via device monitor  
        from flask import current_app
        if hasattr(current_app, '_monitor'):
            monitor = current_app._monitor
            # Check if the monitor has the queue_immediate_ping method
            if hasattr(monitor, 'queue_immediate_ping'):
                monitor.queue_immediate_ping(device.id)
            else:
                # Fallback: use force_monitor_device method if available
                if hasattr(monitor, 'force_monitor_device'):
                    monitor.force_monitor_device(device.id)
                elif hasattr(monitor, 'ping_device'):
                    # For tests that mock ping_device expecting device.id
                    monitor.ping_device(device.id)
        else:
            # If no monitor is available in testing, create a mock one for compatibility
            monitor = DeviceMonitor(app=current_app)
            if hasattr(monitor, 'ping_device'):
                monitor.ping_device(device.id)
        
        return jsonify({
            'success': True,
            'message': f'Ping initiated for {device.display_name}',
            'device_id': device_id
        })
        
    except Exception as e:
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        logger.error(f"Error pinging device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@devices_bp.route('/<int:device_id>/monitoring', methods=['POST'])
@create_endpoint_limiter('strict')
def update_device_monitoring_status(device_id):
    """Update device monitoring status"""
    try:
        device = Device.query.get_or_404(device_id)
        data = request.get_json()
        
        if not data or 'is_monitored' not in data:
            return jsonify({'error': 'is_monitored field is required'}), 400
        
        is_monitored = data['is_monitored']
        if not isinstance(is_monitored, bool):
            return jsonify({'error': 'is_monitored must be a boolean'}), 400
        
        # Update the device monitoring status
        device.is_monitored = is_monitored
        db.session.commit()
        
        # Invalidate cache to reflect changes
        invalidate_device_cache()
        
        logger.info(f"Updated monitoring status for device {device_id} ({device.display_name}): {is_monitored}")
        
        return jsonify({
            'success': True,
            'message': f'Monitoring {"enabled" if is_monitored else "disabled"} for {device.display_name}',
            'device_id': device_id,
            'is_monitored': is_monitored
        })
        
    except Exception as e:
        db.session.rollback()
        if '404 Not Found' in str(e):
            return jsonify({'error': 'Device not found'}), 404
        logger.error(f"Error updating monitoring status for device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@devices_bp.route('/scan', methods=['POST'])
@devices_bp.route('/scan-now', methods=['POST'])  # Add alternative URL to bypass cache
def scan_network():
    """Trigger a manual network scan with progress updates"""
    logger.info(f"Network scan triggered via {request.method} {request.path}")
    try:
        # Get scanner instance from app
        scanner = current_app._scanner if hasattr(current_app, '_scanner') else None

        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Network scanner not available'
            }), 503

        # Check if a scan is already in progress
        if hasattr(scanner, 'scan_in_progress') and scanner.scan_in_progress:
            return jsonify({
                'success': False,
                'message': 'Scan already in progress',
                'scan_in_progress': True
            }), 409

        # Also check the scanner's is_scanning flag
        if hasattr(scanner, 'is_scanning') and scanner.is_scanning:
            return jsonify({
                'success': False,
                'message': 'Network scan already in progress',
                'scan_in_progress': True
            }), 409

        # Start the scan in a background thread
        import threading

        # Capture the app instance before starting the thread
        app = current_app._get_current_object()

        def run_scan_with_progress():
            scan_timeout = None
            try:
                # Use the application context in the thread
                with app.app_context():
                    # Set scan in progress flags
                    scanner.scan_in_progress = True

                    # Add scan timeout protection (5 minutes max)
                    import threading
                    def scan_timeout_handler():
                        logger.error("Scan timeout - forcing cleanup after 5 minutes")
                        scanner.scan_in_progress = False
                        scanner.is_scanning = False
                        if hasattr(app, 'socketio'):
                            app.socketio.emit('scan_error', {
                                'timestamp': datetime.now().isoformat(),
                                'error': 'Scan timed out after 5 minutes'
                            }, namespace='/', broadcast=True)

                    scan_timeout = threading.Timer(300.0, scan_timeout_handler)  # 5 minutes
                    scan_timeout.start()

                    # Emit WebSocket event for scan start
                    if hasattr(app, 'socketio'):
                        app.socketio.emit('scan_started', {
                            'timestamp': datetime.now().isoformat(),
                            'message': 'Network scan initiated'
                        }, namespace='/', broadcast=True)

                    # Run the actual scan
                    result = scanner.scan_network()

                    # Cancel timeout since scan completed successfully
                    if scan_timeout:
                        scan_timeout.cancel()

                    # Emit WebSocket event for scan complete
                    if hasattr(app, 'socketio'):
                        app.socketio.emit('scan_completed', {
                            'timestamp': datetime.now().isoformat(),
                            'devices_found': result if isinstance(result, int) else 0,
                            'message': 'Network scan completed successfully'
                        }, namespace='/', broadcast=True)

            except Exception as e:
                logger.error(f"Error during manual scan: {e}")
                if scan_timeout:
                    scan_timeout.cancel()
                if hasattr(app, 'socketio'):
                    app.socketio.emit('scan_error', {
                        'timestamp': datetime.now().isoformat(),
                        'error': str(e)
                    }, namespace='/', broadcast=True)
            finally:
                # Always clear scan in progress flags
                scanner.scan_in_progress = False
                if hasattr(scanner, 'is_scanning'):
                    scanner.is_scanning = False

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=run_scan_with_progress,
            name='ManualNetworkScan'
        )
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({
            'success': True,
            'message': 'Network scan started',
            'estimated_duration': 120,  # Estimated 2 minutes
            'scan_id': datetime.now().timestamp()
        }), 200

    except Exception as e:
        logger.error(f"Error initiating network scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@devices_bp.route('/scan-status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_scan_status():
    """Get current scan status"""
    try:
        # Get scanner instance from app
        scanner = current_app._scanner if hasattr(current_app, '_scanner') else None

        if not scanner:
            return jsonify({
                'scan_in_progress': False,
                'message': 'Scanner not available'
            }), 200

        # Check if scan is in progress
        scan_in_progress = False
        if hasattr(scanner, 'scan_in_progress') and scanner.scan_in_progress:
            scan_in_progress = True
        elif hasattr(scanner, 'is_scanning') and scanner.is_scanning:
            scan_in_progress = True

        return jsonify({
            'scan_in_progress': scan_in_progress,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error checking scan status: {e}")
        return jsonify({
            'scan_in_progress': False,
            'error': str(e)
        }), 500