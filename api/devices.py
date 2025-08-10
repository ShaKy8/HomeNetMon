from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, Device, MonitoringData, Alert
from monitoring.monitor import DeviceMonitor

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('', methods=['GET'])
def get_devices():
    """Get all devices with optional filtering"""
    try:
        # Query parameters
        group = request.args.get('group')
        device_type = request.args.get('type')
        status = request.args.get('status')
        monitored_only = request.args.get('monitored', 'false').lower() == 'true'
        
        # Build query
        query = Device.query
        
        if group:
            query = query.filter(Device.device_group == group)
        
        if device_type:
            query = query.filter(Device.device_type == device_type)
        
        if monitored_only:
            query = query.filter(Device.is_monitored == True)
        
        devices = query.order_by(Device.ip_address).all()
        
        # Filter by status if requested (client-side filtering since status is computed)
        if status:
            devices = [d for d in devices if d.status == status]
        
        # Convert to dict format
        devices_data = []
        for device in devices:
            device_dict = device.to_dict()
            
            # Add latest monitoring data
            latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                             .order_by(MonitoringData.timestamp.desc())\
                                             .first()
            
            device_dict['latest_response_time'] = latest_data.response_time if latest_data else None
            device_dict['latest_check'] = latest_data.timestamp.isoformat() if latest_data else None
            
            # Add active alerts count
            active_alerts = Alert.query.filter(
                Alert.device_id == device.id,
                Alert.resolved == False
            ).count()
            device_dict['active_alerts'] = active_alerts
            
            devices_data.append(device_dict)
        
        return jsonify({
            'devices': devices_data,
            'count': len(devices_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['GET'])
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
        
        device_dict['recent_monitoring_data'] = [data.to_dict() for data in monitoring_data]
        
        # Add recent alerts
        recent_alerts = Alert.query.filter_by(device_id=device_id)\
                                  .order_by(Alert.created_at.desc())\
                                  .limit(10).all()
        
        device_dict['recent_alerts'] = [alert.to_dict() for alert in recent_alerts]
        
        # Add statistics from DeviceMonitor
        from flask import current_app
        monitor = DeviceMonitor(app=current_app)
        stats_24h = monitor.get_device_statistics(device_id, hours=24)
        stats_7d = monitor.get_device_statistics(device_id, hours=24*7)
        
        device_dict['statistics'] = {
            '24h': stats_24h,
            '7d': stats_7d
        }
        
        return jsonify(device_dict)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('', methods=['POST'])
def create_device():
    """Create a new device"""
    try:
        data = request.get_json()
        
        if not data or 'ip_address' not in data:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Check if device already exists
        existing = Device.query.filter_by(ip_address=data['ip_address']).first()
        if existing:
            return jsonify({'error': 'Device with this IP already exists'}), 409
        
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
        
        return jsonify(device.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['PUT'])
def update_device(device_id):
    """Update device details"""
    try:
        device = Device.query.get_or_404(device_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update allowed fields
        allowed_fields = ['custom_name', 'device_type', 'device_group', 'is_monitored', 'hostname']
        
        for field in allowed_fields:
            if field in data:
                setattr(device, field, data[field])
        
        device.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(device.to_dict())
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    """Delete a device"""
    try:
        device = Device.query.get_or_404(device_id)
        
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({'message': 'Device deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>/ping', methods=['POST'])
def ping_device(device_id):
    """Manually trigger ping for a specific device"""
    import subprocess
    import re
    
    device = Device.query.get_or_404(device_id)
    ip = device.ip_address
    
    # Use ping with simple command
    cmd = ['ping', '-c', '1', '-W', '3', ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        success = result.returncode == 0
        response_time = None
        
        if success:
            # Parse response time
            time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
            response_time = float(time_match.group(1)) if time_match else 0.0
            
            # Update device timestamp
            device.last_seen = datetime.utcnow()
            db.session.commit()
        
        return jsonify({
            'device_id': device_id,
            'ip_address': ip,
            'success': success,
            'response_time': response_time,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'device_id': device_id,
            'ip_address': ip,
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@devices_bp.route('/ping-all', methods=['POST'])
def ping_all_devices():
    """Ping all monitored devices"""
    import subprocess
    import re
    
    # Get all monitored devices
    devices = Device.query.filter_by(is_monitored=True).all()
    
    if not devices:
        return jsonify({'error': 'No monitored devices found'}), 404
    
    results = []
    
    # Ping each device
    for device in devices:
        cmd = ['ping', '-c', '1', '-W', '3', device.ip_address]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
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
            
        except Exception:
            results.append({
                'device_id': device.id,
                'ip_address': device.ip_address,
                'display_name': device.display_name,
                'response_time': None,
                'success': False
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
def get_device_groups():
    """Get all device groups"""
    try:
        groups = db.session.query(Device.device_group)\
                          .filter(Device.device_group.isnot(None))\
                          .distinct()\
                          .all()
        
        group_list = [group[0] for group in groups if group[0]]
        
        return jsonify({'groups': sorted(group_list)})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/types', methods=['GET'])
def get_device_types():
    """Get all device types"""
    try:
        types = db.session.query(Device.device_type)\
                         .filter(Device.device_type.isnot(None))\
                         .distinct()\
                         .all()
        
        type_list = [type_item[0] for type_item in types if type_item[0]]
        
        return jsonify({'types': sorted(type_list)})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/test-ping/<string:ip>', methods=['GET'])
def test_ping(ip):
    """Test ping functionality with direct IP"""
    try:
        import subprocess
        import re
        
        # Simple ping test
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '3', ip], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        return jsonify({
            'ip': ip,
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/<int:device_id>/ping-test', methods=['POST'])
def ping_device_test(device_id):
    """Simple ping test endpoint"""
    try:
        from flask import current_app
        import subprocess
        import re
        
        device = Device.query.get_or_404(device_id)
        ip = device.ip_address
        
        # Simple ping test
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '3', ip], 
            capture_output=True, 
            text=True, 
            timeout=5
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
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/summary', methods=['GET'])
def get_devices_summary():
    """Get summary statistics of all devices"""
    try:
        total_devices = Device.query.count()
        monitored_devices = Device.query.filter_by(is_monitored=True).count()
        
        # Count by status
        devices = Device.query.all()
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
        
        # Count by type
        type_counts = {}
        for device in devices:
            device_type = device.device_type or 'unknown'
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        
        # Active alerts
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        return jsonify({
            'total_devices': total_devices,
            'monitored_devices': monitored_devices,
            'status_counts': status_counts,
            'type_counts': type_counts,
            'active_alerts': active_alerts
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500