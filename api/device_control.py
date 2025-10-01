from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from services.device_control import device_control_service
from models import Device
from api.rate_limited_endpoints import create_endpoint_limiter

device_control_bp = Blueprint('device_control', __name__)

@device_control_bp.route('/wake-on-lan', methods=['POST'])
@create_endpoint_limiter('strict')
def wake_on_lan():
    """Send Wake-on-LAN magic packet to device"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Get MAC address from request or device ID
        mac_address = data.get('mac_address')
        device_id = data.get('device_id')
        
        if not mac_address and not device_id:
            return jsonify({'error': 'Either mac_address or device_id is required'}), 400
        
        # If device_id provided, get MAC from database
        if device_id and not mac_address:
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            if not device.mac_address:
                return jsonify({'error': 'Device has no MAC address stored'}), 400
            mac_address = device.mac_address
        
        # Send Wake-on-LAN packet
        result = device_control_service.send_wake_on_lan(mac_address)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/ping', methods=['POST'])
@create_endpoint_limiter('strict')
def ping_device():
    """Ping a device to test connectivity"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Get IP address from request or device ID
        ip_address = data.get('ip_address')
        device_id = data.get('device_id')
        count = data.get('count', 4)
        
        if not ip_address and not device_id:
            return jsonify({'error': 'Either ip_address or device_id is required'}), 400
        
        # Validate count
        if not isinstance(count, int) or count < 1 or count > 10:
            return jsonify({'error': 'Count must be between 1 and 10'}), 400
        
        # If device_id provided, get IP from database
        if device_id and not ip_address:
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            ip_address = device.ip_address
        
        # Ping device
        result = device_control_service.ping_device(ip_address, count)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/port-scan', methods=['POST'])
@create_endpoint_limiter('critical')
def scan_ports():
    """Scan ports on a device"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Get IP address from request or device ID
        ip_address = data.get('ip_address')
        device_id = data.get('device_id')
        ports = data.get('ports')  # Optional custom ports
        
        if not ip_address and not device_id:
            return jsonify({'error': 'Either ip_address or device_id is required'}), 400
        
        # If device_id provided, get IP from database
        if device_id and not ip_address:
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            ip_address = device.ip_address
        
        # Validate custom ports if provided
        if ports:
            if not isinstance(ports, list):
                return jsonify({'error': 'Ports must be a list of integers'}), 400
            if len(ports) > 50:
                return jsonify({'error': 'Maximum 50 ports allowed'}), 400
            for port in ports:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    return jsonify({'error': 'Ports must be integers between 1 and 65535'}), 400
        
        # Scan ports
        result = device_control_service.scan_device_ports(ip_address, ports)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/discover-info', methods=['POST'])
@create_endpoint_limiter('strict')
def discover_info():
    """Discover additional information about a device"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Get IP address from request or device ID
        ip_address = data.get('ip_address')
        device_id = data.get('device_id')
        
        if not ip_address and not device_id:
            return jsonify({'error': 'Either ip_address or device_id is required'}), 400
        
        # If device_id provided, get IP from database
        if device_id and not ip_address:
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            ip_address = device.ip_address
        
        # Discover device info
        result = device_control_service.discover_device_info(ip_address)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/traceroute', methods=['POST'])
@create_endpoint_limiter('strict')
def traceroute():
    """Perform traceroute to a device"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Get IP address from request or device ID
        ip_address = data.get('ip_address')
        device_id = data.get('device_id')
        
        if not ip_address and not device_id:
            return jsonify({'error': 'Either ip_address or device_id is required'}), 400
        
        # If device_id provided, get IP from database
        if device_id and not ip_address:
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            ip_address = device.ip_address
        
        # Perform traceroute
        result = device_control_service.traceroute_to_device(ip_address)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/capabilities/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_capabilities(device_id):
    """Get available control capabilities for a device"""
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        capabilities = device_control_service.get_device_capabilities(device)
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'device_type': device.device_type,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'capabilities': capabilities,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/bulk-wake', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_wake_on_lan():
    """Send Wake-on-LAN to multiple devices"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        device_ids = data.get('device_ids', [])
        if not isinstance(device_ids, list) or len(device_ids) == 0:
            return jsonify({'error': 'device_ids must be a non-empty list'}), 400
        
        if len(device_ids) > 20:
            return jsonify({'error': 'Maximum 20 devices allowed for bulk operations'}), 400
        
        results = []
        for device_id in device_ids:
            try:
                device = Device.query.get(device_id)
                if not device:
                    results.append({
                        'device_id': device_id,
                        'success': False,
                        'error': 'Device not found'
                    })
                    continue
                
                if not device.mac_address:
                    results.append({
                        'device_id': device_id,
                        'device_name': device.display_name,
                        'success': False,
                        'error': 'No MAC address available'
                    })
                    continue
                
                result = device_control_service.send_wake_on_lan(device.mac_address)
                results.append({
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'mac_address': device.mac_address,
                    **result
                })
                
            except Exception as e:
                results.append({
                    'device_id': device_id,
                    'success': False,
                    'error': str(e)
                })
        
        # Summary statistics
        successful = len([r for r in results if r.get('success')])
        failed = len(results) - successful
        
        return jsonify({
            'results': results,
            'summary': {
                'total': len(results),
                'successful': successful,
                'failed': failed,
                'success_rate': (successful / len(results)) * 100 if results else 0
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/bulk-ping', methods=['POST'])
@create_endpoint_limiter('bulk')
def bulk_ping():
    """Ping multiple devices"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        device_ids = data.get('device_ids', [])
        count = data.get('count', 4)
        
        if not isinstance(device_ids, list) or len(device_ids) == 0:
            return jsonify({'error': 'device_ids must be a non-empty list'}), 400
        
        if len(device_ids) > 20:
            return jsonify({'error': 'Maximum 20 devices allowed for bulk operations'}), 400
        
        if not isinstance(count, int) or count < 1 or count > 10:
            return jsonify({'error': 'Count must be between 1 and 10'}), 400
        
        results = []
        for device_id in device_ids:
            try:
                device = Device.query.get(device_id)
                if not device:
                    results.append({
                        'device_id': device_id,
                        'success': False,
                        'error': 'Device not found'
                    })
                    continue
                
                result = device_control_service.ping_device(device.ip_address, count)
                results.append({
                    'device_id': device_id,
                    'device_name': device.display_name,
                    **result
                })
                
            except Exception as e:
                results.append({
                    'device_id': device_id,
                    'success': False,
                    'error': str(e)
                })
        
        # Summary statistics
        successful = len([r for r in results if r.get('success')])
        failed = len(results) - successful
        
        return jsonify({
            'results': results,
            'summary': {
                'total': len(results),
                'successful': successful,
                'failed': failed,
                'success_rate': (successful / len(results)) * 100 if results else 0
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@device_control_bp.route('/service-status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_service_status():
    """Get device control service status and available tools"""
    try:
        import subprocess
        
        # Check available tools
        tools_status = {}
        tools_to_check = ['ping', 'traceroute', 'tracert', 'mtr', 'nmap']
        
        for tool in tools_to_check:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True, shell=False)
                tools_status[tool] = {
                    'available': result.returncode == 0,
                    'path': result.stdout.strip() if result.returncode == 0 else None
                }
            except:
                tools_status[tool] = {'available': False, 'path': None}
        
        # Check socket capabilities
        import socket
        socket_capabilities = {
            'raw_sockets': True,  # Assume available, would need actual test
            'broadcast': True,    # Standard capability
            'udp': True,         # Standard capability
            'tcp': True          # Standard capability
        }
        
        return jsonify({
            'service': 'Device Control Service',
            'status': 'active',
            'capabilities': [
                'wake_on_lan',
                'ping',
                'port_scan', 
                'device_discovery',
                'traceroute',
                'bulk_operations'
            ],
            'tools_status': tools_status,
            'socket_capabilities': socket_capabilities,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500