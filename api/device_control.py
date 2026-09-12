import ipaddress
from datetime import datetime

from flask import Blueprint, jsonify, request

from api.rate_limited_endpoints import create_endpoint_limiter
from core.validators import is_lan_address
from models import Device
from services.device_control import device_control_service

device_control_bp = Blueprint('device_control', __name__)


def _resolve_target(data):
    """Resolve the target IP from `ip_address` or `device_id` and validate it.

    Only private (RFC 1918 / link-local) unicast addresses are accepted: these
    endpoints run ping/traceroute/nmap and HTTP probes, so an arbitrary value
    would make the app an open relay (and `-f` would be a flood ping).
    Returns (ip_string, None) or (None, (json_response, status)).
    """
    ip_address = data.get('ip_address')
    device_id = data.get('device_id')
    if not ip_address and not device_id:
        return None, (jsonify({'error': 'Either ip_address or device_id is required'}), 400)
    if device_id and not ip_address:
        if not isinstance(device_id, int):
            return None, (jsonify({'error': 'device_id must be an integer'}), 400)
        device = Device.query.get(device_id)
        if not device:
            return None, (jsonify({'error': 'Device not found'}), 404)
        if not device.ip_address:
            return None, (jsonify({'error': 'Device has no IP address'}), 400)
        ip_address = device.ip_address
    try:
        ip = ipaddress.ip_address(str(ip_address).strip())
    except ValueError:
        return None, (jsonify({'error': 'Invalid IP address'}), 400)
    if not is_lan_address(ip):
        return None, (jsonify({'error': 'Only LAN (private) addresses can be targeted'}), 400)
    return str(ip), None

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


@device_control_bp.route('/port-scan', methods=['POST'])
@create_endpoint_limiter('critical')
def scan_ports():
    """Scan ports on a device"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400

        ports = data.get('ports')  # Optional custom ports
        ip_address, error = _resolve_target(data)
        if error:
            return error

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

        ip_address, error = _resolve_target(data)
        if error:
            return error

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

        ip_address, error = _resolve_target(data)
        if error:
            return error

        # Perform traceroute
        result = device_control_service.traceroute_to_device(ip_address)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
