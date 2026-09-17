"""Garage door (ratgdo board) API: state, control, history, discovery.

Same trust model as the rest of the app: no authentication on the LAN, so a
POST here is available to any LAN host or Tailscale peer that can reach the
dashboard. Mitigations are CSRF on every unsafe method, the strict rate-limit
tier, LAN-only host validation and the hold-to-confirm control in the UI.
"""

import logging

from flask import Blueprint, current_app, jsonify, request

from api.rate_limited_endpoints import create_endpoint_limiter
from services import ratgdo_client as rc
from services.garage_monitor import GarageNotConfigured

logger = logging.getLogger(__name__)
garage_bp = Blueprint('garage', __name__)

ACTIONS = {
    'door': ('open', 'close', 'stop', 'toggle'),
    'light': ('on', 'off', 'toggle'),
    'lock': ('lock', 'unlock'),
}


def _monitor():
    return getattr(current_app, 'garage_monitor', None)


def _command(kind):
    monitor = _monitor()
    if monitor is None:
        return jsonify({'error': 'Garage monitor not available'}), 503
    data = request.get_json(silent=True) or {}
    action = str(data.get('action', '')).strip().lower()
    if action not in ACTIONS[kind]:
        return jsonify({'error': f"action must be one of {', '.join(ACTIONS[kind])}"}), 400
    try:
        monitor.command(kind, action)
    except GarageNotConfigured as e:
        return jsonify({'error': str(e)}), 409
    except rc.RatgdoError as e:
        logger.warning(f"garage {kind} {action} failed: {e}")
        return jsonify({'error': f'The garage controller did not accept the command: {e}'}), 502
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'success': True, 'kind': kind, 'action': action, 'state': monitor.status()})


@garage_bp.route('', methods=['GET'])
@create_endpoint_limiter('relaxed')
def garage_status():
    """Current door / light / lock / sensor state and integration status (also pushed as garage_status)."""
    monitor = _monitor()
    if monitor is None:
        return jsonify({'error': 'Garage monitor not available'}), 503
    return jsonify(monitor.status())


@garage_bp.route('/door', methods=['POST'])
@create_endpoint_limiter('strict')
def garage_door():
    """Drive the door: {"action": "open" | "close" | "stop" | "toggle"}."""
    return _command('door')


@garage_bp.route('/light', methods=['POST'])
@create_endpoint_limiter('strict')
def garage_light():
    """Opener light: {"action": "on" | "off" | "toggle"}."""
    return _command('light')


@garage_bp.route('/lock', methods=['POST'])
@create_endpoint_limiter('strict')
def garage_lock():
    """Wireless remotes lock-out: {"action": "lock" | "unlock"}."""
    return _command('lock')


@garage_bp.route('/history', methods=['GET'])
@create_endpoint_limiter('relaxed')
def garage_history():
    """Door events over ?hours= (default 336 = 14 days), daily buckets and headline stats."""
    monitor = _monitor()
    if monitor is None:
        return jsonify({'error': 'Garage monitor not available'}), 503
    hours = request.args.get('hours', default=336, type=int) or 336
    return jsonify(monitor.history(hours))


@garage_bp.route('/discover', methods=['GET'])
@create_endpoint_limiter('moderate')
def garage_discover():
    """Probe known LAN devices that look like a ratgdo (hostname, mDNS, Espressif OUI); confirmed ones first."""
    from services import garage_discovery
    monitor = _monitor()
    current = None
    if monitor is not None:
        try:
            current = monitor.config().get('host')
        except Exception:
            current = None
    return jsonify({'success': True, **garage_discovery.discover(current_host=current)})


@garage_bp.route('/test', methods=['POST'])
@create_endpoint_limiter('strict')
def garage_test():
    """Try a host from the Settings form: {"host", "username", "password"} -> door state and firmware."""
    data = request.get_json(silent=True) or {}
    host = str(data.get('host', '')).strip()
    try:
        rc.parse_host(host)
    except ValueError as e:
        return jsonify({'error': f'Host rejected: {e}'}), 400
    username = str(data.get('username', '') or '').strip() or None
    password = str(data.get('password', '') or '') or None
    if not password and username:
        monitor = _monitor()
        if monitor is not None:
            password = monitor.config().get('password') or None    # "unchanged" password from the form
    try:
        client = rc.RatgdoClient(host, username, password, timeout=3.0)
        state = client.snapshot()
    except rc.RatgdoError as e:
        return jsonify({'error': f'No ratgdo answered at {host}: {e}'}), 502
    return jsonify({'success': True, 'host': client.host, 'door': state['door'], 'light': state['light'],
                    'firmware': state['firmware'], 'openings': state['openings']})
