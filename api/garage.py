"""Garage door state read from the Ring camera: status, snapshot, history, Ring sign-in.

Read-only from the door's point of view (nothing here can move it). Same trust
model as the rest of the app: no authentication on the LAN, so the latest
camera frame is visible to anyone who can reach the dashboard, and anyone can
trigger a check (strict rate-limit tier, CSRF on every POST). The Ring password
is forwarded to Ring once and never stored; only the OAuth token is kept.
"""

import logging

from flask import Blueprint, current_app, jsonify, request, send_file

from api.rate_limited_endpoints import create_endpoint_limiter
from services.door_vision import VisionError
from services.garage_monitor import GarageBusy, GarageNotConfigured
from services.ring_client import RingAuthError, RingError

logger = logging.getLogger(__name__)
garage_bp = Blueprint('garage', __name__)


def _monitor():
    return getattr(current_app, 'garage_monitor', None)


def _unavailable():
    return jsonify({'error': 'Garage monitor not available'}), 503


@garage_bp.route('', methods=['GET'])
@create_endpoint_limiter('relaxed')
def garage_status():
    """Door state, the latest reading, camera and vision status (also pushed as garage_status)."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    return jsonify(monitor.status())


@garage_bp.route('/history', methods=['GET'])
@create_endpoint_limiter('relaxed')
def garage_history():
    """Door events over ?hours= (default 336 = 14 days), daily buckets and headline stats."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    hours = request.args.get('hours', default=336, type=int) or 336
    return jsonify(monitor.history(hours))


@garage_bp.route('/snapshot.jpg', methods=['GET'])
@create_endpoint_limiter('relaxed')
def garage_snapshot():
    """The latest camera frame, or the frame saved with a door event (?event=<id>). 404 until one exists."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    event_id = request.args.get('event', type=int)
    if 'event' in request.args and event_id is None:
        return jsonify({'error': 'event must be a numeric event id'}), 404
    path = monitor.frame_path(event_id)
    if path is None:
        return jsonify({'error': 'No snapshot yet'}), 404
    response = send_file(path, mimetype='image/jpeg', conditional=False, max_age=0)
    response.headers['Cache-Control'] = 'no-store'
    return response


@garage_bp.route('/check', methods=['POST'])
@create_endpoint_limiter('strict')
def garage_check():
    """Ask the camera for a fresh frame now and read the door from it."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    try:
        state = monitor.check_once(fresh=True)
    except (GarageNotConfigured, GarageBusy) as e:
        return jsonify({'error': str(e)}), 409
    except RingAuthError as e:
        return jsonify({'error': f'Ring sign-in needed: {e}'}), 409
    except (RingError, VisionError) as e:
        logger.warning(f"garage check failed: {e}")
        return jsonify({'error': f'Check failed: {e}'}), 502
    return jsonify({'success': True, 'state': state})


@garage_bp.route('/ring/login', methods=['POST'])
@create_endpoint_limiter('strict')
def ring_login():
    """Sign in to Ring: {email, password[, otp]}. Answers status 'ok' or '2fa_required' (then send the code)."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '') or '').strip()
    password = str(data.get('password', '') or '')
    otp = str(data.get('otp', '') or '').strip() or None
    if not email or not password:
        return jsonify({'error': 'Ring email and password are required'}), 400
    try:
        result = monitor.ring_login(email, password, otp)
    except RingAuthError as e:
        return jsonify({'error': str(e)}), 401
    except RingError as e:
        return jsonify({'error': str(e)}), 502
    return jsonify({'success': True, 'status': result.get('status', 'ok')})


@garage_bp.route('/ring/logout', methods=['POST'])
@create_endpoint_limiter('strict')
def ring_logout():
    """Forget the Ring token and stop the checks."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    try:
        monitor.ring_logout()
    except RingError as e:
        return jsonify({'error': str(e)}), 502
    return jsonify({'success': True, 'status': 'signed_out'})


@garage_bp.route('/ring/cameras', methods=['GET'])
@create_endpoint_limiter('moderate')
def ring_cameras():
    """Cameras on the signed-in Ring account, for the Settings picker."""
    monitor = _monitor()
    if monitor is None:
        return _unavailable()
    if not monitor.signed_in():
        return jsonify({'error': 'Not signed in to Ring'}), 409
    try:
        cameras = monitor.ring_cameras()
    except RingAuthError as e:
        return jsonify({'error': str(e)}), 409
    except RingError as e:
        return jsonify({'error': str(e)}), 502
    return jsonify({'success': True, 'cameras': cameras})
