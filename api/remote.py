# HomeNetMon Remote Access API Blueprint
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash, send_file
import os
import tempfile
import logging
from datetime import datetime
from remote_access import get_tunnel_manager
from api.rate_limited_endpoints import create_endpoint_limiter

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
remote_bp = Blueprint('remote', __name__, url_prefix='/api/remote')
remote_ui_bp = Blueprint('remote_ui', __name__, url_prefix='/remote')

# ============================================================================
# API Endpoints
# ============================================================================

@remote_bp.route('/tunnels', methods=['GET'])
@create_endpoint_limiter('relaxed')
def list_tunnels():
    """List all configured tunnels"""
    try:
        tunnel_manager = get_tunnel_manager()
        tunnels = tunnel_manager.list_tunnels()
        
        return jsonify({
            'success': True,
            'tunnels': tunnels
        })
        
    except Exception as e:
        logger.error(f"Error listing tunnels: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels', methods=['POST'])
@create_endpoint_limiter('strict')
def create_tunnel():
    """Create a new secure tunnel"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Tunnel name is required'}), 400
        
        tunnel_name = data['name']
        tunnel_type = data.get('type', 'wireguard')
        port_range = data.get('port_range', [51820, 51830])
        
        tunnel_manager = get_tunnel_manager()
        result = tunnel_manager.create_secure_tunnel(tunnel_name, tunnel_type, port_range)
        
        logger.info(f"Tunnel created: {tunnel_name} by user {request.current_user['username']}")
        
        return jsonify({
            'success': True,
            'tunnel_id': result['tunnel_id'],
            'config': result['config']
        })
        
    except Exception as e:
        logger.error(f"Error creating tunnel: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_tunnel(tunnel_id):
    """Get tunnel details"""
    try:
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        tunnel_config = tunnel_manager.tunnels[tunnel_id]
        tunnel_status = tunnel_manager.get_tunnel_status(tunnel_id)
        
        return jsonify({
            'success': True,
            'tunnel': tunnel_config,
            'status': tunnel_status
        })
        
    except Exception as e:
        logger.error(f"Error getting tunnel {tunnel_id}: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>/start', methods=['POST'])
@create_endpoint_limiter('strict')
def start_tunnel(tunnel_id):
    """Start a tunnel"""
    try:
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        success = tunnel_manager.start_tunnel(tunnel_id)
        
        if success:
            logger.info(f"Tunnel started: {tunnel_id} by user {request.current_user['username']}")
            return jsonify({'success': True, 'message': 'Tunnel started successfully'})
        else:
            return jsonify({'error': 'Failed to start tunnel'}), 500
            
    except Exception as e:
        logger.error(f"Error starting tunnel {tunnel_id}: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>/stop', methods=['POST'])
@create_endpoint_limiter('strict')
def stop_tunnel(tunnel_id):
    """Stop a tunnel"""
    try:
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        success = tunnel_manager.stop_tunnel(tunnel_id)
        
        if success:
            logger.info(f"Tunnel stopped: {tunnel_id} by user {request.current_user['username']}")
            return jsonify({'success': True, 'message': 'Tunnel stopped successfully'})
        else:
            return jsonify({'error': 'Failed to stop tunnel'}), 500
            
    except Exception as e:
        logger.error(f"Error stopping tunnel {tunnel_id}: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>/clients', methods=['POST'])
@create_endpoint_limiter('strict')
def add_tunnel_client(tunnel_id):
    """Add a client to a tunnel"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Client name is required'}), 400
        
        client_name = data['name']
        client_ip = data.get('ip')
        
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        result = tunnel_manager.add_tunnel_client(tunnel_id, client_name, client_ip)
        
        logger.info(f"Client added to tunnel {tunnel_id}: {client_name} by user {request.current_user['username']}")
        
        return jsonify({
            'success': True,
            'client_id': result['client_id'],
            'config': result['config']
        })
        
    except Exception as e:
        logger.error(f"Error adding client to tunnel {tunnel_id}: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>/clients/<client_id>/config', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_client_config(tunnel_id, client_id):
    """Get client configuration file"""
    try:
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        tunnel = tunnel_manager.tunnels[tunnel_id]
        if client_id not in tunnel['clients']:
            return jsonify({'error': 'Client not found'}), 404
        
        config = tunnel_manager._generate_client_config(tunnel_id, client_id)
        client_name = tunnel['clients'][client_id]['name']
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config)
            temp_path = f.name
        
        filename = f"{client_name}-{tunnel['name']}.conf"
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='text/plain'
        )
        
    except Exception as e:
        logger.error(f"Error getting client config: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/tunnels/<tunnel_id>', methods=['DELETE'])
@create_endpoint_limiter('critical')
def delete_tunnel(tunnel_id):
    """Delete a tunnel"""
    try:
        tunnel_manager = get_tunnel_manager()
        
        if tunnel_id not in tunnel_manager.tunnels:
            return jsonify({'error': 'Tunnel not found'}), 404
        
        success = tunnel_manager.delete_tunnel(tunnel_id)
        
        if success:
            logger.info(f"Tunnel deleted: {tunnel_id} by user {request.current_user['username']}")
            return jsonify({'success': True, 'message': 'Tunnel deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete tunnel'}), 500
            
    except Exception as e:
        logger.error(f"Error deleting tunnel {tunnel_id}: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Certificate Management API
# ============================================================================

@remote_bp.route('/certificates', methods=['GET'])
@create_endpoint_limiter('relaxed')
def list_certificates():
    """List all certificates"""
    try:
        tunnel_manager = get_tunnel_manager()
        certificates = tunnel_manager.list_certificates()
        
        return jsonify({
            'success': True,
            'certificates': certificates
        })
        
    except Exception as e:
        logger.error(f"Error listing certificates: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/certificates', methods=['POST'])
@create_endpoint_limiter('strict')
def create_certificate():
    """Create a new client certificate"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Certificate name is required'}), 400
        
        client_name = data['name']
        email = data.get('email')
        valid_days = data.get('valid_days', 365)
        
        tunnel_manager = get_tunnel_manager()
        result = tunnel_manager.create_client_certificate(client_name, email, valid_days)
        
        logger.info(f"Certificate created: {client_name} by user {request.current_user['username']}")
        
        return jsonify({
            'success': True,
            'cert_id': result['cert_id'],
            'certificate': result['certificate'],
            'private_key': result['private_key'],
            'ca_certificate': result['ca_certificate']
        })
        
    except Exception as e:
        logger.error(f"Error creating certificate: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/certificates/<cert_id>/revoke', methods=['POST'])
@create_endpoint_limiter('strict')
def revoke_certificate(cert_id):
    """Revoke a certificate"""
    try:
        tunnel_manager = get_tunnel_manager()
        success = tunnel_manager.revoke_certificate(cert_id)
        
        if success:
            logger.info(f"Certificate revoked: {cert_id} by user {request.current_user['username']}")
            return jsonify({'success': True, 'message': 'Certificate revoked successfully'})
        else:
            return jsonify({'error': 'Certificate not found'}), 404
            
    except Exception as e:
        logger.error(f"Error revoking certificate {cert_id}: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Authentication API
# ============================================================================

@remote_bp.route('/auth/login', methods=['POST'])
@create_endpoint_limiter('strict')
def login():
    """Authenticate user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username']
        password = data['password']
        mfa_token = data.get('mfa_token')
        remember_me = data.get('remember_me', False)
        
        auth_manager = get_auth_manager()
        result = auth_manager.authenticate_user(username, password, mfa_token, remember_me)
        
        if not result:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if 'requires_mfa' in result:
            return jsonify({
                'requires_mfa': True,
                'user_id': result['user_id']
            })
        
        # Store session token
        session['session_token'] = result['session_token']
        session['user_id'] = result['user_id']
        
        return jsonify({
            'success': True,
            'user': {
                'id': result['user_id'],
                'username': result['username'],
                'role': result['role']
            },
            'session_token': result['session_token'],
            'expires_at': result['expires_at']
        })
        
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/auth/logout', methods=['POST'])
@create_endpoint_limiter('strict')
def logout():
    """Logout user"""
    try:
        auth_manager = get_auth_manager()
        session_token = session.get('session_token')
        
        if session_token:
            auth_manager.logout_user(session_token)
        
        session.clear()
        
        return jsonify({'success': True, 'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/auth/user', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_current_user():
    """Get current user information"""
    try:
        user_data = request.current_user
        auth_manager = get_auth_manager()
        
        # Get additional user information
        sessions = auth_manager.get_user_sessions(user_data['user_id'])
        api_keys = auth_manager.get_user_api_keys(user_data['user_id'])
        
        return jsonify({
            'success': True,
            'user': {
                'id': user_data['user_id'],
                'username': user_data['username'],
                'role': user_data['role'],
                'sessions': sessions,
                'api_keys': api_keys
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/auth/api-keys', methods=['POST'])
@create_endpoint_limiter('strict')
def create_api_key():
    """Create a new API key"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'API key name is required'}), 400
        
        name = data['name']
        permissions = data.get('permissions', ['read'])
        expires_days = data.get('expires_days', 30)
        
        auth_manager = get_auth_manager()
        api_key = auth_manager.create_api_key(
            request.current_user['user_id'],
            name,
            permissions,
            expires_days
        )
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'API key created successfully. Store it securely - it will not be shown again.'
        })
        
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/auth/api-keys/<key_id>', methods=['DELETE'])
@create_endpoint_limiter('critical')
def revoke_api_key(key_id):
    """Revoke an API key"""
    try:
        auth_manager = get_auth_manager()
        success = auth_manager.revoke_api_key(key_id)
        
        if success:
            return jsonify({'success': True, 'message': 'API key revoked successfully'})
        else:
            return jsonify({'error': 'API key not found'}), 404
            
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# UI Routes
# ============================================================================

@remote_ui_bp.route('/')
@create_endpoint_limiter('relaxed')
def remote_dashboard():
    """Remote access dashboard"""
    try:
        tunnel_manager = get_tunnel_manager()
        tunnels = tunnel_manager.list_tunnels()
        certificates = tunnel_manager.list_certificates()
        
        return render_template('remote/dashboard.html',
                             tunnels=tunnels,
                             certificates=certificates,
                             user=request.current_user)
        
    except Exception as e:
        logger.error(f"Error loading remote dashboard: {e}")
        flash(f'Error loading dashboard: {e}', 'error')
        return redirect(url_for('dashboard'))

@remote_ui_bp.route('/tunnels')
@create_endpoint_limiter('relaxed')
def tunnel_management():
    """Tunnel management page"""
    try:
        tunnel_manager = get_tunnel_manager()
        tunnels = tunnel_manager.list_tunnels()
        
        return render_template('remote/tunnels.html',
                             tunnels=tunnels,
                             user=request.current_user)
        
    except Exception as e:
        logger.error(f"Error loading tunnel management: {e}")
        flash(f'Error loading tunnels: {e}', 'error')
        return redirect(url_for('remote_ui.remote_dashboard'))

@remote_ui_bp.route('/certificates')
@create_endpoint_limiter('relaxed')
def certificate_management():
    """Certificate management page"""
    try:
        tunnel_manager = get_tunnel_manager()
        certificates = tunnel_manager.list_certificates()
        
        return render_template('remote/certificates.html',
                             certificates=certificates,
                             user=request.current_user)
        
    except Exception as e:
        logger.error(f"Error loading certificate management: {e}")
        flash(f'Error loading certificates: {e}', 'error')
        return redirect(url_for('remote_ui.remote_dashboard'))

@remote_ui_bp.route('/auth/login')
@create_endpoint_limiter('relaxed')
def login_page():
    """Login page for remote access"""
    if 'session_token' in session:
        auth_manager = get_auth_manager()
        user_data = auth_manager.validate_session(session['session_token'])
        if user_data:
            return redirect(url_for('remote_ui.remote_dashboard'))
    
    return render_template('remote/login.html')

@remote_ui_bp.route('/auth/setup')
@create_endpoint_limiter('relaxed')
def setup_page():
    """Setup page for MFA and security"""
    try:
        auth_manager = get_auth_manager()
        user_id = request.current_user['user_id']
        
        # Generate MFA QR code if MFA is not set up
        mfa_data = auth_manager.generate_mfa_qr_code(user_id)
        
        return render_template('remote/setup.html',
                             user=request.current_user,
                             mfa_data=mfa_data)
        
    except Exception as e:
        logger.error(f"Error loading setup page: {e}")
        flash(f'Error loading setup: {e}', 'error')
        return redirect(url_for('remote_ui.remote_dashboard'))

# ============================================================================
# Error Handlers
# ============================================================================

@remote_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized access'}), 401

@remote_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden - insufficient permissions'}), 403

@remote_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@remote_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500