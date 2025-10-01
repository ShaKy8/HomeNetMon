"""
Rate limiting administration and monitoring API.

Provides endpoints to monitor rate limiting status and manage rate limits.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import logging
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

rate_limit_admin_bp = Blueprint('rate_limit_admin', __name__)

@rate_limit_admin_bp.route('/status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_rate_limit_status():
    """Get current rate limiting status and statistics."""
    try:
        if not hasattr(current_app, 'rate_limiter'):
            return jsonify({'error': 'Rate limiter not available'}), 503
        
        rate_limiter = current_app.rate_limiter
        
        # Get basic status
        backend = 'memory'
        try:
            if hasattr(rate_limiter.limiter.storage, 'storage_uri'):
                backend = 'memory' if 'memory://' in str(rate_limiter.limiter.storage.storage_uri) else 'redis'
            else:
                backend = 'memory'  # MemoryStorage doesn't have storage_uri attribute
        except:
            backend = 'memory'
            
        status = {
            'enabled': True,
            'backend': backend,
            'trusted_ips': list(rate_limiter.trusted_ips),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Get rate limit status for current client
        identifier = rate_limiter._get_identifier()
        rate_status = rate_limiter.get_rate_limit_status(identifier)
        
        return jsonify({
            'success': True,
            'status': status,
            'current_client': rate_status
        })
        
    except Exception as e:
        logger.error(f"Error getting rate limit status: {e}")
        return jsonify({'error': str(e)}), 500

@rate_limit_admin_bp.route('/limits', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_configured_limits():
    """Get information about configured rate limits."""
    try:
        limits_info = {
            'endpoint_types': {
                'relaxed': "120 per minute, 2000 per hour (read-heavy operations)",
                'moderate': "60 per minute, 1000 per hour (standard operations)",
                'strict': "10 per minute, 100 per hour (sensitive operations)",
                'bulk': "2 per minute, 20 per hour (bulk operations)",
                'intensive': "1 per minute, 10 per hour (resource-intensive operations)",
                'critical': "1 per 5 minutes, 6 per hour (critical system operations)"
            },
            'applied_endpoints': [
                {'endpoint': '/api/devices (GET)', 'limit_type': 'relaxed'},
                {'endpoint': '/api/devices/<id> (DELETE)', 'limit_type': 'strict'},
                {'endpoint': '/api/devices/ping-all (POST)', 'limit_type': 'intensive'},
                {'endpoint': '/api/devices/bulk-update (POST)', 'limit_type': 'bulk'},
                {'endpoint': '/api/devices/bulk-ping (POST)', 'limit_type': 'intensive'},
                {'endpoint': '/api/speedtest/run (POST)', 'limit_type': 'critical'},
                {'endpoint': '/api/security/device/<id>/scan (POST)', 'limit_type': 'critical'},
                {'endpoint': '/api/security/run-scan (POST)', 'limit_type': 'critical'}
            ],
            'default_limits': "1000 per hour, 100 per minute (for unspecified endpoints)",
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify({
            'success': True,
            'limits': limits_info
        })
        
    except Exception as e:
        logger.error(f"Error getting rate limit configuration: {e}")
        return jsonify({'error': str(e)}), 500

@rate_limit_admin_bp.route('/stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_rate_limit_stats():
    """Get rate limiting abuse statistics."""
    try:
        if not hasattr(current_app, 'rate_limiter'):
            return jsonify({'error': 'Rate limiter not available'}), 503
        
        rate_limiter = current_app.rate_limiter
        hours = int(request.args.get('hours', 24))
        
        stats = rate_limiter.get_abuse_stats(hours)
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting rate limit stats: {e}")
        return jsonify({'error': str(e)}), 500

@rate_limit_admin_bp.route('/reset/<string:identifier>', methods=['POST'])
@create_endpoint_limiter('critical')
def reset_rate_limits(identifier):
    """Reset rate limits for a specific identifier (admin operation)."""
    try:
        if not hasattr(current_app, 'rate_limiter'):
            return jsonify({'error': 'Rate limiter not available'}), 503
        
        rate_limiter = current_app.rate_limiter
        success = rate_limiter.reset_limits(identifier)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Rate limits reset for {identifier}',
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({'error': 'Failed to reset rate limits'}), 500
            
    except Exception as e:
        logger.error(f"Error resetting rate limits: {e}")
        return jsonify({'error': str(e)}), 500

@rate_limit_admin_bp.route('/test', methods=['GET'])
@create_endpoint_limiter('critical')
def test_rate_limiting():
    """Test endpoint to verify rate limiting is working."""
    try:
        # This endpoint has no specific rate limiting, so it uses the default
        return jsonify({
            'success': True,
            'message': 'Rate limiting test endpoint',
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Make multiple requests to test rate limiting'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500