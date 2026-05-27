"""
System Information API

Provides version information, system statistics, and application details.
"""

from flask import Blueprint, jsonify
from version import get_complete_info, get_version_info, get_system_info, get_application_info
import logging
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)
system_bp = Blueprint('system', __name__)

@system_bp.route('/info', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_system_info_endpoint():
    """Get comprehensive system information including version, app details, and system stats"""
    try:
        info = get_complete_info()
        return jsonify({
            'success': True,
            **info
        })
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@system_bp.route('/version', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_version_endpoint():
    """Get version information only"""
    try:
        version_info = get_version_info()
        return jsonify({
            'success': True,
            **version_info
        })
    except Exception as e:
        logger.error(f"Error getting version info: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@system_bp.route('/stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_system_stats_endpoint():
    """Get system statistics only"""
    try:
        system_info = get_system_info()
        return jsonify({
            'success': True,
            **system_info
        })
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@system_bp.route('/about', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_application_info_endpoint():
    """Get application information only"""
    try:
        app_info = get_application_info()
        return jsonify({
            'success': True,
            **app_info
        })
    except Exception as e:
        logger.error(f"Error getting application info: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@system_bp.route('/health', methods=['GET'])
@create_endpoint_limiter('relaxed')
def health_check():
    """Liveness check including background-thread heartbeat status.

    Returns 503 when at least one expected background thread is stuck or
    crashed; 200 otherwise. The full per-thread breakdown is always in
    the body so an external monitor (uptime checker, dashboard) can
    visualize what's wrong.
    """
    try:
        from version import get_version_string
        from core.health import check as check_threads

        thread_status = check_threads()
        body = {
            'success': thread_status['healthy'],
            'status': 'healthy' if thread_status['healthy'] else 'degraded',
            'version': get_version_string(),
            'threads': thread_status['threads'],
            'stale_threads': thread_status['stale'],
        }
        status_code = 200 if thread_status['healthy'] else 503
        return jsonify(body), status_code
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'success': False,
            'status': 'error',
            'error': str(e),
        }), 500
