from flask import Blueprint, request, jsonify, current_app
import logging
from models import db, Configuration, ConfigurationHistory
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

config_management_bp = Blueprint('config_management', __name__)

@config_management_bp.route('/history', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_configuration_history():
    """Get configuration change history"""
    try:
        key = request.args.get('key')
        limit = int(request.args.get('limit', 50))

        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            history = config_service.get_configuration_history(key=key, limit=limit)
            return jsonify({
                'history': history,
                'total': len(history)
            })
        else:
            # Fallback to direct database query
            query = ConfigurationHistory.query

            if key:
                query = query.filter_by(config_key=key)

            history_entries = query.order_by(
                ConfigurationHistory.changed_at.desc()
            ).limit(limit).all()

            return jsonify({
                'history': [entry.to_dict() for entry in history_entries],
                'total': len(history_entries)
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_management_bp.route('/rollback', methods=['POST'])
@create_endpoint_limiter('strict')
def rollback_configuration():
    """Rollback configuration to previous value"""
    try:
        data = request.get_json()

        if not data or 'key' not in data:
            return jsonify({'error': 'Configuration key is required'}), 400

        key = data['key']
        history_id = data.get('history_id')  # Optional: rollback to specific history entry

        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            success, message = config_service.rollback_configuration(key, history_id)

            if success:
                return jsonify({
                    'success': True,
                    'message': message,
                    'key': key
                })
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        else:
            return jsonify({'error': 'Configuration service not available'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500
