from flask import Blueprint, request, jsonify, current_app
import logging
from models import db, Configuration, ConfigurationHistory

logger = logging.getLogger(__name__)

config_management_bp = Blueprint('config_management', __name__)

@config_management_bp.route('/history', methods=['GET'])
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

@config_management_bp.route('/validate', methods=['POST'])
def validate_configuration():
    """Validate configuration value without applying"""
    try:
        data = request.get_json()
        
        if not data or 'key' not in data or 'value' not in data:
            return jsonify({'error': 'Key and value are required'}), 400
        
        key = data['key']
        value = data['value']
        
        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            is_valid, error_message = config_service.validate_configuration(key, value)
            
            return jsonify({
                'valid': is_valid,
                'error': error_message if not is_valid else None,
                'key': key,
                'value': value
            })
        else:
            return jsonify({'error': 'Configuration service not available'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_management_bp.route('/backup', methods=['GET'])
def get_configuration_backup():
    """Get current configuration backup"""
    try:
        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            return jsonify({
                'backup': config_service._config_backup,
                'timestamp': config_service._last_config_check.isoformat() if hasattr(config_service, '_last_config_check') else None
            })
        else:
            return jsonify({'error': 'Configuration service not available'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_management_bp.route('/dependencies', methods=['GET'])
def get_configuration_dependencies():
    """Get configuration dependencies"""
    try:
        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            return jsonify({
                'dependencies': config_service._config_dependencies,
                'validation_rules': list(config_service._validation_rules.keys())
            })
        else:
            return jsonify({'error': 'Configuration service not available'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_management_bp.route('/health', methods=['GET'])
def configuration_health():
    """Get configuration service health status"""
    try:
        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            
            # Basic health checks
            health_status = {
                'running': config_service.running,
                'total_configurations': Configuration.query.count(),
                'total_history_entries': ConfigurationHistory.query.count(),
                'registered_services': list(config_service._service_callbacks.keys()),
                'validation_rules_count': len(config_service._validation_rules),
                'backup_entries': len(config_service._config_backup),
                'in_memory_history': len(config_service._change_history)
            }
            
            return jsonify({
                'status': 'healthy',
                'service': 'ConfigurationService',
                'details': health_status
            })
        else:
            return jsonify({
                'status': 'unavailable',
                'error': 'Configuration service not available'
            }), 500
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500