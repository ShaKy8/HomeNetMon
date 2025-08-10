from flask import Blueprint, request, jsonify
from models import db, Configuration
from config import Config

config_bp = Blueprint('config', __name__)

@config_bp.route('', methods=['GET'])
def get_configuration():
    """Get all configuration settings"""
    try:
        configs = Configuration.query.all()
        config_dict = {config.key: {
            'value': config.value,
            'description': config.description,
            'updated_at': config.updated_at.isoformat()
        } for config in configs}
        
        # Add current runtime configuration values
        runtime_config = {
            'network_range': Config.NETWORK_RANGE,
            'ping_interval': Config.PING_INTERVAL,
            'scan_interval': Config.SCAN_INTERVAL,
            'ping_timeout': Config.PING_TIMEOUT,
            'max_workers': Config.MAX_WORKERS,
            'data_retention_days': Config.DATA_RETENTION_DAYS,
            'host': Config.HOST,
            'port': Config.PORT,
            'debug': Config.DEBUG
        }
        
        return jsonify({
            'database_config': config_dict,
            'runtime_config': runtime_config
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/<string:key>', methods=['GET'])
def get_config_value(key):
    """Get specific configuration value"""
    try:
        config = Configuration.query.filter_by(key=key).first()
        
        if not config:
            return jsonify({'error': 'Configuration key not found'}), 404
        
        return jsonify(config.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/<string:key>', methods=['PUT'])
def update_config_value(key):
    """Update specific configuration value"""
    try:
        data = request.get_json()
        
        if not data or 'value' not in data:
            return jsonify({'error': 'Value is required'}), 400
        
        # Validate certain configuration keys
        if key == 'ping_interval':
            try:
                value = int(data['value'])
                if value < 5 or value > 300:
                    return jsonify({'error': 'Ping interval must be between 5 and 300 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Ping interval must be a number'}), 400
        
        elif key == 'scan_interval':
            try:
                value = int(data['value'])
                if value < 60 or value > 3600:
                    return jsonify({'error': 'Scan interval must be between 60 and 3600 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Scan interval must be a number'}), 400
        
        elif key == 'data_retention_days':
            try:
                value = int(data['value'])
                if value < 1 or value > 365:
                    return jsonify({'error': 'Data retention must be between 1 and 365 days'}), 400
            except ValueError:
                return jsonify({'error': 'Data retention days must be a number'}), 400
        
        # Update configuration
        config = Configuration.set_value(
            key=key,
            value=data['value'],
            description=data.get('description')
        )
        
        return jsonify(config.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/network', methods=['GET'])
def get_network_config():
    """Get network-related configuration"""
    try:
        network_config = {
            'network_range': Configuration.get_value('network_range', Config.NETWORK_RANGE),
            'ping_interval': int(Configuration.get_value('ping_interval', str(Config.PING_INTERVAL))),
            'scan_interval': int(Configuration.get_value('scan_interval', str(Config.SCAN_INTERVAL))),
            'ping_timeout': float(Configuration.get_value('ping_timeout', str(Config.PING_TIMEOUT))),
            'max_workers': int(Configuration.get_value('max_workers', str(Config.MAX_WORKERS)))
        }
        
        return jsonify(network_config)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/network', methods=['PUT'])
def update_network_config():
    """Update network configuration"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate and update each field
        updated_fields = []
        
        if 'network_range' in data:
            # Basic validation for network range (CIDR notation)
            import ipaddress
            try:
                ipaddress.ip_network(data['network_range'], strict=False)
                Configuration.set_value('network_range', data['network_range'], 'Network range to monitor')
                updated_fields.append('network_range')
            except ValueError:
                return jsonify({'error': 'Invalid network range format'}), 400
        
        if 'ping_interval' in data:
            try:
                value = int(data['ping_interval'])
                if 5 <= value <= 300:
                    Configuration.set_value('ping_interval', str(value), 'Ping interval in seconds')
                    updated_fields.append('ping_interval')
                else:
                    return jsonify({'error': 'Ping interval must be between 5 and 300 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Ping interval must be a number'}), 400
        
        if 'scan_interval' in data:
            try:
                value = int(data['scan_interval'])
                if 60 <= value <= 3600:
                    Configuration.set_value('scan_interval', str(value), 'Network scan interval in seconds')
                    updated_fields.append('scan_interval')
                else:
                    return jsonify({'error': 'Scan interval must be between 60 and 3600 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Scan interval must be a number'}), 400
        
        if 'ping_timeout' in data:
            try:
                value = float(data['ping_timeout'])
                if 1.0 <= value <= 10.0:
                    Configuration.set_value('ping_timeout', str(value), 'Ping timeout in seconds')
                    updated_fields.append('ping_timeout')
                else:
                    return jsonify({'error': 'Ping timeout must be between 1.0 and 10.0 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Ping timeout must be a number'}), 400
        
        if 'max_workers' in data:
            try:
                value = int(data['max_workers'])
                if 1 <= value <= 100:
                    Configuration.set_value('max_workers', str(value), 'Maximum worker threads for monitoring')
                    updated_fields.append('max_workers')
                else:
                    return jsonify({'error': 'Max workers must be between 1 and 100'}), 400
            except ValueError:
                return jsonify({'error': 'Max workers must be a number'}), 400
        
        return jsonify({
            'message': f'Updated {len(updated_fields)} network configuration field(s)',
            'updated_fields': updated_fields,
            'note': 'Changes will take effect after service restart'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/alerts', methods=['GET'])
def get_alert_config():
    """Get alert-related configuration"""
    try:
        alert_config = {
            'email_enabled': Configuration.get_value('alert_email_enabled', 'false').lower() == 'true',
            'webhook_enabled': Configuration.get_value('alert_webhook_enabled', 'false').lower() == 'true',
            'push_enabled': Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true',
            'email_from': Configuration.get_value('alert_from_email', ''),
            'email_to': Configuration.get_value('alert_to_emails', ''),
            'webhook_url': Configuration.get_value('alert_webhook_url', ''),
            'ntfy_topic': Configuration.get_value('ntfy_topic', ''),
            'ntfy_server': Configuration.get_value('ntfy_server', 'https://ntfy.sh'),
            'device_down_threshold': int(Configuration.get_value('device_down_threshold_minutes', '3')),
            'high_latency_threshold': int(Configuration.get_value('high_latency_threshold_ms', '1000'))
        }
        
        return jsonify(alert_config)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/alerts', methods=['PUT'])
def update_alert_config():
    """Update alert configuration"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        updated_fields = []
        
        if 'email_enabled' in data:
            Configuration.set_value('alert_email_enabled', str(data['email_enabled']).lower(), 'Enable email alerts')
            updated_fields.append('email_enabled')
        
        if 'webhook_enabled' in data:
            Configuration.set_value('alert_webhook_enabled', str(data['webhook_enabled']).lower(), 'Enable webhook alerts')
            updated_fields.append('webhook_enabled')
        
        if 'push_enabled' in data:
            Configuration.set_value('push_notifications_enabled', str(data['push_enabled']).lower(), 'Enable push notifications')
            updated_fields.append('push_enabled')
        
        if 'ntfy_topic' in data:
            Configuration.set_value('ntfy_topic', data['ntfy_topic'], 'Ntfy topic name')
            updated_fields.append('ntfy_topic')
        
        if 'ntfy_server' in data:
            Configuration.set_value('ntfy_server', data['ntfy_server'], 'Ntfy server URL')
            updated_fields.append('ntfy_server')
        
        if 'email_from' in data:
            Configuration.set_value('alert_from_email', data['email_from'], 'From email address for alerts')
            updated_fields.append('email_from')
        
        if 'email_to' in data:
            Configuration.set_value('alert_to_emails', data['email_to'], 'To email addresses for alerts (comma separated)')
            updated_fields.append('email_to')
        
        if 'webhook_url' in data:
            Configuration.set_value('alert_webhook_url', data['webhook_url'], 'Webhook URL for alerts')
            updated_fields.append('webhook_url')
        
        if 'device_down_threshold' in data:
            try:
                value = int(data['device_down_threshold'])
                if 1 <= value <= 60:
                    Configuration.set_value('device_down_threshold_minutes', str(value), 'Minutes before device down alert')
                    updated_fields.append('device_down_threshold')
                else:
                    return jsonify({'error': 'Device down threshold must be between 1 and 60 minutes'}), 400
            except ValueError:
                return jsonify({'error': 'Device down threshold must be a number'}), 400
        
        if 'high_latency_threshold' in data:
            try:
                value = int(data['high_latency_threshold'])
                if 100 <= value <= 10000:
                    Configuration.set_value('high_latency_threshold_ms', str(value), 'Milliseconds threshold for high latency alert')
                    updated_fields.append('high_latency_threshold')
                else:
                    return jsonify({'error': 'High latency threshold must be between 100 and 10000 ms'}), 400
            except ValueError:
                return jsonify({'error': 'High latency threshold must be a number'}), 400
        
        return jsonify({
            'message': f'Updated {len(updated_fields)} alert configuration field(s)',
            'updated_fields': updated_fields
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/reset', methods=['POST'])
def reset_configuration():
    """Reset configuration to defaults"""
    try:
        data = request.get_json() or {}
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({'error': 'Please confirm reset by sending {"confirm": true}'}), 400
        
        # Delete all configuration entries
        Configuration.query.delete()
        db.session.commit()
        
        # Reinitialize default configuration
        default_configs = [
            ('network_range', '192.168.86.0/24', 'Network range to monitor'),
            ('ping_interval', '30', 'Ping interval in seconds'),
            ('scan_interval', '300', 'Network scan interval in seconds'),
            ('alert_email_enabled', 'false', 'Enable email alerts'),
            ('alert_webhook_enabled', 'false', 'Enable webhook alerts'),
            ('push_notifications_enabled', 'false', 'Enable push notifications'),
            ('ntfy_topic', '', 'Ntfy topic name (e.g., your-unique-topic)'),
            ('ntfy_server', 'https://ntfy.sh', 'Ntfy server URL'),
        ]
        
        for key, value, description in default_configs:
            Configuration.set_value(key, value, description)
        
        return jsonify({
            'message': 'Configuration reset to defaults',
            'note': 'Restart required for changes to take effect'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@config_bp.route('/test/email', methods=['POST'])
def test_email_config():
    """Test email configuration by sending a test email"""
    try:
        data = request.get_json() or {}
        
        # Use provided settings or current configuration
        smtp_server = data.get('smtp_server') or Config.SMTP_SERVER
        smtp_port = data.get('smtp_port') or Config.SMTP_PORT
        smtp_username = data.get('smtp_username') or Config.SMTP_USERNAME
        smtp_password = data.get('smtp_password') or Config.SMTP_PASSWORD
        from_email = data.get('from_email') or Config.ALERT_FROM_EMAIL
        to_emails = data.get('to_emails') or Config.ALERT_TO_EMAILS
        
        if not all([smtp_server, smtp_username, smtp_password, from_email, to_emails]):
            return jsonify({'error': 'All email configuration fields are required'}), 400
        
        # Send test email
        from monitoring.alerts import AlertManager
        alert_manager = AlertManager()
        
        # Create a mock alert for testing
        class MockDevice:
            display_name = "Test Device"
            ip_address = "192.168.1.100"
            id = 999
        
        class MockAlert:
            device = MockDevice()
            alert_type = "test"
            severity = "info"
            message = "This is a test alert from HomeNetMon"
            created_at = datetime.utcnow()
        
        # Temporarily override config for test
        original_config = {
            'SMTP_SERVER': Config.SMTP_SERVER,
            'SMTP_PORT': Config.SMTP_PORT,
            'SMTP_USERNAME': Config.SMTP_USERNAME,
            'SMTP_PASSWORD': Config.SMTP_PASSWORD,
            'ALERT_FROM_EMAIL': Config.ALERT_FROM_EMAIL,
            'ALERT_TO_EMAILS': Config.ALERT_TO_EMAILS
        }
        
        Config.SMTP_SERVER = smtp_server
        Config.SMTP_PORT = smtp_port
        Config.SMTP_USERNAME = smtp_username
        Config.SMTP_PASSWORD = smtp_password
        Config.ALERT_FROM_EMAIL = from_email
        Config.ALERT_TO_EMAILS = to_emails if isinstance(to_emails, list) else [to_emails]
        
        try:
            success = alert_manager.send_email_alert(MockAlert())
            
            # Restore original config
            for key, value in original_config.items():
                setattr(Config, key, value)
            
            if success:
                return jsonify({'message': 'Test email sent successfully'})
            else:
                return jsonify({'error': 'Failed to send test email'}), 500
                
        except Exception as e:
            # Restore original config
            for key, value in original_config.items():
                setattr(Config, key, value)
            raise e
        
    except Exception as e:
        return jsonify({'error': f'Email test failed: {str(e)}'}), 500

@config_bp.route('/test/webhook', methods=['POST'])
def test_webhook_config():
    """Test webhook configuration by sending a test webhook"""
    try:
        data = request.get_json() or {}
        
        webhook_url = data.get('webhook_url') or Config.WEBHOOK_URL
        
        if not webhook_url:
            return jsonify({'error': 'Webhook URL is required'}), 400
        
        # Send test webhook
        test_payload = {
            'alert_id': 999,
            'device_name': 'Test Device',
            'device_ip': '192.168.1.100',
            'alert_type': 'test',
            'severity': 'info',
            'message': 'This is a test alert from HomeNetMon',
            'timestamp': datetime.utcnow().isoformat(),
            'dashboard_url': f"http://{Config.HOST}:{Config.PORT}",
            'test': True
        }
        
        import requests
        response = requests.post(webhook_url, json=test_payload, timeout=10)
        
        if response.status_code == 200:
            return jsonify({
                'message': 'Test webhook sent successfully',
                'status_code': response.status_code,
                'response': response.text[:200]  # First 200 chars of response
            })
        else:
            return jsonify({
                'error': f'Webhook test failed with status {response.status_code}',
                'response': response.text[:200]
            }), 500
        
    except Exception as e:
        return jsonify({'error': f'Webhook test failed: {str(e)}'}), 500

@config_bp.route('/test/push', methods=['POST'])
def test_push_config():
    """Test push notification configuration by sending a test notification"""
    try:
        from services.push_notifications import push_service
        
        # Update push service configuration from database
        push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
        push_service.topic = Configuration.get_value('ntfy_topic', '')
        push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
        
        if not push_service.is_configured():
            return jsonify({
                'success': False,
                'error': 'Push notifications not configured. Please set topic and enable notifications.'
            }), 400
        
        # Send test notification
        success = push_service.send_test_notification()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Test notification sent successfully! Check your mobile device.'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to send test notification. Check your configuration.'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error sending test notification: {str(e)}'
        }), 500

@config_bp.route('/restart-services', methods=['POST'])
def restart_services():
    """Restart monitoring services to apply configuration changes"""
    try:
        import subprocess
        import os
        import signal
        
        # Simple approach: Try to restart the main process
        # This works by sending a signal to reload configuration
        
        # Method 1: Try using systemctl if running as service
        try:
            result = subprocess.run(['systemctl', 'is-active', 'homenetmon'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Service is running, restart it
                subprocess.run(['sudo', 'systemctl', 'restart', 'homenetmon'], 
                             check=True)
                return jsonify({
                    'success': True,
                    'message': 'HomeNetMon service restart initiated via systemctl.',
                    'note': 'Service will restart in a few seconds with new configuration.'
                })
        except:
            pass  # Fall through to other methods
        
        # Method 2: For development/manual runs, just return instructions
        return jsonify({
            'success': True,
            'message': 'Configuration saved. Please restart HomeNetMon to apply network range changes.',
            'instructions': [
                'If running manually: Stop (Ctrl+C) and restart the application',
                'If running as service: Run "sudo systemctl restart homenetmon"',
                'Configuration will be applied after restart'
            ],
            'note': 'Network range changes require a full restart to take effect.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error restarting services: {str(e)}'
        }), 500