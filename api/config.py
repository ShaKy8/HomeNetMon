from flask import Blueprint, request, jsonify, current_app
from models import db, Configuration
from config import Config
from api.rate_limited_endpoints import create_endpoint_limiter
from core.error_handler import handle_errors, ResourceNotFoundError, DatabaseError, ValidationError

config_bp = Blueprint('config', __name__)


def _set(key, value, description=None):
    """Write a runtime setting through the configuration service.

    The service validates, records a ConfigurationHistory row (what the
    Settings > History/rollback UI reads) and fires the hot-reload callbacks the
    scanner/monitor/alert manager registered. Returns (ok, message).
    """
    service = getattr(current_app, 'configuration_service', None)
    if service is None or service.app is None:
        Configuration.set_value(key, str(value), description)
        return True, 'Configuration updated'
    return service.set_configuration(key, value, description, user='settings_ui')


@config_bp.route('', methods=['GET'])
@create_endpoint_limiter('relaxed')
@handle_errors()
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
        raise DatabaseError("Failed to retrieve configuration", operation="get_configuration") from e


@config_bp.route('/<string:key>', methods=['PUT'])
@create_endpoint_limiter('strict')
def update_config_value(key):
    """Update specific configuration value"""
    try:
        from flask import current_app
        data = request.get_json()

        if not data or 'value' not in data:
            return jsonify({'error': 'Value is required'}), 400

        # Use configuration service if available
        if hasattr(current_app, 'configuration_service'):
            config_service = current_app.configuration_service
            success, message = config_service.set_configuration(
                key=key,
                value=data['value'],
                description=data.get('description'),
                user='api_user',
                validate=True
            )

            if success:
                # Get updated configuration
                config = Configuration.query.filter_by(key=key).first()
                return jsonify(config.to_dict() if config else {'key': key, 'value': data['value']})
            else:
                return jsonify({'error': message}), 400
        else:
            # Fallback to legacy validation and direct database access
            # Validate certain configuration keys
            if key == 'ping_interval':
                try:
                    value = int(data['value'])
                    if value < 5 or value > 900:
                        return jsonify({'error': 'Ping interval must be between 30 and 3600 seconds'}), 400
                except ValueError:
                    return jsonify({'error': 'Ping interval must be a number'}), 400

            elif key == 'scan_interval':
                try:
                    value = int(data['value'])
                    if value < 60 or value > 3600:
                        return jsonify({'error': 'Scan interval must be between 300 seconds and 7 days'}), 400
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
@create_endpoint_limiter('relaxed')
def get_network_config():
    """Get network-related configuration"""
    try:
        network_config = {
            'network_range': Configuration.get_value('network_range', Config.NETWORK_RANGE),
            'ping_interval': int(Configuration.get_value('ping_interval', str(Config.PING_INTERVAL))),
            'scan_interval': int(Configuration.get_value('scan_interval', str(Config.SCAN_INTERVAL))),
            'ping_timeout': float(Configuration.get_value('ping_timeout', str(Config.PING_TIMEOUT))),
            'max_workers': int(Configuration.get_value('max_workers', str(Config.MAX_WORKERS))),
            'scan_excluded_ips': Configuration.get_value('scan_excluded_ips', '')
        }

        return jsonify(network_config)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/network', methods=['PUT'])
@create_endpoint_limiter('strict')
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
                ok, msg = _set('network_range', data['network_range'], 'Network range to monitor')
                if not ok:
                    return jsonify({'error': msg}), 400
                updated_fields.append('network_range')
            except ValueError:
                return jsonify({'error': 'Invalid network range format'}), 400

        if 'ping_interval' in data:
            try:
                value = int(data['ping_interval'])
                if 30 <= value <= 3600:
                    ok, msg = _set('ping_interval', str(value), 'Ping interval in seconds')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('ping_interval')
                else:
                    return jsonify({'error': 'Ping interval must be between 30 and 3600 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Ping interval must be a number'}), 400

        if 'scan_interval' in data:
            try:
                value = int(data['scan_interval'])
                if 300 <= value <= 604800:
                    ok, msg = _set('scan_interval', str(value), 'Network scan interval in seconds')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('scan_interval')
                else:
                    return jsonify({'error': 'Scan interval must be between 300 seconds and 7 days'}), 400
            except ValueError:
                return jsonify({'error': 'Scan interval must be a number'}), 400

        if 'ping_timeout' in data:
            try:
                value = float(data['ping_timeout'])
                if 1.0 <= value <= 10.0:
                    ok, msg = _set('ping_timeout', str(value), 'Ping timeout in seconds')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('ping_timeout')
                else:
                    return jsonify({'error': 'Ping timeout must be between 1.0 and 10.0 seconds'}), 400
            except ValueError:
                return jsonify({'error': 'Ping timeout must be a number'}), 400

        if 'max_workers' in data:
            try:
                value = int(data['max_workers'])
                if 1 <= value <= 100:
                    ok, msg = _set('max_workers', str(value), 'Maximum worker threads for monitoring')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('max_workers')
                else:
                    return jsonify({'error': 'Max workers must be between 1 and 100'}), 400
            except ValueError:
                return jsonify({'error': 'Max workers must be a number'}), 400

        if 'scan_excluded_ips' in data:
            # Basic validation for IP addresses
            excluded_ips = data['scan_excluded_ips'].strip()
            if excluded_ips:
                # Parse and validate IP addresses
                try:
                    import ipaddress
                    # Split by comma or newline and validate each IP
                    ip_list = [ip.strip() for ip in excluded_ips.replace('\n', ',').split(',') if ip.strip()]
                    for ip in ip_list:
                        ipaddress.ip_address(ip)  # This will raise ValueError if invalid

                    ok, msg = _set('scan_excluded_ips', excluded_ips, 'IP addresses to exclude from network discovery scans')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('scan_excluded_ips')
                except ValueError as e:
                    return jsonify({'error': f'Invalid IP address in exclusion list: {str(e)}'}), 400
            else:
                # Empty value is valid (clears exclusions)
                ok, msg = _set('scan_excluded_ips', '', 'IP addresses to exclude from network discovery scans')
                if not ok:
                    return jsonify({'error': msg}), 400
                updated_fields.append('scan_excluded_ips')

        return jsonify({
            'message': f'Updated {len(updated_fields)} network configuration field(s)',
            'updated_fields': updated_fields,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/alerts', methods=['GET'])
@create_endpoint_limiter('relaxed')
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
            'high_latency_threshold': int(Configuration.get_value('high_latency_threshold_ms', '1000')),
            'discord_enabled': Configuration.get_value('alert_discord_enabled', 'false').lower() == 'true',
            'discord_webhook_url': Configuration.get_value('discord_webhook_url', ''),
        }

        return jsonify(alert_config)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@config_bp.route('/alerts', methods=['PUT'])
@create_endpoint_limiter('strict')
def update_alert_config():
    """Update alert configuration"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        updated_fields = []

        if 'email_enabled' in data:
            ok, msg = _set('alert_email_enabled', str(data['email_enabled']).lower(), 'Enable email alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('email_enabled')

        if 'webhook_enabled' in data:
            ok, msg = _set('alert_webhook_enabled', str(data['webhook_enabled']).lower(), 'Enable webhook alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('webhook_enabled')

        if 'push_enabled' in data:
            ok, msg = _set('push_notifications_enabled', str(data['push_enabled']).lower(), 'Enable push notifications')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('push_enabled')

        if 'ntfy_topic' in data:
            ok, msg = _set('ntfy_topic', data['ntfy_topic'], 'Ntfy topic name')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('ntfy_topic')

        if 'ntfy_server' in data:
            ok, msg = _set('ntfy_server', data['ntfy_server'], 'Ntfy server URL')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('ntfy_server')

        if 'email_from' in data:
            ok, msg = _set('alert_from_email', data['email_from'], 'From email address for alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('email_from')

        if 'email_to' in data:
            ok, msg = _set('alert_to_emails', data['email_to'], 'To email addresses for alerts (comma separated)')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('email_to')

        if 'webhook_url' in data:
            ok, msg = _set('alert_webhook_url', data['webhook_url'], 'Webhook URL for alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('webhook_url')

        if 'discord_enabled' in data:
            ok, msg = _set('alert_discord_enabled', str(data['discord_enabled']).lower(), 'Enable Discord alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('discord_enabled')

        if 'discord_webhook_url' in data:
            ok, msg = _set('discord_webhook_url', data['discord_webhook_url'], 'Discord webhook URL for alerts')
            if not ok:
                return jsonify({'error': msg}), 400
            updated_fields.append('discord_webhook_url')

        if 'device_down_threshold' in data:
            try:
                value = int(data['device_down_threshold'])
                if 1 <= value <= 1440:
                    ok, msg = _set('device_down_threshold_minutes', str(value), 'Minutes before device down alert')
                    if not ok:
                        return jsonify({'error': msg}), 400
                    updated_fields.append('device_down_threshold')
                else:
                    return jsonify({'error': 'Device down threshold must be between 1 and 1440 minutes'}), 400
            except ValueError:
                return jsonify({'error': 'Device down threshold must be a number'}), 400

        if 'high_latency_threshold' in data:
            try:
                value = int(data['high_latency_threshold'])
                if 100 <= value <= 10000:
                    ok, msg = _set('high_latency_threshold_ms', str(value), 'Milliseconds threshold for high latency alert')
                    if not ok:
                        return jsonify({'error': msg}), 400
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


@config_bp.route('/test/email', methods=['POST'])
@create_endpoint_limiter('strict')
def test_email_config():
    """Test email configuration by sending a test email"""
    try:
        from datetime import datetime
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
@create_endpoint_limiter('strict')
def test_webhook_config():
    """Test webhook configuration by sending a test webhook"""
    try:
        from datetime import datetime
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
            'dashboard_url': f"{Config.BASE_URL}",
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
@create_endpoint_limiter('strict')
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

        # Test connectivity first
        connectivity = push_service.test_connectivity()

        response = {
            'connectivity': connectivity,
            'configured': push_service.is_configured(),
            'config': {
                'enabled': push_service.enabled,
                'server': push_service.server,
                'topic': push_service.topic
            }
        }

        if not connectivity.get('reachable', False):
            response.update({
                'success': False,
                'error': f"Cannot reach notification server: {connectivity.get('error', 'Unknown error')}",
                'recommendation': 'Check network connectivity and firewall settings'
            })
            return jsonify(response), 400

        # Send test notification
        success = push_service.send_test_notification()

        if success:
            response.update({
                'success': True,
                'message': 'Test notification sent successfully! Check your mobile device.'
            })
            return jsonify(response)
        else:
            response.update({
                'success': False,
                'error': 'Failed to send test notification despite connectivity test passing.'
            })
            return jsonify(response), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error testing push notifications: {str(e)}'
        }), 500

def _request_service_restart(reason: str):
    """Schedule a restart of this service, if the operator allowed it.

    The old implementation ran `sudo systemctl restart homenetmon`, which (a) can
    never work for the user-level unit this app actually runs as, and (b) let any
    LAN client restart the service. Restarts are now opt-in via
    ALLOW_SERVICE_RESTART=true and use a transient systemd timer so the request
    completes before the unit is torn down. Otherwise the caller gets instructions.
    """
    import os
    import shutil
    import subprocess
    unit = os.environ.get('HOMENETMON_SERVICE_UNIT', 'homenetmon')
    instructions = [
        f'If running as a user service: systemctl --user restart {unit}',
        f'If running as a system service: sudo systemctl restart {unit}',
        'If running manually: stop (Ctrl+C) and start the application again',
    ]
    if os.environ.get('ALLOW_SERVICE_RESTART', 'false').lower() not in ('1', 'true', 'yes'):
        return {'success': True, 'restarted': False, 'method': 'manual',
                'message': f'{reason} Restart HomeNetMon to apply it.', 'instructions': instructions}
    if shutil.which('systemd-run') and shutil.which('systemctl'):
        for scope in (['--user'], []):
            active = subprocess.run(['systemctl', *scope, 'is-active', unit], capture_output=True, text=True,
                                    timeout=5, shell=False)
            if active.returncode == 0:
                subprocess.run(['systemd-run', *scope, '--on-active=2', '--timer-property=AccuracySec=1s',
                                'systemctl', *scope, 'restart', unit], check=True, timeout=10, shell=False)
                return {'success': True, 'restarted': True, 'method': 'systemd',
                        'message': f'{reason} Service restart scheduled in 2 seconds.'}
    return {'success': True, 'restarted': False, 'method': 'manual',
            'message': f'{reason} Could not find a systemd unit to restart.', 'instructions': instructions}


@config_bp.route('/test/discord', methods=['POST'])
@create_endpoint_limiter('strict')
def test_discord_config():
    """Post a test embed to a Discord webhook (URL from the body, else the saved one)."""
    try:
        from datetime import datetime
        data = request.get_json() or {}
        webhook_url = (data.get('discord_webhook_url') or Configuration.get_value('discord_webhook_url', '') or '').strip()
        if not webhook_url:
            return jsonify({'error': 'No Discord webhook URL provided or saved'}), 400

        from monitoring.alerts import AlertManager

        class MockDevice:
            display_name = "Test Device"
            ip_address = "192.168.1.100"
            id = 0

        class MockAlert:
            id = 0
            device = MockDevice()
            alert_type = "test"
            severity = "info"
            title = "Test alert"
            message = "This is a test alert from HomeNetMon"
            created_at = datetime.utcnow()

        if AlertManager(current_app).send_discord_alert(MockAlert(), webhook_url=webhook_url):
            return jsonify({'message': 'Test Discord message sent successfully'})
        return jsonify({'error': 'Discord rejected the test message; check the webhook URL'}), 502

    except Exception as e:
        return jsonify({'error': f'Discord test failed: {str(e)}'}), 500


@config_bp.route('/restart-system', methods=['POST'])
@create_endpoint_limiter('strict')
def restart_system():
    """Restart the HomeNetMon application"""
    try:
        return jsonify(_request_service_restart('Restart requested.'))
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error restarting system: {str(e)}'}), 500


@config_bp.route('/reset-monitoring-data', methods=['POST'])
@create_endpoint_limiter('critical')
def reset_monitoring_data():
    """Reset all historical monitoring data"""
    try:
        from datetime import datetime
        from models import MonitoringData, Device

        data = request.get_json() or {}
        confirm = data.get('confirm', False)

        if not confirm:
            return jsonify({
                'error': 'Please confirm data deletion by sending {"confirm": true}',
                'warning': 'This action will permanently delete all historical ping data and cannot be undone'
            }), 400

        # Count records before deletion
        total_monitoring_records = MonitoringData.query.count()

        # Get time span of data being deleted
        oldest_record = MonitoringData.query.order_by(MonitoringData.timestamp.asc()).first()
        newest_record = MonitoringData.query.order_by(MonitoringData.timestamp.desc()).first()

        time_span_info = None
        if oldest_record and newest_record:
            time_span = newest_record.timestamp - oldest_record.timestamp
            days = time_span.days
            time_span_info = f"{days} days of data (from {oldest_record.timestamp.strftime('%Y-%m-%d')} to {newest_record.timestamp.strftime('%Y-%m-%d')})"

        # Delete all monitoring data
        deleted_count = MonitoringData.query.delete()

        # Reset device last_seen timestamps to current time for fresh start
        # This ensures uptime calculations start fresh
        updated_devices = Device.query.filter_by(is_monitored=True).all()
        current_time = datetime.utcnow()

        for device in updated_devices:
            device.last_seen = current_time

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} monitoring records',
            'details': {
                'total_deleted': deleted_count,
                'time_span': time_span_info,
                'devices_reset': len(updated_devices),
                'reset_time': current_time.isoformat() + 'Z'
            },
            'note': 'Uptime percentages will now start calculating fresh from this point forward'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Error resetting monitoring data: {str(e)}'
        }), 500
