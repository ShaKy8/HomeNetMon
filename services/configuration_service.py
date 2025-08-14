import logging
import threading
import time
import ipaddress
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from models import db, Configuration, ConfigurationHistory

logger = logging.getLogger(__name__)

@dataclass
class ConfigValidationRule:
    """Represents a configuration validation rule"""
    validator: Callable
    error_message: str
    dependencies: List[str] = None

@dataclass
class ConfigChange:
    """Represents a configuration change event"""
    key: str
    old_value: Any
    new_value: Any
    timestamp: datetime
    user: str = 'system'
    validated: bool = True
    applied: bool = False

class ConfigurationService:
    """Centralized configuration management service with hot-reload, validation, and rollback"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self._stop_event = threading.Event()
        
        # Service registration for configuration change notifications
        self._service_callbacks = {}
        
        # Configuration change tracking
        self._change_history = []
        self._max_history = 100
        
        # Validation rules
        self._validation_rules = {}
        self._setup_validation_rules()
        
        # Configuration backup for rollback
        self._config_backup = {}
        
        # Dependency tracking
        self._config_dependencies = {
            'ping_interval': ['scan_interval'],  # scan_interval should be >= ping_interval
            'network_range': ['ping_interval', 'scan_interval'],  # network changes affect scanning
        }
    
    def _setup_validation_rules(self):
        """Set up configuration validation rules"""
        self._validation_rules = {
            # Network Configuration
            'network_range': ConfigValidationRule(
                validator=self._validate_network_range,
                error_message="Invalid network range format (must be CIDR notation, e.g., 192.168.1.0/24)"
            ),
            'ping_interval': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 5, 900),
                error_message="Ping interval must be between 5 and 900 seconds"
            ),
            'scan_interval': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 60, 3600),
                error_message="Scan interval must be between 60 and 3600 seconds",
                dependencies=['ping_interval']
            ),
            'ping_timeout': ConfigValidationRule(
                validator=lambda v: self._validate_float_range(v, 1.0, 10.0),
                error_message="Ping timeout must be between 1.0 and 10.0 seconds"
            ),
            'bandwidth_interval': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 30, 600),
                error_message="Bandwidth monitoring interval must be between 30 and 600 seconds"
            ),
            'max_workers': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 1, 100),
                error_message="Max workers must be between 1 and 100"
            ),
            
            # Data Management
            'data_retention_days': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 1, 365),
                error_message="Data retention must be between 1 and 365 days"
            ),
            
            # Email Configuration
            'smtp_server': ConfigValidationRule(
                validator=self._validate_smtp_config,
                error_message="SMTP server configuration is invalid"
            ),
            'smtp_port': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 1, 65535),
                error_message="SMTP port must be between 1 and 65535"
            ),
            'smtp_username': ConfigValidationRule(
                validator=self._validate_email_format,
                error_message="SMTP username must be a valid email address"
            ),
            'alert_from_email': ConfigValidationRule(
                validator=self._validate_email_format,
                error_message="From email must be a valid email address"
            ),
            'alert_to_emails': ConfigValidationRule(
                validator=self._validate_email_list,
                error_message="To emails must be a comma-separated list of valid email addresses"
            ),
            
            # Webhook Configuration
            'webhook_url': ConfigValidationRule(
                validator=self._validate_webhook_url,
                error_message="Webhook URL is invalid or unreachable"
            ),
            'webhook_timeout': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 1, 60),
                error_message="Webhook timeout must be between 1 and 60 seconds"
            ),
            
            # Push Notification Configuration
            'ntfy_server': ConfigValidationRule(
                validator=self._validate_ntfy_config,
                error_message="Ntfy server configuration is invalid"
            ),
            'ntfy_topic': ConfigValidationRule(
                validator=self._validate_ntfy_topic,
                error_message="Ntfy topic must be alphanumeric with hyphens/underscores, 3-64 characters"
            ),
            
            # Alert Thresholds
            'device_down_threshold_minutes': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 1, 60),
                error_message="Device down threshold must be between 1 and 60 minutes"
            ),
            'high_latency_threshold_ms': ConfigValidationRule(
                validator=lambda v: self._validate_integer_range(v, 100, 10000),
                error_message="High latency threshold must be between 100 and 10000 milliseconds"
            ),
            
            # Boolean Configuration
            'alert_email_enabled': ConfigValidationRule(
                validator=self._validate_boolean,
                error_message="Must be 'true' or 'false'"
            ),
            'alert_webhook_enabled': ConfigValidationRule(
                validator=self._validate_boolean,
                error_message="Must be 'true' or 'false'"
            ),
            'push_notifications_enabled': ConfigValidationRule(
                validator=self._validate_boolean,
                error_message="Must be 'true' or 'false'"
            ),
            'smtp_use_tls': ConfigValidationRule(
                validator=self._validate_boolean,
                error_message="Must be 'true' or 'false'"
            ),
            'debug': ConfigValidationRule(
                validator=self._validate_boolean,
                error_message="Must be 'true' or 'false'"
            )
        }
    
    def register_service_callback(self, service_name: str, callback: Callable):
        """Register a service callback for configuration changes"""
        self._service_callbacks[service_name] = callback
        logger.info(f"Registered configuration callback for service: {service_name}")
    
    def unregister_service_callback(self, service_name: str):
        """Unregister a service callback"""
        if service_name in self._service_callbacks:
            del self._service_callbacks[service_name]
            logger.info(f"Unregistered configuration callback for service: {service_name}")
    
    def validate_configuration(self, key: str, value: Any, check_dependencies: bool = True) -> tuple[bool, str]:
        """Validate a configuration value"""
        try:
            # Check if we have validation rules for this key
            if key not in self._validation_rules:
                return True, ""
            
            rule = self._validation_rules[key]
            
            # Run the validator
            if not rule.validator(value):
                return False, rule.error_message
            
            # Check dependencies if required
            if check_dependencies and rule.dependencies:
                for dep_key in rule.dependencies:
                    dep_value = self.get_config_value(dep_key)
                    if not self._validate_dependency(key, value, dep_key, dep_value):
                        return False, f"Configuration conflicts with {dep_key}"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Error validating configuration {key}: {e}")
            return False, f"Validation error: {str(e)}"
    
    def _validate_dependency(self, key: str, value: Any, dep_key: str, dep_value: Any) -> bool:
        """Validate configuration dependencies"""
        try:
            if key == 'scan_interval' and dep_key == 'ping_interval':
                # Scan interval should be at least 2x ping interval
                return int(value) >= int(dep_value) * 2
            
            # Add more dependency validations as needed
            return True
            
        except Exception:
            return False
    
    def set_configuration(self, key: str, value: Any, description: str = None, user: str = 'system', validate: bool = True) -> tuple[bool, str]:
        """Set configuration value with validation and change tracking"""
        try:
            if not self.app:
                return False, "No app context available"
            
            with self.app.app_context():
                # Get current value for change tracking
                old_value = Configuration.get_value(key)
                
                # Validate the new value
                if validate:
                    is_valid, error_msg = self.validate_configuration(key, value)
                    if not is_valid:
                        return False, error_msg
                
                # Backup current configuration
                self._backup_configuration(key, old_value)
                
                # Set the new value
                config = Configuration.set_value(key, str(value), description)
                
                # Create change record in database
                ConfigurationHistory.log_change(
                    key=key,
                    old_value=old_value,
                    new_value=str(value),
                    changed_by=user,
                    reason=f"Configuration updated via {user}",
                    validated=validate
                )
                
                # Create change record for in-memory tracking
                change = ConfigChange(
                    key=key,
                    old_value=old_value,
                    new_value=str(value),
                    timestamp=datetime.utcnow(),
                    user=user,
                    validated=validate,
                    applied=True
                )
                
                # Add to change history
                self._add_to_history(change)
                
                # Notify services of the change
                self._notify_services(change)
                
                # Emit WebSocket event if available
                self._emit_config_change_event(change)
                
                logger.info(f"Configuration updated: {key} = {value} (by {user})")
                return True, "Configuration updated successfully"
                
        except Exception as e:
            logger.error(f"Error setting configuration {key}: {e}")
            return False, f"Error updating configuration: {str(e)}"
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value from database"""
        try:
            if self.app:
                with self.app.app_context():
                    return Configuration.get_value(key, default)
            else:
                return Configuration.get_value(key, default)
        except Exception as e:
            logger.error(f"Error getting configuration {key}: {e}")
            return default
    
    def rollback_configuration(self, key: str, target_history_id: int = None) -> tuple[bool, str]:
        """Rollback configuration to previous value or specific history entry"""
        try:
            if not self.app:
                return False, "No app context available"
            
            with self.app.app_context():
                # If specific history ID provided, rollback to that value
                if target_history_id:
                    history_entry = ConfigurationHistory.query.get(target_history_id)
                    if not history_entry or history_entry.config_key != key:
                        return False, f"Invalid history entry for key: {key}"
                    
                    if not history_entry.rollback_available:
                        return False, f"Rollback not available for this history entry"
                    
                    rollback_value = history_entry.old_value
                    reason = f"Rollback to history ID {target_history_id}"
                else:
                    # Find the most recent change for this key
                    recent_history = ConfigurationHistory.query.filter_by(
                        config_key=key
                    ).order_by(ConfigurationHistory.changed_at.desc()).first()
                    
                    if not recent_history:
                        # Fallback to in-memory backup
                        if key not in self._config_backup:
                            return False, f"No backup or history found for configuration key: {key}"
                        rollback_value = self._config_backup[key]
                        reason = "Rollback using in-memory backup"
                    else:
                        if not recent_history.rollback_available:
                            return False, f"Rollback not available for configuration key: {key}"
                        rollback_value = recent_history.old_value
                        reason = f"Rollback to previous value from {recent_history.changed_at}"
                
                # Perform the rollback
                success, message = self.set_configuration(
                    key=key,
                    value=rollback_value,
                    description=f"Rollback of {key}",
                    user='system_rollback',
                    validate=False  # Skip validation for rollback
                )
                
                if success:
                    logger.info(f"Rolled back configuration: {key} = {rollback_value} ({reason})")
                    return True, f"Configuration {key} rolled back successfully"
                else:
                    return False, f"Failed to rollback {key}: {message}"
                
        except Exception as e:
            logger.error(f"Error rolling back configuration {key}: {e}")
            return False, f"Rollback error: {str(e)}"
    
    def get_configuration_history(self, key: str = None, limit: int = 50) -> List[Dict]:
        """Get configuration change history from database"""
        try:
            if not self.app:
                return []
            
            with self.app.app_context():
                query = ConfigurationHistory.query
                
                if key:
                    query = query.filter_by(config_key=key)
                
                history_entries = query.order_by(
                    ConfigurationHistory.changed_at.desc()
                ).limit(limit).all()
                
                return [entry.to_dict() for entry in history_entries]
                
        except Exception as e:
            logger.error(f"Error getting configuration history: {e}")
            # Fallback to in-memory history
            history = self._change_history[-limit:] if limit else self._change_history
            
            if key:
                history = [change for change in history if change.key == key]
            
            return [
                {
                    'key': change.key,
                    'old_value': change.old_value,
                    'new_value': change.new_value,
                    'timestamp': change.timestamp.isoformat(),
                    'user': change.user,
                    'validated': change.validated,
                    'applied': change.applied
                }
                for change in history
            ]
    
    def _backup_configuration(self, key: str, value: Any):
        """Backup current configuration value"""
        self._config_backup[key] = value
    
    def _add_to_history(self, change: ConfigChange):
        """Add change to history"""
        self._change_history.append(change)
        
        # Trim history if it gets too long
        if len(self._change_history) > self._max_history:
            self._change_history = self._change_history[-self._max_history:]
    
    def _notify_services(self, change: ConfigChange):
        """Notify registered services of configuration changes"""
        for service_name, callback in self._service_callbacks.items():
            try:
                callback(change.key, change.old_value, change.new_value)
            except Exception as e:
                logger.error(f"Error notifying service {service_name} of config change: {e}")
    
    def _emit_config_change_event(self, change: ConfigChange):
        """Emit WebSocket event for configuration changes"""
        try:
            if self.app and hasattr(self.app, 'socketio'):
                socketio = self.app.socketio
                socketio.emit('configuration_updated', {
                    'key': change.key,
                    'old_value': change.old_value,
                    'new_value': change.new_value,
                    'timestamp': change.timestamp.isoformat(),
                    'user': change.user,
                    'validated': change.validated
                })
        except Exception as e:
            logger.error(f"Error emitting configuration change event: {e}")
    
    # Validation helper methods
    def _validate_network_range(self, value: str) -> bool:
        """Validate network range in CIDR notation"""
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    
    def _validate_integer_range(self, value: Any, min_val: int, max_val: int) -> bool:
        """Validate integer within range"""
        try:
            int_val = int(value)
            return min_val <= int_val <= max_val
        except (ValueError, TypeError):
            return False
    
    def _validate_float_range(self, value: Any, min_val: float, max_val: float) -> bool:
        """Validate float within range"""
        try:
            float_val = float(value)
            return min_val <= float_val <= max_val
        except (ValueError, TypeError):
            return False
    
    def _validate_smtp_config(self, server: str) -> bool:
        """Validate SMTP server configuration"""
        if not server:
            return True  # Empty is valid (disables SMTP)
        
        try:
            # Basic format validation
            if ':' in server:
                host, port = server.split(':', 1)
                port = int(port)
            else:
                host = server
                port = 587
            
            # Basic connectivity test (with timeout)
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
            
        except Exception:
            return False
    
    def _validate_webhook_url(self, url: str) -> bool:
        """Validate webhook URL"""
        if not url:
            return True  # Empty is valid (disables webhook)
        
        try:
            # Basic URL validation
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Quick connectivity test
            response = requests.head(url, timeout=5)
            return response.status_code < 500
            
        except Exception:
            return False
    
    def _validate_ntfy_config(self, server: str) -> bool:
        """Validate Ntfy server configuration"""
        if not server:
            return True  # Empty is valid
        
        try:
            # Basic URL validation
            from urllib.parse import urlparse
            parsed = urlparse(server)
            return bool(parsed.scheme and parsed.netloc)
            
        except Exception:
            return False
    
    def _validate_email_format(self, email: str) -> bool:
        """Validate email address format"""
        if not email:
            return True  # Empty is valid for optional fields
        
        try:
            import re
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email.strip()))
        except Exception:
            return False
    
    def _validate_email_list(self, emails: str) -> bool:
        """Validate comma-separated list of email addresses"""
        if not emails:
            return True  # Empty is valid
        
        try:
            email_list = [email.strip() for email in emails.split(',')]
            return all(self._validate_email_format(email) for email in email_list if email)
        except Exception:
            return False
    
    def _validate_ntfy_topic(self, topic: str) -> bool:
        """Validate Ntfy topic name"""
        if not topic:
            return True  # Empty is valid
        
        try:
            import re
            # Topic must be 3-64 chars, alphanumeric with hyphens/underscores
            pattern = r'^[a-zA-Z0-9_-]{3,64}$'
            return bool(re.match(pattern, topic))
        except Exception:
            return False
    
    def _validate_boolean(self, value: str) -> bool:
        """Validate boolean configuration value"""
        try:
            return str(value).lower() in ['true', 'false', '1', '0', 'yes', 'no']
        except Exception:
            return False
    
    def start_monitoring(self):
        """Start configuration monitoring service"""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting configuration service")
        
        def monitoring_loop():
            while not self._stop_event.is_set():
                try:
                    # Configuration service runs every 30 seconds
                    self._stop_event.wait(30)
                except Exception as e:
                    logger.error(f"Error in configuration service loop: {e}")
                    time.sleep(60)
        
        monitoring_thread = threading.Thread(
            target=monitoring_loop,
            daemon=True,
            name='ConfigurationService'
        )
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop configuration service"""
        self.running = False
        self._stop_event.set()
        logger.info("Configuration service stopped")

# Global configuration service instance
configuration_service = ConfigurationService()