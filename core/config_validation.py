"""
Configuration validation system using Pydantic models.
"""

import os
import logging
from typing import Optional, List, Dict, Any, Union
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, EmailStr, HttpUrl
from pydantic_settings import BaseSettings
import yaml
import json

logger = logging.getLogger(__name__)

class DatabaseSettings(BaseModel):
    """Database configuration settings."""
    
    database_url: Optional[str] = Field(None, env='DATABASE_URL')
    database_path: str = Field('homeNetMon.db', env='DATABASE_PATH')
    pool_size: int = Field(10, ge=1, le=100)
    max_overflow: int = Field(20, ge=0, le=100)
    pool_timeout: int = Field(30, ge=1, le=300)
    pool_recycle: int = Field(3600, ge=300, le=86400)
    echo_sql: bool = Field(False, env='SQL_ECHO')
    
    @field_validator('database_path')
    def validate_database_path(cls, v):
        """Validate database path is writable."""
        if v and not v.startswith(':memory:'):
            path = Path(v)
            parent_dir = path.parent
            if not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    raise ValueError(f"Cannot create database directory {parent_dir}: {e}")
            if not os.access(parent_dir, os.W_OK):
                raise ValueError(f"Database directory {parent_dir} is not writable")
        return v

class MonitoringSettings(BaseModel):
    """Monitoring configuration settings."""
    
    network_range: str = Field('192.168.1.0/24', env='NETWORK_RANGE')
    ping_interval: int = Field(60, ge=5, le=3600, env='PING_INTERVAL')
    ping_timeout: int = Field(1, ge=1, le=60, env='PING_TIMEOUT')
    scan_interval: int = Field(300, ge=60, le=86400, env='SCAN_INTERVAL')
    max_ping_failures: int = Field(3, ge=1, le=10)
    data_retention_days: int = Field(30, ge=1, le=365)
    enable_bandwidth_monitoring: bool = Field(True)
    
    @field_validator('network_range')
    def validate_network_range(cls, v):
        """Validate CIDR network range format."""
        import re
        cidr_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
            r'\/(?:[0-9]|[1-2][0-9]|3[0-2])$'
        )
        if not cidr_pattern.match(v):
            raise ValueError(f"Invalid CIDR network range: {v}")
        return v

class AlertSettings(BaseModel):
    """Alert configuration settings."""
    
    email_enabled: bool = Field(False, env='EMAIL_ALERTS_ENABLED')
    webhook_enabled: bool = Field(False, env='WEBHOOK_ALERTS_ENABLED')
    
    # Email settings
    smtp_server: Optional[str] = Field(None, env='SMTP_SERVER')
    smtp_port: Optional[int] = Field(587, ge=1, le=65535, env='SMTP_PORT')
    smtp_username: Optional[str] = Field(None, env='SMTP_USERNAME')
    smtp_password: Optional[str] = Field(None, env='SMTP_PASSWORD')
    smtp_use_tls: bool = Field(True, env='SMTP_USE_TLS')
    email_from: Optional[EmailStr] = Field(None, env='EMAIL_FROM')
    email_to: List[EmailStr] = Field(default_factory=list)
    
    # Webhook settings
    webhook_url: Optional[HttpUrl] = Field(None, env='WEBHOOK_URL')
    webhook_timeout: int = Field(10, ge=1, le=60)
    webhook_retries: int = Field(3, ge=0, le=10)
    
    # Alert thresholds
    device_down_threshold: int = Field(180, ge=60, le=3600)  # seconds
    slow_response_threshold: int = Field(1000, ge=100, le=10000)  # milliseconds
    
    @validator('email_to', pre=True)
    def parse_email_list(cls, v):
        """Parse email list from string or list."""
        if isinstance(v, str):
            if v:
                return [email.strip() for email in v.split(',')]
            else:
                return []
        return v or []

class SecuritySettings(BaseModel):
    """Security configuration settings."""
    
    jwt_secret_key: str = Field(..., env='JWT_SECRET_KEY', min_length=32)
    jwt_access_token_expires: int = Field(3600, ge=300, le=86400)  # seconds
    jwt_refresh_token_expires: int = Field(604800, ge=3600, le=2592000)  # seconds
    
    admin_password: str = Field('changeme123', env='ADMIN_PASSWORD', min_length=8)
    
    enable_csrf: bool = Field(True, env='ENABLE_CSRF')
    enable_security_headers: bool = Field(True, env='ENABLE_SECURITY_HEADERS')
    enable_rate_limiting: bool = Field(True, env='ENABLE_RATE_LIMITING')
    
    max_login_attempts: int = Field(5, ge=1, le=20)
    lockout_duration: int = Field(900, ge=300, le=3600)  # seconds
    
    allowed_hosts: List[str] = Field(default_factory=list)
    cors_origins: List[str] = Field(default_factory=list)
    
    @validator('jwt_secret_key')
    def validate_jwt_secret(cls, v):
        """Validate JWT secret key strength."""
        if v == 'change-this-secret-key-in-production':
            logger.warning("Using default JWT secret key - change this in production!")
        return v
        
    @validator('admin_password')
    def validate_admin_password(cls, v):
        """Validate admin password strength."""
        if v == 'changeme123':
            logger.warning("Using default admin password - change this immediately!")
        if len(v) < 8:
            raise ValueError("Admin password must be at least 8 characters")
        return v

class PerformanceSettings(BaseModel):
    """Performance configuration settings."""
    
    max_workers: int = Field(15, ge=1, le=100)
    max_threads: int = Field(20, ge=1, le=100)
    max_connections_per_client: int = Field(5, ge=1, le=50)
    
    # Cache settings
    cache_enabled: bool = Field(True)
    cache_max_size: int = Field(50000, ge=1000, le=1000000)
    cache_default_ttl: int = Field(300, ge=10, le=3600)
    
    # Query profiling
    query_profiling_enabled: bool = Field(True)
    slow_query_threshold: float = Field(1.0, ge=0.1, le=10.0)
    
    # WebSocket settings
    websocket_ping_interval: int = Field(10, ge=5, le=60)
    websocket_ping_timeout: int = Field(60, ge=10, le=300)
    websocket_max_message_size: int = Field(1048576, ge=1024, le=10485760)  # 1MB default

class LoggingSettings(BaseModel):
    """Logging configuration settings."""
    
    log_level: str = Field('INFO', env='LOG_LEVEL')
    log_file: Optional[str] = Field(None, env='LOG_FILE')
    enable_structured_logging: bool = Field(True, env='STRUCTURED_LOGGING')
    enable_request_logging: bool = Field(True)
    log_retention_days: int = Field(30, ge=1, le=365)
    max_log_file_size: int = Field(104857600, ge=1048576, le=1073741824)  # 100MB default
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()

class ApplicationSettings(BaseSettings):
    """Main application configuration settings."""
    
    # Basic app settings
    host: str = Field('0.0.0.0', env='HOST')
    port: int = Field(5000, ge=1, le=65535, env='PORT')
    debug: bool = Field(False, env='DEBUG')
    secret_key: str = Field(..., env='SECRET_KEY', min_length=32)
    
    # Component settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    alerts: AlertSettings = Field(default_factory=AlertSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    performance: PerformanceSettings = Field(default_factory=PerformanceSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    
    # Feature flags
    enable_api_docs: bool = Field(True, env='ENABLE_API_DOCS')
    enable_performance_dashboard: bool = Field(True, env='ENABLE_PERFORMANCE_DASHBOARD')
    enable_admin_interface: bool = Field(True, env='ENABLE_ADMIN_INTERFACE')
    
    class Config:
        env_file = ['.env', '.env.local', '.env.production']
        env_file_encoding = 'utf-8'
        env_nested_delimiter = '__'
        case_sensitive = False
        
    @validator('secret_key')
    def validate_secret_key(cls, v):
        """Validate Flask secret key."""
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        return v

class ConfigurationManager:
    """Manager for application configuration with validation and hot-reload."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.settings: Optional[ApplicationSettings] = None
        self._file_mtime = None
        
    def load_config(self, reload: bool = False) -> ApplicationSettings:
        """Load and validate configuration."""
        if self.settings is not None and not reload:
            return self.settings
            
        try:
            # Check if config file exists and is newer
            if self.config_file and Path(self.config_file).exists():
                current_mtime = Path(self.config_file).stat().st_mtime
                if self._file_mtime is None or current_mtime > self._file_mtime:
                    self._file_mtime = current_mtime
                    config_data = self._load_config_file(self.config_file)
                else:
                    config_data = {}
            else:
                config_data = {}
                
            # Load settings with environment variable override
            self.settings = ApplicationSettings(**config_data)
            
            logger.info(f"Configuration loaded successfully from {self.config_file or 'environment'}")
            return self.settings
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ValueError(f"Configuration validation failed: {e}") from e
            
    def _load_config_file(self, file_path: str) -> Dict[str, Any]:
        """Load configuration from file."""
        path = Path(file_path)
        
        if not path.exists():
            return {}
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                elif path.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {path.suffix}")
                    
        except Exception as e:
            logger.error(f"Failed to load config file {file_path}: {e}")
            return {}
            
    def save_config(self, file_path: Optional[str] = None) -> bool:
        """Save current configuration to file."""
        if not self.settings:
            return False
            
        output_file = file_path or self.config_file
        if not output_file:
            return False
            
        try:
            config_dict = self.settings.dict()
            path = Path(output_file)
            
            with open(path, 'w', encoding='utf-8') as f:
                if path.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(config_dict, f, default_flow_style=False)
                elif path.suffix.lower() == '.json':
                    json.dump(config_dict, f, indent=2)
                else:
                    raise ValueError(f"Unsupported config file format: {path.suffix}")
                    
            logger.info(f"Configuration saved to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration to {output_file}: {e}")
            return False
            
    def validate_runtime_config(self) -> Dict[str, Any]:
        """Validate current runtime configuration."""
        if not self.settings:
            return {'valid': False, 'errors': ['Configuration not loaded']}
            
        errors = []
        warnings = []
        
        # Validate database connectivity
        if self.settings.database.database_url:
            # TODO: Test database connection
            pass
        elif self.settings.database.database_path:
            db_path = Path(self.settings.database.database_path)
            if not db_path.parent.exists():
                errors.append(f"Database directory does not exist: {db_path.parent}")
                
        # Validate monitoring network range
        try:
            import ipaddress
            ipaddress.ip_network(self.settings.monitoring.network_range)
        except ValueError as e:
            errors.append(f"Invalid network range: {e}")
            
        # Validate email settings if enabled
        if self.settings.alerts.email_enabled:
            if not self.settings.alerts.smtp_server:
                errors.append("Email alerts enabled but SMTP server not configured")
            if not self.settings.alerts.email_to:
                warnings.append("Email alerts enabled but no recipients configured")
                
        # Validate security settings
        if self.settings.security.admin_password == 'changeme123':
            warnings.append("Default admin password in use - change immediately!")
        if self.settings.security.jwt_secret_key == 'change-this-secret-key-in-production':
            errors.append("Default JWT secret key in use - must be changed!")
            
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'config_file': self.config_file,
            'last_loaded': datetime.now().isoformat() if self.settings else None
        }
        
    def get_flask_config(self) -> Dict[str, Any]:
        """Get Flask-compatible configuration dictionary."""
        if not self.settings:
            raise RuntimeError("Configuration not loaded")
            
        return {
            'SECRET_KEY': self.settings.secret_key,
            'DEBUG': self.settings.debug,
            'SQLALCHEMY_DATABASE_URI': self.settings.database.database_url or f'sqlite:///{self.settings.database.database_path}',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'SQLALCHEMY_ENGINE_OPTIONS': {
                'pool_size': self.settings.database.pool_size,
                'max_overflow': self.settings.database.max_overflow,
                'pool_timeout': self.settings.database.pool_timeout,
                'pool_recycle': self.settings.database.pool_recycle,
                'echo': self.settings.database.echo_sql
            },
            'JWT_SECRET_KEY': self.settings.security.jwt_secret_key,
            'JWT_ACCESS_TOKEN_EXPIRES': self.settings.security.jwt_access_token_expires,
            'JWT_REFRESH_TOKEN_EXPIRES': self.settings.security.jwt_refresh_token_expires,
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024  # 16MB
        }

# Global configuration manager
config_manager = ConfigurationManager()