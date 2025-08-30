import os
import yaml
import logging
import logging.handlers
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = Path(__file__).parent.absolute()
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{BASE_DIR}/homeNetMon.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network Configuration
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', '192.168.86.0/24')
    PING_INTERVAL = int(os.environ.get('PING_INTERVAL', '30'))
    SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', '300'))
    BANDWIDTH_INTERVAL = int(os.environ.get('BANDWIDTH_INTERVAL', '60'))
    
    # Monitoring Settings
    PING_TIMEOUT = float(os.environ.get('PING_TIMEOUT', '3.0'))
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '50'))
    DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', '30'))
    
    # Web Interface - Enhanced secret key validation
    SECRET_KEY = None  # Will be set after class definition
    # Default to localhost for security - use HOST env var to bind to 0.0.0.0 if needed
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = int(os.environ.get('PORT', '5000'))
    # Disable debug in production environment
    ENV = os.environ.get('ENV', 'development')
    DEBUG = ENV != 'production' and os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Security validation for host binding
    @staticmethod
    def validate_host_binding():
        """Validate host binding configuration for security"""
        import warnings
        if Config.HOST == '0.0.0.0' and Config.ENV == 'production':
            warnings.warn(
                "WARNING: Binding to 0.0.0.0 in production environment without authentication! "
                "This exposes the service to external networks. Consider using proper authentication "
                "or binding to a specific interface.",
                UserWarning,
                stacklevel=2
            )
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.environ.get('LOG_FILE', 'homeNetMon.log')
    LOG_MAX_SIZE = int(os.environ.get('LOG_MAX_SIZE', '10485760'))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', '5'))
    
    # Alert Settings
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() == 'true'
    ALERT_FROM_EMAIL = os.environ.get('ALERT_FROM_EMAIL')
    ALERT_TO_EMAILS = os.environ.get('ALERT_TO_EMAILS', '').split(',') if os.environ.get('ALERT_TO_EMAILS') else []
    
    # Webhook Settings
    WEBHOOK_URL = os.environ.get('WEBHOOK_URL')
    WEBHOOK_TIMEOUT = int(os.environ.get('WEBHOOK_TIMEOUT', '10'))
    
    # Push Notification Settings (Ntfy)
    NTFY_TOPIC = os.environ.get('NTFY_TOPIC')
    NTFY_SERVER = os.environ.get('NTFY_SERVER', 'https://ntfy.sh')
    NTFY_USERNAME = os.environ.get('NTFY_USERNAME')
    NTFY_PASSWORD = os.environ.get('NTFY_PASSWORD')
    NTFY_ENABLED = os.environ.get('NTFY_ENABLED', 'False').lower() == 'true'
    
    @classmethod
    def load_from_file(cls, config_file='config.yaml'):
        config_path = cls.BASE_DIR / config_file
        if config_path.exists():
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                
            # Update class attributes with YAML data
            for key, value in config_data.items():
                if hasattr(cls, key.upper()):
                    setattr(cls, key.upper(), value)
    
    @classmethod
    def save_to_file(cls, config_file='config.yaml'):
        config_path = cls.BASE_DIR / config_file
        config_data = {
            'network_range': cls.NETWORK_RANGE,
            'ping_interval': cls.PING_INTERVAL,
            'scan_interval': cls.SCAN_INTERVAL,
            'ping_timeout': cls.PING_TIMEOUT,
            'max_workers': cls.MAX_WORKERS,
            'data_retention_days': cls.DATA_RETENTION_DAYS,
            'host': cls.HOST,
            'port': cls.PORT,
            'debug': cls.DEBUG,
            'smtp_server': cls.SMTP_SERVER,
            'smtp_port': cls.SMTP_PORT,
            'smtp_username': cls.SMTP_USERNAME,
            'smtp_use_tls': cls.SMTP_USE_TLS,
            'alert_from_email': cls.ALERT_FROM_EMAIL,
            'alert_to_emails': cls.ALERT_TO_EMAILS,
            'webhook_url': cls.WEBHOOK_URL,
            'webhook_timeout': cls.WEBHOOK_TIMEOUT,
        }
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
    
    @classmethod
    def setup_logging(cls):
        """Configure application logging"""
        # Create logs directory if it doesn't exist
        log_dir = cls.BASE_DIR / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        # Set up root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, cls.LOG_LEVEL))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # File handler with rotation
        log_file_path = log_dir / cls.LOG_FILE
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path, 
            maxBytes=cls.LOG_MAX_SIZE, 
            backupCount=cls.LOG_BACKUP_COUNT
        )
        file_handler.setLevel(getattr(logging, cls.LOG_LEVEL))
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        # Add handlers to root logger
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
        
        # Set levels for specific loggers to reduce noise
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        if not cls.DEBUG:
            logging.getLogger('socketio').setLevel(logging.WARNING)
            logging.getLogger('engineio').setLevel(logging.WARNING)
    
    @classmethod
    def _get_validated_secret_key(cls):
        """Get and validate secret key with security checks."""
        import secrets
        import warnings
        
        secret_key = os.environ.get('SECRET_KEY')
        
        # Check if secret key is provided
        if not secret_key:
            # Check if we're in production (not debug mode)
            is_production = not os.environ.get('DEBUG', 'False').lower() == 'true'
            
            if is_production:
                # Generate a secure random key for production if none provided
                secret_key = secrets.token_urlsafe(32)
                warnings.warn(
                    "WARNING: No SECRET_KEY provided in production. Generated a random key. "
                    "This will cause sessions to be invalidated on restart. "
                    "Please set a permanent SECRET_KEY environment variable.",
                    category=UserWarning
                )
            else:
                # Use development key but warn about it
                secret_key = 'dev-secret-key-change-in-production'
                warnings.warn(
                    "Using default development secret key. "
                    "Set SECRET_KEY environment variable for production.",
                    category=UserWarning
                )
        else:
            # Validate provided secret key
            if len(secret_key) < 32:
                warnings.warn(
                    "SECRET_KEY is shorter than recommended (32+ characters). "
                    "Consider using a longer, more secure key.",
                    category=UserWarning
                )
            
            # Check for common insecure values
            insecure_keys = [
                'dev-secret-key-change-in-production',
                'secret',
                'password',
                'key',
                '123456',
                'secret_key',
                'flask_secret_key'
            ]
            
            if secret_key.lower() in [key.lower() for key in insecure_keys]:
                if not os.environ.get('DEBUG', 'False').lower() == 'true':
                    raise ValueError(
                        "Insecure SECRET_KEY detected in production environment. "
                        "Please use a strong, random secret key."
                    )
                else:
                    warnings.warn(
                        "Insecure SECRET_KEY detected in development. "
                        "Use a strong, random key for production.",
                        category=UserWarning
                    )
        
        return secret_key

# Set SECRET_KEY after class definition to avoid circular reference
Config.SECRET_KEY = Config._get_validated_secret_key()

# Load configuration from file if it exists
Config.load_from_file()