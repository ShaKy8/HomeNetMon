import os
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

    # Network Configuration - Home-friendly defaults
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', '192.168.86.0/24')
    PING_INTERVAL = int(os.environ.get('PING_INTERVAL', '600'))      # 10 minutes - gentle for home IoT devices
    SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', '86400'))    # Daily - prevents IoT device instability
    BANDWIDTH_INTERVAL = int(os.environ.get('BANDWIDTH_INTERVAL', '300'))  # 5 minutes - reasonable for home

    # Monitoring Settings
    PING_TIMEOUT = float(os.environ.get('PING_TIMEOUT', '3.0'))
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '50'))
    DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', '30'))
    # Devices not seen for this many days stop being pinged (is_monitored=False)
    # and are hidden from the default dashboard view. They are re-enabled
    # automatically the next time a scan sees their MAC address.
    STALE_DEVICE_DAYS = int(os.environ.get('STALE_DEVICE_DAYS', '30'))
    # Optional dnsmasq / Pi-hole leases file: MAC -> hostname for devices that never answer DNS/mDNS
    DHCP_LEASES_FILE = os.environ.get('DHCP_LEASES_FILE', '')
    # Internet / gateway reachability check (monitoring/wan_monitor.py)
    WAN_CHECK_TARGET = os.environ.get('WAN_CHECK_TARGET', '1.1.1.1')
    WAN_CHECK_INTERVAL = int(os.environ.get('WAN_CHECK_INTERVAL', '60'))
    # nmap security scan cadence (only used when SECURITY_SCANNING_ENABLED=true)
    SECURITY_SCAN_INTERVAL = int(os.environ.get('SECURITY_SCAN_INTERVAL', '86400'))

    # Web Interface - Enhanced secret key validation
    SECRET_KEY = None  # Will be set after class definition
    # Default to localhost for security - use HOST env var to bind to 0.0.0.0 if needed
    HOST = os.environ.get('HOST', '127.0.0.1')

    # Environment must be set before using it
    # ENV is canonical; FLASK_ENV accepted as a fallback because every shipped .env used it.
    ENV = os.environ.get('ENV') or os.environ.get('FLASK_ENV', 'development')

    # Security settings

    # Rate limiting defaults
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = 'memory://'  # Use Redis in production: redis://localhost:6379
    RATELIMIT_DEFAULT = '100 per hour'

    # File upload security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Database connection settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
    }
    if SQLALCHEMY_DATABASE_URI.startswith('sqlite'):
        # SQLite-only driver options; passing them to psycopg2 raises TypeError.
        SQLALCHEMY_ENGINE_OPTIONS['connect_args'] = {'timeout': 20, 'check_same_thread': False}
    PORT = int(os.environ.get('PORT', '5000'))

    @staticmethod
    def _detect_primary_ip():
        """Best-effort LAN address of this host (no packets are sent)."""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('10.255.255.255', 1))
                return s.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return '127.0.0.1'

    # Public URL used in notification links (email, webhook, ntfy, Discord).
    # Set BASE_URL explicitly behind a reverse proxy or when using a hostname;
    # the default is derived from the primary LAN IP because HOST=0.0.0.0 or
    # 127.0.0.1 is useless in a link opened on a phone.
    BASE_URL = (os.environ.get('BASE_URL') or '').rstrip('/')
    # Extra hostnames the Socket.IO origin check accepts (a reverse proxy with its own
    # name). Private IPs, *.local, 100.64.0.0/10 and this node's Tailscale MagicDNS name
    # are accepted without listing them. Comma-separated, case-insensitive.
    ALLOWED_ORIGIN_HOSTS = tuple(
        h.strip().lower() for h in os.environ.get('ALLOWED_ORIGIN_HOSTS', '').split(',') if h.strip()
    )
    # Disable debug in production environment
    DEBUG = ENV != 'production' and os.environ.get('DEBUG', 'False').lower() == 'true'

    # Ensure debug is never enabled in production
    if ENV == 'production' and DEBUG:
        import warnings
        warnings.warn(
            "DEBUG mode is enabled in production! This is a security risk. "
            "Set ENV=production and DEBUG=false for production deployment.",
            UserWarning
        )
        DEBUG = False

    # Security validation for host binding
    @staticmethod
    def validate_host_binding():
        """Validate host binding configuration for security"""
        import warnings
        if Config.HOST == '0.0.0.0' and Config.ENV == 'production':
            warnings.warn(
                "WARNING: Binding to 0.0.0.0 in production environment! "
                "This exposes the service to external networks. Consider binding to a specific interface.",
                UserWarning,
                stacklevel=2
            )

    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.environ.get('LOG_FILE', 'homenetmon.log')
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

    # Printer Protection Settings
    EXCLUDE_PRINTERS_FROM_SECURITY_SCAN = os.environ.get('EXCLUDE_PRINTERS_FROM_SECURITY_SCAN', 'true').lower() == 'true'
    PRINTER_SAFE_MODE = os.environ.get('PRINTER_SAFE_MODE', 'true').lower() == 'true'  # Extra protection for printers

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


if not Config.BASE_URL:
    Config.BASE_URL = f"http://{Config._detect_primary_ip()}:{Config.PORT}"
