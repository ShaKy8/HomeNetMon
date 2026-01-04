"""
HomeNetMon Constants
Centralized configuration values and constants
"""

# Application Metadata
APP_NAME = "HomeNetMon"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Comprehensive Home Network Monitoring Solution"

# Network Configuration
DEFAULT_NETWORK_RANGE = "192.168.86.0/24"
DEFAULT_PING_INTERVAL = 30  # seconds
DEFAULT_SCAN_TIMEOUT = 300  # seconds (5 minutes)
MAX_SCAN_TIMEOUT = 600  # seconds (10 minutes)

# Device Status
DEVICE_STATUS_UP = "up"
DEVICE_STATUS_DOWN = "down"
DEVICE_STATUS_WARNING = "warning"
DEVICE_STATUS_UNKNOWN = "unknown"

# Response Time Thresholds (milliseconds)
RESPONSE_TIME_EXCELLENT = 50
RESPONSE_TIME_GOOD = 100
RESPONSE_TIME_ACCEPTABLE = 200
RESPONSE_TIME_POOR = 500

# Data Retention
DEFAULT_DATA_RETENTION_DAYS = 30
MAX_DATA_RETENTION_DAYS = 365
MIN_DATA_RETENTION_DAYS = 7

# Database Configuration
DB_POOL_SIZE = 10
DB_MAX_OVERFLOW = 20
DB_POOL_TIMEOUT = 30  # seconds
DB_POOL_RECYCLE = 3600  # seconds (1 hour)

# Cache Configuration
CACHE_DEFAULT_TIMEOUT = 60  # seconds
CACHE_DEVICE_LIST_TIMEOUT = 30  # seconds
CACHE_QUERY_TIMEOUT = 300  # seconds (5 minutes)
CACHE_RESPONSE_TIMEOUT = 60  # seconds
CACHE_MAX_SIZE = 1000  # maximum number of cached items

# Rate Limiting
RATE_LIMIT_STRICT = "100 per hour"
RATE_LIMIT_MODERATE = "300 per hour"
RATE_LIMIT_RELAXED = "1000 per hour"
RATE_LIMIT_API_DEFAULT = "300 per hour"
RATE_LIMIT_SCAN = "10 per hour"
RATE_LIMIT_LOGIN = "20 per hour"

# Security
CSRF_TOKEN_LIFETIME = 3600  # seconds (1 hour)
CSRF_MAX_TOKENS = 10000
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
SESSION_LIFETIME = 86400  # seconds (24 hours)

# Alert Configuration
ALERT_COOLDOWN_PERIOD = 300  # seconds (5 minutes)
ALERT_MAX_RETRIES = 3
ALERT_RETRY_DELAY = 60  # seconds
ALERT_BATCH_SIZE = 100

# Alert Priorities
ALERT_PRIORITY_CRITICAL = "critical"
ALERT_PRIORITY_HIGH = "high"
ALERT_PRIORITY_MEDIUM = "medium"
ALERT_PRIORITY_LOW = "low"

# Monitoring
MONITOR_THREAD_POOL_SIZE = 10
MONITOR_MAX_CONCURRENT_PINGS = 50
MONITOR_QUEUE_SIZE = 1000
MONITOR_WORKER_TIMEOUT = 30  # seconds

# WebSocket Configuration
WEBSOCKET_PING_INTERVAL = 25  # seconds
WEBSOCKET_PING_TIMEOUT = 60  # seconds
WEBSOCKET_MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB

# API Pagination
API_DEFAULT_PAGE_SIZE = 50
API_MAX_PAGE_SIZE = 1000
API_MIN_PAGE_SIZE = 10

# File Upload
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'csv', 'json', 'yaml', 'yml'}

# Logging
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Performance
PERFORMANCE_SLOW_QUERY_THRESHOLD = 1.0  # seconds
PERFORMANCE_SLOW_REQUEST_THRESHOLD = 2.0  # seconds
PERFORMANCE_METRICS_INTERVAL = 60  # seconds

# UI/UX
UI_REFRESH_INTERVAL = 30000  # milliseconds (30 seconds)
UI_TOAST_DURATION = 5000  # milliseconds (5 seconds)
UI_ANIMATION_DURATION = 300  # milliseconds
UI_DEBOUNCE_DELAY = 500  # milliseconds

# Device Classification Keywords
DEVICE_TYPE_ROUTER = ['router', 'gateway', 'modem']
DEVICE_TYPE_SWITCH = ['switch', 'hub']
DEVICE_TYPE_AP = ['access point', 'ap', 'wifi']
DEVICE_TYPE_CAMERA = ['camera', 'cam', 'ring', 'nest cam']
DEVICE_TYPE_SMART = ['alexa', 'google home', 'smart', 'echo', 'nest']
DEVICE_TYPE_NAS = ['nas', 'storage', 'synology', 'qnap']
DEVICE_TYPE_PRINTER = ['printer', 'print']
DEVICE_TYPE_TV = ['tv', 'roku', 'apple tv', 'chromecast', 'firestick']
DEVICE_TYPE_PHONE = ['iphone', 'android', 'phone', 'mobile']
DEVICE_TYPE_COMPUTER = ['pc', 'laptop', 'desktop', 'mac', 'imac']
DEVICE_TYPE_TABLET = ['ipad', 'tablet']

# HTTP Status Codes (commonly used)
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_METHOD_NOT_ALLOWED = 405
HTTP_CONFLICT = 409
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_SERVICE_UNAVAILABLE = 503

# Error Messages
ERROR_DEVICE_NOT_FOUND = "Device not found"
ERROR_INVALID_IP = "Invalid IP address format"
ERROR_INVALID_NETWORK_RANGE = "Invalid network range"
ERROR_SCAN_IN_PROGRESS = "Network scan already in progress"
ERROR_SCAN_FAILED = "Network scan failed"
ERROR_DATABASE_ERROR = "Database operation failed"
ERROR_INVALID_INPUT = "Invalid input provided"
ERROR_RATE_LIMIT_EXCEEDED = "Rate limit exceeded. Please try again later."
ERROR_CSRF_VALIDATION_FAILED = "CSRF token validation failed"
ERROR_UNAUTHORIZED = "Authentication required"

# Success Messages
SUCCESS_DEVICE_UPDATED = "Device updated successfully"
SUCCESS_DEVICE_DELETED = "Device deleted successfully"
SUCCESS_SCAN_STARTED = "Network scan initiated"
SUCCESS_SCAN_COMPLETED = "Network scan completed"
SUCCESS_SETTINGS_SAVED = "Settings saved successfully"
SUCCESS_ALERT_ACKNOWLEDGED = "Alert acknowledged"
SUCCESS_ALERT_RESOLVED = "Alert resolved"

# Network Scan Phases (for progress tracking)
SCAN_PHASE_INIT = "Initializing scan..."
SCAN_PHASE_ARP = "Scanning ARP table..."
SCAN_PHASE_NMAP = "Running network discovery (nmap)..."
SCAN_PHASE_PROCESSING = "Processing discovered devices..."
SCAN_PHASE_DATABASE = "Updating database..."
SCAN_PHASE_COMPLETE = "Scan completed successfully!"

# Default Email Configuration
DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_TIMEOUT = 30

# Webhook Configuration
WEBHOOK_TIMEOUT = 10  # seconds
WEBHOOK_MAX_RETRIES = 3
WEBHOOK_RETRY_DELAY = 5  # seconds

# Feature Flags (for gradual rollout)
FEATURE_ANOMALY_DETECTION = True
FEATURE_ADVANCED_ANALYTICS = True
FEATURE_WEBHOOKS = True
FEATURE_EMAIL_ALERTS = True
FEATURE_MOBILE_APPS = False  # Future feature
FEATURE_MULTI_NETWORK = False  # Enterprise feature

# System Limits
MAX_DEVICES_PER_NETWORK = 1000
MAX_ALERTS_PER_DEVICE = 100
MAX_MONITORING_DATA_PER_DEVICE = 10000
MAX_CONCURRENT_SCANS = 1

# Chart/Visualization Defaults
CHART_DEFAULT_TIMERANGE = 24  # hours
CHART_MAX_DATA_POINTS = 1000
CHART_COLORS = [
    '#3b82f6',  # Blue
    '#10b981',  # Green
    '#f59e0b',  # Amber
    '#ef4444',  # Red
    '#8b5cf6',  # Purple
    '#06b6d4',  # Cyan
    '#ec4899',  # Pink
    '#6366f1',  # Indigo
]

# Backup/Export
EXPORT_MAX_RECORDS = 100000
BACKUP_RETENTION_DAYS = 90
