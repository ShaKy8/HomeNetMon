# Session Security Configuration for HomeNetMon

# Add to Flask application configuration
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Session timeout
SESSION_REGENERATE_ON_LOGIN = True  # Prevent session fixation

# Additional security settings
WTF_CSRF_TIME_LIMIT = 3600  # CSRF token timeout
WTF_CSRF_SSL_STRICT = True  # HTTPS only CSRF
