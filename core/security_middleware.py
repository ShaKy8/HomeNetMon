import logging
import secrets
import hashlib
import re
import time
from typing import Optional, Set, Dict, Any
from flask import Flask, request, make_response, g, jsonify
from werkzeug.exceptions import BadRequest
import ipaddress

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """Security middleware for Flask applications."""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.csrf_tokens: Dict[str, float] = {}  # token -> expiration_timestamp
        self.csrf_token_lifetime = 3600  # 1 hour lifetime for tokens
        self.csrf_exempt_routes: Set[str] = {
            '/api/health',  # Health check endpoint
            '/api/auth/login',  # Login endpoint needs to work without token
            '/api/csrf-token',  # CSRF token refresh endpoint
            '/api/monitoring/alerts',  # Alerts data endpoint
            '/api/devices/scan',  # Network scan endpoint (temporary for testing)
            '/api/devices/scan-now',  # Alternative scan endpoint to bypass browser cache
            '/login',  # Web login page
            '/test-login',  # Test login route for debugging
            '/favicon.ico',  # Static resources
            '/static/service-worker.js'  # Service worker
        }
        
        # Security configuration
        self.config = {
            'enable_csrf': True,  # ENABLED for production security
            'enable_security_headers': True,
            'enable_input_validation': True,
            'enable_rate_limiting': True,
            'max_content_length': 16 * 1024 * 1024,  # 16MB
            'allowed_hosts': [],  # Empty means all hosts allowed
            'strict_transport_security_max_age': 31536000,  # 1 year
            'content_security_policy': "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.socket.io; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; img-src 'self' data: https:;"
        }
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask):
        """Initialize security middleware with Flask app."""
        self.app = app
        
        # Set maximum content length
        app.config['MAX_CONTENT_LENGTH'] = self.config['max_content_length']
        
        # Register before_request handlers
        app.before_request(self._before_request)
        
        # Register after_request handlers
        app.after_request(self._after_request)
        
        # Register error handlers
        app.errorhandler(400)(self._handle_bad_request)
        app.errorhandler(413)(self._handle_payload_too_large)
        
        logger.info("Security middleware initialized")
        
    def _before_request(self):
        """Run security checks before each request."""

        # Enhanced debug logging for scan endpoints
        if '/api/devices/scan' in request.path:
            print(f"🔍 SCAN DEBUG: Processing scan request")
            print(f"🔍 Method: {request.method}")
            print(f"🔍 Path: {request.path}")
            print(f"🔍 Endpoint: {request.endpoint}")
            print(f"🔍 Headers: {dict(request.headers)}")
            print(f"🔍 Content-Type: {request.content_type}")
            print(f"🔍 Content-Length: {request.content_length}")
            print(f"🔍 Has JSON: {request.is_json}")

        # Enhanced debug logging for alerts API
        if '/api/monitoring/alerts' in request.path:
            print(f"🔍 SECURITY DEBUG: Processing alerts request")
            print(f"🔍 Method: {request.method}")
            print(f"🔍 Path: {request.path}")
            print(f"🔍 Endpoint: {request.endpoint}")
            print(f"🔍 Query args: {dict(request.args)}")
            print(f"🔍 Headers: {dict(request.headers)}")
            print(f"🔍 User agent: {request.headers.get('User-Agent', 'None')}")

        # Check host header
        if self.config['allowed_hosts'] and request.host not in self.config['allowed_hosts']:
            logger.warning(f"Invalid host header: {request.host}")
            if '/api/monitoring/alerts' in request.path:
                print(f"🔍 SECURITY DEBUG: FAILED - Invalid host header: {request.host}")
            return jsonify({'error': 'Invalid host header'}), 400

        # Validate content type for POST/PUT/PATCH requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.content_type
            if '/api/devices/scan' in request.path:
                print(f"🔍 SCAN DEBUG: Checking content type: {content_type}")
                print(f"🔍 SCAN DEBUG: Is safe content type: {self._is_safe_content_type(content_type) if content_type else 'No content type'}")
            if content_type and not self._is_safe_content_type(content_type):
                logger.warning(f"Unsafe content type: {content_type}")
                if '/api/monitoring/alerts' in request.path:
                    print(f"🔍 SECURITY DEBUG: FAILED - Unsafe content type: {content_type}")
                if '/api/devices/scan' in request.path:
                    print(f"🔍 SCAN DEBUG: FAILED - Unsafe content type: {content_type}")
                return jsonify({'error': 'Unsupported content type'}), 400

        # CSRF protection
        if self.config['enable_csrf'] and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if '/api/devices/scan' in request.path:
                print(f"🔍 SCAN DEBUG: Checking CSRF token...")
            if not self._verify_csrf_token():
                logger.warning("CSRF token verification failed")
                if '/api/monitoring/alerts' in request.path:
                    print(f"🔍 SECURITY DEBUG: FAILED - CSRF token validation failed")
                if '/api/devices/scan' in request.path:
                    print(f"🔍 SCAN DEBUG: FAILED - CSRF token validation failed")
                return jsonify({'error': 'CSRF token validation failed'}), 403
            elif '/api/devices/scan' in request.path:
                print(f"🔍 SCAN DEBUG: CSRF token validation PASSED")

        # Input validation
        if self.config['enable_input_validation']:
            if '/api/monitoring/alerts' in request.path:
                print(f"🔍 SECURITY DEBUG: Running input validation...")
            if '/api/devices/scan' in request.path:
                print(f"🔍 SCAN DEBUG: Running input validation...")
            validation_error = self._validate_input()
            if validation_error:
                if '/api/monitoring/alerts' in request.path:
                    print(f"🔍 SECURITY DEBUG: FAILED - Input validation error: {validation_error}")
                if '/api/devices/scan' in request.path:
                    print(f"🔍 SCAN DEBUG: FAILED - Input validation error: {validation_error}")
                return validation_error
            elif '/api/devices/scan' in request.path:
                print(f"🔍 SCAN DEBUG: Input validation PASSED")

        if '/api/monitoring/alerts' in request.path:
            print(f"🔍 SECURITY DEBUG: All security checks PASSED")
        if '/api/devices/scan' in request.path:
            print(f"🔍 SCAN DEBUG: All security checks PASSED")
                
    def _after_request(self, response):
        """Add security headers to response."""
        if self.config['enable_security_headers']:
            # HSTS (HTTP Strict Transport Security)
            response.headers['Strict-Transport-Security'] = f"max-age={self.config['strict_transport_security_max_age']}; includeSubDomains"
            
            # X-Content-Type-Options
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # X-Frame-Options
            response.headers['X-Frame-Options'] = 'DENY'
            
            # X-XSS-Protection
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Content-Security-Policy
            response.headers['Content-Security-Policy'] = self.config['content_security_policy']
            
            # Referrer-Policy
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Permissions-Policy
            response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
            
            # Generate CSRF token for GET requests
            if self.config['enable_csrf'] and request.method == 'GET':
                csrf_token = self._generate_csrf_token()
                response.set_cookie('csrf_token', csrf_token, secure=False, httponly=False, samesite='Strict')
                
        return response
        
    def _is_safe_content_type(self, content_type: str) -> bool:
        """Check if content type is safe."""
        safe_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'text/html'
        ]
        
        for safe_type in safe_types:
            if content_type.startswith(safe_type):
                return True
        return False
        
    def _generate_csrf_token(self) -> str:
        """Generate a new CSRF token with expiration."""
        token = secrets.token_urlsafe(32)
        expiration_time = time.time() + self.csrf_token_lifetime
        self.csrf_tokens[token] = expiration_time

        # Clean up expired tokens periodically
        self._cleanup_expired_tokens()

        # Limit token storage to prevent memory issues
        if len(self.csrf_tokens) > 10000:
            # Keep only the most recent 5000 tokens
            sorted_tokens = sorted(self.csrf_tokens.items(), key=lambda x: x[1])
            self.csrf_tokens = dict(sorted_tokens[-5000:])

        return token

    def _cleanup_expired_tokens(self):
        """Remove expired CSRF tokens."""
        current_time = time.time()
        expired_tokens = [token for token, expiration in self.csrf_tokens.items()
                         if expiration < current_time]
        for token in expired_tokens:
            del self.csrf_tokens[token]

    def _verify_csrf_token(self) -> bool:
        """Verify CSRF token from request."""
        # Skip CSRF check for exempt routes
        if request.endpoint in self.csrf_exempt_routes or request.path in self.csrf_exempt_routes:
            return True

        # Special handling for alerts endpoints that include alert IDs in the path
        if request.path.startswith('/api/monitoring/alerts'):
            return True

        # Get token from header or form data
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')

        if not token:
            # Try to get from cookies
            token = request.cookies.get('csrf_token')

        if token and token in self.csrf_tokens:
            # Check if token is still valid (not expired)
            current_time = time.time()
            expiration_time = self.csrf_tokens[token]

            if expiration_time > current_time:
                return True
            else:
                # Token expired, remove it
                del self.csrf_tokens[token]
                return False

        return False
        
    def _validate_input(self) -> Optional[tuple]:
        """Validate request input for common security issues."""

        # Debug logging for alerts API
        is_alerts_request = '/api/monitoring/alerts' in request.path

        # Validate query parameters
        for key, value in request.args.items():
            if is_alerts_request:
                print(f"🔍 SECURITY DEBUG: Checking query param '{key}' = '{value}'")
            if self._contains_malicious_pattern(str(value)):
                logger.warning(f"Malicious pattern detected in query parameter: {key}")
                if is_alerts_request:
                    print(f"🔍 SECURITY DEBUG: MALICIOUS PATTERN in query param '{key}' = '{value}'")
                    # Show which pattern matched
                    self._debug_malicious_pattern(str(value))
                return jsonify({'error': f'Invalid input in parameter: {key}'}), 400

        # Validate form data
        if request.form:
            for key, value in request.form.items():
                if is_alerts_request:
                    print(f"🔍 SECURITY DEBUG: Checking form field '{key}' = '{value}'")
                if self._contains_malicious_pattern(str(value)):
                    logger.warning(f"Malicious pattern detected in form field: {key}")
                    if is_alerts_request:
                        print(f"🔍 SECURITY DEBUG: MALICIOUS PATTERN in form field '{key}' = '{value}'")
                        self._debug_malicious_pattern(str(value))
                    return jsonify({'error': f'Invalid input in field: {key}'}), 400

        # Validate JSON data
        if request.is_json:
            if is_alerts_request:
                print(f"🔍 SECURITY DEBUG: Checking JSON data...")
            # Use silent=True to avoid exceptions for empty/invalid JSON bodies
            json_data = request.get_json(silent=True)
            # Only validate if there's actual JSON data (DELETE requests with JSON content type might have None data)
            if json_data is not None:
                validation_error = self._validate_json_data(json_data)
                if validation_error:
                    if is_alerts_request:
                        print(f"🔍 SECURITY DEBUG: MALICIOUS PATTERN in JSON: {validation_error}")
                    return jsonify({'error': validation_error}), 400
            elif is_alerts_request:
                print(f"🔍 SECURITY DEBUG: JSON content type but no JSON data (e.g., DELETE request) - skipping validation")

        if is_alerts_request:
            print(f"🔍 SECURITY DEBUG: Input validation completed - no issues found")
        return None
        
    def _contains_malicious_pattern(self, value: str) -> bool:
        """Check if value contains potentially malicious patterns."""
        # SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b\s*\d+\s*=\s*\d+)",
            r"(\bAND\b\s*\d+\s*=\s*\d+)"
        ]
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>"
        ]
        
        # Command injection patterns
        cmd_patterns = [
            r"[;&|`$()]",
            r"\.\./",
            r"/etc/passwd",
            r"/bin/sh"
        ]
        
        all_patterns = sql_patterns + xss_patterns + cmd_patterns
        
        for pattern in all_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
                
        return False

    def _debug_malicious_pattern(self, value: str):
        """Debug method to identify which pattern matched."""
        # SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b\s*\d+\s*=\s*\d+)",
            r"(\bAND\b\s*\d+\s*=\s*\d+)"
        ]

        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>"
        ]

        # Command injection patterns
        cmd_patterns = [
            r"[;&|`$()]",
            r"\.\./",
            r"/etc/passwd",
            r"/bin/sh"
        ]

        pattern_categories = [
            ("SQL", sql_patterns),
            ("XSS", xss_patterns),
            ("CMD", cmd_patterns)
        ]

        for category, patterns in pattern_categories:
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    print(f"🔍 SECURITY DEBUG: MATCHED {category} PATTERN: '{pattern}' in value: '{value}'")
                    return

    def _validate_json_data(self, data: Any, depth: int = 0) -> Optional[str]:
        """Recursively validate JSON data."""
        if depth > 10:  # Prevent deep recursion
            return "JSON structure too deep"
            
        if isinstance(data, dict):
            for key, value in data.items():
                if self._contains_malicious_pattern(str(key)):
                    return f"Invalid key: {key}"
                error = self._validate_json_data(value, depth + 1)
                if error:
                    return error
                    
        elif isinstance(data, list):
            for item in data:
                error = self._validate_json_data(item, depth + 1)
                if error:
                    return error
                    
        elif isinstance(data, str):
            if self._contains_malicious_pattern(data):
                return "Invalid string value detected"
                
        return None
        
    def _handle_bad_request(self, error):
        """Handle bad request errors."""
        logger.warning(f"Bad request: {error}")
        return jsonify({'error': 'Bad request'}), 400
        
    def _handle_payload_too_large(self, error):
        """Handle payload too large errors."""
        logger.warning(f"Payload too large: {error}")
        return jsonify({'error': 'Request payload too large'}), 413
        
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def validate_hostname(self, hostname: str) -> bool:
        """Validate hostname format."""
        if len(hostname) > 255:
            return False
            
        # Hostname regex pattern
        pattern = r"^(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)*[a-zA-Z0-9-]{1,63}(?<!-)$"
        return bool(re.match(pattern, hostname))
        
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent directory traversal."""
        # Remove path separators and null bytes
        filename = filename.replace('/', '').replace('\\', '').replace('\x00', '')
        
        # Remove leading dots
        while filename.startswith('.'):
            filename = filename[1:]
            
        # Limit filename length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + '.' + ext if ext else name[:255]
            
        return filename or 'unnamed'
        
    def add_csrf_exempt(self, route: str):
        """Add a route to CSRF exemption list."""
        self.csrf_exempt_routes.add(route)
        logger.debug(f"Added CSRF exemption for route: {route}")
        
    def remove_csrf_exempt(self, route: str):
        """Remove a route from CSRF exemption list."""
        self.csrf_exempt_routes.discard(route)
        logger.debug(f"Removed CSRF exemption for route: {route}")