import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from typing import Set
from flask import Flask, request, make_response, g, jsonify
import ipaddress

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """Security middleware for Flask applications."""

    def __init__(self, app: Flask = None):
        self.app = app
        # CSRF tokens are stateless: nonce.timestamp.HMAC(SECRET_KEY). No server-side
        # store (the old global dict raced across request threads and was lost on
        # restart) and the token is accepted ONLY from the X-CSRF-Token header or a
        # csrf_token form field -- never from the cookie, which the browser sends
        # automatically and therefore proves nothing.
        self.csrf_token_lifetime = 3600  # seconds
        self.csrf_exempt_routes: Set[str] = {
            '/api/csrf-token',   # token endpoint itself (GET)
            '/api/system/health',
            '/health', '/ready', '/live',
            '/favicon.ico',
        }

        # Security configuration
        self.config = {
            'enable_csrf': True,  # ENABLED for production security
            'enable_security_headers': True,
            # The former request-wide "malicious pattern" filter is gone: it rejected
            # legitimate input (device names with parentheses, JSON containing the word
            # "update", hex colours) and protected nothing -- all SQL is parameterised
            # and no shell is ever invoked with user input.
            'enable_input_validation': False,
            'enable_rate_limiting': True,
            'max_content_length': 16 * 1024 * 1024,  # 16MB
            'allowed_hosts': [],  # Empty means all hosts allowed
            'strict_transport_security_max_age': 31536000,  # 1 year
            # CSP is tuned conservatively for this LAN dashboard:
            # - 'unsafe-inline' kept on script-src because templates still
            #   include page-specific inline <script> blocks. Worth removing
            #   in a future sweep if a stored-XSS vector ever appears.
            # - 'unsafe-eval' DROPPED — no eval()/Function()/setTimeout("string")
            #   in our code. Shrinks XSS blast radius.
            # - object-src 'none', base-uri 'self', frame-ancestors 'none'
            #   added as defense in depth (block Flash/PDF embeds, <base href>
            #   injection, and clickjacking).
            'content_security_policy': (
                "default-src 'self' https:; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.socket.io; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "font-src 'self' https://cdn.jsdelivr.net data:; "
                "img-src 'self' data: https:; "
                "connect-src 'self' ws: wss:; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none';"
            )
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

        # Debug logging for sensitive endpoints
        if '/api/devices/scan' in request.path or '/api/monitoring/alerts' in request.path:
            logger.debug(f"Security check: {request.method} {request.path}")

        # Check host header
        if self.config['allowed_hosts'] and request.host not in self.config['allowed_hosts']:
            logger.warning(f"Invalid host header: {request.host}")
            return jsonify({'error': 'Invalid host header'}), 400

        # Validate content type for POST/PUT/PATCH requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.content_type
            if content_type and not self._is_safe_content_type(content_type):
                logger.warning(f"Unsafe content type: {content_type}")
                return jsonify({'error': 'Unsupported content type'}), 400

        # CSRF protection
        if self.config['enable_csrf'] and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if not self._verify_csrf_token():
                logger.warning("CSRF token verification failed")
                return jsonify({'error': 'CSRF token validation failed'}), 403

        logger.debug(f"Security checks passed for {request.path}")

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
                # Use environment variable to determine HTTPS mode, default to False for development
                https_enabled = os.environ.get('HTTPS_ENABLED', 'false').lower() in ('true', '1', 'yes')
                response.set_cookie(
                    'csrf_token',
                    csrf_token,
                    secure=https_enabled,
                    httponly=True,
                    samesite='Strict'
                )

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

    def _csrf_secret(self) -> bytes:
        secret = (self.app.config.get('SECRET_KEY') if self.app else None) or os.environ.get('SECRET_KEY', '')
        return str(secret).encode()

    def _sign(self, nonce: str, issued: int) -> str:
        return hmac.new(self._csrf_secret(), f"{nonce}:{issued}".encode(), hashlib.sha256).hexdigest()[:40]

    def _generate_csrf_token(self) -> str:
        """Issue a stateless token: <nonce>.<issued-unix-ts>.<hmac>."""
        nonce = secrets.token_urlsafe(16)
        issued = int(time.time())
        return f"{nonce}.{issued}.{self._sign(nonce, issued)}"

    def _token_is_valid(self, token: str) -> bool:
        try:
            nonce, issued_s, sig = token.split('.')
            issued = int(issued_s)
        except (ValueError, AttributeError):
            return False
        if not (0 <= time.time() - issued <= self.csrf_token_lifetime):
            return False
        return hmac.compare_digest(sig, self._sign(nonce, issued))

    def _verify_csrf_token(self) -> bool:
        """Verify the CSRF token supplied in the request header or form body."""
        if request.endpoint in self.csrf_exempt_routes or request.path in self.csrf_exempt_routes:
            return True
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        return bool(token) and self._token_is_valid(token)

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
