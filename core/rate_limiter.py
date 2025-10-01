"""
Comprehensive Rate Limiting for HomeNetMon
Provides multiple layers of rate limiting for API endpoints, authentication, and WebSocket connections.
"""

import time
import logging
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple
from functools import wraps
from flask import request, jsonify, g, current_app
import threading
from datetime import datetime, timedelta
import ipaddress

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """In-memory rate limiter with sliding window algorithm."""
    
    def __init__(self):
        self._windows = defaultdict(deque)  # key -> deque of timestamps
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, Dict]:
        """Check if request is allowed within rate limit."""
        
        now = time.time()
        
        with self._lock:
            # Cleanup old entries periodically
            if now - self._last_cleanup > 60:  # Every minute
                self._cleanup_old_entries()
                self._last_cleanup = now
            
            # Get or create window for this key
            window = self._windows[key]
            
            # Remove expired entries
            cutoff = now - window_seconds
            while window and window[0] < cutoff:
                window.popleft()
            
            # Check if we're over the limit
            current_count = len(window)
            allowed = current_count < limit
            
            if allowed:
                window.append(now)
            
            # Calculate time until reset
            if window:
                reset_time = window[0] + window_seconds
                retry_after = max(0, reset_time - now) if not allowed else 0
            else:
                retry_after = 0
            
            return allowed, {
                'limit': limit,
                'remaining': max(0, limit - current_count - (1 if allowed else 0)),
                'reset': int(now + retry_after) if retry_after > 0 else int(now + window_seconds),
                'retry_after': int(retry_after) if not allowed else 0
            }
    
    def _cleanup_old_entries(self):
        """Remove expired entries from all windows."""
        now = time.time()
        keys_to_remove = []
        
        for key, window in self._windows.items():
            # Remove entries older than 1 hour (max window we expect)
            cutoff = now - 3600
            while window and window[0] < cutoff:
                window.popleft()
            
            # Remove empty windows
            if not window:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._windows[key]


class GlobalRateLimiter:
    """Global rate limiter with multiple strategies."""
    
    def __init__(self):
        self.limiter = InMemoryRateLimiter()
        
        # Rate limit configurations
        self.limits = {
            # Authentication endpoints (stricter limits)
            'auth_login': (5, 300),     # 5 attempts per 5 minutes per IP
            'auth_failed': (3, 900),    # 3 failed attempts per 15 minutes per IP
            'auth_api': (50, 3600),     # 50 API auth requests per hour per IP
            
            # API endpoints
            'api_general': (100, 3600),   # 100 requests per hour per IP
            'api_device': (200, 3600),    # 200 device requests per hour per IP
            'api_monitoring': (300, 3600), # 300 monitoring requests per hour per IP
            'api_alerts': (50, 3600),     # 50 alert operations per hour per IP
            
            # WebSocket connections
            'websocket_connect': (10, 300),  # 10 connections per 5 minutes per IP
            'websocket_events': (1000, 3600), # 1000 events per hour per IP
            
            # Global limits (across all IPs)
            'global_api': (10000, 3600),     # 10k API requests per hour total
            'global_auth': (1000, 3600),     # 1k auth attempts per hour total
        }
    
    def get_client_key(self, request, category: str) -> str:
        """Generate a unique key for rate limiting."""
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # For authentication, be more strict with key generation
        if category.startswith('auth_'):
            # Include user agent for additional fingerprinting
            user_agent = request.headers.get('User-Agent', 'unknown')[:50]
            return f"{category}:{client_ip}:{hash(user_agent)}"
        
        # For API endpoints, include authenticated user if available
        user_id = getattr(g, 'current_user', {}).get('username', 'anonymous')
        
        return f"{category}:{client_ip}:{user_id}"
    
    def _get_client_ip(self, request) -> str:
        """Get the real client IP address, handling proxies."""
        
        # Check for forwarded headers (be careful with these in production)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP in the chain
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Validate the IP address
        try:
            ipaddress.ip_address(client_ip)
            return client_ip
        except ValueError:
            logger.warning(f"Invalid IP address from headers: {client_ip}")
            return request.remote_addr or '127.0.0.1'
    
    def is_allowed(self, request, category: str) -> Tuple[bool, Dict]:
        """Check if request is allowed."""
        
        if category not in self.limits:
            logger.warning(f"Unknown rate limit category: {category}")
            return True, {}
        
        limit, window = self.limits[category]
        key = self.get_client_key(request, category)
        
        allowed, info = self.limiter.is_allowed(key, limit, window)
        
        if not allowed:
            logger.warning(f"Rate limit exceeded for {key}: {info}")
        
        return allowed, info
    
    def record_failed_auth(self, request):
        """Record a failed authentication attempt."""
        key = self.get_client_key(request, 'auth_failed')
        self.limiter.is_allowed(key, *self.limits['auth_failed'])


# Global rate limiter instance
global_rate_limiter = GlobalRateLimiter()


def rate_limit(category: str = 'api_general'):
    """Decorator for rate limiting endpoints."""
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check rate limit
            allowed, info = global_rate_limiter.is_allowed(request, category)
            
            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Try again in {info.get("retry_after", 0)} seconds.',
                    'rate_limit': {
                        'limit': info.get('limit'),
                        'remaining': info.get('remaining', 0),
                        'reset': info.get('reset'),
                        'retry_after': info.get('retry_after', 0)
                    }
                })
                response.status_code = 429
                
                # Add rate limit headers
                response.headers['X-RateLimit-Limit'] = str(info.get('limit', 0))
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                response.headers['X-RateLimit-Reset'] = str(info.get('reset', 0))
                if info.get('retry_after', 0) > 0:
                    response.headers['Retry-After'] = str(info.get('retry_after', 0))
                
                return response
            
            # Add rate limit headers to successful responses
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(info.get('limit', 0))
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                response.headers['X-RateLimit-Reset'] = str(info.get('reset', 0))
            
            return response
            
        return decorated_function
    return decorator


def apply_global_rate_limiting(app):
    """Apply global rate limiting to the Flask app."""
    
    @app.before_request
    def check_global_rate_limits():
        """Check global rate limits before processing any request."""
        
        # Skip rate limiting for static files and health checks
        if (request.endpoint and 
            (request.endpoint.startswith('static') or 
             request.endpoint == 'health_check' or
             request.path.startswith('/static/') or
             request.path == '/health')):
            return None
        
        # Apply global API rate limiting
        if request.path.startswith('/api/'):
            allowed, info = global_rate_limiter.is_allowed(request, 'global_api')
            if not allowed:
                logger.warning(f"Global API rate limit exceeded from {request.remote_addr}")
                return jsonify({
                    'error': 'Global rate limit exceeded',
                    'message': 'System is under heavy load. Please try again later.',
                    'retry_after': info.get('retry_after', 60)
                }), 503
        
        # Apply global authentication rate limiting
        if request.path in ['/login', '/api/auth/login']:
            allowed, info = global_rate_limiter.is_allowed(request, 'global_auth')
            if not allowed:
                logger.warning(f"Global auth rate limit exceeded from {request.remote_addr}")
                return jsonify({
                    'error': 'Authentication system overloaded',
                    'message': 'Too many authentication attempts. Please try again later.',
                    'retry_after': info.get('retry_after', 300)
                }), 503
        
        return None
    
    logger.info("Global rate limiting enabled")


# Rate limiting decorators for common use cases
auth_rate_limit = rate_limit('auth_login')
api_rate_limit = rate_limit('api_general')
device_rate_limit = rate_limit('api_device')
monitoring_rate_limit = rate_limit('api_monitoring')
websocket_rate_limit = rate_limit('websocket_connect')