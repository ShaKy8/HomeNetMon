"""
Rate Limiting Service for HomeNetMon API endpoints.

This module provides comprehensive rate limiting using Flask-Limiter with Redis backend
for distributed rate limiting and memory-based fallback for single-node deployments.
"""

import os
import logging
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from typing import Optional, Dict, List
from datetime import datetime, timedelta
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    
import json

logger = logging.getLogger(__name__)

class RateLimiterService:
    """
    Comprehensive rate limiting service with multiple backends and configurable limits.
    
    Features:
    - Redis backend for distributed rate limiting
    - Memory backend fallback for single-node deployments
    - Per-IP rate limiting with different limits per endpoint type
    - Administrative bypass for trusted IPs
    - Rate limit monitoring and alerting
    - Custom error responses with retry-after headers
    """
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.limiter = None
        self.redis_client = None
        self.trusted_ips = set()
        self.rate_limit_stats = {}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize the rate limiter with the Flask app."""
        self.app = app
        
        # Configure rate limiting backend
        storage_uri = self._get_storage_uri()
        
        # Configure trusted IPs (admin/localhost access)
        self.trusted_ips = self._get_trusted_ips()
        
        # Initialize Flask-Limiter
        self.limiter = Limiter(
            key_func=self._get_identifier,
            app=app,
            storage_uri=storage_uri,
            default_limits=["1000 per hour", "100 per minute"],
            headers_enabled=True,
            on_breach=self._rate_limit_handler
        )
        
        # Note: Specific endpoint limits will be applied via decorators on route functions
        
        # Initialize Redis client if available
        self._init_redis_client()
        
        # Register error handlers
        app.register_error_handler(429, self._handle_rate_limit_exceeded)
        
        logger.info(f"Rate limiter initialized with backend: {storage_uri}")
        
    def _get_storage_uri(self) -> str:
        """Get the appropriate storage URI for rate limiting backend."""
        # Try Redis first for distributed rate limiting
        redis_url = os.getenv('REDIS_URL')
        if redis_url:
            return redis_url
            
        # Check for Redis connection details
        redis_host = os.getenv('REDIS_HOST', 'localhost')
        redis_port = int(os.getenv('REDIS_PORT', 6379))
        redis_db = int(os.getenv('REDIS_DB', 0))
        redis_password = os.getenv('REDIS_PASSWORD')
        
        if not REDIS_AVAILABLE:
            logger.warning("Redis package not available, using memory backend")
            return "memory://"
        
        try:
            # Test Redis connectivity
            test_client = redis.Redis(
                host=redis_host, 
                port=redis_port, 
                db=redis_db,
                password=redis_password,
                socket_connect_timeout=5
            )
            test_client.ping()
            
            # Build Redis URI
            if redis_password:
                return f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
            else:
                return f"redis://{redis_host}:{redis_port}/{redis_db}"
                
        except (redis.ConnectionError, redis.TimeoutError):
            logger.warning("Redis not available, using memory backend for rate limiting")
            return "memory://"
    
    def _get_trusted_ips(self) -> set:
        """Get list of trusted IP addresses that bypass rate limiting."""
        trusted = {
            '127.0.0.1',  # localhost
            '::1',        # IPv6 localhost
        }
        
        # Add configured trusted IPs
        trusted_config = os.getenv('RATE_LIMIT_TRUSTED_IPS', '')
        if trusted_config:
            trusted.update(ip.strip() for ip in trusted_config.split(','))
        
        return trusted
    
    def _init_redis_client(self):
        """Initialize Redis client for additional rate limiting features."""
        if not REDIS_AVAILABLE:
            self.redis_client = None
            return
            
        try:
            if hasattr(self.limiter.storage, 'storage_uri') and 'redis://' in self.limiter.storage.storage_uri:
                self.redis_client = redis.from_url(self.limiter.storage.storage_uri)
                self.redis_client.ping()
                logger.info("Redis client initialized for advanced rate limiting features")
        except Exception as e:
            logger.warning(f"Could not initialize Redis client: {e}")
            self.redis_client = None
    
    def _get_identifier(self) -> str:
        """
        Get identifier for rate limiting.
        
        Uses IP address by default, but can be extended to use
        API keys, user IDs, etc. for authenticated endpoints.
        """
        # Check if this is a trusted IP
        remote_addr = get_remote_address()
        if remote_addr in self.trusted_ips:
            return f"trusted-{remote_addr}"
        
        # For authenticated requests, could use user ID
        # if hasattr(g, 'user_id'):
        #     return f"user-{g.user_id}"
        
        return remote_addr
    
    def _rate_limit_handler(self, view_func):
        """Handler called when rate limit is exceeded."""
        identifier = self._get_identifier()
        endpoint = request.endpoint or 'unknown'
        
        # Log rate limit breach
        logger.warning(f"Rate limit exceeded for {identifier} on endpoint {endpoint}")
        
        # Track rate limit stats
        self._track_rate_limit_stats(identifier, endpoint)
        
        # Could trigger alerts here for repeated violations
        self._check_for_abuse_patterns(identifier)
    
    def _track_rate_limit_stats(self, identifier: str, endpoint: str):
        """Track rate limiting statistics for monitoring."""
        current_time = datetime.utcnow()
        
        if self.redis_client:
            try:
                # Store in Redis with expiration
                key = f"rate_limit_stats:{current_time.strftime('%Y-%m-%d-%H')}"
                self.redis_client.hincrby(key, f"{identifier}:{endpoint}", 1)
                self.redis_client.expire(key, 7200)  # 2 hours
            except Exception as e:
                logger.error(f"Error tracking rate limit stats: {e}")
        else:
            # Fallback to in-memory tracking
            hour_key = current_time.strftime('%Y-%m-%d-%H')
            if hour_key not in self.rate_limit_stats:
                self.rate_limit_stats[hour_key] = {}
            
            stat_key = f"{identifier}:{endpoint}"
            self.rate_limit_stats[hour_key][stat_key] = \
                self.rate_limit_stats[hour_key].get(stat_key, 0) + 1
    
    def _check_for_abuse_patterns(self, identifier: str):
        """Check for potential abuse patterns and trigger alerts."""
        if identifier.startswith('trusted-'):
            return  # Skip trusted IPs
        
        # Could implement logic to detect:
        # - High frequency of rate limit violations
        # - Attempts across multiple endpoints
        # - Potential DDoS patterns
        
        # For now, just log for monitoring
        logger.info(f"Monitoring potential abuse from {identifier}")
    
    def _handle_rate_limit_exceeded(self, e):
        """Handle 429 Too Many Requests responses."""
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': e.retry_after,
            'timestamp': datetime.utcnow().isoformat()
        }), 429

    # Rate limiting decorators for different endpoint types
    
    def api_strict(self):
        """Strict rate limiting for sensitive API endpoints."""
        return self.limiter.limit("10 per minute, 100 per hour")
    
    def api_moderate(self):
        """Moderate rate limiting for standard API endpoints."""
        return self.limiter.limit("60 per minute, 1000 per hour")
    
    def api_relaxed(self):
        """Relaxed rate limiting for read-heavy endpoints."""
        return self.limiter.limit("120 per minute, 2000 per hour")
    
    def monitoring_data(self):
        """Rate limiting for monitoring data endpoints."""
        return self.limiter.limit("30 per minute, 500 per hour")
    
    def device_control(self):
        """Rate limiting for device control operations."""
        return self.limiter.limit("5 per minute, 50 per hour")
    
    def config_changes(self):
        """Rate limiting for configuration changes."""
        return self.limiter.limit("2 per minute, 20 per hour")
    
    def bulk_operations(self):
        """Rate limiting for bulk operations."""
        return self.limiter.limit("1 per minute, 10 per hour")
    
    def speedtest(self):
        """Rate limiting for speed test operations (resource intensive)."""
        return self.limiter.limit("1 per 5 minutes, 6 per hour")
    
    def security_scan(self):
        """Rate limiting for security scanning operations."""
        return self.limiter.limit("1 per 10 minutes, 3 per hour")
    
    # Utility methods
    
    def get_rate_limit_status(self, identifier: Optional[str] = None) -> Dict:
        """Get current rate limit status for an identifier."""
        if not identifier:
            identifier = self._get_identifier()
        
        try:
            # Get current limits from Flask-Limiter
            limits = {}
            for limit in self.limiter._storage.get_window_stats(identifier):
                limits[limit.key] = {
                    'limit': limit.limit,
                    'remaining': limit.remaining,
                    'reset_time': limit.reset_time
                }
            
            return {
                'identifier': identifier,
                'limits': limits,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting rate limit status: {e}")
            return {'error': str(e)}
    
    def reset_limits(self, identifier: str) -> bool:
        """Reset rate limits for a specific identifier (admin function)."""
        try:
            self.limiter._storage.clear(identifier)
            logger.info(f"Rate limits reset for {identifier}")
            return True
        except Exception as e:
            logger.error(f"Error resetting rate limits for {identifier}: {e}")
            return False
    
    def get_abuse_stats(self, hours: int = 24) -> Dict:
        """Get rate limiting abuse statistics."""
        if not self.redis_client:
            # Return in-memory stats
            return {
                'source': 'memory',
                'stats': self.rate_limit_stats,
                'hours_covered': hours
            }
        
        try:
            stats = {}
            current_time = datetime.utcnow()
            
            for i in range(hours):
                hour_time = current_time - timedelta(hours=i)
                key = f"rate_limit_stats:{hour_time.strftime('%Y-%m-%d-%H')}"
                hour_stats = self.redis_client.hgetall(key)
                
                if hour_stats:
                    # Convert bytes keys/values to strings
                    stats[key] = {
                        k.decode('utf-8'): int(v.decode('utf-8'))
                        for k, v in hour_stats.items()
                    }
            
            return {
                'source': 'redis',
                'stats': stats,
                'hours_covered': hours
            }
            
        except Exception as e:
            logger.error(f"Error getting abuse stats: {e}")
            return {'error': str(e)}

# Global rate limiter instance
rate_limiter = None

def init_rate_limiter(app: Flask) -> RateLimiterService:
    """Initialize the global rate limiter instance."""
    global rate_limiter
    rate_limiter = RateLimiterService(app)
    return rate_limiter

def get_rate_limiter() -> Optional[RateLimiterService]:
    """Get the global rate limiter instance."""
    return rate_limiter