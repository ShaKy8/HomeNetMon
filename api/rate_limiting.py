"""
Rate limiting decorators for API endpoints.

This module provides easy-to-use decorators that can be applied to Flask routes
to enforce rate limiting based on endpoint type and sensitivity.
"""

from functools import wraps
from flask import current_app
import logging

logger = logging.getLogger(__name__)

def get_rate_limiter():
    """Get the rate limiter from the current app context."""
    try:
        return current_app.rate_limiter
    except (AttributeError, RuntimeError):
        logger.warning("Rate limiter not available in current app context")
        return None

def create_rate_limit_decorator(limit_type):
    """Create a rate limiting decorator for a specific limit type."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Apply rate limiting if available
            limiter = get_rate_limiter()
            if limiter:
                try:
                    # Get the appropriate rate limiting method
                    rate_limit_func = getattr(limiter, limit_type, None)
                    if rate_limit_func:
                        # Apply the rate limit decorator
                        rate_limited_func = rate_limit_func()(f)
                        return rate_limited_func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error applying rate limit {limit_type}: {e}")
            
            # Fall back to calling the original function
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Pre-defined decorators for different endpoint types
api_strict = create_rate_limit_decorator('api_strict')
api_moderate = create_rate_limit_decorator('api_moderate')
api_relaxed = create_rate_limit_decorator('api_relaxed')
monitoring_data = create_rate_limit_decorator('monitoring_data')
device_control = create_rate_limit_decorator('device_control')
config_changes = create_rate_limit_decorator('config_changes')
bulk_operations = create_rate_limit_decorator('bulk_operations')
speedtest = create_rate_limit_decorator('speedtest')
security_scan = create_rate_limit_decorator('security_scan')

def safe_rate_limit(limit_type):
    """
    Safely apply rate limiting with fallback.
    
    This decorator will apply rate limiting if the rate limiter is available,
    but won't break the application if it's not configured.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            limiter = get_rate_limiter()
            if limiter and hasattr(limiter, limit_type):
                try:
                    # Get the rate limiting method and apply it
                    limit_method = getattr(limiter, limit_type)
                    return limit_method()(f)(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error applying rate limit {limit_type}: {e}")
            
            # Execute without rate limiting if not available
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator