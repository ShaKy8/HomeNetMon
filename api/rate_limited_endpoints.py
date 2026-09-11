"""
Rate limited API endpoints using Flask-Limiter decorators.

This module applies rate limiting to specific API endpoints by importing
the limiter and applying appropriate limits based on endpoint sensitivity.
"""

from flask import current_app
from functools import wraps
import logging

logger = logging.getLogger(__name__)

def get_limiter():
    """Get the rate limiter instance from current app."""
    try:
        return current_app.rate_limiter.limiter
    except (AttributeError, RuntimeError):
        logger.warning("Rate limiter not available")
        return None

def create_endpoint_limiter(limit_type='moderate'):
    """
    Create a decorator that applies rate limiting to an endpoint.

    Args:
        limit_type: Type of limit (relaxed, moderate, strict, bulk, intensive, critical)
    """
    limits = {
        'relaxed': "120 per minute, 2000 per hour",
        'moderate': "60 per minute, 1000 per hour",
        'strict': "10 per minute, 100 per hour",
        'bulk': "2 per minute, 20 per hour",
        'intensive': "1 per minute, 10 per hour",
        'critical': "1 per 5 minutes, 6 per hour"
    }

    limit_string = limits.get(limit_type, limits['moderate'])

    def decorator(f):
        limited_cache = {}

        @wraps(f)
        def decorated_function(*args, **kwargs):
            limiter = get_limiter()
            if limiter is None:
                logger.debug(f"Rate limiter not available for {f.__name__} - bypassing rate limiting")
                return f(*args, **kwargs)
            # The limiter lives on the app, which does not exist at import time, so the
            # limited view is built lazily -- but exactly once per endpoint, not per request.
            limited = limited_cache.get('fn')
            if limited is None:
                try:
                    limited = limiter.limit(limit_string)(f)
                except Exception as e:
                    logger.error(f"Could not apply rate limit to {f.__name__}: {e}")
                    limited = f
                limited_cache['fn'] = limited
            # No blanket except here: the old wrapper caught flask-limiter's 429
            # (an HTTPException) and fell through to the unlimited view, so no
            # per-endpoint limit was ever enforced.
            return limited(*args, **kwargs)

        decorated_function._rate_limit_tier = limit_type
        return decorated_function
    return decorator
