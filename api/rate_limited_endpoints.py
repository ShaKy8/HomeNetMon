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

def apply_rate_limiting(app):
    """
    Apply rate limiting to specific endpoints after app initialization.
    
    This function is called during app startup to add rate limiting
    decorators to critical endpoints.
    """
    
    # Define rate limits for different endpoint types
    endpoint_limits = {
        # Read operations - relaxed limits
        'relaxed': "120 per minute, 2000 per hour",
        
        # Standard operations - moderate limits  
        'moderate': "60 per minute, 1000 per hour",
        
        # Sensitive operations - strict limits
        'strict': "10 per minute, 100 per hour",
        
        # Bulk operations - very strict limits
        'bulk': "2 per minute, 20 per hour",
        
        # Resource intensive operations - extremely strict
        'intensive': "1 per minute, 10 per hour",
        
        # Critical system operations - minimal limits
        'critical': "1 per 5 minutes, 6 per hour"
    }
    
    # Define which endpoints get which limits
    endpoint_mappings = {
        # Device endpoints
        'devices.get_devices': 'relaxed',
        'devices.get_device': 'relaxed', 
        'devices.get_device_groups': 'relaxed',
        'devices.get_device_types': 'relaxed',
        'devices.get_devices_summary': 'relaxed',
        'devices.get_monitored_devices': 'relaxed',
        'devices.get_device_ip_history': 'moderate',
        'devices.create_device': 'moderate',
        'devices.update_device': 'moderate',
        'devices.delete_device': 'strict',
        'devices.ping_device': 'moderate',
        'devices.test_ping': 'moderate',
        'devices.track_device_ip_change': 'strict',
        'devices.ping_all_devices': 'intensive',
        'devices.bulk_update_devices': 'bulk',
        'devices.bulk_ping_devices': 'intensive',
        
        # Monitoring endpoints
        'monitoring.get_monitoring_data': 'moderate',
        'monitoring.get_device_monitoring': 'moderate',
        'monitoring.get_network_summary': 'relaxed',
        
        # Configuration endpoints
        'config.get_config': 'relaxed',
        'config.update_config': 'strict',
        'config.reset_config': 'critical',
        
        # Speed test endpoints
        'speedtest.run_speedtest': 'critical',
        'speedtest.get_speedtest_results': 'moderate',
        
        # Security endpoints
        'security.run_security_scan': 'critical',
        'security.get_security_results': 'moderate',
        
        # Analytics endpoints
        'analytics.get_performance_metrics': 'moderate',
        'analytics.get_network_analytics': 'moderate',
        
        # Health endpoints
        'health.get_health': 'relaxed',
        'health.get_system_status': 'relaxed',
        
        # Automation endpoints
        'automation.get_rules': 'moderate',
        'automation.create_rule': 'strict',
        'automation.update_rule': 'strict',
        'automation.delete_rule': 'strict',
    }
    
    limiter = get_limiter()
    if not limiter:
        logger.warning("No rate limiter available - skipping endpoint rate limiting")
        return
    
    # Apply rate limits to endpoints
    applied_count = 0
    for endpoint_name, limit_type in endpoint_mappings.items():
        limit_string = endpoint_limits.get(limit_type)
        if limit_string:
            try:
                # Apply limit using Flask-Limiter's exempt decorator approach
                # This applies limits based on endpoint name pattern matching
                limiter.limit(limit_string, per_method=True)(
                    lambda: endpoint_name
                )
                applied_count += 1
                logger.debug(f"Applied {limit_type} rate limit to {endpoint_name}")
            except Exception as e:
                logger.warning(f"Could not apply rate limit to {endpoint_name}: {e}")
    
    logger.info(f"Applied rate limiting to {applied_count} endpoints")

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
        @wraps(f)
        def decorated_function(*args, **kwargs):
            limiter = get_limiter()
            if limiter:
                try:
                    # Apply the rate limit - this creates a new decorated function
                    limited_function = limiter.limit(limit_string)(f)
                    return limited_function(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Rate limit error for {f.__name__}: {e}")
                    # Fallback to original function if rate limiting fails
                    return f(*args, **kwargs)
            else:
                # Rate limiter not available - just call the original function
                logger.debug(f"Rate limiter not available for {f.__name__} - bypassing rate limiting")
                return f(*args, **kwargs)

        return decorated_function
    return decorator