"""
Caching layer for expensive database queries and computations.

This module now uses UnifiedCache from services/unified_cache.py as its backend,
providing a single consolidated caching layer across the application.
"""

import logging
import time
import hashlib
from typing import Any, Dict, Optional, Callable, List
from functools import wraps
from threading import Lock

# Use UnifiedCache as the backend for all caching
from services.unified_cache import UnifiedCache, get_cache as get_unified_cache

logger = logging.getLogger(__name__)

class InMemoryCache:
    """
    Cache wrapper that delegates to UnifiedCache.

    This class provides backward compatibility while using the consolidated
    UnifiedCache backend from services/unified_cache.py.
    """

    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        # Use the global unified cache as the backend
        self._backend = get_unified_cache()
        self.lock = Lock()  # Keep for compatibility

    def _generate_key(self, key: Any) -> str:
        """Generate a string key from any hashable object."""
        if isinstance(key, str):
            return key
        elif isinstance(key, (int, float, bool, type(None))):
            return str(key)
        else:
            # Hash complex objects
            key_str = str(key)
            return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: Any) -> Optional[Any]:
        """Get a value from the cache."""
        str_key = self._generate_key(key)
        return self._backend.get(str_key)

    def set(self, key: Any, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache."""
        str_key = self._generate_key(key)
        ttl = ttl if ttl is not None else self.default_ttl
        self._backend.set(str_key, value, ttl)

    def delete(self, key: Any) -> bool:
        """Delete a key from the cache."""
        str_key = self._generate_key(key)
        return self._backend.delete(str_key)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        self._backend.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries - handled automatically by UnifiedCache."""
        # UnifiedCache handles TTL automatically, no manual cleanup needed
        return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = self._backend.get_stats()
        # Add backward-compatible fields
        if 'hit_rate' in stats:
            stats['hit_rate_percent'] = stats['hit_rate']
        return stats

class QueryResultCache:
    """Specialized cache for database query results."""
    
    def __init__(self, cache: InMemoryCache):
        self.cache = cache
        self.query_stats = {}
        
    def cache_query_result(self, query_key: str, result: Any, ttl: int = 300) -> None:
        """Cache a query result."""
        self.cache.set(f"query:{query_key}", result, ttl)
        
        # Track query statistics
        if query_key not in self.query_stats:
            self.query_stats[query_key] = {
                'calls': 0,
                'cache_hits': 0,
                'avg_execution_time': 0
            }
            
    def get_cached_query_result(self, query_key: str) -> Optional[Any]:
        """Get a cached query result."""
        result = self.cache.get(f"query:{query_key}")
        
        # Update statistics
        if query_key in self.query_stats:
            self.query_stats[query_key]['calls'] += 1
            if result is not None:
                self.query_stats[query_key]['cache_hits'] += 1
                
        return result
        
    def invalidate_query_pattern(self, pattern: str) -> int:
        """Invalidate all queries matching a pattern."""
        invalidated = 0
        keys_to_delete = []
        
        with self.cache.lock:
            for key in self.cache.cache.keys():
                if key.startswith(f"query:{pattern}"):
                    keys_to_delete.append(key)
                    
        for key in keys_to_delete:
            if self.cache.delete(key):
                invalidated += 1
                
        return invalidated

def cached(ttl: int = 300, key_func: Optional[Callable] = None, 
          cache_instance: Optional[InMemoryCache] = None):
    """Decorator to cache function results."""
    
    # Use global cache if not provided
    if cache_instance is None:
        # Import here to avoid circular imports
        cache_instance = globals().get('global_cache') or InMemoryCache()
        
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__module__}.{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
                
            # Try to get from cache
            result = cache_instance.get(cache_key)
            if result is not None:
                return result
                
            # Execute function and cache result
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            cache_instance.set(cache_key, result, ttl)
            
            logger.debug(f"Cached result for {func.__name__} (execution: {execution_time:.3f}s)")
            return result
            
        # Add cache management methods to the wrapped function
        wrapper.cache_clear = lambda: cache_instance.clear()
        wrapper.cache_info = lambda: cache_instance.get_stats()
        
        return wrapper
    return decorator

def invalidate_cache_on_change(*table_names: str):
    """Decorator to invalidate cache when specific tables change."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Invalidate related caches
            for table_name in table_names:
                pattern = f"*{table_name}*"
                query_cache.invalidate_query_pattern(pattern)
                
            return result
        return wrapper
    return decorator

# Global cache instances (create these first)
global_cache = InMemoryCache(max_size=50000, default_ttl=300)
query_cache = QueryResultCache(global_cache)

# Application-specific caching functions
class DeviceDataCache:
    """Specialized caching for device-related data."""
    
    def __init__(self, cache: InMemoryCache):
        self.cache = cache
        
    @cached(ttl=60, key_func=lambda self, device_id: f"device_status:{device_id}")
    def get_device_status(self, device_id: int) -> str:
        """Cache device status calculation."""
        from services.device_metrics_service import DeviceMetricsService
        from models import db
        
        metrics_service = DeviceMetricsService(db)
        return metrics_service.calculate_device_status(device_id)
        
    @cached(ttl=300, key_func=lambda self, device_id, days: f"device_uptime:{device_id}:{days}")
    def get_device_uptime(self, device_id: int, days: int = 7) -> float:
        """Cache device uptime calculation."""
        from services.device_metrics_service import DeviceMetricsService
        from models import db
        
        metrics_service = DeviceMetricsService(db)
        return metrics_service.calculate_uptime_percentage(device_id, days)
        
    @cached(ttl=120, key_func=lambda self: "network_summary")
    def get_network_summary(self) -> Dict[str, Any]:
        """Cache network health summary."""
        from services.device_metrics_service import DeviceMetricsService
        from models import db
        
        metrics_service = DeviceMetricsService(db)
        return metrics_service.get_network_health_summary()
        
    def invalidate_device_cache(self, device_id: int) -> None:
        """Invalidate all caches for a specific device."""
        patterns = [
            f"device_status:{device_id}",
            f"device_uptime:{device_id}:",
            "network_summary"
        ]
        
        for pattern in patterns:
            self.cache.delete(pattern)

class AlertDataCache:
    """Specialized caching for alert-related data."""
    
    def __init__(self, cache: InMemoryCache):
        self.cache = cache
        
    @cached(ttl=30, key_func=lambda self: "active_alerts")
    def get_active_alerts_count(self) -> int:
        """Cache active alerts count."""
        from models import Alert
        return Alert.query.filter_by(resolved=False).count()
        
    @cached(ttl=300, key_func=lambda self, device_id: f"device_alerts:{device_id}")
    def get_device_alerts(self, device_id: int) -> List[Dict[str, Any]]:
        """Cache device alerts."""
        from models import Alert
        
        alerts = Alert.query.filter_by(device_id=device_id, resolved=False).all()
        return [{
            'id': alert.id,
            'message': alert.message,
            'severity': alert.severity,
            'created_at': alert.created_at.isoformat()
        } for alert in alerts]

# Initialize remaining cache instances
device_cache = DeviceDataCache(global_cache)
alert_cache = AlertDataCache(global_cache)

def setup_cache_cleanup():
    """Setup periodic cache cleanup."""
    import threading
    
    def cleanup_worker():
        while True:
            time.sleep(300)  # Run every 5 minutes
            expired_count = global_cache.cleanup_expired()
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired cache entries")
                
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logger.info("Cache cleanup worker started")

def get_cache_health() -> Dict[str, Any]:
    """Get overall cache system health."""
    stats = global_cache.get_stats()

    health_status = "healthy"
    issues = []

    # Check hit rate (support both old and new stat formats)
    hit_rate = stats.get('hit_rate_percent', stats.get('hit_rate', 0))
    if hit_rate < 50:
        health_status = "degraded"
        issues.append("Low cache hit rate")

    # Check cache utilization
    size = stats.get('size', 0)
    max_size = stats.get('max_size', 1)  # Avoid division by zero
    utilization = (size / max_size * 100) if max_size > 0 else 0
    if utilization > 90:
        health_status = "degraded"
        issues.append("High cache utilization")

    return {
        'status': health_status,
        'issues': issues,
        'statistics': stats,
        'utilization_percent': round(utilization, 2)
    }