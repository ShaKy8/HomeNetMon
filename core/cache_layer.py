"""
Caching layer for expensive database queries and computations.
"""

import logging
import pickle
import json
import time
import hashlib
from typing import Any, Dict, Optional, Callable, Union, Tuple, List
from functools import wraps
from datetime import datetime, timedelta
from threading import Lock
import weakref

logger = logging.getLogger(__name__)

class CacheEntry:
    """Represents a cached entry with metadata."""
    
    def __init__(self, value: Any, ttl: int, created_at: float = None):
        self.value = value
        self.ttl = ttl
        self.created_at = created_at or time.time()
        self.access_count = 0
        self.last_accessed = self.created_at
        
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        if self.ttl <= 0:
            return False  # Never expires
        return time.time() - self.created_at > self.ttl
        
    def touch(self):
        """Update access statistics."""
        self.access_count += 1
        self.last_accessed = time.time()

class InMemoryCache:
    """High-performance in-memory cache with TTL and LRU eviction."""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = Lock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'evictions': 0,
            'expired': 0
        }
        
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
        
        with self.lock:
            if str_key in self.cache:
                entry = self.cache[str_key]
                
                if entry.is_expired():
                    del self.cache[str_key]
                    self.stats['expired'] += 1
                    self.stats['misses'] += 1
                    return None
                    
                entry.touch()
                self.stats['hits'] += 1
                return entry.value
                
            self.stats['misses'] += 1
            return None
            
    def set(self, key: Any, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache."""
        str_key = self._generate_key(key)
        ttl = ttl if ttl is not None else self.default_ttl
        
        with self.lock:
            # Check if we need to evict entries
            if len(self.cache) >= self.max_size and str_key not in self.cache:
                self._evict_lru()
                
            self.cache[str_key] = CacheEntry(value, ttl)
            self.stats['sets'] += 1
            
    def delete(self, key: Any) -> bool:
        """Delete a key from the cache."""
        str_key = self._generate_key(key)
        
        with self.lock:
            if str_key in self.cache:
                del self.cache[str_key]
                self.stats['deletes'] += 1
                return True
            return False
            
    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self.lock:
            self.cache.clear()
            
    def _evict_lru(self) -> None:
        """Evict the least recently used entry."""
        if not self.cache:
            return
            
        # Find LRU entry
        lru_key = min(self.cache.keys(), key=lambda k: self.cache[k].last_accessed)
        del self.cache[lru_key]
        self.stats['evictions'] += 1
        
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count of removed entries."""
        expired_keys = []
        
        with self.lock:
            current_time = time.time()
            for key, entry in self.cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
                    
            for key in expired_keys:
                del self.cache[key]
                
        self.stats['expired'] += len(expired_keys)
        return len(expired_keys)
        
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests else 0
            
            return {
                **self.stats,
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate_percent': round(hit_rate, 2)
            }

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
    
    # Check hit rate
    if stats['hit_rate_percent'] < 50:
        health_status = "degraded"
        issues.append("Low cache hit rate")
        
    # Check cache utilization
    utilization = (stats['size'] / stats['max_size']) * 100
    if utilization > 90:
        health_status = "degraded"
        issues.append("High cache utilization")
        
    # Check eviction rate
    if stats['evictions'] > stats['sets'] * 0.1:
        health_status = "degraded"
        issues.append("High eviction rate")
        
    return {
        'status': health_status,
        'issues': issues,
        'statistics': stats,
        'utilization_percent': round(utilization, 2) if stats['max_size'] > 0 else 0
    }