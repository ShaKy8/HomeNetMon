"""
Performance Cache Service for HomeNetMon
Provides intelligent caching for expensive database operations and model properties.
"""
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable
from functools import wraps
import json
import os
import psutil

logger = logging.getLogger(__name__)

class PerformanceCache:
    """High-performance memory cache with intelligent invalidation"""
    
    def __init__(self, default_ttl=300, max_size=10000):
        self.default_ttl = default_ttl  # 5 minutes default
        self.max_size = max_size
        self._cache = {}
        self._access_times = {}
        self._lock = threading.RLock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'invalidations': 0,
            'evictions': 0
        }
        self._cleanup_interval = 60  # Cleanup every minute
        self._last_cleanup = time.time()
        
    def get(self, key: str, default=None):
        """Get value from cache with LRU tracking"""
        with self._lock:
            current_time = time.time()
            
            # Periodic cleanup
            if current_time - self._last_cleanup > self._cleanup_interval:
                self._cleanup_expired()
            
            if key in self._cache:
                entry = self._cache[key]
                
                # Check if expired
                if current_time > entry['expires_at']:
                    del self._cache[key]
                    if key in self._access_times:
                        del self._access_times[key]
                    self._stats['misses'] += 1
                    return default
                
                # Update access time for LRU
                self._access_times[key] = current_time
                self._stats['hits'] += 1
                return entry['value']
            
            self._stats['misses'] += 1
            return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache with optional TTL"""
        with self._lock:
            current_time = time.time()
            ttl = ttl or self.default_ttl
            
            # Enforce max size with LRU eviction
            if len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_lru()
            
            self._cache[key] = {
                'value': value,
                'created_at': current_time,
                'expires_at': current_time + ttl,
                'ttl': ttl
            }
            self._access_times[key] = current_time
    
    def invalidate(self, pattern: str = None, keys: list = None):
        """Invalidate cache entries by pattern or specific keys"""
        with self._lock:
            if keys:
                for key in keys:
                    if key in self._cache:
                        del self._cache[key]
                        self._stats['invalidations'] += 1
                    if key in self._access_times:
                        del self._access_times[key]
            elif pattern:
                keys_to_remove = []
                for key in self._cache.keys():
                    if pattern in key:
                        keys_to_remove.append(key)
                
                for key in keys_to_remove:
                    del self._cache[key]
                    if key in self._access_times:
                        del self._access_times[key]
                    self._stats['invalidations'] += 1
    
    def clear(self):
        """Clear entire cache"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
    
    def get_stats(self):
        """Get cache statistics"""
        with self._lock:
            hit_rate = self._stats['hits'] / (self._stats['hits'] + self._stats['misses']) if (self._stats['hits'] + self._stats['misses']) > 0 else 0
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hit_rate': hit_rate,
                'memory_usage_mb': self._estimate_memory_usage(),
                **self._stats
            }
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = []
        
        for key, entry in self._cache.items():
            if current_time > entry['expires_at']:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
            if key in self._access_times:
                del self._access_times[key]
        
        self._last_cleanup = current_time
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _evict_lru(self):
        """Evict least recently used item"""
        if not self._access_times:
            return
        
        lru_key = min(self._access_times, key=self._access_times.get)
        del self._cache[lru_key]
        del self._access_times[lru_key]
        self._stats['evictions'] += 1
    
    def _estimate_memory_usage(self):
        """Estimate memory usage in MB"""
        try:
            import sys
            total_size = sys.getsizeof(self._cache)
            for key, value in self._cache.items():
                total_size += sys.getsizeof(key) + sys.getsizeof(value)
            return total_size / 1024 / 1024
        except:
            return 0

# Global cache instance
performance_cache = PerformanceCache()

def cached_property(ttl=300, key_func=None, invalidate_on=None):
    """
    Decorator for caching expensive property calculations
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key
        invalidate_on: List of events that should invalidate this cache
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self):
            # Generate cache key
            if key_func:
                cache_key = key_func(self)
            else:
                cache_key = f"{self.__class__.__name__}:{self.id}:{func.__name__}"
            
            # Try to get from cache first
            cached_result = performance_cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Calculate value and cache it
            result = func(self)
            performance_cache.set(cache_key, result, ttl)
            return result
        
        # Return a property that calls the wrapper
        return property(wrapper)
    return decorator

def cached_query(ttl=60, key_func=None):
    """
    Decorator for caching database queries
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key from query parameters
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Create key from function name and arguments
                arg_str = '_'.join(str(arg) for arg in args[1:])  # Skip self
                kwarg_str = '_'.join(f"{k}={v}" for k, v in kwargs.items())
                cache_key = f"query:{func.__name__}:{arg_str}:{kwarg_str}"
            
            # Try cache first
            cached_result = performance_cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute query and cache result
            result = func(*args, **kwargs)
            performance_cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator

class CacheInvalidator:
    """Manages cache invalidation based on database changes"""
    
    def __init__(self):
        self.invalidation_rules = {
            'Device': ['device_*', 'topology_*', 'status_*'],
            'MonitoringData': ['device_*_status', 'device_*_response_time', 'health_*'],
            'PerformanceMetrics': ['device_*_health_score', 'device_*_performance_*'],
            'Alert': ['device_*_active_alerts', 'alert_*']
        }
    
    def invalidate_for_model(self, model_name: str, model_id: int = None):
        """Invalidate cache entries related to a specific model"""
        patterns = self.invalidation_rules.get(model_name, [])
        
        for pattern in patterns:
            if model_id:
                # Replace * with model_id
                actual_pattern = pattern.replace('*', str(model_id))
                performance_cache.invalidate(pattern=actual_pattern)
            else:
                # Invalidate all entries matching the pattern
                performance_cache.invalidate(pattern=pattern)
    
    def invalidate_device_cache(self, device_id: int):
        """Invalidate all cache entries for a specific device"""
        patterns = [
            f"Device:{device_id}:",
            f"device_{device_id}_",
            f"health_{device_id}",
            f"status_{device_id}"
        ]
        
        for pattern in patterns:
            performance_cache.invalidate(pattern=pattern)

# Global invalidator
cache_invalidator = CacheInvalidator()

class ResourceMonitor:
    """Monitor system resources and adjust cache behavior"""
    
    def __init__(self):
        self.memory_threshold = 0.85  # 85% memory usage
        self.cpu_threshold = 0.80     # 80% CPU usage
        
    def get_system_metrics(self):
        """Get current system resource usage"""
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            
            return {
                'memory_percent': memory.percent / 100,
                'memory_available_mb': memory.available / 1024 / 1024,
                'cpu_percent': cpu / 100,
                'cache_stats': performance_cache.get_stats()
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {}
    
    def should_reduce_cache_size(self):
        """Determine if cache size should be reduced due to memory pressure"""
        try:
            memory = psutil.virtual_memory()
            return memory.percent / 100 > self.memory_threshold
        except:
            return False
    
    def adjust_cache_settings(self):
        """Dynamically adjust cache settings based on system resources"""
        if self.should_reduce_cache_size():
            # Reduce cache size under memory pressure
            current_size = len(performance_cache._cache)
            if current_size > 1000:
                # Clear 50% of cache entries (LRU)
                entries_to_remove = current_size // 2
                with performance_cache._lock:
                    sorted_keys = sorted(
                        performance_cache._access_times.items(),
                        key=lambda x: x[1]
                    )
                    
                    for key, _ in sorted_keys[:entries_to_remove]:
                        if key in performance_cache._cache:
                            del performance_cache._cache[key]
                        if key in performance_cache._access_times:
                            del performance_cache._access_times[key]
                
                logger.info(f"Reduced cache size by {entries_to_remove} entries due to memory pressure")

# Global resource monitor
resource_monitor = ResourceMonitor()

def get_cache_performance_metrics():
    """Get comprehensive cache performance metrics"""
    system_metrics = resource_monitor.get_system_metrics()
    cache_stats = performance_cache.get_stats()
    
    return {
        'cache': cache_stats,
        'system': system_metrics,
        'recommendations': _generate_performance_recommendations(system_metrics, cache_stats)
    }

def _generate_performance_recommendations(system_metrics, cache_stats):
    """Generate performance optimization recommendations"""
    recommendations = []
    
    if cache_stats.get('hit_rate', 0) < 0.7:
        recommendations.append({
            'type': 'cache_tuning',
            'message': 'Low cache hit rate detected. Consider increasing TTL for stable data.',
            'severity': 'medium'
        })
    
    if system_metrics.get('memory_percent', 0) > 0.85:
        recommendations.append({
            'type': 'memory_optimization',
            'message': 'High memory usage detected. Cache size will be automatically reduced.',
            'severity': 'high'
        })
    
    if cache_stats.get('size', 0) > cache_stats.get('max_size', 0) * 0.9:
        recommendations.append({
            'type': 'cache_sizing',
            'message': 'Cache is near maximum size. Consider increasing max_size or reducing TTL.',
            'severity': 'low'
        })
    
    return recommendations