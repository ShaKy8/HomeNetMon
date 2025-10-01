"""
Response Cache System for HomeNetMon
Provides intelligent caching of API responses and expensive queries
"""

import json
import time
import hashlib
import threading
from datetime import datetime, timedelta
from collections import OrderedDict
from functools import wraps

class ResponseCache:
    """Thread-safe response cache with TTL and size limits"""

    def __init__(self, max_size=1000, default_ttl=300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def _generate_key(self, *args, **kwargs):
        """Generate cache key from arguments"""
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key):
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    self.hits += 1
                    return value
                else:
                    # Expired
                    del self.cache[key]

            self.misses += 1
            return None

    def set(self, key, value, ttl=None):
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl

        expiry = time.time() + ttl

        with self.lock:
            self.cache[key] = (value, expiry)
            self.cache.move_to_end(key)

            # Evict oldest if over size limit
            while len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def invalidate(self, pattern=None):
        """Invalidate cache entries"""
        with self.lock:
            if pattern is None:
                self.cache.clear()
            else:
                # Remove keys matching pattern
                keys_to_remove = [k for k in self.cache.keys() if pattern in k]
                for key in keys_to_remove:
                    del self.cache[key]

    def get_stats(self):
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            return {
                'size': len(self.cache),
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate
            }

# Global cache instances
_api_cache = ResponseCache(max_size=500, default_ttl=60)  # 1 minute for API responses
_query_cache = ResponseCache(max_size=200, default_ttl=300)  # 5 minutes for queries
_static_cache = ResponseCache(max_size=100, default_ttl=3600)  # 1 hour for static data

def cache_response(cache_type='api', ttl=None, key_func=None):
    """Decorator for caching function responses"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Choose cache
            cache = {
                'api': _api_cache,
                'query': _query_cache,
                'static': _static_cache
            }.get(cache_type, _api_cache)

            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = cache._generate_key(func.__name__, *args, **kwargs)

            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result

        return wrapper
    return decorator

def get_cache_stats():
    """Get statistics for all caches"""
    return {
        'api_cache': _api_cache.get_stats(),
        'query_cache': _query_cache.get_stats(),
        'static_cache': _static_cache.get_stats()
    }

def clear_caches():
    """Clear all caches"""
    _api_cache.invalidate()
    _query_cache.invalidate()
    _static_cache.invalidate()
