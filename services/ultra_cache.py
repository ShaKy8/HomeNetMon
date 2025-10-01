"""
Ultra-fast in-memory cache for HomeNetMon
Provides sub-millisecond response times for cached data.
"""

import time
import threading
from typing import Any, Optional, Dict, Tuple
from collections import OrderedDict
import pickle
import hashlib

class UltraFastCache:
    """High-performance in-memory cache with LRU eviction."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 60):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.lock = threading.RLock()
    
    def _make_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_data = pickle.dumps((args, sorted(kwargs.items())))
        return hashlib.md5(key_data).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    self.hits += 1
                    return value
                else:
                    # Expired
                    del self.cache[key]
            
            self.misses += 1
            return None
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        with self.lock:
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            self.cache[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'size': len(self.cache),
                'max_size': self.max_size
            }

# Global cache instances
device_cache = UltraFastCache(max_size=500, ttl=30)
query_cache = UltraFastCache(max_size=1000, ttl=60)
response_cache = UltraFastCache(max_size=2000, ttl=10)

def cached_query(ttl: int = 60):
    """Decorator for caching query results."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            cache_key = query_cache._make_key(func.__name__, *args, **kwargs)
            
            # Try to get from cache
            result = query_cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute query and cache result
            result = func(*args, **kwargs)
            query_cache.set(cache_key, result)
            return result
        
        wrapper.clear_cache = query_cache.clear
        return wrapper
    return decorator
