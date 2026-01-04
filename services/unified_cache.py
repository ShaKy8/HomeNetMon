"""
Unified Cache Service for HomeNetMon
Consolidates all caching functionality into a single, consistent interface
"""

import time
import hashlib
import pickle
import logging
from typing import Any, Optional, Callable, Dict
from functools import wraps
from threading import Lock
from collections import OrderedDict
from constants import *

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class CacheBackend:
    """Base class for cache backends"""

    def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        raise NotImplementedError

    def clear(self) -> bool:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError


class MemoryCache(CacheBackend):
    """
    In-memory cache with LRU eviction
    Thread-safe implementation for single-server deployments
    """

    def __init__(self, max_size: int = CACHE_MAX_SIZE):
        self.cache = OrderedDict()
        self.ttl_map = {}
        self.max_size = max_size
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            # Check if key exists and is not expired
            if key in self.cache:
                if key in self.ttl_map:
                    if time.time() > self.ttl_map[key]:
                        # Expired, remove it
                        del self.cache[key]
                        del self.ttl_map[key]
                        self.misses += 1
                        return None

                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]

            self.misses += 1
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        with self.lock:
            # Remove oldest if at capacity
            if key not in self.cache and len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                if oldest_key in self.ttl_map:
                    del self.ttl_map[oldest_key]

            self.cache[key] = value
            self.cache.move_to_end(key)

            if ttl:
                self.ttl_map[key] = time.time() + ttl
            elif key in self.ttl_map:
                del self.ttl_map[key]

            return True

    def delete(self, key: str) -> bool:
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.ttl_map:
                    del self.ttl_map[key]
                return True
            return False

    def clear(self) -> bool:
        with self.lock:
            self.cache.clear()
            self.ttl_map.clear()
            self.hits = 0
            self.misses = 0
            return True

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': round(hit_rate, 2),
                'utilization': round(len(self.cache) / self.max_size * 100, 2)
            }


class RedisCache(CacheBackend):
    """
    Redis-based cache for distributed deployments
    Provides persistence and multi-server support
    """

    def __init__(self, redis_url: str = 'redis://localhost:6379/0', prefix: str = 'homenetmon'):
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis not available. Install with: pip install redis")

        self.redis_client = redis.from_url(redis_url, decode_responses=False)
        self.prefix = prefix
        self.default_ttl = CACHE_DEFAULT_TIMEOUT

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.prefix}:{key}"

    def get(self, key: str) -> Optional[Any]:
        try:
            value = self.redis_client.get(self._make_key(key))
            if value:
                return pickle.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        try:
            serialized = pickle.dumps(value)
            ttl = ttl or self.default_ttl
            return self.redis_client.setex(self._make_key(key), ttl, serialized)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    def delete(self, key: str) -> bool:
        try:
            return bool(self.redis_client.delete(self._make_key(key)))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def clear(self) -> bool:
        try:
            # Clear all keys with our prefix
            pattern = f"{self.prefix}:*"
            keys = self.redis_client.keys(pattern)
            if keys:
                self.redis_client.delete(*keys)
            return True
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return False

    def exists(self, key: str) -> bool:
        try:
            return bool(self.redis_client.exists(self._make_key(key)))
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False


class UnifiedCache:
    """
    Unified cache interface that automatically selects the best backend
    Provides consistent API regardless of underlying implementation
    """

    def __init__(self, redis_url: Optional[str] = None, max_memory_size: int = CACHE_MAX_SIZE):
        """
        Initialize unified cache with automatic backend selection

        Args:
            redis_url: Redis connection URL (optional, falls back to memory cache)
            max_memory_size: Maximum size for memory cache
        """
        self.backend = None

        # Try Redis first if URL provided
        if redis_url and REDIS_AVAILABLE:
            try:
                self.backend = RedisCache(redis_url)
                # Test connection
                self.backend.redis_client.ping()
                logger.info("Using Redis cache backend")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}, falling back to memory cache")
                self.backend = None

        # Fall back to memory cache
        if not self.backend:
            self.backend = MemoryCache(max_size=max_memory_size)
            logger.info("Using in-memory cache backend")

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.backend.get(key)

    def set(self, key: str, value: Any, ttl: int = CACHE_DEFAULT_TIMEOUT) -> bool:
        """Set value in cache with optional TTL"""
        return self.backend.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        return self.backend.delete(key)

    def clear(self) -> bool:
        """Clear all cache entries"""
        return self.backend.clear()

    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        return self.backend.exists(key)

    def get_or_set(self, key: str, factory: Callable, ttl: int = CACHE_DEFAULT_TIMEOUT) -> Any:
        """
        Get value from cache, or compute and cache it if missing

        Args:
            key: Cache key
            factory: Function to compute value if not cached
            ttl: Time-to-live in seconds
        """
        value = self.get(key)
        if value is None:
            value = factory()
            self.set(key, value, ttl)
        return value

    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate all keys matching a pattern (memory cache only)

        Args:
            pattern: Key pattern to match (supports * wildcard)

        Returns:
            Number of keys invalidated
        """
        if isinstance(self.backend, MemoryCache):
            import fnmatch
            count = 0
            with self.backend.lock:
                keys_to_delete = [k for k in self.backend.cache.keys() if fnmatch.fnmatch(k, pattern)]
                for key in keys_to_delete:
                    self.backend.delete(key)
                    count += 1
            return count
        elif isinstance(self.backend, RedisCache):
            # For Redis, use SCAN to find and delete matching keys
            try:
                full_pattern = f"{self.backend.prefix}:{pattern}"
                count = 0
                for key in self.backend.redis_client.scan_iter(match=full_pattern):
                    self.backend.redis_client.delete(key)
                    count += 1
                return count
            except Exception as e:
                logger.error(f"Pattern invalidation error: {e}")
                return 0
        return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if isinstance(self.backend, MemoryCache):
            return self.backend.get_stats()
        elif isinstance(self.backend, RedisCache):
            try:
                info = self.backend.redis_client.info('stats')
                return {
                    'backend': 'redis',
                    'hits': info.get('keyspace_hits', 0),
                    'misses': info.get('keyspace_misses', 0),
                }
            except Exception as e:
                logger.error(f"Stats error: {e}")
                return {'backend': 'redis', 'error': str(e)}
        return {}


def cached(ttl: int = CACHE_DEFAULT_TIMEOUT, key_prefix: str = ''):
    """
    Decorator for caching function results

    Args:
        ttl: Time-to-live in seconds
        key_prefix: Prefix for cache keys

    Example:
        @cached(ttl=300, key_prefix='device_list')
        def get_devices():
            return expensive_database_query()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            key_parts = [key_prefix or func.__name__]

            # Add args to key
            if args:
                key_parts.append(hashlib.md5(str(args).encode()).hexdigest()[:8])

            # Add kwargs to key
            if kwargs:
                sorted_kwargs = sorted(kwargs.items())
                key_parts.append(hashlib.md5(str(sorted_kwargs).encode()).hexdigest()[:8])

            cache_key = ':'.join(key_parts)

            # Try to get from cache
            if hasattr(func, '__self__'):
                # Instance method
                cache = getattr(func.__self__, '_cache', None)
            else:
                # Module-level function, use global cache
                cache = _global_cache

            if cache:
                cached_result = cache.get(cache_key)
                if cached_result is not None:
                    return cached_result

            # Compute result
            result = func(*args, **kwargs)

            # Cache result
            if cache:
                cache.set(cache_key, result, ttl)

            return result

        return wrapper
    return decorator


# Global cache instance
_global_cache = UnifiedCache()


def get_cache() -> UnifiedCache:
    """Get the global cache instance"""
    return _global_cache


def init_cache(redis_url: Optional[str] = None, max_memory_size: int = CACHE_MAX_SIZE) -> UnifiedCache:
    """
    Initialize global cache with custom configuration

    Args:
        redis_url: Redis connection URL
        max_memory_size: Maximum size for memory cache

    Returns:
        Configured cache instance
    """
    global _global_cache
    _global_cache = UnifiedCache(redis_url, max_memory_size)
    return _global_cache
