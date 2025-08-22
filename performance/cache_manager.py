# HomeNetMon High-Performance Cache Management System
from flask import Flask, current_app, g
import redis
import pickle
import json
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from functools import wraps, lru_cache
import threading
from collections import defaultdict, OrderedDict
from enum import Enum
import asyncio
import concurrent.futures
from dataclasses import dataclass
import zlib

logger = logging.getLogger(__name__)

class CacheLevel(Enum):
    """Cache levels for different performance requirements"""
    L1_MEMORY = "l1_memory"      # In-memory cache (fastest)
    L2_REDIS = "l2_redis"        # Redis cache (fast, distributed)
    L3_DATABASE = "l3_database"  # Database cache tables (persistent)

class CacheStrategy(Enum):
    """Cache invalidation strategies"""
    TIME_BASED = "time_based"           # TTL-based expiration
    EVENT_BASED = "event_based"         # Event-driven invalidation
    LRU = "lru"                        # Least Recently Used
    LFU = "lfu"                        # Least Frequently Used
    WRITE_THROUGH = "write_through"     # Write to cache and storage
    WRITE_BACK = "write_back"          # Write to cache, storage later

@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    writes: int = 0
    deletes: int = 0
    total_requests: int = 0
    average_response_time: float = 0.0
    hit_rate: float = 0.0
    memory_usage: int = 0

class MultiLevelCache:
    """Multi-level caching system for optimal performance"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.redis_client = None
        self.l1_cache = {}  # In-memory cache
        self.l1_access_times = {}  # LRU tracking
        self.l1_access_counts = {}  # LFU tracking
        self.cache_metrics = defaultdict(CacheMetrics)
        self.compression_enabled = True
        self.max_l1_size = 1000  # Maximum L1 cache entries
        self.lock = threading.RLock()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize cache manager with Flask app"""
        self.app = app
        
        # Initialize Redis connection
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=False)
            self.redis_client.ping()
            logger.info("Redis cache initialized successfully")
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
        
        # Set configuration
        self.max_l1_size = app.config.get('CACHE_L1_MAX_SIZE', 1000)
        self.compression_enabled = app.config.get('CACHE_COMPRESSION', True)
        
        logger.info("MultiLevelCache initialized")
    
    def _generate_key(self, key: str, tenant_id: str = None) -> str:
        """Generate cache key with tenant isolation"""
        if tenant_id:
            return f"tenant:{tenant_id}:{key}"
        return f"global:{key}"
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for storage"""
        serialized = pickle.dumps(value)
        
        if self.compression_enabled and len(serialized) > 1024:
            serialized = zlib.compress(serialized)
            return b'compressed:' + serialized
        
        return serialized
    
    def _deserialize_value(self, data: bytes) -> Any:
        """Deserialize value from storage"""
        if data.startswith(b'compressed:'):
            data = zlib.decompress(data[11:])
        
        return pickle.loads(data)
    
    def get(self, key: str, tenant_id: str = None, default: Any = None) -> Any:
        """Get value from multi-level cache"""
        cache_key = self._generate_key(key, tenant_id)
        start_time = time.time()
        
        try:
            # L1 Cache (Memory) - Fastest
            with self.lock:
                if cache_key in self.l1_cache:
                    self.l1_access_times[cache_key] = time.time()
                    self.l1_access_counts[cache_key] = self.l1_access_counts.get(cache_key, 0) + 1
                    self._update_metrics(CacheLevel.L1_MEMORY, 'hit', time.time() - start_time)
                    return self.l1_cache[cache_key]['value']
            
            # L2 Cache (Redis) - Fast, distributed
            if self.redis_client:
                try:
                    data = self.redis_client.get(cache_key)
                    if data:
                        value = self._deserialize_value(data)
                        
                        # Promote to L1 cache
                        self._set_l1(cache_key, value)
                        
                        self._update_metrics(CacheLevel.L2_REDIS, 'hit', time.time() - start_time)
                        return value
                except Exception as e:
                    logger.error(f"Redis cache error: {e}")
            
            # Cache miss - return default
            self._update_metrics(CacheLevel.L1_MEMORY, 'miss', time.time() - start_time)
            return default
            
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return default
    
    def set(self, key: str, value: Any, ttl: int = 3600, tenant_id: str = None,
            level: CacheLevel = CacheLevel.L2_REDIS) -> bool:
        """Set value in multi-level cache"""
        cache_key = self._generate_key(key, tenant_id)
        start_time = time.time()
        
        try:
            # Always set in L1 for fastest access
            self._set_l1(cache_key, value, ttl)
            
            # Set in L2 (Redis) if available and requested
            if level in [CacheLevel.L2_REDIS, CacheLevel.L3_DATABASE] and self.redis_client:
                try:
                    serialized_value = self._serialize_value(value)
                    self.redis_client.setex(cache_key, ttl, serialized_value)
                except Exception as e:
                    logger.error(f"Redis cache set error: {e}")
            
            self._update_metrics(level, 'write', time.time() - start_time)
            return True
            
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def _set_l1(self, cache_key: str, value: Any, ttl: int = 3600):
        """Set value in L1 memory cache"""
        with self.lock:
            # Check if L1 cache is full and evict if necessary
            if len(self.l1_cache) >= self.max_l1_size:
                self._evict_l1_entry()
            
            self.l1_cache[cache_key] = {
                'value': value,
                'timestamp': time.time(),
                'ttl': ttl
            }
            self.l1_access_times[cache_key] = time.time()
            self.l1_access_counts[cache_key] = self.l1_access_counts.get(cache_key, 0) + 1
    
    def _evict_l1_entry(self):
        """Evict least recently used entry from L1 cache"""
        if not self.l1_cache:
            return
        
        # Find LRU entry
        lru_key = min(self.l1_access_times, key=self.l1_access_times.get)
        
        # Remove from all tracking structures
        del self.l1_cache[lru_key]
        del self.l1_access_times[lru_key]
        if lru_key in self.l1_access_counts:
            del self.l1_access_counts[lru_key]
        
        self._update_metrics(CacheLevel.L1_MEMORY, 'eviction', 0)
    
    def delete(self, key: str, tenant_id: str = None) -> bool:
        """Delete value from all cache levels"""
        cache_key = self._generate_key(key, tenant_id)
        
        try:
            # Delete from L1
            with self.lock:
                if cache_key in self.l1_cache:
                    del self.l1_cache[cache_key]
                if cache_key in self.l1_access_times:
                    del self.l1_access_times[cache_key]
                if cache_key in self.l1_access_counts:
                    del self.l1_access_counts[cache_key]
            
            # Delete from L2 (Redis)
            if self.redis_client:
                try:
                    self.redis_client.delete(cache_key)
                except Exception as e:
                    logger.error(f"Redis cache delete error: {e}")
            
            self._update_metrics(CacheLevel.L1_MEMORY, 'delete', 0)
            return True
            
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def clear(self, tenant_id: str = None):
        """Clear cache for tenant or all"""
        try:
            if tenant_id:
                # Clear tenant-specific cache
                prefix = f"tenant:{tenant_id}:"
                
                with self.lock:
                    keys_to_delete = [k for k in self.l1_cache.keys() if k.startswith(prefix)]
                    for key in keys_to_delete:
                        del self.l1_cache[key]
                        if key in self.l1_access_times:
                            del self.l1_access_times[key]
                        if key in self.l1_access_counts:
                            del self.l1_access_counts[key]
                
                if self.redis_client:
                    try:
                        keys = self.redis_client.keys(f"{prefix}*")
                        if keys:
                            self.redis_client.delete(*keys)
                    except Exception as e:
                        logger.error(f"Redis tenant clear error: {e}")
            else:
                # Clear all cache
                with self.lock:
                    self.l1_cache.clear()
                    self.l1_access_times.clear()
                    self.l1_access_counts.clear()
                
                if self.redis_client:
                    try:
                        self.redis_client.flushdb()
                    except Exception as e:
                        logger.error(f"Redis clear error: {e}")
            
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
    
    def _update_metrics(self, level: CacheLevel, operation: str, response_time: float):
        """Update cache performance metrics"""
        metrics = self.cache_metrics[level.value]
        
        if operation == 'hit':
            metrics.hits += 1
        elif operation == 'miss':
            metrics.misses += 1
        elif operation == 'write':
            metrics.writes += 1
        elif operation == 'delete':
            metrics.deletes += 1
        elif operation == 'eviction':
            metrics.evictions += 1
        
        metrics.total_requests += 1
        
        # Update average response time
        if metrics.total_requests > 1:
            metrics.average_response_time = (
                (metrics.average_response_time * (metrics.total_requests - 1) + response_time) /
                metrics.total_requests
            )
        else:
            metrics.average_response_time = response_time
        
        # Update hit rate
        if metrics.hits + metrics.misses > 0:
            metrics.hit_rate = metrics.hits / (metrics.hits + metrics.misses)
    
    def get_metrics(self) -> Dict[str, CacheMetrics]:
        """Get cache performance metrics"""
        # Update memory usage for L1
        with self.lock:
            l1_size = sum(len(pickle.dumps(v['value'])) for v in self.l1_cache.values())
            self.cache_metrics[CacheLevel.L1_MEMORY.value].memory_usage = l1_size
        
        return dict(self.cache_metrics)
    
    def cleanup_expired(self):
        """Remove expired entries from L1 cache"""
        current_time = time.time()
        
        with self.lock:
            expired_keys = []
            for key, data in self.l1_cache.items():
                if current_time - data['timestamp'] > data['ttl']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.l1_cache[key]
                if key in self.l1_access_times:
                    del self.l1_access_times[key]
                if key in self.l1_access_counts:
                    del self.l1_access_counts[key]

class CacheManager:
    """High-level cache management with decorators and utilities"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.cache = MultiLevelCache(app)
        self.cache_policies = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize cache manager"""
        self.app = app
        self.cache.init_app(app)
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        cleanup_thread.start()
        
        logger.info("CacheManager initialized")
    
    def _cleanup_worker(self):
        """Background worker for cache cleanup"""
        while True:
            try:
                self.cache.cleanup_expired()
                time.sleep(300)  # Cleanup every 5 minutes
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
                time.sleep(60)

# Decorators for automatic caching

def cached(ttl: int = 3600, key_func: Callable = None, tenant_aware: bool = True,
           level: CacheLevel = CacheLevel.L2_REDIS):
    """Decorator for automatic function result caching"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
            
            # Get tenant context if tenant-aware
            tenant_id = None
            if tenant_aware:
                try:
                    from tenant_manager import get_current_tenant
                    tenant = get_current_tenant()
                    if tenant:
                        tenant_id = tenant.id
                except ImportError:
                    pass
            
            # Try to get from cache
            result = cache_manager.cache.get(cache_key, tenant_id)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.cache.set(cache_key, result, ttl, tenant_id, level)
            
            return result
        return wrapper
    return decorator

def cache_invalidate(key_pattern: str = None, tenant_aware: bool = True):
    """Decorator to invalidate cache after function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Invalidate cache
            if key_pattern:
                # Get tenant context if tenant-aware
                tenant_id = None
                if tenant_aware:
                    try:
                        from tenant_manager import get_current_tenant
                        tenant = get_current_tenant()
                        if tenant:
                            tenant_id = tenant.id
                    except ImportError:
                        pass
                
                cache_manager.cache.delete(key_pattern, tenant_id)
            
            return result
        return wrapper
    return decorator

# Specialized caching for common use cases

class DeviceCache:
    """Specialized caching for device data"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager.cache
    
    def get_device_status(self, device_id: int, tenant_id: str) -> Optional[Dict]:
        """Get cached device status"""
        key = f"device_status:{device_id}"
        return self.cache.get(key, tenant_id)
    
    def set_device_status(self, device_id: int, status: Dict, tenant_id: str):
        """Cache device status with short TTL"""
        key = f"device_status:{device_id}"
        self.cache.set(key, status, ttl=300, tenant_id=tenant_id)
    
    def get_device_metrics(self, device_id: int, tenant_id: str) -> Optional[List]:
        """Get cached device metrics"""
        key = f"device_metrics:{device_id}"
        return self.cache.get(key, tenant_id)
    
    def set_device_metrics(self, device_id: int, metrics: List, tenant_id: str):
        """Cache device metrics with medium TTL"""
        key = f"device_metrics:{device_id}"
        self.cache.set(key, metrics, ttl=1800, tenant_id=tenant_id)

class AnalyticsCache:
    """Specialized caching for analytics data"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager.cache
    
    def get_usage_analytics(self, tenant_id: str, period: str) -> Optional[Dict]:
        """Get cached usage analytics"""
        key = f"usage_analytics:{period}"
        return self.cache.get(key, tenant_id)
    
    def set_usage_analytics(self, tenant_id: str, period: str, data: Dict):
        """Cache usage analytics with long TTL"""
        key = f"usage_analytics:{period}"
        self.cache.set(key, data, ttl=3600, tenant_id=tenant_id)
    
    def get_quota_status(self, tenant_id: str) -> Optional[Dict]:
        """Get cached quota status"""
        key = "quota_status"
        return self.cache.get(key, tenant_id)
    
    def set_quota_status(self, tenant_id: str, status: Dict):
        """Cache quota status with short TTL"""
        key = "quota_status"
        self.cache.set(key, status, ttl=300, tenant_id=tenant_id)

# Performance optimization utilities

class QueryCache:
    """Database query result caching"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager.cache
    
    def cache_query(self, query_hash: str, result: Any, ttl: int = 1800, tenant_id: str = None):
        """Cache database query result"""
        key = f"query:{query_hash}"
        self.cache.set(key, result, ttl=ttl, tenant_id=tenant_id)
    
    def get_cached_query(self, query_hash: str, tenant_id: str = None) -> Any:
        """Get cached query result"""
        key = f"query:{query_hash}"
        return self.cache.get(key, tenant_id)

def query_cache(ttl: int = 1800):
    """Decorator for database query caching"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate query hash
            query_parts = [func.__name__]
            query_parts.extend(str(arg) for arg in args)
            query_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            query_hash = hashlib.md5(":".join(query_parts).encode()).hexdigest()
            
            # Get tenant context
            tenant_id = None
            try:
                from tenant_manager import get_current_tenant
                tenant = get_current_tenant()
                if tenant:
                    tenant_id = tenant.id
            except ImportError:
                pass
            
            # Try cache first
            result = query_cache_manager.get_cached_query(query_hash, tenant_id)
            if result is not None:
                return result
            
            # Execute query and cache result
            result = func(*args, **kwargs)
            query_cache_manager.cache_query(query_hash, result, ttl, tenant_id)
            
            return result
        return wrapper
    return decorator

# Global instances
cache_manager = CacheManager()
device_cache = DeviceCache(cache_manager)
analytics_cache = AnalyticsCache(cache_manager)
query_cache_manager = QueryCache(cache_manager)

# Flask integration
def init_cache(app: Flask):
    """Initialize caching system with Flask app"""
    cache_manager.init_app(app)
    
    # Add cache metrics endpoint
    @app.route('/api/cache/metrics')
    def cache_metrics():
        metrics = cache_manager.cache.get_metrics()
        return {
            'cache_metrics': {
                level: {
                    'hits': m.hits,
                    'misses': m.misses,
                    'hit_rate': m.hit_rate,
                    'total_requests': m.total_requests,
                    'average_response_time': m.average_response_time,
                    'memory_usage': m.memory_usage,
                    'evictions': m.evictions
                }
                for level, m in metrics.items()
            }
        }
    
    # Add cache management endpoint
    @app.route('/api/cache/clear', methods=['POST'])
    def clear_cache():
        try:
            tenant_id = request.json.get('tenant_id') if request.is_json else None
            cache_manager.cache.clear(tenant_id)
            return {'success': True, 'message': 'Cache cleared successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500