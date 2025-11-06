"""
Query Result Caching Service for HomeNetMon
Provides intelligent caching for frequently accessed database queries
"""

import time
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, List
from functools import wraps
from threading import RLock

logger = logging.getLogger(__name__)

class QueryCache:
    """Intelligent query result caching with TTL and invalidation"""
    
    def __init__(self, default_ttl=30, max_cache_size=1000):
        self.cache = {}
        self.access_times = {}
        self.default_ttl = default_ttl
        self.max_cache_size = max_cache_size
        self._lock = RLock()
        
        # Cache hit/miss statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'invalidations': 0
        }
    
    def _generate_cache_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate a unique cache key for function call"""
        # Create a deterministic key from function name and arguments
        key_data = {
            'func': func_name,
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _is_expired(self, cached_item: dict) -> bool:
        """Check if cached item has expired"""
        return time.time() > cached_item['expires_at']
    
    def _evict_expired_items(self):
        """Remove expired items from cache"""
        with self._lock:
            current_time = time.time()
            expired_keys = [
                key for key, item in self.cache.items()
                if current_time > item['expires_at']
            ]
            
            for key in expired_keys:
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
                self.stats['evictions'] += 1
    
    def _evict_lru_items(self):
        """Evict least recently used items when cache is full"""
        with self._lock:
            if len(self.cache) <= self.max_cache_size:
                return
            
            # Sort by access time and remove oldest items
            sorted_items = sorted(
                self.access_times.items(), 
                key=lambda x: x[1]
            )
            
            items_to_remove = len(self.cache) - self.max_cache_size + 10  # Remove extra for efficiency
            
            for key, _ in sorted_items[:items_to_remove]:
                if key in self.cache:
                    del self.cache[key]
                    del self.access_times[key]
                    self.stats['evictions'] += 1
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self._lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            cached_item = self.cache[key]
            
            # Check expiration
            if self._is_expired(cached_item):
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
                self.stats['misses'] += 1
                self.stats['evictions'] += 1
                return None
            
            # Update access time
            self.access_times[key] = time.time()
            self.stats['hits'] += 1
            return cached_item['data']
    
    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> None:
        """Set item in cache with TTL"""
        with self._lock:
            # Clean up expired items periodically
            if len(self.cache) % 50 == 0:  # Every 50 operations
                self._evict_expired_items()
            
            # Evict LRU items if cache is full
            if len(self.cache) >= self.max_cache_size:
                self._evict_lru_items()
            
            ttl = ttl or self.default_ttl
            expires_at = time.time() + ttl
            
            self.cache[key] = {
                'data': data,
                'expires_at': expires_at,
                'created_at': time.time()
            }
            self.access_times[key] = time.time()
    
    def invalidate_pattern(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        with self._lock:
            keys_to_remove = [
                key for key in self.cache.keys()
                if pattern in key
            ]
            
            for key in keys_to_remove:
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
                self.stats['invalidations'] += 1
    
    def clear(self):
        """Clear entire cache"""
        with self._lock:
            self.cache.clear()
            self.access_times.clear()
            self.stats['invalidations'] += len(self.cache)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'cache_size': len(self.cache),
                'max_size': self.max_cache_size,
                'hit_rate': f"{hit_rate:.1f}%",
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'evictions': self.stats['evictions'],
                'invalidations': self.stats['invalidations']
            }

# Global cache instance with optimized settings
query_cache = QueryCache(default_ttl=60, max_cache_size=1000)

def cached_query(ttl=30, key_prefix="", invalidate_on_change=True):
    """Decorator for caching query results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = key_prefix + query_cache._generate_cache_key(
                func.__name__, args, kwargs
            )
            
            # Try to get from cache first
            cached_result = query_cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_result
            
            # Execute query and cache result
            logger.debug(f"Cache miss for {func.__name__} - executing query")
            result = func(*args, **kwargs)
            
            # Cache the result
            query_cache.set(cache_key, result, ttl)
            
            return result
        
        # Add cache invalidation method to function
        wrapper.invalidate_cache = lambda pattern="": query_cache.invalidate_pattern(
            key_prefix + pattern if pattern else key_prefix + func.__name__
        )
        
        return wrapper
    return decorator

def get_cached_device_list(app_context_func) -> List[Dict[str, Any]]:
    """Get cached list of all devices with their latest status"""
    
    @cached_query(ttl=60, key_prefix="devices_", invalidate_on_change=True)  # 1-minute cache for production
    def _get_device_list():
        from models import Device, MonitoringData, Alert, db
        from sqlalchemy import func, desc
        from datetime import datetime, timedelta

        with app_context_func():
            # Get all devices efficiently with optimized query
            devices_query = db.session.query(Device).all()
            logger.info(f"=== CACHE MISS: Retrieved {len(devices_query)} devices from database ===")
            logger.info(f"Sample IPs: {[d.ip_address for d in devices_query[:10]]}")
            
            # TODO: Re-add monitoring data and alerts in a separate optimization phase
            # For now, just return basic device data to fix the NOC display issue
            
            # Convert to serializable format
            device_list = []
            current_time = datetime.utcnow()
            
            for device in devices_query:
                # Simplified - no complex monitoring data lookup for now
                response_time = None
                last_monitoring = None
                alert_count = 0
                # Calculate status efficiently based on last_seen timestamp
                status = 'unknown'
                if device.last_seen:
                    threshold = current_time - timedelta(seconds=900)  # 15-minute threshold (ping interval + buffer)
                    if device.last_seen >= threshold:
                        # Device was seen recently, consider it up
                        # TODO: Add proper response time checking in future optimization
                        status = 'up'
                    else:
                        status = 'down'
                else:
                    status = 'unknown'
                
                device_data = {
                    'id': device.id,
                    'ip_address': device.ip_address,
                    'mac_address': device.mac_address,
                    'hostname': device.hostname,
                    'vendor': device.vendor,
                    'custom_name': device.custom_name,
                    'display_name': device.custom_name or device.hostname or device.ip_address,
                    'device_type': device.device_type,
                    'device_group': device.device_group,
                    'is_monitored': device.is_monitored,
                    'status': status,
                    'latest_response_time': response_time,
                    'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
                    'active_alerts': alert_count,
                    'uptime_percentage': device.uptime_percentage(),
                    'created_at': device.created_at.isoformat() + 'Z',
                    'updated_at': device.updated_at.isoformat() + 'Z' if device.updated_at else None
                }
                device_list.append(device_data)

            logger.info(f"=== Returning {len(device_list)} devices from cache function ===")
            return device_list
    
    return _get_device_list()

def get_cached_monitoring_summary(app_context_func) -> Dict[str, Any]:
    """Get cached monitoring summary statistics"""
    
    @cached_query(ttl=30, key_prefix="monitoring_summary_")
    def _get_monitoring_summary():
        from models import Device, Alert
        from sqlalchemy import func
        
        with app_context_func():
            # Get device counts by status
            total_devices = db.session.query(func.count(Device.id)).scalar()
            monitored_devices = db.session.query(func.count(Device.id)).filter(
                Device.is_monitored == True
            ).scalar()
            
            # Get alert counts
            active_alerts = db.session.query(func.count(Alert.id)).filter(
                Alert.resolved == False
            ).scalar()
            
            critical_alerts = db.session.query(func.count(Alert.id)).filter(
                Alert.resolved == False,
                Alert.severity == 'critical'
            ).scalar()
            
            return {
                'total_devices': total_devices,
                'monitored_devices': monitored_devices,
                'active_alerts': active_alerts,
                'critical_alerts': critical_alerts,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    return _get_monitoring_summary()

def invalidate_device_cache():
    """Invalidate all device-related cache entries"""
    query_cache.invalidate_pattern("devices_")
    query_cache.invalidate_pattern("monitoring_summary_")
    logger.debug("Invalidated device cache entries")

def get_cache_stats():
    """Get cache performance statistics"""
    return query_cache.get_stats()

# Initialize cache with app context
def init_query_cache(app):
    """Initialize query cache with Flask app context"""
    global db
    from models import db as database
    db = database
    
    # Create app context function
    def app_context_func():
        return app.app_context()
    
    # Make app context available to cached functions
    get_cached_device_list.app_context = app_context_func
    get_cached_monitoring_summary.app_context = app_context_func
    
    logger.info("Query result caching initialized")
    return query_cache