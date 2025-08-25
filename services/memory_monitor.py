"""
Memory Monitoring and Cleanup Service for HomeNetMon
Monitors memory usage and performs intelligent cleanup when needed.
"""
import gc
import time
import threading
import logging
import psutil
import weakref
import sys
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

@dataclass
class MemoryStats:
    """Memory usage statistics"""
    total_mb: float
    used_mb: float
    available_mb: float
    percent_used: float
    cache_usage_mb: float
    gc_collections: int
    objects_tracked: int

class MemoryCleanupRegistry:
    """Registry for cleanup callbacks"""
    
    def __init__(self):
        self._cleanup_callbacks: Dict[str, Callable] = {}
        self._object_pools: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._weak_refs: Dict[str, List[weakref.ref]] = defaultdict(list)
        self._lock = threading.RLock()
    
    def register_cleanup_callback(self, name: str, callback: Callable):
        """Register a cleanup callback"""
        with self._lock:
            self._cleanup_callbacks[name] = callback
        logger.debug(f"Registered cleanup callback: {name}")
    
    def register_object_pool(self, pool_name: str, max_size: int = 1000):
        """Register an object pool for cleanup"""
        with self._lock:
            self._object_pools[pool_name] = deque(maxlen=max_size)
        logger.debug(f"Registered object pool: {pool_name} (max_size={max_size})")
    
    def add_to_pool(self, pool_name: str, obj: Any):
        """Add object to pool for potential cleanup"""
        with self._lock:
            if pool_name in self._object_pools:
                self._object_pools[pool_name].append(obj)
    
    def cleanup_pool(self, pool_name: str, percentage: float = 0.5):
        """Clean up a percentage of objects in a pool"""
        with self._lock:
            if pool_name in self._object_pools:
                pool = self._object_pools[pool_name]
                items_to_remove = int(len(pool) * percentage)
                
                for _ in range(items_to_remove):
                    if pool:
                        pool.popleft()
                
                logger.debug(f"Cleaned up {items_to_remove} items from pool '{pool_name}'")
                return items_to_remove
        return 0
    
    def cleanup_all_pools(self, percentage: float = 0.5):
        """Clean up all registered object pools"""
        total_cleaned = 0
        with self._lock:
            for pool_name in self._object_pools:
                total_cleaned += self.cleanup_pool(pool_name, percentage)
        
        if total_cleaned > 0:
            logger.info(f"Cleaned up {total_cleaned} total items from all pools")
        return total_cleaned
    
    def run_cleanup_callbacks(self, severity: str = 'normal'):
        """Execute all registered cleanup callbacks"""
        with self._lock:
            callbacks_run = 0
            for name, callback in self._cleanup_callbacks.items():
                try:
                    callback(severity)
                    callbacks_run += 1
                    logger.debug(f"Executed cleanup callback: {name}")
                except Exception as e:
                    logger.error(f"Error in cleanup callback '{name}': {e}")
            
            logger.info(f"Executed {callbacks_run} cleanup callbacks")
            return callbacks_run
    
    def track_weak_reference(self, category: str, obj: Any):
        """Track an object with weak reference for cleanup monitoring"""
        with self._lock:
            weak_ref = weakref.ref(obj, self._cleanup_weak_ref_callback(category))
            self._weak_refs[category].append(weak_ref)
    
    def _cleanup_weak_ref_callback(self, category: str):
        """Create callback for weak reference cleanup"""
        def callback(ref):
            with self._lock:
                if category in self._weak_refs and ref in self._weak_refs[category]:
                    self._weak_refs[category].remove(ref)
        return callback
    
    def get_tracked_objects_count(self) -> Dict[str, int]:
        """Get count of tracked objects by category"""
        with self._lock:
            return {
                category: len([ref for ref in refs if ref() is not None])
                for category, refs in self._weak_refs.items()
            }

class MemoryMonitor:
    """
    Monitors system and application memory usage and triggers cleanup
    when memory usage exceeds configured thresholds.
    """
    
    def __init__(self, cleanup_registry: MemoryCleanupRegistry = None):
        self.cleanup_registry = cleanup_registry or MemoryCleanupRegistry()
        
        # Configuration
        self.warning_threshold = 0.75  # 75% memory usage
        self.critical_threshold = 0.85  # 85% memory usage
        self.emergency_threshold = 0.95  # 95% memory usage
        
        # Monitoring state
        self._monitoring_active = True
        self._monitor_thread = None
        self._stats_history = deque(maxlen=100)  # Keep last 100 stats
        self._last_cleanup = datetime.min
        self._cleanup_cooldown = timedelta(minutes=5)  # Minimum time between cleanups
        
        # Performance tracking
        self._gc_stats = {'collections': 0, 'objects_before': 0, 'objects_after': 0}
        
    def start_monitoring(self, interval: int = 30):
        """Start background memory monitoring"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Memory monitoring already running")
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            name="memory_monitor",
            daemon=True
        )
        self._monitor_thread.start()
        
        logger.info(f"Started memory monitoring with {interval}s interval")
    
    def stop_monitoring(self):
        """Stop background memory monitoring"""
        self._monitoring_active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10)
        logger.info("Stopped memory monitoring")
    
    def get_memory_stats(self) -> MemoryStats:
        """Get current memory usage statistics"""
        try:
            # System memory
            memory = psutil.virtual_memory()
            
            # Process memory
            process = psutil.Process()
            process_memory = process.memory_info()
            
            # Cache usage estimate (from performance cache if available)
            cache_usage = 0.0
            try:
                from services.performance_cache import performance_cache
                cache_stats = performance_cache.get_stats()
                cache_usage = cache_stats.get('memory_usage_mb', 0)
            except:
                pass
            
            # GC stats
            gc_stats = gc.get_stats()
            total_collections = sum(stat['collections'] for stat in gc_stats)
            
            # Object tracking
            tracked_objects = len(gc.get_objects())
            
            return MemoryStats(
                total_mb=memory.total / 1024 / 1024,
                used_mb=memory.used / 1024 / 1024,
                available_mb=memory.available / 1024 / 1024,
                percent_used=memory.percent / 100.0,
                cache_usage_mb=cache_usage,
                gc_collections=total_collections,
                objects_tracked=tracked_objects
            )
            
        except Exception as e:
            logger.error(f"Error getting memory stats: {e}")
            return MemoryStats(0, 0, 0, 0, 0, 0, 0)
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop"""
        while self._monitoring_active:
            try:
                stats = self.get_memory_stats()
                self._stats_history.append((datetime.now(), stats))
                
                # Check thresholds and trigger cleanup if needed
                self._check_memory_thresholds(stats)
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in memory monitoring loop: {e}")
                time.sleep(interval * 2)  # Back off on errors
    
    def _check_memory_thresholds(self, stats: MemoryStats):
        """Check memory usage against thresholds and trigger cleanup"""
        current_time = datetime.now()
        
        # Skip if we recently performed cleanup
        if current_time - self._last_cleanup < self._cleanup_cooldown:
            return
        
        if stats.percent_used >= self.emergency_threshold:
            logger.critical(f"EMERGENCY: Memory usage at {stats.percent_used:.1%}! Performing aggressive cleanup")
            self._perform_cleanup('emergency')
            self._last_cleanup = current_time
            
        elif stats.percent_used >= self.critical_threshold:
            logger.error(f"CRITICAL: Memory usage at {stats.percent_used:.1%}! Performing cleanup")
            self._perform_cleanup('critical')
            self._last_cleanup = current_time
            
        elif stats.percent_used >= self.warning_threshold:
            logger.warning(f"WARNING: Memory usage at {stats.percent_used:.1%}. Performing light cleanup")
            self._perform_cleanup('warning')
            self._last_cleanup = current_time
    
    def _perform_cleanup(self, severity: str):
        """Perform memory cleanup based on severity level"""
        cleanup_start = time.time()
        initial_stats = self.get_memory_stats()
        
        logger.info(f"Starting {severity} cleanup - Memory: {initial_stats.percent_used:.1%}")
        
        # Force garbage collection first
        objects_before = len(gc.get_objects())
        collected = gc.collect()
        objects_after = len(gc.get_objects())
        
        self._gc_stats.update({
            'collections': self._gc_stats['collections'] + 1,
            'objects_before': objects_before,
            'objects_after': objects_after
        })
        
        logger.debug(f"GC collected {collected} objects ({objects_before} -> {objects_after})")
        
        # Run registered cleanup callbacks
        self.cleanup_registry.run_cleanup_callbacks(severity)
        
        # Clean object pools based on severity
        if severity == 'emergency':
            self.cleanup_registry.cleanup_all_pools(0.8)  # Clean 80%
            # Clear performance cache aggressively
            try:
                from services.performance_cache import performance_cache
                performance_cache.clear()
                logger.info("Cleared performance cache due to emergency memory pressure")
            except:
                pass
                
        elif severity == 'critical':
            self.cleanup_registry.cleanup_all_pools(0.6)  # Clean 60%
            # Reduce cache size
            try:
                from services.performance_cache import performance_cache, resource_monitor
                resource_monitor.adjust_cache_settings()
            except:
                pass
                
        elif severity == 'warning':
            self.cleanup_registry.cleanup_all_pools(0.3)  # Clean 30%
        
        # Final garbage collection
        gc.collect()
        
        # Get final stats
        final_stats = self.get_memory_stats()
        cleanup_duration = time.time() - cleanup_start
        
        memory_freed = initial_stats.used_mb - final_stats.used_mb
        
        logger.info(
            f"Completed {severity} cleanup in {cleanup_duration:.2f}s. "
            f"Memory: {initial_stats.percent_used:.1%} -> {final_stats.percent_used:.1%} "
            f"({memory_freed:.1f}MB freed)"
        )
    
    def force_cleanup(self, severity: str = 'normal'):
        """Force immediate cleanup regardless of cooldown"""
        self._last_cleanup = datetime.min  # Reset cooldown
        self._perform_cleanup(severity)
    
    def get_memory_trend(self, minutes: int = 30) -> Dict[str, Any]:
        """Get memory usage trend over the specified time period"""
        if not self._stats_history:
            return {}
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_stats = [
            (timestamp, stats) for timestamp, stats in self._stats_history
            if timestamp >= cutoff_time
        ]
        
        if len(recent_stats) < 2:
            return {}
        
        first_stats = recent_stats[0][1]
        last_stats = recent_stats[-1][1]
        
        memory_change = last_stats.used_mb - first_stats.used_mb
        trend = "increasing" if memory_change > 0 else "decreasing" if memory_change < 0 else "stable"
        
        # Calculate average usage
        avg_usage = sum(stats.percent_used for _, stats in recent_stats) / len(recent_stats)
        
        # Find peak usage
        peak_usage = max(stats.percent_used for _, stats in recent_stats)
        
        return {
            'trend': trend,
            'change_mb': memory_change,
            'avg_usage_percent': avg_usage * 100,
            'peak_usage_percent': peak_usage * 100,
            'samples': len(recent_stats),
            'timespan_minutes': minutes
        }
    
    def get_cleanup_statistics(self) -> Dict[str, Any]:
        """Get cleanup performance statistics"""
        tracked_objects = self.cleanup_registry.get_tracked_objects_count()
        
        return {
            'gc_stats': self._gc_stats.copy(),
            'tracked_objects': tracked_objects,
            'total_tracked': sum(tracked_objects.values()),
            'cleanup_callbacks': len(self.cleanup_registry._cleanup_callbacks),
            'object_pools': len(self.cleanup_registry._object_pools),
            'stats_history_size': len(self._stats_history)
        }
    
    def register_cache_cleanup(self):
        """Register cleanup for performance cache"""
        try:
            from services.performance_cache import performance_cache
            
            def cache_cleanup(severity):
                if severity == 'emergency':
                    performance_cache.clear()
                elif severity == 'critical':
                    # Clear 70% of cache
                    current_size = len(performance_cache._cache)
                    items_to_remove = int(current_size * 0.7)
                    
                    with performance_cache._lock:
                        # Remove oldest items
                        sorted_items = sorted(
                            performance_cache._access_times.items(),
                            key=lambda x: x[1]
                        )
                        for key, _ in sorted_items[:items_to_remove]:
                            if key in performance_cache._cache:
                                del performance_cache._cache[key]
                            if key in performance_cache._access_times:
                                del performance_cache._access_times[key]
                
                elif severity == 'warning':
                    # Clear expired entries
                    performance_cache._cleanup_expired()
            
            self.cleanup_registry.register_cleanup_callback('performance_cache', cache_cleanup)
            logger.info("Registered performance cache cleanup")
            
        except ImportError:
            logger.debug("Performance cache not available for cleanup registration")
    
    def register_websocket_cleanup(self):
        """Register cleanup for WebSocket optimizer"""
        try:
            from services.websocket_optimizer import websocket_optimizer
            
            def websocket_cleanup(severity):
                if websocket_optimizer and severity in ['critical', 'emergency']:
                    websocket_optimizer.clear_update_cache()
                    logger.info(f"Cleared WebSocket optimizer cache due to {severity} memory pressure")
            
            self.cleanup_registry.register_cleanup_callback('websocket_optimizer', websocket_cleanup)
            logger.info("Registered WebSocket optimizer cleanup")
            
        except ImportError:
            logger.debug("WebSocket optimizer not available for cleanup registration")

# Global memory monitor instance
memory_monitor = MemoryMonitor()

def init_memory_monitoring():
    """Initialize memory monitoring with default cleanup registrations"""
    memory_monitor.register_cache_cleanup()
    memory_monitor.register_websocket_cleanup()
    memory_monitor.start_monitoring()
    
    logger.info("Initialized memory monitoring with default cleanup handlers")
    return memory_monitor

def get_memory_stats():
    """Convenience function to get current memory statistics"""
    return memory_monitor.get_memory_stats()

def register_cleanup_callback(name: str, callback: Callable):
    """Convenience function to register cleanup callback"""
    memory_monitor.cleanup_registry.register_cleanup_callback(name, callback)