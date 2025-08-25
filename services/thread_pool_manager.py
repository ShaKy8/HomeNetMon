"""
Dynamic Thread Pool Manager for HomeNetMon
Manages thread pools dynamically based on system resources and workload.
"""
import os
import time
import threading
import logging
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from queue import Queue, Empty
import weakref

logger = logging.getLogger(__name__)

@dataclass
class ThreadPoolStats:
    """Statistics for thread pool monitoring"""
    active_threads: int
    idle_threads: int
    queued_tasks: int
    completed_tasks: int
    failed_tasks: int
    avg_task_duration: float
    memory_usage_mb: float
    cpu_usage_percent: float

class AdaptiveThreadPool:
    """
    An adaptive thread pool that adjusts its size based on system resources
    and workload patterns.
    """
    
    def __init__(self, 
                 pool_name: str,
                 min_workers: int = 2, 
                 max_workers: int = None,
                 target_cpu_usage: float = 0.70,
                 target_memory_usage: float = 0.80):
        
        self.pool_name = pool_name
        self.min_workers = min_workers
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) * 4)
        self.target_cpu_usage = target_cpu_usage
        self.target_memory_usage = target_memory_usage
        
        # Start with a reasonable number of workers
        initial_workers = min(max(os.cpu_count() or 1, min_workers), self.max_workers)
        self.executor = ThreadPoolExecutor(max_workers=initial_workers, thread_name_prefix=pool_name)
        self.current_workers = initial_workers
        
        # Statistics tracking
        self._stats_lock = threading.Lock()
        self._task_durations = []
        self._completed_tasks = 0
        self._failed_tasks = 0
        self._task_start_times = {}
        
        # Resource monitoring
        self._last_adjustment = time.time()
        self._adjustment_interval = 30  # Adjust every 30 seconds
        self._monitoring_active = True
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_and_adjust,
            name=f"{pool_name}_monitor",
            daemon=True
        )
        self._monitor_thread.start()
        
        logger.info(f"Created adaptive thread pool '{pool_name}' with {initial_workers} initial workers")
    
    def submit(self, fn: Callable, *args, **kwargs):
        """Submit a task to the thread pool with monitoring"""
        future = self.executor.submit(self._monitored_task, fn, *args, **kwargs)
        return future
    
    def map(self, fn: Callable, iterable, timeout=None, chunksize=1):
        """Map function over iterable with monitoring"""
        return self.executor.map(self._wrap_monitored_task(fn), iterable, timeout=timeout, chunksize=chunksize)
    
    def shutdown(self, wait=True):
        """Shutdown the thread pool"""
        self._monitoring_active = False
        if hasattr(self, '_monitor_thread') and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        self.executor.shutdown(wait=wait)
        logger.info(f"Shutdown thread pool '{self.pool_name}'")
    
    def _monitored_task(self, fn: Callable, *args, **kwargs):
        """Wrapper for monitoring task execution"""
        task_id = threading.get_ident()
        start_time = time.time()
        
        with self._stats_lock:
            self._task_start_times[task_id] = start_time
        
        try:
            result = fn(*args, **kwargs)
            
            # Record successful completion
            duration = time.time() - start_time
            with self._stats_lock:
                self._completed_tasks += 1
                self._task_durations.append(duration)
                # Keep only last 100 durations to prevent memory growth
                if len(self._task_durations) > 100:
                    self._task_durations = self._task_durations[-50:]
                if task_id in self._task_start_times:
                    del self._task_start_times[task_id]
            
            return result
            
        except Exception as e:
            # Record failure
            duration = time.time() - start_time
            with self._stats_lock:
                self._failed_tasks += 1
                if task_id in self._task_start_times:
                    del self._task_start_times[task_id]
            
            logger.error(f"Task failed in thread pool '{self.pool_name}': {e}")
            raise
    
    def _wrap_monitored_task(self, fn: Callable):
        """Create a monitored version of a function for map operations"""
        def wrapper(*args, **kwargs):
            return self._monitored_task(fn, *args, **kwargs)
        return wrapper
    
    def _monitor_and_adjust(self):
        """Monitor system resources and adjust thread pool size"""
        while self._monitoring_active:
            try:
                time.sleep(10)  # Check every 10 seconds
                
                current_time = time.time()
                if current_time - self._last_adjustment < self._adjustment_interval:
                    continue
                
                # Get current system metrics
                cpu_percent = psutil.cpu_percent(interval=1) / 100.0
                memory_info = psutil.virtual_memory()
                memory_percent = memory_info.percent / 100.0
                
                # Determine if adjustment is needed
                adjustment_needed = self._calculate_adjustment(cpu_percent, memory_percent)
                
                if adjustment_needed != 0:
                    self._adjust_pool_size(adjustment_needed)
                    self._last_adjustment = current_time
                
            except Exception as e:
                logger.error(f"Error in thread pool monitoring for '{self.pool_name}': {e}")
                time.sleep(30)  # Back off on errors
    
    def _calculate_adjustment(self, cpu_percent: float, memory_percent: float) -> int:
        """Calculate how many workers to add or remove"""
        stats = self.get_stats()
        
        # Don't adjust if we don't have enough data
        if stats.completed_tasks < 5:
            return 0
        
        adjustment = 0
        
        # CPU-based adjustments
        if cpu_percent < self.target_cpu_usage * 0.7 and stats.queued_tasks > 2:
            # Low CPU usage but tasks queued - might need more workers
            adjustment += 1
        elif cpu_percent > self.target_cpu_usage * 1.2:
            # High CPU usage - reduce workers
            adjustment -= 1
        
        # Memory-based adjustments
        if memory_percent > self.target_memory_usage:
            # High memory usage - reduce workers
            adjustment -= 1
        
        # Task completion rate adjustments
        if stats.avg_task_duration > 5.0 and stats.queued_tasks > self.current_workers:
            # Slow tasks and backlog - add workers if resources allow
            if cpu_percent < self.target_cpu_usage and memory_percent < self.target_memory_usage:
                adjustment += 1
        
        # Respect min/max limits
        if self.current_workers + adjustment < self.min_workers:
            adjustment = self.min_workers - self.current_workers
        elif self.current_workers + adjustment > self.max_workers:
            adjustment = self.max_workers - self.current_workers
        
        return adjustment
    
    def _adjust_pool_size(self, adjustment: int):
        """Adjust the thread pool size"""
        if adjustment == 0:
            return
        
        new_size = max(self.min_workers, min(self.max_workers, self.current_workers + adjustment))
        
        if new_size == self.current_workers:
            return
        
        try:
            # Create new executor with adjusted size
            old_executor = self.executor
            self.executor = ThreadPoolExecutor(
                max_workers=new_size, 
                thread_name_prefix=self.pool_name
            )
            
            # Shutdown old executor gracefully
            old_executor.shutdown(wait=False)
            
            self.current_workers = new_size
            
            logger.info(
                f"Adjusted thread pool '{self.pool_name}' from "
                f"{self.current_workers - adjustment} to {new_size} workers"
            )
            
        except Exception as e:
            logger.error(f"Failed to adjust thread pool '{self.pool_name}': {e}")
    
    def get_stats(self) -> ThreadPoolStats:
        """Get current thread pool statistics"""
        try:
            with self._stats_lock:
                active_threads = len(self._task_start_times)
                idle_threads = max(0, self.current_workers - active_threads)
                
                avg_duration = 0.0
                if self._task_durations:
                    avg_duration = sum(self._task_durations) / len(self._task_durations)
                
                # Estimate queued tasks (this is approximate)
                queued_tasks = max(0, active_threads - self.current_workers)
                
                completed = self._completed_tasks
                failed = self._failed_tasks
            
            # Get memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
            
            return ThreadPoolStats(
                active_threads=active_threads,
                idle_threads=idle_threads,
                queued_tasks=queued_tasks,
                completed_tasks=completed,
                failed_tasks=failed,
                avg_task_duration=avg_duration,
                memory_usage_mb=memory_mb,
                cpu_usage_percent=cpu_percent
            )
            
        except Exception as e:
            logger.error(f"Error getting stats for thread pool '{self.pool_name}': {e}")
            return ThreadPoolStats(0, 0, 0, 0, 0, 0.0, 0.0, 0.0)

class ThreadPoolManager:
    """
    Centralized manager for all thread pools in the application
    """
    
    def __init__(self):
        self._pools: Dict[str, AdaptiveThreadPool] = {}
        self._pool_configs = {
            'monitoring': {'min_workers': 2, 'max_workers': 8, 'target_cpu_usage': 0.60},
            'scanning': {'min_workers': 1, 'max_workers': 4, 'target_cpu_usage': 0.50},
            'alerts': {'min_workers': 1, 'max_workers': 3, 'target_cpu_usage': 0.40},
            'analytics': {'min_workers': 1, 'max_workers': 4, 'target_cpu_usage': 0.70},
            'general': {'min_workers': 2, 'max_workers': 6, 'target_cpu_usage': 0.60}
        }
        self._shutdown_hooks = []
        
        # Register cleanup on process exit
        import atexit
        atexit.register(self.shutdown_all)
    
    def get_pool(self, pool_name: str) -> AdaptiveThreadPool:
        """Get or create a thread pool with the specified name"""
        if pool_name not in self._pools:
            config = self._pool_configs.get(pool_name, self._pool_configs['general'])
            pool = AdaptiveThreadPool(
                pool_name=pool_name,
                min_workers=config['min_workers'],
                max_workers=config['max_workers'],
                target_cpu_usage=config['target_cpu_usage']
            )
            self._pools[pool_name] = pool
            
            logger.info(f"Created thread pool '{pool_name}' with config: {config}")
        
        return self._pools[pool_name]
    
    def get_all_stats(self) -> Dict[str, ThreadPoolStats]:
        """Get statistics for all thread pools"""
        stats = {}
        for name, pool in self._pools.items():
            stats[name] = pool.get_stats()
        return stats
    
    def get_system_resource_summary(self) -> Dict[str, any]:
        """Get overall system resource usage summary"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            total_active_threads = 0
            total_completed_tasks = 0
            total_pools = len(self._pools)
            
            for pool in self._pools.values():
                stats = pool.get_stats()
                total_active_threads += stats.active_threads
                total_completed_tasks += stats.completed_tasks
            
            return {
                'cpu_usage_percent': cpu_percent,
                'memory_usage_percent': memory.percent,
                'memory_available_mb': memory.available / 1024 / 1024,
                'total_thread_pools': total_pools,
                'total_active_threads': total_active_threads,
                'total_completed_tasks': total_completed_tasks,
                'system_load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            }
            
        except Exception as e:
            logger.error(f"Error getting system resource summary: {e}")
            return {}
    
    def optimize_pools_for_workload(self):
        """Optimize all thread pools based on current workload patterns"""
        system_stats = self.get_system_resource_summary()
        
        # If system is under high load, reduce thread counts
        if system_stats.get('cpu_usage_percent', 0) > 85:
            logger.warning("High CPU usage detected, reducing thread pool sizes")
            for pool in self._pools.values():
                if pool.current_workers > pool.min_workers:
                    pool._adjust_pool_size(-1)
        
        # If memory is low, be more conservative
        elif system_stats.get('memory_usage_percent', 0) > 90:
            logger.warning("High memory usage detected, reducing thread pool sizes")
            for pool in self._pools.values():
                if pool.current_workers > pool.min_workers:
                    pool._adjust_pool_size(-1)
    
    def shutdown_all(self):
        """Shutdown all thread pools"""
        logger.info("Shutting down all thread pools...")
        for name, pool in self._pools.items():
            try:
                pool.shutdown(wait=True)
                logger.info(f"Shutdown thread pool '{name}'")
            except Exception as e:
                logger.error(f"Error shutting down thread pool '{name}': {e}")
        
        self._pools.clear()
        
        # Execute shutdown hooks
        for hook in self._shutdown_hooks:
            try:
                hook()
            except Exception as e:
                logger.error(f"Error executing shutdown hook: {e}")
    
    def register_shutdown_hook(self, hook: Callable):
        """Register a function to be called on shutdown"""
        self._shutdown_hooks.append(hook)

# Global thread pool manager instance
thread_pool_manager = ThreadPoolManager()

def get_thread_pool(pool_name: str = 'general') -> AdaptiveThreadPool:
    """Convenience function to get a thread pool"""
    return thread_pool_manager.get_pool(pool_name)

def get_monitoring_pool() -> AdaptiveThreadPool:
    """Get the monitoring thread pool"""
    return thread_pool_manager.get_pool('monitoring')

def get_scanning_pool() -> AdaptiveThreadPool:
    """Get the network scanning thread pool"""
    return thread_pool_manager.get_pool('scanning')

def get_alerts_pool() -> AdaptiveThreadPool:
    """Get the alerts processing thread pool"""
    return thread_pool_manager.get_pool('alerts')

def get_analytics_pool() -> AdaptiveThreadPool:
    """Get the analytics processing thread pool"""
    return thread_pool_manager.get_pool('analytics')