# HomeNetMon Performance Metrics Collection System
from flask import Flask, request, g, current_app
import time
import psutil
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json
import asyncio
from functools import wraps
import gc
import sys
import os
import resource
import statistics

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """System-level performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_io_sent_mb: float
    network_io_recv_mb: float
    load_average: tuple
    open_files: int
    active_threads: int
    gc_collections: Dict[str, int] = field(default_factory=dict)

@dataclass
class ApplicationMetrics:
    """Application-level performance metrics"""
    timestamp: datetime
    request_count: int
    request_rate: float
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate: float
    active_connections: int
    cache_hit_rate: float
    database_connections: int
    queue_size: int
    memory_objects: int
    memory_size_mb: float

@dataclass
class EndpointMetrics:
    """Per-endpoint performance metrics"""
    endpoint: str
    method: str
    request_count: int = 0
    total_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    error_count: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    status_codes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    last_request: Optional[datetime] = None

class MetricsCollector:
    """Comprehensive performance metrics collector"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.system_metrics: deque = deque(maxlen=1440)  # 24 hours of minute data
        self.application_metrics: deque = deque(maxlen=1440)
        self.endpoint_metrics: Dict[str, EndpointMetrics] = defaultdict(EndpointMetrics)
        self.custom_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        self.collection_thread = None
        self.running = False
        self.lock = threading.RLock()
        
        # Performance tracking
        self.request_start_times = {}
        self.active_requests = 0
        self.total_requests = 0
        self.total_errors = 0
        
        # Initialize system info
        self.process = psutil.Process()
        self.initial_disk_io = psutil.disk_io_counters()
        self.initial_network_io = psutil.net_io_counters()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize metrics collector with Flask app"""
        self.app = app
        
        # Set up request tracking
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_appcontext(self.cleanup_request)
        
        # Start metrics collection
        self.start_collection()
        
        logger.info("Metrics collector initialized")
    
    def start_collection(self):
        """Start background metrics collection"""
        if self.collection_thread and self.collection_thread.is_alive():
            return
        
        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_worker, daemon=True)
        self.collection_thread.start()
        logger.info("Metrics collection started")
    
    def stop_collection(self):
        """Stop background metrics collection"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Metrics collection stopped")
    
    def _collection_worker(self):
        """Background worker for metrics collection"""
        while self.running:
            try:
                self._collect_system_metrics()
                self._collect_application_metrics()
                time.sleep(60)  # Collect every minute
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                time.sleep(10)
    
    def _collect_system_metrics(self):
        """Collect system-level metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            
            # Disk usage
            disk_usage = psutil.disk_usage('/')
            current_disk_io = psutil.disk_io_counters()
            
            # Network I/O
            current_network_io = psutil.net_io_counters()
            
            # System load
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            # Process info
            try:
                open_files = len(self.process.open_files())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                open_files = 0
            
            active_threads = threading.active_count()
            
            # Garbage collection stats
            gc_stats = {}
            for generation in range(3):
                gc_stats[f'gen_{generation}'] = gc.get_count()[generation]
            
            metrics = SystemMetrics(
                timestamp=datetime.utcnow(),
                cpu_percent=cpu_percent,
                memory_percent=memory_info.percent,
                memory_used_mb=memory_info.used / (1024 * 1024),
                memory_available_mb=memory_info.available / (1024 * 1024),
                disk_usage_percent=disk_usage.percent,
                disk_io_read_mb=(current_disk_io.read_bytes - self.initial_disk_io.read_bytes) / (1024 * 1024),
                disk_io_write_mb=(current_disk_io.write_bytes - self.initial_disk_io.write_bytes) / (1024 * 1024),
                network_io_sent_mb=(current_network_io.bytes_sent - self.initial_network_io.bytes_sent) / (1024 * 1024),
                network_io_recv_mb=(current_network_io.bytes_recv - self.initial_network_io.bytes_recv) / (1024 * 1024),
                load_average=load_avg,
                open_files=open_files,
                active_threads=active_threads,
                gc_collections=gc_stats
            )
            
            with self.lock:
                self.system_metrics.append(metrics)
                
        except Exception as e:
            logger.error(f"System metrics collection error: {e}")
    
    def _collect_application_metrics(self):
        """Collect application-level metrics"""
        try:
            current_time = time.time()
            
            # Calculate request rate (requests per second)
            request_rate = 0.0
            if len(self.application_metrics) > 0:
                last_metrics = self.application_metrics[-1]
                time_diff = (current_time - last_metrics.timestamp.timestamp())
                if time_diff > 0:
                    request_diff = self.total_requests - last_metrics.request_count
                    request_rate = request_diff / time_diff
            
            # Calculate response time statistics
            response_times = []
            for endpoint_metrics in self.endpoint_metrics.values():
                if endpoint_metrics.response_times:
                    response_times.extend(list(endpoint_metrics.response_times))
            
            response_time_avg = statistics.mean(response_times) if response_times else 0.0
            response_time_p95 = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else 0.0
            response_time_p99 = statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else 0.0
            
            # Calculate error rate
            error_rate = (self.total_errors / self.total_requests * 100) if self.total_requests > 0 else 0.0
            
            # Get cache metrics (if available)
            cache_hit_rate = 0.0
            try:
                from performance.cache_manager import cache_manager
                cache_metrics = cache_manager.cache.get_metrics()
                if 'l1_memory' in cache_metrics:
                    cache_hit_rate = cache_metrics['l1_memory'].hit_rate
            except ImportError:
                pass
            
            # Database connection count (if available)
            database_connections = 0
            try:
                from sqlalchemy import inspect
                if self.app and hasattr(self.app, 'db'):
                    engine = self.app.db.engine
                    database_connections = engine.pool.size()
            except (ImportError, AttributeError):
                pass
            
            # Memory usage of Python objects
            memory_objects = len(gc.get_objects())
            memory_size_mb = sys.getsizeof(gc.get_objects()) / (1024 * 1024)
            
            metrics = ApplicationMetrics(
                timestamp=datetime.utcnow(),
                request_count=self.total_requests,
                request_rate=request_rate,
                response_time_avg=response_time_avg,
                response_time_p95=response_time_p95,
                response_time_p99=response_time_p99,
                error_rate=error_rate,
                active_connections=self.active_requests,
                cache_hit_rate=cache_hit_rate,
                database_connections=database_connections,
                queue_size=0,  # Would be implemented with actual queue
                memory_objects=memory_objects,
                memory_size_mb=memory_size_mb
            )
            
            with self.lock:
                self.application_metrics.append(metrics)
                
        except Exception as e:
            logger.error(f"Application metrics collection error: {e}")
    
    def before_request(self):
        """Track request start"""
        g.request_start_time = time.time()
        
        with self.lock:
            self.active_requests += 1
            self.total_requests += 1
    
    def after_request(self, response):
        """Track request completion"""
        if hasattr(g, 'request_start_time'):
            response_time = time.time() - g.request_start_time
            
            # Track endpoint metrics
            endpoint_key = f"{request.method}:{request.endpoint or 'unknown'}"
            
            with self.lock:
                if endpoint_key not in self.endpoint_metrics:
                    self.endpoint_metrics[endpoint_key] = EndpointMetrics(
                        endpoint=request.endpoint or 'unknown',
                        method=request.method
                    )
                
                metrics = self.endpoint_metrics[endpoint_key]
                metrics.request_count += 1
                metrics.total_response_time += response_time
                metrics.min_response_time = min(metrics.min_response_time, response_time)
                metrics.max_response_time = max(metrics.max_response_time, response_time)
                metrics.response_times.append(response_time)
                metrics.status_codes[response.status_code] += 1
                metrics.last_request = datetime.utcnow()
                
                if response.status_code >= 400:
                    metrics.error_count += 1
                    self.total_errors += 1
                
                self.active_requests -= 1
        
        return response
    
    def cleanup_request(self, exception=None):
        """Cleanup request tracking"""
        if hasattr(g, 'request_start_time'):
            delattr(g, 'request_start_time')
    
    def record_custom_metric(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record custom application metric"""
        metric_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'value': value,
            'labels': labels or {}
        }
        
        with self.lock:
            self.custom_metrics[name].append(metric_data)
    
    def get_system_metrics(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get system metrics for the last N minutes"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        with self.lock:
            return [
                {
                    'timestamp': m.timestamp.isoformat(),
                    'cpu_percent': m.cpu_percent,
                    'memory_percent': m.memory_percent,
                    'memory_used_mb': m.memory_used_mb,
                    'memory_available_mb': m.memory_available_mb,
                    'disk_usage_percent': m.disk_usage_percent,
                    'disk_io_read_mb': m.disk_io_read_mb,
                    'disk_io_write_mb': m.disk_io_write_mb,
                    'network_io_sent_mb': m.network_io_sent_mb,
                    'network_io_recv_mb': m.network_io_recv_mb,
                    'load_average': m.load_average,
                    'open_files': m.open_files,
                    'active_threads': m.active_threads,
                    'gc_collections': m.gc_collections
                }
                for m in self.system_metrics
                if m.timestamp >= cutoff_time
            ]
    
    def get_application_metrics(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get application metrics for the last N minutes"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        with self.lock:
            return [
                {
                    'timestamp': m.timestamp.isoformat(),
                    'request_count': m.request_count,
                    'request_rate': m.request_rate,
                    'response_time_avg': m.response_time_avg,
                    'response_time_p95': m.response_time_p95,
                    'response_time_p99': m.response_time_p99,
                    'error_rate': m.error_rate,
                    'active_connections': m.active_connections,
                    'cache_hit_rate': m.cache_hit_rate,
                    'database_connections': m.database_connections,
                    'queue_size': m.queue_size,
                    'memory_objects': m.memory_objects,
                    'memory_size_mb': m.memory_size_mb
                }
                for m in self.application_metrics
                if m.timestamp >= cutoff_time
            ]
    
    def get_endpoint_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get per-endpoint metrics"""
        with self.lock:
            result = {}
            for endpoint_key, metrics in self.endpoint_metrics.items():
                avg_response_time = (metrics.total_response_time / metrics.request_count 
                                   if metrics.request_count > 0 else 0.0)
                
                error_rate = (metrics.error_count / metrics.request_count * 100
                            if metrics.request_count > 0 else 0.0)
                
                response_times = list(metrics.response_times)
                p95_response_time = (statistics.quantiles(response_times, n=20)[18] 
                                   if len(response_times) > 20 else 0.0)
                
                result[endpoint_key] = {
                    'endpoint': metrics.endpoint,
                    'method': metrics.method,
                    'request_count': metrics.request_count,
                    'error_count': metrics.error_count,
                    'error_rate': error_rate,
                    'avg_response_time': avg_response_time,
                    'min_response_time': metrics.min_response_time if metrics.min_response_time != float('inf') else 0.0,
                    'max_response_time': metrics.max_response_time,
                    'p95_response_time': p95_response_time,
                    'status_codes': dict(metrics.status_codes),
                    'last_request': metrics.last_request.isoformat() if metrics.last_request else None
                }
            
            return result
    
    def get_custom_metrics(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get custom metrics"""
        with self.lock:
            return {name: list(values) for name, values in self.custom_metrics.items()}
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall system health status"""
        try:
            # Get latest metrics
            latest_system = self.system_metrics[-1] if self.system_metrics else None
            latest_app = self.application_metrics[-1] if self.application_metrics else None
            
            health_score = 100
            issues = []
            
            if latest_system:
                # Check system health
                if latest_system.cpu_percent > 90:
                    health_score -= 20
                    issues.append("High CPU usage")
                
                if latest_system.memory_percent > 90:
                    health_score -= 20
                    issues.append("High memory usage")
                
                if latest_system.disk_usage_percent > 90:
                    health_score -= 15
                    issues.append("High disk usage")
            
            if latest_app:
                # Check application health
                if latest_app.error_rate > 5:
                    health_score -= 25
                    issues.append("High error rate")
                
                if latest_app.response_time_p95 > 5.0:
                    health_score -= 15
                    issues.append("Slow response times")
            
            # Determine overall status
            if health_score >= 80:
                status = "healthy"
            elif health_score >= 60:
                status = "warning"
            else:
                status = "critical"
            
            return {
                'status': status,
                'health_score': max(0, health_score),
                'issues': issues,
                'timestamp': datetime.utcnow().isoformat(),
                'uptime_seconds': time.time() - self.process.create_time(),
                'active_requests': self.active_requests,
                'total_requests': self.total_requests,
                'total_errors': self.total_errors
            }
            
        except Exception as e:
            logger.error(f"Health status error: {e}")
            return {
                'status': 'error',
                'health_score': 0,
                'issues': [f"Health check failed: {str(e)}"],
                'timestamp': datetime.utcnow().isoformat()
            }

# Global metrics collector
metrics_collector = MetricsCollector()

# Decorators for custom metrics
def record_metric(metric_name: str, labels: Dict[str, str] = None):
    """Decorator to record custom metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Record success metric
                metrics_collector.record_custom_metric(
                    f"{metric_name}_duration",
                    execution_time,
                    {**(labels or {}), 'status': 'success'}
                )
                
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                
                # Record error metric
                metrics_collector.record_custom_metric(
                    f"{metric_name}_duration",
                    execution_time,
                    {**(labels or {}), 'status': 'error', 'error_type': type(e).__name__}
                )
                
                raise
        return wrapper
    return decorator

def count_metric(metric_name: str, labels: Dict[str, str] = None):
    """Decorator to count function calls"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Record call count
            metrics_collector.record_custom_metric(
                f"{metric_name}_count",
                1,
                labels
            )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Flask integration
def init_metrics(app: Flask):
    """Initialize metrics system with Flask app"""
    metrics_collector.init_app(app)
    
    # Add metrics endpoints
    @app.route('/api/metrics/system')
    def system_metrics():
        minutes = request.args.get('minutes', 60, type=int)
        return {
            'metrics': metrics_collector.get_system_metrics(minutes),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @app.route('/api/metrics/application')
    def application_metrics():
        minutes = request.args.get('minutes', 60, type=int)
        return {
            'metrics': metrics_collector.get_application_metrics(minutes),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @app.route('/api/metrics/endpoints')
    def endpoint_metrics():
        return {
            'metrics': metrics_collector.get_endpoint_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @app.route('/api/metrics/custom')
    def custom_metrics():
        return {
            'metrics': metrics_collector.get_custom_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @app.route('/api/health')
    def health_check():
        return metrics_collector.get_health_status()
    
    # Prometheus-compatible endpoint
    @app.route('/metrics')
    def prometheus_metrics():
        """Prometheus-compatible metrics endpoint"""
        lines = []
        
        # System metrics
        latest_system = metrics_collector.system_metrics[-1] if metrics_collector.system_metrics else None
        if latest_system:
            lines.extend([
                f'# HELP homenetmon_cpu_percent CPU usage percentage',
                f'# TYPE homenetmon_cpu_percent gauge',
                f'homenetmon_cpu_percent {latest_system.cpu_percent}',
                f'# HELP homenetmon_memory_percent Memory usage percentage',
                f'# TYPE homenetmon_memory_percent gauge',
                f'homenetmon_memory_percent {latest_system.memory_percent}',
            ])
        
        # Application metrics
        latest_app = metrics_collector.application_metrics[-1] if metrics_collector.application_metrics else None
        if latest_app:
            lines.extend([
                f'# HELP homenetmon_requests_total Total number of requests',
                f'# TYPE homenetmon_requests_total counter',
                f'homenetmon_requests_total {latest_app.request_count}',
                f'# HELP homenetmon_request_rate Requests per second',
                f'# TYPE homenetmon_request_rate gauge',
                f'homenetmon_request_rate {latest_app.request_rate}',
                f'# HELP homenetmon_response_time_avg Average response time',
                f'# TYPE homenetmon_response_time_avg gauge',
                f'homenetmon_response_time_avg {latest_app.response_time_avg}',
            ])
        
        return '\n'.join(lines), 200, {'Content-Type': 'text/plain; charset=utf-8'}
    
    # Cleanup on shutdown
    @app.teardown_appcontext
    def cleanup_metrics(exception):
        if not getattr(g, '_metrics_stopped', False):
            metrics_collector.stop_collection()
            g._metrics_stopped = True