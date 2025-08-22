# HomeNetMon Application-Level Load Balancing
from flask import Flask, request, g, current_app
import random
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict, deque
import statistics
from datetime import datetime, timedelta
import asyncio
import concurrent.futures
from functools import wraps

logger = logging.getLogger(__name__)

class LoadBalancingAlgorithm(Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_LEAST_CONNECTIONS = "weighted_least_connections"
    IP_HASH = "ip_hash"
    LEAST_RESPONSE_TIME = "least_response_time"
    RANDOM = "random"
    WEIGHTED_RANDOM = "weighted_random"

class BackendStatus(Enum):
    """Backend server status"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"

@dataclass
class BackendServer:
    """Backend server configuration"""
    name: str
    host: str
    port: int
    weight: int = 1
    max_connections: int = 100
    status: BackendStatus = BackendStatus.HEALTHY
    health_check_url: str = "/health"
    timeout: float = 5.0
    
    # Runtime metrics
    active_connections: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    last_health_check: Optional[datetime] = None
    consecutive_failures: int = 0

@dataclass
class LoadBalancerConfig:
    """Load balancer configuration"""
    algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN
    health_check_interval: int = 30  # seconds
    health_check_timeout: float = 5.0
    health_check_threshold: int = 3  # failures before marking unhealthy
    recovery_threshold: int = 2  # successes before marking healthy
    session_affinity: bool = False
    sticky_session_cookie: str = "lb_session"

class LoadBalancer:
    """Application-level load balancer"""
    
    def __init__(self, name: str, config: LoadBalancerConfig = None):
        self.name = name
        self.config = config or LoadBalancerConfig()
        self.backends: List[BackendServer] = []
        self.current_index = 0
        self.lock = threading.RLock()
        self.session_map: Dict[str, str] = {}
        self.health_check_thread = None
        self.running = False
        
        logger.info(f"Load balancer '{name}' initialized")
    
    def add_backend(self, backend: BackendServer):
        """Add a backend server"""
        with self.lock:
            self.backends.append(backend)
            logger.info(f"Added backend {backend.name} to load balancer {self.name}")
    
    def remove_backend(self, backend_name: str):
        """Remove a backend server"""
        with self.lock:
            self.backends = [b for b in self.backends if b.name != backend_name]
            logger.info(f"Removed backend {backend_name} from load balancer {self.name}")
    
    def get_backend(self, request_context: Dict[str, Any] = None) -> Optional[BackendServer]:
        """Get next backend server based on load balancing algorithm"""
        with self.lock:
            healthy_backends = [b for b in self.backends if b.status == BackendStatus.HEALTHY]
            
            if not healthy_backends:
                logger.warning(f"No healthy backends available for {self.name}")
                return None
            
            # Check for session affinity
            if self.config.session_affinity and request_context:
                session_id = self._get_session_id(request_context)
                if session_id in self.session_map:
                    backend_name = self.session_map[session_id]
                    backend = next((b for b in healthy_backends if b.name == backend_name), None)
                    if backend:
                        return backend
            
            # Apply load balancing algorithm
            if self.config.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
                backend = self._round_robin(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN:
                backend = self._weighted_round_robin(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
                backend = self._least_connections(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.WEIGHTED_LEAST_CONNECTIONS:
                backend = self._weighted_least_connections(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.IP_HASH:
                backend = self._ip_hash(healthy_backends, request_context)
            elif self.config.algorithm == LoadBalancingAlgorithm.LEAST_RESPONSE_TIME:
                backend = self._least_response_time(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.RANDOM:
                backend = self._random(healthy_backends)
            elif self.config.algorithm == LoadBalancingAlgorithm.WEIGHTED_RANDOM:
                backend = self._weighted_random(healthy_backends)
            else:
                backend = self._round_robin(healthy_backends)
            
            # Update session affinity
            if self.config.session_affinity and request_context and backend:
                session_id = self._get_session_id(request_context)
                self.session_map[session_id] = backend.name
            
            return backend
    
    def _get_session_id(self, request_context: Dict[str, Any]) -> str:
        """Get session ID for sticky sessions"""
        if 'session_id' in request_context:
            return request_context['session_id']
        elif 'client_ip' in request_context:
            return hashlib.md5(request_context['client_ip'].encode()).hexdigest()
        else:
            return 'default'
    
    def _round_robin(self, backends: List[BackendServer]) -> BackendServer:
        """Round robin load balancing"""
        backend = backends[self.current_index % len(backends)]
        self.current_index += 1
        return backend
    
    def _weighted_round_robin(self, backends: List[BackendServer]) -> BackendServer:
        """Weighted round robin load balancing"""
        total_weight = sum(b.weight for b in backends)
        if total_weight == 0:
            return self._round_robin(backends)
        
        # Create weighted list
        weighted_backends = []
        for backend in backends:
            weighted_backends.extend([backend] * backend.weight)
        
        backend = weighted_backends[self.current_index % len(weighted_backends)]
        self.current_index += 1
        return backend
    
    def _least_connections(self, backends: List[BackendServer]) -> BackendServer:
        """Least connections load balancing"""
        return min(backends, key=lambda b: b.active_connections)
    
    def _weighted_least_connections(self, backends: List[BackendServer]) -> BackendServer:
        """Weighted least connections load balancing"""
        def connection_ratio(backend):
            if backend.weight == 0:
                return float('inf')
            return backend.active_connections / backend.weight
        
        return min(backends, key=connection_ratio)
    
    def _ip_hash(self, backends: List[BackendServer], request_context: Dict[str, Any]) -> BackendServer:
        """IP hash load balancing"""
        client_ip = request_context.get('client_ip', '127.0.0.1')
        hash_value = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
        return backends[hash_value % len(backends)]
    
    def _least_response_time(self, backends: List[BackendServer]) -> BackendServer:
        """Least response time load balancing"""
        def avg_response_time(backend):
            if not backend.response_times:
                return 0
            return statistics.mean(backend.response_times)
        
        return min(backends, key=avg_response_time)
    
    def _random(self, backends: List[BackendServer]) -> BackendServer:
        """Random load balancing"""
        return random.choice(backends)
    
    def _weighted_random(self, backends: List[BackendServer]) -> BackendServer:
        """Weighted random load balancing"""
        total_weight = sum(b.weight for b in backends)
        if total_weight == 0:
            return self._random(backends)
        
        r = random.uniform(0, total_weight)
        cumulative_weight = 0
        
        for backend in backends:
            cumulative_weight += backend.weight
            if r <= cumulative_weight:
                return backend
        
        return backends[-1]  # Fallback
    
    def start_health_checks(self):
        """Start health check monitoring"""
        if self.health_check_thread and self.health_check_thread.is_alive():
            return
        
        self.running = True
        self.health_check_thread = threading.Thread(target=self._health_check_worker, daemon=True)
        self.health_check_thread.start()
        logger.info(f"Health checks started for load balancer {self.name}")
    
    def stop_health_checks(self):
        """Stop health check monitoring"""
        self.running = False
        if self.health_check_thread:
            self.health_check_thread.join(timeout=5)
        logger.info(f"Health checks stopped for load balancer {self.name}")
    
    def _health_check_worker(self):
        """Background worker for health checks"""
        while self.running:
            try:
                for backend in self.backends:
                    self._check_backend_health(backend)
                time.sleep(self.config.health_check_interval)
            except Exception as e:
                logger.error(f"Health check error: {e}")
                time.sleep(5)
    
    def _check_backend_health(self, backend: BackendServer):
        """Check health of a single backend"""
        try:
            import requests
            
            url = f"http://{backend.host}:{backend.port}{backend.health_check_url}"
            start_time = time.time()
            
            response = requests.get(url, timeout=backend.timeout)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Successful health check
                with self.lock:
                    backend.consecutive_failures = 0
                    backend.last_health_check = datetime.utcnow()
                    backend.response_times.append(response_time)
                    
                    if backend.status == BackendStatus.UNHEALTHY:
                        backend.status = BackendStatus.HEALTHY
                        logger.info(f"Backend {backend.name} marked as healthy")
            else:
                self._mark_backend_failure(backend)
                
        except Exception as e:
            self._mark_backend_failure(backend)
            logger.warning(f"Health check failed for {backend.name}: {e}")
    
    def _mark_backend_failure(self, backend: BackendServer):
        """Mark backend as failed"""
        with self.lock:
            backend.consecutive_failures += 1
            backend.failed_requests += 1
            
            if (backend.consecutive_failures >= self.config.health_check_threshold and
                backend.status == BackendStatus.HEALTHY):
                backend.status = BackendStatus.UNHEALTHY
                logger.warning(f"Backend {backend.name} marked as unhealthy")
    
    def record_request(self, backend: BackendServer, response_time: float, success: bool):
        """Record request metrics"""
        with self.lock:
            backend.total_requests += 1
            backend.response_times.append(response_time)
            
            if not success:
                backend.failed_requests += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics"""
        with self.lock:
            backend_stats = []
            for backend in self.backends:
                avg_response_time = 0
                if backend.response_times:
                    avg_response_time = statistics.mean(backend.response_times)
                
                success_rate = 0
                if backend.total_requests > 0:
                    success_rate = ((backend.total_requests - backend.failed_requests) / 
                                  backend.total_requests) * 100
                
                backend_stats.append({
                    'name': backend.name,
                    'host': backend.host,
                    'port': backend.port,
                    'status': backend.status.value,
                    'weight': backend.weight,
                    'active_connections': backend.active_connections,
                    'total_requests': backend.total_requests,
                    'failed_requests': backend.failed_requests,
                    'success_rate': success_rate,
                    'average_response_time': avg_response_time,
                    'consecutive_failures': backend.consecutive_failures,
                    'last_health_check': backend.last_health_check.isoformat() if backend.last_health_check else None
                })
            
            return {
                'name': self.name,
                'algorithm': self.config.algorithm.value,
                'total_backends': len(self.backends),
                'healthy_backends': len([b for b in self.backends if b.status == BackendStatus.HEALTHY]),
                'session_affinity': self.config.session_affinity,
                'backends': backend_stats
            }

class LoadBalancerManager:
    """Manager for multiple load balancers"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.load_balancers: Dict[str, LoadBalancer] = {}
        self.lock = threading.RLock()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize load balancer manager with Flask app"""
        self.app = app
        
        # Set up load balancer configurations
        self._setup_default_load_balancers()
        
        logger.info("Load balancer manager initialized")
    
    def _setup_default_load_balancers(self):
        """Set up default load balancers"""
        # API load balancer
        api_config = LoadBalancerConfig(
            algorithm=LoadBalancingAlgorithm.LEAST_RESPONSE_TIME,
            session_affinity=False
        )
        self.create_load_balancer('api', api_config)
        
        # Web UI load balancer
        web_config = LoadBalancerConfig(
            algorithm=LoadBalancingAlgorithm.IP_HASH,
            session_affinity=True
        )
        self.create_load_balancer('web', web_config)
        
        # Database connection pool
        db_config = LoadBalancerConfig(
            algorithm=LoadBalancingAlgorithm.LEAST_CONNECTIONS,
            session_affinity=False
        )
        self.create_load_balancer('database', db_config)
    
    def create_load_balancer(self, name: str, config: LoadBalancerConfig = None) -> LoadBalancer:
        """Create a new load balancer"""
        with self.lock:
            if name in self.load_balancers:
                raise ValueError(f"Load balancer '{name}' already exists")
            
            lb = LoadBalancer(name, config)
            self.load_balancers[name] = lb
            lb.start_health_checks()
            
            return lb
    
    def get_load_balancer(self, name: str) -> Optional[LoadBalancer]:
        """Get a load balancer by name"""
        return self.load_balancers.get(name)
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all load balancers"""
        with self.lock:
            return {
                name: lb.get_stats()
                for name, lb in self.load_balancers.items()
            }
    
    def shutdown(self):
        """Shutdown all load balancers"""
        with self.lock:
            for lb in self.load_balancers.values():
                lb.stop_health_checks()
            logger.info("All load balancers shut down")

# Global load balancer manager
load_balancer_manager = LoadBalancerManager()

# Decorators and context managers

class LoadBalancedRequest:
    """Context manager for load balanced requests"""
    
    def __init__(self, load_balancer_name: str, request_context: Dict[str, Any] = None):
        self.load_balancer_name = load_balancer_name
        self.request_context = request_context or {}
        self.backend = None
        self.start_time = None
        
    def __enter__(self) -> Optional[BackendServer]:
        lb = load_balancer_manager.get_load_balancer(self.load_balancer_name)
        if not lb:
            raise ValueError(f"Load balancer '{self.load_balancer_name}' not found")
        
        self.backend = lb.get_backend(self.request_context)
        if self.backend:
            self.backend.active_connections += 1
            self.start_time = time.time()
        
        return self.backend
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.backend and self.start_time:
            response_time = time.time() - self.start_time
            success = exc_type is None
            
            lb = load_balancer_manager.get_load_balancer(self.load_balancer_name)
            if lb:
                lb.record_request(self.backend, response_time, success)
            
            self.backend.active_connections -= 1

def load_balanced(load_balancer_name: str):
    """Decorator for load balanced function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            request_context = {
                'client_ip': request.remote_addr if request else '127.0.0.1',
                'session_id': request.cookies.get('session') if request else None
            }
            
            with LoadBalancedRequest(load_balancer_name, request_context) as backend:
                if not backend:
                    raise Exception(f"No healthy backends available for {load_balancer_name}")
                
                # Add backend info to function kwargs
                kwargs['_backend'] = backend
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

# Flask integration
def init_load_balancers(app: Flask):
    """Initialize load balancer system with Flask app"""
    load_balancer_manager.init_app(app)
    
    # Add load balancer stats endpoint
    @app.route('/api/load-balancers/stats')
    def load_balancer_stats():
        return {
            'load_balancers': load_balancer_manager.get_all_stats(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Graceful shutdown
    @app.teardown_appcontext
    def shutdown_load_balancers(exception):
        if not getattr(g, '_load_balancers_shutdown', False):
            load_balancer_manager.shutdown()
            g._load_balancers_shutdown = True