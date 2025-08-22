# HomeNetMon Circuit Breaker Implementation
from flask import Flask, current_app
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, Optional, Union
from functools import wraps
from enum import Enum
from dataclasses import dataclass, field
import asyncio
import statistics
from collections import deque, defaultdict

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Circuit breaker active, blocking requests
    HALF_OPEN = "half_open" # Testing if service has recovered

@dataclass
class CircuitBreakerMetrics:
    """Circuit breaker performance metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_requests: int = 0
    circuit_opened_count: int = 0
    circuit_closed_count: int = 0
    average_response_time: float = 0.0
    success_rate: float = 100.0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5           # Number of failures to trigger circuit
    recovery_timeout: int = 60           # Seconds before trying half-open
    success_threshold: int = 3           # Successful calls to close circuit
    timeout: float = 30.0               # Request timeout in seconds
    expected_exception: tuple = (Exception,)  # Exceptions that count as failures
    sliding_window_size: int = 100      # Size of sliding window for metrics
    minimum_throughput: int = 10        # Minimum requests before circuit can open

class CircuitBreaker:
    """Production-ready circuit breaker implementation"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.next_attempt_time = None
        self.lock = threading.RLock()
        
        # Metrics tracking
        self.metrics = CircuitBreakerMetrics()
        self.response_times = deque(maxlen=self.config.sliding_window_size)
        self.request_results = deque(maxlen=self.config.sliding_window_size)
        
        logger.info(f"Circuit breaker '{name}' initialized")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator implementation"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self.lock:
            self.metrics.total_requests += 1
            
            # Check if circuit is open
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._move_to_half_open()
                else:
                    raise CircuitBreakerOpenException(
                        f"Circuit breaker '{self.name}' is open"
                    )
            
            start_time = time.time()
            
            try:
                # Execute the function with timeout
                result = self._execute_with_timeout(func, *args, **kwargs)
                
                # Record success
                execution_time = time.time() - start_time
                self._record_success(execution_time)
                
                return result
                
            except self.config.expected_exception as e:
                # Record failure
                execution_time = time.time() - start_time
                self._record_failure(execution_time, e)
                raise
            except TimeoutError as e:
                # Record timeout
                self.metrics.timeout_requests += 1
                self._record_failure(time.time() - start_time, e)
                raise
    
    def _execute_with_timeout(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout protection"""
        if asyncio.iscoroutinefunction(func):
            # Handle async functions
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(
                asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
            )
        else:
            # Handle sync functions with threading timeout
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.start()
            thread.join(timeout=self.config.timeout)
            
            if thread.is_alive():
                # Force thread termination is not safe, log warning
                logger.warning(f"Function timeout in circuit breaker '{self.name}'")
                raise TimeoutError(f"Function execution exceeded {self.config.timeout}s")
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
    
    def _record_success(self, execution_time: float):
        """Record successful execution"""
        self.metrics.successful_requests += 1
        self.metrics.last_success_time = datetime.utcnow()
        self.response_times.append(execution_time)
        self.request_results.append(True)
        
        # Update average response time
        if self.response_times:
            self.metrics.average_response_time = statistics.mean(self.response_times)
        
        # Update success rate
        if self.request_results:
            successes = sum(1 for r in self.request_results if r)
            self.metrics.success_rate = (successes / len(self.request_results)) * 100
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._move_to_closed()
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0  # Reset failure count on success
    
    def _record_failure(self, execution_time: float, exception: Exception):
        """Record failed execution"""
        self.metrics.failed_requests += 1
        self.metrics.last_failure_time = datetime.utcnow()
        self.response_times.append(execution_time)
        self.request_results.append(False)
        
        # Update metrics
        if self.response_times:
            self.metrics.average_response_time = statistics.mean(self.response_times)
        
        if self.request_results:
            successes = sum(1 for r in self.request_results if r)
            self.metrics.success_rate = (successes / len(self.request_results)) * 100
        
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        # Check if we should open the circuit
        if (self.state in [CircuitState.CLOSED, CircuitState.HALF_OPEN] and
            self.failure_count >= self.config.failure_threshold and
            self.metrics.total_requests >= self.config.minimum_throughput):
            self._move_to_open()
        
        logger.warning(f"Circuit breaker '{self.name}' recorded failure: {exception}")
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit"""
        if self.next_attempt_time is None:
            return True
        return time.time() >= self.next_attempt_time
    
    def _move_to_open(self):
        """Move circuit to open state"""
        self.state = CircuitState.OPEN
        self.next_attempt_time = time.time() + self.config.recovery_timeout
        self.metrics.circuit_opened_count += 1
        logger.warning(f"Circuit breaker '{self.name}' opened")
    
    def _move_to_half_open(self):
        """Move circuit to half-open state"""
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
        logger.info(f"Circuit breaker '{self.name}' moved to half-open")
    
    def _move_to_closed(self):
        """Move circuit to closed state"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.next_attempt_time = None
        self.metrics.circuit_closed_count += 1
        logger.info(f"Circuit breaker '{self.name}' closed")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics"""
        with self.lock:
            return {
                'name': self.name,
                'state': self.state.value,
                'failure_count': self.failure_count,
                'success_count': self.success_count,
                'metrics': {
                    'total_requests': self.metrics.total_requests,
                    'successful_requests': self.metrics.successful_requests,
                    'failed_requests': self.metrics.failed_requests,
                    'timeout_requests': self.metrics.timeout_requests,
                    'circuit_opened_count': self.metrics.circuit_opened_count,
                    'circuit_closed_count': self.metrics.circuit_closed_count,
                    'average_response_time': self.metrics.average_response_time,
                    'success_rate': self.metrics.success_rate,
                    'last_failure_time': self.metrics.last_failure_time.isoformat() if self.metrics.last_failure_time else None,
                    'last_success_time': self.metrics.last_success_time.isoformat() if self.metrics.last_success_time else None
                },
                'config': {
                    'failure_threshold': self.config.failure_threshold,
                    'recovery_timeout': self.config.recovery_timeout,
                    'success_threshold': self.config.success_threshold,
                    'timeout': self.config.timeout,
                    'sliding_window_size': self.config.sliding_window_size,
                    'minimum_throughput': self.config.minimum_throughput
                }
            }
    
    def reset(self):
        """Manually reset the circuit breaker"""
        with self.lock:
            self._move_to_closed()
            logger.info(f"Circuit breaker '{self.name}' manually reset")

class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open"""
    pass

class CircuitBreakerManager:
    """Manager for multiple circuit breakers"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.lock = threading.RLock()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize circuit breaker manager with Flask app"""
        self.app = app
        
        # Set default configurations
        app.config.setdefault('CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5)
        app.config.setdefault('CIRCUIT_BREAKER_RECOVERY_TIMEOUT', 60)
        app.config.setdefault('CIRCUIT_BREAKER_SUCCESS_THRESHOLD', 3)
        app.config.setdefault('CIRCUIT_BREAKER_TIMEOUT', 30.0)
        
        logger.info("Circuit breaker manager initialized")
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create a circuit breaker"""
        with self.lock:
            if name not in self.circuit_breakers:
                if config is None and self.app:
                    # Use Flask app configuration
                    config = CircuitBreakerConfig(
                        failure_threshold=self.app.config.get('CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5),
                        recovery_timeout=self.app.config.get('CIRCUIT_BREAKER_RECOVERY_TIMEOUT', 60),
                        success_threshold=self.app.config.get('CIRCUIT_BREAKER_SUCCESS_THRESHOLD', 3),
                        timeout=self.app.config.get('CIRCUIT_BREAKER_TIMEOUT', 30.0)
                    )
                
                self.circuit_breakers[name] = CircuitBreaker(name, config)
            
            return self.circuit_breakers[name]
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all circuit breakers"""
        with self.lock:
            return {
                name: cb.get_metrics() 
                for name, cb in self.circuit_breakers.items()
            }
    
    def reset_all(self):
        """Reset all circuit breakers"""
        with self.lock:
            for cb in self.circuit_breakers.values():
                cb.reset()
            logger.info("All circuit breakers reset")

# Global circuit breaker manager
circuit_breaker_manager = CircuitBreakerManager()

# Convenience decorators
def circuit_breaker(name: str, config: CircuitBreakerConfig = None):
    """Decorator to add circuit breaker protection to a function"""
    def decorator(func: Callable) -> Callable:
        cb = circuit_breaker_manager.get_circuit_breaker(name, config)
        return cb(func)
    return decorator

def database_circuit_breaker(func: Callable) -> Callable:
    """Specialized circuit breaker for database operations"""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30,
        success_threshold=2,
        timeout=10.0,
        expected_exception=(Exception,)
    )
    cb = circuit_breaker_manager.get_circuit_breaker(f"db_{func.__name__}", config)
    return cb(func)

def api_circuit_breaker(func: Callable) -> Callable:
    """Specialized circuit breaker for API calls"""
    config = CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=60,
        success_threshold=3,
        timeout=30.0,
        expected_exception=(Exception,)
    )
    cb = circuit_breaker_manager.get_circuit_breaker(f"api_{func.__name__}", config)
    return cb(func)

def cache_circuit_breaker(func: Callable) -> Callable:
    """Specialized circuit breaker for cache operations"""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=15,
        success_threshold=2,
        timeout=5.0,
        expected_exception=(Exception,)
    )
    cb = circuit_breaker_manager.get_circuit_breaker(f"cache_{func.__name__}", config)
    return cb(func)

# Flask integration
def init_circuit_breakers(app: Flask):
    """Initialize circuit breaker system with Flask app"""
    circuit_breaker_manager.init_app(app)
    
    # Add circuit breaker metrics endpoint
    @app.route('/api/circuit-breakers/metrics')
    def circuit_breaker_metrics():
        return {
            'circuit_breakers': circuit_breaker_manager.get_all_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Add circuit breaker reset endpoint
    @app.route('/api/circuit-breakers/reset', methods=['POST'])
    def reset_circuit_breakers():
        try:
            if request.is_json and 'name' in request.json:
                # Reset specific circuit breaker
                name = request.json['name']
                cb = circuit_breaker_manager.get_circuit_breaker(name)
                cb.reset()
                return {'success': True, 'message': f'Circuit breaker {name} reset'}
            else:
                # Reset all circuit breakers
                circuit_breaker_manager.reset_all()
                return {'success': True, 'message': 'All circuit breakers reset'}
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500