import logging
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import signal
import sys

logger = logging.getLogger(__name__)

class ServiceStatus(Enum):
    """Service status enumeration."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"

@dataclass
class Service:
    """Represents a managed service."""
    name: str
    target: Callable
    args: tuple = ()
    kwargs: dict = None
    daemon: bool = True
    status: ServiceStatus = ServiceStatus.STOPPED
    future: Optional[Future] = None
    
    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}

class ServiceManager:
    """Manages background services with proper lifecycle management."""
    
    def __init__(self, max_workers: int = 10):
        self.services: Dict[str, Service] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.shutdown_event = threading.Event()
        self._lock = threading.Lock()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        
        logger.info(f"ServiceManager initialized with max_workers={max_workers}")
        
    def register_service(self, name: str, target: Callable, 
                        args: tuple = (), kwargs: dict = None,
                        daemon: bool = True) -> None:
        """Register a new service."""
        with self._lock:
            if name in self.services:
                logger.warning(f"Service '{name}' already registered, replacing")
                
            service = Service(
                name=name,
                target=target,
                args=args,
                kwargs=kwargs or {},
                daemon=daemon
            )
            self.services[name] = service
            logger.info(f"Registered service: {name}")
            
    def start_service(self, name: str) -> bool:
        """Start a registered service."""
        with self._lock:
            if name not in self.services:
                logger.error(f"Service '{name}' not registered")
                return False
                
            service = self.services[name]
            
            if service.status in [ServiceStatus.RUNNING, ServiceStatus.STARTING]:
                logger.warning(f"Service '{name}' already running or starting")
                return False
                
            try:
                service.status = ServiceStatus.STARTING
                
                # Wrap the service target to handle lifecycle
                def service_wrapper():
                    try:
                        logger.info(f"Starting service: {name}")
                        service.status = ServiceStatus.RUNNING
                        return service.target(*service.args, **service.kwargs)
                    except Exception as e:
                        logger.error(f"Service '{name}' crashed: {e}")
                        service.status = ServiceStatus.ERROR
                        raise
                    finally:
                        if service.status != ServiceStatus.ERROR:
                            service.status = ServiceStatus.STOPPED
                        logger.info(f"Service '{name}' stopped")
                        
                service.future = self.executor.submit(service_wrapper)
                return True
                
            except Exception as e:
                logger.error(f"Failed to start service '{name}': {e}")
                service.status = ServiceStatus.ERROR
                return False
                
    def stop_service(self, name: str, timeout: float = 5.0) -> bool:
        """Stop a running service."""
        with self._lock:
            if name not in self.services:
                logger.error(f"Service '{name}' not registered")
                return False
                
            service = self.services[name]
            
            if service.status != ServiceStatus.RUNNING:
                logger.warning(f"Service '{name}' not running")
                return False
                
            try:
                service.status = ServiceStatus.STOPPING
                
                if service.future:
                    # Cancel the future (will not stop already running task)
                    service.future.cancel()
                    
                service.status = ServiceStatus.STOPPED
                logger.info(f"Service '{name}' stopped")
                return True
                
            except Exception as e:
                logger.error(f"Failed to stop service '{name}': {e}")
                return False
                
    def start_all(self) -> None:
        """Start all registered services."""
        logger.info("Starting all services")
        for name in list(self.services.keys()):
            self.start_service(name)
            
    def stop_all(self, timeout: float = 5.0) -> None:
        """Stop all running services."""
        logger.info("Stopping all services")
        for name in list(self.services.keys()):
            self.stop_service(name, timeout)
            
    def get_status(self, name: str) -> Optional[ServiceStatus]:
        """Get the status of a service."""
        with self._lock:
            if name in self.services:
                return self.services[name].status
            return None
            
    def get_all_statuses(self) -> Dict[str, ServiceStatus]:
        """Get status of all services."""
        with self._lock:
            return {name: service.status for name, service in self.services.items()}
            
    def shutdown(self, timeout: float = 10.0) -> None:
        """Gracefully shutdown all services and the executor."""
        logger.info("Initiating graceful shutdown")
        
        # Set shutdown event
        self.shutdown_event.set()
        
        # Stop all services
        self.stop_all(timeout)
        
        # Shutdown executor
        self.executor.shutdown(wait=True, timeout=timeout)
        logger.info("ServiceManager shutdown complete")
        
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown()
        sys.exit(0)
        
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on all services."""
        statuses = self.get_all_statuses()
        
        # Count services by status
        status_counts = {}
        for status in ServiceStatus:
            status_counts[status.value] = sum(1 for s in statuses.values() if s == status)
            
        # Determine overall health
        if status_counts.get(ServiceStatus.ERROR.value, 0) > 0:
            health = "unhealthy"
        elif status_counts.get(ServiceStatus.RUNNING.value, 0) == len(self.services):
            health = "healthy"
        else:
            health = "degraded"
            
        return {
            'health': health,
            'total_services': len(self.services),
            'status_counts': status_counts,
            'services': {name: status.value for name, status in statuses.items()}
        }
        
    @classmethod
    def create_default(cls, app) -> 'ServiceManager':
        """Create a ServiceManager with all default services."""
        manager = cls(max_workers=15)
        
        # Import services
        from monitoring.scanner import NetworkScanner
        from monitoring.monitor import DeviceMonitor
        from monitoring.alerts import AlertManager
        from monitoring.bandwidth_monitor import BandwidthMonitor
        
        # Create service instances
        scanner = NetworkScanner(app)
        monitor = DeviceMonitor(None, app)  # socketio will be set later
        alert_manager = AlertManager(app)
        bandwidth_monitor = BandwidthMonitor(app)
        
        # Register core services
        manager.register_service(
            'network_scanner',
            scanner.start_continuous_scan,
            daemon=True
        )
        
        manager.register_service(
            'device_monitor',
            monitor.start_monitoring,
            daemon=True
        )
        
        manager.register_service(
            'alert_manager',
            alert_manager.start_monitoring,
            daemon=True
        )
        
        manager.register_service(
            'bandwidth_monitor',
            bandwidth_monitor.start_monitoring,
            daemon=True
        )
        
        # Store instances for later access
        manager.scanner = scanner
        manager.monitor = monitor
        manager.alert_manager = alert_manager
        manager.bandwidth_monitor = bandwidth_monitor
        
        logger.info("Created default service manager with core services")
        return manager