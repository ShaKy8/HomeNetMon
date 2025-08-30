import logging
import threading
import time
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import signal
import sys

logger = logging.getLogger(__name__)

class ThreadStatus(Enum):
    """Thread status enumeration."""
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class ManagedThread:
    """Represents a managed thread with lifecycle control."""
    name: str
    target: Callable
    args: tuple = ()
    kwargs: dict = None
    daemon: bool = True
    thread: Optional[threading.Thread] = None
    status: ThreadStatus = ThreadStatus.IDLE
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    error: Optional[str] = None
    stop_event: Optional[threading.Event] = None
    
    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}
        self.stop_event = threading.Event()

class ThreadManager:
    """Manages threads with proper lifecycle management and monitoring."""
    
    def __init__(self, max_threads: int = 20):
        self.max_threads = max_threads
        self.threads: Dict[str, ManagedThread] = {}
        self._lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        
        # Start monitor thread
        self._start_monitor()
        
        logger.info(f"ThreadManager initialized with max_threads={max_threads}")
        
    def _start_monitor(self):
        """Start the monitor thread that checks thread health."""
        def monitor():
            while not self.shutdown_event.is_set():
                try:
                    self._check_thread_health()
                    time.sleep(5)  # Check every 5 seconds
                except Exception as e:
                    logger.error(f"Monitor thread error: {e}")
                    
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
        logger.debug("Monitor thread started")
        
    def _check_thread_health(self):
        """Check health of all managed threads."""
        with self._lock:
            for name, managed_thread in self.threads.items():
                if managed_thread.thread and managed_thread.status == ThreadStatus.RUNNING:
                    if not managed_thread.thread.is_alive():
                        logger.warning(f"Thread '{name}' died unexpectedly")
                        managed_thread.status = ThreadStatus.ERROR
                        managed_thread.stopped_at = datetime.now()
                        
                        # Auto-restart critical threads if configured
                        if managed_thread.kwargs.get('auto_restart', False):
                            logger.info(f"Auto-restarting thread '{name}'")
                            self._start_thread_internal(managed_thread)
                            
    def register_thread(self, name: str, target: Callable,
                       args: tuple = (), kwargs: dict = None,
                       daemon: bool = True, auto_restart: bool = False) -> bool:
        """Register a new thread."""
        with self._lock:
            if name in self.threads:
                logger.warning(f"Thread '{name}' already registered")
                return False
                
            if len(self.threads) >= self.max_threads:
                logger.error(f"Maximum thread limit ({self.max_threads}) reached")
                return False
                
            kwargs = kwargs or {}
            kwargs['auto_restart'] = auto_restart
            
            managed_thread = ManagedThread(
                name=name,
                target=target,
                args=args,
                kwargs=kwargs,
                daemon=daemon
            )
            
            self.threads[name] = managed_thread
            logger.info(f"Registered thread: {name}")
            return True
            
    def start_thread(self, name: str) -> bool:
        """Start a registered thread."""
        with self._lock:
            if name not in self.threads:
                logger.error(f"Thread '{name}' not registered")
                return False
                
            managed_thread = self.threads[name]
            
            if managed_thread.status == ThreadStatus.RUNNING:
                logger.warning(f"Thread '{name}' already running")
                return False
                
            return self._start_thread_internal(managed_thread)
            
    def _start_thread_internal(self, managed_thread: ManagedThread) -> bool:
        """Internal method to start a thread."""
        try:
            # Reset stop event
            managed_thread.stop_event.clear()
            
            # Wrap target to handle lifecycle
            def thread_wrapper():
                try:
                    managed_thread.status = ThreadStatus.RUNNING
                    managed_thread.started_at = datetime.now()
                    managed_thread.error = None
                    
                    logger.info(f"Thread '{managed_thread.name}' started")
                    
                    # Pass stop_event if target accepts it
                    import inspect
                    sig = inspect.signature(managed_thread.target)
                    if 'stop_event' in sig.parameters:
                        managed_thread.kwargs['stop_event'] = managed_thread.stop_event
                        
                    result = managed_thread.target(*managed_thread.args, **managed_thread.kwargs)
                    
                    managed_thread.status = ThreadStatus.STOPPED
                    managed_thread.stopped_at = datetime.now()
                    logger.info(f"Thread '{managed_thread.name}' completed successfully")
                    return result
                    
                except Exception as e:
                    logger.error(f"Thread '{managed_thread.name}' crashed: {e}")
                    managed_thread.status = ThreadStatus.ERROR
                    managed_thread.error = str(e)
                    managed_thread.stopped_at = datetime.now()
                    raise
                    
            managed_thread.thread = threading.Thread(
                target=thread_wrapper,
                name=managed_thread.name,
                daemon=managed_thread.daemon
            )
            managed_thread.thread.start()
            return True
            
        except Exception as e:
            logger.error(f"Failed to start thread '{managed_thread.name}': {e}")
            managed_thread.status = ThreadStatus.ERROR
            managed_thread.error = str(e)
            return False
            
    def stop_thread(self, name: str, timeout: float = 5.0) -> bool:
        """Stop a running thread gracefully."""
        with self._lock:
            if name not in self.threads:
                logger.error(f"Thread '{name}' not registered")
                return False
                
            managed_thread = self.threads[name]
            
            if managed_thread.status != ThreadStatus.RUNNING:
                logger.warning(f"Thread '{name}' not running")
                return False
                
            try:
                managed_thread.status = ThreadStatus.STOPPING
                managed_thread.stop_event.set()
                
                # Wait for thread to stop
                if managed_thread.thread:
                    managed_thread.thread.join(timeout)
                    
                    if managed_thread.thread.is_alive():
                        logger.warning(f"Thread '{name}' did not stop within timeout")
                        return False
                        
                managed_thread.status = ThreadStatus.STOPPED
                managed_thread.stopped_at = datetime.now()
                logger.info(f"Thread '{name}' stopped")
                return True
                
            except Exception as e:
                logger.error(f"Failed to stop thread '{name}': {e}")
                return False
                
    def start_all(self) -> Dict[str, bool]:
        """Start all registered threads."""
        results = {}
        for name in list(self.threads.keys()):
            results[name] = self.start_thread(name)
        return results
        
    def stop_all(self, timeout: float = 5.0) -> Dict[str, bool]:
        """Stop all running threads."""
        results = {}
        for name in list(self.threads.keys()):
            if self.threads[name].status == ThreadStatus.RUNNING:
                results[name] = self.stop_thread(name, timeout)
        return results
        
    def get_status(self, name: str) -> Optional[ThreadStatus]:
        """Get status of a specific thread."""
        with self._lock:
            if name in self.threads:
                return self.threads[name].status
            return None
            
    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed status of all threads."""
        with self._lock:
            statuses = {}
            for name, thread in self.threads.items():
                statuses[name] = {
                    'status': thread.status.value,
                    'started_at': thread.started_at.isoformat() if thread.started_at else None,
                    'stopped_at': thread.stopped_at.isoformat() if thread.stopped_at else None,
                    'error': thread.error,
                    'daemon': thread.daemon,
                    'alive': thread.thread.is_alive() if thread.thread else False
                }
            return statuses
            
    def remove_thread(self, name: str) -> bool:
        """Remove a stopped thread from management."""
        with self._lock:
            if name not in self.threads:
                return False
                
            thread = self.threads[name]
            if thread.status == ThreadStatus.RUNNING:
                logger.error(f"Cannot remove running thread '{name}'")
                return False
                
            del self.threads[name]
            logger.info(f"Removed thread '{name}'")
            return True
            
    def cleanup_stopped_threads(self) -> int:
        """Remove all stopped threads from management."""
        with self._lock:
            to_remove = []
            for name, thread in self.threads.items():
                if thread.status in [ThreadStatus.STOPPED, ThreadStatus.ERROR]:
                    to_remove.append(name)
                    
            for name in to_remove:
                del self.threads[name]
                
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} stopped threads")
            return len(to_remove)
            
    def shutdown(self, timeout: float = 10.0):
        """Gracefully shutdown all threads."""
        logger.info("Initiating ThreadManager shutdown")
        
        # Signal shutdown
        self.shutdown_event.set()
        
        # Stop all threads
        self.stop_all(timeout)
        
        # Wait for monitor thread
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            
        logger.info("ThreadManager shutdown complete")
        
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown()
        sys.exit(0)
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get thread manager metrics."""
        with self._lock:
            status_counts = {}
            for status in ThreadStatus:
                status_counts[status.value] = sum(
                    1 for t in self.threads.values() if t.status == status
                )
                
            return {
                'total_threads': len(self.threads),
                'max_threads': self.max_threads,
                'status_counts': status_counts,
                'uptime': {
                    name: (datetime.now() - thread.started_at).total_seconds()
                    for name, thread in self.threads.items()
                    if thread.started_at and thread.status == ThreadStatus.RUNNING
                }
            }