"""
Structured logging framework with request tracing and performance monitoring.
"""

import logging
import json
import uuid
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from functools import wraps
from flask import Flask, request, g, has_request_context
from contextlib import contextmanager
from enum import Enum
import sys
import os

class LogLevel(Enum):
    """Extended log levels for structured logging."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    AUDIT = 60

class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra
        
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Base log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add thread information
        log_entry['thread'] = {
            'id': record.thread,
            'name': record.threadName
        }
        
        # Add process information
        log_entry['process'] = {
            'id': record.process,
            'name': record.processName if hasattr(record, 'processName') else None
        }
        
        # Add request context if available
        if has_request_context():
            log_entry['request'] = self._get_request_context()
            
        # Add user context if available
        if hasattr(g, 'current_user') and g.current_user:
            log_entry['user'] = {
                'username': g.current_user.get('username'),
                'roles': g.current_user.get('roles', [])
            }
            
        # Add trace ID if available
        if hasattr(g, 'trace_id'):
            log_entry['trace_id'] = g.trace_id
            
        # Add exception information
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        # Add extra fields
        if self.include_extra and hasattr(record, 'extra') and record.extra:
            log_entry['extra'] = record.extra
            
        # Add any additional attributes
        for attr, value in record.__dict__.items():
            if attr not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 'exc_text', 
                          'stack_info', 'extra'] and not attr.startswith('_'):
                log_entry[attr] = value
                
        return json.dumps(log_entry, default=str)
        
    def _get_request_context(self) -> Dict[str, Any]:
        """Extract request context information."""
        context = {
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'content_type': request.content_type
        }
        
        # Add query parameters (sanitized)
        if request.args:
            context['query_params'] = dict(request.args)
            
        # Add request ID if available
        if hasattr(request, 'id'):
            context['id'] = request.id
            
        return context

class StructuredLogger:
    """Enhanced logger with structured logging capabilities."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self._local = threading.local()
        
    def _log_with_extra(self, level: int, message: str, 
                       extra: Optional[Dict[str, Any]] = None, 
                       exc_info: Optional[Any] = None, **kwargs):
        """Log message with extra structured data."""
        if extra:
            # Merge with any existing extra data
            all_extra = getattr(self.logger, 'extra', {})
            all_extra.update(extra)
            all_extra.update(kwargs)
            self.logger.log(level, message, extra=all_extra, exc_info=exc_info)
        else:
            self.logger.log(level, message, exc_info=exc_info)
            
    def trace(self, message: str, **kwargs):
        """Log trace message."""
        self._log_with_extra(LogLevel.TRACE.value, message, **kwargs)
        
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log_with_extra(logging.DEBUG, message, **kwargs)
        
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log_with_extra(logging.INFO, message, **kwargs)
        
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log_with_extra(logging.WARNING, message, **kwargs)
        
    def error(self, message: str, exc_info: Optional[Any] = None, **kwargs):
        """Log error message."""
        self._log_with_extra(logging.ERROR, message, exc_info=exc_info, **kwargs)
        
    def critical(self, message: str, exc_info: Optional[Any] = None, **kwargs):
        """Log critical message."""
        self._log_with_extra(logging.CRITICAL, message, exc_info=exc_info, **kwargs)
        
    def audit(self, action: str, resource: Optional[str] = None, 
              resource_id: Optional[Union[str, int]] = None, 
              outcome: str = "success", **kwargs):
        """Log audit trail message."""
        audit_data = {
            'action': action,
            'outcome': outcome,
            'audit': True
        }
        
        if resource:
            audit_data['resource'] = resource
        if resource_id:
            audit_data['resource_id'] = str(resource_id)
            
        audit_data.update(kwargs)
        self._log_with_extra(LogLevel.AUDIT.value, f"AUDIT: {action}", audit_data)
        
    def performance(self, operation: str, duration: float, **kwargs):
        """Log performance metrics."""
        perf_data = {
            'operation': operation,
            'duration_ms': round(duration * 1000, 2),
            'performance': True
        }
        perf_data.update(kwargs)
        
        level = logging.WARNING if duration > 5.0 else logging.INFO
        self._log_with_extra(level, f"PERFORMANCE: {operation} took {duration:.3f}s", perf_data)

class RequestTracer:
    """Request tracing for distributed logging."""
    
    def __init__(self):
        self.trace_header = 'X-Trace-ID'
        
    def get_or_create_trace_id(self) -> str:
        """Get existing trace ID or create new one."""
        if has_request_context():
            # Try to get from header first
            trace_id = request.headers.get(self.trace_header)
            if not trace_id:
                # Create new trace ID
                trace_id = str(uuid.uuid4())
                
            # Store in request context
            if not hasattr(g, 'trace_id'):
                g.trace_id = trace_id
                
            return g.trace_id
        else:
            # Non-request context, create unique ID
            return str(uuid.uuid4())
            
    def add_to_response_headers(self, response):
        """Add trace ID to response headers."""
        if has_request_context() and hasattr(g, 'trace_id'):
            response.headers[self.trace_header] = g.trace_id
        return response

class LoggingMiddleware:
    """Middleware for request/response logging."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.tracer = RequestTracer()
        self.logger = StructuredLogger('request')
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask):
        """Initialize logging middleware with Flask app."""
        self.app = app
        
        # Register request handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_request(self._teardown_request)
        
        # Add custom log level
        logging.addLevelName(LogLevel.AUDIT.value, 'AUDIT')
        logging.addLevelName(LogLevel.TRACE.value, 'TRACE')
        
        logger = logging.getLogger(__name__)
        logger.info("Logging middleware initialized")
        
    def _before_request(self):
        """Log request start and set up tracing."""
        # Set up tracing
        trace_id = self.tracer.get_or_create_trace_id()
        
        # Generate request ID
        request.id = str(uuid.uuid4())
        
        # Record start time
        g.request_start_time = time.time()
        
        # Log request start
        self.logger.info(
            f"Request started: {request.method} {request.path}",
            request_id=request.id,
            method=request.method,
            path=request.path,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
    def _after_request(self, response):
        """Log request completion."""
        duration = time.time() - g.request_start_time
        
        # Log request completion
        self.logger.info(
            f"Request completed: {request.method} {request.path} "
            f"[{response.status_code}] in {duration:.3f}s",
            request_id=request.id,
            status_code=response.status_code,
            duration_ms=round(duration * 1000, 2),
            response_size=response.content_length
        )
        
        # Add trace ID to response headers
        response = self.tracer.add_to_response_headers(response)
        
        # Log slow requests
        if duration > 1.0:
            self.logger.warning(
                f"Slow request detected: {request.method} {request.path}",
                duration_ms=round(duration * 1000, 2),
                slow_request=True
            )
            
        return response
        
    def _teardown_request(self, exception):
        """Log any request exceptions."""
        if exception:
            self.logger.error(
                f"Request failed with exception: {request.method} {request.path}",
                exc_info=exception,
                request_id=getattr(request, 'id', None)
            )

def setup_structured_logging(app: Flask, log_level: str = 'INFO', 
                            log_file: Optional[str] = None,
                            enable_console: bool = True,
                            enable_json: bool = True):
    """Set up structured logging for the application."""
    
    # Remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Create formatters
    if enable_json:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Set log level
    log_level_value = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(log_level_value)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level_value)
        root_logger.addHandler(console_handler)
        
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level_value)
        root_logger.addHandler(file_handler)
        
    # Initialize middleware
    logging_middleware = LoggingMiddleware(app)
    app.extensions['logging_middleware'] = logging_middleware
    
    logger = logging.getLogger(__name__)
    logger.info(f"Structured logging configured (level: {log_level}, json: {enable_json})")

def log_performance(operation: str):
    """Decorator to log function performance."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = StructuredLogger(func.__module__)
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                logger.performance(operation, duration, function=func.__name__)
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"Performance tracking failed for {operation}",
                    exc_info=e,
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2)
                )
                raise
        return wrapper
    return decorator

@contextmanager
def log_operation(operation: str, logger: Optional[StructuredLogger] = None, **context):
    """Context manager for logging operations."""
    if logger is None:
        logger = StructuredLogger(__name__)
        
    start_time = time.time()
    logger.info(f"Starting operation: {operation}", operation=operation, **context)
    
    try:
        yield logger
        duration = time.time() - start_time
        logger.info(
            f"Completed operation: {operation}",
            operation=operation,
            duration_ms=round(duration * 1000, 2),
            **context
        )
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"Failed operation: {operation}",
            exc_info=e,
            operation=operation,
            duration_ms=round(duration * 1000, 2),
            **context
        )
        raise

# Helper function to get structured logger
def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)