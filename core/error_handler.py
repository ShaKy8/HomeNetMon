"""
Comprehensive error handling framework with standardized responses and logging.
"""

import logging
import traceback
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, Type, Union
from enum import Enum
from flask import Flask, jsonify, request, current_app, g
from werkzeug.exceptions import HTTPException
import sys

logger = logging.getLogger(__name__)

class ErrorCode(Enum):
    """Standardized error codes for the application."""
    
    # General errors (1000-1999)
    UNKNOWN_ERROR = "ERR_1000"
    VALIDATION_ERROR = "ERR_1001"
    AUTHENTICATION_REQUIRED = "ERR_1002"
    AUTHORIZATION_FAILED = "ERR_1003"
    RESOURCE_NOT_FOUND = "ERR_1004"
    RATE_LIMIT_EXCEEDED = "ERR_1005"
    
    # Database errors (2000-2999)
    DATABASE_ERROR = "ERR_2000"
    DATABASE_CONNECTION_ERROR = "ERR_2001"
    DATABASE_TIMEOUT = "ERR_2002"
    DATABASE_CONSTRAINT_VIOLATION = "ERR_2003"
    
    # Business logic errors (3000-3999)
    DEVICE_NOT_FOUND = "ERR_3000"
    DEVICE_NOT_MONITORED = "ERR_3001"
    ALERT_NOT_FOUND = "ERR_3002"
    CONFIGURATION_ERROR = "ERR_3003"
    NETWORK_SCAN_FAILED = "ERR_3004"
    
    # External service errors (4000-4999)
    EXTERNAL_SERVICE_ERROR = "ERR_4000"
    EXTERNAL_SERVICE_TIMEOUT = "ERR_4001"
    EXTERNAL_SERVICE_UNAVAILABLE = "ERR_4002"
    
    # System errors (5000-5999)
    SYSTEM_OVERLOAD = "ERR_5000"
    INSUFFICIENT_RESOURCES = "ERR_5001"
    SERVICE_UNAVAILABLE = "ERR_5002"

class AppError(Exception):
    """Base application error with structured error information."""
    
    def __init__(self, message: str, error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR,
                 status_code: int = 500, details: Optional[Dict[str, Any]] = None,
                 cause: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        self.cause = cause
        self.error_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for JSON serialization."""
        error_dict = {
            'error_id': self.error_id,
            'error_code': self.error_code.value,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'status_code': self.status_code
        }
        
        if self.details:
            error_dict['details'] = self.details
            
        # Add request context if available
        if request:
            error_dict['request'] = {
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
        # Add user context if available
        if hasattr(g, 'current_user') and g.current_user:
            error_dict['user'] = g.current_user.get('username')
            
        return error_dict

class ValidationError(AppError):
    """Validation error for request data."""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Optional[Any] = None, **kwargs):
        details = kwargs.get('details', {})
        if field:
            details['field'] = field
        if value is not None:
            details['invalid_value'] = str(value)
            
        super().__init__(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
            details=details,
            **{k: v for k, v in kwargs.items() if k != 'details'}
        )

class AuthenticationError(AppError):
    """Authentication error."""
    
    def __init__(self, message: str = "Authentication required", **kwargs):
        super().__init__(
            message=message,
            error_code=ErrorCode.AUTHENTICATION_REQUIRED,
            status_code=401,
            **kwargs
        )

class AuthorizationError(AppError):
    """Authorization error."""
    
    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(
            message=message,
            error_code=ErrorCode.AUTHORIZATION_FAILED,
            status_code=403,
            **kwargs
        )

class ResourceNotFoundError(AppError):
    """Resource not found error."""
    
    def __init__(self, resource_type: str, resource_id: Optional[Union[str, int]] = None, **kwargs):
        message = f"{resource_type} not found"
        if resource_id:
            message += f": {resource_id}"
            
        details = kwargs.get('details', {})
        details.update({
            'resource_type': resource_type,
            'resource_id': str(resource_id) if resource_id else None
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.RESOURCE_NOT_FOUND,
            status_code=404,
            details=details,
            **{k: v for k, v in kwargs.items() if k != 'details'}
        )

class DatabaseError(AppError):
    """Database operation error."""
    
    def __init__(self, message: str, operation: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if operation:
            details['operation'] = operation
            
        super().__init__(
            message=message,
            error_code=ErrorCode.DATABASE_ERROR,
            status_code=500,
            details=details,
            **{k: v for k, v in kwargs.items() if k != 'details'}
        )

class ExternalServiceError(AppError):
    """External service error."""
    
    def __init__(self, service_name: str, message: Optional[str] = None, **kwargs):
        message = message or f"External service error: {service_name}"
        details = kwargs.get('details', {})
        details['service_name'] = service_name
        
        super().__init__(
            message=message,
            error_code=ErrorCode.EXTERNAL_SERVICE_ERROR,
            status_code=502,
            details=details,
            **{k: v for k, v in kwargs.items() if k != 'details'}
        )

class ErrorHandler:
    """Centralized error handler for Flask applications."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.error_stats = {
            'total_errors': 0,
            'errors_by_code': {},
            'errors_by_endpoint': {},
            'last_reset': datetime.utcnow()
        }
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask):
        """Initialize error handler with Flask app."""
        self.app = app
        
        # Register error handlers
        app.errorhandler(AppError)(self.handle_app_error)
        app.errorhandler(HTTPException)(self.handle_http_error)
        app.errorhandler(Exception)(self.handle_generic_error)
        
        # Register before/after request handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        
        logger.info("Error handler initialized")
        
    def _before_request(self):
        """Set up error tracking for the request."""
        g.error_handler_start_time = datetime.utcnow()
        
    def _after_request(self, response):
        """Log successful requests for monitoring."""
        if hasattr(g, 'error_handled'):
            # Error was already handled
            return response
            
        # Log successful requests at debug level
        duration = (datetime.utcnow() - g.error_handler_start_time).total_seconds()
        if duration > 5.0:  # Log slow requests
            logger.warning(
                f"Slow request: {request.method} {request.path} "
                f"took {duration:.2f}s (status: {response.status_code})"
            )
            
        return response
        
    def handle_app_error(self, error: AppError):
        """Handle application-specific errors."""
        g.error_handled = True
        
        # Update statistics
        self._update_error_stats(error.error_code.value)
        
        # Log error with appropriate level
        log_level = logging.ERROR if error.status_code >= 500 else logging.WARNING
        logger.log(
            log_level,
            f"Application error {error.error_id}: {error.message}",
            extra={
                'error_id': error.error_id,
                'error_code': error.error_code.value,
                'status_code': error.status_code,
                'details': error.details,
                'cause': str(error.cause) if error.cause else None
            }
        )
        
        # Log stack trace for server errors
        if error.status_code >= 500 and error.cause:
            logger.error(f"Error cause for {error.error_id}: {error.cause}", exc_info=error.cause)
            
        return jsonify(error.to_dict()), error.status_code
        
    def handle_http_error(self, error: HTTPException):
        """Handle HTTP errors."""
        g.error_handled = True
        
        app_error = AppError(
            message=error.description or f"HTTP {error.code} error",
            error_code=self._map_http_status_to_error_code(error.code),
            status_code=error.code,
            details={'http_error': True}
        )
        
        return self.handle_app_error(app_error)
        
    def handle_generic_error(self, error: Exception):
        """Handle unexpected errors."""
        g.error_handled = True
        
        # Create application error from generic exception
        app_error = AppError(
            message="An unexpected error occurred",
            error_code=ErrorCode.UNKNOWN_ERROR,
            status_code=500,
            details={
                'exception_type': type(error).__name__,
                'exception_message': str(error)
            },
            cause=error
        )
        
        # Log full stack trace for unexpected errors
        logger.error(
            f"Unexpected error {app_error.error_id}: {error}",
            exc_info=True,
            extra={
                'error_id': app_error.error_id,
                'exception_type': type(error).__name__
            }
        )
        
        return self.handle_app_error(app_error)
        
    def _map_http_status_to_error_code(self, status_code: int) -> ErrorCode:
        """Map HTTP status codes to application error codes."""
        mapping = {
            400: ErrorCode.VALIDATION_ERROR,
            401: ErrorCode.AUTHENTICATION_REQUIRED,
            403: ErrorCode.AUTHORIZATION_FAILED,
            404: ErrorCode.RESOURCE_NOT_FOUND,
            429: ErrorCode.RATE_LIMIT_EXCEEDED,
            502: ErrorCode.EXTERNAL_SERVICE_ERROR,
            503: ErrorCode.SERVICE_UNAVAILABLE,
        }
        return mapping.get(status_code, ErrorCode.UNKNOWN_ERROR)
        
    def _update_error_stats(self, error_code: str):
        """Update error statistics."""
        self.error_stats['total_errors'] += 1
        self.error_stats['errors_by_code'][error_code] = \
            self.error_stats['errors_by_code'].get(error_code, 0) + 1
            
        endpoint = request.endpoint if request else 'unknown'
        self.error_stats['errors_by_endpoint'][endpoint] = \
            self.error_stats['errors_by_endpoint'].get(endpoint, 0) + 1
            
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        return self.error_stats.copy()
        
    def reset_error_stats(self):
        """Reset error statistics."""
        self.error_stats = {
            'total_errors': 0,
            'errors_by_code': {},
            'errors_by_endpoint': {},
            'last_reset': datetime.utcnow()
        }

# Context managers for common error patterns
class database_error_handler:
    """Context manager for database operations."""
    
    def __init__(self, operation: str):
        self.operation = operation
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return
            
        # Handle database-specific exceptions
        if 'IntegrityError' in str(exc_type):
            raise DatabaseError(
                message=f"Database constraint violation during {self.operation}",
                operation=self.operation,
                details={'constraint_violation': True}
            ) from exc_val
        elif 'OperationalError' in str(exc_type):
            if 'timeout' in str(exc_val).lower():
                raise DatabaseError(
                    message=f"Database timeout during {self.operation}",
                    error_code=ErrorCode.DATABASE_TIMEOUT,
                    operation=self.operation
                ) from exc_val
            else:
                raise DatabaseError(
                    message=f"Database connection error during {self.operation}",
                    error_code=ErrorCode.DATABASE_CONNECTION_ERROR,
                    operation=self.operation
                ) from exc_val
        else:
            raise DatabaseError(
                message=f"Database error during {self.operation}",
                operation=self.operation,
                cause=exc_val
            ) from exc_val

def handle_errors(error_type: Type[AppError] = AppError, **error_kwargs):
    """Decorator to handle errors in view functions."""
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except AppError:
                # Re-raise application errors as-is
                raise
            except Exception as e:
                # Convert to application error
                raise error_type(
                    message=f"Error in {func.__name__}: {str(e)}",
                    cause=e,
                    **error_kwargs
                ) from e
        return wrapper
    return decorator

# Global error handler instance
global_error_handler = ErrorHandler()