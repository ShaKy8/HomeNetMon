"""
Quality manager that integrates all code quality and maintainability improvements.
"""

import logging
from typing import Dict, Any, Optional
from flask import Flask
from core.error_handler import ErrorHandler
from core.validation_middleware import ValidationMiddleware
from core.structured_logging import setup_structured_logging
from core.config_validation import ConfigurationManager
from core.api_documentation import APIDocumentation

logger = logging.getLogger(__name__)

class QualityManager:
    """Manages all code quality and maintainability features."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.error_handler = None
        self.validation_middleware = None
        self.config_manager = None
        self.api_documentation = None
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask, config_file: Optional[str] = None):
        """Initialize all quality components with Flask app."""
        self.app = app
        
        logger.info("Initializing quality management system")
        
        # 1. Initialize configuration management
        self._init_config_management(config_file)
        
        # 2. Initialize structured logging
        self._init_structured_logging()
        
        # 3. Initialize error handling
        self._init_error_handling()
        
        # 4. Initialize validation middleware
        self._init_validation_middleware()
        
        # 5. Initialize API documentation
        self._init_api_documentation()
        
        # 6. Register health checks
        self._register_health_checks()
        
        # Store in app extensions
        app.extensions['quality_manager'] = self
        
        logger.info("Quality management system initialized successfully")
        
    def _init_config_management(self, config_file: Optional[str] = None):
        """Initialize configuration management."""
        self.config_manager = ConfigurationManager(config_file)
        
        try:
            settings = self.config_manager.load_config()
            
            # Update Flask config with validated settings
            flask_config = self.config_manager.get_flask_config()
            self.app.config.update(flask_config)
            
            logger.info("Configuration management initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize configuration: {e}")
            raise
            
    def _init_structured_logging(self):
        """Initialize structured logging."""
        # Get logging configuration from settings
        settings = self.config_manager.settings
        if settings:
            log_config = settings.logging
            setup_structured_logging(
                app=self.app,
                log_level=log_config.log_level,
                log_file=log_config.log_file,
                enable_json=log_config.enable_structured_logging
            )
        else:
            # Use defaults if config not available
            setup_structured_logging(self.app)
            
        logger.info("Structured logging initialized")
        
    def _init_error_handling(self):
        """Initialize error handling system."""
        self.error_handler = ErrorHandler(self.app)
        self.app.extensions['error_handler'] = self.error_handler
        
        logger.info("Error handling system initialized")
        
    def _init_validation_middleware(self):
        """Initialize validation middleware."""
        self.validation_middleware = ValidationMiddleware(self.app)
        self.app.extensions['validation_middleware'] = self.validation_middleware
        
        # Register common validation schemas
        from core.validation_middleware import (
            DeviceCreateSchema, DeviceUpdateSchema, AlertCreateSchema,
            ConfigurationSchema, PaginationSchema
        )
        
        # Register schemas for endpoints
        self.validation_middleware.register_schema(
            '/api/devices', DeviceCreateSchema(), 'POST'
        )
        self.validation_middleware.register_schema(
            '/api/devices/<int:device_id>', DeviceUpdateSchema(), 'PUT'
        )
        self.validation_middleware.register_schema(
            '/api/alerts', AlertCreateSchema(), 'POST'
        )
        
        logger.info("Validation middleware initialized")
        
    def _init_api_documentation(self):
        """Initialize API documentation."""
        self.api_documentation = APIDocumentation(self.app)
        self.app.extensions['api_documentation'] = self.api_documentation
        
        # Add common paths to documentation
        from core.api_documentation import DEVICE_API_PATHS
        
        for path, operations in DEVICE_API_PATHS.items():
            for method, operation in operations.items():
                self.api_documentation.add_path(path, method, operation)
                
        logger.info("API documentation initialized")
        
    def _register_health_checks(self):
        """Register health check endpoints."""
        from api.health_check import health_check_bp
        self.app.register_blueprint(health_check_bp, url_prefix='/api')
        
        logger.info("Health check endpoints registered")
        
    def get_quality_metrics(self) -> Dict[str, Any]:
        """Get overall quality metrics."""
        metrics = {
            'timestamp': self.config_manager.settings.logging.log_level if self.config_manager.settings else None,
            'components': {}
        }
        
        # Error handling metrics
        if self.error_handler:
            metrics['components']['error_handling'] = self.error_handler.get_error_stats()
            
        # Validation metrics
        if self.validation_middleware:
            metrics['components']['validation'] = self.validation_middleware.get_validation_stats()
            
        # Configuration validation
        if self.config_manager:
            metrics['components']['configuration'] = self.config_manager.validate_runtime_config()
            
        return metrics
        
    def run_quality_checks(self) -> Dict[str, Any]:
        """Run comprehensive quality checks."""
        logger.info("Running quality checks")
        
        checks = {
            'timestamp': logger.info,
            'overall_status': 'healthy',
            'checks': {}
        }
        
        issues = []
        
        # Configuration validation
        if self.config_manager:
            config_validation = self.config_manager.validate_runtime_config()
            checks['checks']['configuration'] = config_validation
            
            if not config_validation['valid']:
                issues.extend(config_validation['errors'])
                
        # Error rate check
        if self.error_handler:
            error_stats = self.error_handler.get_error_stats()
            error_rate = (error_stats['total_errors'] / max(error_stats.get('total_requests', 1), 1)) * 100
            
            checks['checks']['error_rate'] = {
                'rate_percent': error_rate,
                'threshold_percent': 5.0,
                'healthy': error_rate < 5.0
            }
            
            if error_rate >= 5.0:
                issues.append(f"High error rate: {error_rate:.2f}%")
                
        # Validation failure check
        if self.validation_middleware:
            validation_stats = self.validation_middleware.get_validation_stats()
            failure_rate = (validation_stats['failed_validations'] / 
                          max(validation_stats['total_validations'], 1)) * 100
            
            checks['checks']['validation_failure_rate'] = {
                'rate_percent': failure_rate,
                'threshold_percent': 10.0,
                'healthy': failure_rate < 10.0
            }
            
            if failure_rate >= 10.0:
                issues.append(f"High validation failure rate: {failure_rate:.2f}%")
                
        # Overall status
        if issues:
            checks['overall_status'] = 'degraded'
            checks['issues'] = issues
            
        logger.info(f"Quality checks completed - Status: {checks['overall_status']}")
        
        return checks
        
    def generate_quality_report(self) -> Dict[str, Any]:
        """Generate comprehensive quality report."""
        logger.info("Generating quality report")
        
        report = {
            'report_timestamp': logger.info,
            'application': 'HomeNetMon',
            'quality_metrics': self.get_quality_metrics(),
            'quality_checks': self.run_quality_checks(),
            'recommendations': []
        }
        
        # Generate recommendations based on metrics
        recommendations = self._generate_recommendations(report['quality_metrics'])
        report['recommendations'] = recommendations
        
        return report
        
    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate quality improvement recommendations."""
        recommendations = []
        
        # Check configuration
        config_check = metrics.get('components', {}).get('configuration', {})
        if not config_check.get('valid', True):
            recommendations.append("Fix configuration errors before deployment")
            
        if config_check.get('warnings'):
            recommendations.extend([
                f"Configuration warning: {warning}" 
                for warning in config_check['warnings']
            ])
            
        # Check error rates
        error_stats = metrics.get('components', {}).get('error_handling', {})
        if error_stats.get('total_errors', 0) > 100:
            recommendations.append("High error count detected - review error logs")
            
        # Check validation failures
        validation_stats = metrics.get('components', {}).get('validation', {})
        failure_rate = (validation_stats.get('failed_validations', 0) / 
                       max(validation_stats.get('total_validations', 1), 1)) * 100
        
        if failure_rate > 5:
            recommendations.append("High validation failure rate - review API usage patterns")
            
        return recommendations

# Quality decorators for enhanced monitoring
def monitor_quality(operation: str):
    """Decorator to monitor operation quality."""
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            from core.structured_logging import get_logger
            
            quality_logger = get_logger(f'{func.__module__}.quality')
            
            try:
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                quality_logger.performance(
                    operation=operation,
                    duration=duration,
                    function=func.__name__,
                    success=True
                )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                quality_logger.error(
                    f"Quality monitoring failed for {operation}",
                    exc_info=e,
                    operation=operation,
                    duration=duration,
                    function=func.__name__,
                    success=False
                )
                raise
                
        return wrapper
    return decorator

def validate_input_quality(schema_class):
    """Decorator to validate input data quality."""
    def decorator(func):
        from functools import wraps
        from flask import request, current_app
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            validation_middleware = current_app.extensions.get('validation_middleware')
            
            if validation_middleware and request.is_json:
                try:
                    schema = schema_class()
                    validated_data = validation_middleware.validate_request(schema)
                    # Store validated data for use in the function
                    from flask import g
                    g.validated_data = validated_data
                except Exception as e:
                    from core.error_handler import ValidationError
                    raise ValidationError(f"Input validation failed: {str(e)}")
                    
            return func(*args, **kwargs)
            
        return wrapper
    return decorator

# Global quality manager instance
quality_manager = QualityManager()