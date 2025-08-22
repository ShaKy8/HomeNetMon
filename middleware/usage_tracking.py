# HomeNetMon Usage Tracking Middleware
from flask import Flask, request, g, current_app
from functools import wraps
from datetime import datetime
import logging
import time
from typing import Dict, Any, Optional, Callable
from threading import Lock
import json

from tenant_models import UsageMetricType
from tenant_manager import get_current_tenant
from usage_analytics import usage_analytics, record_usage

logger = logging.getLogger(__name__)

class UsageTracker:
    """Middleware for automatic usage tracking"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.tracking_rules = {}
        self.request_metrics = {}
        self.lock = Lock()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize usage tracker with Flask app"""
        self.app = app
        
        # Set up request tracking
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_appcontext(self.cleanup_request)
        
        # Set up default tracking rules
        self.setup_default_tracking_rules()
        
        logger.info("UsageTracker middleware initialized")
    
    def setup_default_tracking_rules(self):
        """Setup default tracking rules for common endpoints"""
        self.tracking_rules = {
            # API calls tracking
            '/api/': {
                'metric': UsageMetricType.API_CALLS,
                'quantity': 1,
                'conditions': ['method:*']
            },
            
            # Device monitoring tracking
            '/api/devices': {
                'metric': UsageMetricType.DEVICES_MONITORED,
                'quantity': 0,  # Will be calculated based on actual devices
                'conditions': ['method:GET', 'method:POST']
            },
            
            # Alert tracking
            '/api/alerts': {
                'metric': UsageMetricType.ALERTS_PER_MONTH,
                'quantity': 1,
                'conditions': ['method:POST']
            },
            
            # User management tracking
            '/api/users': {
                'metric': UsageMetricType.USERS_PER_TENANT,
                'quantity': 0,  # Will be calculated
                'conditions': ['method:POST', 'method:DELETE']
            }
        }
    
    def before_request(self):
        """Track request start time and context"""
        g.request_start_time = time.time()
        g.request_metrics = {
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path,
            'tenant': get_current_tenant()
        }
    
    def after_request(self, response):
        """Track request completion and usage"""
        try:
            # Calculate request duration
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                g.request_metrics['duration'] = duration
            
            # Track usage based on rules
            self.track_request_usage(response)
            
            # Track API call
            if request.path.startswith('/api/'):
                self.track_api_call()
            
        except Exception as e:
            logger.error(f"Error in usage tracking after_request: {e}")
        
        return response
    
    def track_request_usage(self, response):
        """Track usage based on request and response"""
        if not hasattr(g, 'request_metrics') or not g.request_metrics.get('tenant'):
            return
        
        tenant = g.request_metrics['tenant']
        path = g.request_metrics['path']
        method = g.request_metrics['method']
        
        # Find matching tracking rules
        for rule_path, rule_config in self.tracking_rules.items():
            if self.matches_rule(path, method, rule_path, rule_config):
                metric_type = rule_config['metric']
                quantity = self.calculate_quantity(rule_config, response)
                
                if quantity > 0:
                    metadata = {
                        'endpoint': g.request_metrics['endpoint'],
                        'method': method,
                        'path': path,
                        'response_status': response.status_code,
                        'request_duration': g.request_metrics.get('duration', 0)
                    }
                    
                    usage_analytics.record_usage(
                        tenant_id=tenant.id,
                        metric_type=metric_type,
                        quantity=quantity,
                        metadata=metadata
                    )
    
    def track_api_call(self):
        """Track API call usage"""
        if not hasattr(g, 'request_metrics') or not g.request_metrics.get('tenant'):
            return
        
        tenant = g.request_metrics['tenant']
        
        # Always track API calls
        record_usage(UsageMetricType.API_CALLS, 1, {
            'endpoint': g.request_metrics['endpoint'],
            'method': g.request_metrics['method'],
            'path': g.request_metrics['path']
        })
    
    def matches_rule(self, path: str, method: str, rule_path: str, rule_config: Dict) -> bool:
        """Check if request matches tracking rule"""
        # Check path match
        if not path.startswith(rule_path):
            return False
        
        # Check conditions
        conditions = rule_config.get('conditions', [])
        for condition in conditions:
            if condition.startswith('method:'):
                required_method = condition.split(':', 1)[1]
                if required_method != '*' and required_method != method:
                    return False
        
        return True
    
    def calculate_quantity(self, rule_config: Dict, response) -> float:
        """Calculate usage quantity based on rule and response"""
        base_quantity = rule_config.get('quantity', 1)
        
        # If quantity is 0, calculate based on response
        if base_quantity == 0:
            metric_type = rule_config['metric']
            
            if metric_type == UsageMetricType.DEVICES_MONITORED:
                # Count actual devices being monitored
                return self.count_monitored_devices()
            elif metric_type == UsageMetricType.USERS_PER_TENANT:
                # Count users in tenant
                return self.count_tenant_users()
        
        return base_quantity
    
    def count_monitored_devices(self) -> int:
        """Count number of devices being monitored"""
        try:
            from models import Device
            return Device.query.filter_by(is_monitored=True).count()
        except Exception as e:
            logger.error(f"Error counting monitored devices: {e}")
            return 0
    
    def count_tenant_users(self) -> int:
        """Count number of users in current tenant"""
        try:
            if not hasattr(g, 'request_metrics') or not g.request_metrics.get('tenant'):
                return 0
            
            tenant = g.request_metrics['tenant']
            return TenantUser.query.filter_by(tenant_id=tenant.id).count()
        except Exception as e:
            logger.error(f"Error counting tenant users: {e}")
            return 0
    
    def cleanup_request(self, exception=None):
        """Cleanup request tracking data"""
        if hasattr(g, 'request_metrics'):
            delattr(g, 'request_metrics')
        if hasattr(g, 'request_start_time'):
            delattr(g, 'request_start_time')

# Decorators for manual usage tracking

def track_usage(metric_type: UsageMetricType, quantity: float = 1, 
                metadata: Dict[str, Any] = None):
    """Decorator to automatically track usage for a function"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Track usage after successful execution
            try:
                record_usage(metric_type, quantity, metadata or {
                    'function': func.__name__,
                    'module': func.__module__
                })
            except Exception as e:
                logger.error(f"Error tracking usage for {func.__name__}: {e}")
            
            return result
        return wrapper
    return decorator

def track_device_usage(func: Callable) -> Callable:
    """Decorator to track device-related usage"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        
        # Track device monitoring usage
        try:
            record_usage(UsageMetricType.DEVICES_MONITORED, 1, {
                'function': func.__name__,
                'action': 'device_operation'
            })
        except Exception as e:
            logger.error(f"Error tracking device usage: {e}")
        
        return result
    return wrapper

def track_api_usage(func: Callable) -> Callable:
    """Decorator to track API usage"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        
        # Track API call
        try:
            record_usage(UsageMetricType.API_CALLS, 1, {
                'function': func.__name__,
                'endpoint': request.endpoint if request else 'unknown'
            })
        except Exception as e:
            logger.error(f"Error tracking API usage: {e}")
        
        return result
    return wrapper

def track_alert_usage(func: Callable) -> Callable:
    """Decorator to track alert generation usage"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        
        # Track alert usage
        try:
            record_usage(UsageMetricType.ALERTS_PER_MONTH, 1, {
                'function': func.__name__,
                'alert_type': 'generated'
            })
        except Exception as e:
            logger.error(f"Error tracking alert usage: {e}")
        
        return result
    return wrapper

def track_storage_usage(size_gb: float):
    """Decorator to track storage usage"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Track storage usage
            try:
                record_usage(UsageMetricType.STORAGE_GB, size_gb, {
                    'function': func.__name__,
                    'storage_operation': 'write'
                })
            except Exception as e:
                logger.error(f"Error tracking storage usage: {e}")
            
            return result
        return wrapper
    return decorator

def track_bandwidth_usage(size_gb: float):
    """Decorator to track bandwidth usage"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Track bandwidth usage
            try:
                record_usage(UsageMetricType.BANDWIDTH_GB, size_gb, {
                    'function': func.__name__,
                    'bandwidth_operation': 'transfer'
                })
            except Exception as e:
                logger.error(f"Error tracking bandwidth usage: {e}")
            
            return result
        return wrapper
    return decorator

# Context managers for batch usage tracking

class UsageTrackingContext:
    """Context manager for tracking usage in a block of code"""
    
    def __init__(self, metric_type: UsageMetricType, quantity: float = 1, 
                 metadata: Dict[str, Any] = None):
        self.metric_type = metric_type
        self.quantity = quantity
        self.metadata = metadata or {}
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only track if no exception occurred
        if exc_type is None:
            duration = time.time() - self.start_time
            metadata = self.metadata.copy()
            metadata['execution_time'] = duration
            
            try:
                record_usage(self.metric_type, self.quantity, metadata)
            except Exception as e:
                logger.error(f"Error tracking usage in context: {e}")

# Batch usage tracking

class BatchUsageTracker:
    """Utility for tracking multiple usage metrics in batch"""
    
    def __init__(self):
        self.pending_usage = []
        self.lock = Lock()
    
    def add_usage(self, metric_type: UsageMetricType, quantity: float = 1, 
                  metadata: Dict[str, Any] = None):
        """Add usage to batch"""
        with self.lock:
            self.pending_usage.append({
                'metric_type': metric_type,
                'quantity': quantity,
                'metadata': metadata or {}
            })
    
    def flush(self):
        """Flush all pending usage to analytics system"""
        with self.lock:
            for usage_item in self.pending_usage:
                try:
                    record_usage(
                        usage_item['metric_type'],
                        usage_item['quantity'],
                        usage_item['metadata']
                    )
                except Exception as e:
                    logger.error(f"Error flushing usage item: {e}")
            
            self.pending_usage.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()

# Global usage tracker instance
usage_tracker = UsageTracker()

# Convenience functions for common usage patterns

def track_device_monitoring():
    """Track device monitoring usage"""
    record_usage(UsageMetricType.DEVICES_MONITORED, 1, {
        'source': 'monitoring_service',
        'timestamp': datetime.utcnow().isoformat()
    })

def track_alert_generation(alert_type: str = 'general'):
    """Track alert generation usage"""
    record_usage(UsageMetricType.ALERTS_PER_MONTH, 1, {
        'alert_type': alert_type,
        'source': 'alert_system',
        'timestamp': datetime.utcnow().isoformat()
    })

def track_user_creation():
    """Track user creation usage"""
    record_usage(UsageMetricType.USERS_PER_TENANT, 1, {
        'action': 'user_created',
        'source': 'user_management',
        'timestamp': datetime.utcnow().isoformat()
    })

def track_integration_usage(integration_type: str):
    """Track custom integration usage"""
    record_usage(UsageMetricType.CUSTOM_INTEGRATIONS, 1, {
        'integration_type': integration_type,
        'source': 'integration_system',
        'timestamp': datetime.utcnow().isoformat()
    })