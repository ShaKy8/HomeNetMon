"""
Simple test data factories that don't require external dependencies.

This is a fallback implementation that creates test objects without
factory_boy or faker dependencies.
"""

import random
from datetime import datetime, timedelta
import string

# Add the parent directory to the path so we can import the app modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from models import Device, MonitoringData, PerformanceMetrics, Alert, Configuration


class SimpleDeviceFactory:
    """Simple factory for creating Device test objects."""
    
    _counter = 0
    
    @classmethod
    def create(cls, **kwargs):
        """Create a Device instance with default or provided values."""
        cls._counter += 1
        
        defaults = {
            'ip_address': f'192.168.1.{100 + cls._counter}',
            'mac_address': cls._generate_mac(),
            'hostname': f'device-{cls._counter}',
            'custom_name': kwargs.get('custom_name'),
            'device_type': 'computer',
            'device_group': 'default',
            'is_monitored': True,
            'last_seen': datetime.utcnow() - timedelta(minutes=random.randint(1, 60)),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Override defaults with provided kwargs
        for key, value in kwargs.items():
            defaults[key] = value
        
        device = Device(**defaults)
        
        # Try to add to session if in an app context (but don't commit)
        try:
            from models import db
            if db.session:
                db.session.add(device)
                db.session.flush()  # This assigns an ID without committing
        except:
            # If we can't add to session, that's okay for some tests
            pass
            
        return device
    
    @staticmethod
    def _generate_mac():
        """Generate a random MAC address."""
        import uuid
        # Use UUID to ensure uniqueness across test runs
        unique_suffix = uuid.uuid4().hex[:8]
        return f"02:{unique_suffix[:2]}:{unique_suffix[2:4]}:{unique_suffix[4:6]}:{unique_suffix[6:8]}:00"


class SimpleMonitoringDataFactory:
    """Simple factory for creating MonitoringData test objects."""
    
    @classmethod
    def create(cls, **kwargs):
        """Create a MonitoringData instance."""
        defaults = {
            'device_id': kwargs.get('device_id', 1),
            'timestamp': datetime.utcnow(),
            'response_time': round(random.uniform(1.0, 100.0), 2),
            'packet_loss': 0.0,
            'additional_data': '{}'
        }
        
        # Handle device relationship
        if 'device' in kwargs:
            device = kwargs.pop('device')
            defaults['device_id'] = device.id
            
        for key, value in kwargs.items():
            defaults[key] = value
            
        monitoring_data = MonitoringData(**defaults)
        
        # Try to add to session if in an app context (but don't commit)
        try:
            from models import db
            if db.session:
                db.session.add(monitoring_data)
                db.session.flush()  # This assigns an ID without committing
        except:
            # If we can't add to session, that's okay for some tests
            pass
            
        return monitoring_data


class SimpleSuccessfulMonitoringDataFactory(SimpleMonitoringDataFactory):
    """Factory for successful monitoring data."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'response_time': round(random.uniform(1.0, 50.0), 2),
            'packet_loss': 0.0
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleFailedMonitoringDataFactory(SimpleMonitoringDataFactory):
    """Factory for failed monitoring data."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'response_time': None,
            'packet_loss': 100.0
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleTimeoutMonitoringDataFactory(SimpleMonitoringDataFactory):
    """Factory for timeout monitoring data."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'response_time': None,
            'packet_loss': 100.0,
            'additional_data': '{"error": "timeout"}'
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimplePerformanceMetricsFactory:
    """Simple factory for creating PerformanceMetrics test objects."""
    
    @classmethod
    def create(cls, **kwargs):
        """Create a PerformanceMetrics instance."""
        health_score = kwargs.get('health_score', random.uniform(50.0, 95.0))
        
        defaults = {
            'device_id': kwargs.get('device_id', 1),
            'timestamp': datetime.utcnow(),
            'health_score': health_score,
            'responsiveness_score': health_score + random.uniform(-10, 10),
            'reliability_score': health_score + random.uniform(-5, 5),
            'avg_response_time': round(random.uniform(1.0, 50.0), 2),
            'uptime_percentage': round(random.uniform(90.0, 99.9), 2),
            'packet_loss_rate': round(random.uniform(0.0, 5.0), 2)
        }
        
        # Handle device relationship
        if 'device' in kwargs:
            device = kwargs.pop('device')
            defaults['device_id'] = device.id
            
        for key, value in kwargs.items():
            defaults[key] = value
            
        return PerformanceMetrics(**defaults)


class SimpleExcellentPerformanceMetricsFactory(SimplePerformanceMetricsFactory):
    """Factory for excellent performance metrics."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'health_score': random.uniform(90.0, 100.0),
            'responsiveness_score': random.uniform(90.0, 100.0),
            'reliability_score': random.uniform(95.0, 100.0),
            'avg_response_time': round(random.uniform(1.0, 20.0), 2),
            'uptime_percentage': round(random.uniform(99.0, 100.0), 2),
            'packet_loss_rate': round(random.uniform(0.0, 1.0), 2)
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimplePoorPerformanceMetricsFactory(SimplePerformanceMetricsFactory):
    """Factory for poor performance metrics."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'health_score': random.uniform(0.0, 40.0),
            'responsiveness_score': random.uniform(0.0, 40.0),
            'reliability_score': random.uniform(0.0, 50.0),
            'avg_response_time': round(random.uniform(100.0, 500.0), 2),
            'uptime_percentage': round(random.uniform(60.0, 80.0), 2),
            'packet_loss_rate': round(random.uniform(10.0, 50.0), 2)
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleAlertFactory:
    """Simple factory for creating Alert test objects."""
    
    _counter = 0
    
    @classmethod
    def create(cls, **kwargs):
        """Create an Alert instance."""
        cls._counter += 1
        
        defaults = {
            'device_id': kwargs.get('device_id', 1),
            'alert_type': 'device_down',
            'severity': random.choice(['info', 'warning', 'critical']),
            'message': f'This is test alert message {cls._counter}',
            'created_at': datetime.utcnow(),
            'resolved': False,
            'acknowledged': False,
            'priority_score': random.randint(1, 100),
            'priority_level': 'MEDIUM'
        }
        
        # Handle device relationship
        if 'device' in kwargs:
            device = kwargs.pop('device')
            defaults['device_id'] = device.id
        elif 'device_id' not in kwargs:
            # Create a device if none provided
            device = SimpleDeviceFactory.create()
            defaults['device_id'] = device.id
            
        for key, value in kwargs.items():
            defaults[key] = value
            
        alert = Alert(**defaults)
        
        # Try to add to session if in an app context (but don't commit)
        try:
            from models import db
            if db.session:
                db.session.add(alert)
                db.session.flush()  # This assigns an ID without committing
        except:
            # If we can't add to session, that's okay for some tests
            pass
            
        return alert


class SimplePerformanceAlertFactory(SimpleAlertFactory):
    """Factory for performance-related alerts."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'alert_type': 'performance',
            'severity': kwargs.get('severity', 'warning'),
            'message': f'Performance issue detected - device showing degraded performance metrics'
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleResolvedAlertFactory(SimpleAlertFactory):
    """Factory for resolved alerts."""
    
    @classmethod
    def create(cls, **kwargs):
        # Create alert that was created in the past and resolved afterwards
        created_hours_ago = random.randint(2, 48)  # Created 2-48 hours ago
        resolved_hours_ago = random.randint(1, created_hours_ago - 1)  # Resolved 1 hour to (created_hours_ago - 1) hours ago
        
        created_time = datetime.utcnow() - timedelta(hours=created_hours_ago)
        resolved_time = datetime.utcnow() - timedelta(hours=resolved_hours_ago)
        
        defaults = {
            'resolved': True,
            'resolved_at': resolved_time,
            'created_at': created_time
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleAcknowledgedAlertFactory(SimpleAlertFactory):
    """Factory for acknowledged alerts."""
    
    @classmethod
    def create(cls, **kwargs):
        # Create alert that was created in the past and acknowledged afterwards
        created_minutes_ago = random.randint(30, 300)  # Created 30-300 minutes ago
        acknowledged_minutes_ago = random.randint(1, created_minutes_ago - 10)  # Acknowledged after creation
        
        created_time = datetime.utcnow() - timedelta(minutes=created_minutes_ago)
        acknowledged_time = datetime.utcnow() - timedelta(minutes=acknowledged_minutes_ago)
        
        defaults = {
            'acknowledged': True,
            'acknowledged_at': acknowledged_time,
            'acknowledged_by': 'test_operator',
            'created_at': created_time
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleRouterDeviceFactory(SimpleDeviceFactory):
    """Factory for router devices."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'device_type': 'router',
            'ip_address': '192.168.1.1',
            'hostname': 'router'
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleComputerDeviceFactory(SimpleDeviceFactory):
    """Factory for computer devices."""
    
    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'device_type': 'computer',
            'device_group': 'computers',
            'vendor': random.choice(['Dell Inc.', 'HP Inc.', 'Lenovo', 'Apple Inc.'])
        }
        defaults.update(kwargs)
        return super().create(**defaults)


class SimpleConfigurationFactory:
    """Simple factory for creating Configuration test objects."""
    
    _counter = 0
    
    @classmethod
    def create(cls, **kwargs):
        """Create a Configuration instance."""
        cls._counter += 1
        
        defaults = {
            'key': kwargs.get('key', f'test_config_{cls._counter}'),
            'value': kwargs.get('value', f'test_value_{cls._counter}'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        for key, value in kwargs.items():
            defaults[key] = value
            
        return Configuration(**defaults)


# Create aliases to match the original factory names
DeviceFactory = SimpleDeviceFactory
MonitoringDataFactory = SimpleMonitoringDataFactory
SuccessfulMonitoringDataFactory = SimpleSuccessfulMonitoringDataFactory
FailedMonitoringDataFactory = SimpleFailedMonitoringDataFactory
TimeoutMonitoringDataFactory = SimpleTimeoutMonitoringDataFactory
PerformanceMetricsFactory = SimplePerformanceMetricsFactory
ExcellentPerformanceMetricsFactory = SimpleExcellentPerformanceMetricsFactory
PoorPerformanceMetricsFactory = SimplePoorPerformanceMetricsFactory
AlertFactory = SimpleAlertFactory
PerformanceAlertFactory = SimplePerformanceAlertFactory
ResolvedAlertFactory = SimpleResolvedAlertFactory
AcknowledgedAlertFactory = SimpleAcknowledgedAlertFactory
RouterDeviceFactory = SimpleRouterDeviceFactory
ComputerDeviceFactory = SimpleComputerDeviceFactory
ConfigurationFactory = SimpleConfigurationFactory