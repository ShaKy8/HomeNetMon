"""
Factory classes for generating test data using factory_boy.

These factories provide a consistent way to create test objects with
realistic data for HomeNetMon testing.
"""

import factory
import factory.fuzzy
from datetime import datetime, timedelta
from faker import Faker

# Add the parent directory to the path so we can import the app modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from models import Device, MonitoringData, PerformanceMetrics, Alert, Configuration

fake = Faker()


class DeviceFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Factory for creating Device test instances."""
    
    class Meta:
        model = Device
        sqlalchemy_session_persistence = 'commit'
    
    ip_address = factory.LazyFunction(lambda: fake.ipv4_private())
    mac_address = factory.LazyFunction(lambda: fake.mac_address())
    hostname = factory.LazyFunction(lambda: fake.hostname())
    vendor = factory.Faker('company')
    custom_name = factory.LazyAttribute(lambda obj: f"Test {obj.hostname}")
    device_type = factory.fuzzy.FuzzyChoice(['router', 'computer', 'phone', 'iot', 'printer', 'camera'])
    device_group = factory.Faker('word')
    is_monitored = True
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
    last_seen = factory.LazyFunction(lambda: datetime.utcnow() - timedelta(minutes=fake.random_int(0, 10)))


class RouterDeviceFactory(DeviceFactory):
    """Factory for creating router-type devices."""
    ip_address = '192.168.1.1'
    device_type = 'router'
    vendor = 'Router Corp'
    hostname = 'home-router'


class ComputerDeviceFactory(DeviceFactory):
    """Factory for creating computer-type devices."""
    device_type = 'computer'
    vendor = factory.fuzzy.FuzzyChoice(['Dell Inc.', 'HP Inc.', 'Lenovo', 'Apple Inc.'])


class PhoneDeviceFactory(DeviceFactory):
    """Factory for creating phone-type devices."""
    device_type = 'phone'
    vendor = factory.fuzzy.FuzzyChoice(['Apple Inc.', 'Samsung', 'Google', 'OnePlus'])


class MonitoringDataFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Factory for creating MonitoringData test instances."""
    
    class Meta:
        model = MonitoringData
        sqlalchemy_session_persistence = 'commit'
    
    device = factory.SubFactory(DeviceFactory)
    timestamp = factory.LazyFunction(lambda: datetime.utcnow() - timedelta(minutes=fake.random_int(0, 60)))
    response_time = factory.fuzzy.FuzzyFloat(5.0, 100.0, precision=2)
    packet_loss = factory.fuzzy.FuzzyFloat(0.0, 5.0, precision=1)


class SuccessfulMonitoringDataFactory(MonitoringDataFactory):
    """Factory for creating successful monitoring data (low response time, no packet loss)."""
    response_time = factory.fuzzy.FuzzyFloat(5.0, 30.0, precision=2)
    packet_loss = 0.0


class FailedMonitoringDataFactory(MonitoringDataFactory):
    """Factory for creating failed monitoring data (high response time or packet loss)."""
    response_time = factory.fuzzy.FuzzyFloat(500.0, 2000.0, precision=2)
    packet_loss = factory.fuzzy.FuzzyFloat(10.0, 100.0, precision=1)


class TimeoutMonitoringDataFactory(MonitoringDataFactory):
    """Factory for creating timeout monitoring data (None response time)."""
    response_time = None
    packet_loss = 100.0


class PerformanceMetricsFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Factory for creating PerformanceMetrics test instances."""
    
    class Meta:
        model = PerformanceMetrics
        sqlalchemy_session_persistence = 'commit'
    
    device = factory.SubFactory(DeviceFactory)
    timestamp = factory.LazyFunction(datetime.utcnow)
    
    # Health scores (0-100)
    health_score = factory.fuzzy.FuzzyFloat(60.0, 95.0, precision=1)
    responsiveness_score = factory.fuzzy.FuzzyFloat(70.0, 100.0, precision=1)
    reliability_score = factory.fuzzy.FuzzyFloat(80.0, 100.0, precision=1)
    efficiency_score = factory.fuzzy.FuzzyFloat(60.0, 90.0, precision=1)
    
    # Response time metrics (milliseconds)
    avg_response_time = factory.fuzzy.FuzzyFloat(10.0, 50.0, precision=2)
    min_response_time = factory.LazyAttribute(lambda obj: obj.avg_response_time * 0.5)
    max_response_time = factory.LazyAttribute(lambda obj: obj.avg_response_time * 2.0)
    response_time_std_dev = factory.fuzzy.FuzzyFloat(1.0, 10.0, precision=2)
    
    # Availability metrics
    uptime_percentage = factory.fuzzy.FuzzyFloat(95.0, 100.0, precision=2)
    total_checks = factory.fuzzy.FuzzyInteger(50, 200)
    successful_checks = factory.LazyAttribute(lambda obj: int(obj.total_checks * obj.uptime_percentage / 100))
    failed_checks = factory.LazyAttribute(lambda obj: obj.total_checks - obj.successful_checks)
    
    # Bandwidth metrics (Mbps)
    avg_bandwidth_in_mbps = factory.fuzzy.FuzzyFloat(1.0, 100.0, precision=3)
    avg_bandwidth_out_mbps = factory.fuzzy.FuzzyFloat(0.5, 50.0, precision=3)
    peak_bandwidth_in_mbps = factory.LazyAttribute(lambda obj: obj.avg_bandwidth_in_mbps * 2.0)
    peak_bandwidth_out_mbps = factory.LazyAttribute(lambda obj: obj.avg_bandwidth_out_mbps * 2.0)
    
    # Quality metrics
    jitter_ms = factory.fuzzy.FuzzyFloat(0.5, 10.0, precision=2)
    packet_loss_percentage = factory.fuzzy.FuzzyFloat(0.0, 2.0, precision=2)
    connection_stability_score = factory.fuzzy.FuzzyFloat(85.0, 100.0, precision=1)
    
    # Collection metadata
    collection_period_minutes = 60
    sample_count = factory.fuzzy.FuzzyInteger(10, 100)
    anomaly_count = factory.fuzzy.FuzzyInteger(0, 5)


class ExcellentPerformanceMetricsFactory(PerformanceMetricsFactory):
    """Factory for creating excellent performance metrics."""
    health_score = factory.fuzzy.FuzzyFloat(90.0, 100.0, precision=1)
    responsiveness_score = factory.fuzzy.FuzzyFloat(95.0, 100.0, precision=1)
    reliability_score = factory.fuzzy.FuzzyFloat(98.0, 100.0, precision=1)
    efficiency_score = factory.fuzzy.FuzzyFloat(85.0, 100.0, precision=1)
    uptime_percentage = factory.fuzzy.FuzzyFloat(99.0, 100.0, precision=2)
    avg_response_time = factory.fuzzy.FuzzyFloat(5.0, 20.0, precision=2)


class PoorPerformanceMetricsFactory(PerformanceMetricsFactory):
    """Factory for creating poor performance metrics."""
    health_score = factory.fuzzy.FuzzyFloat(30.0, 60.0, precision=1)
    responsiveness_score = factory.fuzzy.FuzzyFloat(20.0, 60.0, precision=1)
    reliability_score = factory.fuzzy.FuzzyFloat(40.0, 80.0, precision=1)
    efficiency_score = factory.fuzzy.FuzzyFloat(20.0, 60.0, precision=1)
    uptime_percentage = factory.fuzzy.FuzzyFloat(70.0, 90.0, precision=2)
    avg_response_time = factory.fuzzy.FuzzyFloat(100.0, 500.0, precision=2)


class AlertFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Factory for creating Alert test instances."""
    
    class Meta:
        model = Alert
        sqlalchemy_session_persistence = 'commit'
    
    device = factory.SubFactory(DeviceFactory)
    alert_type = factory.fuzzy.FuzzyChoice(['device_down', 'high_latency', 'performance', 'anomaly'])
    alert_subtype = factory.fuzzy.FuzzyChoice(['ping_timeout', 'high_response_time', 'performance_critical'])
    severity = factory.fuzzy.FuzzyChoice(['info', 'warning', 'critical'])
    message = factory.Faker('sentence')
    details = factory.LazyFunction(lambda: fake.text(max_nb_chars=200))
    created_at = factory.LazyFunction(lambda: datetime.utcnow() - timedelta(hours=fake.random_int(0, 24)))
    resolved = False
    acknowledged = False
    resolved_at = None
    acknowledged_at = None
    acknowledged_by = None
    resolution_message = None


class ResolvedAlertFactory(AlertFactory):
    """Factory for creating resolved alerts."""
    resolved = True
    resolved_at = factory.LazyAttribute(lambda obj: obj.created_at + timedelta(hours=fake.random_int(1, 12)))
    resolution_message = factory.Faker('sentence')


class AcknowledgedAlertFactory(AlertFactory):
    """Factory for creating acknowledged alerts."""
    acknowledged = True
    acknowledged_at = factory.LazyAttribute(lambda obj: obj.created_at + timedelta(minutes=fake.random_int(5, 60)))
    acknowledged_by = factory.Faker('name')


class PerformanceAlertFactory(AlertFactory):
    """Factory for creating performance-related alerts."""
    alert_type = 'performance'
    alert_subtype = factory.fuzzy.FuzzyChoice(['performance_critical', 'performance_warning', 'performance_responsiveness'])
    message = factory.LazyAttribute(lambda obj: f"Device performance is {obj.alert_subtype.split('_')[1]}")


class ConfigurationFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Factory for creating Configuration test instances."""
    
    class Meta:
        model = Configuration
        sqlalchemy_session_persistence = 'commit'
    
    key = factory.Sequence(lambda n: f"test_config_key_{n}")
    value = factory.Faker('word')
    description = factory.Faker('sentence')
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
    version = 1


class PerformanceConfigurationFactory(ConfigurationFactory):
    """Factory for creating performance-related configuration."""
    key = factory.fuzzy.FuzzyChoice([
        'performance_alert_critical_threshold',
        'performance_alert_warning_threshold', 
        'performance_alert_recovery_threshold',
        'performance_collection_interval',
        'performance_retention_days'
    ])
    value = factory.fuzzy.FuzzyChoice(['50', '70', '80', '300', '30'])


# Sequence factories for creating multiple related objects

def create_device_with_monitoring_data(session, monitoring_count=10, **device_kwargs):
    """Create a device with associated monitoring data."""
    device = DeviceFactory.create(**device_kwargs)
    session.add(device)
    session.commit()
    
    monitoring_data = []
    base_time = datetime.utcnow() - timedelta(hours=monitoring_count)
    
    for i in range(monitoring_count):
        data = MonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=i * 6)  # Every 6 minutes
        )
        monitoring_data.append(data)
    
    session.commit()
    return device, monitoring_data


def create_device_with_performance_metrics(session, metrics_count=5, **device_kwargs):
    """Create a device with associated performance metrics."""
    device = DeviceFactory.create(**device_kwargs)
    session.add(device)
    session.commit()
    
    performance_metrics = []
    base_time = datetime.utcnow() - timedelta(hours=metrics_count)
    
    for i in range(metrics_count):
        metrics = PerformanceMetricsFactory.create(
            device=device,
            timestamp=base_time + timedelta(hours=i)
        )
        performance_metrics.append(metrics)
    
    session.commit()
    return device, performance_metrics


def create_network_topology(session, device_count=5):
    """Create a complete network topology with various device types."""
    devices = []
    
    # Create a router
    router = RouterDeviceFactory.create()
    devices.append(router)
    
    # Create computers
    for i in range(2):
        computer = ComputerDeviceFactory.create(ip_address=f"192.168.1.{10 + i}")
        devices.append(computer)
    
    # Create phones
    for i in range(2):
        phone = PhoneDeviceFactory.create(ip_address=f"192.168.1.{20 + i}")
        devices.append(phone)
    
    session.add_all(devices)
    session.commit()
    
    # Add monitoring data for all devices
    for device in devices:
        MonitoringDataFactory.create_batch(5, device=device)
        PerformanceMetricsFactory.create(device=device)
    
    session.commit()
    return devices