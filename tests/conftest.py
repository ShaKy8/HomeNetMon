"""
Pytest configuration and fixtures for HomeNetMon tests.

This module provides:
- Flask application fixtures for testing
- Test database setup and teardown
- Mock fixtures for external dependencies
- Common test utilities and helpers
"""

import os
import tempfile
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json

# Add the parent directory to the path so we can import the app modules
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models import (
    db, Device, MonitoringData, PerformanceMetrics, Alert, Configuration,
    DeviceIpHistory, ConfigurationHistory, BandwidthData, NotificationHistory,
    NotificationReceipt, AlertSuppression, AutomationRule, RuleExecution,
    EscalationRule, EscalationExecution, EscalationActionLog, SecurityScan,
    SecurityVulnerability, SecurityEvent, ComplianceResult, DeviceOSInfo,
    SecurityIncident, PerformanceSnapshot, BandwidthTest, LatencyAnalysis,
    PerformanceAlert, OptimizationRecommendation
)
from config import Config


class TestConfig(Config):
    """Test-specific configuration that overrides production settings."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # In-memory database for tests
    SECRET_KEY = 'test-secret-key'
    WTF_CSRF_ENABLED = False
    
    # Disable external network operations for tests
    NETWORK_RANGE = '192.168.1.0/24'
    PING_INTERVAL = 1
    SCAN_INTERVAL = 1
    PING_TIMEOUT = 0.1
    
    # Disable real SMTP for tests
    SMTP_SERVER = None
    WEBHOOK_URL = None
    
    # Fast test execution
    DATA_RETENTION_DAYS = 1
    MAX_WORKERS = 2


@pytest.fixture(scope='session')
def app():
    """Create and configure a new app instance for each test session."""
    # Create a temporary file for the test database
    db_fd, db_path = tempfile.mkstemp()
    
    # Override the production Config before creating the app
    original_db_uri = Config.SQLALCHEMY_DATABASE_URI
    Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    Config.TESTING = True
    Config.WTF_CSRF_ENABLED = False
    
    # Disable background services for testing
    Config.PING_INTERVAL = 3600  # Very long interval to prevent background activity
    Config.SCAN_INTERVAL = 3600
    
    try:
        app, socketio = create_app()
        
        # Additional test configuration
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Create the database and the database table
        with app.app_context():
            db.create_all()
            yield app
            
    finally:
        # Restore original configuration
        Config.SQLALCHEMY_DATABASE_URI = original_db_uri
        Config.TESTING = False
        Config.WTF_CSRF_ENABLED = True
        
        # Clean up temp file
        os.close(db_fd)
        os.unlink(db_path)


@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture(scope='function')
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()


@pytest.fixture(scope='function')
def db_session(app):
    """
    Create a fresh database session for each test.
    
    This fixture provides a clean database state for each test and
    automatically clears all data after the test completes.
    """
    with app.app_context():
        # Create all tables if they don't exist
        db.create_all()
        
        # Clear all existing data at the start of each test
        # This ensures tests start with a clean database
        db.session.query(Alert).delete()
        db.session.query(MonitoringData).delete() 
        db.session.query(PerformanceMetrics).delete()
        db.session.query(Device).delete()
        db.session.query(Configuration).delete()
        db.session.commit()
        
        yield db.session
        
        # Clean up after test - clear all data
        try:
            db.session.query(Alert).delete()
            db.session.query(MonitoringData).delete()
            db.session.query(PerformanceMetrics).delete() 
            db.session.query(Device).delete()
            db.session.query(Configuration).delete()
            db.session.commit()
        except:
            db.session.rollback()


@pytest.fixture
def sample_device_data():
    """Sample device data for testing."""
    return {
        'ip_address': '192.168.1.100',
        'mac_address': '00:11:22:33:44:55',
        'hostname': 'test-device',
        'vendor': 'Test Vendor',
        'custom_name': 'Test Device',
        'device_type': 'computer',
        'device_group': 'test-group',
        'is_monitored': True
    }


@pytest.fixture
def sample_device(db_session, sample_device_data):
    """Create a sample device in the test database."""
    device = Device(**sample_device_data)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


@pytest.fixture
def sample_devices(db_session):
    """Create multiple sample devices for testing."""
    devices = []
    
    device_configs = [
        {
            'ip_address': '192.168.1.1',
            'mac_address': '00:11:22:33:44:01',
            'hostname': 'router',
            'vendor': 'Router Inc',
            'device_type': 'router',
            'is_monitored': True
        },
        {
            'ip_address': '192.168.1.10',
            'mac_address': '00:11:22:33:44:02',
            'hostname': 'desktop-pc',
            'vendor': 'Computer Corp',
            'device_type': 'computer',
            'is_monitored': True
        },
        {
            'ip_address': '192.168.1.20',
            'mac_address': '00:11:22:33:44:03',
            'hostname': 'iphone',
            'vendor': 'Apple Inc',
            'device_type': 'phone',
            'is_monitored': True
        }
    ]
    
    for config in device_configs:
        device = Device(**config)
        device.last_seen = datetime.utcnow()  # Set as recently seen
        db_session.add(device)
        devices.append(device)
    
    db_session.commit()
    return devices


@pytest.fixture
def sample_monitoring_data(db_session, sample_device):
    """Create sample monitoring data for testing."""
    monitoring_records = []
    base_time = datetime.utcnow() - timedelta(hours=1)
    
    for i in range(10):
        record = MonitoringData(
            device_id=sample_device.id,
            timestamp=base_time + timedelta(minutes=i * 5),
            response_time=20.0 + (i * 2.0),  # Increasing response times
            packet_loss=0.0 if i < 8 else 10.0  # Some packet loss in later records
        )
        monitoring_records.append(record)
        db_session.add(record)
    
    db_session.commit()
    return monitoring_records


@pytest.fixture
def sample_performance_metrics(db_session, sample_device):
    """Create sample performance metrics for testing."""
    metrics = PerformanceMetrics(
        device_id=sample_device.id,
        timestamp=datetime.utcnow(),
        health_score=85.0,
        responsiveness_score=90.0,
        reliability_score=95.0,
        efficiency_score=80.0,
        avg_response_time=25.5,
        uptime_percentage=98.5,
        total_checks=100,
        successful_checks=98,
        failed_checks=2,
        collection_period_minutes=60
    )
    db_session.add(metrics)
    db_session.commit()
    db_session.refresh(metrics)
    return metrics


@pytest.fixture
def sample_alert(db_session, sample_device):
    """Create a sample alert for testing."""
    alert = Alert(
        device_id=sample_device.id,
        alert_type='device_down',
        severity='warning',
        message='Device is not responding to ping',
        created_at=datetime.utcnow(),
        resolved=False,
        acknowledged=False
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


@pytest.fixture
def sample_configuration(db_session):
    """Create sample configuration entries for testing."""
    configs = [
        Configuration(
            key='test_setting_1',
            value='test_value_1',
            description='Test configuration setting 1'
        ),
        Configuration(
            key='performance_alert_critical_threshold',
            value='50',
            description='Critical performance alert threshold'
        ),
        Configuration(
            key='performance_alert_warning_threshold', 
            value='70',
            description='Warning performance alert threshold'
        )
    ]
    
    for config in configs:
        db_session.add(config)
    
    db_session.commit()
    return configs


# Mock fixtures for external dependencies

@pytest.fixture
def mock_nmap():
    """Mock nmap scanning functionality."""
    with patch('nmap.PortScanner') as mock_scanner:
        mock_instance = MagicMock()
        mock_instance.scan.return_value = None
        mock_instance.all_hosts.return_value = ['192.168.1.1', '192.168.1.10']
        mock_instance.__getitem__.return_value = {
            'addresses': {'ipv4': '192.168.1.1', 'mac': '00:11:22:33:44:55'},
            'vendor': {'00:11:22:33:44:55': 'Test Vendor'},
            'hostnames': [{'name': 'test-host', 'type': 'PTR'}]
        }
        mock_scanner.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_ping():
    """Mock ping functionality."""
    with patch('ping3.ping') as mock_ping_func:
        mock_ping_func.return_value = 0.025  # 25ms response time
        yield mock_ping_func


@pytest.fixture
def mock_smtp():
    """Mock SMTP email functionality."""
    with patch('smtplib.SMTP') as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_requests():
    """Mock HTTP requests for webhook functionality."""
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True}
        mock_post.return_value = mock_response
        yield mock_post


@pytest.fixture
def mock_socketio():
    """Mock SocketIO for testing real-time functionality."""
    with patch('flask_socketio.SocketIO') as mock_socketio:
        mock_instance = MagicMock()
        mock_socketio.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_performance_monitor():
    """Mock the performance monitor service."""
    with patch('services.performance_monitor.performance_monitor') as mock_monitor:
        mock_monitor.collect_device_performance_metrics.return_value = True
        mock_monitor.get_network_performance_summary.return_value = {
            'network_health': {
                'avg_health_score': 85.0,
                'avg_uptime_percentage': 95.0,
                'total_devices': 3,
                'devices_with_data': 3
            },
            'device_status_breakdown': {
                'excellent': 1,
                'good': 1,
                'fair': 1,
                'poor': 0,
                'critical': 0
            }
        }
        yield mock_monitor


# Test utilities

def create_test_device(db_session, **kwargs):
    """Utility function to create test devices with custom attributes."""
    default_data = {
        'ip_address': '192.168.1.200',
        'mac_address': '00:11:22:33:44:99',
        'hostname': 'test-util-device',
        'vendor': 'Test Util Vendor',
        'device_type': 'computer',
        'is_monitored': True
    }
    default_data.update(kwargs)
    
    device = Device(**default_data)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def create_test_monitoring_data(db_session, device, count=5, **kwargs):
    """Utility function to create test monitoring data."""
    records = []
    base_time = datetime.utcnow() - timedelta(hours=1)
    
    for i in range(count):
        default_data = {
            'device_id': device.id,
            'timestamp': base_time + timedelta(minutes=i * 10),
            'response_time': 20.0 + (i * 5.0),
            'packet_loss': 0.0
        }
        default_data.update(kwargs)
        
        record = MonitoringData(**default_data)
        db_session.add(record)
        records.append(record)
    
    db_session.commit()
    return records


def create_test_performance_metrics(db_session, device, **kwargs):
    """Utility function to create test performance metrics."""
    default_data = {
        'device_id': device.id,
        'timestamp': datetime.utcnow(),
        'health_score': 85.0,
        'responsiveness_score': 90.0,
        'reliability_score': 95.0,
        'efficiency_score': 80.0,
        'collection_period_minutes': 60
    }
    default_data.update(kwargs)
    
    metrics = PerformanceMetrics(**default_data)
    db_session.add(metrics)
    db_session.commit()
    db_session.refresh(metrics)
    return metrics


# Pytest configuration

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "api: mark test as an API test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "network: mark test as requiring network access")


# Automatically mark tests based on their location
def pytest_collection_modifyitems(config, items):
    """Automatically add markers based on test file paths."""
    for item in items:
        # Add markers based on directory structure
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "api" in str(item.fspath):
            item.add_marker(pytest.mark.api)