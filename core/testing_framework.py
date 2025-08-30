"""
Automated testing framework for HomeNetMon application.
"""

import unittest
import pytest
import json
import time
from typing import Dict, Any, Optional, List, Callable
from flask import Flask
from flask.testing import FlaskClient
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class TestDatabase:
    """Test database utilities."""
    
    @staticmethod
    def create_test_db(app: Flask):
        """Create test database with sample data."""
        from models import db, Device, Alert, MonitoringData
        
        with app.app_context():
            db.create_all()
            
            # Create test devices
            test_devices = [
                Device(
                    ip_address='192.168.1.1',
                    mac_address='00:11:22:33:44:55',
                    hostname='router.local',
                    device_type='router',
                    is_monitored=True
                ),
                Device(
                    ip_address='192.168.1.100',
                    mac_address='AA:BB:CC:DD:EE:FF',
                    hostname='computer.local',
                    device_type='computer',
                    is_monitored=True
                ),
                Device(
                    ip_address='192.168.1.200',
                    mac_address='11:22:33:44:55:66',
                    hostname='phone.local',
                    device_type='phone',
                    is_monitored=False
                )
            ]
            
            for device in test_devices:
                db.session.add(device)
            db.session.commit()
            
            # Create test monitoring data
            now = datetime.utcnow()
            for i, device in enumerate(test_devices):
                for j in range(10):  # 10 data points per device
                    data = MonitoringData(
                        device_id=device.id,
                        response_time=10.0 + (i * 5) + j,  # Varying response times
                        timestamp=now - timedelta(minutes=j)
                    )
                    db.session.add(data)
                    
            # Create test alerts
            test_alerts = [
                Alert(
                    device_id=1,
                    message='Device offline',
                    severity='high',
                    alert_type='device_down',
                    resolved=False
                ),
                Alert(
                    device_id=2,
                    message='Slow response time',
                    severity='medium',
                    alert_type='slow_response',
                    resolved=True
                )
            ]
            
            for alert in test_alerts:
                db.session.add(alert)
            db.session.commit()
            
    @staticmethod
    def cleanup_test_db(app: Flask):
        """Clean up test database."""
        from models import db
        
        with app.app_context():
            db.drop_all()

class APITestClient:
    """Enhanced test client for API testing."""
    
    def __init__(self, app: Flask):
        self.app = app
        self.client = app.test_client()
        self.auth_token = None
        self.base_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
    def authenticate(self, username: str = 'admin', password: str = 'changeme123'):
        """Authenticate and store JWT token."""
        response = self.client.post('/api/auth/login', 
                                  json={
                                      'username': username,
                                      'password': password
                                  },
                                  headers=self.base_headers)
        
        if response.status_code == 200:
            data = response.get_json()
            self.auth_token = data.get('access_token')
            return True
        return False
        
    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = self.base_headers.copy()
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        return headers
        
    def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated GET request."""
        headers = kwargs.pop('headers', {})
        headers.update(self.get_auth_headers())
        
        response = self.client.get(url, headers=headers, **kwargs)
        return {
            'status_code': response.status_code,
            'data': response.get_json(),
            'headers': dict(response.headers)
        }
        
    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """Make authenticated POST request."""
        headers = kwargs.pop('headers', {})
        headers.update(self.get_auth_headers())
        
        response = self.client.post(url, 
                                   json=data, 
                                   headers=headers, 
                                   **kwargs)
        return {
            'status_code': response.status_code,
            'data': response.get_json(),
            'headers': dict(response.headers)
        }
        
    def put(self, url: str, data: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """Make authenticated PUT request."""
        headers = kwargs.pop('headers', {})
        headers.update(self.get_auth_headers())
        
        response = self.client.put(url, 
                                  json=data, 
                                  headers=headers, 
                                  **kwargs)
        return {
            'status_code': response.status_code,
            'data': response.get_json(),
            'headers': dict(response.headers)
        }
        
    def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated DELETE request."""
        headers = kwargs.pop('headers', {})
        headers.update(self.get_auth_headers())
        
        response = self.client.delete(url, headers=headers, **kwargs)
        return {
            'status_code': response.status_code,
            'data': response.get_json(),
            'headers': dict(response.headers)
        }

class BaseTestCase(unittest.TestCase):
    """Base test case with common functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.app = self.create_test_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = APITestClient(self.app)
        
        # Set up test database
        TestDatabase.create_test_db(self.app)
        
    def tearDown(self):
        """Clean up test environment."""
        TestDatabase.cleanup_test_db(self.app)
        self.app_context.pop()
        
    def create_test_app(self) -> Flask:
        """Create test application."""
        from core.application import Application
        
        # Create application with test configuration
        app = Application().create_app()
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SECRET_KEY': 'test-secret-key',
            'JWT_SECRET_KEY': 'test-jwt-secret-key-for-testing-only',
            'WTF_CSRF_ENABLED': False
        })
        
        return app
        
    def assert_api_success(self, response: Dict[str, Any], expected_status: int = 200):
        """Assert API response is successful."""
        self.assertEqual(response['status_code'], expected_status)
        self.assertIsNotNone(response['data'])
        if 'success' in response['data']:
            self.assertTrue(response['data']['success'])
            
    def assert_api_error(self, response: Dict[str, Any], expected_status: int, error_code: str = None):
        """Assert API response is an error."""
        self.assertEqual(response['status_code'], expected_status)
        self.assertIsNotNone(response['data'])
        if error_code:
            self.assertEqual(response['data'].get('error_code'), error_code)

class PerformanceTestMixin:
    """Mixin for performance testing."""
    
    def assert_response_time(self, func: Callable, max_time: float = 1.0):
        """Assert function completes within time limit."""
        start_time = time.time()
        result = func()
        execution_time = time.time() - start_time
        
        self.assertLessEqual(
            execution_time, 
            max_time,
            f"Function took {execution_time:.3f}s, expected < {max_time}s"
        )
        return result
        
    def benchmark_endpoint(self, endpoint: str, method: str = 'GET', 
                          iterations: int = 10, **kwargs) -> Dict[str, float]:
        """Benchmark an endpoint."""
        times = []
        
        for _ in range(iterations):
            start_time = time.time()
            
            if method == 'GET':
                response = self.client.get(endpoint, **kwargs)
            elif method == 'POST':
                response = self.client.post(endpoint, **kwargs)
            elif method == 'PUT':
                response = self.client.put(endpoint, **kwargs)
            elif method == 'DELETE':
                response = self.client.delete(endpoint, **kwargs)
                
            execution_time = time.time() - start_time
            times.append(execution_time)
            
        return {
            'min': min(times),
            'max': max(times),
            'avg': sum(times) / len(times),
            'total': sum(times)
        }

# Sample test cases
class AuthenticationTests(BaseTestCase):
    """Test authentication functionality."""
    
    def test_login_success(self):
        """Test successful login."""
        response = self.client.post('/api/auth/login', {
            'username': 'admin',
            'password': 'changeme123'
        })
        
        self.assert_api_success(response)
        self.assertIn('access_token', response['data'])
        self.assertIn('refresh_token', response['data'])
        
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        response = self.client.post('/api/auth/login', {
            'username': 'admin',
            'password': 'wrong-password'
        })
        
        self.assert_api_error(response, 401)
        
    def test_protected_endpoint_without_auth(self):
        """Test accessing protected endpoint without authentication."""
        response = self.client.get('/api/devices')
        self.assert_api_error(response, 401)
        
    def test_protected_endpoint_with_auth(self):
        """Test accessing protected endpoint with authentication."""
        self.client.authenticate()
        response = self.client.get('/api/devices')
        self.assert_api_success(response)

class DeviceAPITests(BaseTestCase, PerformanceTestMixin):
    """Test device API endpoints."""
    
    def setUp(self):
        super().setUp()
        self.client.authenticate()
        
    def test_list_devices(self):
        """Test listing devices."""
        response = self.client.get('/api/devices')
        self.assert_api_success(response)
        
        data = response['data']
        self.assertIn('data', data)
        self.assertIsInstance(data['data'], list)
        self.assertGreater(len(data['data']), 0)
        
    def test_get_device_detail(self):
        """Test getting device details."""
        response = self.client.get('/api/devices/1')
        self.assert_api_success(response)
        
        device = response['data']['data']
        self.assertEqual(device['id'], 1)
        self.assertEqual(device['ip_address'], '192.168.1.1')
        
    def test_create_device(self):
        """Test creating a new device."""
        new_device = {
            'ip_address': '192.168.1.50',
            'hostname': 'test-device',
            'device_type': 'computer'
        }
        
        response = self.client.post('/api/devices', new_device)
        self.assert_api_success(response, 201)
        
        device = response['data']['data']
        self.assertEqual(device['ip_address'], '192.168.1.50')
        
    def test_create_device_invalid_ip(self):
        """Test creating device with invalid IP."""
        invalid_device = {
            'ip_address': 'invalid-ip',
            'hostname': 'test-device'
        }
        
        response = self.client.post('/api/devices', invalid_device)
        self.assert_api_error(response, 400, 'ERR_1001')
        
    def test_device_list_performance(self):
        """Test device list endpoint performance."""
        stats = self.benchmark_endpoint('/api/devices', iterations=5)
        self.assertLess(stats['avg'], 1.0, "Device list endpoint too slow")

class MonitoringTests(BaseTestCase):
    """Test monitoring functionality."""
    
    def setUp(self):
        super().setUp()
        self.client.authenticate()
        
    def test_monitoring_summary(self):
        """Test monitoring summary endpoint."""
        response = self.client.get('/api/monitoring/summary')
        self.assert_api_success(response)
        
        summary = response['data']['data']
        self.assertIn('total_devices', summary)
        self.assertIn('online_devices', summary)
        
    def test_device_monitoring_data(self):
        """Test device monitoring data endpoint."""
        response = self.client.get('/api/monitoring/devices/1/data')
        self.assert_api_success(response)
        
        data = response['data']['data']
        self.assertIsInstance(data, list)
        
    @patch('monitoring.monitor.DeviceMonitor.ping_device')
    def test_device_ping_mock(self, mock_ping):
        """Test device ping with mocked network call."""
        mock_ping.return_value = (True, 50.0)  # Mock successful ping
        
        response = self.client.post('/api/monitoring/devices/1/ping')
        self.assert_api_success(response)

class HealthCheckTests(BaseTestCase):
    """Test health check endpoints."""
    
    def test_basic_health_check(self):
        """Test basic health check."""
        response = self.client.get('/api/health')
        self.assertEqual(response['status_code'], 200)
        
        data = response['data']
        self.assertEqual(data['status'], 'healthy')
        
    def test_detailed_health_check(self):
        """Test detailed health check."""
        self.client.authenticate()
        response = self.client.get('/api/health/detailed')
        self.assert_api_success(response)
        
        data = response['data']
        self.assertIn('checks', data)
        self.assertIn('database', data['checks'])
        self.assertIn('system', data['checks'])

# Test runners and utilities
class TestRunner:
    """Test runner with reporting capabilities."""
    
    @staticmethod
    def run_all_tests(verbosity: int = 2) -> unittest.TestResult:
        """Run all tests and return results."""
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add test cases
        test_classes = [
            AuthenticationTests,
            DeviceAPITests,
            MonitoringTests,
            HealthCheckTests
        ]
        
        for test_class in test_classes:
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)
            
        runner = unittest.TextTestRunner(verbosity=verbosity)
        return runner.run(suite)
        
    @staticmethod
    def run_performance_tests() -> Dict[str, Any]:
        """Run performance-specific tests."""
        # Implementation for performance testing suite
        pass
        
    @staticmethod
    def generate_test_report(results: unittest.TestResult) -> Dict[str, Any]:
        """Generate test report from results."""
        return {
            'tests_run': results.testsRun,
            'failures': len(results.failures),
            'errors': len(results.errors),
            'skipped': len(results.skipped),
            'success_rate': ((results.testsRun - len(results.failures) - len(results.errors)) / 
                           results.testsRun * 100) if results.testsRun > 0 else 0,
            'failure_details': [str(failure[1]) for failure in results.failures],
            'error_details': [str(error[1]) for error in results.errors]
        }

# Pytest fixtures for advanced testing
@pytest.fixture
def app():
    """Create test application."""
    from core.application import Application
    
    app = Application().create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-secret-key',
        'JWT_SECRET_KEY': 'test-jwt-secret-key-for-testing-only'
    })
    
    with app.app_context():
        TestDatabase.create_test_db(app)
        yield app
        TestDatabase.cleanup_test_db(app)

@pytest.fixture
def client(app):
    """Create test client."""
    return APITestClient(app)

@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client."""
    client.authenticate()
    return client