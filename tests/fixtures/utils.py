"""
Test utilities and helper functions for HomeNetMon tests.

This module provides common functions used across multiple test files
to reduce code duplication and ensure consistent test behavior.
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from contextlib import contextmanager

# Add the parent directory to the path so we can import the app modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from models import db


class TestDatabaseManager:
    """Helper class for managing test database state."""
    
    @staticmethod
    def clear_all_tables(session):
        """Clear all data from all tables."""
        # Get all table names
        tables = [
            'performance_metrics',
            'monitoring_data', 
            'alerts',
            'devices',
            'configurations'
        ]
        
        # Delete in reverse order to handle foreign keys
        for table in tables:
            session.execute(f"DELETE FROM {table}")
        session.commit()
    
    @staticmethod
    def get_table_count(session, table_name):
        """Get the number of records in a table."""
        result = session.execute(f"SELECT COUNT(*) FROM {table_name}")
        return result.scalar()
    
    @staticmethod
    def create_test_schema(app):
        """Create the test database schema."""
        with app.app_context():
            db.create_all()


class APITestHelper:
    """Helper class for API testing."""
    
    @staticmethod
    def assert_json_response(response, status_code=200):
        """Assert that response is JSON with expected status code."""
        assert response.status_code == status_code
        assert response.content_type == 'application/json'
        return response.get_json()
    
    @staticmethod
    def assert_success_response(response, message_contains=None):
        """Assert that response indicates success."""
        data = APITestHelper.assert_json_response(response, 200)
        if message_contains:
            assert message_contains in data.get('message', '')
        return data
    
    @staticmethod
    def assert_error_response(response, status_code=400, error_contains=None):
        """Assert that response indicates an error."""
        data = APITestHelper.assert_json_response(response, status_code)
        assert 'error' in data
        if error_contains:
            assert error_contains in data['error']
        return data
    
    @staticmethod
    def post_json(client, url, data, **kwargs):
        """Make a POST request with JSON data."""
        return client.post(url, 
                          data=json.dumps(data),
                          content_type='application/json',
                          **kwargs)
    
    @staticmethod
    def put_json(client, url, data, **kwargs):
        """Make a PUT request with JSON data."""
        return client.put(url,
                         data=json.dumps(data),
                         content_type='application/json',
                         **kwargs)


class MockHelper:
    """Helper class for creating and managing mocks."""
    
    @staticmethod
    def create_mock_nmap_result(hosts_data):
        """
        Create a mock nmap result.
        
        Args:
            hosts_data: List of dicts with 'ip', 'mac', 'vendor', 'hostname'
        """
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host['ip'] for host in hosts_data]
        
        def getitem_side_effect(ip):
            host_data = next((h for h in hosts_data if h['ip'] == ip), None)
            if host_data:
                return {
                    'addresses': {
                        'ipv4': host_data['ip'],
                        'mac': host_data.get('mac', '00:11:22:33:44:55')
                    },
                    'vendor': {host_data.get('mac', '00:11:22:33:44:55'): host_data.get('vendor', 'Unknown')},
                    'hostnames': [{'name': host_data.get('hostname', 'unknown'), 'type': 'PTR'}]
                }
            return {}
        
        mock_nm.__getitem__.side_effect = getitem_side_effect
        return mock_nm
    
    @staticmethod
    def create_mock_ping_responses(ip_responses):
        """
        Create a mock ping function that returns different responses for different IPs.
        
        Args:
            ip_responses: Dict mapping IP addresses to response times (or None for timeout)
        """
        def mock_ping(ip, timeout=None):
            return ip_responses.get(ip, None)
        
        return mock_ping
    
    @staticmethod
    @contextmanager
    def mock_external_services():
        """Context manager that mocks all external services."""
        with patch('nmap.PortScanner') as mock_nmap, \
             patch('ping3.ping') as mock_ping, \
             patch('smtplib.SMTP') as mock_smtp, \
             patch('requests.post') as mock_requests:
            
            # Configure default behaviors
            mock_nmap_instance = MagicMock()
            mock_nmap.return_value = mock_nmap_instance
            mock_ping.return_value = 0.025  # 25ms default
            
            mock_smtp_instance = MagicMock()
            mock_smtp.return_value = mock_smtp_instance
            
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.return_value = mock_response
            
            yield {
                'nmap': mock_nmap_instance,
                'ping': mock_ping,
                'smtp': mock_smtp_instance,
                'requests': mock_requests
            }


class TimeHelper:
    """Helper class for time-related test utilities."""
    
    @staticmethod
    def create_time_series(start_time, count, interval_minutes=5):
        """Create a series of timestamps for testing."""
        timestamps = []
        current_time = start_time
        
        for i in range(count):
            timestamps.append(current_time)
            current_time += timedelta(minutes=interval_minutes)
        
        return timestamps
    
    @staticmethod
    def wait_for_condition(condition_func, timeout_seconds=5, check_interval=0.1):
        """Wait for a condition to become true, with timeout."""
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            if condition_func():
                return True
            time.sleep(check_interval)
        
        return False


class PerformanceTestHelper:
    """Helper class for performance-related tests."""
    
    @staticmethod
    def create_health_score_test_data():
        """Create test data for health score calculations."""
        return {
            'response_metrics': {
                'avg_ms': 25.0,
                'min_ms': 10.0,
                'max_ms': 50.0,
                'std_dev_ms': 8.5
            },
            'availability_metrics': {
                'uptime_percentage': 98.5,
                'total_checks': 100,
                'successful_checks': 98,
                'failed_checks': 2
            },
            'bandwidth_metrics': {
                'avg_in_mbps': 45.2,
                'avg_out_mbps': 12.8,
                'peak_in_mbps': 89.5,
                'peak_out_mbps': 25.6,
                'total_bytes_in': 1024000,
                'total_bytes_out': 512000
            },
            'quality_metrics': {
                'jitter_ms': 3.2,
                'packet_loss_percentage': 1.5,
                'stability_score': 92.0
            }
        }
    
    @staticmethod
    def assert_health_score_range(score, min_score=0, max_score=100):
        """Assert that a health score is within valid range."""
        assert isinstance(score, (int, float)), f"Health score must be numeric, got {type(score)}"
        assert min_score <= score <= max_score, f"Health score {score} not in range [{min_score}, {max_score}]"
    
    @staticmethod
    def assert_performance_grade(grade):
        """Assert that a performance grade is valid."""
        valid_grades = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F', 'N/A']
        assert grade in valid_grades, f"Invalid performance grade: {grade}"


class AlertTestHelper:
    """Helper class for alert-related tests."""
    
    @staticmethod
    def create_alert_test_scenarios():
        """Create various alert test scenarios."""
        return {
            'device_down': {
                'alert_type': 'device_down',
                'severity': 'critical',
                'message': 'Device is not responding to ping',
                'should_notify': True
            },
            'high_latency': {
                'alert_type': 'high_latency',
                'severity': 'warning',
                'message': 'Device response time is high',
                'should_notify': True
            },
            'performance_critical': {
                'alert_type': 'performance',
                'alert_subtype': 'performance_critical',
                'severity': 'critical',
                'message': 'Device performance is critically low',
                'should_notify': True
            },
            'performance_warning': {
                'alert_type': 'performance',
                'alert_subtype': 'performance_warning',
                'severity': 'warning', 
                'message': 'Device performance is below normal',
                'should_notify': False
            }
        }
    
    @staticmethod
    def assert_alert_properties(alert, expected_type, expected_severity):
        """Assert alert has expected properties."""
        assert alert.alert_type == expected_type
        assert alert.severity == expected_severity
        assert alert.created_at is not None
        assert alert.resolved is False  # New alerts should not be resolved
        assert alert.acknowledged is False  # New alerts should not be acknowledged


class WebSocketTestHelper:
    """Helper class for WebSocket testing."""
    
    @staticmethod
    def create_mock_socketio():
        """Create a mock SocketIO instance for testing."""
        mock_socketio = MagicMock()
        mock_socketio.emit.return_value = None
        return mock_socketio
    
    @staticmethod
    def assert_socketio_emit_called(mock_socketio, event_name, data_contains=None):
        """Assert that socketio.emit was called with expected event."""
        mock_socketio.emit.assert_called()
        
        # Check if the event name was used in any call
        calls = mock_socketio.emit.call_args_list
        event_found = any(call[0][0] == event_name for call in calls if call[0])
        assert event_found, f"Event '{event_name}' was not emitted"
        
        if data_contains:
            # Check if data contains expected content
            for call in calls:
                if call[0] and call[0][0] == event_name:
                    call_data = call[0][1] if len(call[0]) > 1 else {}
                    for key, value in data_contains.items():
                        assert key in call_data, f"Key '{key}' not found in emitted data"
                        if value is not None:
                            assert call_data[key] == value, f"Expected {key}={value}, got {call_data[key]}"


# Common test assertions

def assert_device_properties(device, expected_ip=None, expected_type=None):
    """Assert device has expected properties."""
    assert device.id is not None
    assert device.ip_address is not None
    assert device.created_at is not None
    assert device.updated_at is not None
    
    if expected_ip:
        assert device.ip_address == expected_ip
    if expected_type:
        assert device.device_type == expected_type


def assert_monitoring_data_properties(monitoring_data, expected_device_id=None):
    """Assert monitoring data has expected properties."""
    assert monitoring_data.id is not None
    assert monitoring_data.device_id is not None
    assert monitoring_data.timestamp is not None
    
    if expected_device_id:
        assert monitoring_data.device_id == expected_device_id


def assert_performance_metrics_properties(performance_metrics, expected_device_id=None):
    """Assert performance metrics has expected properties."""
    assert performance_metrics.id is not None
    assert performance_metrics.device_id is not None
    assert performance_metrics.timestamp is not None
    assert performance_metrics.health_score is not None
    
    # Health scores should be in valid range
    PerformanceTestHelper.assert_health_score_range(performance_metrics.health_score)
    
    if expected_device_id:
        assert performance_metrics.device_id == expected_device_id


# Test data helpers

def get_sample_network_scan_result():
    """Get sample network scan result for testing."""
    return [
        {
            'ip': '192.168.1.1',
            'mac': '00:11:22:33:44:01', 
            'vendor': 'Router Corp',
            'hostname': 'home-router'
        },
        {
            'ip': '192.168.1.10',
            'mac': '00:11:22:33:44:02',
            'vendor': 'Computer Inc',
            'hostname': 'desktop-pc'
        },
        {
            'ip': '192.168.1.20',
            'mac': '00:11:22:33:44:03',
            'vendor': 'Apple Inc',
            'hostname': 'iphone'
        }
    ]


def get_sample_ping_responses():
    """Get sample ping responses for testing."""
    return {
        '192.168.1.1': 0.015,    # 15ms - router
        '192.168.1.10': 0.025,   # 25ms - computer
        '192.168.1.20': 0.035,   # 35ms - phone
        '192.168.1.30': None,    # timeout
        '192.168.1.40': 0.500    # 500ms - slow response
    }