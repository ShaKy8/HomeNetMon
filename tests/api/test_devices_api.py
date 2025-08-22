"""
Unit tests for the devices API endpoints.

Tests cover:
- Device CRUD operations (Create, Read, Update, Delete)
- Device filtering and querying
- Device details and status information
- Device ping functionality
- Device groups and types
- Device monitoring controls
- Bulk operations
- Error handling and validation
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

from models import Device, MonitoringData, Alert
from tests.fixtures.factories import (
    DeviceFactory, MonitoringDataFactory, AlertFactory,
    SuccessfulMonitoringDataFactory, FailedMonitoringDataFactory
)
from tests.fixtures.utils import APITestHelper


class TestDevicesListAPI:
    """Test devices list API endpoint."""
    
    def test_get_devices_empty(self, client, db_session):
        """Test getting devices when none exist."""
        response = client.get('/api/devices')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['devices'] == []
        assert data['total'] == 0
    
    def test_get_devices_basic(self, client, db_session):
        """Test getting basic device list."""
        # Create test devices
        device1 = DeviceFactory.create(ip_address='192.168.1.10')
        device2 = DeviceFactory.create(ip_address='192.168.1.20')
        
        response = client.get('/api/devices')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert len(data['devices']) == 2
        assert data['total'] == 2
        
        # Check device data structure
        device_data = data['devices'][0]
        assert 'id' in device_data
        assert 'ip_address' in device_data
        assert 'display_name' in device_data
        assert 'status' in device_data
        assert 'latest_response_time' in device_data
        assert 'latest_check' in device_data
    
    def test_get_devices_with_monitoring_data(self, client, db_session):
        """Test getting devices with latest monitoring data."""
        device = DeviceFactory.create()
        
        # Add monitoring data
        monitoring_data = SuccessfulMonitoringDataFactory.create(
            device=device,
            response_time=25.5
        )
        
        response = client.get('/api/devices')
        
        data = APITestHelper.assert_json_response(response, 200)
        device_data = data['devices'][0]
        
        assert device_data['latest_response_time'] == 25.5
        assert device_data['latest_check'] is not None
    
    def test_get_devices_filter_by_group(self, client, db_session):
        """Test filtering devices by group."""
        device1 = DeviceFactory.create(device_group='servers')
        device2 = DeviceFactory.create(device_group='laptops')
        device3 = DeviceFactory.create(device_group='servers')
        
        response = client.get('/api/devices?group=servers')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['devices']) == 2
        
        # All returned devices should be in 'servers' group
        for device_data in data['devices']:
            assert device_data['device_group'] == 'servers'
    
    def test_get_devices_filter_by_type(self, client, db_session):
        """Test filtering devices by type."""
        device1 = DeviceFactory.create(device_type='router')
        device2 = DeviceFactory.create(device_type='computer')
        device3 = DeviceFactory.create(device_type='router')
        
        response = client.get('/api/devices?type=router')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['devices']) == 2
        
        # All returned devices should be routers
        for device_data in data['devices']:
            assert device_data['device_type'] == 'router'
    
    def test_get_devices_filter_by_status(self, client, db_session):
        """Test filtering devices by status."""
        # Create devices with different statuses
        up_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(minutes=2)
        )
        down_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(hours=2)
        )
        
        # Add monitoring data to make status clear
        SuccessfulMonitoringDataFactory.create(device=up_device)
        
        response = client.get('/api/devices?status=up')
        
        data = APITestHelper.assert_json_response(response, 200)
        # Should only return devices with 'up' status
        for device_data in data['devices']:
            assert device_data['status'] == 'up'
    
    def test_get_devices_monitored_only(self, client, db_session):
        """Test filtering to monitored devices only."""
        monitored_device = DeviceFactory.create(is_monitored=True)
        unmonitored_device = DeviceFactory.create(is_monitored=False)
        
        response = client.get('/api/devices?monitored=true')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['devices']) == 1
        assert data['devices'][0]['is_monitored'] is True
    
    def test_get_devices_multiple_filters(self, client, db_session):
        """Test combining multiple filters."""
        # Create devices with various combinations
        target_device = DeviceFactory.create(
            device_group='servers',
            device_type='computer',
            is_monitored=True
        )
        
        other_device1 = DeviceFactory.create(
            device_group='laptops',
            device_type='computer',
            is_monitored=True
        )
        
        other_device2 = DeviceFactory.create(
            device_group='servers',
            device_type='router',
            is_monitored=True
        )
        
        response = client.get('/api/devices?group=servers&type=computer&monitored=true')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['devices']) == 1
        assert data['devices'][0]['id'] == target_device.id


class TestDeviceDetailAPI:
    """Test device detail API endpoint."""
    
    def test_get_device_success(self, client, db_session):
        """Test getting specific device details."""
        device = DeviceFactory.create(
            ip_address='192.168.1.100',
            hostname='test-device'
        )
        
        response = client.get(f'/api/devices/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['device']['id'] == device.id
        assert data['device']['ip_address'] == '192.168.1.100'
        assert data['device']['hostname'] == 'test-device'
    
    def test_get_device_not_found(self, client, db_session):
        """Test getting non-existent device."""
        response = client.get('/api/devices/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    def test_get_device_with_monitoring_history(self, client, db_session):
        """Test device details include monitoring history."""
        device = DeviceFactory.create()
        
        # Create monitoring data
        for i in range(5):
            MonitoringDataFactory.create(
                device=device,
                timestamp=datetime.utcnow() - timedelta(minutes=i * 5)
            )
        
        response = client.get(f'/api/devices/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'monitoring_history' in data['device']
        assert len(data['device']['monitoring_history']) > 0
    
    def test_get_device_with_alerts(self, client, db_session):
        """Test device details include alert information."""
        device = DeviceFactory.create()
        
        # Create alerts
        AlertFactory.create(device=device, severity='critical')
        AlertFactory.create(device=device, severity='warning')
        
        response = client.get(f'/api/devices/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'alerts' in data['device']
        assert len(data['device']['alerts']) == 2


class TestDeviceCreateAPI:
    """Test device creation API endpoint."""
    
    def test_create_device_success(self, client, db_session):
        """Test creating a new device."""
        device_data = {
            'ip_address': '192.168.1.150',
            'mac_address': '00:11:22:33:44:55',
            'hostname': 'new-device',
            'device_type': 'computer',
            'device_group': 'laptops',
            'custom_name': 'My Laptop'
        }
        
        response = APITestHelper.post_json(client, '/api/devices', device_data)
        
        data = APITestHelper.assert_json_response(response, 201)
        assert data['success'] is True
        assert data['device']['ip_address'] == '192.168.1.150'
        assert data['device']['hostname'] == 'new-device'
        assert data['device']['custom_name'] == 'My Laptop'
        
        # Verify device was created in database
        device = Device.query.filter_by(ip_address='192.168.1.150').first()
        assert device is not None
    
    def test_create_device_minimal_data(self, client, db_session):
        """Test creating device with minimal required data."""
        device_data = {
            'ip_address': '192.168.1.151'
        }
        
        response = APITestHelper.post_json(client, '/api/devices', device_data)
        
        data = APITestHelper.assert_json_response(response, 201)
        assert data['success'] is True
        assert data['device']['ip_address'] == '192.168.1.151'
        assert data['device']['is_monitored'] is True  # Default value
    
    def test_create_device_duplicate_ip(self, client, db_session):
        """Test creating device with duplicate IP address."""
        # Create existing device
        existing_device = DeviceFactory.create(ip_address='192.168.1.100')
        
        device_data = {
            'ip_address': '192.168.1.100',  # Duplicate IP
            'hostname': 'duplicate-device'
        }
        
        response = APITestHelper.post_json(client, '/api/devices', device_data)
        
        APITestHelper.assert_error_response(response, 400, 'already exists')
    
    def test_create_device_invalid_ip(self, client, db_session):
        """Test creating device with invalid IP address."""
        device_data = {
            'ip_address': '999.999.999.999',  # Invalid IP
            'hostname': 'invalid-device'
        }
        
        response = APITestHelper.post_json(client, '/api/devices', device_data)
        
        APITestHelper.assert_error_response(response, 400)
    
    def test_create_device_missing_ip(self, client, db_session):
        """Test creating device without required IP address."""
        device_data = {
            'hostname': 'no-ip-device'
        }
        
        response = APITestHelper.post_json(client, '/api/devices', device_data)
        
        APITestHelper.assert_error_response(response, 400, 'IP address is required')


class TestDeviceUpdateAPI:
    """Test device update API endpoint."""
    
    def test_update_device_success(self, client, db_session):
        """Test updating device details."""
        device = DeviceFactory.create(
            hostname='old-hostname',
            custom_name='Old Name'
        )
        
        update_data = {
            'hostname': 'new-hostname',
            'custom_name': 'New Name',
            'device_group': 'updated-group'
        }
        
        response = APITestHelper.put_json(client, f'/api/devices/{device.id}', update_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['device']['hostname'] == 'new-hostname'
        assert data['device']['custom_name'] == 'New Name'
        assert data['device']['device_group'] == 'updated-group'
        
        # Verify update in database
        updated_device = Device.query.get(device.id)
        assert updated_device.hostname == 'new-hostname'
    
    def test_update_device_not_found(self, client, db_session):
        """Test updating non-existent device."""
        update_data = {
            'hostname': 'new-hostname'
        }
        
        response = APITestHelper.put_json(client, '/api/devices/99999', update_data)
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    def test_update_device_monitoring_status(self, client, db_session):
        """Test updating device monitoring status."""
        device = DeviceFactory.create(is_monitored=True)
        
        update_data = {
            'is_monitored': False
        }
        
        response = APITestHelper.put_json(client, f'/api/devices/{device.id}', update_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['device']['is_monitored'] is False
        
        # Verify in database
        updated_device = Device.query.get(device.id)
        assert updated_device.is_monitored is False
    
    def test_update_device_ip_change_validation(self, client, db_session):
        """Test IP address change validation."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        other_device = DeviceFactory.create(ip_address='192.168.1.101')
        
        # Try to change to existing IP
        update_data = {
            'ip_address': '192.168.1.101'  # Already exists
        }
        
        response = APITestHelper.put_json(client, f'/api/devices/{device.id}', update_data)
        
        APITestHelper.assert_error_response(response, 400)


class TestDeviceDeleteAPI:
    """Test device deletion API endpoint."""
    
    def test_delete_device_success(self, client, db_session):
        """Test deleting a device."""
        device = DeviceFactory.create()
        device_id = device.id
        
        response = client.delete(f'/api/devices/{device_id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'deleted' in data['message'].lower()
        
        # Verify device was deleted
        deleted_device = Device.query.get(device_id)
        assert deleted_device is None
    
    def test_delete_device_not_found(self, client, db_session):
        """Test deleting non-existent device."""
        response = client.delete('/api/devices/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    def test_delete_device_cascade_monitoring_data(self, client, db_session):
        """Test that deleting device cascades to monitoring data."""
        device = DeviceFactory.create()
        monitoring_data = MonitoringDataFactory.create(device=device)
        
        device_id = device.id
        monitoring_id = monitoring_data.id
        
        response = client.delete(f'/api/devices/{device_id}')
        
        APITestHelper.assert_json_response(response, 200)
        
        # Monitoring data should be deleted too
        deleted_monitoring = MonitoringData.query.get(monitoring_id)
        assert deleted_monitoring is None
    
    def test_delete_device_cascade_alerts(self, client, db_session):
        """Test that deleting device cascades to alerts."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        device_id = device.id
        alert_id = alert.id
        
        response = client.delete(f'/api/devices/{device_id}')
        
        APITestHelper.assert_json_response(response, 200)
        
        # Alert should be deleted too
        deleted_alert = Alert.query.get(alert_id)
        assert deleted_alert is None


class TestDevicePingAPI:
    """Test device ping functionality."""
    
    @patch('flask.current_app')
    def test_ping_device_success(self, mock_current_app, client, db_session):
        """Test pinging a specific device."""
        device = DeviceFactory.create()
        
        # Mock the monitor on current_app
        mock_monitor = Mock()
        mock_current_app._monitor = mock_monitor
        mock_monitor.queue_immediate_ping.return_value = True
        
        response = client.post(f'/api/devices/{device.id}/ping')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'ping initiated' in data['message'].lower()
        
        # Verify monitor was called
        mock_monitor.queue_immediate_ping.assert_called_once_with(device.id)
    
    @patch('api.devices.DeviceMonitor')
    def test_ping_device_not_found(self, mock_monitor, client, db_session):
        """Test pinging non-existent device."""
        response = client.post('/api/devices/99999/ping')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    def test_ping_all_devices(self, client, db_session):
        """Test pinging all monitored devices."""
        # Create monitored and unmonitored devices
        monitored_device1 = DeviceFactory.create(is_monitored=True)
        monitored_device2 = DeviceFactory.create(is_monitored=True)
        unmonitored_device = DeviceFactory.create(is_monitored=False)
        
        response = client.post('/api/devices/ping-all')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['devices_pinged'] == 2  # Only monitored devices
        
        # Verify the response includes results for monitored devices
        assert len(data['results']) == 2
        assert all(result['device_id'] in [monitored_device1.id, monitored_device2.id] for result in data['results'])
    
    @patch('api.devices.ping3.ping')
    def test_test_ping_ip(self, mock_ping, client, db_session):
        """Test direct IP ping functionality."""
        # Mock successful ping
        mock_ping.return_value = 0.025  # 25ms response
        
        response = client.get('/api/devices/test-ping/192.168.1.100')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['ip'] == '192.168.1.100'
        assert data['response_time'] == 25.0  # Converted to ms
        assert data['reachable'] is True
        
        mock_ping.assert_called_once_with('192.168.1.100', timeout=3)
    
    @patch('api.devices.ping3.ping')
    def test_test_ping_ip_timeout(self, mock_ping, client, db_session):
        """Test IP ping with timeout."""
        # Mock timeout (None response)
        mock_ping.return_value = None
        
        response = client.get('/api/devices/test-ping/192.168.1.100')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['reachable'] is False
        assert data['response_time'] is None
    
    def test_test_ping_invalid_ip(self, client, db_session):
        """Test ping with invalid IP address."""
        response = client.get('/api/devices/test-ping/invalid-ip')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid IP address')


class TestDeviceGroupsAndTypesAPI:
    """Test device groups and types API endpoints."""
    
    def test_get_device_groups(self, client, db_session):
        """Test getting all device groups."""
        # Create devices with various groups
        DeviceFactory.create(device_group='servers')
        DeviceFactory.create(device_group='laptops')
        DeviceFactory.create(device_group='servers')  # Duplicate
        DeviceFactory.create(device_group='phones')
        DeviceFactory.create(device_group=None)  # No group
        
        response = client.get('/api/devices/groups')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        # Should return unique groups
        groups = data['groups']
        assert 'servers' in groups
        assert 'laptops' in groups
        assert 'phones' in groups
        assert len(set(groups)) == len(groups)  # No duplicates
    
    def test_get_device_types(self, client, db_session):
        """Test getting all device types."""
        # Create devices with various types
        DeviceFactory.create(device_type='router')
        DeviceFactory.create(device_type='computer')
        DeviceFactory.create(device_type='router')  # Duplicate
        DeviceFactory.create(device_type='phone')
        DeviceFactory.create(device_type=None)  # No type
        
        response = client.get('/api/devices/types')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        # Should return unique types
        types = data['types']
        assert 'router' in types
        assert 'computer' in types
        assert 'phone' in types
        assert len(set(types)) == len(types)  # No duplicates


class TestDeviceSummaryAPI:
    """Test devices summary API endpoint."""
    
    def test_get_devices_summary(self, client, db_session):
        """Test getting device summary statistics."""
        # Create devices with various statuses
        up_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(minutes=2)
        )
        down_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(hours=2)
        )
        unknown_device = DeviceFactory.create(last_seen=None)
        
        # Add monitoring data to establish status
        SuccessfulMonitoringDataFactory.create(device=up_device)
        
        response = client.get('/api/devices/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        summary = data['summary']
        assert summary['total_devices'] == 3
        assert 'devices_up' in summary
        assert 'devices_down' in summary
        assert 'devices_unknown' in summary
        assert 'uptime_percentage' in summary
        assert summary['total_devices'] == (
            summary['devices_up'] + 
            summary['devices_down'] + 
            summary['devices_unknown']
        )
    
    def test_get_devices_summary_empty(self, client, db_session):
        """Test device summary with no devices."""
        response = client.get('/api/devices/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        summary = data['summary']
        
        assert summary['total_devices'] == 0
        assert summary['devices_up'] == 0
        assert summary['devices_down'] == 0
        assert summary['devices_unknown'] == 0
        assert summary['uptime_percentage'] == 0


class TestDeviceBulkOperationsAPI:
    """Test bulk device operations API endpoints."""
    
    def test_bulk_update_devices(self, client, db_session):
        """Test bulk updating device properties."""
        device1 = DeviceFactory.create(device_group='old-group')
        device2 = DeviceFactory.create(device_group='old-group')
        device3 = DeviceFactory.create(device_group='other-group')
        
        bulk_data = {
            'device_ids': [device1.id, device2.id],
            'updates': {
                'device_group': 'new-group',
                'is_monitored': False
            }
        }
        
        response = APITestHelper.post_json(client, '/api/devices/bulk-update', bulk_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['updated_count'] == 2
        
        # Verify updates
        updated_device1 = Device.query.get(device1.id)
        updated_device2 = Device.query.get(device2.id)
        unchanged_device3 = Device.query.get(device3.id)
        
        assert updated_device1.device_group == 'new-group'
        assert updated_device2.device_group == 'new-group'
        assert updated_device1.is_monitored is False
        assert updated_device2.is_monitored is False
        
        # Device3 should be unchanged
        assert unchanged_device3.device_group == 'other-group'
    
    @patch('flask.current_app')
    def test_bulk_ping_devices(self, mock_current_app, client, db_session):
        """Test bulk pinging multiple devices."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        device3 = DeviceFactory.create()
        
        # Mock the monitor on current_app
        mock_monitor = Mock()
        mock_current_app._monitor = mock_monitor
        mock_monitor.queue_immediate_ping.return_value = True
        
        bulk_data = {
            'device_ids': [device1.id, device2.id, device3.id]
        }
        
        response = APITestHelper.post_json(client, '/api/devices/bulk-ping', bulk_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['pinged_count'] == 3
        
        # Verify all devices were pinged
        assert mock_monitor.queue_immediate_ping.call_count == 3
        # Verify the specific device IDs were called
        expected_calls = [device1.id, device2.id, device3.id]
        actual_calls = [call[0][0] for call in mock_monitor.queue_immediate_ping.call_args_list]
        assert sorted(actual_calls) == sorted(expected_calls)
    
    def test_bulk_update_invalid_device_ids(self, client, db_session):
        """Test bulk update with invalid device IDs."""
        device1 = DeviceFactory.create()
        
        bulk_data = {
            'device_ids': [device1.id, 99999],  # 99999 doesn't exist
            'updates': {
                'device_group': 'new-group'
            }
        }
        
        response = APITestHelper.post_json(client, '/api/devices/bulk-update', bulk_data)
        
        # Should still succeed for valid devices
        data = APITestHelper.assert_json_response(response, 200)
        assert data['updated_count'] == 1  # Only device1 updated
        assert 'errors' in data  # Should report invalid IDs
    
    def test_bulk_update_missing_data(self, client, db_session):
        """Test bulk update with missing required data."""
        bulk_data = {
            'device_ids': [],  # Empty list
            'updates': {}
        }
        
        response = APITestHelper.post_json(client, '/api/devices/bulk-update', bulk_data)
        
        APITestHelper.assert_error_response(response, 400, 'No devices specified')


class TestDeviceIPHistoryAPI:
    """Test device IP history API endpoint."""
    
    def test_get_device_ip_history(self, client, db_session):
        """Test getting device IP change history."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        
        # This would require implementing IP history tracking
        # For now, test the endpoint exists and returns expected structure
        response = client.get(f'/api/devices/{device.id}/ip-history')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'ip_history' in data
        assert isinstance(data['ip_history'], list)
    
    def test_get_device_ip_history_not_found(self, client, db_session):
        """Test IP history for non-existent device."""
        response = client.get('/api/devices/99999/ip-history')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')


class TestDeviceAPIErrorHandling:
    """Test device API error handling."""
    
    def test_invalid_json_data(self, client, db_session):
        """Test handling invalid JSON data."""
        response = client.post(
            '/api/devices',
            data='invalid json{',
            content_type='application/json'
        )
        
        APITestHelper.assert_error_response(response, 400)
    
    def test_missing_content_type(self, client, db_session):
        """Test handling missing content type."""
        device_data = {
            'ip_address': '192.168.1.150'
        }
        
        response = client.post(
            '/api/devices',
            data=json.dumps(device_data)
            # Missing content_type='application/json'
        )
        
        # Should handle gracefully or return appropriate error
        assert response.status_code in [400, 415]  # Bad Request or Unsupported Media Type
    
    def test_database_error_handling(self, client, db_session):
        """Test handling database errors during operations."""
        device = DeviceFactory.create()
        
        # Mock database error
        with patch('models.db.session.commit', side_effect=Exception("Database error")):
            update_data = {
                'hostname': 'new-hostname'
            }
            
            response = APITestHelper.put_json(client, f'/api/devices/{device.id}', update_data)
            
            APITestHelper.assert_error_response(response, 500)
    
    def test_concurrent_modification_handling(self, client, db_session):
        """Test handling concurrent device modifications."""
        device = DeviceFactory.create(hostname='original')
        
        # This would test optimistic locking if implemented
        # For now, just verify basic update works
        update_data = {
            'hostname': 'updated'
        }
        
        response = APITestHelper.put_json(client, f'/api/devices/{device.id}', update_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['device']['hostname'] == 'updated'