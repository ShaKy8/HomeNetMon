"""
Unit tests for the monitoring API endpoints.

Tests cover:
- Network scanning operations
- Monitoring data retrieval and filtering
- Monitoring statistics and metrics
- Timeline and chart data
- Alert management operations
- Background monitoring status
- Export functionality
- Network topology data
- Bandwidth monitoring
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, Mock
from io import StringIO

from models import Device, MonitoringData, Alert, AlertSuppression
from tests.fixtures.factories import (
    DeviceFactory, MonitoringDataFactory, AlertFactory,
    SuccessfulMonitoringDataFactory, FailedMonitoringDataFactory,
    TimeoutMonitoringDataFactory
)
from tests.fixtures.utils import APITestHelper


class TestNetworkScanAPI:
    """Test network scanning API endpoints."""
    
    @patch('api.monitoring.get_scanner_instance')
    def test_trigger_network_scan_success(self, mock_get_scanner, client, db_session):
        """Test triggering manual network scan."""
        # Mock scanner
        mock_scanner = Mock()
        mock_get_scanner.return_value = mock_scanner
        mock_scanner.start_manual_scan.return_value = True
        
        response = client.post('/api/monitoring/scan')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'scan started' in data['message'].lower()
        
        mock_scanner.start_manual_scan.assert_called_once()
    
    @patch('api.monitoring.get_scanner_instance')
    def test_trigger_network_scan_already_running(self, mock_get_scanner, client, db_session):
        """Test triggering scan when already running."""
        # Mock scanner already running
        mock_scanner = Mock()
        mock_get_scanner.return_value = mock_scanner
        mock_scanner.is_scanning = True
        mock_scanner.start_manual_scan.return_value = False
        
        response = client.post('/api/monitoring/scan')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'already running' in data['message'].lower()
    
    @patch('api.monitoring.get_scanner_instance')
    def test_reload_scanner_config(self, mock_get_scanner, client, db_session):
        """Test reloading scanner configuration."""
        mock_scanner = Mock()
        mock_get_scanner.return_value = mock_scanner
        mock_scanner.reload_configuration.return_value = True
        
        response = client.post('/api/monitoring/reload-config')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'configuration reloaded' in data['message'].lower()
        
        mock_scanner.reload_configuration.assert_called_once()


class TestMonitoringDataAPI:
    """Test monitoring data retrieval API endpoints."""
    
    def test_get_monitoring_data_basic(self, client, db_session):
        """Test getting basic monitoring data."""
        device = DeviceFactory.create()
        
        # Create monitoring data
        data1 = SuccessfulMonitoringDataFactory.create(device=device)
        data2 = FailedMonitoringDataFactory.create(device=device)
        
        response = client.get('/api/monitoring/data')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert len(data['monitoring_data']) == 2
        assert data['total'] == 2
    
    def test_get_monitoring_data_filter_by_device(self, client, db_session):
        """Test filtering monitoring data by device."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        # Create data for both devices
        SuccessfulMonitoringDataFactory.create(device=device1)
        SuccessfulMonitoringDataFactory.create(device=device2)
        SuccessfulMonitoringDataFactory.create(device=device1)
        
        response = client.get(f'/api/monitoring/data?device_id={device1.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['monitoring_data']) == 2
        
        # All returned data should be for device1
        for item in data['monitoring_data']:
            assert item['device_id'] == device1.id
    
    def test_get_monitoring_data_time_range(self, client, db_session):
        """Test filtering monitoring data by time range."""
        device = DeviceFactory.create()
        
        # Create data at different times
        now = datetime.utcnow()
        recent_data = MonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(hours=1)
        )
        old_data = MonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(days=2)
        )
        
        # Get data from last 24 hours
        start_time = (now - timedelta(hours=24)).isoformat()
        response = client.get(f'/api/monitoring/data?start_time={start_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['monitoring_data']) == 1
        assert data['monitoring_data'][0]['id'] == recent_data.id
    
    def test_get_monitoring_data_pagination(self, client, db_session):
        """Test monitoring data pagination."""
        device = DeviceFactory.create()
        
        # Create multiple data points
        for i in range(25):
            MonitoringDataFactory.create(device=device)
        
        # Test first page
        response = client.get('/api/monitoring/data?page=1&per_page=10')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['monitoring_data']) == 10
        assert data['total'] == 25
        assert data['page'] == 1
        assert data['per_page'] == 10
        assert data['total_pages'] == 3
    
    def test_get_monitoring_data_empty(self, client, db_session):
        """Test getting monitoring data when none exists."""
        response = client.get('/api/monitoring/data')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['monitoring_data'] == []
        assert data['total'] == 0


class TestMonitoringStatisticsAPI:
    """Test monitoring statistics API endpoints."""
    
    def test_get_monitoring_statistics(self, client, db_session):
        """Test getting monitoring statistics."""
        device = DeviceFactory.create()
        
        # Create various monitoring data
        for _ in range(8):
            SuccessfulMonitoringDataFactory.create(device=device)
        for _ in range(2):
            TimeoutMonitoringDataFactory.create(device=device)
        
        response = client.get('/api/monitoring/statistics')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        stats = data['statistics']
        assert stats['total_checks'] == 10
        assert stats['successful_checks'] == 8
        assert stats['failed_checks'] == 2
        assert stats['success_rate'] == 80.0
        assert 'avg_response_time' in stats
        assert 'devices_monitored' in stats
    
    def test_get_monitoring_statistics_by_device(self, client, db_session):
        """Test getting statistics filtered by device."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        # Create data for both devices
        SuccessfulMonitoringDataFactory.create(device=device1)
        SuccessfulMonitoringDataFactory.create(device=device1)
        TimeoutMonitoringDataFactory.create(device=device2)
        
        response = client.get(f'/api/monitoring/statistics?device_id={device1.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        stats = data['statistics']
        
        assert stats['total_checks'] == 2
        assert stats['successful_checks'] == 2
        assert stats['success_rate'] == 100.0
    
    def test_get_quick_stats(self, client, db_session):
        """Test getting quick statistics for sidebar."""
        # Create devices with various statuses
        up_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(minutes=2)
        )
        down_device = DeviceFactory.create(
            last_seen=datetime.utcnow() - timedelta(hours=2)
        )
        
        # Create alerts
        AlertFactory.create(device=up_device, severity='warning')
        AlertFactory.create(device=down_device, severity='critical')
        
        response = client.get('/api/monitoring/quick-stats')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        stats = data['stats']
        assert 'total_devices' in stats
        assert 'devices_up' in stats
        assert 'devices_down' in stats
        assert 'active_alerts' in stats
        assert 'critical_alerts' in stats
    
    def test_get_monitoring_statistics_time_range(self, client, db_session):
        """Test statistics with time range filtering."""
        device = DeviceFactory.create()
        
        now = datetime.utcnow()
        
        # Recent data
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(hours=1)
        )
        
        # Old data
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(days=2)
        )
        
        # Get stats for last 24 hours
        start_time = (now - timedelta(hours=24)).isoformat()
        response = client.get(f'/api/monitoring/statistics?start_time={start_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        stats = data['statistics']
        
        assert stats['total_checks'] == 1  # Only recent data


class TestMonitoringTimelineAPI:
    """Test monitoring timeline and chart data API endpoints."""
    
    def test_get_chart_data(self, client, db_session):
        """Test getting simple chart data."""
        device = DeviceFactory.create()
        
        # Create monitoring data over time
        base_time = datetime.utcnow() - timedelta(hours=5)
        for i in range(5):
            MonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(hours=i),
                response_time=20.0 + i * 5  # Increasing response times
            )
        
        response = client.get('/api/monitoring/chart-data')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'chart_data' in data
        assert len(data['chart_data']) > 0
    
    def test_get_monitoring_timeline(self, client, db_session):
        """Test getting monitoring timeline data."""
        device = DeviceFactory.create()
        
        # Create time series data
        base_time = datetime.utcnow() - timedelta(hours=24)
        for i in range(24):
            MonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(hours=i)
            )
        
        response = client.get('/api/monitoring/timeline')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'timeline' in data
        assert len(data['timeline']) > 0
        
        # Check timeline data structure
        timeline_point = data['timeline'][0]
        assert 'timestamp' in timeline_point
        assert 'value' in timeline_point
    
    def test_get_monitoring_timeline_filtered(self, client, db_session):
        """Test timeline data with device filtering."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        # Create data for both devices
        MonitoringDataFactory.create(device=device1, response_time=10.0)
        MonitoringDataFactory.create(device=device2, response_time=50.0)
        
        response = client.get(f'/api/monitoring/timeline?device_id={device1.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'timeline' in data
        
        # Should only include device1 data
        for point in data['timeline']:
            if 'device_id' in point:
                assert point['device_id'] == device1.id
    
    def test_get_timeline_aggregation_options(self, client, db_session):
        """Test timeline data with different aggregation options."""
        device = DeviceFactory.create()
        
        # Create multiple data points
        for i in range(10):
            MonitoringDataFactory.create(device=device)
        
        # Test hourly aggregation
        response = client.get('/api/monitoring/timeline?interval=hour')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'timeline' in data
        
        # Test daily aggregation
        response = client.get('/api/monitoring/timeline?interval=day')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'timeline' in data


class TestAlertManagementAPI:
    """Test alert management API endpoints."""
    
    def test_get_alerts_basic(self, client, db_session):
        """Test getting basic alerts list."""
        device = DeviceFactory.create()
        
        alert1 = AlertFactory.create(device=device, severity='critical')
        alert2 = AlertFactory.create(device=device, severity='warning')
        
        response = client.get('/api/monitoring/alerts')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert len(data['alerts']) == 2
        assert data['total'] == 2
    
    def test_get_alerts_filter_by_severity(self, client, db_session):
        """Test filtering alerts by severity."""
        device = DeviceFactory.create()
        
        critical_alert = AlertFactory.create(device=device, severity='critical')
        warning_alert = AlertFactory.create(device=device, severity='warning')
        
        response = client.get('/api/monitoring/alerts?severity=critical')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['alerts']) == 1
        assert data['alerts'][0]['severity'] == 'critical'
    
    def test_get_alerts_filter_by_status(self, client, db_session):
        """Test filtering alerts by resolution status."""
        device = DeviceFactory.create()
        
        active_alert = AlertFactory.create(device=device, resolved=False)
        resolved_alert = AlertFactory.create(device=device, resolved=True)
        
        response = client.get('/api/monitoring/alerts?resolved=false')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['alerts']) == 1
        assert data['alerts'][0]['resolved'] is False
    
    def test_acknowledge_alert_success(self, client, db_session):
        """Test acknowledging a specific alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device, acknowledged=False)
        
        response = client.post(f'/api/monitoring/alerts/{alert.id}/acknowledge')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'acknowledged' in data['message'].lower()
        
        # Verify alert was acknowledged in database
        updated_alert = Alert.query.get(alert.id)
        assert updated_alert.acknowledged is True
        assert updated_alert.acknowledged_at is not None
    
    def test_acknowledge_alert_not_found(self, client, db_session):
        """Test acknowledging non-existent alert."""
        response = client.post('/api/monitoring/alerts/99999/acknowledge')
        
        APITestHelper.assert_error_response(response, 404, 'Alert not found')
    
    def test_acknowledge_all_alerts(self, client, db_session):
        """Test acknowledging all active alerts."""
        device = DeviceFactory.create()
        
        alert1 = AlertFactory.create(device=device, acknowledged=False)
        alert2 = AlertFactory.create(device=device, acknowledged=False)
        alert3 = AlertFactory.create(device=device, acknowledged=True)  # Already acknowledged
        
        response = client.post('/api/monitoring/alerts/acknowledge-all')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['acknowledged_count'] == 2  # Only unacknowledged alerts
        
        # Verify alerts were acknowledged
        updated_alert1 = Alert.query.get(alert1.id)
        updated_alert2 = Alert.query.get(alert2.id)
        
        assert updated_alert1.acknowledged is True
        assert updated_alert2.acknowledged is True
    
    def test_resolve_alert_success(self, client, db_session):
        """Test resolving a specific alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device, resolved=False)
        
        response = client.post(f'/api/monitoring/alerts/{alert.id}/resolve')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'resolved' in data['message'].lower()
        
        # Verify alert was resolved in database
        updated_alert = Alert.query.get(alert.id)
        assert updated_alert.resolved is True
        assert updated_alert.resolved_at is not None
    
    def test_delete_alert_success(self, client, db_session):
        """Test deleting a specific alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        alert_id = alert.id
        
        response = client.delete(f'/api/monitoring/alerts/{alert_id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'deleted' in data['message'].lower()
        
        # Verify alert was deleted
        deleted_alert = Alert.query.get(alert_id)
        assert deleted_alert is None
    
    def test_delete_all_alerts(self, client, db_session):
        """Test deleting all alerts."""
        device = DeviceFactory.create()
        
        AlertFactory.create(device=device)
        AlertFactory.create(device=device)
        AlertFactory.create(device=device)
        
        response = client.delete('/api/monitoring/alerts/delete-all')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['deleted_count'] == 3
        
        # Verify all alerts were deleted
        remaining_alerts = Alert.query.count()
        assert remaining_alerts == 0
    
    @patch('api.monitoring.get_correlation_service')
    def test_cleanup_duplicate_alerts(self, mock_get_correlation, client, db_session):
        """Test cleaning up duplicate alerts."""
        mock_correlation = Mock()
        mock_get_correlation.return_value = mock_correlation
        mock_correlation.cleanup_duplicate_alerts.return_value = 3  # Cleaned up 3 duplicates
        
        response = client.post('/api/monitoring/alerts/cleanup-duplicates')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['cleaned_up_count'] == 3
        
        mock_correlation.cleanup_duplicate_alerts.assert_called_once()


class TestBulkAlertOperations:
    """Test bulk alert operations API endpoints."""
    
    def test_bulk_acknowledge_alerts(self, client, db_session):
        """Test bulk acknowledging alerts."""
        device = DeviceFactory.create()
        
        alert1 = AlertFactory.create(device=device, acknowledged=False)
        alert2 = AlertFactory.create(device=device, acknowledged=False)
        alert3 = AlertFactory.create(device=device, acknowledged=False)
        
        bulk_data = {
            'alert_ids': [alert1.id, alert2.id]
        }
        
        response = APITestHelper.post_json(client, '/api/monitoring/alerts/bulk-acknowledge', bulk_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['acknowledged_count'] == 2
        
        # Verify specific alerts were acknowledged
        updated_alert1 = Alert.query.get(alert1.id)
        updated_alert2 = Alert.query.get(alert2.id)
        unchanged_alert3 = Alert.query.get(alert3.id)
        
        assert updated_alert1.acknowledged is True
        assert updated_alert2.acknowledged is True
        assert unchanged_alert3.acknowledged is False
    
    def test_bulk_resolve_alerts(self, client, db_session):
        """Test bulk resolving alerts."""
        device = DeviceFactory.create()
        
        alert1 = AlertFactory.create(device=device, resolved=False)
        alert2 = AlertFactory.create(device=device, resolved=False)
        
        bulk_data = {
            'alert_ids': [alert1.id, alert2.id]
        }
        
        response = APITestHelper.post_json(client, '/api/monitoring/alerts/bulk-resolve', bulk_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['resolved_count'] == 2
    
    def test_bulk_delete_alerts(self, client, db_session):
        """Test bulk deleting alerts."""
        device = DeviceFactory.create()
        
        # Create resolved alerts (typically only resolved alerts can be bulk deleted)
        alert1 = AlertFactory.create(device=device, resolved=True)
        alert2 = AlertFactory.create(device=device, resolved=True)
        
        bulk_data = {
            'alert_ids': [alert1.id, alert2.id]
        }
        
        response = APITestHelper.post_json(client, '/api/monitoring/alerts/bulk-delete', bulk_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['deleted_count'] == 2
        
        # Verify alerts were deleted
        deleted_alert1 = Alert.query.get(alert1.id)
        deleted_alert2 = Alert.query.get(alert2.id)
        
        assert deleted_alert1 is None
        assert deleted_alert2 is None
    
    def test_bulk_operations_invalid_ids(self, client, db_session):
        """Test bulk operations with invalid alert IDs."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        bulk_data = {
            'alert_ids': [alert.id, 99999]  # 99999 doesn't exist
        }
        
        response = APITestHelper.post_json(client, '/api/monitoring/alerts/bulk-acknowledge', bulk_data)
        
        # Should succeed for valid IDs and report errors for invalid ones
        data = APITestHelper.assert_json_response(response, 200)
        assert data['acknowledged_count'] == 1
        assert 'errors' in data or 'invalid_ids' in data


class TestMonitoringStatusAPI:
    """Test monitoring system status API endpoints."""
    
    @patch('api.monitoring.get_scanner_instance')
    @patch('api.monitoring.get_monitor_instance')
    def test_get_monitoring_status(self, mock_get_monitor, mock_get_scanner, client, db_session):
        """Test getting overall monitoring system status."""
        # Mock services
        mock_scanner = Mock()
        mock_monitor = Mock()
        mock_get_scanner.return_value = mock_scanner
        mock_get_monitor.return_value = mock_monitor
        
        mock_scanner.is_running = True
        mock_scanner.is_scanning = False
        mock_monitor.is_running = True
        
        response = client.get('/api/monitoring/status')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        status = data['status']
        assert status['scanner_running'] is True
        assert status['monitor_running'] is True
        assert status['scan_in_progress'] is False
        assert 'uptime' in status
        assert 'last_scan' in status
    
    def test_get_background_activity(self, client, db_session):
        """Test getting background monitoring activity."""
        response = client.get('/api/monitoring/background-activity')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        activity = data['activity']
        assert 'active_threads' in activity
        assert 'memory_usage' in activity
        assert 'recent_operations' in activity


class TestNetworkTopologyAPI:
    """Test network topology API endpoints."""
    
    def test_get_network_topology(self, client, db_session):
        """Test getting network topology data."""
        # Create devices with relationships
        router = DeviceFactory.create(
            ip_address='192.168.1.1',
            device_type='router'
        )
        computer = DeviceFactory.create(
            ip_address='192.168.1.10',
            device_type='computer'
        )
        phone = DeviceFactory.create(
            ip_address='192.168.1.20',
            device_type='phone'
        )
        
        response = client.get('/api/monitoring/topology')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        topology = data['topology']
        assert 'nodes' in topology
        assert 'edges' in topology
        assert len(topology['nodes']) == 3
        
        # Check node structure
        node = topology['nodes'][0]
        assert 'id' in node
        assert 'label' in node
        assert 'type' in node
        assert 'status' in node
    
    def test_get_topology_test(self, client, db_session):
        """Test topology test endpoint."""
        DeviceFactory.create(device_type='router')
        DeviceFactory.create(device_type='computer')
        
        response = client.get('/api/monitoring/topology-test')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'devices' in data
        assert len(data['devices']) == 2


class TestExportFunctionality:
    """Test data export API endpoints."""
    
    def test_export_monitoring_data_csv(self, client, db_session):
        """Test exporting monitoring data as CSV."""
        device = DeviceFactory.create()
        
        # Create some monitoring data
        for i in range(5):
            MonitoringDataFactory.create(device=device)
        
        response = client.get('/api/monitoring/export?format=csv')
        
        assert response.status_code == 200
        assert response.content_type == 'text/csv; charset=utf-8'
        
        # Check CSV content
        csv_content = response.get_data(as_text=True)
        assert 'timestamp' in csv_content
        assert 'device_ip' in csv_content
        assert 'response_time' in csv_content
    
    def test_export_monitoring_data_filtered(self, client, db_session):
        """Test exporting filtered monitoring data."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        MonitoringDataFactory.create(device=device1)
        MonitoringDataFactory.create(device=device2)
        
        response = client.get(f'/api/monitoring/export?format=csv&device_id={device1.id}')
        
        assert response.status_code == 200
        csv_content = response.get_data(as_text=True)
        
        # Should only contain device1 data
        lines = csv_content.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row
    
    def test_export_monitoring_data_json(self, client, db_session):
        """Test exporting monitoring data as JSON."""
        device = DeviceFactory.create()
        MonitoringDataFactory.create(device=device)
        
        response = client.get('/api/monitoring/export?format=json')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'monitoring_data' in data
        assert len(data['monitoring_data']) == 1


class TestBandwidthMonitoringAPI:
    """Test bandwidth monitoring API endpoints."""
    
    def test_get_bandwidth_data(self, client, db_session):
        """Test getting bandwidth usage data."""
        # This would require bandwidth data model/factory
        # For now, test endpoint exists and returns expected structure
        response = client.get('/api/monitoring/bandwidth')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'bandwidth_data' in data
    
    def test_get_bandwidth_timeline(self, client, db_session):
        """Test getting bandwidth timeline data."""
        response = client.get('/api/monitoring/bandwidth/timeline')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'timeline' in data
    
    def test_get_bandwidth_summary(self, client, db_session):
        """Test getting bandwidth usage summary."""
        response = client.get('/api/monitoring/bandwidth/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'summary' in data
    
    def test_get_device_bandwidth_rankings(self, client, db_session):
        """Test getting bandwidth usage rankings by device."""
        response = client.get('/api/monitoring/bandwidth/devices')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'device_rankings' in data


class TestAlertPriorityAPI:
    """Test alert priority management API endpoints."""
    
    def test_get_alert_priority_summary(self, client, db_session):
        """Test getting alert priority summary."""
        device = DeviceFactory.create()
        
        # Create alerts with different priorities
        AlertFactory.create(device=device, priority_level='CRITICAL')
        AlertFactory.create(device=device, priority_level='HIGH')
        AlertFactory.create(device=device, priority_level='MEDIUM')
        
        response = client.get('/api/monitoring/alerts/priority-summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        summary = data['summary']
        assert 'critical_count' in summary
        assert 'high_count' in summary
        assert 'medium_count' in summary
        assert 'total_alerts' in summary
    
    @patch('api.monitoring.AlertPriorityScorer')
    def test_recalculate_alert_priorities(self, mock_scorer_class, client, db_session):
        """Test recalculating priorities for all active alerts."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Mock priority scorer
        mock_scorer = Mock()
        mock_scorer_class.return_value = mock_scorer
        mock_scorer.calculate_priority_score.return_value = (85, 'HIGH', {})
        
        response = client.post('/api/monitoring/alerts/recalculate-priorities')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'recalculated_count' in data
    
    def test_get_alerts_by_priority(self, client, db_session):
        """Test getting alerts sorted by priority."""
        device = DeviceFactory.create()
        
        high_alert = AlertFactory.create(device=device, priority_score=90)
        medium_alert = AlertFactory.create(device=device, priority_score=50)
        low_alert = AlertFactory.create(device=device, priority_score=20)
        
        response = client.get('/api/monitoring/alerts/by-priority')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        alerts = data['alerts']
        assert len(alerts) == 3
        
        # Should be sorted by priority score (highest first)
        assert alerts[0]['priority_score'] >= alerts[1]['priority_score']
        assert alerts[1]['priority_score'] >= alerts[2]['priority_score']
    
    def test_get_alert_priority_details(self, client, db_session):
        """Test getting detailed priority breakdown for specific alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(
            device=device,
            priority_breakdown='{"severity_weight": 30, "device_criticality": 25}'
        )
        
        response = client.get(f'/api/monitoring/alerts/{alert.id}/priority')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'priority_details' in data
        assert 'breakdown' in data['priority_details']


class TestMonitoringAPIErrorHandling:
    """Test monitoring API error handling."""
    
    def test_invalid_device_id_parameter(self, client, db_session):
        """Test handling invalid device ID parameters."""
        response = client.get('/api/monitoring/data?device_id=invalid')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid device ID')
    
    def test_invalid_time_range_parameters(self, client, db_session):
        """Test handling invalid time range parameters."""
        response = client.get('/api/monitoring/data?start_time=invalid-date')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid time format')
    
    def test_pagination_out_of_range(self, client, db_session):
        """Test handling pagination out of range."""
        response = client.get('/api/monitoring/data?page=999&per_page=10')
        
        # Should handle gracefully, possibly returning empty results
        data = APITestHelper.assert_json_response(response, 200)
        assert data['monitoring_data'] == []
    
    def test_service_unavailable_handling(self, client, db_session):
        """Test handling when monitoring services are unavailable."""
        with patch('api.monitoring.get_scanner_instance', return_value=None):
            response = client.post('/api/monitoring/scan')
            
            APITestHelper.assert_error_response(response, 503, 'Service unavailable')