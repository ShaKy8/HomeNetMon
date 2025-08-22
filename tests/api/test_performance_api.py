"""
Unit tests for the performance API endpoints.

Tests cover:
- Performance summary and statistics
- Device performance metrics
- Performance timelines and trends
- Health score distributions
- Top performers identification
- Performance collection triggers
- Performance alert summaries
- Error handling and validation
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

from models import Device, PerformanceMetrics, Alert
from tests.fixtures.factories import (
    DeviceFactory, PerformanceMetricsFactory, 
    ExcellentPerformanceMetricsFactory, PoorPerformanceMetricsFactory,
    AlertFactory, PerformanceAlertFactory
)
from tests.fixtures.utils import APITestHelper


class TestPerformanceSummaryAPI:
    """Test performance summary API endpoints."""
    
    def test_get_performance_summary_basic(self, client, db_session):
        """Test getting basic network-wide performance summary."""
        # Create devices with performance metrics
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        ExcellentPerformanceMetricsFactory.create(device=device1, health_score=95.0)
        PoorPerformanceMetricsFactory.create(device=device2, health_score=45.0)
        
        response = client.get('/api/performance/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        summary = data['summary']
        assert 'network_health_score' in summary
        assert 'total_devices' in summary
        assert 'devices_with_metrics' in summary
        assert 'avg_response_time' in summary
        assert 'avg_uptime_percentage' in summary
        assert 'performance_distribution' in summary
        
        # Check performance distribution
        distribution = summary['performance_distribution']
        assert 'excellent' in distribution
        assert 'good' in distribution
        assert 'fair' in distribution
        assert 'poor' in distribution
    
    def test_get_performance_summary_empty(self, client, db_session):
        """Test performance summary with no devices."""
        response = client.get('/api/performance/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        summary = data['summary']
        
        assert summary['total_devices'] == 0
        assert summary['devices_with_metrics'] == 0
        assert summary['network_health_score'] == 0
    
    def test_get_performance_summary_calculation(self, client, db_session):
        """Test performance summary calculations."""
        # Create devices with known performance scores
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        device3 = DeviceFactory.create()
        
        PerformanceMetricsFactory.create(device=device1, health_score=90.0)
        PerformanceMetricsFactory.create(device=device2, health_score=80.0)
        PerformanceMetricsFactory.create(device=device3, health_score=70.0)
        
        response = client.get('/api/performance/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        summary = data['summary']
        
        # Network health should be average of device health scores
        assert summary['network_health_score'] == 80.0  # (90+80+70)/3
        assert summary['total_devices'] == 3
        assert summary['devices_with_metrics'] == 3


class TestDevicesPerformanceAPI:
    """Test devices performance API endpoints."""
    
    def test_get_devices_performance_basic(self, client, db_session):
        """Test getting performance metrics for all devices."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        
        metrics1 = ExcellentPerformanceMetricsFactory.create(device=device1)
        metrics2 = PoorPerformanceMetricsFactory.create(device=device2)
        
        response = client.get('/api/performance/devices')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert len(data['devices']) == 2
        
        # Check device performance data structure
        device_perf = data['devices'][0]
        assert 'device_id' in device_perf
        assert 'device_name' in device_perf
        assert 'health_score' in device_perf
        assert 'performance_grade' in device_perf
        assert 'last_metrics' in device_perf
    
    def test_get_devices_performance_sorting(self, client, db_session):
        """Test devices performance sorting options."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        device3 = DeviceFactory.create()
        
        PerformanceMetricsFactory.create(device=device1, health_score=90.0)
        PerformanceMetricsFactory.create(device=device2, health_score=70.0)
        PerformanceMetricsFactory.create(device=device3, health_score=80.0)
        
        # Test sorting by health score (descending)
        response = client.get('/api/performance/devices?sort=health_score&order=desc')
        
        data = APITestHelper.assert_json_response(response, 200)
        devices = data['devices']
        
        # Should be sorted by health score (highest first)
        assert devices[0]['health_score'] >= devices[1]['health_score']
        assert devices[1]['health_score'] >= devices[2]['health_score']
    
    def test_get_devices_performance_filtering(self, client, db_session):
        """Test devices performance filtering options."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        device3 = DeviceFactory.create()
        
        ExcellentPerformanceMetricsFactory.create(device=device1, health_score=95.0)
        PerformanceMetricsFactory.create(device=device2, health_score=75.0)
        PoorPerformanceMetricsFactory.create(device=device3, health_score=45.0)
        
        # Test filtering by performance grade
        response = client.get('/api/performance/devices?grade=A')
        
        data = APITestHelper.assert_json_response(response, 200)
        
        # Should only return devices with grade A
        for device in data['devices']:
            assert device['performance_grade'] == 'A'
    
    def test_get_devices_performance_pagination(self, client, db_session):
        """Test devices performance pagination."""
        # Create multiple devices with performance metrics
        for i in range(15):
            device = DeviceFactory.create()
            PerformanceMetricsFactory.create(device=device)
        
        response = client.get('/api/performance/devices?page=1&per_page=10')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert len(data['devices']) == 10
        assert data['total'] == 15
        assert data['page'] == 1
        assert data['per_page'] == 10
        assert data['total_pages'] == 2


class TestDevicePerformanceAPI:
    """Test specific device performance API endpoints."""
    
    def test_get_device_performance_success(self, client, db_session):
        """Test getting detailed performance metrics for specific device."""
        device = DeviceFactory.create()
        
        # Create performance metrics history
        base_time = datetime.utcnow() - timedelta(hours=5)
        for i in range(5):
            PerformanceMetricsFactory.create(
                device=device,
                timestamp=base_time + timedelta(hours=i),
                health_score=80.0 + i  # Improving performance
            )
        
        response = client.get(f'/api/performance/device/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        perf_data = data['device_performance']
        assert perf_data['device_id'] == device.id
        assert 'current_health_score' in perf_data
        assert 'performance_grade' in perf_data
        assert 'performance_trend' in perf_data
        assert 'metrics_history' in perf_data
        assert len(perf_data['metrics_history']) == 5
    
    def test_get_device_performance_not_found(self, client, db_session):
        """Test getting performance for non-existent device."""
        response = client.get('/api/performance/device/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    def test_get_device_performance_no_metrics(self, client, db_session):
        """Test device performance when no metrics exist."""
        device = DeviceFactory.create()
        
        response = client.get(f'/api/performance/device/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        perf_data = data['device_performance']
        
        assert perf_data['current_health_score'] is None
        assert perf_data['performance_grade'] == 'N/A'
        assert perf_data['metrics_history'] == []
    
    def test_get_device_performance_timeline_success(self, client, db_session):
        """Test getting device performance timeline."""
        device = DeviceFactory.create()
        
        # Create timeline data
        base_time = datetime.utcnow() - timedelta(days=7)
        for i in range(7):
            PerformanceMetricsFactory.create(
                device=device,
                timestamp=base_time + timedelta(days=i),
                health_score=70.0 + i * 3  # Gradually improving
            )
        
        response = client.get(f'/api/performance/device/{device.id}/timeline')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        timeline = data['timeline']
        assert len(timeline) == 7
        
        # Check timeline data structure
        timeline_point = timeline[0]
        assert 'timestamp' in timeline_point
        assert 'health_score' in timeline_point
        assert 'responsiveness_score' in timeline_point
        assert 'reliability_score' in timeline_point
    
    def test_get_device_performance_timeline_filtered(self, client, db_session):
        """Test device performance timeline with time filtering."""
        device = DeviceFactory.create()
        
        now = datetime.utcnow()
        
        # Create recent and old metrics
        recent_metrics = PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(hours=1)
        )
        old_metrics = PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(days=30)
        )
        
        # Get timeline for last 24 hours
        start_time = (now - timedelta(hours=24)).isoformat()
        response = client.get(f'/api/performance/device/{device.id}/timeline?start_time={start_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        timeline = data['timeline']
        
        assert len(timeline) == 1  # Only recent metrics
        assert timeline[0]['timestamp'] == recent_metrics.timestamp.isoformat() + 'Z'


class TestHealthScoresAPI:
    """Test health scores distribution API endpoints."""
    
    def test_get_health_scores_distribution(self, client, db_session):
        """Test getting health scores distribution."""
        # Create devices with various health scores
        devices_scores = [95, 85, 75, 65, 55, 45, 35]
        
        for score in devices_scores:
            device = DeviceFactory.create()
            PerformanceMetricsFactory.create(device=device, health_score=score)
        
        response = client.get('/api/performance/health-scores')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        distribution = data['distribution']
        assert 'score_ranges' in distribution
        assert 'grade_distribution' in distribution
        assert 'statistics' in distribution
        
        # Check score ranges (buckets)
        score_ranges = distribution['score_ranges']
        assert len(score_ranges) > 0
        
        # Check grade distribution
        grade_dist = distribution['grade_distribution']
        assert 'A+' in grade_dist or 'A' in grade_dist
        assert 'F' in grade_dist
        
        # Check statistics
        stats = distribution['statistics']
        assert 'avg_score' in stats
        assert 'median_score' in stats
        assert 'min_score' in stats
        assert 'max_score' in stats
    
    def test_get_health_scores_distribution_empty(self, client, db_session):
        """Test health scores distribution with no data."""
        response = client.get('/api/performance/health-scores')
        
        data = APITestHelper.assert_json_response(response, 200)
        distribution = data['distribution']
        
        assert distribution['score_ranges'] == []
        assert distribution['statistics']['avg_score'] == 0


class TestTopPerformersAPI:
    """Test top performers API endpoints."""
    
    def test_get_top_performers_basic(self, client, db_session):
        """Test getting top performing devices."""
        # Create devices with various performance levels
        excellent_device = DeviceFactory.create()
        good_device = DeviceFactory.create()
        poor_device = DeviceFactory.create()
        
        ExcellentPerformanceMetricsFactory.create(device=excellent_device, health_score=95.0)
        PerformanceMetricsFactory.create(device=good_device, health_score=80.0)
        PoorPerformanceMetricsFactory.create(device=poor_device, health_score=45.0)
        
        response = client.get('/api/performance/top-performers')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        performers = data['top_performers']
        assert len(performers) <= 3  # Should be limited
        
        # Should be sorted by performance (best first)
        if len(performers) > 1:
            assert performers[0]['health_score'] >= performers[1]['health_score']
        
        # Check performer data structure
        performer = performers[0]
        assert 'device_id' in performer
        assert 'device_name' in performer
        assert 'health_score' in performer
        assert 'performance_grade' in performer
    
    def test_get_top_performers_limit(self, client, db_session):
        """Test top performers with custom limit."""
        # Create many devices
        for i in range(10):
            device = DeviceFactory.create()
            PerformanceMetricsFactory.create(device=device, health_score=90 - i)
        
        response = client.get('/api/performance/top-performers?limit=5')
        
        data = APITestHelper.assert_json_response(response, 200)
        performers = data['top_performers']
        
        assert len(performers) == 5
        
        # Should be in descending order of health score
        for i in range(1, len(performers)):
            assert performers[i-1]['health_score'] >= performers[i]['health_score']
    
    def test_get_top_performers_minimum_score(self, client, db_session):
        """Test top performers with minimum score threshold."""
        # Create devices with various scores
        high_device = DeviceFactory.create()
        medium_device = DeviceFactory.create()
        low_device = DeviceFactory.create()
        
        PerformanceMetricsFactory.create(device=high_device, health_score=95.0)
        PerformanceMetricsFactory.create(device=medium_device, health_score=75.0)
        PerformanceMetricsFactory.create(device=low_device, health_score=45.0)
        
        # Get performers with minimum score of 80
        response = client.get('/api/performance/top-performers?min_score=80')
        
        data = APITestHelper.assert_json_response(response, 200)
        performers = data['top_performers']
        
        # Should only include devices with score >= 80
        for performer in performers:
            assert performer['health_score'] >= 80.0


class TestPerformanceCollectionAPI:
    """Test performance collection trigger API endpoints."""
    
    @patch('api.performance.get_performance_monitor')
    def test_trigger_device_performance_collection(self, mock_get_monitor, client, db_session):
        """Test triggering performance collection for specific device."""
        device = DeviceFactory.create()
        
        # Mock performance monitor
        mock_monitor = Mock()
        mock_get_monitor.return_value = mock_monitor
        mock_monitor.collect_device_performance_metrics.return_value = True
        
        response = client.post(f'/api/performance/collect/{device.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'collection started' in data['message'].lower()
        
        mock_monitor.collect_device_performance_metrics.assert_called_once_with(device.id)
    
    @patch('api.performance.get_performance_monitor')
    def test_trigger_device_performance_collection_not_found(self, mock_get_monitor, client, db_session):
        """Test triggering collection for non-existent device."""
        response = client.post('/api/performance/collect/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Device not found')
    
    @patch('api.performance.get_performance_monitor')
    def test_trigger_all_performance_collection(self, mock_get_monitor, client, db_session):
        """Test triggering performance collection for all devices."""
        # Create monitored devices
        device1 = DeviceFactory.create(is_monitored=True)
        device2 = DeviceFactory.create(is_monitored=True)
        unmonitored_device = DeviceFactory.create(is_monitored=False)
        
        # Mock performance monitor
        mock_monitor = Mock()
        mock_get_monitor.return_value = mock_monitor
        mock_monitor.collect_all_device_metrics.return_value = 2  # 2 devices processed
        
        response = client.post('/api/performance/collect')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert data['devices_processed'] == 2
        
        mock_monitor.collect_all_device_metrics.assert_called_once()
    
    @patch('api.performance.get_performance_monitor')
    def test_trigger_performance_collection_service_error(self, mock_get_monitor, client, db_session):
        """Test performance collection when service is unavailable."""
        device = DeviceFactory.create()
        
        # Mock service unavailable
        mock_get_monitor.return_value = None
        
        response = client.post(f'/api/performance/collect/{device.id}')
        
        APITestHelper.assert_error_response(response, 503, 'Performance monitoring service unavailable')


class TestPerformanceAlertsAPI:
    """Test performance alerts summary API endpoints."""
    
    def test_get_performance_alerts_summary(self, client, db_session):
        """Test getting performance alerts summary."""
        device1 = DeviceFactory.create()
        device2 = DeviceFactory.create()
        device3 = DeviceFactory.create()
        
        # Create performance alerts
        critical_alert = PerformanceAlertFactory.create(
            device=device1,
            alert_subtype='performance_critical',
            severity='critical'
        )
        warning_alert = PerformanceAlertFactory.create(
            device=device2,
            alert_subtype='performance_warning',
            severity='warning'
        )
        
        # Create non-performance alert
        other_alert = AlertFactory.create(
            device=device3,
            alert_type='device_down',
            severity='critical'
        )
        
        response = client.get('/api/performance/alerts/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        summary = data['summary']
        assert summary['total_performance_alerts'] == 2
        assert summary['critical_alerts'] == 1
        assert summary['warning_alerts'] == 1
        assert 'affected_devices' in summary
        assert 'alert_types' in summary
    
    def test_get_performance_alerts_summary_by_subtype(self, client, db_session):
        """Test performance alerts summary breakdown by subtype."""
        device = DeviceFactory.create()
        
        # Create different types of performance alerts
        PerformanceAlertFactory.create(
            device=device,
            alert_subtype='performance_critical'
        )
        PerformanceAlertFactory.create(
            device=device,
            alert_subtype='performance_warning'
        )
        PerformanceAlertFactory.create(
            device=device,
            alert_subtype='performance_responsiveness'
        )
        
        response = client.get('/api/performance/alerts/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        summary = data['summary']
        
        alert_types = summary['alert_types']
        assert 'performance_critical' in alert_types
        assert 'performance_warning' in alert_types
        assert 'performance_responsiveness' in alert_types
    
    def test_get_performance_alerts_summary_empty(self, client, db_session):
        """Test performance alerts summary with no alerts."""
        response = client.get('/api/performance/alerts/summary')
        
        data = APITestHelper.assert_json_response(response, 200)
        summary = data['summary']
        
        assert summary['total_performance_alerts'] == 0
        assert summary['critical_alerts'] == 0
        assert summary['warning_alerts'] == 0
        assert summary['affected_devices'] == 0


class TestPerformanceAPIAdvancedFeatures:
    """Test advanced performance API features."""
    
    def test_performance_comparison_across_time(self, client, db_session):
        """Test performance comparison across different time periods."""
        device = DeviceFactory.create()
        
        # Create metrics for different time periods
        now = datetime.utcnow()
        
        # Last week
        PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(days=7),
            health_score=70.0
        )
        
        # Yesterday
        PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(days=1),
            health_score=80.0
        )
        
        # Current
        PerformanceMetricsFactory.create(
            device=device,
            timestamp=now,
            health_score=90.0
        )
        
        response = client.get(f'/api/performance/device/{device.id}?include_comparison=true')
        
        data = APITestHelper.assert_json_response(response, 200)
        perf_data = data['device_performance']
        
        assert 'performance_comparison' in perf_data
        comparison = perf_data['performance_comparison']
        assert 'current_vs_yesterday' in comparison
        assert 'current_vs_last_week' in comparison
    
    def test_performance_trends_analysis(self, client, db_session):
        """Test performance trends analysis."""
        device = DeviceFactory.create()
        
        # Create trending data (improving performance)
        base_time = datetime.utcnow() - timedelta(days=10)
        for i in range(10):
            PerformanceMetricsFactory.create(
                device=device,
                timestamp=base_time + timedelta(days=i),
                health_score=60.0 + i * 3  # Improving trend
            )
        
        response = client.get(f'/api/performance/device/{device.id}?include_trends=true')
        
        data = APITestHelper.assert_json_response(response, 200)
        perf_data = data['device_performance']
        
        assert 'performance_trend' in perf_data
        trend = perf_data['performance_trend']
        assert trend['direction'] in ['improving', 'declining', 'stable']
        assert 'trend_strength' in trend
        assert 'prediction' in trend
    
    def test_performance_benchmarking(self, client, db_session):
        """Test performance benchmarking against network average."""
        # Create multiple devices with known performance
        devices = []
        scores = [95, 85, 75, 65, 55]  # Average = 75
        
        for score in scores:
            device = DeviceFactory.create()
            PerformanceMetricsFactory.create(device=device, health_score=score)
            devices.append(device)
        
        # Test benchmarking for the best performing device
        response = client.get(f'/api/performance/device/{devices[0].id}?include_benchmark=true')
        
        data = APITestHelper.assert_json_response(response, 200)
        perf_data = data['device_performance']
        
        assert 'benchmark' in perf_data
        benchmark = perf_data['benchmark']
        assert 'network_average' in benchmark
        assert 'percentile_rank' in benchmark
        assert 'relative_performance' in benchmark
        
        # Best device should be above average
        assert benchmark['relative_performance'] == 'above_average'


class TestPerformanceAPIFiltering:
    """Test performance API filtering and query options."""
    
    def test_devices_performance_grade_filtering(self, client, db_session):
        """Test filtering devices by performance grade."""
        # Create devices with specific grades
        a_grade_device = DeviceFactory.create()
        b_grade_device = DeviceFactory.create()
        f_grade_device = DeviceFactory.create()
        
        PerformanceMetricsFactory.create(device=a_grade_device, health_score=95)  # A+
        PerformanceMetricsFactory.create(device=b_grade_device, health_score=82)  # B
        PerformanceMetricsFactory.create(device=f_grade_device, health_score=35)  # F
        
        # Test filtering for A grades
        response = client.get('/api/performance/devices?min_grade=A')
        
        data = APITestHelper.assert_json_response(response, 200)
        
        for device in data['devices']:
            assert device['performance_grade'] in ['A+', 'A']
    
    def test_devices_performance_score_range_filtering(self, client, db_session):
        """Test filtering devices by health score range."""
        # Create devices with various scores
        high_device = DeviceFactory.create()
        medium_device = DeviceFactory.create()
        low_device = DeviceFactory.create()
        
        PerformanceMetricsFactory.create(device=high_device, health_score=90)
        PerformanceMetricsFactory.create(device=medium_device, health_score=70)
        PerformanceMetricsFactory.create(device=low_device, health_score=40)
        
        # Test score range filtering
        response = client.get('/api/performance/devices?min_score=60&max_score=80')
        
        data = APITestHelper.assert_json_response(response, 200)
        
        for device in data['devices']:
            assert 60 <= device['health_score'] <= 80
    
    def test_devices_performance_time_based_filtering(self, client, db_session):
        """Test filtering devices by metrics time period."""
        device = DeviceFactory.create()
        
        now = datetime.utcnow()
        
        # Recent metrics
        recent_metrics = PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(hours=1),
            health_score=85
        )
        
        # Old metrics
        old_metrics = PerformanceMetricsFactory.create(
            device=device,
            timestamp=now - timedelta(days=30),
            health_score=95
        )
        
        # Get devices with metrics from last 24 hours
        since = (now - timedelta(hours=24)).isoformat()
        response = client.get(f'/api/performance/devices?since={since}')
        
        data = APITestHelper.assert_json_response(response, 200)
        
        # Should use recent metrics, not old ones
        if data['devices']:
            device_data = data['devices'][0]
            assert device_data['health_score'] == 85


class TestPerformanceAPIErrorHandling:
    """Test performance API error handling."""
    
    def test_invalid_device_id_parameter(self, client, db_session):
        """Test handling invalid device ID parameter."""
        response = client.get('/api/performance/device/invalid')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid device ID')
    
    def test_invalid_time_parameters(self, client, db_session):
        """Test handling invalid time parameters."""
        device = DeviceFactory.create()
        
        response = client.get(f'/api/performance/device/{device.id}/timeline?start_time=invalid-date')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid time format')
    
    def test_invalid_score_range_parameters(self, client, db_session):
        """Test handling invalid score range parameters."""
        response = client.get('/api/performance/devices?min_score=invalid')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid score value')
    
    def test_invalid_pagination_parameters(self, client, db_session):
        """Test handling invalid pagination parameters."""
        response = client.get('/api/performance/devices?page=0&per_page=-1')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid pagination parameters')
    
    def test_performance_service_unavailable(self, client, db_session):
        """Test handling when performance service is unavailable."""
        device = DeviceFactory.create()
        
        with patch('api.performance.get_performance_monitor', return_value=None):
            response = client.post(f'/api/performance/collect/{device.id}')
            
            APITestHelper.assert_error_response(response, 503, 'Service unavailable')
    
    def test_database_error_handling(self, client, db_session):
        """Test handling database errors during performance operations."""
        device = DeviceFactory.create()
        
        with patch('models.PerformanceMetrics.query', side_effect=Exception("Database error")):
            response = client.get(f'/api/performance/device/{device.id}')
            
            APITestHelper.assert_error_response(response, 500, 'Internal server error')
    
    def test_large_dataset_handling(self, client, db_session):
        """Test handling large datasets in performance queries."""
        device = DeviceFactory.create()
        
        # Create many performance metrics
        for i in range(1000):
            PerformanceMetricsFactory.create(device=device)
        
        # Should handle large dataset gracefully
        response = client.get(f'/api/performance/device/{device.id}/timeline')
        
        # Should either succeed with pagination or return appropriate response
        assert response.status_code in [200, 206]  # OK or Partial Content