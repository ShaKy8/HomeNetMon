"""
Unit tests for the PerformanceMonitor service.

Tests cover:
- Service initialization and configuration
- Performance metrics collection and aggregation
- Health score calculations
- Alert threshold monitoring
- Background thread management
- Database integration and error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import time

from services.performance_monitor import PerformanceMonitor
from models import Device, MonitoringData, PerformanceMetrics, Configuration, Alert
from tests.fixtures.factories import (
    DeviceFactory, MonitoringDataFactory, PerformanceMetricsFactory,
    SuccessfulMonitoringDataFactory, FailedMonitoringDataFactory,
    ConfigurationFactory
)
from tests.fixtures.utils import MockHelper, TimeHelper


class TestPerformanceMonitorInitialization:
    """Test PerformanceMonitor service initialization."""
    
    def test_performance_monitor_init_default(self):
        """Test PerformanceMonitor initialization with defaults."""
        monitor = PerformanceMonitor()
        
        assert monitor.app is None
        assert monitor.socketio is None
        assert monitor.is_running is False
        assert monitor.monitor_thread is None
        assert monitor.collection_interval == 300  # 5 minutes default
        assert isinstance(monitor._stop_event, threading.Event)
        
        # Check default alert thresholds
        assert monitor.alert_thresholds['health_score_critical'] == 50
        assert monitor.alert_thresholds['health_score_warning'] == 70
        assert monitor.alert_thresholds['health_score_recovery'] == 80
    
    def test_performance_monitor_init_with_app(self, app):
        """Test PerformanceMonitor initialization with Flask app."""
        mock_socketio = Mock()
        monitor = PerformanceMonitor(app=app, socketio=mock_socketio)
        
        assert monitor.app == app
        assert monitor.socketio == mock_socketio
        assert monitor.is_running is False
    
    def test_performance_monitor_alert_thresholds(self):
        """Test default alert threshold configuration."""
        monitor = PerformanceMonitor()
        
        expected_thresholds = {
            'health_score_critical': 50,
            'health_score_warning': 70,
            'health_score_recovery': 80,
            'responsiveness_critical': 40,
            'reliability_critical': 60,
            'consecutive_periods': 2
        }
        
        for key, expected_value in expected_thresholds.items():
            assert monitor.alert_thresholds[key] == expected_value


class TestPerformanceMonitorConfiguration:
    """Test PerformanceMonitor configuration management."""
    
    def test_get_config_value_with_app(self, app, db_session):
        """Test getting configuration value with Flask app context."""
        # Create a configuration entry
        config = ConfigurationFactory.create(
            key='performance_interval',
            value='600'
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            value = monitor.get_config_value('performance_interval', '300')
            assert value == '600'
    
    def test_get_config_value_default(self, app, db_session):
        """Test getting default configuration value when key doesn't exist."""
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            value = monitor.get_config_value('nonexistent_key', '300')
            assert value == '300'
    
    def test_get_config_value_no_app(self):
        """Test getting configuration value without Flask app."""
        monitor = PerformanceMonitor()
        
        # Should return default when no app context
        value = monitor.get_config_value('any_key', '300')
        assert value == '300'
    
    @patch('services.performance_monitor.Configuration.get_value')
    def test_get_config_value_exception_handling(self, mock_get_value, app):
        """Test configuration value retrieval with exception handling."""
        mock_get_value.side_effect = Exception("Database error")
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            value = monitor.get_config_value('test_key', '300')
            assert value == '300'  # Should return default on exception


class TestPerformanceMetricsCollection:
    """Test performance metrics collection and aggregation."""
    
    def test_collect_device_performance_metrics_no_app(self):
        """Test performance metrics collection without Flask app."""
        monitor = PerformanceMonitor()
        
        result = monitor.collect_device_performance_metrics(device_id=1)
        assert result is None
    
    def test_collect_device_performance_metrics_basic(self, app, db_session):
        """Test basic performance metrics collection for a device."""
        device = DeviceFactory.create()
        
        # Create monitoring data for the device
        base_time = datetime.utcnow() - timedelta(hours=2)
        for i in range(10):
            SuccessfulMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=i * 6),
                response_time=20.0 + i,  # Increasing response times
                packet_loss=0.0
            )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            metrics = monitor.collect_device_performance_metrics(
                device_id=device.id,
                collection_period_minutes=60
            )
        
        assert metrics is not None
        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.device_id == device.id
        assert metrics.health_score is not None
        assert 0 <= metrics.health_score <= 100
        assert metrics.sample_count > 0
    
    def test_collect_device_performance_metrics_no_data(self, app, db_session):
        """Test performance metrics collection with no monitoring data."""
        device = DeviceFactory.create()
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            metrics = monitor.collect_device_performance_metrics(
                device_id=device.id,
                collection_period_minutes=60
            )
        
        # Should handle gracefully with no data
        assert metrics is None or metrics.sample_count == 0
    
    def test_collect_device_performance_metrics_mixed_data(self, app, db_session):
        """Test performance metrics collection with mixed success/failure data."""
        device = DeviceFactory.create()
        
        # Create mixed monitoring data
        base_time = datetime.utcnow() - timedelta(hours=1)
        
        # 70% successful, 30% failed
        for i in range(7):
            SuccessfulMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=i * 8)
            )
        
        for i in range(3):
            FailedMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=(i + 7) * 8)
            )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            metrics = monitor.collect_device_performance_metrics(
                device_id=device.id,
                collection_period_minutes=60
            )
        
        assert metrics is not None
        assert metrics.uptime_percentage == 70.0  # 7 out of 10 successful
        assert metrics.failed_checks == 3
        assert metrics.successful_checks == 7
        assert metrics.total_checks == 10
    
    @patch('services.performance_monitor.PerformanceMetrics.calculate_health_score')
    def test_health_score_calculation_integration(self, mock_calculate, app, db_session):
        """Test integration with health score calculation."""
        mock_calculate.return_value = 85.5
        
        device = DeviceFactory.create()
        SuccessfulMonitoringDataFactory.create(device=device)
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            metrics = monitor.collect_device_performance_metrics(device_id=device.id)
        
        # Should call the static health score calculation method
        mock_calculate.assert_called_once()
        assert metrics.health_score == 85.5


class TestPerformanceAlertGeneration:
    """Test performance alert generation based on thresholds."""
    
    def test_check_performance_alerts_critical_health(self, app, db_session):
        """Test alert generation for critical health score."""
        device = DeviceFactory.create()
        
        # Create performance metrics with critical health score
        critical_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=45.0,  # Below critical threshold of 50
            timestamp=datetime.utcnow()
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            alerts = monitor.check_performance_alerts(device.id)
        
        assert len(alerts) > 0
        critical_alert = next((a for a in alerts if a.severity == 'critical'), None)
        assert critical_alert is not None
        assert critical_alert.alert_type == 'performance'
        assert critical_alert.device_id == device.id
    
    def test_check_performance_alerts_warning_health(self, app, db_session):
        """Test alert generation for warning health score."""
        device = DeviceFactory.create()
        
        # Create performance metrics with warning health score
        warning_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=65.0,  # Below warning threshold of 70, above critical of 50
            timestamp=datetime.utcnow()
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            alerts = monitor.check_performance_alerts(device.id)
        
        warning_alert = next((a for a in alerts if a.severity == 'warning'), None)
        assert warning_alert is not None
        assert warning_alert.alert_type == 'performance'
    
    def test_check_performance_alerts_good_health(self, app, db_session):
        """Test no alert generation for good health score."""
        device = DeviceFactory.create()
        
        # Create performance metrics with good health score
        good_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=85.0,  # Above warning threshold
            timestamp=datetime.utcnow()
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            alerts = monitor.check_performance_alerts(device.id)
        
        # Should not generate alerts for good performance
        performance_alerts = [a for a in alerts if a.alert_type == 'performance']
        assert len(performance_alerts) == 0
    
    def test_check_performance_alerts_consecutive_periods(self, app, db_session):
        """Test alert generation requires consecutive periods below threshold."""
        device = DeviceFactory.create()
        
        # Create performance metrics showing improvement (shouldn't alert)
        old_bad_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=45.0,  # Critical
            timestamp=datetime.utcnow() - timedelta(hours=1)
        )
        
        current_good_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=85.0,  # Good - recovered
            timestamp=datetime.utcnow()
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            alerts = monitor.check_performance_alerts(device.id)
        
        # Should not alert if current performance is good
        critical_alerts = [a for a in alerts if a.severity == 'critical']
        assert len(critical_alerts) == 0


class TestPerformanceMonitorThreading:
    """Test PerformanceMonitor background thread management."""
    
    def test_start_monitoring_thread(self, app):
        """Test starting the performance monitoring thread."""
        monitor = PerformanceMonitor(app=app)
        
        # Mock the monitoring method to avoid actual work
        monitor.run_performance_monitoring = Mock()
        
        monitor.start()
        
        assert monitor.is_running is True
        assert monitor.monitor_thread is not None
        assert monitor.monitor_thread.is_alive()
        
        # Clean up
        monitor.stop()
        monitor.monitor_thread.join(timeout=1)
    
    def test_stop_monitoring_thread(self, app):
        """Test stopping the performance monitoring thread."""
        monitor = PerformanceMonitor(app=app)
        
        # Mock the monitoring method
        monitor.run_performance_monitoring = Mock()
        
        # Start and then stop
        monitor.start()
        assert monitor.is_running is True
        
        monitor.stop()
        monitor.monitor_thread.join(timeout=1)
        
        assert monitor.is_running is False
        assert monitor._stop_event.is_set()
    
    def test_double_start_prevention(self, app):
        """Test that starting already running monitor doesn't create duplicate threads."""
        monitor = PerformanceMonitor(app=app)
        monitor.run_performance_monitoring = Mock()
        
        # Start twice
        monitor.start()
        first_thread = monitor.monitor_thread
        
        monitor.start()  # Should not create new thread
        second_thread = monitor.monitor_thread
        
        assert first_thread == second_thread
        
        # Clean up
        monitor.stop()
        monitor.monitor_thread.join(timeout=1)
    
    def test_stop_when_not_running(self, app):
        """Test stopping monitor when not running."""
        monitor = PerformanceMonitor(app=app)
        
        # Should handle gracefully
        monitor.stop()
        
        assert monitor.is_running is False


class TestPerformanceMonitorIntegration:
    """Test PerformanceMonitor integration with other components."""
    
    @patch('services.performance_monitor.PerformanceMonitor.socketio')
    def test_socketio_integration(self, mock_socketio, app, db_session):
        """Test SocketIO integration for real-time updates."""
        device = DeviceFactory.create()
        SuccessfulMonitoringDataFactory.create(device=device)
        
        monitor = PerformanceMonitor(app=app, socketio=mock_socketio)
        
        with app.app_context():
            monitor.emit_performance_update(device.id)
        
        # Should emit performance update via SocketIO
        mock_socketio.emit.assert_called()
        call_args = mock_socketio.emit.call_args[0]
        assert 'performance_update' in call_args[0]
    
    def test_database_transaction_handling(self, app, db_session):
        """Test proper database transaction handling during metrics collection."""
        device = DeviceFactory.create()
        SuccessfulMonitoringDataFactory.create(device=device)
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            # Should handle database operations properly
            metrics = monitor.collect_device_performance_metrics(device.id)
            
            # Verify metrics were persisted
            saved_metrics = PerformanceMetrics.query.filter_by(device_id=device.id).first()
            assert saved_metrics is not None
    
    def test_error_handling_during_collection(self, app, db_session):
        """Test error handling during metrics collection."""
        device = DeviceFactory.create()
        
        monitor = PerformanceMonitor(app=app)
        
        # Mock database error
        with patch('services.performance_monitor.db.session.commit', side_effect=Exception("DB Error")):
            with app.app_context():
                # Should handle error gracefully
                result = monitor.collect_device_performance_metrics(device.id)
                
                # Should return None or handle error appropriately
                assert result is None or isinstance(result, PerformanceMetrics)


class TestPerformanceMonitorConfiguration:
    """Test PerformanceMonitor configuration and customization."""
    
    def test_custom_collection_interval(self, app, db_session):
        """Test custom collection interval configuration."""
        # Create configuration for custom interval
        ConfigurationFactory.create(
            key='performance_collection_interval',
            value='900'  # 15 minutes
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            interval = int(monitor.get_config_value('performance_collection_interval', '300'))
            assert interval == 900
    
    def test_custom_alert_thresholds(self, app, db_session):
        """Test custom alert threshold configuration."""
        # Create configuration for custom thresholds
        ConfigurationFactory.create(
            key='performance_alert_critical_threshold',
            value='40'
        )
        ConfigurationFactory.create(
            key='performance_alert_warning_threshold',
            value='60'
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            critical_threshold = int(monitor.get_config_value('performance_alert_critical_threshold', '50'))
            warning_threshold = int(monitor.get_config_value('performance_alert_warning_threshold', '70'))
            
            assert critical_threshold == 40
            assert warning_threshold == 60
    
    def test_performance_data_retention(self, app, db_session):
        """Test performance data retention configuration."""
        ConfigurationFactory.create(
            key='performance_retention_days',
            value='14'
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            retention_days = int(monitor.get_config_value('performance_retention_days', '30'))
            assert retention_days == 14


class TestPerformanceMonitorStatistics:
    """Test PerformanceMonitor statistical calculations."""
    
    def test_calculate_response_time_statistics(self, app, db_session):
        """Test response time statistical calculations."""
        device = DeviceFactory.create()
        
        # Create monitoring data with known response times
        response_times = [10.0, 15.0, 20.0, 25.0, 30.0]
        for rt in response_times:
            MonitoringDataFactory.create(
                device=device,
                response_time=rt,
                packet_loss=0.0
            )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            stats = monitor.calculate_response_time_stats(device.id)
        
        assert stats['avg'] == 20.0  # Average
        assert stats['min'] == 10.0  # Minimum
        assert stats['max'] == 30.0  # Maximum
        assert stats['std_dev'] > 0   # Standard deviation
    
    def test_calculate_availability_statistics(self, app, db_session):
        """Test availability statistical calculations."""
        device = DeviceFactory.create()
        
        # Create 80% successful, 20% failed
        for _ in range(8):
            SuccessfulMonitoringDataFactory.create(device=device)
        for _ in range(2):
            FailedMonitoringDataFactory.create(device=device)
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            stats = monitor.calculate_availability_stats(device.id)
        
        assert stats['uptime_percentage'] == 80.0
        assert stats['total_checks'] == 10
        assert stats['successful_checks'] == 8
        assert stats['failed_checks'] == 2
    
    def test_detect_performance_anomalies(self, app, db_session):
        """Test performance anomaly detection."""
        device = DeviceFactory.create()
        
        # Create baseline normal performance
        for i in range(10):
            MonitoringDataFactory.create(
                device=device,
                response_time=20.0 + (i % 3),  # 20-22ms range
                packet_loss=0.0
            )
        
        # Create anomalous performance
        anomaly_data = MonitoringDataFactory.create(
            device=device,
            response_time=200.0,  # 10x normal
            packet_loss=0.0
        )
        
        monitor = PerformanceMonitor(app=app)
        
        with app.app_context():
            anomalies = monitor.detect_performance_anomalies(device.id)
        
        assert len(anomalies) > 0
        assert anomaly_data.id in [a.id for a in anomalies]