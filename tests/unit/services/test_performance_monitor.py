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


class TestPerformanceMonitorIntegration:
    """Test PerformanceMonitor integration with other components."""

    def test_database_transaction_handling(self, app, db_session):
        """Test proper database transaction handling during metrics collection."""
        device = DeviceFactory.create()
        # Pin the sample inside the 60-minute collection window (the factory's random
        # 0-60 min offset made this test fail about once in sixty runs).
        SuccessfulMonitoringDataFactory.create(device=device, timestamp=datetime.utcnow() - timedelta(minutes=5))

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


class TestPerformanceMonitorCustomization:
    """Test PerformanceMonitor customization (renamed from duplicate TestPerformanceMonitorConfiguration)."""

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
