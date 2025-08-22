"""
Unit tests for the AlertManager service.

Tests cover:
- Service initialization and configuration
- Alert creation and lifecycle management
- Device down detection and alerting
- High latency and packet loss detection
- Critical device identification
- Notification sending (email, webhook, push)
- Alert deduplication and correlation
- Background thread management
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import smtplib

from monitoring.alerts import AlertManager
from models import Device, Alert, MonitoringData, Configuration
from tests.fixtures.factories import (
    DeviceFactory, AlertFactory, MonitoringDataFactory,
    SuccessfulMonitoringDataFactory, FailedMonitoringDataFactory,
    TimeoutMonitoringDataFactory, ConfigurationFactory
)
from tests.fixtures.utils import AlertTestHelper, MockHelper


class TestAlertManagerInitialization:
    """Test AlertManager service initialization."""
    
    def test_alert_manager_init_default(self):
        """Test AlertManager initialization with defaults."""
        manager = AlertManager()
        
        assert manager.app is None
        assert manager.is_running is False
        assert manager.rule_engine_service is None
        assert manager.correlation_service is None
        assert isinstance(manager._stop_event, threading.Event)
        
        # Check default alert thresholds
        assert manager.alert_thresholds['device_down_minutes_critical'] == 10
        assert manager.alert_thresholds['device_down_minutes_regular'] == 20
        assert manager.alert_thresholds['high_latency_ms'] == 1000
        assert manager.alert_thresholds['packet_loss_threshold'] == 50
        assert manager.alert_thresholds['consecutive_failures_required'] == 2
    
    def test_alert_manager_init_with_app(self, app):
        """Test AlertManager initialization with Flask app."""
        manager = AlertManager(app=app)
        
        assert manager.app == app
        assert manager.is_running is False
    
    def test_alert_manager_threshold_configuration(self):
        """Test default alert threshold configuration."""
        manager = AlertManager()
        
        expected_thresholds = {
            'device_down_minutes_critical': 10,
            'device_down_minutes_regular': 20,
            'high_latency_ms': 1000,
            'packet_loss_threshold': 50,
            'consecutive_failures_required': 2
        }
        
        for key, expected_value in expected_thresholds.items():
            assert manager.alert_thresholds[key] == expected_value


class TestCriticalDeviceIdentification:
    """Test critical device identification logic."""
    
    def test_is_critical_device_router_ip(self, db_session):
        """Test critical device identification by router IP (.1)."""
        manager = AlertManager()
        
        router_device = DeviceFactory.create(ip_address='192.168.1.1')
        regular_device = DeviceFactory.create(ip_address='192.168.1.100')
        
        assert manager.is_critical_device(router_device) is True
        assert manager.is_critical_device(regular_device) is False
    
    def test_is_critical_device_server_ip(self, db_session):
        """Test critical device identification by server IP (.64)."""
        manager = AlertManager()
        
        server_device = DeviceFactory.create(ip_address='192.168.1.64')
        regular_device = DeviceFactory.create(ip_address='192.168.1.50')
        
        assert manager.is_critical_device(server_device) is True
        assert manager.is_critical_device(regular_device) is False
    
    def test_is_critical_device_by_type(self, db_session):
        """Test critical device identification by device type."""
        manager = AlertManager()
        
        router_device = DeviceFactory.create(device_type='router')
        server_device = DeviceFactory.create(device_type='server')
        computer_device = DeviceFactory.create(device_type='computer')
        
        assert manager.is_critical_device(router_device) is True
        assert manager.is_critical_device(server_device) is True
        assert manager.is_critical_device(computer_device) is False
    
    def test_is_critical_device_by_hostname(self, db_session):
        """Test critical device identification by hostname."""
        manager = AlertManager()
        
        nuc_device = DeviceFactory.create(hostname='home-nuc-server')
        gateway_device = DeviceFactory.create(hostname='main-gateway')
        laptop_device = DeviceFactory.create(hostname='laptop-01')
        
        assert manager.is_critical_device(nuc_device) is True
        assert manager.is_critical_device(gateway_device) is True
        assert manager.is_critical_device(laptop_device) is False
    
    def test_is_critical_device_none_values(self, db_session):
        """Test critical device identification with None values."""
        manager = AlertManager()
        
        device_no_type = DeviceFactory.create(device_type=None, hostname=None)
        device_empty_hostname = DeviceFactory.create(hostname='')
        
        # Should handle None/empty values gracefully
        assert manager.is_critical_device(device_no_type) is False
        assert manager.is_critical_device(device_empty_hostname) is False


class TestConsecutiveFailureDetection:
    """Test consecutive failure detection logic."""
    
    def test_has_consecutive_failures_never_seen(self, db_session):
        """Test consecutive failures for device never seen."""
        manager = AlertManager()
        device = DeviceFactory.create(last_seen=None)
        
        result = manager.has_consecutive_failures(device, required_failures=2)
        assert result is True  # Never seen = definitely down
    
    def test_has_consecutive_failures_with_timeouts(self, app, db_session):
        """Test consecutive failures with timeout monitoring data."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create consecutive timeout records
        base_time = datetime.utcnow() - timedelta(minutes=30)
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=i * 5)
            )
        
        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)
        
        assert result is True
    
    def test_has_consecutive_failures_mixed_results(self, app, db_session):
        """Test consecutive failures with mixed success/failure data."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        base_time = datetime.utcnow() - timedelta(minutes=30)
        
        # Create pattern: success, fail, fail, success
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=base_time
        )
        TimeoutMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=5)
        )
        TimeoutMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=10)
        )
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=15)
        )
        
        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)
        
        # Latest is success, so not consecutive failures
        assert result is False
    
    def test_has_consecutive_failures_not_enough(self, app, db_session):
        """Test consecutive failures with insufficient failure count."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create only one failure
        TimeoutMonitoringDataFactory.create(device=device)
        
        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)
        
        assert result is False


class TestDeviceDownAlertCreation:
    """Test device down alert creation logic."""
    
    def test_create_device_down_alert_critical_device(self, app, db_session):
        """Test creating device down alert for critical device."""
        manager = AlertManager(app=app)
        
        # Critical device (router)
        critical_device = DeviceFactory.create(
            ip_address='192.168.1.1',
            last_seen=datetime.utcnow() - timedelta(minutes=15),
            is_monitored=True
        )
        
        # Create consecutive failures
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=critical_device,
                timestamp=datetime.utcnow() - timedelta(minutes=10 - i)
            )
        
        with app.app_context():
            # Call the actual method that checks devices and creates alerts
            manager.check_device_down_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=critical_device.id,
                alert_type='device_down'
            ).first()
        
        assert alert is not None
        assert alert.alert_type == 'device_down'
        assert alert.severity == 'critical'
        assert alert.device_id == critical_device.id
        assert 'critical' in alert.message.lower()
    
    def test_create_device_down_alert_regular_device(self, app, db_session):
        """Test creating device down alert for regular device."""
        manager = AlertManager(app=app)
        
        # Regular device
        regular_device = DeviceFactory.create(
            ip_address='192.168.1.100',
            last_seen=datetime.utcnow() - timedelta(minutes=25)
        )
        
        # Create consecutive failures
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=regular_device,
                timestamp=datetime.utcnow() - timedelta(minutes=15 - i)
            )
        
        with app.app_context():
            # Call the actual method that checks devices and creates alerts
            manager.check_device_down_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=regular_device.id,
                alert_type='device_down'
            ).first()
        
        assert alert is not None
        assert alert.alert_type == 'device_down'
        assert alert.severity == 'warning'  # Regular devices get warning
        assert alert.device_id == regular_device.id
    
    def test_create_device_down_alert_too_recent(self, app, db_session):
        """Test not creating device down alert for recently seen device."""
        manager = AlertManager(app=app)
        
        # Device seen recently
        recent_device = DeviceFactory.create(
            ip_address='192.168.1.1',
            last_seen=datetime.utcnow() - timedelta(minutes=5)  # Too recent
        )
        
        with app.app_context():
            # Call the actual method that checks devices and creates alerts
            manager.check_device_down_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=recent_device.id,
                alert_type='device_down'
            ).first()
        
        assert alert is None  # Should not create alert
    
    def test_create_device_down_alert_no_consecutive_failures(self, app, db_session):
        """Test not creating device down alert without consecutive failures."""
        manager = AlertManager(app=app)
        
        device = DeviceFactory.create(
            ip_address='192.168.1.1',
            last_seen=datetime.utcnow() - timedelta(minutes=15)
        )
        
        # Create mixed success/failure (no consecutive failures)
        SuccessfulMonitoringDataFactory.create(device=device)
        
        with app.app_context():
            # Call the actual method that checks devices and creates alerts
            manager.check_device_down_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type='device_down'
            ).first()
        
        assert alert is None


class TestHighLatencyAlertCreation:
    """Test high latency alert creation logic."""
    
    def test_create_high_latency_alert(self, app, db_session):
        """Test creating high latency alert."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create(is_monitored=True)
        
        # Create multiple high latency monitoring data points within last 5 minutes
        # (Implementation requires at least 3 high latency measurements)
        base_time = datetime.utcnow() - timedelta(minutes=2)
        for i in range(3):
            MonitoringDataFactory.create(
                device=device,
                response_time=1500.0,  # Above 1000ms threshold
                packet_loss=0.0,
                timestamp=base_time + timedelta(minutes=i)
            )
        
        with app.app_context():
            # Call the actual method that checks for high latency patterns
            manager.check_high_latency_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type='high_latency'
            ).first()
        
        assert alert is not None
        assert alert.alert_type == 'high_latency'
        assert alert.severity == 'warning'
        assert alert.device_id == device.id
        assert 'latency' in alert.message.lower()
    
    def test_create_high_latency_alert_below_threshold(self, app, db_session):
        """Test not creating high latency alert for normal response time."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create(is_monitored=True)
        
        # Create normal latency monitoring data (below threshold)
        base_time = datetime.utcnow() - timedelta(minutes=2)
        for i in range(3):
            SuccessfulMonitoringDataFactory.create(
                device=device,
                response_time=50.0,  # Below 1000ms threshold
                timestamp=base_time + timedelta(minutes=i)
            )
        
        with app.app_context():
            # Call the actual method that checks for high latency patterns
            manager.check_high_latency_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type='high_latency'
            ).first()
        
        assert alert is None
    
    def test_create_high_latency_alert_timeout(self, app, db_session):
        """Test not creating high latency alert for timeout (None response)."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create(is_monitored=True)
        
        # Create timeout monitoring data (response_time=None)
        base_time = datetime.utcnow() - timedelta(minutes=2)
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=i)
            )
        
        with app.app_context():
            # Call the actual method that checks for high latency patterns
            manager.check_high_latency_alerts()
            
            # Query the database for created alert
            from models import Alert
            alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type='high_latency'
            ).first()
        
        assert alert is None  # Timeout should be handled as device down, not latency


class TestPacketLossAlertCreation:
    """Test packet loss alert creation logic."""
    
    def test_create_packet_loss_alert(self, app, db_session):
        """Test creating packet loss alert."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create high packet loss monitoring data
        packet_loss_data = MonitoringDataFactory.create(
            device=device,
            response_time=50.0,
            packet_loss=75.0  # Above 50% threshold
        )
        
        with app.app_context():
            alert = manager.create_packet_loss_alert(device, packet_loss_data)
        
        assert alert is not None
        assert alert.alert_type == 'packet_loss'
        assert alert.severity == 'warning'
        assert alert.device_id == device.id
        assert '75' in alert.message
    
    def test_create_packet_loss_alert_below_threshold(self, app, db_session):
        """Test not creating packet loss alert for low packet loss."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create low packet loss monitoring data
        low_loss_data = SuccessfulMonitoringDataFactory.create(
            device=device,
            packet_loss=2.0  # Below 50% threshold
        )
        
        with app.app_context():
            alert = manager.create_packet_loss_alert(device, low_loss_data)
        
        assert alert is None


class TestNotificationSending:
    """Test notification sending functionality."""
    
    @patch('monitoring.alerts.smtplib.SMTP')
    def test_send_email_notification(self, mock_smtp, app, db_session):
        """Test sending email notification."""
        manager = AlertManager(app=app)
        
        # Configure email settings
        ConfigurationFactory.create(key='smtp_server', value='smtp.example.com')
        ConfigurationFactory.create(key='smtp_port', value='587')
        ConfigurationFactory.create(key='smtp_username', value='test@example.com')
        ConfigurationFactory.create(key='smtp_password', value='password')
        ConfigurationFactory.create(key='alert_email_to', value='admin@example.com')
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device, severity='critical')
        
        # Mock SMTP instance
        mock_smtp_instance = Mock()
        mock_smtp.return_value = mock_smtp_instance
        
        with app.app_context():
            result = manager.send_email_alert(alert)
        
        assert result is True
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once()
        mock_smtp_instance.send_message.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()
    
    @patch('monitoring.alerts.smtplib.SMTP')
    def test_send_email_notification_failure(self, mock_smtp, app, db_session):
        """Test email notification sending failure."""
        manager = AlertManager(app=app)
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Mock SMTP failure
        mock_smtp.side_effect = smtplib.SMTPException("Connection failed")
        
        with app.app_context():
            result = manager.send_email_alert(alert)
        
        assert result is False
    
    @patch('monitoring.alerts.requests.post')
    def test_send_webhook_notification(self, mock_post, app, db_session):
        """Test sending webhook notification."""
        manager = AlertManager(app=app)
        
        # Configure webhook settings
        ConfigurationFactory.create(key='webhook_url', value='https://example.com/webhook')
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device, severity='critical')
        
        # Mock successful webhook response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        with app.app_context():
            result = manager.send_webhook_alert(alert)
        
        assert result is True
        mock_post.assert_called_once()
        
        # Verify webhook payload
        call_args = mock_post.call_args
        assert call_args[1]['json']['alert_type'] == alert.alert_type
        assert call_args[1]['json']['severity'] == alert.severity
    
    @patch('monitoring.alerts.requests.post')
    def test_send_webhook_notification_failure(self, mock_post, app, db_session):
        """Test webhook notification sending failure."""
        manager = AlertManager(app=app)
        
        ConfigurationFactory.create(key='webhook_url', value='https://example.com/webhook')
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Mock webhook failure
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response
        
        with app.app_context():
            result = manager.send_webhook_alert(alert)
        
        assert result is False
    
    @patch('monitoring.alerts.push_service')
    def test_send_push_notification(self, mock_push_service, app, db_session):
        """Test sending push notification."""
        manager = AlertManager(app=app)
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device, severity='critical')
        
        # Mock push service
        mock_push_service.send_alert_notification.return_value = True
        
        with app.app_context():
            result = manager.send_push_notification(alert)
        
        assert result is True
        mock_push_service.send_alert_notification.assert_called_once_with(alert)


class TestAlertDeduplication:
    """Test alert deduplication and correlation."""
    
    def test_should_create_alert_new_alert(self, app, db_session):
        """Test should create alert for new alert type."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        with app.app_context():
            should_create = manager.should_create_alert(device, 'device_down', 'critical')
        
        assert should_create is True
    
    def test_should_create_alert_duplicate(self, app, db_session):
        """Test should not create duplicate alert."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create existing alert
        existing_alert = AlertFactory.create(
            device=device,
            alert_type='device_down',
            severity='critical',
            resolved=False,
            created_at=datetime.utcnow() - timedelta(minutes=5)
        )
        
        with app.app_context():
            should_create = manager.should_create_alert(device, 'device_down', 'critical')
        
        assert should_create is False
    
    def test_should_create_alert_resolved_alert(self, app, db_session):
        """Test should create alert when previous is resolved."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create resolved alert
        resolved_alert = AlertFactory.create(
            device=device,
            alert_type='device_down',
            severity='critical',
            resolved=True,
            resolved_at=datetime.utcnow() - timedelta(minutes=5)
        )
        
        with app.app_context():
            should_create = manager.should_create_alert(device, 'device_down', 'critical')
        
        assert should_create is True
    
    def test_should_create_alert_old_alert(self, app, db_session):
        """Test should create alert when previous is old."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create old alert (beyond deduplication window)
        old_alert = AlertFactory.create(
            device=device,
            alert_type='device_down',
            severity='critical',
            resolved=False,
            created_at=datetime.utcnow() - timedelta(hours=25)  # Older than 24 hours
        )
        
        with app.app_context():
            should_create = manager.should_create_alert(device, 'device_down', 'critical')
        
        assert should_create is True


class TestAlertManagerThreading:
    """Test AlertManager background thread management."""
    
    def test_start_alert_monitoring(self, app):
        """Test starting alert monitoring thread."""
        manager = AlertManager(app=app)
        
        # Mock the monitoring method
        manager.run_alert_monitoring = Mock()
        
        manager.start_monitoring()
        
        assert manager.is_running is True
        
        # Clean up
        manager.stop()
    
    def test_stop_alert_monitoring(self, app):
        """Test stopping alert monitoring thread."""
        manager = AlertManager(app=app)
        
        # Mock the monitoring method
        manager.run_alert_monitoring = Mock()
        
        manager.start_monitoring()
        manager.stop()
        
        assert manager.is_running is False
        assert manager._stop_event.is_set()
    
    def test_alert_monitoring_cycle(self, app, db_session):
        """Test alert monitoring cycle execution."""
        manager = AlertManager(app=app)
        
        # Create devices with various states
        down_device = DeviceFactory.create(
            ip_address='192.168.1.1',
            last_seen=datetime.utcnow() - timedelta(minutes=15)
        )
        
        # Create consecutive failures for down device
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=down_device,
                timestamp=datetime.utcnow() - timedelta(minutes=10 - i)
            )
        
        with app.app_context():
            # Run one monitoring cycle
            manager.check_all_devices_for_alerts()
            
            # Should create device down alert
            alerts = Alert.query.filter_by(device_id=down_device.id).all()
            assert len(alerts) > 0
            
            device_down_alerts = [a for a in alerts if a.alert_type == 'device_down']
            assert len(device_down_alerts) > 0


class TestAlertManagerConfiguration:
    """Test AlertManager configuration and customization."""
    
    def test_custom_alert_thresholds(self, app, db_session):
        """Test custom alert threshold configuration."""
        # Create custom configuration
        ConfigurationFactory.create(
            key='alert_device_down_minutes_critical',
            value='5'
        )
        ConfigurationFactory.create(
            key='alert_high_latency_ms',
            value='500'
        )
        
        manager = AlertManager(app=app)
        
        with app.app_context():
            # Should use custom thresholds
            critical_threshold = manager.get_config_value('alert_device_down_minutes_critical', '10')
            latency_threshold = manager.get_config_value('alert_high_latency_ms', '1000')
            
            assert critical_threshold == '5'
            assert latency_threshold == '500'
    
    def test_notification_configuration(self, app, db_session):
        """Test notification configuration."""
        # Create notification configuration
        ConfigurationFactory.create(key='alerts_enabled', value='true')
        ConfigurationFactory.create(key='email_notifications_enabled', value='true')
        ConfigurationFactory.create(key='webhook_notifications_enabled', value='false')
        ConfigurationFactory.create(key='push_notifications_enabled', value='true')
        
        manager = AlertManager(app=app)
        
        with app.app_context():
            assert manager.get_config_value('alerts_enabled', 'false') == 'true'
            assert manager.get_config_value('email_notifications_enabled', 'false') == 'true'
            assert manager.get_config_value('webhook_notifications_enabled', 'false') == 'false'
            assert manager.get_config_value('push_notifications_enabled', 'false') == 'true'


class TestAlertManagerIntegration:
    """Test AlertManager integration with other components."""
    
    def test_integration_with_monitoring_data(self, app, db_session):
        """Test integration with monitoring data for alert generation."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()
        
        # Create monitoring data that should trigger alerts
        high_latency_data = MonitoringDataFactory.create(
            device=device,
            response_time=1500.0,
            packet_loss=0.0
        )
        
        packet_loss_data = MonitoringDataFactory.create(
            device=device,
            response_time=50.0,
            packet_loss=75.0
        )
        
        with app.app_context():
            # Process monitoring data for alerts
            manager.process_monitoring_data_for_alerts(device, high_latency_data)
            manager.process_monitoring_data_for_alerts(device, packet_loss_data)
            
            # Should create appropriate alerts
            alerts = Alert.query.filter_by(device_id=device.id).all()
            alert_types = [a.alert_type for a in alerts]
            
            assert 'high_latency' in alert_types
            assert 'packet_loss' in alert_types
    
    def test_alert_priority_integration(self, app, db_session):
        """Test integration with alert priority calculation."""
        manager = AlertManager(app=app)
        
        # Create critical device alert
        critical_device = DeviceFactory.create(ip_address='192.168.1.1')
        
        with app.app_context():
            alert = manager.create_device_down_alert(critical_device)
            
            if alert:
                # Should have high priority for critical device
                assert alert.severity == 'critical'
                # Priority calculation would be handled by AlertPriorityScorer
                # This tests the integration point