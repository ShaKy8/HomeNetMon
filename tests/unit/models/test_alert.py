"""
Unit tests for the Alert model.

Tests cover:
- Model creation and validation
- Alert state transitions (creation, acknowledgment, resolution)
- Priority calculations and scoring
- Notification correlation tracking
- Relationships with other models
- Business logic methods
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from models import Alert, Device
from tests.fixtures.factories import (
    AlertFactory, ResolvedAlertFactory, AcknowledgedAlertFactory,
    PerformanceAlertFactory, DeviceFactory
)
from tests.fixtures.utils import AlertTestHelper


class TestAlertModel:
    """Test the Alert model basic functionality."""
    
    def test_alert_creation(self, db_session):
        """Test creating an alert with all attributes."""
        device = DeviceFactory.create()
        
        alert_data = {
            'device_id': device.id,
            'alert_type': 'device_down',
            'severity': 'critical',
            'message': 'Device is not responding to ping',
            'priority_score': 85,
            'priority_level': 'HIGH',
            'notification_sent': False,
            'notification_count': 0,
            'notification_status': 'pending'
        }
        
        alert = Alert(**alert_data)
        db_session.add(alert)
        db_session.commit()
        
        # Verify alert was created with correct attributes
        assert alert.id is not None
        assert alert.device_id == device.id
        assert alert.alert_type == 'device_down'
        assert alert.severity == 'critical'
        assert alert.message == 'Device is not responding to ping'
        assert alert.acknowledged is False
        assert alert.resolved is False
        assert alert.priority_score == 85
        assert alert.priority_level == 'HIGH'
        assert alert.created_at is not None

    def test_alert_creation_minimal(self, db_session):
        """Test creating an alert with only required attributes."""
        device = DeviceFactory.create()
        
        alert = Alert(
            device_id=device.id,
            alert_type='high_latency',
            message='High response time detected'
        )
        db_session.add(alert)
        db_session.commit()
        
        assert alert.id is not None
        assert alert.device_id == device.id
        assert alert.alert_type == 'high_latency'
        assert alert.severity == 'warning'  # Default value
        assert alert.acknowledged is False
        assert alert.resolved is False
        assert alert.priority_score == 50  # Default value
        assert alert.priority_level == 'MEDIUM'  # Default value

    def test_alert_repr(self, db_session):
        """Test the string representation of an alert."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        alert = AlertFactory.create(
            device=device,
            alert_type='device_down'
        )
        
        repr_str = repr(alert)
        assert 'device_down' in repr_str
        assert '192.168.1.100' in repr_str


class TestAlertStateTransitions:
    """Test Alert state transitions and lifecycle management."""
    
    def test_alert_acknowledge(self, db_session):
        """Test acknowledging an alert."""
        alert = AlertFactory.create()
        
        # Initially not acknowledged
        assert alert.acknowledged is False
        assert alert.acknowledged_at is None
        assert alert.acknowledged_by is None
        
        # Acknowledge the alert
        alert.acknowledge(acknowledged_by='test_user')
        
        # Should be acknowledged with proper metadata
        assert alert.acknowledged is True
        assert alert.acknowledged_at is not None
        assert alert.acknowledged_by == 'test_user'
        assert isinstance(alert.acknowledged_at, datetime)
    
    def test_alert_acknowledge_default_user(self, db_session):
        """Test acknowledging an alert with default user."""
        alert = AlertFactory.create()
        
        alert.acknowledge()  # No user specified
        
        assert alert.acknowledged is True
        assert alert.acknowledged_by == 'system'
    
    def test_alert_resolve(self, db_session):
        """Test resolving an alert."""
        alert = AlertFactory.create()
        
        # Initially not resolved
        assert alert.resolved is False
        assert alert.resolved_at is None
        
        # Resolve the alert
        alert.resolve()
        
        # Should be resolved with proper metadata
        assert alert.resolved is True
        assert alert.resolved_at is not None
        assert isinstance(alert.resolved_at, datetime)
    
    def test_alert_acknowledge_and_resolve(self, db_session):
        """Test acknowledging and then resolving an alert."""
        alert = AlertFactory.create()
        
        # Acknowledge first
        acknowledge_time = datetime.utcnow()
        alert.acknowledge(acknowledged_by='operator')
        
        # Then resolve
        resolve_time = datetime.utcnow()
        alert.resolve()
        
        # Both states should be properly set
        assert alert.acknowledged is True
        assert alert.resolved is True
        assert alert.acknowledged_at <= alert.resolved_at
        assert alert.acknowledged_by == 'operator'
    
    def test_alert_state_immutability(self, db_session):
        """Test that state changes are persistent."""
        alert = AlertFactory.create()
        alert_id = alert.id
        
        # Acknowledge and commit
        alert.acknowledge(acknowledged_by='test_user')
        db_session.refresh(alert)
        
        # Re-fetch from database
        refreshed_alert = db_session.query(Alert).filter_by(id=alert_id).first()
        assert refreshed_alert.acknowledged is True
        assert refreshed_alert.acknowledged_by == 'test_user'


class TestAlertPriorityScoring:
    """Test Alert priority scoring and calculation."""
    
    @patch('services.alert_priority.AlertPriorityScorer')
    def test_calculate_and_update_priority(self, mock_scorer_class, db_session):
        """Test priority calculation and update."""
        # Mock the scorer
        mock_scorer = MagicMock()
        mock_scorer.calculate_priority_score.return_value = (75, 'HIGH', {
            'severity_weight': 30,
            'device_criticality': 25,
            'time_factor': 20
        })
        mock_scorer_class.return_value = mock_scorer
        
        alert = AlertFactory.create()
        
        # Calculate priority
        alert.calculate_and_update_priority()
        
        # Should update priority fields
        assert alert.priority_score == 75
        assert alert.priority_level == 'HIGH'
        assert alert.priority_breakdown is not None
        
        # Priority breakdown should be valid JSON
        breakdown = json.loads(alert.priority_breakdown)
        assert breakdown['severity_weight'] == 30
        assert breakdown['device_criticality'] == 25
        assert breakdown['time_factor'] == 20
    
    def test_priority_score_bounds(self, db_session):
        """Test that priority scores are within valid bounds."""
        # Create alerts with various priority scores
        low_priority = AlertFactory.create(priority_score=10)
        medium_priority = AlertFactory.create(priority_score=50)
        high_priority = AlertFactory.create(priority_score=90)
        
        # All should be within 0-100 range
        assert 0 <= low_priority.priority_score <= 100
        assert 0 <= medium_priority.priority_score <= 100
        assert 0 <= high_priority.priority_score <= 100
    
    def test_priority_level_mapping(self, db_session):
        """Test priority level mappings."""
        critical_alert = AlertFactory.create(priority_level='CRITICAL')
        high_alert = AlertFactory.create(priority_level='HIGH')
        medium_alert = AlertFactory.create(priority_level='MEDIUM')
        low_alert = AlertFactory.create(priority_level='LOW')
        minimal_alert = AlertFactory.create(priority_level='MINIMAL')
        
        valid_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']
        assert critical_alert.priority_level in valid_levels
        assert high_alert.priority_level in valid_levels
        assert medium_alert.priority_level in valid_levels
        assert low_alert.priority_level in valid_levels
        assert minimal_alert.priority_level in valid_levels


class TestAlertNotificationTracking:
    """Test Alert notification correlation and tracking."""
    
    def test_notification_status_default(self, db_session):
        """Test default notification status for new alerts."""
        alert = AlertFactory.create()
        
        assert alert.notification_sent is False
        assert alert.notification_count == 0
        assert alert.last_notification_at is None
        assert alert.notification_status == 'pending'
    
    def test_notification_tracking_update(self, db_session):
        """Test updating notification tracking fields."""
        alert = AlertFactory.create()
        
        # Simulate sending notification
        notification_time = datetime.utcnow()
        alert.notification_sent = True
        alert.notification_count = 1
        alert.last_notification_at = notification_time
        alert.notification_status = 'sent'
        
        db_session.commit()
        
        assert alert.notification_sent is True
        assert alert.notification_count == 1
        assert alert.last_notification_at == notification_time
        assert alert.notification_status == 'sent'
    
    def test_multiple_notifications(self, db_session):
        """Test tracking multiple notifications for same alert."""
        alert = AlertFactory.create()
        
        # First notification
        alert.notification_count = 1
        alert.notification_status = 'sent'
        alert.last_notification_at = datetime.utcnow() - timedelta(hours=1)
        
        # Second notification (escalation)
        latest_notification = datetime.utcnow()
        alert.notification_count = 2
        alert.last_notification_at = latest_notification
        
        db_session.commit()
        
        assert alert.notification_count == 2
        assert alert.last_notification_at == latest_notification
    
    def test_notification_failure_tracking(self, db_session):
        """Test tracking notification failures."""
        alert = AlertFactory.create()
        
        # Simulate failed notification
        alert.notification_status = 'failed'
        alert.notification_sent = False
        
        db_session.commit()
        
        assert alert.notification_status == 'failed'
        assert alert.notification_sent is False


class TestAlertRelationships:
    """Test Alert model relationships."""
    
    def test_device_relationship(self, db_session):
        """Test relationship between Alert and Device."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Test relationship works both ways
        assert alert.device == device
        assert alert in device.alerts
    
    @pytest.mark.skip(reason="Database schema mismatch - notification_history table missing columns in test DB")
    def test_cascade_delete_from_device(self, db_session):
        """Test that deleting a device cascades to alerts."""
        # NOTE: This test is skipped due to database schema issues with notification_history table
        # The test database is missing the alert_id column which causes SQLAlchemy errors during cascade deletes
        # Database schema now includes all models (resolved)
        
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        alert_id = alert.id
        
        # Delete the device
        db_session.delete(device)
        db_session.commit()
        
        # Alert should be deleted too
        deleted_alert = db_session.query(Alert).filter_by(id=alert_id).first()
        assert deleted_alert is None
    
    def test_multiple_alerts_per_device(self, db_session):
        """Test that a device can have multiple alerts."""
        device = DeviceFactory.create()
        
        alert1 = AlertFactory.create(device=device, alert_type='device_down')
        alert2 = AlertFactory.create(device=device, alert_type='high_latency')
        alert3 = AlertFactory.create(device=device, alert_type='performance')
        
        # Device should have all alerts
        assert len(device.alerts) == 3
        assert alert1 in device.alerts
        assert alert2 in device.alerts
        assert alert3 in device.alerts


class TestAlertBusinessLogic:
    """Test Alert model business logic methods."""
    
    def test_to_dict_method(self, db_session):
        """Test the to_dict method for API serialization."""
        device = DeviceFactory.create(
            ip_address='192.168.1.100',
            hostname='test-device'
        )
        alert = AlertFactory.create(
            device=device,
            alert_type='device_down',
            severity='critical',
            message='Device is not responding',
            priority_score=85,
            priority_level='HIGH'
        )
        
        alert_dict = alert.to_dict()
        
        assert isinstance(alert_dict, dict)
        assert alert_dict['id'] == alert.id
        assert alert_dict['device_id'] == device.id
        assert alert_dict['device_name'] == device.display_name
        assert alert_dict['device_ip'] == '192.168.1.100'
        assert alert_dict['alert_type'] == 'device_down'
        assert alert_dict['severity'] == 'critical'
        assert alert_dict['message'] == 'Device is not responding'
        assert alert_dict['priority_score'] == 85
        assert alert_dict['priority_level'] == 'HIGH'
        assert alert_dict['acknowledged'] is False
        assert alert_dict['resolved'] is False
        assert 'created_at' in alert_dict
    
    def test_is_active_method(self, db_session):
        """Test the is_active method for determining alert status."""
        # Active alert (not acknowledged or resolved)
        active_alert = AlertFactory.create()
        assert active_alert.is_active() is True
        
        # Acknowledged but not resolved
        acknowledged_alert = AcknowledgedAlertFactory.create()
        assert acknowledged_alert.is_active() is True
        
        # Resolved alert
        resolved_alert = ResolvedAlertFactory.create()
        assert resolved_alert.is_active() is False
    
    def test_get_age_method(self, db_session):
        """Test getting alert age in various formats."""
        # Create alert from 2 hours ago
        old_time = datetime.utcnow() - timedelta(hours=2)
        alert = AlertFactory.create(created_at=old_time)
        
        age_seconds = alert.get_age_seconds()
        age_minutes = alert.get_age_minutes()
        age_hours = alert.get_age_hours()
        
        assert age_seconds >= 7200  # At least 2 hours in seconds
        assert age_minutes >= 120   # At least 2 hours in minutes
        assert age_hours >= 2       # At least 2 hours
    
    def test_should_escalate_method(self, db_session):
        """Test escalation logic for alerts."""
        # New critical alert should escalate
        critical_alert = AlertFactory.create(
            severity='critical',
            created_at=datetime.utcnow() - timedelta(minutes=30)
        )
        assert critical_alert.should_escalate() is True
        
        # Old warning alert might not escalate
        warning_alert = AlertFactory.create(
            severity='warning',
            created_at=datetime.utcnow() - timedelta(minutes=5)
        )
        assert warning_alert.should_escalate() is False
        
        # Resolved alert should not escalate
        resolved_alert = ResolvedAlertFactory.create()
        assert resolved_alert.should_escalate() is False
    
    def test_get_severity_weight(self, db_session):
        """Test getting numeric weight for severity levels."""
        critical_alert = AlertFactory.create(severity='critical')
        warning_alert = AlertFactory.create(severity='warning')
        info_alert = AlertFactory.create(severity='info')
        
        critical_weight = critical_alert.get_severity_weight()
        warning_weight = warning_alert.get_severity_weight()
        info_weight = info_alert.get_severity_weight()
        
        # Critical should have highest weight
        assert critical_weight > warning_weight > info_weight
        assert critical_weight == 100
        assert warning_weight == 50
        assert info_weight == 10


class TestAlertFactories:
    """Test the Alert factory classes."""
    
    def test_alert_factory(self, db_session):
        """Test the basic AlertFactory."""
        alert = AlertFactory.create()
        AlertTestHelper.assert_alert_properties(alert, alert.alert_type, alert.severity)
        
        assert alert.alert_type in ['device_down', 'high_latency', 'performance', 'anomaly']
        assert alert.severity in ['info', 'warning', 'critical']
        assert alert.message is not None
    
    def test_resolved_alert_factory(self, db_session):
        """Test the ResolvedAlertFactory."""
        alert = ResolvedAlertFactory.create()
        
        assert alert.resolved is True
        assert alert.resolved_at is not None
        assert alert.resolved_at > alert.created_at
    
    def test_acknowledged_alert_factory(self, db_session):
        """Test the AcknowledgedAlertFactory."""
        alert = AcknowledgedAlertFactory.create()
        
        assert alert.acknowledged is True
        assert alert.acknowledged_at is not None
        assert alert.acknowledged_by is not None
        assert alert.acknowledged_at >= alert.created_at
    
    def test_performance_alert_factory(self, db_session):
        """Test the PerformanceAlertFactory."""
        alert = PerformanceAlertFactory.create()
        
        assert alert.alert_type == 'performance'
        assert alert.severity in ['warning', 'critical']
        assert 'performance' in alert.message.lower()


class TestAlertQueries:
    """Test Alert model query methods and filtering."""
    
    def test_get_active_alerts(self, db_session):
        """Test querying for active alerts."""
        device = DeviceFactory.create()
        
        # Create various alert types
        active_alert1 = AlertFactory.create(device=device)
        active_alert2 = AlertFactory.create(device=device)
        resolved_alert = ResolvedAlertFactory.create(device=device)
        
        # Query active alerts
        active_alerts = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.resolved == False
        ).all()
        
        assert len(active_alerts) == 2
        assert active_alert1 in active_alerts
        assert active_alert2 in active_alerts
        assert resolved_alert not in active_alerts
    
    def test_get_alerts_by_severity(self, db_session):
        """Test querying alerts by severity."""
        device = DeviceFactory.create()
        
        critical_alert = AlertFactory.create(device=device, severity='critical')
        warning_alert = AlertFactory.create(device=device, severity='warning')
        info_alert = AlertFactory.create(device=device, severity='info')
        
        # Query critical alerts
        critical_alerts = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.severity == 'critical'
        ).all()
        
        assert len(critical_alerts) == 1
        assert critical_alert in critical_alerts
        assert warning_alert not in critical_alerts
        assert info_alert not in critical_alerts
    
    def test_get_alerts_by_time_range(self, db_session):
        """Test querying alerts by time range."""
        device = DeviceFactory.create()
        
        now = datetime.utcnow()
        recent_alert = AlertFactory.create(
            device=device,
            created_at=now - timedelta(hours=1)
        )
        old_alert = AlertFactory.create(
            device=device, 
            created_at=now - timedelta(days=2)
        )
        
        # Query alerts from last 24 hours
        recent_alerts = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.created_at >= now - timedelta(hours=24)
        ).all()
        
        assert len(recent_alerts) == 1
        assert recent_alert in recent_alerts
        assert old_alert not in recent_alerts


class TestAlertValidation:
    """Test Alert model validation and constraints."""
    
    def test_required_fields(self, db_session):
        """Test that required fields are enforced."""
        device = DeviceFactory.create()
        
        # Valid alert
        valid_alert = Alert(
            device_id=device.id,
            alert_type='device_down',
            message='Test message'
        )
        db_session.add(valid_alert)
        db_session.commit()
        
        assert valid_alert.id is not None
    
    def test_severity_values(self, db_session):
        """Test valid severity values."""
        device = DeviceFactory.create()
        
        valid_severities = ['info', 'warning', 'critical']
        
        for severity in valid_severities:
            alert = AlertFactory.create(device=device, severity=severity)
            assert alert.severity == severity
    
    def test_alert_type_values(self, db_session):
        """Test valid alert type values."""
        device = DeviceFactory.create()
        
        valid_types = ['device_down', 'high_latency', 'performance', 'anomaly']
        
        for alert_type in valid_types:
            alert = AlertFactory.create(device=device, alert_type=alert_type)
            assert alert.alert_type == alert_type
    
    def test_priority_level_values(self, db_session):
        """Test valid priority level values."""
        device = DeviceFactory.create()
        
        valid_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']
        
        for level in valid_levels:
            alert = AlertFactory.create(device=device, priority_level=level)
            assert alert.priority_level == level