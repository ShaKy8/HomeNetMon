"""
Regression tests for Bug 2: device.last_seen outside transaction.

The bug was in ping_device() where device.last_seen was modified on a detached
SQLAlchemy instance outside the Flask app context. These changes were not persisted.

Fixed by removing the redundant last_seen updates in ping_device() - the proper
update already exists in monitor_device() inside the transaction.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta
import subprocess


class TestLastSeenPersistence:
    """Tests for last_seen update persistence in database."""

    def test_last_seen_updated_after_successful_ping(self, app, db_session):
        """last_seen should be updated in DB after successful ping via monitor_device."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, db

        # Create device with old last_seen
        old_time = datetime.utcnow() - timedelta(hours=1)
        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:55',
            hostname='test-device',
            device_type='computer',
            is_monitored=True,
            last_seen=old_time
        )
        db_session.add(device)
        db_session.commit()
        device_id = device.id

        # Mock successful ping response
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'time=25.0 ms'

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            with patch('subprocess.run', return_value=mock_result):
                with patch('monitoring.monitor.iot_optimizer') as mock_optimizer:
                    mock_optimizer.should_skip_monitoring.return_value = (False, 0)
                    mock_optimizer.get_optimized_settings.return_value = {'max_retries': 1, 'ping_timeout': 1.0}
                    mock_optimizer.record_ping_result = Mock()

                    # Run monitor_device which should update last_seen in transaction
                    monitor.monitor_device(device)

            # Re-query device from DB to verify persistence
            db.session.expire_all()
            updated_device = Device.query.get(device_id)

            # last_seen should be updated (within last minute)
            assert updated_device.last_seen is not None
            assert updated_device.last_seen > old_time
            time_diff = (datetime.utcnow() - updated_device.last_seen).total_seconds()
            assert time_diff < 60, f"last_seen not updated recently: {time_diff}s ago"

    def test_last_seen_not_updated_after_failed_ping(self, app, db_session):
        """last_seen should NOT be updated after failed ping."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, db

        # Create device with specific last_seen
        old_time = datetime.utcnow() - timedelta(hours=1)
        device = Device(
            ip_address='192.168.1.101',
            mac_address='00:11:22:33:44:56',
            hostname='offline-device',
            device_type='computer',
            is_monitored=True,
            last_seen=old_time
        )
        db_session.add(device)
        db_session.commit()
        device_id = device.id

        # Mock failed ping response
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ''

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            with patch('subprocess.run', return_value=mock_result):
                with patch('monitoring.monitor.iot_optimizer') as mock_optimizer:
                    mock_optimizer.should_skip_monitoring.return_value = (False, 0)
                    mock_optimizer.get_optimized_settings.return_value = {'max_retries': 1, 'ping_timeout': 1.0}
                    mock_optimizer.record_ping_result = Mock()

                    # Run monitor_device - ping fails
                    monitor.monitor_device(device)

            # Re-query device from DB
            db.session.expire_all()
            updated_device = Device.query.get(device_id)

            # last_seen should NOT be updated - should still be old_time
            assert updated_device.last_seen is not None
            time_diff = abs((updated_device.last_seen - old_time).total_seconds())
            assert time_diff < 1, f"last_seen was incorrectly updated after failed ping"

    def test_ping_device_does_not_modify_last_seen(self, app, db_session):
        """ping_device should NOT modify device.last_seen directly (fix for bug)."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        # Create device
        device = Device(
            ip_address='192.168.1.102',
            mac_address='00:11:22:33:44:57',
            hostname='test-device',
            device_type='computer',
            is_monitored=True,
            last_seen=None
        )
        db_session.add(device)
        db_session.commit()

        # Store original last_seen (None)
        original_last_seen = device.last_seen

        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'time=25.0 ms'

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            with patch('subprocess.run', return_value=mock_result):
                with patch('monitoring.monitor.iot_optimizer') as mock_optimizer:
                    mock_optimizer.should_skip_monitoring.return_value = (False, 0)
                    mock_optimizer.get_optimized_settings.return_value = {'max_retries': 1, 'ping_timeout': 1.0}
                    mock_optimizer.record_ping_result = Mock()

                    # Call ping_device directly (not monitor_device)
                    result = monitor.ping_device(device)

            # ping_device should return the response time
            assert result == 25.0

            # But device.last_seen should NOT have been modified by ping_device
            # (it should be modified by monitor_device in the transaction)
            # Note: The object might be detached, so we check the attribute directly
            assert device.last_seen == original_last_seen, \
                "ping_device should not modify device.last_seen directly"

    def test_last_seen_persists_across_sessions(self, app, db_session):
        """last_seen should persist after session is closed."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, db

        # Create device
        device = Device(
            ip_address='192.168.1.103',
            mac_address='00:11:22:33:44:58',
            hostname='persistence-test',
            device_type='computer',
            is_monitored=True,
            last_seen=None
        )
        db_session.add(device)
        db_session.commit()
        device_id = device.id

        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'time=30.0 ms'

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            with patch('subprocess.run', return_value=mock_result):
                with patch('monitoring.monitor.iot_optimizer') as mock_optimizer:
                    mock_optimizer.should_skip_monitoring.return_value = (False, 0)
                    mock_optimizer.get_optimized_settings.return_value = {'max_retries': 1, 'ping_timeout': 1.0}
                    mock_optimizer.record_ping_result = Mock()

                    monitor.monitor_device(device)

            db.session.commit()

        # New session - verify persistence
        with app.app_context():
            reloaded_device = Device.query.get(device_id)
            assert reloaded_device.last_seen is not None, \
                "last_seen should persist across sessions"
