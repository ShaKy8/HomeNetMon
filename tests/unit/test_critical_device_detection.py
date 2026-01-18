"""
Regression tests for Bug 1: Operator precedence in critical device detection.

The bug was in is_critical_device() where Python's operator precedence caused
incorrect evaluation of conditional expressions with 'or' operators.

Fixed by adding parentheses around each conditional expression.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime


class TestCriticalDeviceOperatorPrecedence:
    """Tests for operator precedence fix in is_critical_device methods."""

    def test_router_ip_is_critical_monitor(self, app, db_session):
        """Devices ending in .1 should be critical (monitor.py)."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.1',
            mac_address='00:11:22:33:44:01',
            device_type=None,
            hostname=None,
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is True

    def test_router_ip_is_critical_alerts(self, app, db_session):
        """Devices ending in .1 should be critical (alerts.py)."""
        from monitoring.alerts import AlertManager
        from models import Device

        device = Device(
            ip_address='192.168.1.1',
            mac_address='00:11:22:33:44:01',
            device_type=None,
            hostname=None,
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            alert_manager = AlertManager(app=app)
            assert alert_manager.is_critical_device(device) is True

    def test_router_type_is_critical(self, app, db_session):
        """Devices with type 'router' should be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',  # Not .1
            mac_address='00:11:22:33:44:02',
            device_type='router',
            hostname='some-host',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is True

    def test_server_type_is_critical(self, app, db_session):
        """Devices with type 'server' should be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:03',
            device_type='server',
            hostname='web-server',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is True

    def test_nuc_hostname_is_critical(self, app, db_session):
        """Devices with 'nuc' in hostname should be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:04',
            device_type='computer',
            hostname='home-nuc-server',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is True

    def test_gateway_hostname_is_critical(self, app, db_session):
        """Devices with 'gateway' in hostname should be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:05',
            device_type='appliance',
            hostname='backup-gateway',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is True

    def test_regular_device_not_critical(self, app, db_session):
        """Regular devices should NOT be marked critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:06',
            device_type='computer',
            hostname='laptop-01',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            assert monitor.is_critical_device(device) is False

    def test_none_device_type_not_critical(self, app, db_session):
        """Devices with None device_type should not crash and not be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:07',
            device_type=None,
            hostname='some-host',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            # Should not raise and should return False
            result = monitor.is_critical_device(device)
            assert result is False

    def test_none_hostname_not_critical(self, app, db_session):
        """Devices with None hostname should not crash and not be critical."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:08',
            device_type='computer',
            hostname=None,
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            # Should not raise and should return False
            result = monitor.is_critical_device(device)
            assert result is False

    def test_operator_precedence_regression(self, app, db_session):
        """
        REGRESSION TEST: Verify operator precedence is correct.

        Before the fix, the expression:
            'router' in type if type else False or 'server' in type if type else False

        Would incorrectly evaluate due to 'False or' binding to the next condition.
        A device with type='computer' could incorrectly be marked as critical.
        """
        from monitoring.monitor import DeviceMonitor
        from models import Device

        # Device with type='computer' should NOT be critical
        device = Device(
            ip_address='192.168.1.50',
            mac_address='00:11:22:33:44:09',
            device_type='computer',
            hostname='desktop',
            is_monitored=True
        )
        db_session.add(device)
        db_session.commit()

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            result = monitor.is_critical_device(device)

            # This is the key assertion - with the bug, this might return True incorrectly
            assert result is False, \
                "Operator precedence bug: computer device incorrectly marked as critical"

    def test_both_implementations_consistent(self, app, db_session):
        """Monitor and AlertManager should have consistent is_critical_device logic."""
        from monitoring.monitor import DeviceMonitor
        from monitoring.alerts import AlertManager
        from models import Device

        # Test multiple device configurations
        test_cases = [
            {'ip': '192.168.1.1', 'type': None, 'hostname': None, 'expected': True},
            {'ip': '192.168.1.64', 'type': None, 'hostname': None, 'expected': True},
            {'ip': '192.168.1.100', 'type': 'router', 'hostname': 'test', 'expected': True},
            {'ip': '192.168.1.100', 'type': 'server', 'hostname': 'test', 'expected': True},
            {'ip': '192.168.1.100', 'type': 'computer', 'hostname': 'my-nuc', 'expected': True},
            {'ip': '192.168.1.100', 'type': 'computer', 'hostname': 'main-gateway', 'expected': True},
            {'ip': '192.168.1.100', 'type': 'computer', 'hostname': 'laptop', 'expected': False},
        ]

        with app.app_context():
            monitor = DeviceMonitor(app=app)
            alert_manager = AlertManager(app=app)

            for i, tc in enumerate(test_cases):
                device = Device(
                    ip_address=tc['ip'],
                    mac_address=f'00:11:22:33:44:{10+i:02x}',
                    device_type=tc['type'],
                    hostname=tc['hostname'],
                    is_monitored=True
                )
                db_session.add(device)
                db_session.commit()

                monitor_result = monitor.is_critical_device(device)
                alert_result = alert_manager.is_critical_device(device)

                assert monitor_result == tc['expected'], \
                    f"Monitor: {tc} returned {monitor_result}, expected {tc['expected']}"
                assert alert_result == tc['expected'], \
                    f"AlertManager: {tc} returned {alert_result}, expected {tc['expected']}"

                db_session.delete(device)
                db_session.commit()
