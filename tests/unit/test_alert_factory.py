"""
AlertManager.create_alert is the single alert pipeline (dedup -> suppression ->
correlation -> commit -> notify -> emit). The performance monitor and the
security scanner used to write Alert rows directly and bypass all of it.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from models import Alert, AlertSuppression, Device, db
from monitoring.alerts import AlertManager


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.70', mac_address='00:ff:00:00:00:01', hostname='af',
               device_type='computer', is_monitored=True, last_seen=datetime.utcnow())
    db_session.add(d)
    db_session.commit()
    return d


@pytest.fixture
def manager(app):
    m = AlertManager(app=app)
    m.send_alert_notifications = Mock()
    m._emit_alert_update = Mock()
    return m


class TestCreateAlert:

    def test_creates_notifies_and_emits(self, app, db_session, device, manager):
        with app.app_context():
            a = manager.create_alert(device.id, 'device_down', 'warning', 'gone', subtype=None)
            assert a is not None and a.id
            manager.send_alert_notifications.assert_called_once()
            manager._emit_alert_update.assert_called_once_with(a, 'created')

    def test_duplicate_unresolved_alert_is_not_created(self, app, db_session, device, manager):
        with app.app_context():
            assert manager.create_alert(device.id, 'security_new_service', 'medium', 'ssh', subtype='port_22')
            assert manager.create_alert(device.id, 'security_new_service', 'medium', 'ssh again', subtype='port_22') is None
            assert manager.create_alert(device.id, 'security_new_service', 'medium', 'http', subtype='port_80')
            assert Alert.query.filter_by(device_id=device.id).count() == 2

    def test_resolved_alert_allows_a_new_one(self, app, db_session, device, manager):
        with app.app_context():
            first = manager.create_alert(device.id, 'device_down', 'warning', 'x')
            first.resolve()
            assert manager.create_alert(device.id, 'device_down', 'warning', 'x again') is not None

    def test_suppression_rule_blocks_creation(self, app, db_session, device, manager):
        db_session.add(AlertSuppression(name='mute perf', enabled=True, device_id=device.id, alert_type='performance'))
        db_session.commit()
        with app.app_context():
            assert manager.create_alert(device.id, 'performance', 'warning', 'slow', subtype='performance_warning') is None
            assert manager.create_alert(device.id, 'device_down', 'warning', 'down') is not None
        manager.send_alert_notifications.assert_called_once()

    def test_notify_false_skips_dispatch_but_still_emits(self, app, db_session, device, manager):
        with app.app_context():
            a = manager.create_alert(device.id, 'security_suspicious_port', 'high', 'telnet', subtype='port_23', notify=False)
        assert a is not None
        manager.send_alert_notifications.assert_not_called()
        manager._emit_alert_update.assert_called_once()


class TestProducersUseTheFactory:

    def test_performance_monitor_routes_through_manager(self, app, db_session, device):
        from services.performance_monitor import PerformanceMonitor
        fake_manager = Mock()
        fake_manager.create_alert.return_value = SimpleNamespace(id=1, created_at=datetime.utcnow())
        fake_app = SimpleNamespace(alert_manager=fake_manager, app_context=app.app_context)
        pm = PerformanceMonitor(app=fake_app, socketio=None)
        with app.app_context():
            pm._create_performance_alert(device, 'performance_warning', 'meh', {})
        fake_manager.create_alert.assert_called_once()
        kwargs = fake_manager.create_alert.call_args
        assert kwargs[0][1] == 'performance' and kwargs[1]['subtype'] == 'performance_warning'

    def test_security_scanner_keys_alerts_by_port(self, app, db_session, device):
        from services import security_scanner as ss
        from services.security_scanner import SecurityAlert
        fake_manager = Mock()
        fake_manager.create_alert.return_value = SimpleNamespace(id=7)
        ScannerClass = type(ss.security_scanner)
        scanner = ScannerClass.__new__(ScannerClass)
        scanner.app = SimpleNamespace(alert_manager=fake_manager)
        sa = SecurityAlert(device_id=device.id, device_name='af', alert_type='new_service', severity='medium',
                           message='New service detected: ssh on port 22', detected_at=datetime.utcnow(),
                           port=22, service='ssh', risk_score=3.0)
        with app.app_context():
            assert scanner.create_security_alert(sa) is not None
        args, kwargs = fake_manager.create_alert.call_args
        assert args[1] == 'security_new_service' and kwargs['subtype'] == 'port_22' and kwargs['notify'] is False


class TestSecurityLifecycle:

    def _scanner(self, app):
        from services import security_scanner as ss
        ScannerClass = type(ss.security_scanner)
        s = ScannerClass.__new__(ScannerClass)
        s.app = app
        s.scan_interval = 86400
        return s

    @staticmethod
    def _open(device, port, service):
        from services.security_scanner import PortScanResult
        return PortScanResult(device_id=device.id, ip_address=device.ip_address, port=port, state='open',
                              service=service, version='', product='', extra_info='', confidence=10,
                              scanned_at=datetime.utcnow())

    def test_alerts_for_closed_ports_are_resolved(self, app, db_session, device):
        db_session.add_all([
            Alert(device_id=device.id, alert_type='security_new_service', alert_subtype='port_22', message='ssh'),
            Alert(device_id=device.id, alert_type='security_suspicious_port', alert_subtype='port_23', message='telnet'),
            Alert(device_id=device.id, alert_type='security_new_service', alert_subtype=None, message='legacy'),
            Alert(device_id=device.id, alert_type='device_down', message='unrelated'),
        ])
        db_session.commit()
        results = [self._open(device, 22, 'ssh')]
        with app.app_context():
            assert self._scanner(app).resolve_closed_port_alerts(device, results) == 1
            unresolved = {(a.alert_type, a.alert_subtype) for a in Alert.query.filter_by(resolved=False).all()}
        assert ('security_suspicious_port', 'port_23') not in unresolved
        assert ('security_new_service', 'port_22') in unresolved
        assert ('security_new_service', None) in unresolved and ('device_down', None) in unresolved

    def test_previous_scan_lookback_covers_daily_cadence(self, app, db_session, device):
        from models import SecurityScan
        db_session.add(SecurityScan(device_id=device.id, ip_address=device.ip_address, port=443, state='open',
                                    service='https', scanned_at=datetime.utcnow() - timedelta(hours=30)))
        db_session.commit()
        with app.app_context():
            prev = self._scanner(app).get_previous_scan_results(device.id)
        assert [p['port'] for p in prev] == [443]   # a 24 h window would have missed this
        db_session.query(SecurityScan).delete()
        db_session.commit()
