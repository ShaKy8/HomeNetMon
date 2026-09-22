"""AlertManager decision helpers (consecutive-failure detection). Policy tests are added in 2.9.0."""

from datetime import datetime, timedelta

from monitoring.alerts import AlertManager
from tests.fixtures.factories import (
    DeviceFactory,
    SuccessfulMonitoringDataFactory,
    TimeoutMonitoringDataFactory,
)


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


# ---------------------------------------------------------------------------
# 2.9.0 alert policy: per-device "alert when down", one creation path,
# notification policy, startup grace, notification status.
# ---------------------------------------------------------------------------

from unittest.mock import patch  # noqa: E402

from constants import ALERT_ON_DOWN_BY_TYPE, ALERT_STARTUP_GRACE_SECONDS  # noqa: E402
from models import Alert, Configuration, Device, db  # noqa: E402
from monitoring.notification_policy import NotificationPolicy  # noqa: E402


def _device(**kw):
    defaults = dict(ip_address='192.168.1.77', mac_address='00:ab:00:00:00:77', hostname='thing', device_type='computer',
                    is_monitored=True, last_seen=datetime.utcnow() - timedelta(hours=2))
    defaults.update(kw)
    d = Device(**defaults)
    db.session.add(d)
    db.session.commit()
    return d


class TestAlertsOnDownInheritance:

    def test_type_defaults(self, app, db_session):
        with app.app_context():
            assert ALERT_ON_DOWN_BY_TYPE == {'phone': False, 'apple': False, 'unknown': False}
            assert _device(device_type='phone', ip_address='192.168.1.10', mac_address='00:ab:00:00:00:10').alerts_on_down is False
            assert _device(device_type='apple', ip_address='192.168.1.11', mac_address='00:ab:00:00:00:11').alerts_on_down is False
            assert _device(device_type=None, ip_address='192.168.1.12', mac_address='00:ab:00:00:00:12').alerts_on_down is False
            assert _device(device_type='camera', ip_address='192.168.1.13', mac_address='00:ab:00:00:00:13').alerts_on_down is True
            assert _device(device_type='computer', ip_address='192.168.1.14', mac_address='00:ab:00:00:00:14').alerts_on_down is True

    def test_explicit_value_wins(self, app, db_session):
        with app.app_context():
            assert _device(device_type='phone', alert_on_down=True).alerts_on_down is True
            assert _device(device_type='camera', alert_on_down=False, ip_address='192.168.1.15',
                           mac_address='00:ab:00:00:00:15').alerts_on_down is False

    def test_critical_devices_always_alert_by_default(self, app, db_session):
        with app.app_context():
            router = _device(device_type='unknown', ip_address='192.168.1.1', mac_address='00:ab:00:00:00:01')
            assert router.is_critical and router.alerts_on_down is True
            server = _device(device_type='phone', hostname='nuc-box', ip_address='192.168.1.16', mac_address='00:ab:00:00:00:16')
            assert server.is_critical and server.alerts_on_down is True

    def test_to_dict_exposes_both_values(self, app, db_session):
        with app.app_context():
            d = _device(device_type='phone')
            for payload in (d.to_dict(), d.to_dict_fast()):
                assert payload['alert_on_down'] is None and payload['alerts_on_down'] is False

    def test_api_accepts_alert_on_down(self, client, app, db_session):
        with app.app_context():
            d = _device(device_type='phone')
            token = client.get('/api/csrf-token').get_json()['csrf_token']
            r = client.put(f'/api/devices/{d.id}', json={'alert_on_down': True}, headers={'X-CSRF-Token': token})
            assert r.status_code == 200, r.get_json()
            assert client.get(f'/api/devices/{d.id}').get_json()['device']['alerts_on_down'] is True
            r = client.put(f'/api/devices/{d.id}', json={'alert_on_down': None}, headers={'X-CSRF-Token': token})
            assert r.status_code == 200, r.get_json()
            assert client.get(f'/api/devices/{d.id}').get_json()['device']['alert_on_down'] is None
            r = client.post('/api/devices/bulk-update', json={'device_ids': [d.id], 'alert_on_down': False},
                            headers={'X-CSRF-Token': token})
            assert r.status_code == 200, r.get_json()
            db.session.expire_all()
            assert db.session.get(Device, d.id).alert_on_down is False


class TestSinglePath:

    def _manager(self, app):
        m = AlertManager(app=app)
        m.send_alert_notifications = lambda alert: None
        return m

    def test_phone_that_is_down_is_skipped(self, app, db_session):
        with app.app_context():
            m = self._manager(app)
            phone = _device(device_type='phone', last_seen=datetime.utcnow() - timedelta(hours=3))
            for i in range(4):
                TimeoutMonitoringDataFactory.create(device=phone, timestamp=datetime.utcnow() - timedelta(minutes=5 * i))
            with patch.object(Device, 'uptime_percentage', return_value=0.0):
                m.check_device_down_alerts()
                assert Alert.query.filter_by(device_id=phone.id, alert_type='device_down').count() == 0
                phone.alert_on_down = True
                db.session.commit()
                m.check_device_down_alerts()
            assert Alert.query.filter_by(device_id=phone.id, alert_type='device_down').count() == 1

    def test_down_alert_goes_through_create_alert(self, app, db_session):
        with app.app_context():
            m = self._manager(app)
            d = _device(device_type='camera', last_seen=datetime.utcnow() - timedelta(hours=3))
            for i in range(4):
                TimeoutMonitoringDataFactory.create(device=d, timestamp=datetime.utcnow() - timedelta(minutes=5 * i))
            with patch.object(m, 'create_alert', wraps=m.create_alert) as spy, \
                    patch.object(Device, 'uptime_percentage', return_value=0.0):
                m.check_device_down_alerts()
                m.check_device_down_alerts()
            assert spy.call_count == 2
            assert Alert.query.filter_by(device_id=d.id, alert_type='device_down').count() == 1

    def test_high_latency_goes_through_create_alert_once(self, app, db_session):
        with app.app_context():
            m = self._manager(app)
            d = _device(device_type='camera', last_seen=datetime.utcnow())
            for i in range(4):
                SuccessfulMonitoringDataFactory.create(device=d, response_time=4000,
                                                       timestamp=datetime.utcnow() - timedelta(minutes=2 * i))
            with patch.object(m, 'create_alert', wraps=m.create_alert) as spy:
                m.check_high_latency_alerts()
                m.check_high_latency_alerts()
            assert spy.call_count >= 1
            assert Alert.query.filter_by(device_id=d.id, alert_type='high_latency').count() == 1

    def test_recovery_is_resolved_and_not_pushed_during_startup_grace(self, app, db_session):
        with app.app_context():
            m = self._manager(app)
            d = _device(device_type='camera', last_seen=datetime.utcnow())
            down = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='down',
                         created_at=datetime.utcnow() - timedelta(hours=1))
            db.session.add(down)
            db.session.commit()
            m._started_at = datetime.utcnow()
            with patch.object(m, 'create_alert', wraps=m.create_alert) as spy:
                rec = m._create_recovery_alert(down, d)
            assert rec is not None and rec.resolved is True and rec.resolved_at is not None
            assert spy.call_args.kwargs == {'notify': False, 'resolved': True}
            assert m._create_recovery_alert(down, d) is None       # one recovery per down alert

    def test_recovery_notifies_after_grace(self, app, db_session):
        with app.app_context():
            m = self._manager(app)
            d = _device(device_type='camera', last_seen=datetime.utcnow())
            down = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='down',
                         created_at=datetime.utcnow() - timedelta(hours=1))
            db.session.add(down)
            db.session.commit()
            m._started_at = datetime.utcnow() - timedelta(seconds=ALERT_STARTUP_GRACE_SECONDS + 1)
            with patch.object(m, 'create_alert', wraps=m.create_alert) as spy:
                m._create_recovery_alert(down, d)
            assert spy.call_args.kwargs == {'notify': True, 'resolved': True}

    def test_removed_hooks_are_gone(self):
        for name in ('run_alert_correlation', 'cleanup_duplicate_alerts', 'setup_default_suppressions'):
            assert not hasattr(AlertManager, name), name


class TestNotificationStatus:

    def test_policy_blocks_write_suppressed(self, app, db_session):
        with app.app_context():
            m = AlertManager(app=app)
            d = _device(device_type='camera')
            Configuration.set_value('notify_device_down', 'false')
            Configuration.set_value('push_notifications_enabled', 'true')
            alert = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='down')
            db.session.add(alert)
            db.session.commit()
            with patch.object(m, 'send_push_notification') as push:
                assert m.send_alert_notifications(alert) is False
            push.assert_not_called()
            assert alert.notification_status == 'suppressed'

    def test_sent_and_failed_and_none(self, app, db_session):
        with app.app_context():
            m = AlertManager(app=app)
            d = _device(device_type='camera')
            alert = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='down')
            db.session.add(alert)
            db.session.commit()
            assert m.send_alert_notifications(alert) is False
            assert alert.notification_status == 'none'
            Configuration.set_value('push_notifications_enabled', 'true')
            with patch.object(m, 'send_push_notification', return_value=False):
                m.send_alert_notifications(alert)
            assert alert.notification_status == 'failed' and not alert.notification_sent
            with patch.object(m, 'send_push_notification', return_value=True):
                assert m.send_alert_notifications(alert) is True
            assert alert.notification_status == 'sent' and alert.notification_sent
            assert alert.notification_count == 1 and alert.last_notification_at is not None

    def test_quiet_hours_let_critical_through(self, app, db_session):
        with app.app_context():
            m = AlertManager(app=app)
            d = _device(device_type='camera')
            Configuration.set_value('push_notifications_enabled', 'true')
            warning = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='w')
            critical = Alert(device_id=d.id, alert_type='wan_down', severity='critical', message='c')
            db.session.add_all([warning, critical])
            db.session.commit()
            always_quiet = NotificationPolicy(quiet_start=0, quiet_end=23)
            with patch.object(NotificationPolicy, 'load', return_value=always_quiet), \
                    patch.object(NotificationPolicy, 'in_quiet_hours', return_value=True), \
                    patch.object(m, 'send_push_notification', return_value=True) as push:
                m.send_alert_notifications(warning)
                m.send_alert_notifications(critical)
            assert push.call_count == 1 and warning.notification_status == 'suppressed'
            assert critical.notification_status == 'sent'


class TestScanNotifications:

    def test_scan_complete_push_is_off_by_default_and_gated(self, app, db_session):
        from monitoring.scanner import NetworkScanner
        scanner = NetworkScanner(app=app)
        scanner._new_devices_found = []
        with app.app_context(), patch('monitoring.scanner.push_service') as push:
            scanner._notify_scan_results(total_devices=3)
            push.send_network_scan_complete.assert_not_called()
            Configuration.set_value('notify_scan_complete', 'true')
            scanner._notify_scan_results(total_devices=3)
            push.send_network_scan_complete.assert_called_once()

    def test_first_five_new_devices_notify_the_rest_are_recorded(self, app, db_session):
        from monitoring.scanner import NetworkScanner
        app.alert_manager = AlertManager(app=app)
        scanner = NetworkScanner(app=app)
        found = []
        with app.app_context():
            for i in range(7):
                d = _device(ip_address=f'192.168.1.{100 + i}', mac_address=f'00:ab:00:00:01:{i:02x}', hostname=f'n{i}',
                            device_type='camera')
                found.append({'ip': d.ip_address, 'mac': d.mac_address, 'hostname': d.hostname, 'device_type': 'camera', 'vendor': None})
            scanner._new_devices_found = found
            with patch.object(app.alert_manager, 'create_alert', wraps=app.alert_manager.create_alert) as spy, \
                    patch.object(app.alert_manager, 'send_alert_notifications'):
                scanner._notify_scan_results(total_devices=7)
            notify_flags = [c.kwargs['notify'] for c in spy.call_args_list]
            assert notify_flags == [True] * 5 + [False] * 2
            assert Alert.query.filter_by(alert_type='new_device').count() == 7
