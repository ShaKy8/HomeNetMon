"""Push notifications: one table-driven sender, deep links per alert type, log rows carry ids."""

from unittest.mock import MagicMock, patch

from config import Config
from models import Alert, Configuration, NotificationHistory, db
from monitoring.alerts import AlertManager
from services.push_notifications import push_service
from tests.fixtures.factories import DeviceFactory


def _alert(device, alert_type, severity='warning'):
    a = Alert(device_id=device.id, alert_type=alert_type, severity=severity, message=f'{alert_type} on {device.ip_address}')
    db.session.add(a)
    db.session.commit()
    return a


def _configured():
    # send_notification() re-reads the runtime settings before every send
    Configuration.set_value('push_notifications_enabled', 'true')
    Configuration.set_value('ntfy_server', 'https://ntfy.example')
    Configuration.set_value('ntfy_topic', 'hnm')
    return patch('services.push_notifications.push_service.username', None)


class TestDeepLinks:

    def test_click_url_by_type(self, app, db_session):
        device = DeviceFactory.create()
        manager = AlertManager(app=app)
        base = Config.BASE_URL.rstrip('/')
        with app.app_context():
            assert manager._click_url(_alert(device, 'device_down')) == f'{base}/device/{device.id}'
            assert manager._click_url(_alert(device, 'security_new_service')) == f'{base}/security'
            assert manager._click_url(_alert(device, 'wan_down', 'critical')) == f'{base}/alerts'
            assert manager._click_url(_alert(device, 'gateway_down', 'critical')) == f'{base}/alerts'
            assert manager._click_url(_alert(device, 'high_latency')) == f'{base}/device/{device.id}'

    def test_push_sends_click_header_and_logs_ids(self, app, db_session):
        device = DeviceFactory.create(custom_name='Office PC')
        manager = AlertManager(app=app)
        with app.app_context():
            alert = _alert(device, 'device_down')
            response = MagicMock(status_code=200)
            with _configured(), patch('services.push_notifications.requests.post', return_value=response) as post:
                assert manager.send_push_notification(alert) is True
            headers = post.call_args.kwargs['headers']
            assert headers['Click'].endswith(f'/device/{device.id}')
            assert headers['Title'].encode('latin-1').decode('utf-8').startswith('🔴 Device Offline: Office PC')   # ntfy wants latin-1 header bytes
            assert headers['Priority'] == 'high'
            row = NotificationHistory.query.filter_by(alert_id=alert.id).one()
            assert row.device_id == device.id and row.notification_type == 'device_down'
            assert row.delivery_status == 'success'

    def test_critical_raises_priority_and_unknown_type_has_a_fallback(self, app, db_session):
        device = DeviceFactory.create()
        manager = AlertManager(app=app)
        with app.app_context():
            alert = _alert(device, 'performance', 'critical')
            with _configured(), patch('services.push_notifications.requests.post', return_value=MagicMock(status_code=200)) as post:
                manager.send_push_notification(alert)
            assert post.call_args.kwargs['headers']['Priority'] == 'high'
            other = _alert(device, 'something_new')
            with _configured(), patch('services.push_notifications.requests.post', return_value=MagicMock(status_code=200)) as post:
                manager.send_push_notification(other)
            assert post.call_args.kwargs['headers']['Title'].encode('latin-1').decode('utf-8').startswith('🚨 Alert')

    def test_failed_push_is_logged_with_the_alert(self, app, db_session):
        device = DeviceFactory.create()
        manager = AlertManager(app=app)
        with app.app_context():
            alert = _alert(device, 'device_down')
            with _configured(), patch('services.push_notifications.requests.post', return_value=MagicMock(status_code=429, text='rate limited')):
                assert manager.send_push_notification(alert) is False
            row = NotificationHistory.query.filter_by(alert_id=alert.id).one()
            assert row.delivery_status == 'failed' and row.notification_type == 'device_down'

    def test_typed_senders_are_gone(self):
        for name in ('send_device_down_alert', 'send_device_up_alert', 'send_new_device_alert',
                     'send_high_latency_alert', 'send_security_alert'):
            assert not hasattr(push_service, name), name
        assert not hasattr(AlertManager, '_send_high_latency_push_notification')
