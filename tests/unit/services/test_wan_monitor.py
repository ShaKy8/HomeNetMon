"""monitoring/wan_monitor.py: gateway + internet checks, alerting through AlertManager."""

from unittest.mock import patch

import pytest

from models import Alert, Configuration, Device, WanCheck, db
from monitoring.wan_monitor import WanMonitor, detect_default_gateway


@pytest.fixture
def wan(app, db_session):
    monitor = WanMonitor(app)
    monitor._gateway_cache = ('192.168.1.1', 10 ** 12)     # skip `ip route`
    return monitor


def _pings(gateway, target):
    def fake(ip, timeout=2.0):
        return {'192.168.1.1': gateway, '1.1.1.1': target}.get(ip)
    return fake


def test_check_writes_a_row_and_reports_up(app, wan):
    with app.app_context(), patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.2, 12.5)):
        state = wan.check_once(notify=False)
    assert state['status'] == 'up' and state['internet_up'] and state['gateway_up']
    with app.app_context():
        row = WanCheck.query.first()
        assert row.internet_up and row.gateway_up and row.target == '1.1.1.1' and row.gateway_ip == '192.168.1.1'


def test_three_target_failures_raise_one_wan_down_alert(app, wan):
    with app.app_context(), patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.0, None)):
        for _ in range(4):
            state = wan.check_once(notify=False)
    assert state['status'] == 'down' and state['consecutive_failures'] == 4
    with app.app_context():
        alerts = Alert.query.filter_by(alert_type='wan_down').all()
        assert len(alerts) == 1 and alerts[0].severity == 'critical' and alerts[0].resolved is False
        gateway = Device.query.filter_by(ip_address='192.168.1.1').first()
        assert gateway is not None and gateway.device_type == 'router' and alerts[0].device_id == gateway.id
        assert Alert.query.filter_by(alert_type='gateway_down').count() == 0


def test_gateway_failure_raises_gateway_down_not_wan_down(app, wan):
    with app.app_context(), patch('monitoring.wan_monitor.ping_host', side_effect=_pings(None, None)):
        for _ in range(3):
            wan.check_once(notify=False)
    with app.app_context():
        assert Alert.query.filter_by(alert_type='gateway_down').count() == 1
        assert Alert.query.filter_by(alert_type='wan_down').count() == 0


def test_recovery_resolves_and_announces(app, wan):
    with app.app_context():
        with patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.0, None)):
            for _ in range(3):
                wan.check_once(notify=False)
        with patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.0, 9.0)):
            state = wan.check_once(notify=False)
        assert state['status'] == 'up'
        down = Alert.query.filter_by(alert_type='wan_down').first()
        assert down.resolved is True
        assert Alert.query.filter_by(alert_type='wan_recovery', severity='info').count() == 1


def test_threshold_and_target_are_runtime_configurable(app, wan):
    with app.app_context():
        Configuration.set_value('wan_down_after_checks', '1')
        Configuration.set_value('wan_check_target', '9.9.9.9')
        db.session.commit()
        with patch('monitoring.wan_monitor.ping_host', side_effect=lambda ip, timeout=2.0: 1.0 if ip == '192.168.1.1' else None):
            state = wan.check_once(notify=False)
        assert state['target'] == '9.9.9.9' and state['status'] == 'down'
        assert Alert.query.filter_by(alert_type='wan_down').count() == 1


def test_status_view_summarises_the_window(app, wan):
    with app.app_context():
        with patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.0, 10.0)):
            wan.check_once(notify=False)
            wan.check_once(notify=False)
        with patch('monitoring.wan_monitor.ping_host', side_effect=_pings(1.0, None)):
            wan.check_once(notify=False)
        view = wan.status(24)
    assert view['checks'] == 3 and view['availability_pct'] == 66.7 and view['avg_rtt_ms'] == 10.0
    assert view['gateway']['ip'] == '192.168.1.1' and len(view['timeline']) == 3


def test_api_endpoint(client, app, wan):
    app.wan_monitor = wan
    r = client.get('/api/monitoring/wan?hours=6')
    assert r.status_code == 200
    assert r.get_json()['hours'] == 6


def test_watchdog_and_retention_know_the_monitor():
    from core.health import EXPECTED_THREADS
    from services import retention
    assert 'WanMonitor' in EXPECTED_THREADS
    assert any(r.table == 'wan_checks' for r in retention.RETENTION_TABLES)


def test_gateway_detection_parses_ip_route():
    with patch('monitoring.wan_monitor.subprocess.run') as run:
        run.return_value.stdout = 'default via 192.168.86.1 dev enp2s0 proto dhcp src 192.168.86.30 metric 100 \n'
        assert detect_default_gateway() == '192.168.86.1'
