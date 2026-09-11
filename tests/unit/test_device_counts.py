"""services/device_counts.py is the one definition of total / monitored / up / down /
unknown / active_alerts. /api/monitoring/summary, the analytics health score and the
Socket.IO summary push must all agree with it (they used to report 145 / 107 / 60)."""

from datetime import datetime, timedelta

import pytest

from constants import DEVICE_DOWN_AFTER_SECONDS
from models import Alert, Configuration, Device, db
from services import device_counts


@pytest.fixture
def fleet(db_session):
    Configuration.set_value('network_range', '192.168.1.0/24')
    now = datetime.utcnow()
    rows = [
        Device(ip_address='192.168.1.10', mac_address='00:aa:00:00:00:10', hostname='up', is_monitored=True,
               last_seen=now - timedelta(seconds=30)),
        Device(ip_address='192.168.1.11', mac_address='00:aa:00:00:00:11', hostname='down', is_monitored=True,
               last_seen=now - timedelta(seconds=DEVICE_DOWN_AFTER_SECONDS + 60)),
        Device(ip_address='172.19.0.2', mac_address='00:aa:00:00:00:12', hostname='docker', is_monitored=True,
               last_seen=now),
        Device(ip_address=None, mac_address='00:aa:00:00:00:13', hostname='no-ip', is_monitored=True, last_seen=now),
        Device(ip_address='192.168.1.14', mac_address='00:aa:00:00:00:14', hostname='archived', is_monitored=False,
               last_seen=now),
    ]
    db_session.add_all(rows)
    db_session.commit()
    db_session.add(Alert(device_id=rows[0].id, alert_type='device_down', severity='warning', message='x', resolved=False))
    db_session.add(Alert(device_id=rows[2].id, alert_type='device_down', severity='warning', message='y', resolved=False))
    db_session.add(Alert(device_id=rows[1].id, alert_type='device_down', severity='warning', message='z', resolved=True))
    db_session.commit()
    return rows


def test_summary_definitions(app, fleet):
    with app.app_context():
        s = device_counts.summarize()
    assert s['total_devices'] == 5
    assert s['monitored_devices'] == 2          # in range, with an IP, is_monitored
    assert s['devices_up'] == 1
    assert s['devices_down'] == 1
    assert s['devices_unknown'] == 3            # docker bridge, no IP, archived
    assert s['active_alerts'] == 2              # over all devices, unresolved only
    assert s['network_range'] == '192.168.1.0/24'


def test_monitored_devices_excludes_out_of_range_and_unaddressed(app, fleet):
    with app.app_context():
        names = sorted(d.hostname for d in device_counts.monitored_devices())
    assert names == ['down', 'up']


def test_unparsable_range_does_not_stop_monitoring(app, fleet):
    with app.app_context():
        Configuration.set_value('network_range', 'garbage')
        db.session.commit()
        names = sorted(d.hostname for d in device_counts.monitored_devices())
    assert names == ['docker', 'down', 'up']


def test_summary_endpoint_and_health_score_agree(client, app, fleet):
    summary = client.get('/api/monitoring/summary').get_json()
    health = client.get('/api/analytics/network-health-score').get_json()
    assert summary['monitored_devices'] == 2
    assert summary['devices_up'] == 1 and summary['devices_down'] == 1
    assert summary['total_devices'] == 5
    assert summary['active_alerts'] == 2
    assert summary['network_uptime'] == '50.0%'
    assert health['metrics']['total_devices'] == summary['monitored_devices']
    assert health['metrics']['devices_up'] == summary['devices_up']
    assert health['metrics']['active_alerts'] == summary['active_alerts']


def test_scanner_range_change_archives_and_resumes(app, fleet):
    from monitoring.scanner import NetworkScanner
    scanner = NetworkScanner(app=app)
    with app.app_context():
        docker = Device.query.filter_by(hostname='docker').first()
        docker.is_monitored = False       # archived earlier; seen today, so it resumes
        db.session.commit()
        archived, resumed = scanner.apply_network_range('172.19.0.0/16')
        assert (archived, resumed) == (2, 1)
        assert Device.query.filter_by(hostname='docker').first().is_monitored is True
        assert Device.query.filter_by(hostname='up').first().is_monitored is False
        assert Device.query.filter_by(hostname='archived').first().is_monitored is False
