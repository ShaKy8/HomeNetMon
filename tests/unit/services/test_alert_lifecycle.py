"""
AlertManager.resolve_alerts() is the single owner of alert auto-resolution.

The former services/alert_auto_resolver.py and alert_retention_policy.py were
called from the DeviceMonitor loop without an app context and never completed a
cycle, which is how 141 alerts (oldest May 2026) stayed open in production.
These tests pin each resolution rule and the dry-run contract.
"""

from datetime import datetime, timedelta

import pytest

from models import Alert, Configuration, Device, MonitoringData, PerformanceMetrics, db
from monitoring.alerts import AlertManager


@pytest.fixture
def manager(app):
    return AlertManager(app)


def _device(db_session, ip, monitored=True, last_seen=None):
    d = Device(ip_address=ip, mac_address='00:aa:00:00:00:' + ip.split('.')[-1].zfill(2)[-2:],
               hostname=f'host-{ip.split(".")[-1]}', device_type='computer',
               is_monitored=monitored, last_seen=last_seen)
    db_session.add(d)
    db_session.commit()
    return d


def _alert(db_session, device, alert_type, age_hours=1, subtype=None, severity='warning'):
    a = Alert(device_id=device.id, alert_type=alert_type, alert_subtype=subtype, severity=severity,
              message=f'{alert_type} for {device.hostname}',
              created_at=datetime.utcnow() - timedelta(hours=age_hours), resolved=False)
    db_session.add(a)
    db_session.commit()
    return a


def _metrics(db_session, device, age_hours=1, health=80.0, responsiveness=80.0, reliability=80.0):
    m = PerformanceMetrics(device_id=device.id, timestamp=datetime.utcnow() - timedelta(hours=age_hours),
                           health_score=health, responsiveness_score=responsiveness,
                           reliability_score=reliability)
    db_session.add(m)
    db_session.commit()
    return m


class TestDeviceDown:

    def test_resolves_when_device_seen_recently(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.10', last_seen=datetime.utcnow() - timedelta(minutes=1))
        alert = _alert(db_session, dev, 'device_down')
        counts = manager.resolve_alerts()
        assert counts['device_down'] == 1
        assert db.session.get(Alert, alert.id).resolved is True

    def test_stays_open_when_device_still_silent(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.11', last_seen=datetime.utcnow() - timedelta(hours=2))
        alert = _alert(db_session, dev, 'device_down')
        counts = manager.resolve_alerts()
        assert counts['device_down'] == 0
        assert db.session.get(Alert, alert.id).resolved is False


class TestHighLatency:

    def test_resolves_when_no_recent_high_sample(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.12', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'high_latency')
        db_session.add(MonitoringData(device_id=dev.id, response_time=20.0, timestamp=datetime.utcnow()))
        db_session.commit()
        assert manager.resolve_alerts()['high_latency'] == 1
        assert db.session.get(Alert, alert.id).resolved is True

    def test_stays_open_while_latency_still_high(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.13', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'high_latency')
        db_session.add(MonitoringData(device_id=dev.id, response_time=5000.0, timestamp=datetime.utcnow()))
        db_session.commit()
        assert manager.resolve_alerts()['high_latency'] == 0
        assert db.session.get(Alert, alert.id).resolved is False


class TestPerformance:

    def test_unmonitored_device_resolves_with_note(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.20', monitored=False)
        alert = _alert(db_session, dev, 'performance', subtype='performance_warning')
        assert manager.resolve_alerts()['performance'] == 1
        refreshed = db.session.get(Alert, alert.id)
        assert refreshed.resolved is True
        assert 'no longer monitored' in refreshed.message

    def test_no_recent_metrics_resolves(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.21', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'performance', subtype='performance_critical')
        _metrics(db_session, dev, age_hours=48, health=5.0)
        assert manager.resolve_alerts()['performance'] == 1
        assert 'no recent performance data' in db.session.get(Alert, alert.id).message

    def test_low_health_stays_open(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.22', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'performance', subtype='performance_critical')
        _metrics(db_session, dev, age_hours=1, health=10.0)
        assert manager.resolve_alerts()['performance'] == 0
        assert db.session.get(Alert, alert.id).resolved is False

    def test_recovered_health_resolves(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.23', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'performance', subtype='performance_warning')
        _metrics(db_session, dev, age_hours=1, health=75.0)
        assert manager.resolve_alerts()['performance'] == 1
        assert db.session.get(Alert, alert.id).resolved is True

    def test_responsiveness_subtype_uses_its_own_score(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.24', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'performance', subtype='performance_responsiveness')
        _metrics(db_session, dev, age_hours=1, health=90.0, responsiveness=10.0)
        assert manager.resolve_alerts()['performance'] == 0
        assert db.session.get(Alert, alert.id).resolved is False

    def test_recovery_threshold_is_runtime_configurable(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.25', last_seen=datetime.utcnow())
        _alert(db_session, dev, 'performance', subtype='performance_warning')
        _metrics(db_session, dev, age_hours=1, health=50.0)
        Configuration.set_value('performance_alert_recovery_threshold', '70')
        db_session.commit()
        assert manager.resolve_alerts()['performance'] == 0


class TestNewDevice:

    def test_expires_after_a_day(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.30', last_seen=datetime.utcnow())
        old = _alert(db_session, dev, 'new_device', age_hours=30, severity='info')
        fresh = _alert(db_session, dev, 'new_device', age_hours=2, severity='info')
        assert manager.resolve_alerts()['new_device'] == 1
        assert db.session.get(Alert, old.id).resolved is True
        assert db.session.get(Alert, fresh.id).resolved is False


class TestStale:

    def test_anything_older_than_max_open_days_resolves(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.40', last_seen=datetime.utcnow() - timedelta(days=40))
        stale = _alert(db_session, dev, 'security_suspicious_port', age_hours=24 * 31, severity='high')
        recent = _alert(db_session, dev, 'security_suspicious_port', age_hours=24 * 5, severity='high')
        counts = manager.resolve_alerts()
        assert counts['stale'] == 1
        refreshed = db.session.get(Alert, stale.id)
        assert refreshed.resolved is True
        assert refreshed.message.endswith('[auto-resolved: stale]')
        assert db.session.get(Alert, recent.id).resolved is False

    def test_max_open_days_is_runtime_configurable(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.41', last_seen=datetime.utcnow())
        alert = _alert(db_session, dev, 'security_new_service', age_hours=24 * 8, severity='low')
        Configuration.set_value('alert_max_open_days', '7')
        db_session.commit()
        assert manager.resolve_alerts()['stale'] == 1
        assert db.session.get(Alert, alert.id).resolved is True


class TestDryRun:

    def test_dry_run_counts_without_writing(self, app, db_session, manager):
        dev = _device(db_session, '192.168.1.50', last_seen=datetime.utcnow())
        down = _alert(db_session, dev, 'device_down')
        stale = _alert(db_session, dev, 'high_latency', age_hours=24 * 45)
        counts = manager.resolve_alerts(dry_run=True)
        assert counts['device_down'] == 1
        assert counts['stale'] == 1
        assert db.session.get(Alert, down.id).resolved is False
        assert db.session.get(Alert, stale.id).resolved is False
        assert 'stale' not in db.session.get(Alert, stale.id).message

    def test_each_alert_counted_once(self, app, db_session, manager):
        # A stale device_down alert on a device that is also back online must not be double-counted.
        dev = _device(db_session, '192.168.1.51', last_seen=datetime.utcnow())
        _alert(db_session, dev, 'device_down', age_hours=24 * 45)
        counts = manager.resolve_alerts()
        assert sum(counts.values()) == 1
