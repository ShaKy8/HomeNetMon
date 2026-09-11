"""
Tests for services/retention.py — the single retention service that replaced
five inconsistent cleanup paths (per-insert DELETE listeners, DeviceMonitor's
7-day startup purge, ResourceMonitor's hardcoded days, AlertManager's
cleanup_old_alerts, and Config.DATA_RETENTION_DAYS being applied to one table).
"""

from datetime import datetime, timedelta

import pytest

from models import Alert, Configuration, Device, MonitoringData, NotificationHistory, db
from services import retention


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.50', mac_address='00:cc:00:00:00:01', hostname='ret-test',
               device_type='computer', is_monitored=True, last_seen=datetime.utcnow())
    db_session.add(d)
    db_session.commit()
    return d


def _rows(device, ages_days):
    now = datetime.utcnow()
    return [MonitoringData(device_id=device.id, response_time=1.0, timestamp=now - timedelta(days=a))
            for a in ages_days]


def _rule(table):
    return next(r for r in retention.RETENTION_TABLES if r.table == table)


class TestPurgeTable:

    def test_deletes_only_rows_older_than_default(self, app, db_session, device):
        db_session.add_all(_rows(device, [1, 10, 29, 31, 40]))
        db_session.commit()
        with app.app_context():
            deleted = retention.purge_table(_rule('monitoring_data'), days=30)
            assert deleted == 2
            assert MonitoringData.query.count() == 3

    def test_runtime_configuration_overrides_default(self, app, db_session, device):
        db_session.add_all(_rows(device, [1, 3, 5]))
        Configuration.set_value('data_retention_days', '2')
        db_session.commit()
        with app.app_context():
            assert retention.purge_table(_rule('monitoring_data')) == 2
            assert MonitoringData.query.count() == 1

    def test_specific_key_beats_global_key(self, app, db_session, device):
        db_session.add_all(_rows(device, [1, 3, 5]))
        Configuration.set_value('data_retention_days', '2')
        Configuration.set_value('performance_retention_days', '10')
        db_session.commit()
        with app.app_context():
            assert retention._days_for(_rule('performance_metrics')) == 10
            assert retention._days_for(_rule('monitoring_data')) == 2

    def test_garbage_configuration_falls_back_to_default(self, app, db_session):
        Configuration.set_value('notification_retention_days', 'soon')
        db_session.commit()
        with app.app_context():
            assert retention._days_for(_rule('notification_history')) == 30

    def test_batches_larger_than_batch_size(self, app, db_session, device, monkeypatch):
        monkeypatch.setattr(retention, 'BATCH_SIZE', 7)
        db_session.add_all(_rows(device, [40] * 23 + [1]))
        db_session.commit()
        with app.app_context():
            assert retention.purge_table(_rule('monitoring_data'), days=30) == 23
            assert MonitoringData.query.count() == 1

    def test_dry_run_deletes_nothing(self, app, db_session, device):
        db_session.add_all(_rows(device, [40, 41]))
        db_session.commit()
        with app.app_context():
            assert retention.purge_table(_rule('monitoring_data'), days=30, dry_run=True) == 2
            assert MonitoringData.query.count() == 2

    def test_resolved_alert_rule_leaves_open_alerts(self, app, db_session, device):
        old = datetime.utcnow() - timedelta(days=45)
        db_session.add_all([
            Alert(device_id=device.id, alert_type='device_down', message='a', created_at=old,
                  resolved=True, resolved_at=old),
            Alert(device_id=device.id, alert_type='device_down', message='b', created_at=old,
                  resolved=False),
        ])
        db_session.commit()
        with app.app_context():
            assert retention.purge_table(_rule('alerts'), days=30) == 1
            remaining = Alert.query.all()
            assert len(remaining) == 1 and remaining[0].resolved is False

    def test_missing_table_is_skipped(self, app, db_session):
        ghost = retention.RetentionRule('no_such_table', 'ts', 'x_days', 1, label='ghosts')
        with app.app_context():
            assert retention.purge_table(ghost, days=1) == 0


class TestRunAll:

    def test_run_all_covers_multiple_tables_and_records_status(self, app, db_session, device):
        old = datetime.utcnow() - timedelta(days=400)
        db_session.add_all(_rows(device, [400, 1]))
        db_session.add(NotificationHistory(device_id=device.id, notification_type='device_down',
                                           title='t', message='m', sent_at=old))
        db_session.add(NotificationHistory(device_id=device.id, notification_type='device_down',
                                           title='t', message='m', sent_at=datetime.utcnow()))
        db_session.commit()

        deleted = retention.run_all(app)

        assert deleted['monitoring_data'] == 1
        assert deleted['notification_history'] >= 1
        with app.app_context():
            cutoff = datetime.utcnow() - timedelta(days=300)
            assert MonitoringData.query.filter(MonitoringData.timestamp < cutoff).count() == 0
            assert MonitoringData.query.filter(MonitoringData.timestamp >= cutoff, MonitoringData.device_id == device.id).count() >= 1
            assert NotificationHistory.query.filter_by(device_id=device.id).count() == 1
        st = retention.status()
        assert st['runs'] >= 1 and st['last_run'] and st['last_deleted'] == deleted

    def test_no_before_insert_listeners_remain(self, app, db_session, device):
        """Inserting a row must never delete other rows as a side effect."""
        old = _rows(device, [400])[0]
        db_session.add(old)
        db_session.commit()
        db_session.add(_rows(device, [0])[0])
        db_session.commit()
        with app.app_context():
            assert MonitoringData.query.count() == 2


class TestRunAllIsolation:

    def test_failed_rule_does_not_block_next_rule(self, app, db_session, device, monkeypatch):
        db_session.add_all(_rows(device, [1, 40]))
        db_session.commit()
        bad = retention.RetentionRule('monitoring_data', 'no_such_column', 'nope_days', 1, label='broken')
        good = _rule('monitoring_data')
        monkeypatch.setattr(retention, 'RETENTION_TABLES', (bad, good))
        deleted = retention.run_all(app)
        assert deleted.get('monitoring_data') == 1
        with app.app_context():
            assert MonitoringData.query.count() == 1
