"""Half-built features finished in Track A: speed-test persistence/scheduling,
suppression rules API + UI, new-device alerts, config history UI, dashboard groups."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models import Alert, AlertSuppression, Device, db


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


class TestSuppressionRulesUi:

    def test_alerts_page_has_rules_modal(self, client):
        html = client.get('/alerts').get_data(as_text=True)
        assert 'id="suppressionsModal"' in html and '/api/monitoring/alerts/suppressions' in html

    def test_rule_roundtrip_via_api(self, client, db_session):
        tok = _token(client)
        r = client.post('/api/monitoring/alerts/suppressions', json={'name': 'Night', 'enabled': True, 'alert_type': 'performance',
                                                                     'daily_start_hour': 23, 'daily_end_hour': 7},
                        headers={'X-CSRF-Token': tok})
        assert r.status_code in (200, 201), r.get_json()
        rules = client.get('/api/monitoring/alerts/suppressions').get_json()['suppressions']
        rule = next(x for x in rules if x['name'] == 'Night')
        assert rule['alert_type'] == 'performance' and rule['daily_start_hour'] == 23
        r = client.put(f"/api/monitoring/alerts/suppressions/{rule['id']}", json={'enabled': False}, headers={'X-CSRF-Token': tok})
        assert r.status_code == 200
        r = client.delete(f"/api/monitoring/alerts/suppressions/{rule['id']}", headers={'X-CSRF-Token': tok})
        assert r.status_code == 200


class TestNewDeviceAlerts:

    def test_scanner_records_an_alert_for_each_new_device(self, app, db_session):
        from monitoring.alerts import AlertManager
        from monitoring.scanner import NetworkScanner
        d = Device(ip_address='192.168.1.200', mac_address='00:cd:00:00:00:01', hostname='newbie', device_type='phone',
                   is_monitored=True, last_seen=datetime.utcnow())
        db_session.add(d); db_session.commit()
        app.alert_manager = AlertManager(app=app)
        app.alert_manager.send_alert_notifications = lambda alert: None
        scanner = NetworkScanner(app=app)
        scanner._new_devices_found = [{'ip': '192.168.1.200', 'mac': '00:cd:00:00:00:01', 'hostname': 'newbie', 'device_type': 'phone', 'vendor': None}]
        with app.app_context():
            scanner._create_new_device_alerts()
            alerts = Alert.query.filter_by(device_id=d.id, alert_type='new_device').all()
        assert len(alerts) == 1 and alerts[0].severity == 'info' and 'newbie' in alerts[0].message


class TestSettingsAndDashboardAdditions:

    def test_settings_has_history_section(self, client):
        html = client.get('/settings').get_data(as_text=True)
        assert 'id="history"' in html and '/api/config-management/history' in html and '/api/config-management/rollback' in html

    def test_dashboard_has_group_filter(self, client):
        html = client.get('/').get_data(as_text=True)
        assert 'id="group-filter"' in html
        from pathlib import Path
        js = (Path(__file__).resolve().parents[2] / 'static/js/dashboard-page.js').read_text()
        assert 'refreshGroupOptions' in js and 'device_group' in js
