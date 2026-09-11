"""End-to-end checks over every API route a page, script or health check calls.

Runs against the Flask test client with the shared conftest fixtures. Covers the
envelope each route returns (the two envelope styles documented in CLAUDE.md), the
write paths with CSRF, validation, and the rate-limit tiers. This suite is a CI
gate; the previous api/integration suites targeted routes that never existed.
"""

from datetime import datetime, timedelta

import pytest

from models import Alert, Configuration, Device, MonitoringData, db


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


def _hdr(client):
    return {'X-CSRF-Token': _token(client)}


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.21', mac_address='00:11:22:33:44:21', hostname='integ-1', device_type='computer',
               is_monitored=True, last_seen=datetime.utcnow())
    db_session.add(d)
    db_session.commit()
    now = datetime.utcnow()
    db_session.add_all(MonitoringData(device_id=d.id, response_time=float(5 + i), timestamp=now - timedelta(minutes=i)) for i in range(5))
    db_session.add(Alert(device_id=d.id, alert_type='device_down', severity='warning', message='integration alert'))
    db_session.commit()
    return d


class TestDevices:

    def test_list_and_detail(self, client, device):
        body = client.get('/api/devices').get_json()
        assert body['success'] is True and body['total'] == 1
        assert body['devices'][0]['display_name'] == 'integ-1' and 'tags' in body['devices'][0]
        detail = client.get(f'/api/devices/{device.id}').get_json()
        assert detail['success'] is True and detail['device']['id'] == device.id
        assert 'uptime_percentage' in detail['device']

    def test_create_update_delete(self, client, app, db_session):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(app._scanner, 'resolve_hostname', lambda ip: None)
            r = client.post('/api/devices', json={'ip_address': '192.168.1.22', 'custom_name': 'New', 'tags': 'a,b'}, headers=_hdr(client))
        assert r.status_code == 201
        new_id = r.get_json()['device']['id']
        r = client.put(f'/api/devices/{new_id}', json={'custom_name': 'Renamed', 'is_monitored': False}, headers=_hdr(client))
        assert r.status_code == 200
        assert client.get(f'/api/devices/{new_id}').get_json()['device']['custom_name'] == 'Renamed'
        assert client.delete(f'/api/devices/{new_id}', headers=_hdr(client)).status_code == 200
        assert client.get(f'/api/devices/{new_id}').status_code == 404

    def test_create_rejects_bad_and_duplicate_ip(self, client, device):
        assert client.post('/api/devices', json={'ip_address': 'nope'}, headers=_hdr(client)).status_code == 400
        assert client.post('/api/devices', json={'ip_address': device.ip_address}, headers=_hdr(client)).status_code == 400

    def test_update_rejects_unknown_fields(self, client, device):
        r = client.put(f'/api/devices/{device.id}', json={'evil': 1}, headers=_hdr(client))
        assert r.status_code == 400

    def test_history_csv_types_ip_history(self, client, device):
        r = client.get(f'/api/devices/{device.id}/history.csv')
        assert r.status_code == 200 and r.mimetype == 'text/csv'
        assert 'computer' in client.get('/api/devices/types').get_json()['types']
        body = client.get(f'/api/devices/{device.id}/ip-history').get_json()
        assert body['success'] and body['device_id'] == device.id and isinstance(body['ip_history'], list)

    def test_ping_bulk_update_scan_status(self, client, device):
        r = client.post(f'/api/devices/{device.id}/ping', json={}, headers=_hdr(client))
        assert r.status_code == 200 and r.get_json()['success']
        r = client.post('/api/devices/bulk-update', json={'device_ids': [device.id], 'is_monitored': False}, headers=_hdr(client))
        assert r.status_code == 200
        assert db.session.get(Device, device.id).is_monitored is False
        assert client.get('/api/devices/scan-status').get_json()['scan_in_progress'] in (True, False)


class TestMonitoring:

    def test_data_summary_bandwidth(self, client, device):
        body = client.get(f'/api/monitoring/data?device_id={device.id}&hours=24&limit=500').get_json()
        assert len(body['monitoring_data']) == 5 and body['pagination']['per_page'] == 500
        summary = client.get('/api/monitoring/summary').get_json()
        assert summary['monitored_devices'] == 1 and summary['devices_up'] == 1 and summary['active_alerts'] == 1
        for path in ('/api/monitoring/bandwidth/summary', '/api/monitoring/bandwidth/timeline', '/api/monitoring/bandwidth/devices'):
            assert client.get(path).status_code == 200, path

    def test_alert_lifecycle(self, client, device):
        alert = Alert.query.first()
        listing = client.get('/api/monitoring/alerts').get_json()
        assert listing['pagination']['total'] == 1 and listing['alerts'][0]['title'] == 'Device offline'
        assert client.post(f'/api/monitoring/alerts/{alert.id}/acknowledge', json={}, headers=_hdr(client)).status_code == 200
        assert client.get('/api/monitoring/alerts?status=acknowledged').get_json()['pagination']['total'] == 1
        assert client.post(f'/api/monitoring/alerts/{alert.id}/resolve', json={}, headers=_hdr(client)).status_code == 200
        assert client.get('/api/monitoring/alerts').get_json()['pagination']['total'] == 0
        assert client.delete(f'/api/monitoring/alerts/{alert.id}', headers=_hdr(client)).status_code == 200

    def test_bulk_alert_routes(self, client, device):
        ids = [Alert.query.first().id]
        assert client.post('/api/monitoring/alerts/bulk-acknowledge', json={'alert_ids': ids}, headers=_hdr(client)).status_code == 200
        assert client.post('/api/monitoring/alerts/bulk-resolve', json={'alert_ids': ids}, headers=_hdr(client)).status_code == 200
        assert client.post('/api/monitoring/alerts/acknowledge-all', json={}, headers=_hdr(client)).status_code == 200
        r = client.delete('/api/monitoring/alerts/bulk-delete', json={'resolved': True}, headers=_hdr(client))
        assert r.status_code == 200
        assert client.delete('/api/monitoring/alerts/delete-all', json={'confirm': True}, headers=_hdr(client)).status_code == 200

    def test_suppression_rules_crud(self, client, device):
        r = client.post('/api/monitoring/alerts/suppressions', json={'name': 'Night', 'enabled': True, 'daily_start_hour': 22, 'daily_end_hour': 6}, headers=_hdr(client))
        assert r.status_code in (200, 201), r.get_json()
        rules = client.get('/api/monitoring/alerts/suppressions').get_json()['suppressions']
        assert any(x['name'] == 'Night' for x in rules)
        rule_id = next(x['id'] for x in rules if x['name'] == 'Night')
        assert client.put(f'/api/monitoring/alerts/suppressions/{rule_id}', json={'enabled': False}, headers=_hdr(client)).status_code == 200
        assert client.delete(f'/api/monitoring/alerts/suppressions/{rule_id}', headers=_hdr(client)).status_code == 200

    def test_wan_status(self, client, app):
        body = client.get('/api/monitoring/wan?hours=6').get_json()
        assert body['hours'] == 6 and 'gateway' in body and 'internet' in body


class TestConfig:

    def test_read_routes(self, client, db_session):
        cfg = client.get('/api/config').get_json()
        assert 'runtime_config' in cfg and 'database_config' in cfg
        net = client.get('/api/config/network').get_json()
        assert {'network_range', 'ping_interval', 'scan_interval', 'wan_check_target'} <= set(net)
        alerts = client.get('/api/config/alerts').get_json()
        assert 'discord_webhook_url' in alerts
        assert 'history' in client.get('/api/config-management/history').get_json()

    def test_write_routes_validate_and_record_history(self, client, app, db_session):
        assert client.put('/api/config/dashboard_title', json={'value': 'Lab'}, headers=_hdr(client)).status_code == 200
        r = client.put('/api/config/network', json={'ping_interval': 900, 'wan_check_interval': 120}, headers=_hdr(client))
        assert r.status_code == 200, r.get_json()
        assert client.put('/api/config/network', json={'ping_interval': 1}, headers=_hdr(client)).status_code == 400
        assert client.put('/api/config/alerts', json={'discord_webhook_url': 'http://not-discord/x'}, headers=_hdr(client)).status_code == 400
        with app.app_context():
            assert Configuration.get_value('ping_interval') == '900'
        assert client.get('/api/config-management/history').get_json()['total'] >= 2

    def test_channel_tests_need_configuration(self, client, db_session):
        for channel in ('email', 'webhook', 'discord'):
            r = client.post(f'/api/config/test/{channel}', json={}, headers=_hdr(client))
            assert r.status_code == 400, channel


class TestSecurity:

    @pytest.mark.parametrize('path', ['/api/security/summary', '/api/security/alerts', '/api/security/network-overview',
                                      '/api/security/risk-assessment', '/api/security/scan-progress'])
    def test_read_routes(self, client, device, path):
        r = client.get(path)
        assert r.status_code == 200, (path, r.get_json())
        assert r.get_json().get('success', True) is True

    def test_device_ports(self, client, device):
        body = client.get(f'/api/security/device/{device.id}/ports?hours=720').get_json()
        assert body['device_id'] == device.id and 'open_ports' in body


class TestSystemAnalyticsPerformance:

    def test_system_info(self, client):
        body = client.get('/api/system/info').get_json()
        assert body['success'] and body['version']['version'].startswith('2.')

    def test_system_health_reports_threads(self, client):
        r = client.get('/api/system/health')
        assert r.status_code in (200, 503)      # 503 under TESTING: monitoring threads are not started
        assert 'threads' in r.get_json()

    @pytest.mark.parametrize('path,key', [
        ('/api/analytics/network-health-score', 'health_score'),
        ('/api/analytics/device-insights', 'most_reliable'),
        ('/api/analytics/usage-patterns', 'hourly_patterns'),
        ('/api/analytics/network-trends', 'trend_data'),
        ('/api/analytics/topology/visualization', 'visualization'),
    ])
    def test_analytics_routes(self, client, device, path, key):
        body = client.get(path).get_json()
        assert key in body, (path, sorted(body))

    def test_performance_routes(self, client, device):
        assert 'window' in client.get(f'/api/performance/device/{device.id}').get_json()
        assert 'timeline' in client.get(f'/api/performance/device/{device.id}/timeline?granularity=day').get_json()

    def test_notification_history_and_docs(self, client):
        assert 'notifications' in client.get('/api/notifications/history').get_json()
        assert client.get('/api/openapi.json').get_json()['openapi'].startswith('3.')
        assert client.get('/api/docs/').status_code == 200


class TestDeviceControl:

    def test_targets_must_be_private(self, client, device):
        for path in ('/api/device-control/traceroute', '/api/device-control/port-scan', '/api/device-control/discover-info'):
            assert client.post(path, json={'ip_address': '8.8.8.8'}, headers=_hdr(client)).status_code == 400, path

    def test_wake_on_lan_needs_a_mac(self, client, device):
        r = client.post('/api/device-control/wake-on-lan', json={}, headers=_hdr(client))
        assert r.status_code == 400


class TestCrossCutting:

    def test_unsafe_methods_require_csrf(self, client, device):
        assert client.post(f'/api/devices/{device.id}/ping', json={}).status_code == 403
        assert client.put('/api/config/dashboard_title', json={'value': 'x'}).status_code == 403
        assert client.delete(f'/api/devices/{device.id}').status_code == 403

    def test_api_errors_are_json(self, client):
        r = client.get('/api/devices/999999')
        assert r.status_code == 404 and r.is_json

    def test_strict_tier_limits_untrusted_clients(self, client, device):
        codes = [client.post(f'/api/devices/{device.id}/ping', json={}, headers=_hdr(client),
                             environ_base={'REMOTE_ADDR': '10.77.77.77'}).status_code for _ in range(12)]
        assert 429 in codes
