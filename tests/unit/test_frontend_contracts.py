"""
Frontend <-> backend contracts fixed in Phase 6: pages render, the settings
page targets real endpoints, the dashboard JS uses the API's field names,
live updates subscribe to a room, and the base template no longer clobbers
page toast helpers.
"""

import re
from datetime import datetime
from pathlib import Path

import pytest

from models import Device

ROOT = Path(__file__).resolve().parents[2]


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.80', mac_address='00:ab:00:00:00:01', hostname='page-test',
               device_type='computer', is_monitored=True, last_seen=datetime.utcnow())
    db_session.add(d)
    db_session.commit()
    return d


class TestPagesRender:

    @pytest.mark.parametrize('path', ['/', '/settings', '/alerts', '/analytics', '/network-map', '/security'])
    def test_page_renders(self, client, path):
        r = client.get(path)
        assert r.status_code == 200, path
        html = r.get_data(as_text=True)
        assert 'js/ui-feedback.js' in html
        assert "window.showError = function" not in html   # the console-only stub is gone

    def test_device_page_renders(self, client, device):
        r = client.get(f'/device/{device.id}')
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert 'edit-device-priority' in html and 'edit-device-description' not in html
        assert 'data.device || data' in html                 # envelope is unwrapped
        assert '/history.csv' in html and '/export' not in html.split('history.csv')[1][:400]

    def test_nav_has_no_retired_pages(self, client):
        html = client.get('/').get_data(as_text=True)
        assert 'AI Dashboard' not in html and 'Full View' not in html


class TestDashboardJs:

    def test_uses_api_field_names(self):
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert 'monitor_enabled' not in js and 'has_alerts' not in js
        assert 'is_monitored' in js and 'active_alerts' in js
        assert "/api/devices/ping-all" in js and 'ping_all' not in js

    def test_subscribes_to_live_update_room(self):
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert "socket.emit('subscribe_to_updates'" in js
        assert "socket.on('device_status_update'" in js
        assert "socket.on('device_update'" not in js

    def test_lan_controlled_strings_are_escaped(self):
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert '${esc(name)}' in js and '${esc(device.ip_address)}' in js


class TestSettingsPage:

    def test_settings_page_targets_real_endpoints(self, client):
        html = client.get('/settings').get_data(as_text=True)
        for url in ("/api/config/network", "/api/config/alerts", "/api/config/restart-system",
                    "/api/config/reset-monitoring-data", "/api/config/test/"):
            assert url in html, url
        assert "fetch('/api/config', {" not in html          # the old POST to a GET-only route
        assert "/api/system/restart" not in html and "/api/system/clear-data" not in html

    def test_network_save_roundtrip_with_documented_defaults(self, client):
        r = client.put('/api/config/network', json={'network_range': '192.168.1.0/24', 'ping_interval': 600,
                                                     'scan_interval': 86400},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        cfg = client.get('/api/config').get_json()['database_config']
        assert cfg['ping_interval']['value'] == '600' and cfg['scan_interval']['value'] == '86400'

    def test_alert_save_roundtrip_including_discord(self, client):
        body = {'device_down_threshold': 20, 'high_latency_threshold': 2500, 'push_enabled': True,
                'ntfy_server': 'https://ntfy.sh', 'ntfy_topic': 'hnm-test', 'email_enabled': False,
                'email_from': 'a@b.c', 'email_to': 'x@y.z', 'webhook_enabled': False, 'webhook_url': '',
                'discord_enabled': True, 'discord_webhook_url': 'https://discord.com/api/webhooks/1/x'}
        r = client.put('/api/config/alerts', json=body, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        a = client.get('/api/config/alerts').get_json()
        assert a['device_down_threshold'] == 20 and a['high_latency_threshold'] == 2500
        assert a['discord_enabled'] is True and a['discord_webhook_url'].endswith('/1/x')
        assert a['ntfy_topic'] == 'hnm-test'


class TestDeviceEditContract:

    def test_edit_payload_is_accepted(self, client, device):
        body = {'custom_name': 'Office PC', 'device_type': 'computer', 'device_priority': 'important',
                'device_group': 'Office', 'room_location': 'Upstairs', 'is_monitored': False}
        r = client.put(f'/api/devices/{device.id}', json=body, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        d = client.get(f'/api/devices/{device.id}').get_json()['device']
        assert d['custom_name'] == 'Office PC' and d['device_priority'] == 'important'
        assert d['is_monitored'] is False and d['display_name'] == 'Office PC'
        assert 'statistics' in d and '24h' in d['statistics'] and 'monitoring_history' in d


class TestRetiredPagesAndConsolidation:

    @pytest.mark.parametrize('path,target', [('/full-view', '/'), ('/noc', '/'), ('/dashboard/full', '/'),
                                             ('/performance-dashboard', '/analytics#performance'),
                                             ('/ai-dashboard', '/analytics'), ('/ai_dashboard', '/analytics')])
    def test_retired_pages_redirect_permanently(self, client, path, target):
        r = client.get(path)
        assert r.status_code == 301
        assert r.headers['Location'].endswith(target)

    def test_analytics_has_no_anomaly_or_speedtest_remnants(self, client):
        html = client.get('/analytics').get_data(as_text=True)
        assert 'anomalies-tab' not in html and '/api/anomaly/' not in html
        assert '/api/speedtest/' not in html and 'speedtest-btn' not in html

    def test_network_map_uses_topology_engine(self, client):
        html = client.get('/network-map').get_data(as_text=True)
        assert '/api/analytics/topology/visualization' in html and 'topology-test' not in html
        assert 'data.visualization || data' in html   # payload is wrapped under `visualization`
        assert html.count('cdn.jsdelivr.net/npm/d3@7') == 1

    def test_manifest_is_a_web_app_manifest(self, client):
        m = client.get('/static/manifest.json').get_json()
        assert m['name'] == 'HomeNetMon' and m['start_url'] == '/' and m['icons']

    def test_service_worker_route_is_gone(self, client):
        assert client.get('/static/service-worker.js').status_code == 404


class TestSerializerContract:

    def test_to_dict_and_to_dict_fast_share_the_core_keys(self, app, db_session, device):
        with app.app_context():
            full = Device.query.get(device.id).to_dict()
            fast = Device.query.get(device.id).to_dict_fast()
        core = {'id', 'ip_address', 'mac_address', 'hostname', 'display_name', 'is_monitored', 'status',
                'active_alerts', 'latest_response_time', 'latest_check', 'last_seen', 'device_type', 'device_group'}
        assert core <= set(full) and core <= set(fast)
        assert 'current_bandwidth' not in full and 'bandwidth_usage_24h' not in full   # unmeasurable per device
        assert 'uptime_percentage' not in full                                          # 7-day walk; detail endpoint only

    def test_detail_endpoint_adds_uptime(self, client, device):
        d = client.get(f'/api/devices/{device.id}').get_json()['device']
        assert 'uptime_percentage' in d and 'statistics' in d and 'health_score' in d


class TestEndpointsFixedBySweep:

    def test_performance_devices_no_longer_selects_properties(self, client, device):
        r = client.get('/api/performance/devices?hours=24')
        assert r.status_code == 200, r.get_json()
        assert 'devices' in r.get_json()

    def test_topology_engine_has_an_app_context_without_an_attached_app(self, app):
        from services.network_topology import NetworkTopologyEngine
        engine = NetworkTopologyEngine()
        with app.test_request_context('/'):
            with engine._app_context():
                pass  # must not raise 'NoneType has no app_context'


class TestLiveRegressions:

    def test_device_list_tolerates_devices_without_an_ip(self, client, db_session, device):
        """A stale device whose address was reassigned has ip_address NULL; the list must still sort."""
        ghost = Device(ip_address=None, mac_address='00:ab:00:00:00:99', hostname='ghost', device_type='unknown',
                       is_monitored=False, last_seen=datetime(2026, 1, 1))
        db_session.add(ghost)
        db_session.commit()
        from services.query_cache import invalidate_device_cache
        invalidate_device_cache()
        r = client.get('/api/devices')
        assert r.status_code == 200, r.get_json()
        ips = [d['ip_address'] for d in r.get_json()['devices']]
        assert None in ips and ips[-1] is None

    def test_topology_engine_constructor_is_complete(self):
        from services.network_topology import NetworkTopologyEngine
        engine = NetworkTopologyEngine()
        assert hasattr(engine, 'discovery_lock') and hasattr(engine, 'discovery_methods')


class TestPhase1Fixes:

    def test_device_page_defines_its_chart_initialiser(self):
        html = (ROOT / 'templates/device_detail.html').read_text()
        assert 'function initializeCharts()' in html
        assert html.index('initializeCharts();') < html.index('loadDeviceData();')

    def test_analytics_page_has_no_toast_stub(self):
        html = (ROOT / 'templates/analytics.html').read_text()
        assert 'Toast (${type})' not in html
        assert 'GlobalFilters' not in html

    def test_dashboard_bulk_ops_use_bulk_update(self):
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert '/api/devices/bulk-update' in js
        assert 'event.stopPropagation();' not in js      # implicit global event broke bulk loops
        assert '192.168.86.1' not in js

    @pytest.mark.parametrize('path,needle', [
        ('static/js/security-page.js', '${escapeHtml(device.name)}'),
        ('static/js/security-page.js', "${escapeHtml(alert.message.replace('[SECURITY] ', ''))}"),
        ('templates/topology.html', '${escapeHtml(node.vendor'),
        ('templates/analytics.html', '${escapeHtml(device.device_name)}'),
    ])
    def test_lan_strings_are_escaped_on_kept_pages(self, path, needle):
        assert needle in (ROOT / path).read_text()

    def test_dashboard_hero_reads_shared_summary(self):
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert "fetch('/api/monitoring/summary')" in js


class TestPhase6Cleanup:

    def test_one_toast_and_debounce_implementation(self):
        clones = []
        for path in ROOT.glob('static/js/*.js'):
            if path.name == 'ui-feedback.js':
                continue
            js = path.read_text()
            if 'function debounce(' in js or 'toastContainer.appendChild' in js:
                clones.append(path.name)
        assert clones == []
        assert 'window.debounce = debounce' in (ROOT / 'static/js/ui-feedback.js').read_text()

    def test_no_page_script_hand_rolls_csrf(self):
        for path in ROOT.glob('static/js/*.js'):
            if path.name == 'csrf-handler.js':
                continue
            assert 'csrf_token=' not in path.read_text(), path.name

    @pytest.mark.parametrize('path', ['templates/dashboard.html', 'templates/security.html'])
    def test_page_scripts_carry_cache_buster(self, path):
        html = (ROOT / path).read_text()
        for line in html.splitlines():
            if "url_for('static', filename='js/" in line:
                assert 'app_version' in line, line

    def test_cdn_assets_are_pinned(self):
        assert 'chart.js@4.4.1' in (ROOT / 'templates/base_beautiful.html').read_text()
        assert 'd3@7.9.0' in (ROOT / 'templates/topology.html').read_text()

    def test_no_stale_version_strings(self, client):
        for path in ('/about', '/settings'):
            html = client.get(path).get_data(as_text=True)
            assert 'v2.0.0' not in html and 'v2.0<' not in html and 'your-repo' not in html, path
            assert 'v2.' in html

    def test_topology_dead_controls_are_gone(self, client):
        html = client.get('/network-map').get_data(as_text=True)
        assert 'ping-by-type' not in html and 'ping-export-results' not in html
        assert 'High Traffic' not in html and 'Gateway dependency' in html

    def test_security_settings_persist_through_config_api(self, client, app, db_session):
        from models import Configuration
        token = _token(client)
        for key, value in (('security_scan_interval_hours', '12'), ('security_top_ports', '200'),
                           ('security_service_detection', 'false')):
            r = client.put(f'/api/config/{key}', json={'value': value}, headers={'X-CSRF-Token': token})
            assert r.status_code == 200, (key, r.get_json())
        with app.app_context():
            assert Configuration.get_value('security_scan_interval_hours') == '12'
        r = client.put('/api/config/security_top_ports', json={'value': '5'}, headers={'X-CSRF-Token': token})
        assert r.status_code == 400

    def test_acknowledge_all_accepts_a_type_prefix(self, client, db_session, device):
        from models import Alert, db
        db.session.add_all([Alert(device_id=device.id, alert_type='security_new_service', severity='low', message='a'),
                            Alert(device_id=device.id, alert_type='device_down', severity='warning', message='b')])
        db.session.commit()
        r = client.post('/api/monitoring/alerts/acknowledge-all', json={'alert_type_prefix': 'security_'},
                        headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200 and r.get_json()['count'] == 1
        assert Alert.query.filter_by(alert_type='device_down').first().acknowledged is False


class TestAlertsPage:

    def test_offers_every_severity_and_status(self, client):
        html = client.get('/alerts').get_data(as_text=True)
        for sev in ('critical', 'high', 'warning', 'medium', 'low', 'info'):
            assert f'<option value="{sev}">' in html, sev
        for status in ('active', 'unacknowledged', 'acknowledged', 'resolved', 'all'):
            assert f'value="{status}"' in html, status
        assert '.alert-card.warning' in html and '.status-badge.info' in html

    def test_has_acknowledge_controls_and_pager(self, client):
        html = client.get('/alerts').get_data(as_text=True)
        assert 'alertsManager.acknowledge(' in html and 'acknowledgeAllFiltered' in html
        assert 'id="alerts-pager"' in html and '/api/notifications/history' in html

    def test_uses_shared_helpers_only(self, client):
        html = client.get('/alerts').get_data(as_text=True)
        assert 'this.showToast' not in html and 'this.escapeHtml' not in html
        assert 'X-CSRFToken' not in html

    def test_navbar_badge_uses_server_side_status_filter(self, client):
        html = client.get('/').get_data(as_text=True)
        assert '/api/monitoring/alerts?status=active&hours=0&per_page=1' in html
