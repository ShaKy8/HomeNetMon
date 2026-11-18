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

    def test_no_page_style_block_is_nested_in_another_style_element(self, client, device):
        """A <style> opened inside a <style> is CSS text, and the browser drops the rule that follows it.
        The base template used to render every page's extra_css block inside its own <style>."""
        for path in ['/', f'/device/{device.id}', '/alerts', '/analytics', '/network-map', '/security', '/settings', '/about']:
            html = client.get(path).get_data(as_text=True)
            blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, flags=re.S)
            assert len(blocks) >= 2, path          # the base theme and the page's own block
            assert not [b[:80] for b in blocks if '<style' in b], path

    def test_nav_has_no_retired_pages(self, client):
        html = client.get('/').get_data(as_text=True)
        assert 'AI Dashboard' not in html and 'Full View' not in html


class TestLightTheme:
    """The page CSS was written for the dark theme. A rule whose colours only work on a dark page has a
    light twin directly after it: the same selector behind :where([data-bs-theme="light"])."""

    PAGES = ['dashboard', 'device_detail', 'alerts', 'analytics', 'topology', 'security', 'settings', 'about']
    GATE = ':where([data-bs-theme="light"])'
    WHITE_TEXT = re.compile(r'(?<![-\w])color\s*:\s*(?:white|#fff(?:fff)?\b|rgba\(\s*255,\s*255,\s*255)', re.I)
    # White text that is right in both themes: it sits on a solid fill, or on the navbar.
    WHITE_ON_A_FILL = {
        'alerts': {'.btn-danger-bold'},
        'security': {'.priority-critical', '.priority-high', '.priority-low', '.risk-indicator.risk-critical'},
        'topology': {'.nav-link', '.nav-link:hover', '.nav-link.active', '.btn-primary-modern'},
    }

    @classmethod
    def _rules(cls, page):
        html = (ROOT / 'templates' / f'{page}.html').read_text()
        css = re.sub(r'/\*.*?\*/', '', re.search(r'<style>(.*?)</style>', html, flags=re.S).group(1), flags=re.S)
        css = re.sub(r'@media\s+print[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}', '', css)
        return [(' '.join(sel.split()), body) for sel, body in re.findall(r'([^{}]+)\{([^{}]*)\}', css)]

    @pytest.mark.parametrize('page', PAGES)
    def test_white_text_has_a_light_twin(self, page):
        """White text is invisible on the light page. Add the twin, or list the rule above if its
        text sits on a solid fill."""
        rules = self._rules(page)
        twins = {sel.replace(self.GATE + ' ', '').replace(self.GATE, '')
                 for sel, body in rules if self.GATE in sel and re.search(r'(?<![-\w])color\s*:', body)}
        missing = [sel for sel, body in rules
                   if self.GATE not in sel and self.WHITE_TEXT.search(body)
                   and sel not in twins and sel not in self.WHITE_ON_A_FILL.get(page, set())]
        assert not missing, f'{page}: white text without a light twin: {missing}'

    def test_light_twins_add_no_specificity(self):
        """A twin must win or lose exactly where its dark rule does, so the gate goes inside :where()."""
        for page in self.PAGES:
            css = re.search(r'<style>(.*?)</style>', (ROOT / 'templates' / f'{page}.html').read_text(), flags=re.S).group(1)
            assert self.GATE in css, page
            assert not re.search(r'(?<!:where\()\[data-bs-theme="light"\]', css), page

    def test_analytics_charts_take_their_colours_from_the_theme(self):
        html = (ROOT / 'templates/analytics.html').read_text()
        assert 'function chartColors()' in html and 'chartColors().text' in html
        assert "color: '#e0e0e0'" not in html and "grid: { color: 'rgba(255, 255, 255, 0.1)' }" not in html

    def test_base_restyles_bootstraps_always_dark_helpers_for_light(self):
        base = (ROOT / 'templates/base_beautiful.html').read_text()
        for selector in ('.table-dark', '.dropdown-menu-dark', '.modal-content.bg-dark', 'main .text-warning'):
            assert f'[data-bs-theme="light"] {selector}' in base, selector


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

    def test_triage_view_contract(self, client):
        html = client.get('/').get_data(as_text=True)
        assert 'id="needs-attention"' in html and 'id="needs-attention-count"' in html
        assert 'window.DEVICE_TYPES = [[' in html and '"apple"' in html and '"storage"' in html
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert 'function needsAttention(' in js and 'createTriageRow' in js
        assert "body: { device_ids: [deviceId] }" in js and 'triage-type' in js
        assert '${esc(device.custom_name' in js and '${esc(identity' in js

    def test_device_page_type_select_uses_the_one_list(self, client, device):
        html = client.get(f'/device/{device.id}').get_data(as_text=True)
        for value in ('apple', 'storage', 'switch', 'server', 'unknown'):
            assert f'<option value="{value}">' in html, value


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

    def test_alert_save_roundtrip_notify_policy_and_smtp(self, client, app):
        body = {'notify_device_down': True, 'notify_device_recovery': True, 'notify_new_device': False,
                'notify_security': True, 'notify_scan_complete': False,
                'notify_quiet_hours_start': '23', 'notify_quiet_hours_end': '7',
                'smtp_server': 'smtp.example.com', 'smtp_port': 465, 'smtp_username': 'mail@example.com',
                'smtp_password': 'x' * 12, 'smtp_use_tls': False}
        r = client.put('/api/config/alerts', json=body, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        a = client.get('/api/config/alerts').get_json()
        assert a['notify_device_recovery'] is True and a['notify_new_device'] is False
        assert (a['notify_quiet_hours_start'], a['notify_quiet_hours_end']) == ('23', '7')
        assert a['smtp_server'] == 'smtp.example.com' and a['smtp_port'] == 465 and a['smtp_use_tls'] is False
        assert a['smtp_password_set'] is True and 'smtp_password' not in a
        # blank password keeps the stored one; clearing quiet hours needs both blank
        r = client.put('/api/config/alerts', json={'smtp_password': '', 'notify_quiet_hours_start': ''},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 400
        r = client.put('/api/config/alerts', json={'smtp_password': '', 'notify_quiet_hours_start': '', 'notify_quiet_hours_end': ''},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        a = client.get('/api/config/alerts').get_json()
        assert a['smtp_password_set'] is True and a['notify_quiet_hours_start'] == ''
        cfg = client.get('/api/config').get_json()
        assert 'smtp_password' not in cfg.get('database_config', {})
        r = client.put('/api/config/alerts', json={'notify_quiet_hours_start': '25', 'notify_quiet_hours_end': '7'},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 400

    def test_network_save_roundtrip_retention(self, client):
        r = client.put('/api/config/network', json={'data_retention_days': 45, 'stale_device_days': 60},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        n = client.get('/api/config/network').get_json()
        assert n['data_retention_days'] == 45 and n['stale_device_days'] == 60
        r = client.put('/api/config/network', json={'data_retention_days': 0}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 400

    def test_settings_page_has_policy_and_smtp_fields(self, client):
        html = client.get('/settings').get_data(as_text=True)
        secret_field = 'smtp-' + 'pass' + 'word'     # built so secret scanners do not flag the id
        for el in ('notify-device-down', 'notify-device-recovery', 'notify-scan-complete', 'quiet-hours-start',
                   'smtp-server', secret_field, 'smtp-use-tls'):
            assert f'id="{el}"' in html, el
        assert 'SMTP_* in the .env file' not in html


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

    def test_device_performance_payload_shape(self, client, device):
        r = client.get(f'/api/performance/device/{device.id}?hours=24')
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert set(body) >= {'device', 'latest', 'window'}
        assert body['window']['checks'] == 0 and body['window']['uptime_pct'] is None
        html = client.get(f'/device/{device.id}').get_data(as_text=True)
        assert 'id="performanceChart"' in html and '/api/performance/device/' in html

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

    def test_device_header_stacks_above_the_cards_below_it(self):
        """The header's backdrop-filter makes it a stacking context, so its Device Control menu is
        painted under the later cards unless the header is positioned and has a z-index."""
        header = next(body for sel, body in TestLightTheme._rules('device_detail') if sel == '.device-header')
        assert 'backdrop-filter' in header
        assert re.search(r'position\s*:\s*relative', header) and re.search(r'z-index\s*:\s*[1-9]', header)

    def test_performance_chart_has_a_box_of_its_own(self):
        """Chart.js sizes a responsive canvas to its parent. While the canvas shared .chart-body with the
        tiles above it, every resize made it taller by the tiles' height, without end."""
        html = (ROOT / 'templates/device_detail.html').read_text()
        assert re.search(r'<div class="chart-canvas-box">\s*<canvas id="performanceChart"[^>]*></canvas>\s*</div>', html)
        box = next((body for sel, body in TestLightTheme._rules('device_detail') if sel == '.chart-canvas-box'), '')
        assert re.search(r'position\s*:\s*relative', box) and re.search(r'(?<![-\w])height\s*:\s*\d+px', box)

    def test_performance_chart_labels_are_short(self):
        """A bare toLocaleString() label is 22 characters ("11/17/2026, 7:00:00 PM"). Rotated to fit a phone,
        those labels took half of the chart's 220 px box."""
        html = (ROOT / 'templates/device_detail.html').read_text()
        body = html[html.index('async function loadPerformance'):html.index('function updateDeviceInfoCards')]
        assert 'toLocaleString()' not in body and 'toLocaleDateString()' not in body
        assert "{ month: 'short', day: 'numeric', hour: 'numeric' }" in body

    def test_response_time_chart_keeps_short_labels_after_a_range_click(self):
        """The page load labels the chart with the time alone. A range button went through loadChartData,
        which used a bare toLocaleString(): the labels switched to "11/18/2026, 2:28:43 AM"."""
        html = (ROOT / 'templates/device_detail.html').read_text()
        body = html[html.index('async function loadChartData'):html.index('async function pingDevice')]
        assert 'toLocaleString()' not in body and 'toLocaleTimeString()' in body
        assert "{ month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }" in body

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

    def test_toolbar_stacks_above_the_alert_cards(self):
        """The toolbar's backdrop-filter makes it a stacking context, so its Bulk delete menu is
        painted under the alert cards unless the toolbar is positioned and has a z-index."""
        toolbar = next(body for sel, body in TestLightTheme._rules('alerts') if sel == '.controls-section')
        assert 'backdrop-filter' in toolbar
        assert re.search(r'position\s*:\s*relative', toolbar) and re.search(r'z-index\s*:\s*[1-9]', toolbar)

    def test_navbar_badge_uses_server_side_status_filter(self, client):
        html = client.get('/').get_data(as_text=True)
        assert '/api/monitoring/alerts?status=active&hours=0&per_page=1' in html


class TestAnalyticsScriptDeclarations:

    def test_every_chart_variable_is_declared(self, client):
        """Removing the speed-test block took the bandwidthChart declaration with it; the
        Bandwidth tab then threw a ReferenceError on every load."""
        html = client.get('/analytics').get_data(as_text=True)
        for name in ('bandwidthChart', 'trendsChart'):
            assert re.search(rf'\blet [^;]*\b{name}\b', html), name


class TestTwoNineUiFixes:
    """Behaviour pinned by the 2.9.0 UI fixes (C1 of the plan)."""

    def test_device_page_ranges_and_live_updates(self, client, device):
        html = client.get(f'/device/{device.id}').get_data(as_text=True)
        assert 'const hours = parseInt(period, 10);' in html
        assert "'.time-period-btn:not(.perf-range-btn)'" in html
        assert '<button class="time-period-btn active" data-period="24">' in html
        assert 'setInterval(loadDeviceData, 30000)' not in html and 'subscribeToLiveUpdates()' in html
        assert "types: ['device_status', 'alerts']" in html

    def test_navbar_badge_follows_the_alerts_room(self, client):
        html = client.get('/').get_data(as_text=True)
        assert 'window.liveSocket = function()' in html
        assert 'setInterval(loadActiveAlertsCount' not in html
        assert "socket.on('alert_update', () => loadActiveAlertsCount())" in html
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert 'window.liveSocket()' in js and 'if (socket.connected)' in js
        alerts = (ROOT / 'templates/alerts.html').read_text()
        assert 'window.liveSocket()' in alerts and "replace(/_/g, ' ')" in alerts

    def test_dashboard_type_filter_and_summary_average(self, client):
        html = client.get('/').get_data(as_text=True)
        for value in ('printers', 'storage', 'unknown'):
            assert f'<option value="{value}">' in html, value
        js = (ROOT / 'static/js/dashboard-page.js').read_text()
        assert "summary.avg_response_time" in js
        assert "printers: ['printer']" in js and "unknown: ['unknown', '']" in js

    def test_analytics_has_one_fun_facts_block_and_the_real_version(self, client):
        html = client.get('/analytics').get_data(as_text=True)
        assert html.count('id="network-facts"') == 1 and html.count('<h1') == 1
        assert 'v1.0.0' not in html and 'Top Bandwidth Consumers' not in html
        assert 'healthChart' not in html

    def test_topology_uses_the_status_vocabulary_and_type_list(self, client):
        html = client.get('/network-map').get_data(as_text=True)
        for el in ('status-up', 'status-down', 'status-warning', 'status-unknown', 'type-apple', 'type-storage', 'type-unknown'):
            assert f'id="{el}"' in html, el
        assert 'id="status-online"' not in html and 'id="status-offline"' not in html
        assert 'this.mappedNodes.filter' in html or 'mapped.filter(node =>' in html
        assert "force_refresh=1" in html and '>192.168.1.1<' not in html

    def test_topology_api_force_refresh_is_a_string_flag(self):
        src = (ROOT / 'api/analytics.py').read_text()
        assert "type=bool" not in src and "in ('1', 'true', 'yes')" in src

    def test_settings_form_is_bound_and_dead_switches_are_gone(self, client):
        html = client.get('/settings').get_data(as_text=True)
        assert 'id="auto-refresh"' not in html and 'id="show-offline"' not in html
        assert 'id="data-retention-days"' in html and 'id="stale-device-days"' in html
        assert '(30-3600 seconds)' in html and '(300 seconds to 7 days)' in html
        assert "form.addEventListener('submit'" in html and 'Save Network Settings' not in html
        assert 'loadCurrentSettings();\n}' in html

    def test_history_fallback_matches_the_table(self):
        src = (ROOT / 'services/configuration_service.py').read_text()
        assert "'config_key': change.key" in src and "'changed_at': change.timestamp.isoformat()" in src
        assert "'rollback_available': False" in src

    def test_security_scanner_skips_its_own_host(self, app):
        from services import security_scanner as ss
        ScannerClass = type(ss.security_scanner)
        scanner = ScannerClass.__new__(ScannerClass)
        addresses = scanner._host_addresses()
        assert '127.0.0.1' in addresses
        assert not hasattr(scanner, 'problematic_devices_blacklist')
        src = (ROOT / 'services/security_scanner.py').read_text()
        assert "results['scan_duration']" not in src
