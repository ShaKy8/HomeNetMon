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
