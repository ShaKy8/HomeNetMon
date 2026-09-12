"""services/tailscale.py: parse `tailscale status --json`, degrade quietly, feed the origin check."""

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from config import Config
from services import tailscale

# Trimmed copy of the real output shape (1.102.x).
STATUS = {
    'Version': '1.102.4-t3caf7d9e7-g084ee3b64',
    'BackendState': 'Running',
    'MagicDNSSuffix': 'tail52dabf.ts.net',
    'Self': {'HostName': 'geekom1', 'DNSName': 'geekom1.tail52dabf.ts.net.', 'OS': 'linux', 'Online': True,
             'TailscaleIPs': ['100.99.81.103', 'fd7a:115c:a1e0::d329:5168']},
    'Peer': {
        'nodekey:1': {'HostName': 'omarchy', 'DNSName': 'omarchy.tail52dabf.ts.net.', 'OS': 'linux', 'Online': False,
                      'LastSeen': '2026-09-10T02:11:00Z', 'TailscaleIPs': ['100.70.65.115'], 'Relay': 'ord',
                      'CurAddr': '', 'RxBytes': 10, 'TxBytes': 20, 'ExitNode': False},
        'nodekey:2': {'HostName': 'localhost', 'DNSName': 'ipad-pro.tail52dabf.ts.net.', 'OS': 'iOS', 'Online': True,
                      'LastSeen': '0001-01-01T00:00:00Z', 'TailscaleIPs': ['100.126.143.64'], 'Relay': 'ord',
                      'CurAddr': '192.168.86.57:41641', 'RxBytes': 0, 'TxBytes': 0, 'ExitNode': False},
    },
}


@pytest.fixture(autouse=True)
def fresh_cache():
    tailscale.reset_cache()
    yield
    tailscale.reset_cache()


def _run(stdout='', returncode=0, stderr=''):
    return Mock(stdout=stdout, returncode=returncode, stderr=stderr)


def test_summary_from_status_json():
    with patch('services.tailscale.subprocess.run', return_value=_run(json.dumps(STATUS))):
        s = tailscale.summary()
    assert s['installed'] and s['running'] and s['backend_state'] == 'Running'
    assert s['version'] == '1.102.4'
    assert s['self']['dns_name'] == 'geekom1.tail52dabf.ts.net'          # trailing dot stripped
    assert s['self']['url'] == f'http://geekom1.tail52dabf.ts.net:{Config.PORT}'
    assert (s['online_peers'], s['total_peers']) == (1, 2)
    online, offline = s['peers']                                          # online first
    assert online['hostname'] == 'ipad-pro'                                # iOS "localhost" -> MagicDNS label
    assert online['relay'] == 'direct' and online['last_seen'] is None
    assert offline['hostname'] == 'omarchy' and offline['relay'] == 'ord'
    assert offline['last_seen'] == '2026-09-10T02:11:00Z'


def test_url_prefers_base_url_when_it_names_this_node(monkeypatch):
    monkeypatch.setattr(Config, 'BASE_URL', 'https://geekom1.tail52dabf.ts.net')
    with patch('services.tailscale.subprocess.run', return_value=_run(json.dumps(STATUS))):
        assert tailscale.summary()['self']['url'] == 'https://geekom1.tail52dabf.ts.net'


def test_not_installed():
    with patch('services.tailscale.subprocess.run', side_effect=FileNotFoundError):
        s = tailscale.summary()
    assert s == {'installed': False, 'running': False, 'backend_state': None, 'error': 'not_installed',
                 'version': None, 'magic_dns_suffix': None, 'self': None, 'peers': [],
                 'online_peers': 0, 'total_peers': 0}
    assert tailscale.own_hostnames() == set()


def test_daemon_stopped():
    with patch('services.tailscale.subprocess.run',
               return_value=_run(returncode=1, stderr='failed to connect to local tailscaled; it doesn\'t appear to be running\n')):
        s = tailscale.summary()
    assert s['installed'] and not s['running']
    assert 'tailscaled' in s['error']


def test_timeout_and_bad_json_degrade():
    with patch('services.tailscale.subprocess.run', side_effect=subprocess.TimeoutExpired('tailscale', 3)):
        assert not tailscale.summary()['running']
    tailscale.reset_cache()
    with patch('services.tailscale.subprocess.run', return_value=_run('not json')):
        assert not tailscale.summary()['running']


def test_status_is_cached():
    with patch('services.tailscale.subprocess.run', return_value=_run(json.dumps(STATUS))) as run:
        tailscale.summary()
        tailscale.own_hostnames()
        assert run.call_count == 1
        tailscale.reset_cache()
        tailscale.summary()
        assert run.call_count == 2


def test_own_hostnames():
    with patch('services.tailscale.subprocess.run', return_value=_run(json.dumps(STATUS))):
        assert tailscale.own_hostnames() == {'geekom1.tail52dabf.ts.net'}


def test_api_endpoint(client):
    with patch('services.tailscale.subprocess.run', return_value=_run(json.dumps(STATUS))):
        r = client.get('/api/system/tailscale')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] and body['running']
    assert body['self']['url'].startswith('http://geekom1.tail52dabf.ts.net')
    assert [p['hostname'] for p in body['peers']] == ['ipad-pro', 'omarchy']
