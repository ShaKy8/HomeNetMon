"""core/host_policy.py: the Host header, Socket.IO origin and webhook-target rules (2.10.1)."""

from unittest.mock import patch

import pytest

from core import host_policy as hp

Config = hp.Config   # the class the policy reads, even after test_config_coherence reloads config


class TestHostHeader:

    @pytest.mark.parametrize('host', ['localhost:5000', '127.0.0.1:5000', '[::1]:5000', '192.168.86.42:5000', '192.168.86.42',
                                      '10.1.2.3', '172.16.0.9:80', '100.99.81.103:5000', 'geekom1:5000', 'geekom1.local', 'geekom1.lan:5000', 'nuc.home.arpa',
                                      'LOCALHOST', '169.254.1.1'])
    def test_own_names_are_accepted(self, host):
        assert hp.host_header_allowed(host), host

    @pytest.mark.parametrize('host', ['attacker.example.net:5000', 'evil.com', '8.8.8.8:5000', '1.1.1.1', 'a.b.c.d',
                                      'geekom1.tail52dabf.ts.net.evil.com', 'geekom1.lan.evil.com', 'x.y.lan', '', None])
    def test_other_names_are_refused(self, host):
        with patch('services.tailscale.own_hostnames', return_value=set()):
            assert not hp.host_header_allowed(host), host

    def test_tailscale_name_is_this_nodes_only(self):
        with patch('services.tailscale.own_hostnames', return_value={'geekom1.tail52dabf.ts.net'}):
            assert hp.host_header_allowed('geekom1.tail52dabf.ts.net:5000')
            assert hp.host_header_allowed('GEEKOM1.tail52dabf.ts.net')
            assert not hp.host_header_allowed('other.tail52dabf.ts.net:5000')

    def test_base_url_and_allowed_hosts_setting(self, monkeypatch):
        monkeypatch.setattr(Config, 'BASE_URL', 'https://netmon.example.org')
        monkeypatch.setattr(Config, 'ALLOWED_ORIGIN_HOSTS', ('proxy.example.org',))
        with patch('services.tailscale.own_hostnames', return_value=set()):
            assert hp.host_header_allowed('netmon.example.org') and hp.host_header_allowed('proxy.example.org:443')
            assert not hp.host_header_allowed('other.example.org')


class TestRequests:
    """End to end through the real middleware (the test client sends Host: localhost by default)."""

    def test_rebinding_host_is_rejected_before_anything_else(self, client):
        for path in ('/api/csrf-token', '/api/system/health', '/', '/api/devices'):
            r = client.get(path, headers={'Host': 'attacker.example.net:5000'})
            assert r.status_code == 400, path
            assert r.get_json() == {'error': 'Invalid host header'}

    def test_own_hosts_still_work(self, client):
        for host in ('localhost', '192.168.86.42:5000', '100.99.81.103:5000', 'geekom1.local:5000'):
            assert client.get('/api/csrf-token', headers={'Host': host}).status_code == 200, host

    def test_token_cannot_be_minted_under_a_foreign_host(self, client):
        r = client.post('/api/system/info', json={}, headers={'Host': 'attacker.example.net'})
        assert r.status_code == 400          # not 403/405: stopped at the Host check


class TestOutboundTargets:

    @pytest.mark.parametrize('url', ['http://127.0.0.1:11434/api', 'http://localhost:9200', 'http://[::1]/x',
                                     'http://169.254.169.254/latest/meta-data', 'http://0.0.0.0:80', 'ftp://192.168.1.5/x',
                                     'file:///etc/passwd', 'http:///nohost', 'not a url', ''])
    def test_dangerous_targets_are_refused(self, url):
        assert hp.outbound_url_problem(url), url

    @pytest.mark.parametrize('url', ['http://192.168.86.50:8123/api/webhook/abc', 'https://hooks.example.com/x',
                                     'http://homeassistant.local:8123/hook'])
    def test_lan_and_public_targets_are_allowed(self, url):
        fake = lambda host, port: [(2, 1, 6, '', ('192.168.86.50' if host.endswith('.local') else '93.184.216.34', 0))]   # noqa: E731
        assert hp.outbound_url_problem(url, resolve=fake) is None, url

    def test_a_name_that_resolves_to_loopback_is_refused(self):
        assert hp.outbound_url_problem('http://sneaky.example.com/x', resolve=lambda h, p: [(2, 1, 6, '', ('127.0.0.1', 0))])
        assert hp.outbound_url_problem('http://unresolvable.example.com/x', resolve=lambda h, p: (_ for _ in ()).throw(OSError()))

    def test_webhook_test_route_refuses_loopback_before_sending(self, client):
        token = client.get('/api/csrf-token').get_json()['csrf_token']
        with patch('requests.post') as post:
            r = client.post('/api/config/test/webhook', json={'webhook_url': 'http://127.0.0.1:11434/x'},
                            headers={'X-CSRF-Token': token})
        assert r.status_code == 400 and 'rejected' in r.get_json()['error']
        post.assert_not_called()

    def test_discord_test_route_only_accepts_discord(self, client):
        token = client.get('/api/csrf-token').get_json()['csrf_token']
        r = client.post('/api/config/test/discord', json={'discord_webhook_url': 'http://127.0.0.1:9200/x'},
                        headers={'X-CSRF-Token': token})
        assert r.status_code == 400

    def test_saved_webhook_setting_applies_the_same_rule(self, app):
        assert app.configuration_service._validate_webhook_url('http://127.0.0.1:11434/x') is False


class TestFrontendAndDocs:

    def test_scan_error_text_is_escaped(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2] / 'static/js/security-page.js').read_text()
        assert '${errorMessage}' not in src.replace('escapeHtml(errorMessage)', '') or 'escapeHtml(errorMessage)' in src
        assert '>${escapeHtml(errorMessage)}<' in src

    def test_redoc_script_has_an_integrity_hash(self, client):
        html = client.get('/api/redoc').get_data(as_text=True)
        assert 'redoc.standalone.js' in html and 'integrity="sha384-' in html and 'crossorigin="anonymous"' in html
