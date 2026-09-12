"""
Request pipeline after Phase 4: stateless header-only CSRF, no request WAF,
HTML errors for pages / JSON for the API, one cache/security header policy,
threading-mode Socket.IO, dead debug routes gone.
"""

import time
from unittest.mock import patch

import pytest


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


class TestCsrf:
    """POSTing to a GET-only route is a side-effect-free probe: 403 means CSRF
    rejected the request, 405 means CSRF passed and routing rejected the method."""

    def test_post_without_token_is_rejected(self, client):
        assert client.post('/api/system/info', json={}).status_code == 403

    def test_cookie_alone_is_not_a_token(self, client):
        client.get('/')  # sets the csrf_token cookie the browser would replay
        assert client.post('/api/system/info', json={}).status_code == 403

    def test_header_token_is_accepted(self, client):
        r = client.post('/api/system/info', json={}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 405

    def test_form_field_token_is_accepted(self, client):
        r = client.post('/api/system/info', data={'csrf_token': _token(client)})
        assert r.status_code == 405

    def test_tampered_and_garbage_tokens_are_rejected(self, client):
        good = _token(client)
        nonce, ts, sig = good.split('.')
        for bad in (f"{nonce}.{ts}.{sig[:-1]}x", f"{nonce}.{int(ts) + 5}.{sig}", 'nonsense', '', 'a.b.c'):
            assert client.post('/api/system/info', json={}, headers={'X-CSRF-Token': bad}).status_code == 403, bad

    def test_expired_token_is_rejected(self, app, client):
        mw = app.security_middleware
        nonce, issued = 'abc', int(time.time()) - mw.csrf_token_lifetime - 5
        old = f"{nonce}.{issued}.{mw._sign(nonce, issued)}"
        assert client.post('/api/system/info', json={}, headers={'X-CSRF-Token': old}).status_code == 403

    def test_token_survives_restart_because_it_is_stateless(self, app, client):
        """A token minted by one middleware instance validates on another with the same SECRET_KEY."""
        from core.security_middleware import SecurityMiddleware
        token = _token(client)
        other = SecurityMiddleware()
        other.app = app
        assert other._token_is_valid(token)

    def test_template_token_matches_verifier(self, app, client):
        html = client.get('/').get_data(as_text=True)
        start = html.index('name="csrf-token" content="') + len('name="csrf-token" content="')
        token = html[start:html.index('"', start)]
        assert client.post('/api/system/info', json={}, headers={'X-CSRF-Token': token}).status_code == 405


class TestNoRequestWaf:

    def test_legitimate_punctuation_is_not_rejected(self, client):
        for q in ["Kyle's PC (office)", 'my-device--1', 'Tom & Jerry TV', '#0f0f23', 'update firmware', "select model"]:
            r = client.get('/api/devices', query_string={'search': q})
            assert r.status_code != 400, q

    def test_json_body_with_sql_words_is_not_rejected(self, client):
        r = client.put('/api/config/dashboard_title', json={'value': 'Create Update Delete (HQ) -- #1'},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code != 400


class TestErrorsAndHeaders:

    def test_page_404_is_html(self, client):
        r = client.get('/no-such-page', headers={'Accept': 'text/html'})
        assert r.status_code == 404 and r.content_type.startswith('text/html')
        assert 'Back to the dashboard' in r.get_data(as_text=True)

    def test_api_404_is_json(self, client):
        r = client.get('/api/no-such-endpoint', headers={'Accept': 'text/html'})
        assert r.status_code == 404 and r.is_json

    def test_security_and_cache_headers(self, client):
        r = client.get('/')
        assert r.headers['X-Frame-Options'] == 'DENY'          # PerformanceMiddleware used to downgrade to SAMEORIGIN
        assert r.headers.get('Last-Modified', 'absent') != ''  # no empty header
        assert r.headers.get('ETag', 'absent') != ''
        assert r.headers['Cache-Control'] == 'no-cache'
        api = client.get('/api/system/info')
        assert api.headers['Cache-Control'] == 'no-store'

    def test_debug_routes_are_gone(self, client):
        for path in ('/debug/routes', '/test', '/test-debug', '/simple-test', '/traceroute-test'):
            assert client.get(path).status_code == 404, path


class TestSocketIo:

    def test_threading_mode(self, app):
        assert app.socketio.async_mode == 'threading'

    def test_dead_request_handlers_removed(self, app):
        handlers = app.socketio.server.handlers.get('/', {})
        assert 'update_configuration' not in handlers
        assert 'trigger_performance_collection' not in handlers
        assert not any(name.startswith('request_') for name in handlers)
        assert 'subscribe_to_updates' in handlers


class TestSocketIoOrigins:

    def test_private_origins_accepted_public_refused(self, app):
        cb = app.socketio.server.eio.cors_allowed_origins
        for ok in ('http://192.168.86.42:5000', 'http://192.168.192.168:5000', 'http://10.8.0.2:5000',
                   'http://172.16.5.9:5000', 'http://localhost:5000', 'http://homenetmon.local:5000'):
            assert cb(ok), ok
        for bad in ('http://8.8.8.8:5000', 'https://evil.example.com', 'ftp://192.168.1.1', ''):
            assert not cb(bad), bad

    def test_tailscale_origins(self, app):
        cb = app.socketio.server.eio.cors_allowed_origins
        assert cb('http://100.99.81.103:5000')      # CGNAT literal, whatever CPython says about is_private
        assert cb('http://[fd7a:115c:a1e0::d329:5168]:5000')
        with patch('services.tailscale.own_hostnames', return_value={'geekom1.tail52dabf.ts.net'}):
            assert cb('http://geekom1.tail52dabf.ts.net:5000')
            assert cb('https://GEEKOM1.tail52dabf.ts.net')
            assert not cb('http://other.tail52dabf.ts.net:5000')   # only this node's own name
            assert not cb('https://evil.ts.net')
        with patch('services.tailscale.own_hostnames', return_value=set()):
            assert not cb('http://geekom1.tail52dabf.ts.net:5000')

    def test_allowed_origin_hosts_setting(self, app, monkeypatch):
        import app as app_module   # the Config class the callback reads (test_config_coherence reloads config)
        cb = app.socketio.server.eio.cors_allowed_origins
        monkeypatch.setattr(app_module.Config, 'ALLOWED_ORIGIN_HOSTS', ('netmon.example.com',))
        with patch('services.tailscale.own_hostnames', return_value=set()):
            assert cb('https://netmon.example.com')
            assert cb('https://NetMon.example.com')
            assert not cb('https://other.example.com')


class TestRateLimitIdentity:
    """A proxy on this host (tailscale serve, Caddy) makes every client loopback, which is
    trusted; the forwarded address counts then and only then."""

    def _addr(self, app, remote, forwarded=None):
        from services.rate_limiter import client_address
        headers = {'X-Forwarded-For': forwarded} if forwarded else {}
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': remote}, headers=headers):
            return client_address()

    def test_loopback_uses_first_forwarded_hop(self, app):
        assert self._addr(app, '127.0.0.1', '100.99.41.23, 10.0.0.1') == '100.99.41.23'

    def test_plain_loopback_stays_loopback(self, app):
        assert self._addr(app, '127.0.0.1') == '127.0.0.1'

    def test_lan_client_cannot_spoof_its_way_to_trusted(self, app):
        assert self._addr(app, '192.168.86.57', '127.0.0.1') == '192.168.86.57'

    def test_forwarded_client_is_rate_limited(self, client):
        limited = client.get('/api/system/info', headers={'X-Forwarded-For': '100.99.41.23'})
        assert 'X-RateLimit-Limit' in limited.headers
        assert 'X-RateLimit-Limit' not in client.get('/api/system/info').headers   # loopback: trusted


class TestHsts:

    def test_not_sent_over_plain_http(self, client, monkeypatch):
        monkeypatch.delenv('HTTPS_ENABLED', raising=False)
        assert 'Strict-Transport-Security' not in client.get('/api/system/info').headers

    def test_sent_when_https_enabled(self, client, monkeypatch):
        monkeypatch.setenv('HTTPS_ENABLED', 'true')
        assert client.get('/api/system/info').headers['Strict-Transport-Security'].startswith('max-age=')
