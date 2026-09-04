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
