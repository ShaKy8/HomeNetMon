"""create_endpoint_limiter must build the limited view once and let a 429 propagate."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from werkzeug.exceptions import TooManyRequests

from api.rate_limited_endpoints import create_endpoint_limiter


class FakeLimiter:
    def __init__(self):
        self.builds = 0
        self.calls = 0
        self.trip = False

    def limit(self, limit_string):
        self.builds += 1

        def deco(f):
            def limited(*a, **k):
                self.calls += 1
                if self.trip:
                    raise TooManyRequests('slow down')
                return f(*a, **k)
            return limited
        return deco


def test_limited_view_is_built_once_and_429_propagates(app):
    fake = FakeLimiter()

    @create_endpoint_limiter('strict')
    def view():
        return 'ok'

    with patch('api.rate_limited_endpoints.get_limiter', return_value=fake):
        assert view() == 'ok' and view() == 'ok'
        assert fake.builds == 1 and fake.calls == 2
        fake.trip = True
        with pytest.raises(TooManyRequests):   # the old wrapper swallowed this and served the request
            view()


def test_missing_limiter_falls_through(app):
    @create_endpoint_limiter('strict')
    def view():
        return 'ok'

    with patch('api.rate_limited_endpoints.get_limiter', return_value=None):
        assert view() == 'ok'


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


def test_no_read_only_route_is_on_the_critical_tier(app):
    """'critical' is 1 request per 5 minutes; a page that polls or loads a GET on it gets 429s."""
    offenders = []
    for rule in app.url_map.iter_rules():
        if (rule.methods or set()) - {'HEAD', 'OPTIONS'} != {'GET'}:
            continue
        view = app.view_functions.get(rule.endpoint)
        if getattr(view, '_rate_limit_tier', None) == 'critical':
            offenders.append(rule.rule)
    assert offenders == []


def test_trusted_address_is_exempt_from_limits(client):
    """RATE_LIMIT_TRUSTED_IPS (and localhost) used to only change the limiter key, so
    'trusted-127.0.0.1' was throttled like anyone else."""
    token = _token(client)
    for _ in range(15):   # PUT /api/config/network is on the 10/minute 'strict' tier
        r = client.put('/api/config/network', json={}, headers={'X-CSRF-Token': token},
                       environ_base={'REMOTE_ADDR': '127.0.0.1'})
        assert r.status_code != 429


def test_untrusted_address_is_limited(client):
    token = _token(client)
    codes = [client.put('/api/config/network', json={}, headers={'X-CSRF-Token': token},
                        environ_base={'REMOTE_ADDR': '10.99.99.99'}).status_code for _ in range(12)]
    assert 429 in codes
