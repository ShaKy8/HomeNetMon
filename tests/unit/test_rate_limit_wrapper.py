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
