"""wsgi.py is what gunicorn imports; it must build the app without side effects under TESTING."""

import importlib


def test_wsgi_exposes_the_app(app):
    module = importlib.import_module('wsgi')
    assert module.app.name == 'app'
    assert hasattr(module, 'socketio')
