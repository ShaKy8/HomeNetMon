"""
Performance middleware: request timing header and one cache-control policy.

Compression is flask-compress (registered in app.py); security headers are
core.security_middleware. This used to duplicate both -- a second gzip WSGI
wrapper that buffered every response and never closed file iterators, an md5
of every 200 body for ETags, and an X-Frame-Options that overrode the
security middleware's DENY with SAMEORIGIN because after_request hooks run in
reverse registration order.
"""
import time

from flask import current_app, request


class PerformanceMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self.before_request)
        app.after_request(self.after_request)

    def before_request(self):
        request.start_time = time.time()

    def after_request(self, response):
        try:
            if hasattr(request, 'start_time'):
                response.headers['X-Response-Time'] = f"{time.time() - request.start_time:.3f}s"

            if request.endpoint == 'static':
                # Versioned via ?v=<app_version> in templates, so long immutable caching is safe.
                response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            elif request.path.startswith('/api/'):
                # Live monitoring data; the pages poll and push, never cache.
                response.headers['Cache-Control'] = 'no-store'
            else:
                response.headers['Cache-Control'] = 'no-cache'
        except Exception as e:
            current_app.logger.warning(f"Performance middleware error: {e}")
        return response
