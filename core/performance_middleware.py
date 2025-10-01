"""
Flask Performance Middleware for HomeNetMon
Provides request optimization, memory management, and performance monitoring
"""

import time
import gc
import threading
from datetime import datetime
from flask import request, jsonify, g
from functools import wraps
from core.database_pool import get_db_connection
from core.response_cache import cache_response, get_cache_stats

class PerformanceMiddleware:
    """Middleware for optimizing Flask application performance"""

    def __init__(self, app=None):
        self.app = app
        self.request_count = 0
        self.slow_requests = []
        self.lock = threading.Lock()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize middleware with Flask app"""
        self.app = app

        # Add before request handlers
        app.before_request(self.before_request)
        app.after_request(self.after_request)

        # Add error handlers
        app.errorhandler(500)(self.handle_server_error)

        # Add performance endpoints
        app.route('/api/performance/cache-stats')(self.cache_stats)
        app.route('/api/performance/memory-stats')(self.memory_stats)

    def before_request(self):
        """Called before each request"""
        g.start_time = time.time()
        g.request_id = f"{int(time.time())}-{threading.get_ident()}"

        # Increment request counter
        with self.lock:
            self.request_count += 1

            # Trigger garbage collection every 100 requests
            if self.request_count % 100 == 0:
                collected = gc.collect()
                if collected > 0:
                    print(f"Garbage collected {collected} objects after {self.request_count} requests")

    def after_request(self, response):
        """Called after each request"""
        if hasattr(g, 'start_time'):
            request_time = (time.time() - g.start_time) * 1000

            # Log slow requests
            if request_time > 1000:  # > 1 second
                with self.lock:
                    self.slow_requests.append({
                        'url': request.url,
                        'method': request.method,
                        'time_ms': request_time,
                        'timestamp': datetime.now().isoformat()
                    })

                    # Keep only last 50 slow requests
                    if len(self.slow_requests) > 50:
                        self.slow_requests = self.slow_requests[-50:]

                print(f"Slow request: {request.method} {request.path} - {request_time:.0f}ms")

            # Add performance headers
            response.headers['X-Response-Time'] = f"{request_time:.2f}ms"
            response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')

        return response

    def handle_server_error(self, error):
        """Handle 500 errors gracefully"""
        return jsonify({
            'error': 'Internal server error',
            'message': 'The server encountered an error processing your request',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 500

    def cache_stats(self):
        """Get cache performance statistics"""
        stats = get_cache_stats()
        stats['slow_requests'] = len(self.slow_requests)
        stats['total_requests'] = self.request_count
        return jsonify(stats)

    def memory_stats(self):
        """Get memory usage statistics"""
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()

        return jsonify({
            'memory_mb': memory_info.rss / 1024 / 1024,
            'cpu_percent': process.cpu_percent(),
            'num_threads': process.num_threads(),
            'open_files': len(process.open_files()),
            'connections': len(process.connections())
        })

def optimize_database_query(func):
    """Decorator to optimize database queries"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Use connection pool
        database_path = kwargs.get('database_path', 'homeNetMon.db')
        with get_db_connection(database_path) as conn:
            kwargs['conn'] = conn
            return func(*args, **kwargs)
    return wrapper

def rate_limit(requests_per_minute=60):
    """Simple rate limiting decorator"""
    request_times = {}
    lock = threading.Lock()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()

            with lock:
                # Clean old requests
                if client_ip in request_times:
                    request_times[client_ip] = [
                        req_time for req_time in request_times[client_ip]
                        if now - req_time < 60  # Last minute
                    ]
                else:
                    request_times[client_ip] = []

                # Check rate limit
                if len(request_times[client_ip]) >= requests_per_minute:
                    return jsonify({'error': 'Rate limit exceeded'}), 429

                # Add current request
                request_times[client_ip].append(now)

            return func(*args, **kwargs)
        return wrapper
    return decorator
