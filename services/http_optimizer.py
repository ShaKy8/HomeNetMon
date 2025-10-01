#!/usr/bin/env python3
"""
HTTP Optimization Service
Provides HTTP/2, caching headers, and performance optimizations.
"""

import os
import logging
from datetime import datetime, timedelta
from flask import make_response, request, g
import mimetypes
import hashlib

logger = logging.getLogger(__name__)

class HTTPOptimizer:
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize HTTP optimization middleware."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Configure server for HTTP/2 when using production server
        self.configure_http2_settings(app)
        
        logger.info("HTTP optimizer initialized with caching and performance headers")
    
    def configure_http2_settings(self, app):
        """Configure HTTP/2 settings for production deployment."""
        # These settings will be used when deploying with a production server
        app.config['HTTP2_ENABLED'] = True
        app.config['HTTP2_PUSH_ENABLED'] = True
        
        # Server push resources that should be preloaded
        app.config['HTTP2_PUSH_RESOURCES'] = [
            ('/static/bundles/core.css', 'style'),
            ('/static/bundles/core.js', 'script'),
            ('/static/bundles/dashboard.css', 'style'),
            ('/static/bundles/dashboard.js', 'script')
        ]
    
    def before_request(self):
        """Process request before handling."""
        g.start_time = datetime.utcnow()
        
        # Enable connection keep-alive
        g.keep_alive = True
    
    def after_request(self, response):
        """Optimize response with caching and performance headers."""
        
        # Calculate request processing time
        if hasattr(g, 'start_time'):
            processing_time = (datetime.utcnow() - g.start_time).total_seconds()
            response.headers['X-Response-Time'] = f"{processing_time:.3f}s"
        
        # Add security and performance headers
        self.add_security_headers(response)
        self.add_performance_headers(response)
        self.add_caching_headers(response)
        
        # Add HTTP/2 server push hints
        self.add_server_push_hints(response)
        
        return response
    
    def add_security_headers(self, response):
        """Add security headers for better protection."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Only add HSTS for HTTPS connections
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    def add_performance_headers(self, response):
        """Add performance optimization headers."""
        # Enable keep-alive connections
        response.headers['Connection'] = 'keep-alive'
        response.headers['Keep-Alive'] = 'timeout=30, max=100'
        
        # Add resource hints for better loading
        if 'text/html' in response.content_type:
            # DNS prefetch for external resources
            response.headers['Link'] = '<https://cdn.jsdelivr.net>; rel=dns-prefetch, <https://cdn.socket.io>; rel=dns-prefetch'
    
    def add_caching_headers(self, response):
        """Add intelligent caching headers based on content type."""
        path = request.path
        
        # Static assets - long cache with versioning
        if path.startswith('/static/'):
            if any(path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg']):
                # 1 year cache for versioned assets
                response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
                response.headers['Expires'] = (datetime.utcnow() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                
                # Add ETag for cache validation (skip for passthrough responses)
                try:
                    if response.direct_passthrough:
                        # Skip ETag for file responses in passthrough mode
                        pass
                    elif response.data:
                        etag = hashlib.md5(response.data).hexdigest()[:16]
                        response.headers['ETag'] = f'"{etag}"'
                except (RuntimeError, AttributeError):
                    # Skip if response doesn't support data access
                    pass
        
        # API responses - short cache with validation
        elif path.startswith('/api/'):
            if request.method == 'GET':
                response.headers['Cache-Control'] = 'public, max-age=30, must-revalidate'
            else:
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        
        # HTML pages - moderate cache with validation
        elif 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'public, max-age=300, must-revalidate'
            
            # Add Last-Modified header
            response.headers['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    def add_server_push_hints(self, response):
        """Add HTTP/2 server push hints for critical resources."""
        if 'text/html' in response.content_type and request.path == '/':
            # Critical resources to push with main page
            push_resources = [
                '</static/bundles/core.css>; rel=preload; as=style',
                '</static/bundles/core.js>; rel=preload; as=script',
                '</static/icons/icon-192x192.png>; rel=preload; as=image'
            ]
            
            existing_link = response.headers.get('Link', '')
            if existing_link:
                push_resources.insert(0, existing_link)
            
            response.headers['Link'] = ', '.join(push_resources)
    
    def should_compress(self, response):
        """Determine if response should be compressed."""
        # Already handled by Flask-Compress, but can add custom logic here
        if response.status_code >= 400:
            return False
        
        if 'Content-Encoding' in response.headers:
            return False
        
        content_type = response.headers.get('Content-Type', '').lower()
        compressible_types = [
            'text/', 'application/javascript', 'application/json',
            'application/xml', 'image/svg+xml'
        ]
        
        return any(content_type.startswith(ct) for ct in compressible_types)


def create_performance_response(data, mimetype=None, status=200):
    """Create a performance-optimized response."""
    response = make_response(data, status)
    
    if mimetype:
        response.headers['Content-Type'] = mimetype
    
    # Add performance headers
    response.headers['X-Powered-By'] = 'HomeNetMon/Optimized'
    
    return response


def enable_http2_push(app):
    """Enable HTTP/2 server push for critical resources."""
    @app.context_processor
    def inject_http2_push():
        """Inject HTTP/2 push resources into templates."""
        return {
            'http2_push_resources': app.config.get('HTTP2_PUSH_RESOURCES', [])
        }