"""
Performance middleware for HomeNetMon Flask application
Enables compression, caching headers, and other optimizations
"""

from flask import request, Response, current_app
import gzip
import time
from functools import wraps

class PerformanceMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        # Register middleware hooks
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Enable compression wrapper for better performance
        app.wsgi_app = self.add_gzip_compression(app.wsgi_app)
    
    def before_request(self):
        """Before request processing"""
        # Track request start time for performance monitoring
        request.start_time = time.time()
        
        # Add security headers that might help with caching
        if request.endpoint and request.endpoint.startswith('static'):
            # Static files - enable aggressive caching
            pass
    
    def after_request(self, response):
        """After request processing - add performance headers"""
        try:
            # Calculate request processing time
            if hasattr(request, 'start_time'):
                processing_time = time.time() - request.start_time
                response.headers['X-Response-Time'] = f"{processing_time:.3f}s"
            
            # Security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            
            # Generate ETag for cacheable responses
            if response.status_code == 200 and request.method == 'GET':
                if response.data:
                    import hashlib
                    etag = hashlib.md5(response.data).hexdigest()
                    response.headers['ETag'] = f'"{etag}"'
                    
                    # Check If-None-Match header
                    if request.headers.get('If-None-Match') == f'"{etag}"':
                        response.status_code = 304
                        response.data = b''
            
            # Cache control for different content types
            if request.endpoint:
                if request.endpoint == 'static':
                    # Static files - cache for 1 year with immutable
                    response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
                elif '/api/' in request.path:
                    # API endpoints - smart caching based on endpoint
                    if request.path.endswith('/devices') or 'monitoring' in request.path:
                        # Dynamic data - cache for 10 seconds with revalidation
                        response.headers['Cache-Control'] = 'private, max-age=10, must-revalidate'
                    elif 'config' in request.path or 'settings' in request.path:
                        # Configuration - cache for 5 minutes
                        response.headers['Cache-Control'] = 'private, max-age=300'
                    else:
                        # Other API endpoints - moderate cache
                        response.headers['Cache-Control'] = 'public, max-age=60'
                else:
                    # HTML pages - cache with revalidation
                    response.headers['Cache-Control'] = 'private, max-age=60, must-revalidate'
            
            # Enable HTTP/2 server push hints for critical resources
            if request.path == '/' and response.status_code == 200:
                # Preload critical CSS and JS
                critical_resources = [
                    '</static/bundles/core.css>; rel=preload; as=style',
                    '</static/bundles/core.js>; rel=preload; as=script',
                    '<https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css>; rel=preload; as=style; crossorigin',
                ]
                response.headers['Link'] = ', '.join(critical_resources)
            
        except Exception as e:
            current_app.logger.warning(f"Performance middleware error: {e}")
        
        return response
    
    def add_gzip_compression(self, app):
        """Add gzip compression wrapper - FIXED version"""
        def gzip_wrapper(environ, start_response):
            # Store the original start_response
            stored_status = None
            stored_headers = None
            stored_exc_info = None
            
            def new_start_response(status, response_headers, exc_info=None):
                nonlocal stored_status, stored_headers, stored_exc_info
                stored_status = status
                stored_headers = response_headers
                stored_exc_info = exc_info
                # Don't call start_response yet - wait until we know if we're compressing
                return None
            
            # Capture response
            response_data = []
            app_iter = app(environ, new_start_response)
            
            # Collect response data
            for data in app_iter:
                response_data.append(data)
            
            # Join all data
            full_response = b''.join(response_data)
            
            # Determine if we should compress
            accept_encoding = environ.get('HTTP_ACCEPT_ENCODING', '')
            should_compress = (
                'gzip' in accept_encoding and 
                len(full_response) > 1024 and  # Only compress if > 1KB
                self.should_compress(stored_headers)
            )
            
            # Actually compress if appropriate
            if should_compress:
                try:
                    compressed_response = gzip.compress(full_response)
                    # Only use compression if it actually reduces size
                    if len(compressed_response) < len(full_response):
                        full_response = compressed_response
                        # Add gzip headers
                        stored_headers.append(('Content-Encoding', 'gzip'))
                        # Remove content-length as it will be wrong after compression
                        stored_headers = [(k, v) for k, v in stored_headers if k.lower() != 'content-length']
                        # Add new content length
                        stored_headers.append(('Content-Length', str(len(full_response))))
                except Exception as e:
                    # Fall back to uncompressed on any error
                    current_app.logger.debug(f"Compression failed: {e}")
            
            # Now call the real start_response with final headers
            start_response(stored_status, stored_headers, stored_exc_info)
            
            return [full_response]
        
        return gzip_wrapper
    
    def should_compress(self, response_headers):
        """Check if response should be compressed"""
        content_type = None
        for header, value in response_headers:
            if header.lower() == 'content-type':
                content_type = value.lower()
                break
        
        if not content_type:
            return False
        
        compressible_types = [
            'text/html',
            'text/css', 
            'text/javascript',
            'application/javascript',
            'application/json',
            'application/xml',
            'text/xml'
        ]
        
        return any(comp_type in content_type for comp_type in compressible_types)

def add_cache_control(max_age=300):
    """Decorator to add cache control headers"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['Cache-Control'] = f'public, max-age={max_age}'
            return response
        return decorated_function
    return decorator

def no_cache(f):
    """Decorator to disable caching"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if hasattr(response, 'headers'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
    return decorated_function