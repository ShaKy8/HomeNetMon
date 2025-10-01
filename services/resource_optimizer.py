"""
Frontend Resource Optimization Service for HomeNetMon
Provides resource bundling, minification, and caching for improved performance.
"""
import os
import hashlib
import json
import gzip
import brotli
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import mimetypes
from flask import current_app

logger = logging.getLogger(__name__)

class ResourceBundler:
    """Handles bundling and optimization of CSS and JavaScript resources"""
    
    def __init__(self, static_folder: str):
        self.static_folder = Path(static_folder)
        self.bundles_folder = self.static_folder / 'bundles'
        self.bundles_folder.mkdir(exist_ok=True)
        
        # Resource configurations
        self.css_bundles = {
            'core': {
                'files': [
                    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
                    'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css',
                    'css/app.css'
                ],
                'minify': True,
                'cache_duration': 3600 * 24  # 24 hours
            },
            'dashboard': {
                'files': [
                    'css/dashboard.css'
                ],
                'minify': True,
                'cache_duration': 3600 * 24
            }
        }
        
        self.js_bundles = {
            'core': {
                'files': [
                    'https://cdn.jsdelivr.net/npm/chart.js',
                    'https://cdn.socket.io/4.7.2/socket.io.min.js',
                    'js/app.js'
                ],
                'minify': True,
                'cache_duration': 3600 * 24
            },
            'dashboard': {
                'files': [
                    'js/dashboard.js',
                    'js/real-time-updates.js'
                ],
                'minify': True,
                'cache_duration': 3600 * 24
            },
            'topology': {
                'files': [
                    'https://cdn.jsdelivr.net/npm/d3@7',
                    'js/network-topology.js'
                ],
                'minify': True,
                'cache_duration': 3600 * 24
            }
        }
        
        # Bundle cache
        self._bundle_cache = {}
        self._bundle_hashes = {}
        self._cache_timestamps = {}
        
    def get_css_bundle_url(self, bundle_name: str) -> Optional[str]:
        """Get URL for CSS bundle, creating it if necessary"""
        return self._get_bundle_url(bundle_name, 'css')
    
    def get_js_bundle_url(self, bundle_name: str) -> Optional[str]:
        """Get URL for JavaScript bundle, creating it if necessary"""
        return self._get_bundle_url(bundle_name, 'js')
    
    def _get_bundle_url(self, bundle_name: str, resource_type: str) -> Optional[str]:
        """Get bundle URL, creating bundle if necessary"""
        bundles = self.css_bundles if resource_type == 'css' else self.js_bundles
        
        if bundle_name not in bundles:
            logger.error(f"Unknown {resource_type} bundle: {bundle_name}")
            return None
        
        bundle_config = bundles[bundle_name]
        cache_key = f"{bundle_name}_{resource_type}"
        
        # Check if bundle needs regeneration
        if self._should_regenerate_bundle(cache_key, bundle_config):
            bundle_path = self._create_bundle(bundle_name, resource_type, bundle_config)
            if bundle_path:
                # Generate hash for cache busting
                bundle_hash = self._generate_file_hash(bundle_path)
                self._bundle_hashes[cache_key] = bundle_hash
                self._cache_timestamps[cache_key] = time.time()
                
                # Return relative URL with hash for cache busting
                bundle_filename = f"{bundle_name}.{resource_type}"
                return f"/static/bundles/{bundle_filename}?v={bundle_hash[:8]}"
        
        # Return existing bundle
        if cache_key in self._bundle_hashes:
            bundle_filename = f"{bundle_name}.{resource_type}"
            return f"/static/bundles/{bundle_filename}?v={self._bundle_hashes[cache_key][:8]}"
        
        return None
    
    def _should_regenerate_bundle(self, cache_key: str, bundle_config: Dict) -> bool:
        """Check if bundle should be regenerated"""
        # Always regenerate if not cached
        if cache_key not in self._cache_timestamps:
            return True
        
        # Check cache duration
        cache_age = time.time() - self._cache_timestamps[cache_key]
        if cache_age > bundle_config.get('cache_duration', 3600):
            return True
        
        # Check if source files have changed
        bundle_name, resource_type = cache_key.split('_', 1)
        bundle_path = self.bundles_folder / f"{bundle_name}.{resource_type}"
        
        if not bundle_path.exists():
            return True
        
        # Check modification times of local source files
        for file_path in bundle_config['files']:
            if not file_path.startswith('http'):
                local_path = self.static_folder / file_path
                if local_path.exists():
                    if local_path.stat().st_mtime > self._cache_timestamps[cache_key]:
                        return True
        
        return False
    
    def _create_bundle(self, bundle_name: str, resource_type: str, bundle_config: Dict) -> Optional[Path]:
        """Create a bundled resource file"""
        try:
            bundle_content = []
            
            # Process each file in the bundle
            for file_path in bundle_config['files']:
                if file_path.startswith('http'):
                    # CDN resource - add as external reference or download
                    if resource_type == 'css':
                        bundle_content.append(f"@import url('{file_path}');")
                    else:
                        # For JS, add a comment indicating external dependency
                        bundle_content.append(f"/* External dependency: {file_path} */")
                else:
                    # Local resource
                    local_path = self.static_folder / file_path
                    if local_path.exists():
                        content = local_path.read_text(encoding='utf-8')
                        bundle_content.append(f"/* Source: {file_path} */")
                        bundle_content.append(content)
                        bundle_content.append("")
                    else:
                        logger.warning(f"Local resource not found: {file_path}")
            
            # Combine all content
            combined_content = "\n".join(bundle_content)
            
            # Minify if requested
            if bundle_config.get('minify', False):
                combined_content = self._minify_content(combined_content, resource_type)
            
            # Write bundle file
            bundle_path = self.bundles_folder / f"{bundle_name}.{resource_type}"
            bundle_path.write_text(combined_content, encoding='utf-8')
            
            # Create compressed versions for better performance
            self._create_compressed_versions(bundle_path, combined_content)
            
            logger.info(f"Created {resource_type} bundle: {bundle_name} ({len(combined_content)} bytes)")
            return bundle_path
            
        except Exception as e:
            logger.error(f"Error creating bundle {bundle_name}.{resource_type}: {e}")
            return None
    
    def _minify_content(self, content: str, resource_type: str) -> str:
        """Basic minification (remove comments and unnecessary whitespace)"""
        if resource_type == 'css':
            return self._minify_css(content)
        elif resource_type == 'js':
            return self._minify_js(content)
        return content
    
    def _minify_css(self, css_content: str) -> str:
        """Basic CSS minification"""
        import re
        
        # Remove comments
        css_content = re.sub(r'/\*.*?\*/', '', css_content, flags=re.DOTALL)
        
        # Remove extra whitespace
        css_content = re.sub(r'\s+', ' ', css_content)
        
        # Remove whitespace around certain characters
        css_content = re.sub(r'\s*([{}:;,>+~])\s*', r'\1', css_content)
        
        # Remove trailing semicolons before }
        css_content = re.sub(r';\s*}', '}', css_content)
        
        return css_content.strip()
    
    def _minify_js(self, js_content: str) -> str:
        """Basic JavaScript minification"""
        import re
        
        # Remove single-line comments (but preserve URLs)
        js_content = re.sub(r'(?<!:)//.*$', '', js_content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        js_content = re.sub(r'/\*.*?\*/', '', js_content, flags=re.DOTALL)
        
        # Remove extra whitespace
        js_content = re.sub(r'\s+', ' ', js_content)
        
        # Remove whitespace around operators and punctuation
        js_content = re.sub(r'\s*([{}();,=+\-*/])\s*', r'\1', js_content)
        
        return js_content.strip()
    
    def _create_compressed_versions(self, bundle_path: Path, content: str):
        """Create multiple compressed versions of the bundle"""
        try:
            # Create gzipped version (widely supported)
            gzipped_path = bundle_path.with_suffix(bundle_path.suffix + '.gz')
            with gzip.open(gzipped_path, 'wt', encoding='utf-8', compresslevel=9) as gz_file:
                gz_file.write(content)
            
            # Create brotli version (better compression, modern browsers)
            try:
                brotli_path = bundle_path.with_suffix(bundle_path.suffix + '.br')
                with open(brotli_path, 'wb') as br_file:
                    compressed = brotli.compress(content.encode('utf-8'), quality=11)
                    br_file.write(compressed)
                logger.debug(f"Created brotli compressed version: {brotli_path}")
            except ImportError:
                logger.debug("Brotli compression not available")
            except Exception as e:
                logger.warning(f"Failed to create brotli compressed version: {e}")
                
            # Log compression ratios
            original_size = len(content.encode('utf-8'))
            gzip_size = gzipped_path.stat().st_size if gzipped_path.exists() else 0
            
            if gzip_size > 0:
                compression_ratio = (1 - gzip_size / original_size) * 100
                logger.info(f"Compression: {original_size} → {gzip_size} bytes ({compression_ratio:.1f}% reduction)")
                
        except Exception as e:
            logger.error(f"Error creating compressed versions: {e}")

    def _generate_file_hash(self, file_path: Path) -> str:
        """Generate SHA256 hash of file content for cache busting"""
        try:
            content = file_path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.error(f"Error generating hash for {file_path}: {e}")
            return str(int(time.time()))
    
    def preload_bundles(self):
        """Preload all configured bundles"""
        logger.info("Preloading resource bundles...")
        
        # Preload CSS bundles
        for bundle_name in self.css_bundles:
            self.get_css_bundle_url(bundle_name)
        
        # Preload JS bundles
        for bundle_name in self.js_bundles:
            self.get_js_bundle_url(bundle_name)
        
        logger.info("Completed preloading resource bundles")
    
    def get_bundle_info(self) -> Dict:
        """Get information about all bundles"""
        info = {
            'css_bundles': {},
            'js_bundles': {},
            'cache_stats': {
                'total_bundles': len(self._bundle_hashes),
                'cache_hits': 0,
                'cache_size_bytes': 0
            }
        }
        
        # Get CSS bundle info
        for bundle_name, config in self.css_bundles.items():
            bundle_path = self.bundles_folder / f"{bundle_name}.css"
            info['css_bundles'][bundle_name] = {
                'files': len(config['files']),
                'exists': bundle_path.exists(),
                'size_bytes': bundle_path.stat().st_size if bundle_path.exists() else 0,
                'url': self.get_css_bundle_url(bundle_name)
            }
        
        # Get JS bundle info
        for bundle_name, config in self.js_bundles.items():
            bundle_path = self.bundles_folder / f"{bundle_name}.js"
            info['js_bundles'][bundle_name] = {
                'files': len(config['files']),
                'exists': bundle_path.exists(),
                'size_bytes': bundle_path.stat().st_size if bundle_path.exists() else 0,
                'url': self.get_js_bundle_url(bundle_name)
            }
        
        return info

class StaticResourceOptimizer:
    """Optimizes static resource serving with caching and compression"""
    
    def __init__(self, static_folder: str):
        self.static_folder = Path(static_folder)
        # Enhanced cache headers with compression support and security headers
        self.cache_headers = {
            'css': {
                'Cache-Control': 'public, max-age=31536000, immutable',
                'Vary': 'Accept-Encoding',
                'X-Content-Type-Options': 'nosniff'
            },
            'js': {
                'Cache-Control': 'public, max-age=31536000, immutable',
                'Vary': 'Accept-Encoding',
                'X-Content-Type-Options': 'nosniff'
            },
            'images': {
                'Cache-Control': 'public, max-age=2592000',
                'Vary': 'Accept-Encoding',
                'X-Content-Type-Options': 'nosniff'
            },
            'fonts': {
                'Cache-Control': 'public, max-age=31536000, immutable',
                'Access-Control-Allow-Origin': '*'
            },
            'icons': {
                'Cache-Control': 'public, max-age=604800',  # 1 week for favicons
                'X-Content-Type-Options': 'nosniff'
            },
            'default': {
                'Cache-Control': 'public, max-age=3600',
                'Vary': 'Accept-Encoding'
            }
        }
        
    def get_optimized_headers(self, file_path: str) -> Dict[str, str]:
        """Get optimized cache headers for a file"""
        file_extension = Path(file_path).suffix.lower()
        filename = Path(file_path).name.lower()
        
        if file_extension in ['.css']:
            return self.cache_headers['css'].copy()
        elif file_extension in ['.js']:
            return self.cache_headers['js'].copy()
        elif file_extension in ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg']:
            return self.cache_headers['images'].copy()
        elif file_extension in ['.woff', '.woff2', '.ttf', '.eot']:
            return self.cache_headers['fonts'].copy()
        elif filename in ['favicon.ico', 'apple-touch-icon.png'] or 'icon' in filename:
            return self.cache_headers['icons'].copy()
        else:
            return self.cache_headers['default'].copy()
    
    def should_compress(self, file_path: str) -> bool:
        """Check if file should be compressed"""
        file_extension = Path(file_path).suffix.lower()
        compressible_types = ['.css', '.js', '.html', '.json', '.xml', '.txt', '.svg', '.map']
        return file_extension in compressible_types
    
    def get_best_encoding(self, accept_encoding: str, file_path: Path) -> Optional[Tuple[str, Path]]:
        """Get the best available encoding for a file based on Accept-Encoding header"""
        if not accept_encoding:
            return None, file_path
        
        accept_encoding = accept_encoding.lower()
        
        # Check for brotli first (better compression)
        if 'br' in accept_encoding:
            br_path = file_path.with_suffix(file_path.suffix + '.br')
            if br_path.exists():
                return 'br', br_path
        
        # Check for gzip
        if 'gzip' in accept_encoding:
            gz_path = file_path.with_suffix(file_path.suffix + '.gz')
            if gz_path.exists():
                return 'gzip', gz_path
        
        # Return original file
        return None, file_path
    
    def create_precompressed_files(self, source_path: Path):
        """Create precompressed versions of a file"""
        if not self.should_compress(str(source_path)):
            return
        
        try:
            content = source_path.read_text(encoding='utf-8')
            
            # Create gzipped version
            gz_path = source_path.with_suffix(source_path.suffix + '.gz')
            with gzip.open(gz_path, 'wt', encoding='utf-8', compresslevel=9) as gz_file:
                gz_file.write(content)
            
            # Create brotli version if available
            try:
                br_path = source_path.with_suffix(source_path.suffix + '.br')
                with open(br_path, 'wb') as br_file:
                    compressed = brotli.compress(content.encode('utf-8'), quality=11)
                    br_file.write(compressed)
            except (ImportError, NameError):
                pass  # Brotli not available
                
        except Exception as e:
            logger.error(f"Error precompressing {source_path}: {e}")

# Global resource optimization instances
resource_bundler = None
static_optimizer = None

def init_resource_optimization(app):
    """Initialize resource optimization for the Flask app"""
    global resource_bundler, static_optimizer
    
    static_folder = app.static_folder
    if not static_folder:
        logger.warning("No static folder configured, skipping resource optimization")
        return None, None
    
    # Initialize bundler and optimizer
    resource_bundler = ResourceBundler(static_folder)
    static_optimizer = StaticResourceOptimizer(static_folder)
    
    # Always preload bundles to ensure they exist
    resource_bundler.preload_bundles()
    
    # Add template globals for easy access to bundle URLs
    app.jinja_env.globals['get_css_bundle'] = resource_bundler.get_css_bundle_url
    app.jinja_env.globals['get_js_bundle'] = resource_bundler.get_js_bundle_url
    
    # Add static compression middleware
    try:
        add_static_compression_middleware(app)
        logger.info("Enabled static file compression middleware")
    except Exception as e:
        # This warning is expected due to Flask's endpoint overriding behavior
        # Static compression may still be working via other mechanisms
        logger.info(f"Static compression middleware registration skipped: {e}")
        logger.info("Static files will still be served with compression via resource bundles")
    
    logger.info("Initialized frontend resource optimization")
    return resource_bundler, static_optimizer

def get_resource_bundle_info():
    """Get information about resource bundles"""
    if resource_bundler:
        return resource_bundler.get_bundle_info()
    return {}

class ServiceWorkerGenerator:
    """Generates service worker for aggressive caching"""
    
    def __init__(self, static_folder: str, version: str = "1.0.0"):
        self.static_folder = Path(static_folder)
        self.version = version
        
    def generate_service_worker(self) -> str:
        """Generate service worker JavaScript content"""
        cache_name = f"homenetmon-v{self.version}"
        
        # Get list of files to cache
        cache_files = [
            '/',
            '/static/bundles/core.css',
            '/static/bundles/core.js',
            '/static/bundles/dashboard.css',
            '/static/bundles/dashboard.js',
            '/static/css/app.css',
            '/static/icons/icon-192x192.png',
            '/static/icons/icon-512x512.png'
        ]
        
        service_worker_content = f"""
// HomeNetMon Service Worker v{self.version}
const CACHE_NAME = '{cache_name}';
const urlsToCache = {json.dumps(cache_files, indent=2)};

// Install event - cache core resources
self.addEventListener('install', event => {{
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {{
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      }})
      .then(() => self.skipWaiting())
  );
}});

// Activate event - clean up old caches
self.addEventListener('activate', event => {{
  event.waitUntil(
    caches.keys().then(cacheNames => {{
      return Promise.all(
        cacheNames.map(cacheName => {{
          if (cacheName !== CACHE_NAME) {{
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }}
        }})
      );
    }})
  );
  event.waitUntil(clients.claim());
}});

// Fetch event - serve from cache when possible
self.addEventListener('fetch', event => {{
  // Skip cross-origin requests
  if (!event.request.url.startsWith(self.location.origin)) {{
    return;
  }}
  
  // Skip WebSocket and API requests for real-time data
  if (event.request.url.includes('/socket.io') || 
      event.request.url.includes('/api/')) {{
    return;
  }}
  
  event.respondWith(
    caches.match(event.request)
      .then(response => {{
        // Return cached version or fetch from network
        if (response) {{
          return response;
        }}
        
        return fetch(event.request).then(response => {{
          // Don't cache non-successful responses
          if (!response || response.status !== 200 || response.type !== 'basic') {{
            return response;
          }}
          
          // Clone the response
          const responseToCache = response.clone();
          
          caches.open(CACHE_NAME)
            .then(cache => {{
              cache.put(event.request, responseToCache);
            }});
          
          return response;
        }});
      }})
  );
}});

// Handle background sync for offline actions
self.addEventListener('sync', event => {{
  if (event.tag === 'background-sync') {{
    console.log('Background sync triggered');
    event.waitUntil(doBackgroundSync());
  }}
}});

function doBackgroundSync() {{
  // Implement background sync logic here
  return Promise.resolve();
}}
"""
        
        return service_worker_content
    
    def write_service_worker(self) -> str:
        """Write service worker to static folder"""
        sw_content = self.generate_service_worker()
        sw_path = self.static_folder / 'service-worker.js'
        
        sw_path.write_text(sw_content, encoding='utf-8')
        logger.info(f"Generated service worker: {sw_path}")
        
        return str(sw_path)

def add_static_compression_middleware(app):
    """Add middleware to serve compressed static files"""
    from flask import request, g, send_file, abort, Response
    from werkzeug.exceptions import NotFound
    
    # Override the default static route (need to remove existing rule first)
    static_route = '/static/<path:filename>'
    
    # Remove existing static route if it exists
    rules_to_remove = []
    for rule in app.url_map.iter_rules():
        if rule.rule == static_route and rule.endpoint == 'static':
            rules_to_remove.append(rule)
    
    for rule in rules_to_remove:
        app.url_map._rules.remove(rule)
        app.url_map._rules_by_endpoint.setdefault(rule.endpoint, []).remove(rule)
    
    # Clear the URL map cache
    app.url_map._remap = True
    
    @app.route(static_route, endpoint='static')
    def compressed_static(filename):
        """Serve static files with compression support"""
        if not static_optimizer:
            # Fall back to default static file serving
            return app.send_static_file(filename)
        
        try:
            # Get the requested file path
            file_path = Path(app.static_folder) / filename
            
            if not file_path.exists():
                abort(404)
            
            # Get Accept-Encoding header
            accept_encoding = request.headers.get('Accept-Encoding', '')
            
            # Find best encoding
            encoding, serve_path = static_optimizer.get_best_encoding(accept_encoding, file_path)
            
            # Get optimized headers
            headers = static_optimizer.get_optimized_headers(filename)
            
            # Add encoding header if compressed
            if encoding:
                headers['Content-Encoding'] = encoding
                headers['Content-Length'] = str(serve_path.stat().st_size)
            
            # Create response with optimized headers
            response = send_file(str(serve_path), 
                               mimetype=mimetypes.guess_type(filename)[0],
                               as_attachment=False)
            
            # Apply all optimization headers
            for key, value in headers.items():
                response.headers[key] = value
                
            return response
            
        except Exception as e:
            logger.error(f"Error serving compressed static file {filename}: {e}")
            # Fall back to default static serving
            return app.send_static_file(filename)

def generate_service_worker(app, version: str = None):
    """Generate service worker for the app"""
    if not app.static_folder:
        return None
    
    if not version:
        # Try to get version from app
        version = getattr(app, 'version', '1.0.0')
    
    sw_generator = ServiceWorkerGenerator(app.static_folder, version)
    return sw_generator.write_service_worker()