"""
Frontend Resource Optimization Service for HomeNetMon
Provides resource bundling, minification, and caching for improved performance.
"""
import os
import hashlib
import json
import gzip
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
            
            # Create gzipped version for better compression
            gzipped_path = self.bundles_folder / f"{bundle_name}.{resource_type}.gz"
            with gzip.open(gzipped_path, 'wt', encoding='utf-8') as gz_file:
                gz_file.write(combined_content)
            
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
        self.cache_headers = {
            'css': {'Cache-Control': 'public, max-age=31536000', 'Vary': 'Accept-Encoding'},
            'js': {'Cache-Control': 'public, max-age=31536000', 'Vary': 'Accept-Encoding'},
            'images': {'Cache-Control': 'public, max-age=2592000', 'Vary': 'Accept-Encoding'},
            'fonts': {'Cache-Control': 'public, max-age=31536000'},
            'default': {'Cache-Control': 'public, max-age=3600'}
        }
        
    def get_optimized_headers(self, file_path: str) -> Dict[str, str]:
        """Get optimized cache headers for a file"""
        file_extension = Path(file_path).suffix.lower()
        
        if file_extension in ['.css']:
            return self.cache_headers['css']
        elif file_extension in ['.js']:
            return self.cache_headers['js']
        elif file_extension in ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg']:
            return self.cache_headers['images']
        elif file_extension in ['.woff', '.woff2', '.ttf', '.eot']:
            return self.cache_headers['fonts']
        else:
            return self.cache_headers['default']
    
    def should_compress(self, file_path: str) -> bool:
        """Check if file should be compressed"""
        file_extension = Path(file_path).suffix.lower()
        compressible_types = ['.css', '.js', '.html', '.json', '.xml', '.txt', '.svg']
        return file_extension in compressible_types

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
    
    # Preload bundles in development
    if app.debug:
        resource_bundler.preload_bundles()
    
    # Add template globals for easy access to bundle URLs
    app.jinja_env.globals['get_css_bundle'] = resource_bundler.get_css_bundle_url
    app.jinja_env.globals['get_js_bundle'] = resource_bundler.get_js_bundle_url
    
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

def generate_service_worker(app, version: str = None):
    """Generate service worker for the app"""
    if not app.static_folder:
        return None
    
    if not version:
        # Try to get version from app
        version = getattr(app, 'version', '1.0.0')
    
    sw_generator = ServiceWorkerGenerator(app.static_folder, version)
    return sw_generator.write_service_worker()